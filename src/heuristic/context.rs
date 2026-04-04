use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DEFAULT_CAPACITY: usize = 20;

/// file-backed ring buffer for multi-turn context tracking.
/// persists to disk as bincode so state survives across sentinel evaluate invocations.
#[derive(Serialize, Deserialize)]
pub struct ContextWindow {
    turns: Vec<String>,
    capacity: usize,
    #[serde(skip)]
    path: PathBuf,
}

impl ContextWindow {
    pub fn load_or_create(path: &Path) -> Self {
        if path.exists() {
            match Self::load_from_file(path) {
                Ok(mut ctx) => {
                    ctx.path = path.to_path_buf();
                    return ctx;
                }
                Err(e) => {
                    tracing::warn!("corrupt context file, resetting: {e}");
                    // fall through to create new
                }
            }
        }

        Self {
            turns: Vec::with_capacity(DEFAULT_CAPACITY),
            capacity: DEFAULT_CAPACITY,
            path: path.to_path_buf(),
        }
    }

    fn load_from_file(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        bincode::deserialize(&data).map_err(|e| e.to_string())
    }

    /// add a turn to the ring buffer. evicts oldest if at capacity.
    pub fn push(&mut self, content: &str) {
        if self.turns.len() >= self.capacity {
            self.turns.remove(0);
        }
        self.turns.push(content.to_string());
    }

    /// get all turns in order (oldest first)
    pub fn recent_turns(&self) -> &[String] {
        &self.turns
    }

    /// persist to disk
    pub fn save(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match bincode::serialize(self) {
            Ok(data) => {
                if let Err(e) = std::fs::write(&self.path, data) {
                    tracing::warn!("failed to save context: {e}");
                }
            }
            Err(e) => {
                tracing::warn!("failed to serialize context: {e}");
            }
        }
    }

    pub fn len(&self) -> usize {
        self.turns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.turns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn push_and_retrieve() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("context.bin");
        let mut ctx = ContextWindow::load_or_create(&path);

        ctx.push("turn 1");
        ctx.push("turn 2");

        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx.recent_turns(), &["turn 1", "turn 2"]);
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("context.bin");
        let mut ctx = ContextWindow {
            turns: Vec::new(),
            capacity: 3,
            path: path.clone(),
        };

        ctx.push("a");
        ctx.push("b");
        ctx.push("c");
        ctx.push("d"); // should evict "a"

        assert_eq!(ctx.len(), 3);
        assert_eq!(ctx.recent_turns(), &["b", "c", "d"]);
    }

    #[test]
    fn save_and_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("context.bin");

        {
            let mut ctx = ContextWindow::load_or_create(&path);
            ctx.push("persisted turn");
            ctx.save();
        }

        let ctx = ContextWindow::load_or_create(&path);
        assert_eq!(ctx.len(), 1);
        assert_eq!(ctx.recent_turns(), &["persisted turn"]);
    }

    #[test]
    fn handles_corrupt_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("context.bin");
        std::fs::write(&path, b"not valid bincode data!!!").unwrap();

        let ctx = ContextWindow::load_or_create(&path);
        assert!(ctx.is_empty()); // should reset gracefully
    }
}
