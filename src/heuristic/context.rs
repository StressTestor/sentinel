use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const DEFAULT_CAPACITY: usize = 50;

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
        Self::load_or_create_with_capacity(path, DEFAULT_CAPACITY)
    }

    /// Load the ring buffer from `path`, or create a fresh one.
    /// `capacity` overrides any capacity stored in the file -- the caller's
    /// config value always wins. If the loaded buffer has more turns than
    /// `capacity`, oldest turns are trimmed until it fits.
    pub fn load_or_create_with_capacity(path: &Path, capacity: usize) -> Self {
        debug_assert!(capacity > 0, "ring buffer capacity must be at least 1");
        if path.exists() {
            match Self::load_from_file(path) {
                Ok(mut ctx) => {
                    ctx.path = path.to_path_buf();
                    // honor caller's capacity even if stored file had a different one
                    ctx.capacity = capacity;
                    // trim if the new capacity is smaller than current length;
                    // drains from the front (oldest-first) in a single memmove.
                    let excess = ctx.turns.len().saturating_sub(capacity);
                    ctx.turns.drain(..excess);
                    return ctx;
                }
                Err(e) => {
                    tracing::warn!("corrupt context file, resetting: {e}");
                }
            }
        }

        Self {
            turns: Vec::with_capacity(capacity),
            capacity,
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

    /// persist to disk. uses an exclusive advisory lock on a sidecar
    /// lockfile, then writes to a temp file and atomically renames into
    /// place. safe under concurrent `sentinel evaluate` processes.
    ///
    /// NOTE: turn loss is possible under concurrent writers because load
    /// happens outside the lock (process A loads, process B loads, A writes,
    /// B writes overwrites A's turn). this is acceptable for a best-effort
    /// heuristic input -- the ring buffer is not a source of truth.
    pub fn save(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let lock_path = self.lock_path();
        let lock_file = match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
        {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("failed to open lock file {}: {e}", lock_path.display());
                return;
            }
        };

        if let Err(e) = lock_file.lock_exclusive() {
            tracing::warn!("failed to acquire lock on {}: {e}", lock_path.display());
            return;
        }

        let result = self.write_atomic();

        // unlock happens implicitly when lock_file is dropped, but be explicit
        let _ = FileExt::unlock(&lock_file);

        if let Err(e) = result {
            tracing::warn!("failed to save context: {e}");
        }
    }

    fn lock_path(&self) -> PathBuf {
        let mut p = self.path.clone();
        let name = p
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| std::ffi::OsString::from("context"));
        let mut lock_name = name;
        lock_name.push(".lock");
        p.set_file_name(lock_name);
        p
    }

    fn write_atomic(&self) -> std::io::Result<()> {
        let data = bincode::serialize(self)
            .map_err(|e| std::io::Error::other(format!("serialize: {e}")))?;

        // write to <path>.tmp then rename. rename is atomic on POSIX.
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.turns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.turns.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
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

    #[test]
    fn default_capacity_is_50() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("context.bin");
        let ctx = ContextWindow::load_or_create(&path);
        assert_eq!(ctx.capacity(), 50);
    }

    #[test]
    fn custom_capacity_via_constructor() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("context.bin");
        let ctx = ContextWindow::load_or_create_with_capacity(&path, 10);
        assert_eq!(ctx.capacity(), 10);
    }

    #[test]
    fn custom_capacity_evicts_at_configured_limit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("context.bin");
        let mut ctx = ContextWindow::load_or_create_with_capacity(&path, 3);
        for i in 0..5 {
            ctx.push(&format!("turn-{i}"));
        }
        assert_eq!(ctx.len(), 3);
        assert_eq!(ctx.recent_turns(), &["turn-2", "turn-3", "turn-4"]);
    }

    #[test]
    fn concurrent_writers_do_not_corrupt_file() {
        use std::sync::Arc;
        use std::thread;

        let dir = Arc::new(TempDir::new().unwrap());
        let path = Arc::new(dir.path().join("context.bin"));

        let handles: Vec<_> = (0..4)
            .map(|worker_id| {
                let path = Arc::clone(&path);
                thread::spawn(move || {
                    for turn in 0..20 {
                        let mut ctx = ContextWindow::load_or_create(&path);
                        ctx.push(&format!("w{worker_id}-t{turn}"));
                        ctx.save();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // the file must be readable (not truncated / not half-written bincode).
        let ctx = ContextWindow::load_or_create(&path);
        assert!(
            !ctx.is_empty(),
            "ring buffer lost all data under concurrent writes"
        );
        // and every turn we read back should be a well-formed "wN-tN" string.
        for t in ctx.recent_turns() {
            assert!(
                t.starts_with('w') && t.contains("-t"),
                "corrupted turn content: {t:?}"
            );
        }
    }

    #[test]
    fn load_with_smaller_capacity_trims_oldest_turns() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("context.bin");

        // write 8 turns at capacity 10
        {
            let mut ctx = ContextWindow::load_or_create_with_capacity(&path, 10);
            for i in 0..8 {
                ctx.push(&format!("turn-{i}"));
            }
            ctx.save();
        }

        // reload with capacity 5 - should trim oldest 3
        let ctx = ContextWindow::load_or_create_with_capacity(&path, 5);
        assert_eq!(ctx.len(), 5);
        assert_eq!(ctx.capacity(), 5);
        assert_eq!(ctx.recent_turns()[0], "turn-3"); // oldest survivor
        assert_eq!(ctx.recent_turns()[4], "turn-7"); // newest
    }
}
