use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub tool_name: String,
    pub action: String,
    pub reason: Option<String>,
    pub matched_rule: Option<String>,
    pub mode: String,
}

/// Read the audit trail back as events (for `sentinel doctor`). Missing/unreadable
/// log → empty; individual unparseable lines are skipped, not fatal.
pub fn read_events() -> Vec<AuditEvent> {
    let path = audit_log_path();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| serde_json::from_str::<AuditEvent>(line).ok())
        .collect()
}

/// append an audit event to the JSONL log file.
/// creates ~/.sentinel/audit.jsonl if it doesn't exist.
pub fn log_event(event: &AuditEvent) -> Result<(), std::io::Error> {
    let path = audit_log_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let line = serde_json::to_string(event)
        .map_err(std::io::Error::other)?;

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    writeln!(file, "{line}")?;
    Ok(())
}

fn audit_log_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".sentinel").join("audit.jsonl")
}
