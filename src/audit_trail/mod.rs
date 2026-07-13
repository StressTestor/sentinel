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
    /// Correlation id shared with the process that invoked this evaluation
    /// (e.g. the ghost bridge sets `SENTINEL_CALL_ID` per call), so this audit
    /// line can be joined against the caller's own per-call log. `serde(default)`
    /// so audit lines written before this field existed still parse (-> None);
    /// `skip_serializing_if` so standalone installs (no env var) keep writing
    /// byte-identical lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
}

/// The env var a wrapping caller sets to correlate its own per-call log line
/// with the audit line sentinel writes for the same call.
pub const CALL_ID_ENV: &str = "SENTINEL_CALL_ID";

/// Correlation id for the current evaluation, read from `SENTINEL_CALL_ID`.
/// Missing, empty, or non-unicode values are simply None — a malformed env var
/// must never affect the verdict, error, or write to stdout/stderr (the hook's
/// stdout is a parsed JSON contract).
pub fn call_id_from_env() -> Option<String> {
    normalize_call_id(std::env::var(CALL_ID_ENV).ok())
}

/// The pure normalization behind `call_id_from_env`: trim, drop empties.
fn normalize_call_id(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn event(call_id: Option<String>) -> AuditEvent {
        AuditEvent {
            timestamp: "2026-07-13T00:00:00+00:00".into(),
            tool_name: "Bash".into(),
            action: "block".into(),
            reason: Some("pipe to shell execution".into()),
            matched_rule: Some("deny.commands[0]".into()),
            mode: "enforce".into(),
            call_id,
        }
    }

    #[test]
    fn call_id_roundtrips_when_present() {
        let ev = event(Some("2f1e9c1a-7c39-4b6e-9d1a-000000000001".into()));
        let line = serde_json::to_string(&ev).unwrap();
        assert!(line.contains("2f1e9c1a-7c39-4b6e-9d1a-000000000001"));
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(
            back.call_id.as_deref(),
            Some("2f1e9c1a-7c39-4b6e-9d1a-000000000001")
        );
    }

    #[test]
    fn call_id_none_keeps_the_line_free_of_the_key_and_roundtrips() {
        let ev = event(None);
        let line = serde_json::to_string(&ev).unwrap();
        assert!(
            !line.contains("call_id"),
            "a standalone install (no env var) must keep writing byte-identical lines: {line}"
        );
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert!(back.call_id.is_none());
    }

    #[test]
    fn old_audit_lines_without_call_id_still_parse() {
        // a literal pre-call_id line, exactly as older sentinels wrote it.
        let old = r#"{"timestamp":"2026-01-01T00:00:00+00:00","tool_name":"Read","action":"allow","reason":null,"matched_rule":null,"mode":"audit"}"#;
        let ev: AuditEvent = serde_json::from_str(old).expect("old lines must keep parsing");
        assert!(ev.call_id.is_none());
        assert_eq!(ev.tool_name, "Read");
    }

    #[test]
    fn normalize_call_id_drops_missing_empty_and_whitespace() {
        assert_eq!(normalize_call_id(None), None);
        assert_eq!(normalize_call_id(Some(String::new())), None);
        assert_eq!(normalize_call_id(Some("   ".into())), None);
        assert_eq!(
            normalize_call_id(Some("  abc-123 ".into())),
            Some("abc-123".into())
        );
    }
}
