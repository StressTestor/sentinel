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
    /// byte-identical lines. Pre phase only: the env var can only reach the
    /// evaluate subprocess a wrapper spawns, never a PostToolUse invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,

    /// Claude Code's per-call tool use id, read from the hook payload. The same
    /// value arrives in the PreToolUse and PostToolUse payloads for one tool
    /// call, so it joins this call's pre line to its post line(s). Same compat
    /// discipline as `call_id`: old lines parse (-> None), all-None lines stay
    /// byte-identical to the previous format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,

    /// Which hook phase wrote this line: "pre" (`sentinel evaluate`) or "post"
    /// (`sentinel post-evaluate`). None on lines written before this field
    /// existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_phase: Option<String>,
}

// THE JOIN CONTRACT (when ghost + sentinel are both current):
//   ghost feed line  <->  sentinel PRE line   via `call_id`   (env-derived)
//   sentinel PRE line <-> sentinel POST lines via `tool_use_id` (payload-derived)
// One governing call = exactly one pre line + zero-or-more post lines. Claude
// Code does not fire PostToolUse for a denied call (verified 2.1.207), so a
// blocked call has zero post lines — that's expected, not missing data.

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

    let line = serde_json::to_string(event).map_err(std::io::Error::other)?;

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
            tool_use_id: None,
            hook_phase: None,
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
    fn tool_use_id_and_hook_phase_roundtrip() {
        let mut ev = event(Some("2f1e9c1a-7c39-4b6e-9d1a-000000000001".into()));
        ev.tool_use_id = Some("toolu_01QoWqbiPYgBoiZQPDuvUHKb".into());
        ev.hook_phase = Some("pre".into());
        let line = serde_json::to_string(&ev).unwrap();
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(
            back.tool_use_id.as_deref(),
            Some("toolu_01QoWqbiPYgBoiZQPDuvUHKb")
        );
        assert_eq!(back.hook_phase.as_deref(), Some("pre"));
        // and call_id coexists: the ghost<->pre key and the pre<->post key are
        // independent columns on the same line.
        assert_eq!(
            back.call_id.as_deref(),
            Some("2f1e9c1a-7c39-4b6e-9d1a-000000000001")
        );
    }

    #[test]
    fn all_none_new_fields_keep_the_line_byte_identical_to_the_prior_format() {
        // an event with call_id/tool_use_id/hook_phase all None must serialize
        // to EXACTLY the pre-correlation shape — no new keys, ever.
        let line = serde_json::to_string(&event(None)).unwrap();
        assert_eq!(
            line,
            r#"{"timestamp":"2026-07-13T00:00:00+00:00","tool_name":"Bash","action":"block","reason":"pipe to shell execution","matched_rule":"deny.commands[0]","mode":"enforce"}"#
        );
    }

    #[test]
    fn prior_generation_audit_lines_still_parse() {
        // a #60-era line: call_id present, tool_use_id/hook_phase not yet born.
        let v60 = r#"{"timestamp":"2026-07-13T23:45:53+00:00","tool_name":"Bash","action":"block","reason":"pipe to shell execution","matched_rule":"deny.commands: x","mode":"enforce","call_id":"e1987b56-04bb-4cc1-b0c1-af4eb4fdc7b1"}"#;
        let ev: AuditEvent = serde_json::from_str(v60).expect("#60-era lines must keep parsing");
        assert_eq!(
            ev.call_id.as_deref(),
            Some("e1987b56-04bb-4cc1-b0c1-af4eb4fdc7b1")
        );
        assert!(ev.tool_use_id.is_none());
        assert!(ev.hook_phase.is_none());
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
