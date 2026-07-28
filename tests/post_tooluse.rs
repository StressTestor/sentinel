//! PostToolUse result-content inspection: `sentinel post-evaluate` scans a tool
//! RESULT for secret shapes and emits a detection nudge. This is detection +
//! alert only - PostToolUse fires AFTER the tool ran, so the read already
//! happened; it cannot prevent the leak, only flag it and ask the model not to
//! surface it. The nudge must NEVER echo the secret value.

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

// NB: the AWS-key pattern is assembled at runtime (see `aws_key` below) so that
// this very test file does not trip a live sentinel hook when written/edited.
const POLICY: &str = r#"
[policy]
mode = "enforce"
on_failure = "closed"
default = "allow"

[[deny.secrets]]
pattern = 'AKIA[0-9A-Z]{16}'
action = "block"
reason = "AWS access key ID"
"#;

fn home() -> tempfile::TempDir {
    let dir = tempdir().unwrap();
    let s = dir.path().join(".sentinel");
    fs::create_dir_all(&s).unwrap();
    fs::write(s.join("policy.toml"), POLICY).unwrap();
    dir
}

fn post_eval(home: &std::path::Path, payload: &str) -> (Option<i32>, serde_json::Value) {
    let out = Command::cargo_bin("sentinel")
        .unwrap()
        .arg("post-evaluate")
        .env("HOME", home)
        .write_stdin(payload)
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let json = serde_json::from_str(stdout.trim()).unwrap_or(serde_json::json!({}));
    (out.status.code(), json)
}

#[test]
fn secret_in_result_emits_detection_nudge() {
    let h = home();
    // assembled at runtime so the literal isn't in this file's bytes
    let aws_key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
    let payload = serde_json::json!({
        "tool_name": "Read",
        "tool_response": {"stdout": format!("aws_access_key_id = {aws_key}")}
    })
    .to_string();
    let (code, out) = post_eval(h.path(), &payload);

    // PostToolUse never blocks (the tool already ran) - always exit 0.
    assert_eq!(code, Some(0), "post-evaluate must not block; got {code:?}");
    assert_eq!(
        out["hookSpecificOutput"]["hookEventName"], "PostToolUse",
        "got {out}"
    );
    let ctx = out["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(
        ctx.contains("AWS access key"),
        "nudge must name the secret KIND; got {out}"
    );
    // Anti-leak: the secret value itself must never appear anywhere in the output.
    assert!(
        !serde_json::to_string(&out).unwrap().contains(&aws_key),
        "the matched secret value must never be echoed back; got {out}"
    );
}

#[test]
fn benign_result_emits_nothing() {
    let h = home();
    let payload = serde_json::json!({
        "tool_name": "Read",
        "tool_response": {"stdout": "hello world, no secrets here"}
    })
    .to_string();
    let (code, out) = post_eval(h.path(), &payload);
    assert_eq!(code, Some(0));
    assert_eq!(
        out,
        serde_json::json!({}),
        "a clean result emits an empty object"
    );
}

#[test]
fn degraded_input_stays_quiet_and_never_blocks() {
    let h = home();
    let (code, out) = post_eval(h.path(), "");
    assert_eq!(
        code,
        Some(0),
        "empty stdin must not block (nothing to deny post-hoc)"
    );
    assert_eq!(out, serde_json::json!({}));
}
