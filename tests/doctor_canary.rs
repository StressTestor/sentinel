//! Doctor liveness canary — the spoof-shim regression suite (finding #6).
//!
//! The old canary "proved" liveness with two checks that never exercised the
//! hooked binary's enforcement: (a) `--version` output contains "sentinel" and
//! (b) an IN-PROCESS policy evaluation inside doctor itself. A shim that prints
//! "sentinel 0.2.1" on `--version` and no-ops `evaluate` passed both, so doctor
//! reported HEALTHY while enforcement was dead. These tests drive the real
//! `sentinel` binary end-to-end and assert:
//!   1. the spoof shim is caught (doctor unhealthy),
//!   2. a genuine enforce install still reads healthy, with NO audit pollution,
//!   3. a genuine audit-mode install reads WARN (would-deny) — the `--canary`
//!      flag is what makes the probe see the would-be decision there,
//!   4. `evaluate --canary` reports the would-be deny without logging, and
//!   5. plain `evaluate` behavior is unchanged (logs, audit mode never blocks).

use assert_cmd::Command;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

const KNOWN_BAD: &str = r#"{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}"#;
const BENIGN: &str = r#"{"tool_name":"Read","tool_input":{"file_path":"src/main.rs"}}"#;

fn write_policy(home: &Path, mode: &str) {
    let dir = home.join(".sentinel");
    fs::create_dir_all(&dir).unwrap();
    let policy = format!(
        r#"
[policy]
mode = "{mode}"
on_failure = "closed"
default = "allow"

[[deny.paths]]
pattern = "~/.ssh/*"
action = "block"
reason = "SSH key access"
"#
    );
    fs::write(dir.join("policy.toml"), policy).unwrap();
}

fn write_settings(home: &Path, hook_cmd: &str) {
    let dir = home.join(".claude");
    fs::create_dir_all(&dir).unwrap();
    let settings = serde_json::json!({
        "hooks": {
            "PreToolUse": [
                {"matcher": ".*", "hooks": [{"type": "command", "command": hook_cmd}]}
            ]
        }
    });
    fs::write(
        dir.join("settings.json"),
        serde_json::to_string_pretty(&settings).unwrap(),
    )
    .unwrap();
}

/// A shim that beats the OLD canary: identifies as sentinel on `--version`,
/// silently no-ops everything else (consumes stdin, prints nothing, exits 0).
/// With this installed as the hook, enforcement is dead.
fn write_spoof_shim(home: &Path) -> PathBuf {
    let shim = home.join("sentinel");
    fs::write(
        &shim,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo \"sentinel 0.2.1\"\n  exit 0\nfi\ncat > /dev/null 2>&1\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    shim
}

fn doctor_json(home: &Path) -> serde_json::Value {
    let assert = Command::cargo_bin("sentinel")
        .unwrap()
        .args(["doctor", "--json"])
        .env("HOME", home)
        .assert()
        .success(); // doctor only exits non-zero under --strict
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("doctor --json emitted invalid JSON: {e}\n{stdout}"))
}

/// (level, message) of the liveness check line in a doctor JSON report.
fn liveness_check(report: &serde_json::Value) -> (String, String) {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["message"].as_str().unwrap_or("").starts_with("liveness:"))
        .map(|c| {
            (
                c["level"].as_str().unwrap().to_string(),
                c["message"].as_str().unwrap().to_string(),
            )
        })
        .unwrap_or_else(|| panic!("no liveness check in report: {report}"))
}

fn run_evaluate(home: &Path, args: &[&str], stdin: &str) -> serde_json::Value {
    let assert = Command::cargo_bin("sentinel")
        .unwrap()
        .args(args)
        .env("HOME", home)
        .write_stdin(stdin)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("evaluate stdout was not valid JSON: {e}\nstdout: {stdout:?}"))
}

fn is_nested_deny(v: &serde_json::Value) -> bool {
    v["hookSpecificOutput"]["permissionDecision"] == "deny"
}

/// THE regression test for finding #6: a hooked "binary" that runs, prints
/// "sentinel 0.2.1" on --version, but does NOT deny on evaluate must NOT read
/// healthy. The old in-process canary reported HEALTHY here.
#[test]
fn spoof_shim_that_noops_evaluate_is_caught() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    write_policy(home, "enforce");
    let shim = write_spoof_shim(home);
    write_settings(home, &format!("{} evaluate", shim.display()));

    let report = doctor_json(home);
    let (level, msg) = liveness_check(&report);

    assert_eq!(
        report["healthy"], false,
        "a spoof shim (no-op evaluate) must NOT read healthy; report: {report}"
    );
    assert_eq!(level, "ERR", "spoofed liveness must be an ERR line, got {level}: {msg}");
}

#[test]
fn real_binary_enforce_install_is_healthy_and_does_not_pollute_audit_trail() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    write_policy(home, "enforce");
    write_settings(home, &format!("{} evaluate", env!("CARGO_BIN_EXE_sentinel")));

    let report = doctor_json(home);
    let (level, _) = liveness_check(&report);

    assert_eq!(report["healthy"], true, "genuine enforce install must be healthy: {report}");
    assert_eq!(level, "OK");
    // the synthetic known-bad probe must never land in the audit trail
    assert!(
        !home.join(".sentinel").join("audit.jsonl").exists(),
        "doctor's canary probe polluted the audit trail"
    );
}

/// the audit-mode nuance: the live hook emits {} in audit mode (never blocks),
/// so a naive spawn of plain `evaluate` would read NoDecision -> ERR even on a
/// perfectly healthy audit install. `evaluate --canary` reports the would-be
/// decision, so doctor reads Denied -> WARN ("would deny, but audit only logs").
#[test]
fn audit_mode_real_binary_reads_would_deny_warn_not_err() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    write_policy(home, "audit");
    write_settings(home, &format!("{} evaluate", env!("CARGO_BIN_EXE_sentinel")));

    let report = doctor_json(home);
    let (level, msg) = liveness_check(&report);

    assert_eq!(report["healthy"], true, "a healthy audit install must not fail doctor: {report}");
    assert_eq!(level, "WARN", "audit + would-deny is WARN, got {level}: {msg}");
    assert!(
        !home.join(".sentinel").join("audit.jsonl").exists(),
        "doctor's canary probe polluted the audit trail"
    );
}

#[test]
fn evaluate_canary_reports_would_be_deny_in_audit_mode_without_logging() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    write_policy(home, "audit");

    let out = run_evaluate(home, &["evaluate", "--canary"], KNOWN_BAD);

    assert!(
        is_nested_deny(&out),
        "--canary must surface the would-be deny even in audit mode; got: {out}"
    );
    assert!(
        !home.join(".sentinel").join("audit.jsonl").exists(),
        "--canary must not write to the audit trail"
    );
}

#[test]
fn evaluate_canary_emits_allow_for_benign_input() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    write_policy(home, "enforce");

    let out = run_evaluate(home, &["evaluate", "--canary"], BENIGN);

    assert_eq!(out, serde_json::json!({}), "benign canary input must defer (empty object)");
    assert!(
        !home.join(".sentinel").join("audit.jsonl").exists(),
        "--canary must not write to the audit trail"
    );
}

/// the normal hot path must be untouched: audit mode logs the would-block and
/// emits {} (never blocks).
#[test]
fn evaluate_normal_path_still_logs_and_never_blocks_in_audit_mode() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    write_policy(home, "audit");

    let out = run_evaluate(home, &["evaluate"], KNOWN_BAD);

    assert_eq!(out, serde_json::json!({}), "audit mode never blocks");
    let trail = fs::read_to_string(home.join(".sentinel").join("audit.jsonl"))
        .expect("normal evaluate must log to the audit trail");
    assert!(
        trail.contains("\"block\""),
        "the would-block decision must be logged in audit mode; trail: {trail}"
    );
}

/// the normal enforce path must be untouched: deny JSON AND an audit entry.
#[test]
fn evaluate_normal_path_still_logs_and_denies_in_enforce_mode() {
    let dir = tempdir().unwrap();
    let home = dir.path();
    write_policy(home, "enforce");

    let out = run_evaluate(home, &["evaluate"], KNOWN_BAD);

    assert!(is_nested_deny(&out), "enforce mode must deny the known-bad; got: {out}");
    assert!(
        home.join(".sentinel").join("audit.jsonl").exists(),
        "normal evaluate must log to the audit trail"
    );
}
