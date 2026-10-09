//! `sentinel session-check` end to end, through the real binary in an isolated
//! HOME (the same pattern as `home_config.rs` and `sandbox_install.rs`): a
//! clean install pins the digests and registers the SessionStart entry, a
//! clean check prints nothing and exits 0, every mismatch is one finding and
//! still exits 0, uninstall removes only the sentinel-owned entry, and doctor
//! reports the row.

use assert_cmd::Command;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn sentinel(home: &Path) -> Command {
    let mut command = Command::cargo_bin("sentinel").unwrap();
    command
        .current_dir(home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env("HOME", home);
    command
}

fn settings_path(home: &Path) -> std::path::PathBuf {
    home.join(".claude/settings.json")
}

fn state_path(home: &Path) -> std::path::PathBuf {
    home.join(".sentinel/install-state.json")
}

fn policy_path(home: &Path) -> std::path::PathBuf {
    home.join(".sentinel/policy.toml")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

fn install(home: &Path) -> String {
    let output = sentinel(home).arg("install").output().unwrap();
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// the SessionStart payload Claude Code sends; the check must drain and never
/// echo it
const SESSION_START_PAYLOAD: &str = r#"{"session_id":"abc","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","hook_event_name":"SessionStart","source":"startup"}"#;

struct Check {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

fn session_check(home: &Path, json: bool) -> Check {
    let mut command = sentinel(home);
    command.arg("session-check");
    if json {
        command.arg("--json");
    }
    let output = command.write_stdin(SESSION_START_PAYLOAD).output().unwrap();
    Check {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        code: output.status.code(),
    }
}

fn findings(home: &Path) -> (bool, Vec<(String, String)>, Value) {
    let check = session_check(home, true);
    assert_eq!(check.code, Some(0), "--json must exit 0: {}", check.stderr);
    let report: Value = serde_json::from_str(&check.stdout).unwrap_or_else(|error| {
        panic!(
            "--json stdout must be the object only: {error}\n{}",
            check.stdout
        )
    });
    let findings = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| {
            (
                finding["kind"].as_str().unwrap().to_string(),
                finding["detail"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    (report["ok"].as_bool().unwrap(), findings, report)
}

#[test]
fn install_registers_the_sessionstart_entry_and_pins_both_digests() {
    let home = tempdir().unwrap();
    let stdout = install(home.path());
    assert!(stdout.contains("SessionStart integrity check"), "{stdout}");
    assert!(
        stdout.contains("pinned the binary and policy digests"),
        "{stdout}"
    );

    let settings = read_json(&settings_path(home.path()));
    let start = settings["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(start.len(), 1);
    assert_eq!(start[0]["matcher"], "startup|resume");
    let command = start[0]["hooks"][0]["command"].as_str().unwrap();
    assert!(command.ends_with(" session-check"), "{command}");
    let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre.len(), 1);
    let pre_command = pre[0]["hooks"][0]["command"].as_str().unwrap();
    assert_eq!(
        command.strip_suffix(" session-check"),
        pre_command.strip_suffix(" evaluate"),
        "both entries point at the same binary"
    );

    let state = read_json(&state_path(home.path()));
    assert_eq!(state["version"], 1);
    assert_eq!(state["binary_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(state["policy_sha256"].as_str().unwrap().len(), 64);
    assert!(state.get("sandbox").is_none());

    // a reinstall keeps one entry and the same pins
    install(home.path());
    let again = read_json(&settings_path(home.path()));
    assert_eq!(again["hooks"]["SessionStart"].as_array().unwrap().len(), 1);
    assert_eq!(read_json(&state_path(home.path())), state);
}

#[test]
fn a_clean_check_prints_nothing_and_exits_zero() {
    let home = tempdir().unwrap();
    install(home.path());
    let check = session_check(home.path(), false);
    assert_eq!(check.code, Some(0));
    assert_eq!(check.stdout, "", "clean check must add nothing to context");
    assert_eq!(check.stderr, "");

    let (ok, findings, report) = findings(home.path());
    assert!(ok, "{report}");
    assert!(findings.is_empty());
    assert_eq!(report["agent"], "claude-code");
    let state = read_json(&state_path(home.path()));
    assert_eq!(report["pins"]["binary_sha256"], state["binary_sha256"]);
    assert_eq!(report["pins"]["policy_sha256"], state["policy_sha256"]);
    assert_eq!(report["pins"]["sandbox_recorded"], false);
    assert_eq!(report["live"]["binary_sha256"], state["binary_sha256"]);
    assert_eq!(report["live"]["policy_sha256"], state["policy_sha256"]);
    let text = report.to_string();
    assert!(
        !text.contains("transcript_path") && !text.contains("abc"),
        "the payload never reaches the output: {text}"
    );
}

#[test]
fn each_mismatch_is_a_finding_on_stdout_and_stderr_and_still_exits_zero() {
    let home = tempdir().unwrap();
    install(home.path());

    // policy edited after install
    let policy = policy_path(home.path());
    let mut content = fs::read_to_string(&policy).unwrap();
    content.push_str("\n# edited after install\n");
    fs::write(&policy, content).unwrap();
    let check = session_check(home.path(), false);
    assert_eq!(check.code, Some(0));
    assert!(check.stdout.starts_with("sentinel: "), "{}", check.stdout);
    assert!(
        check
            .stdout
            .contains("differs from the policy pinned at install"),
        "{}",
        check.stdout
    );
    assert_eq!(
        check.stdout, check.stderr,
        "the same line goes to both streams"
    );
    assert_eq!(check.stdout.lines().count(), 1);
    let (ok, found, _) = findings(home.path());
    assert!(!ok);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "policy");

    // binary pin no longer matches the binary the hook runs
    let state_file = state_path(home.path());
    let mut state = read_json(&state_file);
    state["binary_sha256"] = json!("0".repeat(64));
    write_json(&state_file, &state);
    let (ok, found, _) = findings(home.path());
    assert!(!ok);
    let kinds: Vec<&str> = found.iter().map(|(kind, _)| kind.as_str()).collect();
    assert_eq!(kinds, ["binary", "policy"]);
    assert!(found[0]
        .1
        .contains("differs from the one pinned at install"));
    let check = session_check(home.path(), false);
    assert_eq!(check.code, Some(0));
    assert_eq!(check.stdout.lines().count(), 2);
    assert!(check
        .stdout
        .lines()
        .all(|line| line.starts_with("sentinel: ")));

    // re-pinning through a reinstall clears both
    install(home.path());
    let check = session_check(home.path(), false);
    assert_eq!((check.code, check.stdout.as_str()), (Some(0), ""));

    // the PreToolUse entry removed by hand
    let settings_file = settings_path(home.path());
    let mut settings = read_json(&settings_file);
    settings["hooks"]
        .as_object_mut()
        .unwrap()
        .remove("PreToolUse");
    write_json(&settings_file, &settings);
    let check = session_check(home.path(), false);
    assert_eq!(check.code, Some(0));
    assert!(
        check
            .stdout
            .contains("no sentinel PreToolUse hook is registered"),
        "{}",
        check.stdout
    );
    let (ok, found, report) = findings(home.path());
    assert!(!ok);
    assert_eq!(found.len(), 1, "{report}");
    assert_eq!(found[0].0, "hook");
    assert_eq!(report["live"]["binary_sha256"], Value::Null);

    // the hook disabled by the host switch
    install(home.path());
    let mut settings = read_json(&settings_file);
    settings["disableAllHooks"] = json!(true);
    write_json(&settings_file, &settings);
    let (ok, found, _) = findings(home.path());
    assert!(!ok);
    assert_eq!(found[0].0, "hook");
    assert!(found[0].1.contains("disabled"), "{}", found[0].1);
}

#[test]
fn an_install_without_pins_is_clean_and_reported_as_unpinned() {
    let home = tempdir().unwrap();
    install(home.path());
    // an install from before the pins existed
    let state_file = state_path(home.path());
    fs::write(&state_file, "{\"version\":1}\n").unwrap();
    let check = session_check(home.path(), false);
    assert_eq!((check.code, check.stdout.as_str()), (Some(0), ""));
    let (ok, found, report) = findings(home.path());
    assert!(ok, "{report}");
    assert!(found.is_empty());
    assert_eq!(report["pins"]["binary_sha256"], Value::Null);
    assert_eq!(report["pins"]["policy_sha256"], Value::Null);
    assert!(report["live"]["binary_sha256"].is_string());

    // no state file at all, and an unreadable one
    fs::remove_file(&state_file).unwrap();
    let (ok, _, _) = findings(home.path());
    assert!(ok);
    fs::write(&state_file, "not json").unwrap();
    let check = session_check(home.path(), false);
    assert_eq!(check.code, Some(0));
    assert!(check.stdout.contains("install state cannot be read"));
    let (_, found, _) = findings(home.path());
    assert_eq!(found[0].0, "state");

    // doctor: the hook is wired, the pins are not; strict still passes
    fs::remove_file(&state_file).unwrap();
    let doctor = sentinel(home.path())
        .args(["doctor", "--strict", "--json"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(report["healthy"], true, "{report}");
    assert_eq!(report["session_check"]["hook_registered"], true);
    assert_eq!(report["session_check"]["binary_pinned"], false);
    assert!(report["checks"].as_array().unwrap().iter().any(|check| {
        check["level"] == "WARN"
            && check["message"]
                .as_str()
                .unwrap()
                .contains("no binary or policy digest is pinned")
    }));
}

#[test]
fn doctor_reports_the_row_and_uninstall_removes_only_sentinel_entries() {
    let home = tempdir().unwrap();
    let claude = home.path().join(".claude");
    fs::create_dir_all(&claude).unwrap();
    write_json(
        &settings_path(home.path()),
        &json!({
            "theme": "dark",
            "hooks": {
                "SessionStart": [
                    {"matcher": "startup", "hooks": [{"type": "command", "command": "echo welcome"}]}
                ]
            }
        }),
    );
    install(home.path());
    let settings = read_json(&settings_path(home.path()));
    let start = settings["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(start.len(), 2, "{settings}");
    assert_eq!(start[0]["hooks"][0]["command"], "echo welcome");

    let doctor = sentinel(home.path())
        .args(["doctor", "--strict", "--json"])
        .output()
        .unwrap();
    assert!(doctor.status.success(), "{:?}", doctor.stderr);
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(
        report["session_check"],
        json!({"hook_registered": true, "binary_pinned": true, "policy_pinned": true}),
        "{report}"
    );
    assert!(report["checks"].as_array().unwrap().iter().any(|check| {
        check["level"] == "OK"
            && check["message"]
                .as_str()
                .unwrap()
                .starts_with("session-check: SessionStart hook registered")
    }));
    let human = sentinel(home.path()).arg("doctor").output().unwrap();
    assert!(String::from_utf8_lossy(&human.stdout).contains("[OK] session-check:"));

    let output = sentinel(home.path()).arg("uninstall").output().unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(String::from_utf8_lossy(&output.stdout).contains("SessionStart"));
    let after = read_json(&settings_path(home.path()));
    assert_eq!(after["theme"], "dark");
    let start = after["hooks"]["SessionStart"].as_array().unwrap();
    assert_eq!(start.len(), 1, "{after}");
    assert_eq!(start[0]["hooks"][0]["command"], "echo welcome");
    assert!(after["hooks"]["PreToolUse"]
        .as_array()
        .is_none_or(|entries| entries.is_empty()));
    let state = read_json(&state_path(home.path()));
    assert!(state.get("binary_sha256").is_none(), "{state}");
    assert!(state.get("policy_sha256").is_none(), "{state}");

    // the check after uninstall reports the missing hook and nothing else
    let (ok, found, _) = findings(home.path());
    assert!(!ok);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, "hook");

    // the codex doctor has no session-check row
    let codex = sentinel(home.path())
        .args(["doctor", "--agent", "codex", "--json"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&codex.stdout).unwrap();
    assert!(report["session_check"].is_null());
}

#[test]
fn sandbox_drift_is_a_finding_once_the_bridge_is_recorded() {
    let home = tempdir().unwrap();
    let output = sentinel(home.path())
        .args(["install", "--sandbox"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let (ok, found, report) = findings(home.path());
    assert!(ok, "{found:?}");
    assert_eq!(report["pins"]["sandbox_recorded"], true);

    let path = settings_path(home.path());
    let mut settings = read_json(&path);
    settings["sandbox"]["filesystem"]["denyRead"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry != "~/.aws");
    settings["sandbox"]["allowUnsandboxedCommands"] = json!(true);
    write_json(&path, &settings);
    let check = session_check(home.path(), false);
    assert_eq!(check.code, Some(0));
    let (ok, found, _) = findings(home.path());
    assert!(!ok);
    let kinds: Vec<&str> = found.iter().map(|(kind, _)| kind.as_str()).collect();
    assert_eq!(kinds, ["sandbox", "sandbox"], "{found:?}");
    assert!(found[0].1.contains("allowUnsandboxedCommands=true"));
    assert!(found[1].1.contains("1 projected entries missing"));
}

#[test]
fn unsupported_agent_and_invalid_home_are_findings_not_failures() {
    let home = tempdir().unwrap();
    let output = sentinel(home.path())
        .args(["session-check", "--agent", "gemini"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("does not support agent"));

    let output = Command::cargo_bin("sentinel")
        .unwrap()
        .current_dir(home.path())
        .env_remove("HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .arg("session-check")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("HOME"));
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}
