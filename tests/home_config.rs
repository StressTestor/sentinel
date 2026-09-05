use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn command(cwd: &Path, home: Option<&str>) -> Command {
    let mut command = Command::cargo_bin("sentinel").unwrap();
    command
        .current_dir(cwd)
        .env_remove("HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME");
    if let Some(home) = home {
        command.env("HOME", home);
    }
    command
}

#[test]
fn invalid_home_is_rejected_before_install_or_uninstall_changes_files() {
    for home in [None, Some(""), Some("relative-home")] {
        let dir = tempdir().unwrap();
        let settings = dir.path().join("settings.json");
        fs::write(&settings, "{\"theme\":\"dark\"}").unwrap();
        for operation in ["install", "uninstall"] {
            let output = command(dir.path(), home)
                .env("CLAUDE_CONFIG_DIR", dir.path())
                .arg(operation)
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("HOME"));
            assert_eq!(
                fs::read_to_string(&settings).unwrap(),
                "{\"theme\":\"dark\"}"
            );
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}

#[test]
fn invalid_home_keeps_the_hook_failure_response_machine_readable() {
    for home in [None, Some(""), Some("relative-home")] {
        let dir = tempdir().unwrap();
        let output = command(dir.path(), home)
            .arg("evaluate")
            .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"./README.md"}}"#)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn explicit_policy_lint_does_not_require_home() {
    let dir = tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    fs::write(&policy, "[policy]\nmode = \"enforce\"\n").unwrap();
    command(dir.path(), None)
        .arg("policy-lint")
        .arg("--policy")
        .arg(policy)
        .assert()
        .success();
}

#[test]
fn project_audit_fixture_is_independent_of_the_live_audit_trail() {
    let home = tempdir().unwrap();
    let project = tempdir().unwrap();
    fs::create_dir(home.path().join(".sentinel")).unwrap();
    fs::write(
        home.path().join(".sentinel/policy.toml"),
        "[policy]\nmode = \"enforce\"\non_failure = \"closed\"\ndefault = \"allow\"\n",
    )
    .unwrap();
    fs::create_dir(project.path().join(".sentinel")).unwrap();
    let fixture = project.path().join(".sentinel/audit.jsonl");
    fs::write(&fixture, "fixture record\n").unwrap();
    let payload = serde_json::json!({
        "tool_name": "Write",
        "cwd": project.path(),
        "tool_input": {"file_path": ".sentinel/audit.jsonl", "content": "updated fixture\n"}
    });
    let output = command(project.path(), home.path().to_str())
        .args(["check", "--json"])
        .arg(payload.to_string())
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["blocks"], false, "{response}");
    assert_eq!(fs::read_to_string(fixture).unwrap(), "fixture record\n");
    let mut live_payload = payload;
    live_payload["tool_input"]["file_path"] =
        serde_json::json!(home.path().join(".sentinel/audit.jsonl"));
    let output = command(project.path(), home.path().to_str())
        .args(["check", "--json"])
        .arg(live_payload.to_string())
        .output()
        .unwrap();
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["blocks"], true, "{response}");
    assert_eq!(response["matched_rule"], "selfprotect: audit-trail write");
    assert!(!home.path().join(".sentinel/audit.jsonl").exists());
}

#[test]
fn relocated_claude_install_status_and_uninstall_share_the_same_file() {
    let home = tempdir().unwrap();
    let config = tempdir().unwrap();
    let settings = config.path().join("settings.json");
    fs::write(&settings, "{\"theme\":\"dark\"}").unwrap();
    let run = |operation: &str| {
        command(home.path(), home.path().to_str())
            .env("CLAUDE_CONFIG_DIR", config.path())
            .arg(operation)
            .output()
            .unwrap()
    };
    let install = run("install");
    assert!(install.status.success(), "{:?}", install.stderr);
    let installed: Value = serde_json::from_slice(&fs::read(&settings).unwrap()).unwrap();
    assert_eq!(installed["theme"], "dark");
    assert!(installed["hooks"]["PreToolUse"].is_array());
    assert!(!home.path().join(".claude").exists());
    let status = run("status");
    assert!(status.status.success(), "{:?}", status.stderr);
    assert!(String::from_utf8_lossy(&status.stdout).contains(settings.to_str().unwrap()));
    let uninstall = run("uninstall");
    assert!(uninstall.status.success(), "{:?}", uninstall.stderr);
    let remaining: Value = serde_json::from_slice(&fs::read(settings).unwrap()).unwrap();
    assert_eq!(remaining["theme"], "dark");
    assert!(home.path().join(".sentinel/policy.toml").exists());
}
