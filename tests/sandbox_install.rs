//! `sentinel install --sandbox` end to end, through the real binary in an
//! isolated HOME (the same pattern as `home_config.rs`): clean install,
//! reinstall idempotence, user entries preserved, uninstall removes only the
//! sentinel-owned entries, doctor reports drift, and self-protect blocks a
//! weakening settings write once the bridge is recorded.

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

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn install_sandbox(home: &Path) -> String {
    let output = sentinel(home)
        .args(["install", "--sandbox"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "install --sandbox failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn clean_home_install_writes_the_projection_and_a_record() {
    let home = tempdir().unwrap();
    let stdout = install_sandbox(home.path());
    assert!(stdout.contains("sandbox bridge: wrote"), "{stdout}");

    let settings = read_json(&settings_path(home.path()));
    assert!(settings["hooks"]["PreToolUse"].is_array());
    let sandbox = &settings["sandbox"];
    assert_eq!(sandbox["enabled"], true);
    assert_eq!(sandbox["failIfUnavailable"], true);
    assert_eq!(sandbox["allowUnsandboxedCommands"], false);
    let deny_read = strings(&sandbox["filesystem"]["denyRead"]);
    let deny_write = strings(&sandbox["filesystem"]["denyWrite"]);
    // the S1 projection on a Linux host with no mcp-baseline and no
    // settings.local.json: 41 denyRead, 41 denyWrite
    assert_eq!(deny_read.len(), 41, "{deny_read:#?}");
    assert_eq!(deny_write.len(), 41, "{deny_write:#?}");
    for entry in ["~/.ssh", "~/.aws", "~/.gnupg", "~/.netrc", "/etc/passwd"] {
        assert!(deny_read.contains(&entry.to_string()), "{entry}");
    }
    for entry in [
        "~/.ssh",
        "~/.sentinel/policy.toml",
        "~/.sentinel/install-state.json",
        "~/.claude/settings.json",
    ] {
        assert!(deny_write.contains(&entry.to_string()), "{entry}");
    }
    // the running binary is write-denied under its resolved path
    let exe = std::env::current_exe().unwrap();
    let bin = Command::cargo_bin("sentinel").unwrap();
    let bin_path = bin.get_program().to_string_lossy().into_owned();
    let bin_path = fs::canonicalize(&bin_path).unwrap_or_else(|_| bin_path.into());
    assert!(
        deny_write
            .iter()
            .any(|entry| Path::new(entry) == bin_path || Path::new(entry) == exe),
        "running binary missing from denyWrite: {deny_write:#?}"
    );
    // nothing absolute or wildcarded leaks into denyWrite from the rule set
    assert!(!deny_write.contains(&"/etc/passwd".to_string()));
    assert!(!deny_write.contains(&"/etc/shadow*".to_string()));
    assert!(deny_read.contains(&"/etc/shadow*".to_string()));

    let state = read_json(&state_path(home.path()));
    assert_eq!(state["version"], 1);
    assert_eq!(
        state["sandbox"]["settings_path"].as_str().unwrap(),
        settings_path(home.path()).to_string_lossy()
    );
    assert_eq!(strings(&state["sandbox"]["deny_read"]), deny_read);
    assert_eq!(strings(&state["sandbox"]["deny_write"]), deny_write);
    assert!(state["sandbox"]["prior"].as_object().unwrap().is_empty());
}

#[test]
fn reinstall_is_byte_for_byte_identical_and_plain_install_leaves_the_bridge() {
    let home = tempdir().unwrap();
    install_sandbox(home.path());
    let first = fs::read_to_string(settings_path(home.path())).unwrap();
    let first_state = fs::read_to_string(state_path(home.path())).unwrap();

    install_sandbox(home.path());
    assert_eq!(
        fs::read_to_string(settings_path(home.path())).unwrap(),
        first
    );
    assert_eq!(
        fs::read_to_string(state_path(home.path())).unwrap(),
        first_state
    );

    // a plain reinstall does not touch the sandbox keys or lists
    let output = sentinel(home.path()).arg("install").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("sandbox bridge is installed"));
    assert_eq!(
        fs::read_to_string(settings_path(home.path())).unwrap(),
        first
    );
}

#[test]
fn user_entries_and_user_keys_survive_install_and_uninstall() {
    let home = tempdir().unwrap();
    let claude = home.path().join(".claude");
    fs::create_dir_all(&claude).unwrap();
    let existing = json!({
        "theme": "dark",
        "sandbox": {
            "enabled": true,
            "excludedCommands": ["docker *"],
            "filesystem": {
                "denyRead": ["~/mine", "~/.ssh"],
                "allowWrite": ["~/scratch"]
            },
            "network": {"allowedDomains": ["crates.io"]}
        }
    });
    fs::write(
        settings_path(home.path()),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    let stdout = install_sandbox(home.path());
    assert!(
        stdout.contains("1 projected entries were already present"),
        "{stdout}"
    );
    let settings = read_json(&settings_path(home.path()));
    assert_eq!(settings["theme"], "dark");
    assert_eq!(settings["sandbox"]["enabled"], true);
    assert_eq!(settings["sandbox"]["excludedCommands"], json!(["docker *"]));
    assert_eq!(
        settings["sandbox"]["filesystem"]["allowWrite"],
        json!(["~/scratch"])
    );
    assert_eq!(
        settings["sandbox"]["network"]["allowedDomains"],
        json!(["crates.io"])
    );
    let deny_read = strings(&settings["sandbox"]["filesystem"]["denyRead"]);
    assert_eq!(&deny_read[..2], ["~/mine", "~/.ssh"], "user order kept");
    assert_eq!(deny_read.iter().filter(|e| *e == "~/.ssh").count(), 1);

    // the record owns everything except the entry the user already had, and
    // remembers that enabled was already true (user-set)
    let state = read_json(&state_path(home.path()));
    let owned_read = strings(&state["sandbox"]["deny_read"]);
    assert!(!owned_read.contains(&"~/.ssh".to_string()));
    assert!(!owned_read.contains(&"~/mine".to_string()));
    assert_eq!(state["sandbox"]["prior"]["enabled"], true);
    assert!(state["sandbox"]["prior"]
        .get("fail_if_unavailable")
        .is_none());

    let output = sentinel(home.path()).arg("uninstall").output().unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(String::from_utf8_lossy(&output.stdout).contains("sentinel-owned sandbox entries"));
    let after = read_json(&settings_path(home.path()));
    assert_eq!(after["theme"], "dark");
    assert!(after.get("hooks").is_none_or(|hooks| hooks["PreToolUse"]
        .as_array()
        .is_none_or(|entries| entries.is_empty())));
    assert_eq!(
        after["sandbox"],
        json!({
            "enabled": true,
            "excludedCommands": ["docker *"],
            "filesystem": {
                "denyRead": ["~/mine", "~/.ssh"],
                "allowWrite": ["~/scratch"]
            },
            "network": {"allowedDomains": ["crates.io"]}
        }),
        "uninstall restores the user's sandbox block exactly"
    );
    let state = read_json(&state_path(home.path()));
    assert!(state.get("sandbox").is_none());
}

#[test]
fn clean_install_then_uninstall_leaves_no_sandbox_block() {
    let home = tempdir().unwrap();
    install_sandbox(home.path());
    let output = sentinel(home.path()).arg("uninstall").output().unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let after = read_json(&settings_path(home.path()));
    assert!(after.get("sandbox").is_none(), "{after}");
    // a second uninstall is a no-op
    let output = sentinel(home.path()).arg("uninstall").output().unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("sandbox entries"));
}

#[test]
fn sandbox_flag_is_refused_for_other_agents_before_any_write() {
    let home = tempdir().unwrap();
    for agent in ["codex", "gemini"] {
        let output = sentinel(home.path())
            .args(["install", "--sandbox", "--agent", agent])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{agent}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Claude Code only"), "{agent}: {stderr}");
        assert!(!home.path().join(".sentinel").exists(), "{agent}");
        assert!(!home.path().join(".codex").exists(), "{agent}");
    }
}

#[test]
fn status_and_doctor_report_the_bridge_and_fail_strict_on_drift() {
    let home = tempdir().unwrap();
    let status = sentinel(home.path()).arg("status").output().unwrap();
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("sandbox:  bridge not installed")
            || !status.status.success()
    );

    install_sandbox(home.path());
    let status = sentinel(home.path()).arg("status").output().unwrap();
    assert!(status.status.success(), "{:?}", status.stderr);
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains(
            "sandbox:  enabled=true failIfUnavailable=true allowUnsandboxedCommands=false"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("no drift"), "{stdout}");
    assert!(stdout.contains("hook-only: /proc/*/environ"), "{stdout}");

    let doctor = sentinel(home.path())
        .args(["doctor", "--strict", "--json"])
        .output()
        .unwrap();
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(report["healthy"], true, "{report}");
    assert_eq!(report["sandbox"]["installed"], true);
    assert_eq!(report["sandbox"]["drift"], false);
    assert_eq!(report["sandbox"]["denyRead"]["present"], 41);
    assert_eq!(report["sandbox"]["denyRead"]["missing"], json!([]));

    // drift: an owned entry disappears from the live list, and the user adds one
    let path = settings_path(home.path());
    let mut settings = read_json(&path);
    let list = settings["sandbox"]["filesystem"]["denyRead"]
        .as_array_mut()
        .unwrap();
    list.retain(|entry| entry != "~/.aws");
    list.push(json!("~/mine"));
    fs::write(&path, serde_json::to_string_pretty(&settings).unwrap()).unwrap();

    let doctor = sentinel(home.path())
        .args(["doctor", "--strict", "--json"])
        .output()
        .unwrap();
    assert!(!doctor.status.success(), "drift must fail --strict");
    let report: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(report["healthy"], false);
    assert_eq!(report["sandbox"]["drift"], true);
    assert_eq!(report["sandbox"]["denyRead"]["missing"], json!(["~/.aws"]));
    assert_eq!(report["sandbox"]["denyRead"]["user"], 1);
    let checks = report["checks"].as_array().unwrap();
    assert!(checks.iter().any(|check| {
        check["level"] == "ERR"
            && check["message"]
                .as_str()
                .unwrap()
                .contains("drift in denyRead")
    }));
    assert!(checks.iter().any(|check| {
        check["level"] == "OK"
            && check["message"]
                .as_str()
                .unwrap()
                .contains("1 user entries")
    }));

    let human = sentinel(home.path()).args(["doctor"]).output().unwrap();
    assert!(String::from_utf8_lossy(&human.stdout).contains("[ERR] sandbox: drift in denyRead"));

    // re-running install --sandbox repairs the drift and keeps the user entry
    install_sandbox(home.path());
    let doctor = sentinel(home.path())
        .args(["doctor", "--strict"])
        .output()
        .unwrap();
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stdout)
    );
    let repaired = strings(&read_json(&path)["sandbox"]["filesystem"]["denyRead"]);
    assert!(repaired.contains(&"~/.aws".to_string()));
    assert!(repaired.contains(&"~/mine".to_string()));

    // the codex doctor has no sandbox row
    let codex = sentinel(home.path())
        .args(["doctor", "--agent", "codex", "--json"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&codex.stdout).unwrap();
    assert!(report["sandbox"].is_null());
}

#[test]
fn self_protect_blocks_a_weakening_settings_write_only_once_the_bridge_exists() {
    let home = tempdir().unwrap();
    let path = settings_path(home.path());
    let check = |home: &Path, content: &Value| -> Value {
        let payload = json!({
            "tool_name": "Write",
            "tool_input": {"file_path": path, "content": content.to_string()}
        });
        let output = sentinel(home)
            .args(["check", "--json"])
            .arg(payload.to_string())
            .output()
            .unwrap();
        serde_json::from_slice(&output.stdout).unwrap()
    };

    // hook only, no bridge: a settings write that turns the sandbox off is the
    // policy's warn-tier settings write, nothing more
    let output = sentinel(home.path()).arg("install").output().unwrap();
    assert!(output.status.success());
    let mut off = read_json(&path);
    off["sandbox"] = json!({"enabled": false});
    let response = check(home.path(), &off);
    assert_eq!(response["blocks"], false, "{response}");

    install_sandbox(home.path());
    let installed = read_json(&path);

    let mut disabled = installed.clone();
    disabled["sandbox"]["enabled"] = json!(false);
    let response = check(home.path(), &disabled);
    assert_eq!(response["blocks"], true, "{response}");
    assert_eq!(response["matched_rule"], "selfprotect: sandbox-weakening");

    let mut unsandboxed = installed.clone();
    unsandboxed["sandbox"]["allowUnsandboxedCommands"] = json!(true);
    assert_eq!(check(home.path(), &unsandboxed)["blocks"], true);

    let mut excluded = installed.clone();
    excluded["sandbox"]["excludedCommands"] = json!(["gh *"]);
    assert_eq!(check(home.path(), &excluded)["blocks"], true);

    let mut dropped = installed.clone();
    dropped["sandbox"]["filesystem"]["denyRead"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry != "~/.ssh");
    let response = check(home.path(), &dropped);
    assert_eq!(response["blocks"], true, "{response}");
    assert!(response["reason"]
        .as_str()
        .unwrap()
        .contains("sentinel-owned entry `~/.ssh`"));

    // an edit that keeps every sentinel key stays at the policy's action
    let mut kept = installed.clone();
    kept["model"] = json!("sonnet");
    kept["sandbox"]["filesystem"]["denyRead"]
        .as_array_mut()
        .unwrap()
        .push(json!("~/mine"));
    let response = check(home.path(), &kept);
    assert_eq!(response["blocks"], false, "{response}");
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        serde_json::to_string_pretty(&installed).unwrap(),
        "check never writes"
    );
}
