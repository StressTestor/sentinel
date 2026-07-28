use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::symlink;
use tempfile::TempDir;

const POLICY_UPDATE: &str = include_str!("fixtures/hooks/codex-policy-update.json");
const POLICY_MULTIFILE: &str = include_str!("fixtures/hooks/codex-policy-multifile.json");
const BENIGN_SECURITY_SOURCE: &str =
    include_str!("fixtures/hooks/codex-benign-security-source.json");
const HOOK_REMOVAL: &str = include_str!("fixtures/hooks/codex-hook-removal.json");
const AUTORUN_INJECTION: &str = include_str!("fixtures/hooks/codex-autorun-injection.json");

fn installed_home() -> TempDir {
    let home = TempDir::new().expect("temporary home");
    Command::cargo_bin("sentinel")
        .expect("sentinel binary")
        .env("HOME", home.path())
        .args(["install"])
        .assert()
        .success();
    home
}

fn evaluate(home: &TempDir, payload: &str) -> assert_cmd::assert::Assert {
    let mut command = Command::cargo_bin("sentinel").expect("sentinel binary");
    command
        .env("HOME", home.path())
        .args(["evaluate", "--agent", "codex"])
        .write_stdin(payload);
    command.assert()
}

fn assert_codex_deny(home: &TempDir, payload: &str) {
    let output = evaluate(home, payload).code(2).get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).expect("deny stdout is JSON");
    assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
}

fn patch_payload(operation: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": { "command": operation },
        "tool_use_id": "call_operation"
    })
    .to_string()
}

fn patch_payload_at(cwd: &std::path::Path, operation: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "apply_patch",
        "tool_input": { "command": operation },
        "tool_use_id": "call_operation",
        "cwd": cwd,
    })
    .to_string()
}

#[test]
fn codex_policy_mutations_deny_with_the_real_wire_contract() {
    let home = installed_home();
    for payload in [
        POLICY_UPDATE.to_string(),
        POLICY_MULTIFILE.to_string(),
        patch_payload(
            "*** Begin Patch\n*** Add File: ~/.sentinel/policy.toml\n+[policy]\n+mode = \"audit\"\n*** End Patch",
        ),
        patch_payload(
            "*** Begin Patch\n*** Delete File: ~/.sentinel/policy.toml\n*** End Patch",
        ),
        patch_payload(
            "*** Begin Patch\n*** Update File: ~/.sentinel/policy.toml\n*** Move to: ./policy.disabled\n@@\n-mode = \"enforce\"\n+mode = \"audit\"\n*** End Patch",
        ),
    ] {
        assert_codex_deny(&home, &payload);
    }
}

#[test]
fn codex_patch_cannot_remove_an_installed_hook_or_inject_autorun() {
    let home = installed_home();
    let claude = home.path().join(".claude");
    fs::create_dir_all(&claude).expect("create Claude config directory");
    fs::write(
        claude.join("settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"sentinel evaluate"}]}]}}"#,
    )
    .expect("write installed hook fixture");

    assert_codex_deny(&home, HOOK_REMOVAL);
    assert_codex_deny(&home, AUTORUN_INJECTION);
}

#[test]
fn codex_source_patch_is_not_misclassified_as_shell_execution() {
    let home = installed_home();
    let output = evaluate(&home, BENIGN_SECURITY_SOURCE)
        .code(0)
        .get_output()
        .clone();
    let json: Value = serde_json::from_slice(&output.stdout).expect("allow stdout is JSON");
    assert_eq!(json, serde_json::json!({}));
}

#[test]
fn malformed_codex_patch_fails_closed() {
    let home = installed_home();
    let payload =
        patch_payload("*** Begin Patch\n*** Update File: src/lib.rs\n+missing hunk and end marker");
    assert_codex_deny(&home, &payload);
}

#[test]
fn codex_patch_cannot_bypass_self_protection_through_existing_symlinks() {
    let home = installed_home();
    let alias = home.path().join("policy-alias.toml");
    symlink(home.path().join(".sentinel/policy.toml"), &alias).unwrap();
    let patch = "*** Begin Patch\n*** Update File: policy-alias.toml\n@@\n-mode = \"enforce\"\n+mode = \"audit\"\n*** End Patch";
    assert_codex_deny(&home, &patch_payload_at(home.path(), patch));

    let baseline = home.path().join(".sentinel/mcp-baseline.json");
    fs::write(&baseline, r#"{"version":1,"salt":"00","servers":{}}"#).unwrap();
    let baseline_alias = home.path().join("baseline-alias.json");
    symlink(&baseline, &baseline_alias).unwrap();
    let patch = format!(
        "*** Begin Patch\n*** Update File: {}\n@@\n-\"servers\":{{}}\n+\"servers\":{{\"evil\":\"accepted\"}}\n*** End Patch",
        baseline_alias.display()
    );
    assert_codex_deny(&home, &patch_payload(&patch));

    let ordinary = home.path().join("ordinary.txt");
    let ordinary_alias = home.path().join("ordinary-alias.txt");
    fs::write(&ordinary, "old\n").unwrap();
    symlink(&ordinary, &ordinary_alias).unwrap();
    let benign =
        "*** Begin Patch\n*** Update File: ordinary-alias.txt\n@@\n-old\n+new\n*** End Patch";
    let output = evaluate(&home, &patch_payload_at(home.path(), benign))
        .code(0)
        .get_output()
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        serde_json::json!({}),
        "an ordinary existing symlink must not be blanket-blocked"
    );
}

#[test]
fn codex_patch_to_mcp_baseline_is_self_protected() {
    let home = installed_home();
    for patch in [
        "*** Begin Patch\n*** Add File: ~/.sentinel/mcp-baseline.json\n+{}\n*** End Patch",
        "*** Begin Patch\n*** Delete File: ~/.sentinel/mcp-baseline.json\n*** End Patch",
    ] {
        assert_codex_deny(&home, &patch_payload(patch));
    }
}

#[test]
fn agent_cannot_accept_mcp_baseline_but_read_only_audit_still_runs() {
    let home = installed_home();
    let update = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "sentinel audit-mcp --update"},
        "tool_use_id": "call_update_baseline"
    })
    .to_string();
    assert_codex_deny(&home, &update);

    let strict = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "sentinel audit-mcp --strict"},
        "tool_use_id": "call_read_baseline"
    })
    .to_string();
    let output = evaluate(&home, &strict).code(0).get_output().clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        serde_json::json!({})
    );
}
