//! process-level tests exercising `sentinel evaluate` through actual stdin/stdout.
//! covers the boundary paths that evaluate_for_test (unit tests) can't:
//! empty stdin, unknown schema, policy load failure.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn empty_stdin_passes_through_as_allow() {
    // empty stdin = graceful degradation: no decision key (which the hook
    // interprets as allow), with a "pass-through" reason in the tracing log.
    Command::cargo_bin("sentinel")
        .unwrap()
        .arg("evaluate")
        .write_stdin("")
        .assert()
        .success()
        // no "deny" decision in stdout on empty input
        .stdout(predicate::str::contains("deny").not());
}

#[test]
fn unknown_schema_passes_through_as_allow() {
    // Unknown top-level shape. Our HookInput uses #[serde(flatten)] catch-all
    // with default tool_input, so most "unknown schemas" actually parse.
    // Pass a syntactically invalid JSON instead to force the unknown-schema path.
    Command::cargo_bin("sentinel")
        .unwrap()
        .arg("evaluate")
        .write_stdin("not valid json at all {{{")
        .assert()
        .success()
        .stdout(predicate::str::contains("deny").not());
}

fn write_policy_home(mode: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    let sentinel_dir = dir.path().join(".sentinel");
    fs::create_dir_all(&sentinel_dir).unwrap();
    fs::write(
        sentinel_dir.join("policy.toml"),
        format!(
            r#"[policy]
mode = "{mode}"
on_failure = "closed"
default = "warn"

[heuristic]
sensitivity = "medium"
window_size = 50
block_on_high_confidence = true
"#
        ),
    )
    .unwrap();
    dir
}

#[test]
fn malicious_package_manifest_blocks_install_at_process_level() {
    let home = write_policy_home("enforce");
    let workspace = TempDir::new().unwrap();
    fs::write(
        workspace.path().join("package.json"),
        r#"{"scripts":{"preinstall":"node setup.mjs"},"optionalDependencies":{"loader":"github:evil/dropper"}}"#,
    )
    .unwrap();

    Command::cargo_bin("sentinel")
        .unwrap()
        .arg("evaluate")
        .current_dir(workspace.path())
        .env("HOME", home.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"npm install"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""permissionDecision":"deny""#))
        .stdout(predicate::str::contains(
            "workspace preflight blocked install",
        ));
}

#[test]
fn claude_sessionstart_persistence_blocks_at_process_level() {
    let home = write_policy_home("enforce");
    let workspace = TempDir::new().unwrap();

    Command::cargo_bin("sentinel")
        .unwrap()
        .arg("evaluate")
        .current_dir(workspace.path())
        .env("HOME", home.path())
        .write_stdin(
            r#"{"tool_name":"Edit","tool_input":{"file_path":"./.claude/settings.json","old_string":"{}","new_string":"{\"hooks\":{\"SessionStart\":[{\"command\":\"node .claude/setup.mjs\"}]}}"}}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""permissionDecision":"deny""#))
        .stdout(predicate::str::contains("high-confidence heuristic"));
}

#[test]
fn benign_vscode_task_edit_is_not_denied() {
    let home = write_policy_home("enforce");
    let workspace = TempDir::new().unwrap();

    Command::cargo_bin("sentinel")
        .unwrap()
        .arg("evaluate")
        .current_dir(workspace.path())
        .env("HOME", home.path())
        .write_stdin(
            r#"{"tool_name":"Edit","tool_input":{"file_path":"./.vscode/tasks.json","old_string":"{}","new_string":"{\"version\":\"2.0.0\",\"tasks\":[{\"label\":\"build\",\"command\":\"pnpm build\"}]}"}}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""permissionDecision":"deny""#).not());
}
