//! `sentinel audit-mcp`: enumerate configured MCP servers and flag drift via a
//! trust-on-first-use baseline. Read-only; --strict exits non-zero on drift.

use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn run_audit(
    home: &std::path::Path,
    cwd: &std::path::Path,
    args: &[&str],
) -> (Option<i32>, String) {
    let out = Command::cargo_bin("sentinel")
        .unwrap()
        .arg("audit-mcp")
        .args(args)
        .env("HOME", home)
        .current_dir(cwd)
        .output()
        .unwrap();
    (out.status.code(), String::from_utf8(out.stdout).unwrap())
}

#[test]
fn tofu_baseline_then_flags_a_new_server() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    fs::write(
        home.path().join(".claude.json"),
        r#"{"mcpServers":{"github":{"command":"npx","args":["-y","gh-mcp"]}}}"#,
    )
    .unwrap();

    // first run establishes the baseline, reports no drift
    let (code, out) = run_audit(home.path(), cwd.path(), &[]);
    assert_eq!(code, Some(0));
    assert!(out.contains("baseline established"), "first run baselines; got {out}");
    assert!(out.contains("github"), "got {out}");

    // a new server appears -> flagged, --strict exits non-zero
    fs::write(
        home.path().join(".claude.json"),
        r#"{"mcpServers":{"github":{"command":"npx","args":["-y","gh-mcp"]},"newsrv":{"command":"node","args":["srv.js"]}}}"#,
    )
    .unwrap();
    let (code, out) = run_audit(home.path(), cwd.path(), &["--strict"]);
    assert_eq!(code, Some(1), "a new server with --strict must exit non-zero; got {out}");
    assert!(
        out.contains("newsrv") && out.contains("[NEW]"),
        "must flag the new server; got {out}"
    );
}

#[test]
fn no_servers_configured_is_clean() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    let (code, out) = run_audit(home.path(), cwd.path(), &[]);
    assert_eq!(code, Some(0));
    assert!(out.contains("no MCP servers configured"), "got {out}");
}
