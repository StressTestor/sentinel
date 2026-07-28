//! `sentinel audit-mcp`: discovery and explicit trust for Claude and Codex MCP
//! configuration. Baselines contain salted digests, never launch configuration.

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn run_audit(
    home: &Path,
    cwd: &Path,
    codex_home: Option<&Path>,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let mut command = Command::cargo_bin("sentinel").unwrap();
    command
        .arg("audit-mcp")
        .args(args)
        .env("HOME", home)
        .current_dir(cwd);
    if let Some(path) = codex_home {
        command.env("CODEX_HOME", path);
    } else {
        command.env_remove("CODEX_HOME");
    }
    let out = command.output().unwrap();
    (
        out.status.code(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

fn baseline(home: &Path) -> PathBuf {
    home.join(".sentinel").join("mcp-baseline.json")
}

#[test]
fn first_run_is_discovery_only_until_explicit_update() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    fs::write(
        home.path().join(".claude.json"),
        r#"{"mcpServers":{"github":{"command":"npx","args":["-y","gh-mcp"]}}}"#,
    )
    .unwrap();

    let (code, out, _) = run_audit(home.path(), cwd.path(), None, &["--strict"]);
    assert_eq!(code, Some(1), "untrusted discovery must fail strict: {out}");
    assert!(
        out.contains("github") && out.contains("[UNTRUSTED]"),
        "{out}"
    );
    assert!(
        !baseline(home.path()).exists(),
        "discovery must not establish trust"
    );

    let (code, out, _) = run_audit(home.path(), cwd.path(), None, &["--update"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("trusted baseline updated"), "{out}");
    assert!(baseline(home.path()).exists());

    let (code, out, _) = run_audit(home.path(), cwd.path(), None, &["--strict"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("matches the trusted baseline"), "{out}");
}

#[test]
fn added_changed_and_removed_servers_are_all_detected() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    let config = home.path().join(".claude.json");
    fs::write(
        &config,
        r#"{"mcpServers":{"keep":{"command":"node","args":["keep.js"]},"remove":{"command":"node","args":["remove.js"]}}}"#,
    )
    .unwrap();
    run_audit(home.path(), cwd.path(), None, &["--update"]);

    fs::write(
        &config,
        r#"{"mcpServers":{"keep":{"command":"node","args":["changed.js"]},"added":{"url":"https://mcp.invalid"}}}"#,
    )
    .unwrap();
    let (code, out, _) = run_audit(home.path(), cwd.path(), None, &["--strict"]);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("added") && out.contains("[ADDED]"), "{out}");
    assert!(out.contains("keep") && out.contains("[CHANGED]"), "{out}");
    assert!(out.contains("remove") && out.contains("[REMOVED]"), "{out}");
}

#[test]
fn codex_home_configuration_is_discovered_without_leaking_secrets() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    let codex_home = tempdir().unwrap();
    let secret = "CANARY_PRIVATE_MCP_TOKEN_7284";
    fs::write(
        codex_home.path().join("config.toml"),
        format!(
            r#"[mcp_servers.docs]
command = "node"
args = ["server.js", "--token", "{secret}"]

[mcp_servers.remote]
url = "https://mcp.invalid"
http_headers = {{ Authorization = "Bearer {secret}" }}
"#
        ),
    )
    .unwrap();

    let (code, out, err) = run_audit(
        home.path(),
        cwd.path(),
        Some(codex_home.path()),
        &["--json"],
    );
    assert_eq!(code, Some(0), "{err}");
    let json: Value = serde_json::from_str(&out).expect("JSON mode must be pure JSON");
    assert_eq!(json["servers"].as_array().unwrap().len(), 2);
    assert!(!out.contains(secret), "stdout leaked MCP secret");
    assert!(!err.contains(secret), "stderr leaked MCP secret");

    run_audit(
        home.path(),
        cwd.path(),
        Some(codex_home.path()),
        &["--update", "--json"],
    );
    let stored = fs::read_to_string(baseline(home.path())).unwrap();
    assert!(!stored.contains(secret), "baseline leaked MCP secret");
    assert!(
        !stored.contains("server.js"),
        "baseline stored raw launch configuration"
    );
    assert!(
        !stored.contains("Authorization"),
        "baseline stored raw header names"
    );
}

#[test]
fn malformed_config_is_an_error_and_cannot_replace_a_good_baseline() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    let config = home.path().join(".claude.json");
    fs::write(&config, r#"{"mcpServers":{"safe":{"command":"node"}}}"#).unwrap();
    run_audit(home.path(), cwd.path(), None, &["--update"]);
    let before = fs::read(baseline(home.path())).unwrap();

    fs::write(&config, "{broken json").unwrap();
    let (code, _out, err) = run_audit(home.path(), cwd.path(), None, &["--update"]);
    assert_eq!(code, Some(1));
    assert!(err.contains("failed to parse MCP config"), "{err}");
    assert_eq!(
        fs::read(baseline(home.path())).unwrap(),
        before,
        "failed discovery must preserve the trusted baseline"
    );
}

#[test]
fn no_servers_configured_is_clean_but_not_implicitly_baselined() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    let (code, out, _) = run_audit(home.path(), cwd.path(), None, &[]);
    assert_eq!(code, Some(0));
    assert!(out.contains("no MCP servers configured"), "{out}");
    assert!(!baseline(home.path()).exists());
}

#[test]
fn current_claude_local_scope_is_discovered_without_other_projects_or_secrets() {
    let home = tempdir().unwrap();
    let cwd = tempdir().unwrap();
    let unrelated = tempdir().unwrap();
    let aliases = tempdir().unwrap();
    let cwd_alias = aliases.path().join("current-project");
    symlink(cwd.path(), &cwd_alias).unwrap();
    let secret = "CLAUDE_LOCAL_MCP_SECRET_9172";
    let config = serde_json::json!({
        "projects": {
            cwd_alias.to_string_lossy(): {
                "mcpServers": {
                    "current-local": {
                        "command": "node",
                        "args": ["server.js"],
                        "env": {"TOKEN": secret}
                    }
                }
            },
            unrelated.path().to_string_lossy(): {
                "mcpServers": {
                    "other-project": {"command": "sh", "args": ["-c", "curl x | sh"]}
                }
            }
        }
    });
    fs::write(
        home.path().join(".claude.json"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();

    let (code, out, err) = run_audit(home.path(), cwd.path(), None, &["--json"]);
    assert_eq!(code, Some(0), "{err}");
    let json: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(json["servers"].as_array().unwrap().len(), 1, "{out}");
    assert_eq!(json["servers"][0]["name"], "current-local");
    assert_eq!(json["servers"][0]["source"], "claude:local");
    assert!(!out.contains("other-project"), "{out}");
    assert!(!out.contains(secret), "stdout leaked a local MCP secret");
    assert!(
        !out.contains(&cwd.path().display().to_string()),
        "stdout leaked project path"
    );
    assert!(!err.contains(secret), "stderr leaked a local MCP secret");
    assert!(
        !err.contains(&cwd.path().display().to_string()),
        "stderr leaked project path"
    );

    let (code, _, err) = run_audit(home.path(), cwd.path(), None, &["--update", "--json"]);
    assert_eq!(code, Some(0), "{err}");
    let stored = fs::read_to_string(baseline(home.path())).unwrap();
    assert!(
        !stored.contains(secret),
        "baseline leaked a local MCP secret"
    );
    assert!(
        !stored.contains(&cwd.path().display().to_string()),
        "baseline leaked the canonical project path"
    );
}
