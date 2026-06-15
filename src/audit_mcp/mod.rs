//! `sentinel audit-mcp` — enumerate configured MCP servers and flag drift.
//!
//! An MCP server is arbitrary code the agent will happily invoke. Sentinel
//! cannot inspect a server's *internal* behavior (its own network, its own file
//! I/O) — that never crosses the PreToolUse hook. But it CAN enumerate what is
//! configured and flag the supply-chain-shaped risk: a NEW server appears, or an
//! existing server's launch command silently CHANGES. Trust-on-first-use: the
//! first run snapshots the current set as trusted; later runs flag anything new
//! or changed against that baseline.
//!
//! Read-only and detection-only. It does not block, sandbox, or modify configs;
//! a server's actual behavior at call time is out of reach (the call-arg layer —
//! deny.paths/commands/secrets/tools — already police `mcp__*` invocations).

use crate::cli::AuditMcpArgs;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

struct Server {
    name: String,
    source: String,
    /// command + args, the launch fingerprint we detect drift against.
    fingerprint: String,
}

pub fn run(args: AuditMcpArgs) -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let servers = collect_servers(Path::new(&home), &cwd);

    let baseline_path = PathBuf::from(&home).join(".sentinel").join("mcp-baseline.json");
    let prior = load_baseline(&baseline_path);
    let first_run = prior.is_none();
    let prior = prior.unwrap_or_default();

    let current: BTreeMap<String, String> = servers
        .iter()
        .map(|s| (format!("{}@{}", s.name, s.source), s.fingerprint.clone()))
        .collect();

    // first run establishes the trusted baseline; --update re-snapshots it.
    if first_run || args.update {
        save_baseline(&baseline_path, &current)?;
    }

    // drift = servers absent from the prior baseline (new) or whose launch
    // command changed. skipped on the first run (nothing to compare against) AND
    // when --update was passed (the user just accepted the current set as trusted,
    // so there is no drift to report or --strict-fail on).
    let mut new_servers = Vec::new();
    let mut changed = Vec::new();
    if !first_run && !args.update {
        for s in &servers {
            let key = format!("{}@{}", s.name, s.source);
            match prior.get(&key) {
                None => new_servers.push(s),
                Some(fp) if *fp != s.fingerprint => changed.push(s),
                _ => {}
            }
        }
    }

    if args.json {
        let out = serde_json::json!({
            "servers": servers.iter().map(|s| serde_json::json!({
                "name": s.name, "source": s.source, "command": s.fingerprint
            })).collect::<Vec<_>>(),
            "baseline_established": first_run || args.update,
            "new": new_servers.iter().map(|s| &s.name).collect::<Vec<_>>(),
            "changed": changed.iter().map(|s| &s.name).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_human(&servers, &new_servers, &changed, first_run || args.update);
    }

    if args.strict && !(new_servers.is_empty() && changed.is_empty()) {
        std::process::exit(1);
    }
    Ok(())
}

fn print_human(servers: &[Server], new: &[&Server], changed: &[&Server], baselined: bool) {
    if servers.is_empty() {
        println!("no MCP servers configured (checked ~/.claude.json and ./.mcp.json).");
    } else {
        println!("configured MCP servers ({}):", servers.len());
        for s in servers {
            let tag = if new.iter().any(|n| n.name == s.name && n.source == s.source) {
                "  [NEW]"
            } else if changed.iter().any(|c| c.name == s.name && c.source == s.source) {
                "  [CHANGED]"
            } else {
                ""
            };
            println!("  - {} ({}){}", s.name, s.source, tag);
        }
    }
    println!();
    if baselined {
        println!("baseline established/updated — future runs flag new or changed servers.");
    } else if new.is_empty() && changed.is_empty() {
        println!("ok: every configured server matches the trusted baseline.");
    } else {
        println!(
            "DRIFT: {} new, {} changed server(s) since the baseline. review them, then",
            new.len(),
            changed.len()
        );
        println!("re-run with --update to trust the current set.");
    }
    println!();
    println!("note: this enumerates CONFIG and flags drift. it cannot see a server's");
    println!("runtime behavior — that never crosses the hook. detection, not prevention.");
}

/// read MCP server definitions from `~/.claude.json` (global) and `./.mcp.json`
/// (project). both store servers under a top-level `mcpServers` object.
fn collect_servers(home: &Path, cwd: &Path) -> Vec<Server> {
    let mut out = Vec::new();
    let sources = [
        (home.join(".claude.json"), "~/.claude.json"),
        (cwd.join(".mcp.json"), "./.mcp.json"),
    ];
    for (path, label) in sources {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) {
            for (name, def) in servers {
                out.push(Server {
                    name: name.clone(),
                    source: label.to_string(),
                    fingerprint: fingerprint(def),
                });
            }
        }
    }
    out
}

/// launch fingerprint: the command plus its args, so a silent change to either
/// shows up as drift.
fn fingerprint(def: &Value) -> String {
    let command = def.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let args = def
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let url = def.get("url").and_then(|v| v.as_str()).unwrap_or("");
    format!("{command} {args} {url}").trim().to_string()
}

fn load_baseline(path: &Path) -> Option<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_baseline(
    path: &Path,
    map: &BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(map)?)?;
    Ok(())
}
