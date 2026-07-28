//! `sentinel audit-mcp` discovers configured MCP servers and compares them with
//! an explicitly trusted baseline.
//!
//! Discovery is intentionally not trust. The first run reports every configured
//! server as untrusted and writes nothing. Only `--update` accepts the complete
//! discovered set. Baselines contain salted SHA-256 digests of canonical typed
//! configuration, never commands, arguments, URLs, headers, environment values,
//! or tokens.

use crate::cli::AuditMcpArgs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

const BASELINE_VERSION: u32 = 1;

#[derive(Debug)]
struct Server {
    name: String,
    source: String,
    definition: Value,
}

impl Server {
    fn key(&self) -> String {
        server_key(&self.source, &self.name)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Baseline {
    version: u32,
    salt: String,
    servers: BTreeMap<String, String>,
}

enum BaselineState {
    Missing,
    Current(Baseline),
    Legacy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentStatus {
    Trusted,
    Added,
    Changed,
}

pub fn run(args: AuditMcpArgs) -> Result<(), Box<dyn std::error::Error>> {
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let servers = collect_servers(&home, &cwd)?;
    let baseline_path = home.join(".sentinel").join("mcp-baseline.json");
    let baseline_state = load_baseline(&baseline_path)?;

    if args.update {
        let salt = match &baseline_state {
            BaselineState::Current(baseline) => decode_hex(&baseline.salt)?,
            BaselineState::Missing | BaselineState::Legacy => random_salt()?,
        };
        let trusted = digest_servers(&servers, &salt)?;
        let baseline = Baseline {
            version: BASELINE_VERSION,
            salt: encode_hex(&salt),
            servers: trusted,
        };
        save_baseline(&baseline_path, &baseline)?;
        emit(&servers, &BTreeMap::new(), &[], true, true, args.json)?;
        return Ok(());
    }

    let (statuses, removed, baseline_present) = match baseline_state {
        BaselineState::Missing => (
            servers
                .iter()
                .map(|server| (server.key(), CurrentStatus::Added))
                .collect(),
            Vec::new(),
            false,
        ),
        BaselineState::Legacy => {
            return Err(
                "legacy MCP baseline contains raw launch data; review current discovery, then run \
                 `sentinel audit-mcp --update` to replace it with secret-safe digests"
                    .into(),
            );
        }
        BaselineState::Current(baseline) => {
            if baseline.version != BASELINE_VERSION {
                return Err(format!(
                    "unsupported MCP baseline version {}; expected {}",
                    baseline.version, BASELINE_VERSION
                )
                .into());
            }
            let salt = decode_hex(&baseline.salt)?;
            let current = digest_servers(&servers, &salt)?;
            compare(&baseline.servers, &current)
        }
    };

    let drift = statuses
        .values()
        .any(|status| *status != CurrentStatus::Trusted)
        || !removed.is_empty();
    emit(
        &servers,
        &statuses,
        &removed,
        baseline_present,
        false,
        args.json,
    )?;

    if args.strict && drift {
        return Err("MCP configuration is not fully trusted".into());
    }
    Ok(())
}

fn compare(
    prior: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> (BTreeMap<String, CurrentStatus>, Vec<String>, bool) {
    let statuses = current
        .iter()
        .map(|(key, digest)| {
            let status = match prior.get(key) {
                None => CurrentStatus::Added,
                Some(previous) if previous != digest => CurrentStatus::Changed,
                Some(_) => CurrentStatus::Trusted,
            };
            (key.clone(), status)
        })
        .collect();
    let removed = prior
        .keys()
        .filter(|key| !current.contains_key(*key))
        .cloned()
        .collect();
    (statuses, removed, true)
}

fn emit(
    servers: &[Server],
    statuses: &BTreeMap<String, CurrentStatus>,
    removed: &[String],
    baseline_present: bool,
    baseline_updated: bool,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        let current = servers
            .iter()
            .map(|server| {
                let status = statuses
                    .get(&server.key())
                    .copied()
                    .unwrap_or(CurrentStatus::Trusted);
                serde_json::json!({
                    "name": server.name,
                    "source": server.source,
                    "status": status_label(status, baseline_present),
                })
            })
            .collect::<Vec<_>>();
        let removed = removed
            .iter()
            .map(|key| {
                let (source, name) = split_server_key(key);
                serde_json::json!({"name": name, "source": source, "status": "removed"})
            })
            .collect::<Vec<_>>();
        let output = serde_json::json!({
            "servers": current,
            "removed": removed,
            "baseline_present": baseline_present,
            "baseline_updated": baseline_updated,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    if servers.is_empty() && removed.is_empty() {
        println!(
            "no MCP servers configured (checked Claude and Codex user/project configuration)."
        );
    } else {
        println!("configured MCP servers ({}):", servers.len());
        for server in servers {
            let status = statuses
                .get(&server.key())
                .copied()
                .unwrap_or(CurrentStatus::Trusted);
            println!(
                "  - {} ({}) [{}]",
                server.name,
                server.source,
                status_label(status, baseline_present).to_ascii_uppercase()
            );
        }
        for key in removed {
            let (source, name) = split_server_key(key);
            println!("  - {name} ({source}) [REMOVED]");
        }
    }

    println!();
    if baseline_updated {
        println!("trusted baseline updated from the complete discovered server set.");
    } else if !baseline_present {
        if servers.is_empty() {
            println!("no baseline exists; nothing was trusted or written.");
        } else {
            println!("discovery only: configured servers are UNTRUSTED until reviewed.");
            println!("run `sentinel audit-mcp --update` only after reviewing the complete set.");
        }
    } else if statuses
        .values()
        .all(|status| *status == CurrentStatus::Trusted)
        && removed.is_empty()
    {
        println!("ok: every configured server matches the trusted baseline.");
    } else {
        let added = statuses
            .values()
            .filter(|status| **status == CurrentStatus::Added)
            .count();
        let changed = statuses
            .values()
            .filter(|status| **status == CurrentStatus::Changed)
            .count();
        println!(
            "DRIFT: {added} added, {changed} changed, {} removed server(s).",
            removed.len()
        );
        println!("review the complete set before accepting it with `--update`.");
    }
    println!();
    println!("note: this checks configuration identity, not an MCP server's runtime behavior.");
    Ok(())
}

fn status_label(status: CurrentStatus, baseline_present: bool) -> &'static str {
    match status {
        CurrentStatus::Trusted => "trusted",
        CurrentStatus::Added if baseline_present => "added",
        CurrentStatus::Added => "untrusted",
        CurrentStatus::Changed => "changed",
    }
}

fn collect_servers(home: &Path, cwd: &Path) -> Result<Vec<Server>, String> {
    let mut out = Vec::new();
    collect_claude_user_json(&home.join(".claude.json"), cwd, &mut out)?;
    collect_json(&cwd.join(".mcp.json"), "claude:project", &mut out)?;

    let codex_home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".codex"));
    collect_toml(&codex_home.join("config.toml"), "codex:user", &mut out)?;
    collect_toml(
        &cwd.join(".codex").join("config.toml"),
        "codex:project",
        &mut out,
    )?;

    out.sort_by_key(|server| server.key());
    let mut keys = BTreeSet::new();
    for server in &out {
        if !keys.insert(server.key()) {
            return Err(format!(
                "duplicate MCP server identity {} in {}",
                server.name, server.source
            ));
        }
    }
    Ok(out)
}

fn collect_claude_user_json(path: &Path, cwd: &Path, out: &mut Vec<Server>) -> Result<(), String> {
    let Some(text) = read_optional(path)? else {
        return Ok(());
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("failed to parse MCP config {}: {error}", display_path(path)))?;
    collect_json_servers(&value, path, "claude:user", out)?;

    let Some(projects) = value.get("projects") else {
        return Ok(());
    };
    let projects = projects.as_object().ok_or_else(|| {
        format!(
            "failed to parse MCP config {}: projects must be an object",
            display_path(path)
        )
    })?;
    let canonical_cwd = std::fs::canonicalize(cwd)
        .map_err(|error| format!("failed to resolve current project directory: {error}"))?;
    let project = canonical_cwd
        .to_str()
        .and_then(|canonical| projects.get(canonical))
        .or_else(|| {
            projects.iter().find_map(|(project_path, project)| {
                std::fs::canonicalize(project_path)
                    .ok()
                    .filter(|candidate| candidate == &canonical_cwd)
                    .map(|_| project)
            })
        });
    if let Some(project) = project {
        collect_json_servers(project, path, "claude:local", out)?;
    }
    Ok(())
}

fn collect_json(path: &Path, source: &str, out: &mut Vec<Server>) -> Result<(), String> {
    let Some(text) = read_optional(path)? else {
        return Ok(());
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("failed to parse MCP config {}: {error}", display_path(path)))?;
    collect_json_servers(&value, path, source, out)
}

fn collect_json_servers(
    value: &Value,
    path: &Path,
    source: &str,
    out: &mut Vec<Server>,
) -> Result<(), String> {
    let Some(raw_servers) = value.get("mcpServers") else {
        return Ok(());
    };
    let servers = raw_servers.as_object().ok_or_else(|| {
        format!(
            "failed to parse MCP config {}: mcpServers must be an object",
            display_path(path)
        )
    })?;
    for (name, definition) in servers {
        out.push(Server {
            name: name.clone(),
            source: source.into(),
            definition: canonicalize(definition),
        });
    }
    Ok(())
}

fn collect_toml(path: &Path, source: &str, out: &mut Vec<Server>) -> Result<(), String> {
    let Some(text) = read_optional(path)? else {
        return Ok(());
    };
    let value: toml::Value = toml::from_str(&text)
        .map_err(|error| format!("failed to parse MCP config {}: {error}", display_path(path)))?;
    let Some(raw_servers) = value.get("mcp_servers") else {
        return Ok(());
    };
    let servers = raw_servers.as_table().ok_or_else(|| {
        format!(
            "failed to parse MCP config {}: mcp_servers must be a table",
            display_path(path)
        )
    })?;
    for (name, definition) in servers {
        let json = serde_json::to_value(definition).map_err(|error| {
            format!(
                "failed to normalize MCP config {}: {error}",
                display_path(path)
            )
        })?;
        out.push(Server {
            name: name.clone(),
            source: source.into(),
            definition: canonicalize(&json),
        });
    }
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "failed to read MCP config {}: {error}",
            display_path(path)
        )),
    }
}

fn display_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("configuration")
        .to_string()
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted = map
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

fn digest_servers(servers: &[Server], salt: &[u8]) -> Result<BTreeMap<String, String>, String> {
    servers
        .iter()
        .map(|server| {
            let key = server.key();
            let canonical = serde_json::to_vec(&server.definition)
                .map_err(|error| format!("failed to fingerprint MCP server: {error}"))?;
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(key.as_bytes());
            hasher.update([0]);
            hasher.update(canonical);
            Ok((key, encode_hex(&hasher.finalize())))
        })
        .collect()
}

fn server_key(source: &str, name: &str) -> String {
    format!("{source}\u{1f}{name}")
}

fn split_server_key(key: &str) -> (&str, &str) {
    key.split_once('\u{1f}').unwrap_or(("unknown", key))
}

fn random_salt() -> Result<Vec<u8>, String> {
    let mut salt = vec![0_u8; 32];
    getrandom::fill(&mut salt)
        .map_err(|error| format!("failed to create MCP baseline salt: {error}"))?;
    Ok(salt)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid MCP baseline salt".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).map_err(|_| "invalid MCP baseline salt".to_string())?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid MCP baseline salt".to_string())
        })
        .collect()
}

fn load_baseline(path: &Path) -> Result<BaselineState, String> {
    let Some(text) = read_optional(path)? else {
        return Ok(BaselineState::Missing);
    };
    if let Ok(baseline) = serde_json::from_str::<Baseline>(&text) {
        return Ok(BaselineState::Current(baseline));
    }
    if serde_json::from_str::<BTreeMap<String, String>>(&text).is_ok() {
        return Ok(BaselineState::Legacy);
    }
    Err("failed to parse MCP baseline; refusing to overwrite it".into())
}

fn save_baseline(path: &Path, baseline: &Baseline) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "MCP baseline path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create MCP baseline directory: {error}"))?;
    let temp = parent.join(format!(".mcp-baseline.{}.tmp", std::process::id()));
    let content = serde_json::to_vec_pretty(baseline)
        .map_err(|error| format!("failed to encode MCP baseline: {error}"))?;
    let result = (|| -> Result<(), String> {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|error| format!("failed to stage MCP baseline: {error}"))?;
        file.write_all(&content)
            .map_err(|error| format!("failed to stage MCP baseline: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("failed to sync MCP baseline: {error}"))?;
        std::fs::rename(&temp, path)
            .map_err(|error| format!("failed to atomically replace MCP baseline: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_object_order_does_not_change_digest() {
        let first = Server {
            name: "x".into(),
            source: "test".into(),
            definition: canonicalize(&serde_json::json!({"b": 2, "a": 1})),
        };
        let second = Server {
            name: "x".into(),
            source: "test".into(),
            definition: canonicalize(&serde_json::json!({"a": 1, "b": 2})),
        };
        assert_eq!(
            digest_servers(&[first], &[7; 32]).unwrap(),
            digest_servers(&[second], &[7; 32]).unwrap()
        );
    }

    #[test]
    fn hex_round_trip() {
        let bytes = (0_u8..32).collect::<Vec<_>>();
        assert_eq!(decode_hex(&encode_hex(&bytes)).unwrap(), bytes);
    }
}
