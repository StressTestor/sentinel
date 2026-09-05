use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    Active,
    ConfiguredNeedsTrust,
    Disabled,
    Unverified(String),
    Broken(String),
}

impl Activation {
    pub fn healthy(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ConfiguredNeedsTrust => "configured-needs-trust",
            Self::Disabled => "disabled",
            Self::Unverified(_) => "unverified",
            Self::Broken(_) => "broken",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Unverified(detail) | Self::Broken(detail) => Some(detail),
            _ => None,
        }
    }
}

pub fn claude_activation(settings: &Value) -> Activation {
    if settings
        .get("disableAllHooks")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        Activation::Disabled
    } else {
        Activation::Active
    }
}

/// Ask Codex's public app-server `hooks/list` API for the effective host state.
/// Config presence alone cannot prove trust or activation.
pub fn query_codex_activation(command: &str) -> Activation {
    let mut child = match Command::new(codex_binary())
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return Activation::Unverified(format!("could not start `codex app-server`: {error}"));
        }
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Activation::Unverified("Codex app-server did not expose stdout".into());
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = sender.send(line);
        }
    });

    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .to_string_lossy()
        .to_string();
    let requests = [
        serde_json::json!({
            "method": "initialize",
            "id": 0,
            "params": {
                "clientInfo": {
                    "name": "sentinel",
                    "title": "Sentinel",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
        serde_json::json!({"method": "initialized", "params": {}}),
        serde_json::json!({"method": "hooks/list", "id": 1, "params": {"cwds": [cwd]}}),
    ];
    let write_result = child.stdin.as_mut().map(|stdin| {
        for request in requests {
            writeln!(stdin, "{request}")?;
        }
        stdin.flush()
    });
    if !matches!(write_result, Some(Ok(()))) {
        let _ = child.kill();
        let _ = child.wait();
        return Activation::Unverified("could not query Codex hook state".into());
    }

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut result = None;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(line) => {
                let Ok(value) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if value.get("id") == Some(&Value::from(1)) {
                    result = Some(activation_from_hooks_list(&value, command));
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    result.unwrap_or_else(|| {
        Activation::Unverified("Codex did not return hooks/list within 4 seconds".into())
    })
}

/// Prefer usable executables at common install paths. PATH remains a
/// compatibility fallback; this preference does not authenticate the binary.
fn codex_binary() -> std::path::PathBuf {
    let mut candidates = Vec::new();
    if let Ok(home) = crate::common::home_dir() {
        candidates.push(home.join(".local/bin/codex"));
    }
    candidates.extend([
        std::path::PathBuf::from("/opt/homebrew/bin/codex"),
        std::path::PathBuf::from("/usr/local/bin/codex"),
    ]);
    candidates
        .into_iter()
        .find(|path| is_executable_file(path))
        .unwrap_or_else(|| std::path::PathBuf::from("codex"))
}

fn is_executable_file(path: &std::path::Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub fn activation_from_hooks_list(response: &Value, configured_command: &str) -> Activation {
    if let Some(error) = response.get("error") {
        return Activation::Unverified(format!("Codex hooks/list error: {error}"));
    }
    let mut candidates = Vec::new();
    collect_hook_objects(response, &mut candidates);
    let matching: Vec<&Value> = candidates
        .into_iter()
        .filter(|hook| hook.get("command").and_then(Value::as_str) == Some(configured_command))
        .collect();
    if matching.is_empty() {
        return Activation::Unverified(
            "configured Sentinel hook was absent from Codex hooks/list".into(),
        );
    }
    if matching.len() > 1 {
        return Activation::Broken("Codex reports duplicate Sentinel hook entries".into());
    }
    let hook = matching[0];
    if hook.get("enabled").and_then(Value::as_bool) != Some(true) {
        return Activation::Disabled;
    }
    match hook
        .get("trustStatus")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_ascii_lowercase()
        .as_str()
    {
        "trusted" => Activation::Active,
        "untrusted" | "nottrusted" | "pending" => Activation::ConfiguredNeedsTrust,
        other => Activation::Unverified(format!(
            "Codex returned unknown hook trust status `{other}`"
        )),
    }
}

fn collect_hook_objects<'a>(value: &'a Value, found: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("command")
                && map.contains_key("enabled")
                && map.contains_key("trustStatus")
            {
                found.push(value);
            }
            for child in map.values() {
                collect_hook_objects(child, found);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_hook_objects(child, found);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn executable_candidates_skip_directories_and_nonexecutable_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_executable_file(dir.path()));
        assert!(!is_executable_file(&dir.path().join("missing")));
        let candidate = dir.path().join("codex");
        std::fs::write(&candidate, "placeholder").unwrap();
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_executable_file(&candidate));
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(is_executable_file(&candidate));
    }

    fn response(command: &str, enabled: bool, trust: &str) -> Value {
        serde_json::json!({
            "id": 1,
            "result": {
                "data": [{
                    "hooks": [{
                        "command": command,
                        "enabled": enabled,
                        "trustStatus": trust
                    }]
                }]
            }
        })
    }

    #[test]
    fn codex_activation_requires_both_enabled_and_trusted() {
        let command = "/bin/sentinel evaluate --agent codex";
        assert_eq!(
            activation_from_hooks_list(&response(command, true, "trusted"), command),
            Activation::Active
        );
        assert_eq!(
            activation_from_hooks_list(&response(command, true, "untrusted"), command),
            Activation::ConfiguredNeedsTrust
        );
        assert_eq!(
            activation_from_hooks_list(&response(command, false, "trusted"), command),
            Activation::Disabled
        );
    }

    #[test]
    fn missing_and_duplicate_hooks_are_not_healthy() {
        let command = "/bin/sentinel evaluate --agent codex";
        assert!(matches!(
            activation_from_hooks_list(&response("other", true, "trusted"), command),
            Activation::Unverified(_)
        ));
        let duplicate = serde_json::json!({
            "id": 1,
            "result": {"data": [{"hooks": [
                {"command": command, "enabled": true, "trustStatus": "trusted"},
                {"command": command, "enabled": true, "trustStatus": "trusted"}
            ]}]}
        });
        assert!(matches!(
            activation_from_hooks_list(&duplicate, command),
            Activation::Broken(_)
        ));
    }
}
