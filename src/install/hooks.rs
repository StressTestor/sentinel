use super::InstallError;
use serde_json::{json, Value};
use std::path::Path;

const SENTINEL_HOOK_MARKER: &str = "sentinel evaluate";

/// install the sentinel PreToolUse hook into Claude Code settings.
/// merges with existing hooks without clobbering them. idempotent.
pub fn install_hook(settings_path: &Path, sentinel_binary: &Path) -> Result<(), InstallError> {
    let mut settings = read_settings(settings_path)?;

    // ensure hooks object exists
    if settings.get("hooks").is_none() {
        settings["hooks"] = json!({});
    }

    let hooks = settings["hooks"]
        .as_object_mut()
        .ok_or_else(|| InstallError::WriteError("hooks is not an object".into()))?;

    // build sentinel hook entry
    let sentinel_cmd = format!("{} evaluate", sentinel_binary.display());
    let sentinel_hook = json!({
        "matcher": ".*",
        "hooks": [{
            "type": "command",
            "command": sentinel_cmd
        }]
    });

    // get or create PreToolUse array
    let pre_tool_use = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));

    let arr = pre_tool_use
        .as_array_mut()
        .ok_or_else(|| InstallError::WriteError("PreToolUse is not an array".into()))?;

    // remove existing sentinel hooks (idempotent)
    arr.retain(|entry| !is_sentinel_hook(entry));

    // add new sentinel hook
    arr.push(sentinel_hook);

    write_settings(settings_path, &settings)?;
    Ok(())
}

/// remove sentinel hooks from Claude Code settings.
/// preserves all other hooks. idempotent.
pub fn uninstall_hook(settings_path: &Path) -> Result<(), InstallError> {
    if !settings_path.exists() {
        return Ok(()); // nothing to uninstall
    }

    let mut settings = read_settings(settings_path)?;

    if let Some(hooks) = settings.get_mut("hooks") {
        if let Some(pre_tool_use) = hooks.get_mut("PreToolUse") {
            if let Some(arr) = pre_tool_use.as_array_mut() {
                arr.retain(|entry| !is_sentinel_hook(entry));
            }
        }
    }

    write_settings(settings_path, &settings)?;
    Ok(())
}

/// check if a hook entry belongs to sentinel
fn is_sentinel_hook(entry: &Value) -> bool {
    if let Some(hooks_arr) = entry.get("hooks").and_then(|h| h.as_array()) {
        for hook in hooks_arr {
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                if cmd.contains(SENTINEL_HOOK_MARKER) {
                    return true;
                }
            }
        }
    }
    false
}

fn read_settings(path: &Path) -> Result<Value, InstallError> {
    if !path.exists() {
        // create parent dirs if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| InstallError::WriteError(e.to_string()))?;
        }
        return Ok(json!({}));
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| InstallError::ReadError(e.to_string()))?;

    serde_json::from_str(&content)
        .map_err(|e| InstallError::ReadError(format!("invalid JSON: {e}")))
}

fn write_settings(path: &Path, settings: &Value) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| InstallError::WriteError(e.to_string()))?;
    }

    let content = serde_json::to_string_pretty(settings)
        .map_err(|e| InstallError::WriteError(e.to_string()))?;

    std::fs::write(path, content)
        .map_err(|e| InstallError::WriteError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_settings(content: &str) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        if !content.is_empty() {
            std::fs::write(&path, content).unwrap();
        }
        (dir, path)
    }

    #[test]
    fn install_creates_new_settings() {
        let (_dir, path) = temp_settings("");
        install_hook(&path, Path::new("/usr/local/bin/sentinel")).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let settings: Value = serde_json::from_str(&content).unwrap();

        let hooks = &settings["hooks"]["PreToolUse"];
        assert!(hooks.is_array());
        assert_eq!(hooks.as_array().unwrap().len(), 1);
    }

    #[test]
    fn install_preserves_existing_hooks() {
        let existing = r#"{
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Edit|Write",
                    "hooks": [{"type": "command", "command": "python3 some_other_hook.py"}]
                }]
            }
        }"#;
        let (_dir, path) = temp_settings(existing);
        install_hook(&path, Path::new("/usr/local/bin/sentinel")).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let settings: Value = serde_json::from_str(&content).unwrap();

        let hooks = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 2); // existing + sentinel
    }

    #[test]
    fn install_is_idempotent() {
        let (_dir, path) = temp_settings("");
        install_hook(&path, Path::new("/usr/local/bin/sentinel")).unwrap();
        install_hook(&path, Path::new("/usr/local/bin/sentinel")).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let settings: Value = serde_json::from_str(&content).unwrap();

        let hooks = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1); // not duplicated
    }

    #[test]
    fn uninstall_removes_sentinel_only() {
        let existing = r#"{
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Edit", "hooks": [{"type": "command", "command": "other_hook.py"}]},
                    {"matcher": ".*", "hooks": [{"type": "command", "command": "/usr/local/bin/sentinel evaluate"}]}
                ]
            }
        }"#;
        let (_dir, path) = temp_settings(existing);
        uninstall_hook(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let settings: Value = serde_json::from_str(&content).unwrap();

        let hooks = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert!(!is_sentinel_hook(&hooks[0]));
    }

    #[test]
    fn uninstall_no_settings_is_ok() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");
        uninstall_hook(&path).unwrap(); // should not error
    }
}
