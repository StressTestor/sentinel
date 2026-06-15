use super::InstallError;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Write `content` to `path` atomically: write a sibling temp file, then rename
/// over the target (atomic on the same filesystem). A crash or full disk leaves
/// the original settings file intact rather than half-written.
pub(crate) fn atomic_write(path: &Path, content: &str) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| InstallError::WriteError(e.to_string()))?;
    }
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    std::fs::write(&tmp, content).map_err(|e| InstallError::WriteError(e.to_string()))?;
    // on a failed rename, remove the temp so a repeatedly-failing write doesn't
    // leave orphaned .tmp files beside the real one.
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(InstallError::WriteError(e.to_string()));
    }
    Ok(())
}

const SENTINEL_HOOK_MARKER: &str = "sentinel evaluate";
/// the PostToolUse (result-scan) hook marker. NB `sentinel post-evaluate` does
/// NOT contain `sentinel evaluate` as a substring, so both markers must be
/// recognized or uninstall/dedup would orphan the post-evaluate entry.
const SENTINEL_POST_HOOK_MARKER: &str = "sentinel post-evaluate";

/// the hook events sentinel owns, for uninstall cleanup.
const SENTINEL_HOOK_EVENTS: &[&str] = &["PreToolUse", "PostToolUse"];

/// install the sentinel PreToolUse hook into Claude Code settings.
/// merges with existing hooks without clobbering them. idempotent.
pub fn install_hook(settings_path: &Path, sentinel_binary: &Path) -> Result<(), InstallError> {
    add_sentinel_hook(settings_path, sentinel_binary, "PreToolUse", "evaluate")
}

/// install the sentinel PostToolUse (result-scan) hook. opt-in: result scanning
/// is detection-only and higher-FP than the PreToolUse policy layer, so it is
/// not registered by a default install.
pub fn install_post_hook(settings_path: &Path, sentinel_binary: &Path) -> Result<(), InstallError> {
    add_sentinel_hook(settings_path, sentinel_binary, "PostToolUse", "post-evaluate")
}

/// shared core: register `<binary> <subcommand>` as a `.*` hook under `event`,
/// removing any prior sentinel entry from that event's array first (idempotent).
fn add_sentinel_hook(
    settings_path: &Path,
    sentinel_binary: &Path,
    event: &str,
    subcommand: &str,
) -> Result<(), InstallError> {
    let mut settings = read_settings(settings_path)?;

    if settings.get("hooks").is_none() {
        settings["hooks"] = json!({});
    }
    let hooks = settings["hooks"]
        .as_object_mut()
        .ok_or_else(|| InstallError::WriteError("hooks is not an object".into()))?;

    let cmd = format!("{} {}", sentinel_binary.display(), subcommand);
    let entry = json!({
        "matcher": ".*",
        "hooks": [{ "type": "command", "command": cmd }]
    });

    let arr = hooks
        .entry(event)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| InstallError::WriteError(format!("{event} is not an array")))?;

    arr.retain(|e| !is_sentinel_hook(e)); // idempotent: drop our prior entry
    arr.push(entry);

    write_settings(settings_path, &settings)?;
    Ok(())
}

/// remove sentinel hooks from Claude Code settings.
/// preserves all other hooks. idempotent. cleans every event sentinel owns.
pub fn uninstall_hook(settings_path: &Path) -> Result<(), InstallError> {
    if !settings_path.exists() {
        return Ok(()); // nothing to uninstall
    }

    let mut settings = read_settings(settings_path)?;

    if let Some(hooks) = settings.get_mut("hooks") {
        for event in SENTINEL_HOOK_EVENTS {
            if let Some(arr) = hooks.get_mut(*event).and_then(|e| e.as_array_mut()) {
                arr.retain(|entry| !is_sentinel_hook(entry));
            }
        }
    }

    write_settings(settings_path, &settings)?;
    Ok(())
}

/// check if a hook entry belongs to sentinel (either the evaluate or the
/// post-evaluate hook).
fn is_sentinel_hook(entry: &Value) -> bool {
    if let Some(hooks_arr) = entry.get("hooks").and_then(|h| h.as_array()) {
        for hook in hooks_arr {
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                if cmd.contains(SENTINEL_HOOK_MARKER) || cmd.contains(SENTINEL_POST_HOOK_MARKER) {
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
    // serialize FIRST so a bad value errors out before we touch disk, then write
    // atomically - a failed write never truncates the user's real settings.json.
    let content = serde_json::to_string_pretty(settings)
        .map_err(|e| InstallError::WriteError(e.to_string()))?;
    atomic_write(path, &content)
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

    #[test]
    fn atomic_write_writes_content_and_leaves_no_temp() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        atomic_write(&path, "{\"x\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"x\":1}");
        // the temp sibling must be renamed away, not left behind
        assert!(!dir.path().join("settings.json.tmp").exists());
    }

    #[test]
    fn install_post_hook_registers_posttooluse_and_is_idempotent() {
        let (_dir, path) = temp_settings("{}");
        let bin = Path::new("/usr/local/bin/sentinel");
        install_hook(&path, bin).unwrap();
        install_post_hook(&path, bin).unwrap();

        let s: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let post = s["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(s["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(post.len(), 1);
        assert!(post[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("post-evaluate"));
        assert!(is_sentinel_hook(&post[0]), "the post-evaluate marker must be recognized");

        // idempotent: re-registering does not duplicate
        install_post_hook(&path, bin).unwrap();
        let s2: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(s2["hooks"]["PostToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn uninstall_removes_both_pre_and_post_sentinel_hooks() {
        let existing = r#"{
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Edit", "hooks": [{"type": "command", "command": "other_hook.py"}]},
                    {"matcher": ".*", "hooks": [{"type": "command", "command": "/usr/local/bin/sentinel evaluate"}]}
                ],
                "PostToolUse": [
                    {"matcher": ".*", "hooks": [{"type": "command", "command": "/usr/local/bin/sentinel post-evaluate"}]},
                    {"matcher": ".*", "hooks": [{"type": "command", "command": "prettier.sh"}]}
                ]
            }
        }"#;
        let (_dir, path) = temp_settings(existing);
        uninstall_hook(&path).unwrap();
        let s: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

        let pre = s["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1, "non-sentinel PreToolUse hook must survive");
        assert!(!is_sentinel_hook(&pre[0]));

        let post = s["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post.len(), 1, "the sentinel post-evaluate hook must be removed");
        assert!(!is_sentinel_hook(&post[0]), "prettier.sh must survive");
    }
}
