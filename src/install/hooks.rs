use super::InstallError;
use serde_json::{json, Value};
use std::path::Path;
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

/// Write `content` to `path` atomically: write a uniquely-named sibling temp
/// file, then rename over the target (atomic on the same filesystem). A crash
/// or full disk leaves the original settings file intact rather than
/// half-written.
///
/// Each invocation uses a pid/time suffix and retries collisions. `create_new`
/// provides exclusive creation, so a pre-existing symlink at a guessable
/// `<target>.tmp` path can neither capture the write nor redirect it into
/// another file. A leftover temp from a crashed run is simply skipped over by
/// the next attempt.
pub(crate) fn atomic_write(path: &Path, content: &str) -> Result<(), InstallError> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    atomic_write_with_stamp(path, content, stamp)
}

// Keep name generation deterministic in collision tests; all actual file I/O
// stays in this implementation, which the public entry point also calls.
fn atomic_write_with_stamp(path: &Path, content: &str, stamp: u128) -> Result<(), InstallError> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| InstallError::WriteError(e.to_string()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sentinel-write");
    let existing_permissions = std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let mut temp = None;
    for attempt in 0..1000_u32 {
        let candidate = parent.join(format!(
            ".{name}.sentinel-write.{}.{}.tmp",
            std::process::id(),
            stamp + u128::from(attempt)
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => {
                temp = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(InstallError::WriteError(error.to_string())),
        }
    }
    let Some((tmp, mut file)) = temp else {
        return Err(InstallError::WriteError(
            "could not allocate a unique sibling temporary file".into(),
        ));
    };
    let write_result = (|| -> Result<(), InstallError> {
        if let Some(permissions) = existing_permissions {
            file.set_permissions(permissions)
                .map_err(|error| InstallError::WriteError(error.to_string()))?;
        }
        file.write_all(content.as_bytes())
            .map_err(|error| InstallError::WriteError(error.to_string()))?;
        file.sync_all()
            .map_err(|error| InstallError::WriteError(error.to_string()))
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    // on a failed rename, remove the temp so a repeatedly-failing write doesn't
    // leave orphaned .tmp files beside the real one.
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(InstallError::WriteError(e.to_string()));
    }
    sync_parent_dir(parent);
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) {
    let _ = std::fs::File::open(parent).and_then(|directory| directory.sync_all());
}

#[cfg(not(unix))]
fn sync_parent_dir(_parent: &Path) {}

/// the hook events sentinel owns, for uninstall cleanup.
const SENTINEL_HOOK_EVENTS: &[&str] = &["PreToolUse", "PostToolUse"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookCommandKind {
    DirectPre,
    DirectPost,
    GhostBridge,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookOwnership {
    Absent,
    Direct,
    Mediated,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookInspection {
    pub ownership: HookOwnership,
    pub command: Option<String>,
    pub direct_count: usize,
    pub mediated_count: usize,
}

/// Classify a hook by parsed argv, not substring. A command such as
/// `echo sentinel evaluate` or `my-sentinel evaluate` is not Sentinel-owned and
/// must survive install/uninstall.
pub fn classify_hook_command(command: &str) -> HookCommandKind {
    let Some(argv) = split_shell_words(command) else {
        return HookCommandKind::Other;
    };
    if binary_name(argv.first().map(String::as_str).unwrap_or_default()) == Some("sentinel") {
        if matches!(
            argv.as_slice(),
            [_, evaluate] if evaluate == "evaluate"
        ) || matches!(
            argv.as_slice(),
            [_, evaluate, agent_flag, _]
                if evaluate == "evaluate" && agent_flag == "--agent"
        ) {
            return HookCommandKind::DirectPre;
        }
        if matches!(
            argv.as_slice(),
            [_, post_evaluate] if post_evaluate == "post-evaluate"
        ) {
            return HookCommandKind::DirectPost;
        }
    }
    if argv.len() == 4
        && binary_name(&argv[0]) == Some("ghost")
        && argv[1] == "hook"
        && argv[2] == "--sentinel"
        && binary_name(&argv[3]) == Some("sentinel")
    {
        return HookCommandKind::GhostBridge;
    }
    HookCommandKind::Other
}

fn binary_name(path: &str) -> Option<&str> {
    Path::new(path).file_name()?.to_str()
}

fn quote_shell_word(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_+-./:".contains(&byte))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Minimal POSIX argv parser sufficient for hook commands. It handles quoted
/// install paths and rejects unterminated quoting instead of guessing ownership.
pub(crate) fn split_shell_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut chars = command.chars().peekable();
    let mut quote = None;
    let mut started = false;
    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    word.push(ch);
                }
                started = true;
            }
            Some('"') => {
                if ch == '"' {
                    quote = None;
                } else if ch == '\\' {
                    word.push(chars.next()?);
                } else {
                    word.push(ch);
                }
                started = true;
            }
            Some(_) => unreachable!(),
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    started = true;
                }
                '\\' => {
                    word.push(chars.next()?);
                    started = true;
                }
                ch if ch.is_whitespace() => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                _ => {
                    word.push(ch);
                    started = true;
                }
            },
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

/// install the sentinel PreToolUse hook into Claude Code settings.
/// merges with existing hooks without clobbering them. idempotent.
pub fn install_hook(settings_path: &Path, sentinel_binary: &Path) -> Result<(), InstallError> {
    add_sentinel_hook(settings_path, sentinel_binary, "PreToolUse", "evaluate")
}

/// install the sentinel PostToolUse (result-scan) hook. opt-in: result scanning
/// is detection-only and higher-FP than the PreToolUse policy layer, so it is
/// not registered by a default install.
pub fn install_post_hook(settings_path: &Path, sentinel_binary: &Path) -> Result<(), InstallError> {
    add_sentinel_hook(
        settings_path,
        sentinel_binary,
        "PostToolUse",
        "post-evaluate",
    )
}

pub fn install_codex_json_hook(
    hooks_path: &Path,
    sentinel_binary: &Path,
) -> Result<(), InstallError> {
    add_sentinel_hook(
        hooks_path,
        sentinel_binary,
        "PreToolUse",
        "evaluate --agent codex",
    )
}

pub fn install_codex_json_post_hook(
    hooks_path: &Path,
    sentinel_binary: &Path,
) -> Result<(), InstallError> {
    add_sentinel_hook(hooks_path, sentinel_binary, "PostToolUse", "post-evaluate")
}

pub fn install_codex_hook(config_path: &Path, sentinel_binary: &Path) -> Result<(), InstallError> {
    add_codex_hook(
        config_path,
        sentinel_binary,
        "PreToolUse",
        "evaluate --agent codex",
    )
}

pub fn install_codex_post_hook(
    config_path: &Path,
    sentinel_binary: &Path,
) -> Result<(), InstallError> {
    add_codex_hook(config_path, sentinel_binary, "PostToolUse", "post-evaluate")
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

    let arr = hooks
        .entry(event)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| InstallError::WriteError(format!("{event} is not an array")))?;

    let has_ghost_bridge = event == "PreToolUse" && event_has_ghost_bridge(arr);
    remove_direct_handlers(arr, event);
    if has_ghost_bridge {
        write_settings(settings_path, &settings)?;
        return Ok(());
    }

    let cmd = format!(
        "{} {subcommand}",
        quote_shell_word(&sentinel_binary.to_string_lossy())
    );
    let entry = json!({
        "matcher": ".*",
        "hooks": [{ "type": "command", "command": cmd }]
    });

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
                remove_direct_handlers(arr, event);
            }
        }
    }

    write_settings(settings_path, &settings)?;
    Ok(())
}

/// check if a hook entry belongs to sentinel (either the evaluate or the
/// post-evaluate hook).
fn entry_has_kind(entry: &Value, kind: HookCommandKind) -> bool {
    if let Some(hooks_arr) = entry.get("hooks").and_then(|h| h.as_array()) {
        for hook in hooks_arr {
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                if classify_hook_command(cmd) == kind {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
fn is_sentinel_hook(entry: &Value) -> bool {
    entry_has_kind(entry, HookCommandKind::DirectPre)
        || entry_has_kind(entry, HookCommandKind::DirectPost)
}

fn event_has_ghost_bridge(entries: &[Value]) -> bool {
    entries
        .iter()
        .any(|entry| entry_has_kind(entry, HookCommandKind::GhostBridge))
}

pub fn inspect_claude_pre_tool(settings: &Value) -> Result<HookInspection, InstallError> {
    let hooks = match settings.get("hooks") {
        None => {
            return Ok(HookInspection {
                ownership: HookOwnership::Absent,
                command: None,
                direct_count: 0,
                mediated_count: 0,
            });
        }
        Some(Value::Object(hooks)) => hooks,
        Some(_) => return Err(InstallError::ReadError("hooks is not an object".into())),
    };
    let entries = match hooks.get("PreToolUse") {
        None => Vec::new(),
        Some(Value::Array(entries)) => entries.clone(),
        Some(_) => {
            return Err(InstallError::ReadError(
                "hooks.PreToolUse is not an array".into(),
            ));
        }
    };
    let mut direct = Vec::new();
    let mut mediated = Vec::new();
    for entry in entries {
        let Some(handlers) = entry.get("hooks").and_then(Value::as_array) else {
            continue;
        };
        for handler in handlers {
            let Some(command) = handler.get("command").and_then(Value::as_str) else {
                continue;
            };
            match classify_hook_command(command) {
                HookCommandKind::DirectPre => direct.push(command.to_string()),
                HookCommandKind::GhostBridge => mediated.push(command.to_string()),
                _ => {}
            }
        }
    }
    let direct_count = direct.len();
    let mediated_count = mediated.len();
    let ownership = match (direct_count, mediated_count) {
        (0, 0) => HookOwnership::Absent,
        (1, 0) => HookOwnership::Direct,
        (0, 1) => HookOwnership::Mediated,
        _ => HookOwnership::Conflict,
    };
    let command = match ownership {
        HookOwnership::Direct => direct.into_iter().next(),
        HookOwnership::Mediated => mediated.into_iter().next(),
        _ => None,
    };
    Ok(HookInspection {
        ownership,
        command,
        direct_count,
        mediated_count,
    })
}

fn remove_direct_handlers(entries: &mut Vec<Value>, event: &str) {
    let owned_kind = if event == "PostToolUse" {
        HookCommandKind::DirectPost
    } else {
        HookCommandKind::DirectPre
    };
    for entry in entries.iter_mut() {
        if let Some(handlers) = entry.get_mut("hooks").and_then(Value::as_array_mut) {
            handlers.retain(|handler| {
                handler
                    .get("command")
                    .and_then(Value::as_str)
                    .is_none_or(|command| classify_hook_command(command) != owned_kind)
            });
        }
    }
    entries.retain(|entry| {
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_none_or(|handlers| !handlers.is_empty())
    });
}

fn read_settings(path: &Path) -> Result<Value, InstallError> {
    if !path.exists() {
        // create parent dirs if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| InstallError::WriteError(e.to_string()))?;
        }
        return Ok(json!({}));
    }

    let content =
        std::fs::read_to_string(path).map_err(|e| InstallError::ReadError(e.to_string()))?;

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

fn add_codex_hook(
    config_path: &Path,
    sentinel_binary: &Path,
    event: &str,
    subcommand: &str,
) -> Result<(), InstallError> {
    let mut document = read_codex_config(config_path)?;
    remove_codex_direct_handlers(&mut document, event)?;

    let command = format!(
        "{} {subcommand}",
        quote_shell_word(&sentinel_binary.to_string_lossy())
    );
    let mut group = Table::new();
    group["matcher"] = value(".*");
    let mut handler = Table::new();
    handler["type"] = value("command");
    handler["command"] = value(command);
    let mut handlers = ArrayOfTables::new();
    handlers.push(handler);
    group["hooks"] = Item::ArrayOfTables(handlers);
    codex_event_hooks_mut(&mut document, event)?.push(group);
    write_codex_config(config_path, &document)
}

pub fn uninstall_codex_hook(config_path: &Path) -> Result<(), InstallError> {
    if !config_path.exists() {
        return Ok(());
    }
    let mut document = read_codex_config(config_path)?;
    for event in SENTINEL_HOOK_EVENTS {
        remove_codex_direct_handlers(&mut document, event)?;
    }
    write_codex_config(config_path, &document)
}

pub(crate) fn read_codex_config(config_path: &Path) -> Result<DocumentMut, InstallError> {
    if !config_path.exists() {
        return Ok(DocumentMut::new());
    }
    let content = std::fs::read_to_string(config_path)
        .map_err(|error| InstallError::ReadError(error.to_string()))?;
    content
        .parse::<DocumentMut>()
        .map_err(|error| InstallError::ReadError(format!("invalid TOML: {error}")))
}

fn write_codex_config(config_path: &Path, document: &DocumentMut) -> Result<(), InstallError> {
    atomic_write(config_path, &document.to_string())
}

fn codex_event_hooks_mut<'a>(
    document: &'a mut DocumentMut,
    event: &str,
) -> Result<&'a mut ArrayOfTables, InstallError> {
    match document.as_table().get("hooks") {
        None => {
            document
                .as_table_mut()
                .insert("hooks", Item::Table(Table::new()));
        }
        Some(item) if item.is_table() => {}
        Some(_) => return Err(InstallError::WriteError("hooks is not a TOML table".into())),
    }
    let hooks = document
        .as_table_mut()
        .get_mut("hooks")
        .and_then(Item::as_table_mut)
        .expect("hooks table was just validated");
    match hooks.get(event) {
        None => {
            hooks.insert(event, Item::ArrayOfTables(ArrayOfTables::new()));
        }
        Some(item) if item.is_array_of_tables() => {}
        Some(_) => {
            return Err(InstallError::WriteError(format!(
                "hooks.{event} is not an array of tables"
            )));
        }
    }
    hooks
        .get_mut(event)
        .and_then(Item::as_array_of_tables_mut)
        .ok_or_else(|| InstallError::WriteError(format!("hooks.{event} is invalid")))
}

fn remove_codex_direct_handlers(
    document: &mut DocumentMut,
    event: &str,
) -> Result<(), InstallError> {
    let Some(hooks) = document.as_table_mut().get_mut("hooks") else {
        return Ok(());
    };
    let hooks = hooks
        .as_table_mut()
        .ok_or_else(|| InstallError::WriteError("hooks is not a TOML table".into()))?;
    let Some(groups_item) = hooks.get_mut(event) else {
        return Ok(());
    };
    let groups = groups_item.as_array_of_tables_mut().ok_or_else(|| {
        InstallError::WriteError(format!("hooks.{event} is not an array of tables"))
    })?;
    let owned_kind = if event == "PostToolUse" {
        HookCommandKind::DirectPost
    } else {
        HookCommandKind::DirectPre
    };
    for group in groups.iter_mut() {
        let Some(handlers_item) = group.get_mut("hooks") else {
            continue;
        };
        let handlers = handlers_item.as_array_of_tables_mut().ok_or_else(|| {
            InstallError::WriteError(format!("hooks.{event}.hooks is not an array of tables"))
        })?;
        handlers.retain(|handler| {
            handler
                .get("command")
                .and_then(Item::as_str)
                .is_none_or(|command| classify_hook_command(command) != owned_kind)
        });
    }
    groups.retain(|group| {
        group
            .get("hooks")
            .and_then(Item::as_array_of_tables)
            .is_none_or(|handlers| !handlers.is_empty())
    });
    Ok(())
}

pub(crate) fn codex_pre_tool_commands(document: &DocumentMut) -> Vec<String> {
    let Some(groups) = document
        .as_table()
        .get("hooks")
        .and_then(Item::as_table)
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Item::as_array_of_tables)
    else {
        return Vec::new();
    };
    groups
        .iter()
        .flat_map(|group| {
            group
                .get("hooks")
                .and_then(Item::as_array_of_tables)
                .into_iter()
                .flat_map(ArrayOfTables::iter)
        })
        .filter_map(|handler| handler.get("command").and_then(Item::as_str))
        .map(str::to_string)
        .collect()
}

pub(crate) fn inspect_codex_pre_tool(document: &DocumentMut) -> HookInspection {
    let direct: Vec<String> = codex_pre_tool_commands(document)
        .into_iter()
        .filter(|command| classify_hook_command(command) == HookCommandKind::DirectPre)
        .collect();
    let ownership = match direct.len() {
        0 => HookOwnership::Absent,
        1 => HookOwnership::Direct,
        _ => HookOwnership::Conflict,
    };
    let command = (ownership == HookOwnership::Direct)
        .then(|| direct.first().cloned())
        .flatten();
    HookInspection {
        ownership,
        command,
        direct_count: direct.len(),
        mediated_count: 0,
    }
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
        // no leftover sibling of any kind may remain beside the target
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("settings.json")]);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_ignores_preplanted_tmp_symlink() {
        use std::os::unix::fs::symlink;

        // regression (audit F-3): the old implementation opened a predictable
        // `<target>.tmp` without O_EXCL, so a planted symlink redirected the
        // write (and the chmod) into the symlink's victim. The unique
        // create_new temp must leave the plant untouched and write the target.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, "precious").unwrap();
        symlink(&victim, dir.path().join("settings.json.tmp")).unwrap();

        atomic_write(&path, "{\"x\":1}").unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"x\":1}");
        // the plant itself is left as-is for the user to see, not followed
        assert!(dir
            .path()
            .join("settings.json.tmp")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_skips_over_stale_tmp_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let stamp = 42;
        let stale: Vec<_> = (0..5)
            .map(|attempt| {
                dir.path().join(format!(
                    ".config.toml.sentinel-write.{}.{}.tmp",
                    std::process::id(),
                    stamp + attempt
                ))
            })
            .collect();
        for candidate in &stale {
            std::fs::write(candidate, "stale").unwrap();
        }
        // These are the first five candidates the actual writer will try.
        atomic_write_with_stamp(&path, "fresh", stamp).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh");
        for candidate in &stale {
            assert_eq!(std::fs::read_to_string(candidate).unwrap(), "stale");
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 6);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_preserves_existing_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        atomic_write(&path, "new").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
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
        assert!(
            is_sentinel_hook(&post[0]),
            "the post-evaluate marker must be recognized"
        );

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
        assert_eq!(
            post.len(),
            1,
            "the sentinel post-evaluate hook must be removed"
        );
        assert!(!is_sentinel_hook(&post[0]), "prettier.sh must survive");
    }

    #[test]
    fn parsed_ownership_rejects_substring_lookalikes_and_handles_quoted_paths() {
        assert_eq!(
            classify_hook_command("echo sentinel evaluate"),
            HookCommandKind::Other
        );
        assert_eq!(
            classify_hook_command("/tmp/not-sentinel evaluate"),
            HookCommandKind::Other
        );
        assert_eq!(
            classify_hook_command("'/Applications/Sentinel Tools/sentinel' evaluate --agent codex"),
            HookCommandKind::DirectPre
        );
        assert_eq!(
            classify_hook_command("ghost hook --sentinel '/Applications/Sentinel Tools/sentinel'"),
            HookCommandKind::GhostBridge
        );
        for wrapped in [
            "sentinel evaluate >/dev/null 2>&1 || true",
            "sentinel evaluate ; true",
            "sentinel evaluate --agent codex trailing",
            "sentinel post-evaluate | cat",
        ] {
            assert_eq!(
                classify_hook_command(wrapped),
                HookCommandKind::Other,
                "shell-wrapped or trailing argv must not be treated as an owned hook: {wrapped}"
            );
        }
    }

    #[test]
    fn ghost_bridge_wins_without_destroying_mixed_handlers() {
        let existing = r#"{
            "hooks": {
                "PreToolUse": [{
                    "matcher": ".*",
                    "hooks": [
                        {"type":"command","command":"other_hook.py"},
                        {"type":"command","command":"/old/sentinel evaluate"},
                        {"type":"command","command":"ghost hook --sentinel /bridge/sentinel"}
                    ]
                }]
            }
        }"#;
        let (_dir, path) = temp_settings(existing);
        install_hook(&path, Path::new("/new/sentinel")).unwrap();
        let settings: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let handlers = settings["hooks"]["PreToolUse"][0]["hooks"]
            .as_array()
            .unwrap();
        assert!(handlers
            .iter()
            .any(|handler| handler["command"] == "other_hook.py"));
        assert!(handlers.iter().any(|handler| {
            classify_hook_command(handler["command"].as_str().unwrap())
                == HookCommandKind::GhostBridge
        }));
        assert!(!handlers.iter().any(|handler| {
            classify_hook_command(handler["command"].as_str().unwrap())
                == HookCommandKind::DirectPre
        }));

        uninstall_hook(&path).unwrap();
        let after: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(after.to_string().contains("ghost hook"));
        assert!(after.to_string().contains("other_hook.py"));
    }

    #[test]
    fn codex_install_is_idempotent_and_preserves_unrelated_handlers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"model = "gpt-5"

[[hooks.PreToolUse]]
matcher = ".*"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "python3 other.py"
"#,
        )
        .unwrap();
        install_codex_hook(&path, Path::new("/Applications/My Tools/sentinel")).unwrap();
        install_codex_hook(&path, Path::new("/Applications/My Tools/sentinel")).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("python3 other.py"));
        assert!(content.contains(r#"model = "gpt-5""#));
        assert_eq!(content.matches("evaluate --agent codex").count(), 1);
        let document = read_codex_config(&path).unwrap();
        let inspection = inspect_codex_pre_tool(&document);
        assert_eq!(inspection.ownership, HookOwnership::Direct);
        assert_eq!(
            inspection.command.as_deref(),
            Some("'/Applications/My Tools/sentinel' evaluate --agent codex")
        );
    }

    #[test]
    fn codex_uninstall_removes_only_direct_sentinel_handlers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"[[hooks.PreToolUse]]
matcher = ".*"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/local/bin/sentinel evaluate --agent codex"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "echo sentinel evaluate"
"#,
        )
        .unwrap();
        uninstall_codex_hook(&path).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("/usr/local/bin/sentinel evaluate"));
        assert!(content.contains("echo sentinel evaluate"));
    }

    #[test]
    fn codex_json_install_uses_codex_agent_contract() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        std::fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"other"}]}]}}"#,
        )
        .unwrap();
        install_codex_json_hook(&path, Path::new("/usr/local/bin/sentinel")).unwrap();
        install_codex_json_hook(&path, Path::new("/usr/local/bin/sentinel")).unwrap();
        let settings: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let inspection = inspect_claude_pre_tool(&settings).unwrap();
        assert_eq!(inspection.ownership, HookOwnership::Direct);
        assert_eq!(inspection.direct_count, 1);
        assert_eq!(
            inspection.command.as_deref(),
            Some("/usr/local/bin/sentinel evaluate --agent codex")
        );
        assert!(settings.to_string().contains("\"other\""));
    }
}
