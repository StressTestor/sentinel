//! sandbox bridge: project the policy's `deny.paths` rules onto Claude Code's
//! own sandbox (`sandbox.filesystem.denyRead` / `denyWrite` in settings.json).
//!
//! Opt-in through `sentinel install --sandbox`, Claude Code only. The hook sees
//! the agent's tool calls; the sandbox sees every `open()` a sandboxed shell
//! command makes, including the ones inside `npm install`, `python -c`, or a
//! script the agent wrote a moment ago. Compiling the directory-shaped deny
//! rules into the sandbox lists gives those reads a kernel-level floor the
//! regex layer cannot provide.
//!
//! The projection rules come from the S1 spike
//! (`docs/hardening/2026-10-08-s1-sandbox-projection.md` on the spike branch):
//!
//! - only `~/` and absolute patterns are expressible; a relative entry in user
//!   settings resolves under `~/.claude`, so an unanchored `**/name` rule
//!   stays hook-only;
//! - a trailing `/`, `/*`, or `/**` is stripped: the bare directory covers its
//!   subtree on every Claude Code version;
//! - a wildcard that survives normalization is kept in `denyRead` on every
//!   platform; the write lists skip wildcard entries on Linux and WSL2, so it
//!   is dropped from `denyWrite` there;
//! - a wildcard in a middle segment (`/proc/*/environ`) has no stable entry
//!   and stays hook-only;
//! - warn-tier rules stay hook-only: the sandbox has no warn, and compiling a
//!   dual-use rule into a deny list would turn a review signal into a block;
//! - the self-protect files (`policy.toml`, `install-state.json`, the Claude
//!   settings files, the running binary, and `mcp-baseline.json` when it
//!   exists) get `denyWrite` entries;
//! - entries whose syntax the docs do not cover (a path with whitespace, which
//!   Seatbelt must quote) are withheld pending the live test, and reported.
//!
//! Everything the compiler emits is also recorded in
//! `~/.sentinel/install-state.json`, so uninstall removes only what sentinel
//! wrote and doctor can diff the live lists against a fresh projection.

use super::hooks::{read_settings, write_settings};
use super::state::{self, SandboxRecord};
use super::InstallError;
use crate::policy::PolicyEngine;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

/// the binary name the self-protect binary rules point at.
const BINARY_NAME: &str = "sentinel";

/// the three top-level sandbox keys `install --sandbox` pins, with the value
/// it pins them to. `enabled` turns the sandbox on, `failIfUnavailable` stops
/// a host without bubblewrap or Seatbelt from silently running unsandboxed,
/// and `allowUnsandboxedCommands: false` closes the "run it outside" escape.
pub const PINNED_KEYS: [(&str, bool); 3] = [
    ("enabled", true),
    ("failIfUnavailable", true),
    ("allowUnsandboxedCommands", false),
];

/// Host facts the projection depends on. Built from the environment by
/// [`ProjectionContext::from_environment`]; tests construct it directly so the
/// table test is deterministic on every machine.
#[derive(Debug, Clone)]
pub struct ProjectionContext {
    pub home: PathBuf,
    pub config_dir: PathBuf,
    pub current_exe: Option<PathBuf>,
    pub mcp_baseline_exists: bool,
    pub settings_local_exists: bool,
    /// whether a wildcard entry may go into `denyWrite`. False on Linux and
    /// WSL2, where Claude Code skips wildcard write entries.
    pub write_wildcards: bool,
}

impl ProjectionContext {
    pub fn from_environment() -> std::io::Result<Self> {
        let home = crate::common::home_dir()?;
        let config_dir = super::claude_config_dir()?;
        let sentinel_dir = home.join(".sentinel");
        Ok(Self {
            mcp_baseline_exists: sentinel_dir.join("mcp-baseline.json").is_file(),
            settings_local_exists: config_dir.join("settings.local.json").is_file(),
            home,
            config_dir,
            current_exe: std::env::current_exe().ok(),
            write_wildcards: !cfg!(target_os = "linux"),
        })
    }

    fn policy_path(&self) -> PathBuf {
        self.home.join(".sentinel").join("policy.toml")
    }

    fn install_state_path(&self) -> PathBuf {
        self.home.join(".sentinel").join("install-state.json")
    }

    fn mcp_baseline_path(&self) -> PathBuf {
        self.home.join(".sentinel").join("mcp-baseline.json")
    }

    fn settings_path(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }

    fn settings_local_path(&self) -> PathBuf {
        self.config_dir.join("settings.local.json")
    }

    /// expand a `~/` pattern against this context's home.
    fn expand(&self, pattern: &str) -> PathBuf {
        match pattern.strip_prefix("~/") {
            Some(rest) => self.home.join(rest),
            None => PathBuf::from(pattern),
        }
    }

    /// render a path the way the sandbox lists spell it: `~/rest` under home,
    /// the absolute path otherwise.
    fn entry_for(&self, path: &Path) -> String {
        match path.strip_prefix(&self.home) {
            Ok(rest) if !rest.as_os_str().is_empty() => {
                format!("~/{}", rest.to_string_lossy())
            }
            _ => path.to_string_lossy().into_owned(),
        }
    }
}

/// one rule that compiled into a sandbox entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRule {
    pub pattern: String,
    pub entry: String,
    pub read: bool,
    pub write: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxProjection {
    /// entries for `sandbox.filesystem.denyRead`, in rule order, deduplicated.
    pub deny_read: Vec<String>,
    /// entries for `sandbox.filesystem.denyWrite`, in rule order, then the
    /// self-protect extras, deduplicated.
    pub deny_write: Vec<String>,
    /// every rule that produced an entry (plus the self-protect extras).
    pub compiled: Vec<CompiledRule>,
    /// rules the sandbox cannot express: `(pattern, reason)`.
    pub hook_only: Vec<(String, String)>,
    /// rules the sandbox could express but this host does not emit:
    /// `(pattern, reason)`. Conditional self-protect files that are absent,
    /// sentinel binary paths that are not the running binary, and entries
    /// whose syntax is undocumented (whitespace) and waits on the live test.
    pub withheld: Vec<(String, String)>,
}

impl SandboxProjection {
    /// policy rules that produced an entry (the self-protect extras are not
    /// rules and are excluded).
    pub fn compiled_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.compiled
            .iter()
            .filter(|rule| rule.note.as_deref() != Some(SELF_PROTECT_EXTRA))
    }

    fn push_read(&mut self, entry: &str) {
        if !self.deny_read.iter().any(|existing| existing == entry) {
            self.deny_read.push(entry.to_string());
        }
    }

    fn push_write(&mut self, entry: &str) {
        if !self.deny_write.iter().any(|existing| existing == entry) {
            self.deny_write.push(entry.to_string());
        }
    }
}

const SELF_PROTECT_EXTRA: &str = "self-protect target added by the bridge, not a policy rule";

enum Disposition {
    Emit {
        entry: String,
        read: bool,
        write: bool,
        note: Option<String>,
    },
    Withheld(String),
    HookOnly(String),
}

/// Compile the policy's `deny.paths` rules for this host.
pub fn project(policy: &PolicyEngine) -> std::io::Result<SandboxProjection> {
    Ok(project_with(
        policy,
        &ProjectionContext::from_environment()?,
    ))
}

/// Pure projection: no environment reads, so the table test can pin it.
pub fn project_with(policy: &PolicyEngine, ctx: &ProjectionContext) -> SandboxProjection {
    let mut projection = SandboxProjection::default();
    for rule in policy.rules() {
        if rule.section != "deny.paths" {
            continue;
        }
        match classify(rule.pattern, rule.action, ctx) {
            Disposition::Emit {
                entry,
                read,
                write,
                note,
            } => {
                if read {
                    projection.push_read(&entry);
                }
                if write {
                    projection.push_write(&entry);
                }
                projection.compiled.push(CompiledRule {
                    pattern: rule.pattern.to_string(),
                    entry,
                    read,
                    write,
                    note,
                });
            }
            Disposition::Withheld(reason) => {
                projection.withheld.push((rule.pattern.to_string(), reason));
            }
            Disposition::HookOnly(reason) => {
                projection
                    .hook_only
                    .push((rule.pattern.to_string(), reason));
            }
        }
    }
    // self-protect extras: files no bundled rule names (or names at warn
    // tier) that a sandboxed child must not rewrite. Only the write side; the
    // hook keeps the content-aware check for the agent's own Write/Edit.
    for (path, emit) in self_protect_targets(ctx) {
        let entry = ctx.entry_for(&path);
        match emit {
            Ok(()) => {
                if !projection.deny_write.contains(&entry) {
                    projection.push_write(&entry);
                    projection.compiled.push(CompiledRule {
                        pattern: entry.clone(),
                        entry,
                        read: false,
                        write: true,
                        note: Some(SELF_PROTECT_EXTRA.into()),
                    });
                }
            }
            Err(reason) => {
                if !projection
                    .withheld
                    .iter()
                    .any(|(pattern, _)| *pattern == entry)
                {
                    projection.withheld.push((entry, reason));
                }
            }
        }
    }
    projection
}

/// the self-protect write targets, each with Ok (emit) or Err (why not).
fn self_protect_targets(ctx: &ProjectionContext) -> Vec<(PathBuf, Result<(), String>)> {
    let mut targets = vec![
        (ctx.policy_path(), Ok(())),
        (ctx.install_state_path(), Ok(())),
        (ctx.settings_path(), Ok(())),
        (
            ctx.settings_local_path(),
            if ctx.settings_local_exists {
                Ok(())
            } else {
                Err(MISSING_FILE_REASON.into())
            },
        ),
        (
            ctx.mcp_baseline_path(),
            if ctx.mcp_baseline_exists {
                Ok(())
            } else {
                Err(MISSING_FILE_REASON.into())
            },
        ),
    ];
    if let Some(exe) = &ctx.current_exe {
        targets.push((exe.clone(), Ok(())));
    }
    targets
}

const MISSING_FILE_REASON: &str = "file does not exist on this host; on Linux a denyWrite entry for a missing file creates a read-only placeholder during every sandboxed command, and a placeholder left behind by a killed session blocks later writes there";

fn classify(pattern: &str, action: &str, ctx: &ProjectionContext) -> Disposition {
    let (normalized, had_subtree_suffix) = strip_subtree_suffix(pattern);
    if normalized.is_empty() || normalized == "~" || normalized == "/" {
        return Disposition::HookOnly(
            "pattern covers the whole home directory or filesystem; not projected".into(),
        );
    }
    let anchored = normalized.starts_with("~/") || normalized.starts_with('/');
    let expanded = anchored.then(|| ctx.expand(normalized));

    // self-protect files: projected on the write side whatever their tier.
    if let Some(expanded) = &expanded {
        if *expanded == ctx.policy_path() || *expanded == ctx.install_state_path() {
            return emit_write(
                ctx.entry_for(expanded),
                "self-protect: writes only; reads stay open for backup and inspection",
            );
        }
        if *expanded == ctx.mcp_baseline_path() {
            return if ctx.mcp_baseline_exists {
                emit_write(
                    ctx.entry_for(expanded),
                    "self-protect: writes only; the baseline is updated outside the agent",
                )
            } else {
                Disposition::Withheld(MISSING_FILE_REASON.into())
            };
        }
    }

    if action.eq_ignore_ascii_case("warn") {
        return Disposition::HookOnly(
            "warn tier: the sandbox has no warn, so compiling this rule would turn a review signal into a hard block".into(),
        );
    }
    if !action.eq_ignore_ascii_case("block") {
        return Disposition::HookOnly(format!("action `{action}` has no sandbox equivalent"));
    }
    let Some(expanded) = expanded else {
        return Disposition::HookOnly(
            "unanchored pattern: a relative entry in user settings resolves under ~/.claude, not anywhere".into(),
        );
    };

    let body = normalized
        .strip_prefix("~/")
        .or_else(|| normalized.strip_prefix('/'))
        .unwrap_or(normalized);
    let segments: Vec<&str> = body.split('/').collect();
    let (last, middle) = segments.split_last().unwrap_or((&"", &[]));
    if middle
        .iter()
        .any(|segment| has_wildcard(segment) && *segment != "**")
    {
        return Disposition::HookOnly(
            "wildcard in a middle segment: the sandbox expands Linux read entries once at configuration build and skips wildcard write entries, so there is no stable entry for it".into(),
        );
    }

    // the sentinel binary: only the running binary gets an entry, and only on
    // the write side (a read deny would stop the agent from running sentinel
    // status inside the sandbox).
    if !had_subtree_suffix
        && Path::new(normalized).file_name().and_then(|n| n.to_str()) == Some(BINARY_NAME)
    {
        return if ctx.current_exe.as_deref() == Some(expanded.as_path()) {
            emit_write(
                ctx.entry_for(&expanded),
                "self-protect: the running sentinel binary, writes only",
            )
        } else {
            Disposition::Withheld(
                "sentinel binary path that is not the running binary on this host (std::env::current_exe); a denyWrite on a missing file would create a Linux placeholder".into(),
            )
        };
    }

    if normalized.chars().any(char::is_whitespace) {
        return Disposition::Withheld(
            "path contains whitespace; how the generated Seatbelt profile quotes it is not documented, held back pending the live test".into(),
        );
    }

    let home_anchored = normalized.starts_with("~/");
    let wildcard = has_wildcard(last) || middle.contains(&"**");
    if wildcard {
        let write = home_anchored && ctx.write_wildcards;
        let note = if write {
            "wildcard entry: kept in denyRead; macOS also accepts it in denyWrite"
        } else if home_anchored {
            "wildcard entry: kept in denyRead on every platform; dropped from denyWrite because Linux and WSL2 skip wildcard write entries"
        } else {
            "wildcard entry: kept in denyRead on every platform; an absolute path gets no denyWrite entry"
        };
        return Disposition::Emit {
            entry: normalized.to_string(),
            read: true,
            write,
            note: Some(note.into()),
        };
    }
    if home_anchored {
        return Disposition::Emit {
            entry: normalized.to_string(),
            read: true,
            write: true,
            note: None,
        };
    }
    Disposition::Emit {
        entry: normalized.to_string(),
        read: true,
        write: false,
        note: Some("absolute system path: denyRead only; writes there are already outside the default writable set and a denyWrite on a possibly missing path would create a Linux placeholder".into()),
    }
}

fn emit_write(entry: String, note: &str) -> Disposition {
    Disposition::Emit {
        entry,
        read: false,
        write: true,
        note: Some(note.into()),
    }
}

fn has_wildcard(segment: &str) -> bool {
    segment.contains(['*', '?', '['])
}

/// strip a trailing `/`, `/*`, or `/**` (repeatedly). Returns the bare path
/// and whether anything was stripped, which tells a file rule from a subtree
/// rule.
fn strip_subtree_suffix(pattern: &str) -> (&str, bool) {
    let mut current = pattern.trim();
    let mut stripped = false;
    loop {
        let next = current
            .strip_suffix("/**")
            .or_else(|| current.strip_suffix("/*"))
            .or_else(|| current.strip_suffix('/'));
        match next {
            Some(shorter) if !shorter.is_empty() => {
                current = shorter;
                stripped = true;
            }
            _ => return (current, stripped),
        }
    }
}

// ---------------------------------------------------------------------------
// reconciliation against the live settings document
// ---------------------------------------------------------------------------

/// Apply a projection to a parsed settings document. Keeps every entry
/// sentinel did not write, replaces the entries recorded by a previous
/// install, never duplicates an entry the user already has, and pins the
/// three top-level keys while remembering what they were before sentinel
/// first touched them. Returns the record to persist.
pub fn apply_projection(
    settings: &mut Value,
    previous: Option<&SandboxRecord>,
    projection: &SandboxProjection,
    settings_path: &Path,
) -> Result<SandboxRecord, InstallError> {
    let sandbox = object_entry(settings, "sandbox")?;
    let mut prior = previous
        .map(|record| record.prior.clone())
        .unwrap_or_default();
    for (key, desired) in PINNED_KEYS {
        if previous.is_none() {
            prior.set(key, sandbox.get(key).cloned());
        }
        sandbox.insert(key.to_string(), Value::Bool(desired));
    }
    let filesystem = object_entry_in(sandbox, "filesystem", "sandbox.filesystem")?;
    let deny_read = reconcile_list(
        filesystem,
        "denyRead",
        previous.map(|record| record.deny_read.as_slice()),
        &projection.deny_read,
    )?;
    let deny_write = reconcile_list(
        filesystem,
        "denyWrite",
        previous.map(|record| record.deny_write.as_slice()),
        &projection.deny_write,
    )?;
    Ok(SandboxRecord {
        settings_path: settings_path.to_string_lossy().into_owned(),
        deny_read,
        deny_write,
        prior,
    })
}

/// Remove exactly the entries a record says sentinel wrote, and put the three
/// pinned keys back the way they were, but only where they still carry the
/// value sentinel set (a key the user changed since is left alone).
pub fn remove_projection(settings: &mut Value, record: &SandboxRecord) {
    let Some(sandbox) = settings.get_mut("sandbox").and_then(Value::as_object_mut) else {
        return;
    };
    if let Some(filesystem) = sandbox.get_mut("filesystem").and_then(Value::as_object_mut) {
        for (key, owned) in [
            ("denyRead", &record.deny_read),
            ("denyWrite", &record.deny_write),
        ] {
            if let Some(list) = filesystem.get_mut(key).and_then(Value::as_array_mut) {
                list.retain(|entry| !entry.as_str().is_some_and(|s| owned.iter().any(|o| o == s)));
                if list.is_empty() {
                    filesystem.remove(key);
                }
            }
        }
        if filesystem.is_empty() {
            sandbox.remove("filesystem");
        }
    }
    for (key, desired) in PINNED_KEYS {
        if sandbox.get(key) == Some(&Value::Bool(desired)) {
            match record.prior.get(key) {
                Some(value) => {
                    sandbox.insert(key.to_string(), value.clone());
                }
                None => {
                    sandbox.remove(key);
                }
            }
        }
    }
    if sandbox.is_empty() {
        settings.as_object_mut().map(|root| root.remove("sandbox"));
    }
}

fn object_entry<'a>(
    root: &'a mut Value,
    key: &str,
) -> Result<&'a mut Map<String, Value>, InstallError> {
    let map = root
        .as_object_mut()
        .ok_or_else(|| InstallError::WriteError("settings root is not an object".into()))?;
    object_entry_in(map, key, key)
}

fn object_entry_in<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'a mut Map<String, Value>, InstallError> {
    parent
        .entry(key)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| InstallError::WriteError(format!("{label} is not an object")))
}

fn reconcile_list(
    filesystem: &mut Map<String, Value>,
    key: &str,
    previously_owned: Option<&[String]>,
    projected: &[String],
) -> Result<Vec<String>, InstallError> {
    let list = filesystem
        .entry(key)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            InstallError::WriteError(format!("sandbox.filesystem.{key} is not an array"))
        })?;
    if let Some(owned) = previously_owned {
        list.retain(|entry| !entry.as_str().is_some_and(|s| owned.iter().any(|o| o == s)));
    }
    let mut written = Vec::new();
    for entry in projected {
        if !list.iter().any(|existing| existing.as_str() == Some(entry)) {
            list.push(Value::String(entry.clone()));
            written.push(entry.clone());
        }
    }
    Ok(written)
}

/// `sentinel install --sandbox`: write the projection into the settings file
/// the hook lives in, and record what was written.
pub fn install_bridge(
    settings_path: &Path,
    state_path: &Path,
    projection: &SandboxProjection,
) -> Result<SandboxRecord, InstallError> {
    let mut settings = read_settings(settings_path)?;
    let mut install_state = state::load_install_state(state_path)?;
    let record = apply_projection(
        &mut settings,
        install_state.sandbox.as_ref(),
        projection,
        settings_path,
    )?;
    install_state.sandbox = Some(record.clone());
    // the record first: if the settings write then fails, doctor reports the
    // entries as missing instead of the file carrying entries nobody owns.
    state::save_install_state(state_path, &install_state)?;
    write_settings(settings_path, &settings)?;
    Ok(record)
}

/// `sentinel uninstall`: remove only what the record says sentinel wrote.
/// Returns the record that was removed, if any.
pub fn uninstall_bridge(
    settings_path: &Path,
    state_path: &Path,
) -> Result<Option<SandboxRecord>, InstallError> {
    let mut install_state = state::load_install_state(state_path)?;
    let Some(record) = install_state.sandbox.take() else {
        return Ok(None);
    };
    if settings_path.exists() {
        let mut settings = read_settings(settings_path)?;
        remove_projection(&mut settings, &record);
        write_settings(settings_path, &settings)?;
    }
    state::save_install_state(state_path, &install_state)?;
    Ok(Some(record))
}

// ---------------------------------------------------------------------------
// inspection for status and doctor
// ---------------------------------------------------------------------------

/// live state of one deny list against the projection and the record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListDrift {
    /// projected entries present in the live list
    pub present: usize,
    /// projected entries absent from the live list
    pub missing: Vec<String>,
    /// recorded (sentinel-written) entries still live but no longer projected
    pub stale: Vec<String>,
    /// live entries sentinel neither wrote nor projects (the user's own)
    pub user: usize,
}

impl ListDrift {
    pub fn drifted(&self) -> bool {
        !self.missing.is_empty() || !self.stale.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxInspection {
    pub enabled: Option<bool>,
    pub fail_if_unavailable: Option<bool>,
    pub allow_unsandboxed_commands: Option<bool>,
    pub filesystem_disabled: bool,
    pub excluded_commands: Vec<String>,
    pub deny_read: ListDrift,
    pub deny_write: ListDrift,
}

impl SandboxInspection {
    /// the three pinned keys carry the values install set
    pub fn keys_pinned(&self) -> bool {
        self.enabled == Some(true)
            && self.fail_if_unavailable == Some(true)
            && self.allow_unsandboxed_commands == Some(false)
    }

    pub fn drifted(&self) -> bool {
        self.deny_read.drifted() || self.deny_write.drifted()
    }

    pub fn to_json(&self) -> Value {
        let list = |drift: &ListDrift| {
            json!({
                "present": drift.present,
                "missing": drift.missing,
                "stale": drift.stale,
                "user": drift.user,
            })
        };
        json!({
            "installed": true,
            "enabled": self.enabled,
            "failIfUnavailable": self.fail_if_unavailable,
            "allowUnsandboxedCommands": self.allow_unsandboxed_commands,
            "filesystemDisabled": self.filesystem_disabled,
            "excludedCommands": self.excluded_commands,
            "denyRead": list(&self.deny_read),
            "denyWrite": list(&self.deny_write),
            "drift": self.drifted(),
        })
    }
}

/// Compare the live settings document with the record and a fresh projection.
pub fn inspect(
    settings: &Value,
    record: &SandboxRecord,
    projection: &SandboxProjection,
) -> SandboxInspection {
    let sandbox = settings.get("sandbox");
    let flag = |key: &str| sandbox.and_then(|s| s.get(key)).and_then(Value::as_bool);
    let filesystem = sandbox.and_then(|s| s.get("filesystem"));
    let live_list = |key: &str| -> Vec<String> {
        filesystem
            .and_then(|f| f.get(key))
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let drift = |live: &[String], projected: &[String], recorded: &[String]| ListDrift {
        present: projected.iter().filter(|p| live.contains(p)).count(),
        missing: projected
            .iter()
            .filter(|p| !live.contains(p))
            .cloned()
            .collect(),
        stale: recorded
            .iter()
            .filter(|r| live.contains(r) && !projected.contains(r))
            .cloned()
            .collect(),
        user: live
            .iter()
            .filter(|l| !projected.contains(l) && !recorded.contains(l))
            .count(),
    };
    SandboxInspection {
        enabled: flag("enabled"),
        fail_if_unavailable: flag("failIfUnavailable"),
        allow_unsandboxed_commands: flag("allowUnsandboxedCommands"),
        filesystem_disabled: filesystem
            .and_then(|f| f.get("disabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        excluded_commands: sandbox
            .and_then(|s| s.get("excludedCommands"))
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        deny_read: drift(
            &live_list("denyRead"),
            &projection.deny_read,
            &record.deny_read,
        ),
        deny_write: drift(
            &live_list("denyWrite"),
            &projection.deny_write,
            &record.deny_write,
        ),
    }
}

/// Everything status and doctor need about the bridge on this host, gathered
/// with I/O: a fresh projection of the live policy and its comparison with
/// the live settings and the record. `None` when no bridge is recorded.
pub struct BridgeStatus {
    pub projection: SandboxProjection,
    pub inspection: SandboxInspection,
}

pub fn bridge_status(
    settings_path: &Path,
    policy: Result<&PolicyEngine, String>,
) -> Result<Option<BridgeStatus>, String> {
    let state_path = state::install_state_path().map_err(|e| e.to_string())?;
    let install_state = state::load_install_state(&state_path).map_err(|e| e.to_string())?;
    let Some(record) = install_state.sandbox else {
        return Ok(None);
    };
    let projection = project(policy?).map_err(|e| e.to_string())?;
    let settings = if settings_path.exists() {
        read_settings(settings_path).map_err(|e| e.to_string())?
    } else {
        json!({})
    };
    let inspection = inspect(&settings, &record, &projection);
    Ok(Some(BridgeStatus {
        projection,
        inspection,
    }))
}

/// one-line summary for `sentinel status`
pub fn summary_line(status: &BridgeStatus) -> String {
    let i = &status.inspection;
    let flag = |value: Option<bool>| match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unset",
    };
    let drift = if i.drifted() {
        format!(
            "drift ({} missing, {} stale; re-run `sentinel install --sandbox`)",
            i.deny_read.missing.len() + i.deny_write.missing.len(),
            i.deny_read.stale.len() + i.deny_write.stale.len()
        )
    } else {
        "no drift".into()
    };
    format!(
        "enabled={} failIfUnavailable={} allowUnsandboxedCommands={}; denyRead {}/{} denyWrite {}/{}; {}; {} rules compiled, {} hook-only, {} withheld",
        flag(i.enabled),
        flag(i.fail_if_unavailable),
        flag(i.allow_unsandboxed_commands),
        i.deny_read.present,
        status.projection.deny_read.len(),
        i.deny_write.present,
        status.projection.deny_write.len(),
        drift,
        status.projection.compiled_rules().count(),
        status.projection.hook_only.len(),
        status.projection.withheld.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::defaults::default_policy_content;
    use crate::install::state::SandboxPrior;

    fn ctx() -> ProjectionContext {
        ProjectionContext {
            home: PathBuf::from("/home/t"),
            config_dir: PathBuf::from("/home/t/.claude"),
            current_exe: Some(PathBuf::from("/home/t/.cargo/bin/sentinel")),
            mcp_baseline_exists: false,
            settings_local_exists: false,
            write_wildcards: false,
        }
    }

    fn engine() -> PolicyEngine {
        PolicyEngine::from_toml_str(&default_policy_content("enforce")).unwrap()
    }

    fn policy_with(rules: &str) -> PolicyEngine {
        PolicyEngine::from_toml_str(&format!(
            "[policy]\nmode = \"enforce\"\non_failure = \"closed\"\ndefault = \"allow\"\n{rules}"
        ))
        .unwrap()
    }

    /// The table test: every bundled deny.paths rule lands in exactly one of
    /// compiled, withheld, or hook-only, and the split matches the S1 spike
    /// counts at 089e0b8 (75 rules: 56 with a sandbox expression, 19 hook-only).
    #[test]
    fn bundled_rules_split_matches_the_s1_projection() {
        let engine = engine();
        let total = engine
            .rules()
            .iter()
            .filter(|r| r.section == "deny.paths")
            .count();
        assert_eq!(
            total, 75,
            "bundled deny.paths rule count changed; recompute the S1 split"
        );
        let projection = project_with(&engine, &ctx());

        let patterns: Vec<&str> = engine
            .rules()
            .iter()
            .filter(|r| r.section == "deny.paths")
            .map(|r| r.pattern)
            .collect();
        let compiled_rules = projection.compiled_rules().count();
        // withheld entries that are policy rules (settings.local.json is a
        // self-protect extra, withheld because the file is absent)
        let withheld_rules = projection
            .withheld
            .iter()
            .filter(|(pattern, _)| patterns.contains(&pattern.as_str()))
            .count();
        assert_eq!(projection.withheld.len(), withheld_rules + 1);
        assert_eq!(
            compiled_rules + withheld_rules + projection.hook_only.len(),
            total
        );
        assert_eq!(
            projection.hook_only.len(),
            19,
            "{:#?}",
            projection.hook_only
        );
        assert_eq!(
            compiled_rules + withheld_rules,
            56,
            "{:#?}",
            projection.withheld
        );
        assert_eq!(compiled_rules, 43);
        assert_eq!(withheld_rules, 13);

        // the hook-only set is exactly the 4 block rules with an unanchored
        // or mid-path glob plus the 15 warn rules
        let hook_only: Vec<&str> = projection
            .hook_only
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
        for pattern in [
            "/proc/*/environ",
            "**/globalStorage/state.vscdb",
            "**/*.kdbx",
            "**/wallet.dat",
        ] {
            assert!(hook_only.contains(&pattern), "{pattern} must be hook-only");
        }
        let warn_hook_only = projection
            .hook_only
            .iter()
            .filter(|(_, reason)| reason.starts_with("warn tier"))
            .count();
        assert_eq!(warn_hook_only, 15);

        // withheld: 9 whitespace paths (8 Application Support + Group
        // Containers), 3 binary paths that are not current_exe, the missing
        // mcp-baseline.json, and the missing settings.local.json
        let withheld: Vec<&str> = projection
            .withheld
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
        assert_eq!(withheld.len(), 14, "{withheld:#?}");
        assert_eq!(
            projection
                .withheld
                .iter()
                .filter(|(_, r)| r.starts_with("path contains whitespace"))
                .count(),
            9
        );
        for pattern in [
            "~/.local/bin/sentinel",
            "/usr/local/bin/sentinel",
            "/opt/homebrew/bin/sentinel",
            "~/.sentinel/mcp-baseline.json",
            "~/.claude/settings.local.json",
        ] {
            assert!(withheld.contains(&pattern), "{pattern} must be withheld");
        }

        // emitted lists: 37 both + 4 denyRead-only; 37 both + policy.toml +
        // the running binary + install-state.json + settings.json
        assert_eq!(
            projection.deny_read.len(),
            41,
            "{:#?}",
            projection.deny_read
        );
        assert_eq!(
            projection.deny_write.len(),
            41,
            "{:#?}",
            projection.deny_write
        );
        for entry in [
            "~/.ssh",
            "~/.aws",
            "~/.npmrc",
            "~/.kube/config",
            "~/.config/op",
        ] {
            assert!(projection.deny_read.contains(&entry.to_string()));
            assert!(projection.deny_write.contains(&entry.to_string()));
        }
        for entry in [
            "/etc/passwd",
            "/etc/shadow*",
            "/etc/master.passwd",
            "/Library/Keychains",
        ] {
            assert!(projection.deny_read.contains(&entry.to_string()), "{entry}");
            assert!(
                !projection.deny_write.contains(&entry.to_string()),
                "{entry}"
            );
        }
        for entry in [
            "~/.sentinel/policy.toml",
            "~/.sentinel/install-state.json",
            "~/.claude/settings.json",
            "~/.cargo/bin/sentinel",
        ] {
            assert!(
                projection.deny_write.contains(&entry.to_string()),
                "{entry}"
            );
            assert!(
                !projection.deny_read.contains(&entry.to_string()),
                "{entry}"
            );
        }
        // no entry keeps a trailing slash or glob suffix
        for entry in projection.deny_read.iter().chain(&projection.deny_write) {
            assert!(
                !entry.ends_with('/') && !entry.ends_with("/*") && !entry.ends_with("/**"),
                "{entry}"
            );
            assert!(entry.starts_with("~/") || entry.starts_with('/'), "{entry}");
        }
    }

    #[test]
    fn every_bundled_rule_is_listed_once() {
        let engine = engine();
        let projection = project_with(&engine, &ctx());
        let mut seen: Vec<&str> = projection
            .compiled_rules()
            .map(|rule| rule.pattern.as_str())
            .chain(projection.withheld.iter().map(|(p, _)| p.as_str()))
            .chain(projection.hook_only.iter().map(|(p, _)| p.as_str()))
            .filter(|p| *p != "~/.claude/settings.local.json")
            .collect();
        seen.sort_unstable();
        let mut expected: Vec<&str> = engine
            .rules()
            .iter()
            .filter(|r| r.section == "deny.paths")
            .map(|r| r.pattern)
            .collect();
        expected.sort_unstable();
        assert_eq!(seen, expected);
    }

    #[test]
    fn suffix_stripping_and_wildcard_rules() {
        assert_eq!(strip_subtree_suffix("~/.ssh/*"), ("~/.ssh", true));
        assert_eq!(
            strip_subtree_suffix("~/.config/op/**"),
            ("~/.config/op", true)
        );
        assert_eq!(strip_subtree_suffix("~/.aws/"), ("~/.aws", true));
        assert_eq!(strip_subtree_suffix("~/.netrc"), ("~/.netrc", false));
        assert_eq!(
            strip_subtree_suffix("/etc/shadow*"),
            ("/etc/shadow*", false)
        );

        let policy = policy_with(
            r#"
[[deny.paths]]
pattern = "~/**/.secret"
action = "block"
reason = "documented ~/**/name shape"

[[deny.paths]]
pattern = "~/vault/*.kdbx"
action = "block"
reason = "suffix glob under home"

[[deny.paths]]
pattern = "/var/*/secret"
action = "block"
reason = "mid-path glob"

[[deny.paths]]
pattern = "relative/thing"
action = "block"
reason = "unanchored"

[[deny.paths]]
pattern = "~/.sentinel/mcp-baseline.json"
action = "warn"
reason = "self-protect file"
"#,
        );
        let linux = project_with(&policy, &ctx());
        assert!(linux.deny_read.contains(&"~/**/.secret".to_string()));
        assert!(!linux.deny_write.contains(&"~/**/.secret".to_string()));
        assert!(linux.deny_read.contains(&"~/vault/*.kdbx".to_string()));
        assert!(!linux.deny_write.contains(&"~/vault/*.kdbx".to_string()));
        let hook_only: Vec<&str> = linux.hook_only.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(hook_only, ["/var/*/secret", "relative/thing"]);
        assert!(linux
            .withheld
            .iter()
            .any(|(p, _)| p == "~/.sentinel/mcp-baseline.json"));

        let mut macos = ctx();
        macos.write_wildcards = true;
        macos.mcp_baseline_exists = true;
        let macos = project_with(&policy, &macos);
        assert!(macos.deny_write.contains(&"~/**/.secret".to_string()));
        assert!(macos.deny_write.contains(&"~/vault/*.kdbx".to_string()));
        assert!(macos
            .deny_write
            .contains(&"~/.sentinel/mcp-baseline.json".to_string()));
        assert!(!macos
            .deny_read
            .contains(&"~/.sentinel/mcp-baseline.json".to_string()));
    }

    #[test]
    fn relocated_config_dir_and_binary_outside_home_use_absolute_entries() {
        let mut context = ctx();
        context.config_dir = PathBuf::from("/srv/claude-config");
        context.current_exe = Some(PathBuf::from("/usr/local/bin/sentinel"));
        let projection = project_with(&engine(), &context);
        assert!(projection
            .deny_write
            .contains(&"/srv/claude-config/settings.json".to_string()));
        assert!(projection
            .deny_write
            .contains(&"/usr/local/bin/sentinel".to_string()));
        assert!(!projection
            .deny_write
            .contains(&"~/.cargo/bin/sentinel".to_string()));
        assert!(projection
            .withheld
            .iter()
            .any(|(p, _)| p == "~/.cargo/bin/sentinel"));
    }

    fn projection_of(read: &[&str], write: &[&str]) -> SandboxProjection {
        SandboxProjection {
            deny_read: read.iter().map(|s| s.to_string()).collect(),
            deny_write: write.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn apply_keeps_user_entries_and_reinstall_is_identical() {
        let mut settings = json!({
            "theme": "dark",
            "sandbox": {
                "enabled": false,
                "filesystem": {"denyRead": ["~/mine"], "denyWrite": ["~/.ssh"]}
            }
        });
        let projection = projection_of(&["~/.ssh", "~/.aws"], &["~/.ssh", "~/.aws"]);
        let path = Path::new("/home/t/.claude/settings.json");
        let record = apply_projection(&mut settings, None, &projection, path).unwrap();
        assert_eq!(record.deny_read, ["~/.ssh", "~/.aws"]);
        // the user already had ~/.ssh in denyWrite: not duplicated, not owned
        assert_eq!(record.deny_write, ["~/.aws"]);
        assert_eq!(record.prior.enabled, Some(Value::Bool(false)));
        assert_eq!(record.prior.fail_if_unavailable, None);
        let first = settings.clone();
        assert_eq!(first["sandbox"]["enabled"], true);
        assert_eq!(first["sandbox"]["failIfUnavailable"], true);
        assert_eq!(first["sandbox"]["allowUnsandboxedCommands"], false);
        assert_eq!(
            first["sandbox"]["filesystem"]["denyRead"],
            json!(["~/mine", "~/.ssh", "~/.aws"])
        );
        assert_eq!(
            first["sandbox"]["filesystem"]["denyWrite"],
            json!(["~/.ssh", "~/.aws"])
        );

        let again = apply_projection(&mut settings, Some(&record), &projection, path).unwrap();
        assert_eq!(again, record);
        assert_eq!(
            settings, first,
            "reinstall must produce an identical document"
        );

        // a changed projection drops the stale owned entry and keeps the user's
        let narrower = projection_of(&["~/.ssh"], &["~/.ssh"]);
        let third = apply_projection(&mut settings, Some(&record), &narrower, path).unwrap();
        assert_eq!(
            settings["sandbox"]["filesystem"]["denyRead"],
            json!(["~/mine", "~/.ssh"])
        );
        assert_eq!(
            settings["sandbox"]["filesystem"]["denyWrite"],
            json!(["~/.ssh"])
        );
        assert_eq!(third.deny_write, Vec::<String>::new());
        assert_eq!(
            third.prior, record.prior,
            "prior values survive a reinstall"
        );
    }

    #[test]
    fn remove_restores_prior_keys_and_leaves_user_changes() {
        let mut settings = json!({"theme": "dark"});
        let projection = projection_of(&["~/.ssh"], &["~/.ssh", "~/.sentinel/policy.toml"]);
        let path = Path::new("/home/t/.claude/settings.json");
        let record = apply_projection(&mut settings, None, &projection, path).unwrap();
        remove_projection(&mut settings, &record);
        assert_eq!(
            settings,
            json!({"theme": "dark"}),
            "a clean install uninstalls to the original"
        );

        // the user flipped enabled off and added an entry after install
        let mut settings = json!({"sandbox": {"enabled": true}});
        let record = apply_projection(&mut settings, None, &projection, path).unwrap();
        settings["sandbox"]["allowUnsandboxedCommands"] = json!(true);
        settings["sandbox"]["filesystem"]["denyRead"]
            .as_array_mut()
            .unwrap()
            .push(json!("~/mine"));
        remove_projection(&mut settings, &record);
        assert_eq!(
            settings,
            json!({"sandbox": {
                "enabled": true,
                "allowUnsandboxedCommands": true,
                "filesystem": {"denyRead": ["~/mine"]}
            }})
        );
    }

    #[test]
    fn apply_rejects_a_malformed_sandbox_shape() {
        let mut settings = json!({"sandbox": "yes"});
        let projection = projection_of(&["~/.ssh"], &[]);
        let path = Path::new("/home/t/.claude/settings.json");
        assert!(apply_projection(&mut settings, None, &projection, path).is_err());
        let mut settings = json!({"sandbox": {"filesystem": {"denyRead": "~/.ssh"}}});
        assert!(apply_projection(&mut settings, None, &projection, path).is_err());
    }

    #[test]
    fn inspect_reports_missing_stale_and_user_entries() {
        let projection = projection_of(&["~/.ssh", "~/.aws"], &["~/.ssh"]);
        let record = SandboxRecord {
            settings_path: "/home/t/.claude/settings.json".into(),
            deny_read: vec!["~/.ssh".into(), "~/.old".into()],
            deny_write: vec!["~/.ssh".into()],
            prior: SandboxPrior::default(),
        };
        let settings = json!({"sandbox": {
            "enabled": true,
            "failIfUnavailable": true,
            "allowUnsandboxedCommands": false,
            "excludedCommands": ["gh *"],
            "filesystem": {"denyRead": ["~/.ssh", "~/.old", "~/mine"], "denyWrite": []}
        }});
        let inspection = inspect(&settings, &record, &projection);
        assert!(inspection.keys_pinned());
        assert_eq!(inspection.deny_read.present, 1);
        assert_eq!(inspection.deny_read.missing, ["~/.aws"]);
        assert_eq!(inspection.deny_read.stale, ["~/.old"]);
        assert_eq!(inspection.deny_read.user, 1);
        assert_eq!(inspection.deny_write.missing, ["~/.ssh"]);
        assert!(inspection.drifted());
        assert_eq!(inspection.excluded_commands, ["gh *"]);
        assert_eq!(inspection.to_json()["drift"], true);

        let healthy = json!({"sandbox": {
            "enabled": true,
            "failIfUnavailable": true,
            "allowUnsandboxedCommands": false,
            "filesystem": {"denyRead": ["~/.ssh", "~/.aws"], "denyWrite": ["~/.ssh"]}
        }});
        let record = SandboxRecord {
            deny_read: vec!["~/.ssh".into(), "~/.aws".into()],
            ..record
        };
        let inspection = inspect(&healthy, &record, &projection);
        assert!(!inspection.drifted());
        assert_eq!(inspection.deny_read.user, 0);
        let unset = inspect(&json!({}), &record, &projection);
        assert!(!unset.keys_pinned());
        assert_eq!(unset.enabled, None);
    }
}
