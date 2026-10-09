use super::activation::{self, Activation};
use super::hooks::{self, HookInspection, HookOwnership};
use super::{claude_settings_path, codex_config_path, codex_hooks_path, AgentTarget, InstallError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Sidecar record of what `sentinel install` wrote into a host's settings
/// beyond the hook entry itself. The sandbox lists are plain string arrays with
/// no room for an ownership tag, so this file is the tag: uninstall removes
/// only entries listed here, doctor diffs them, and self-protect reads it to
/// know whether the sandbox bridge is installed at all.
///
/// It also carries the pins `sentinel session-check` compares the live
/// install against: the SHA-256 of the installed binary and of the policy as
/// they were when `sentinel install` last ran (`policy-migrate --apply`
/// re-pins the policy). A missing pin means "not pinned", which the check
/// reports but never fails on, so an install that predates the pins keeps
/// working.
///
/// Lives at `~/.sentinel/install-state.json`, 0600 on Unix, written atomically.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallState {
    #[serde(default = "install_state_version")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxRecord>,
    /// SHA-256 (lowercase hex) of the sentinel binary `install` ran as
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_sha256: Option<String>,
    /// SHA-256 (lowercase hex) of `~/.sentinel/policy.toml` after `install`
    /// wrote or preserved it, or after `policy-migrate --apply` rewrote it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_sha256: Option<String>,
}

impl InstallState {
    /// whether `install` has pinned both digests
    pub fn pinned(&self) -> bool {
        self.binary_sha256.is_some() && self.policy_sha256.is_some()
    }
}

fn install_state_version() -> u32 {
    1
}

/// SHA-256 of a file's bytes, lowercase hex. The same digest `session-check`
/// computes at session start, so a pin and a live value compare as strings.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    Ok(crate::common::encode_hex(&Sha256::digest(bytes)))
}

/// `sentinel install`: pin the digests of the binary that is being installed
/// and the policy that was just written or preserved. Keeps everything else
/// in the state file (the sandbox record in particular).
pub fn pin_digests(
    state_path: &Path,
    binary_path: &Path,
    policy_path: &Path,
) -> Result<InstallState, InstallError> {
    let mut state = load_install_state(state_path)?;
    state.binary_sha256 =
        Some(sha256_file(binary_path).map_err(|error| {
            InstallError::ReadError(format!("{}: {error}", binary_path.display()))
        })?);
    state.policy_sha256 =
        Some(sha256_file(policy_path).map_err(|error| {
            InstallError::ReadError(format!("{}: {error}", policy_path.display()))
        })?);
    save_install_state(state_path, &state)?;
    Ok(state)
}

/// `policy-migrate --apply`: the policy was just rewritten by sentinel, so the
/// pin follows it. Only an existing state file is touched: without one, no
/// install ever pinned anything and there is nothing to refresh. Returns
/// whether a pin was written.
pub fn refresh_policy_pin(state_path: &Path, policy_path: &Path) -> Result<bool, InstallError> {
    if !state_path.exists() {
        return Ok(false);
    }
    let mut state = load_install_state(state_path)?;
    state.policy_sha256 =
        Some(sha256_file(policy_path).map_err(|error| {
            InstallError::ReadError(format!("{}: {error}", policy_path.display()))
        })?);
    save_install_state(state_path, &state)?;
    Ok(true)
}

/// `sentinel uninstall`: the hook is gone, so the pins that described the
/// install go with it. The sandbox record is handled by `sandbox::uninstall_bridge`.
pub fn clear_pins(state_path: &Path) -> Result<(), InstallError> {
    if !state_path.exists() {
        return Ok(());
    }
    let mut state = load_install_state(state_path)?;
    if state.binary_sha256.is_none() && state.policy_sha256.is_none() {
        return Ok(());
    }
    state.binary_sha256 = None;
    state.policy_sha256 = None;
    save_install_state(state_path, &state)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRecord {
    /// the settings file the entries were written to
    pub settings_path: String,
    /// `sandbox.filesystem.denyRead` entries sentinel appended (entries the
    /// user already had are not listed and are never removed)
    pub deny_read: Vec<String>,
    /// `sandbox.filesystem.denyWrite` entries sentinel appended
    pub deny_write: Vec<String>,
    /// the pinned keys as they were before sentinel first set them
    #[serde(default)]
    pub prior: SandboxPrior,
}

/// Values of the three pinned sandbox keys before the first `--sandbox`
/// install. `None` means the key was absent, so uninstall removes it again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPrior {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_if_unavailable: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_unsandboxed_commands: Option<Value>,
}

impl SandboxPrior {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match key {
            "enabled" => self.enabled.as_ref(),
            "failIfUnavailable" => self.fail_if_unavailable.as_ref(),
            "allowUnsandboxedCommands" => self.allow_unsandboxed_commands.as_ref(),
            _ => None,
        }
    }

    pub fn set(&mut self, key: &str, value: Option<Value>) {
        match key {
            "enabled" => self.enabled = value,
            "failIfUnavailable" => self.fail_if_unavailable = value,
            "allowUnsandboxedCommands" => self.allow_unsandboxed_commands = value,
            _ => {}
        }
    }
}

pub fn install_state_path() -> std::io::Result<PathBuf> {
    Ok(super::sentinel_dir()?.join("install-state.json"))
}

/// An absent file is an empty state. A present but unreadable or unparseable
/// file is an error: guessing "nothing installed" would let uninstall leave
/// entries behind and self-protect stand down.
pub fn load_install_state(path: &Path) -> Result<InstallState, InstallError> {
    if !path.exists() {
        return Ok(InstallState::default());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|error| InstallError::ReadError(format!("{}: {error}", path.display())))?;
    serde_json::from_str(&content).map_err(|error| {
        InstallError::ReadError(format!(
            "{} is not valid install state: {error}",
            path.display()
        ))
    })
}

pub fn save_install_state(path: &Path, state: &InstallState) -> Result<(), InstallError> {
    let content = serde_json::to_string_pretty(&InstallState {
        version: 1,
        ..state.clone()
    })
    .map_err(|error| InstallError::WriteError(error.to_string()))?;
    hooks::atomic_write(path, &content)
}

#[derive(Debug, Clone)]
pub struct AgentState {
    pub config_path: PathBuf,
    pub config_exists: bool,
    pub hook: HookInspection,
    pub activation: Activation,
}

pub fn inspect_agent(target: AgentTarget) -> std::io::Result<AgentState> {
    Ok(match target {
        AgentTarget::ClaudeCode => inspect_claude(claude_settings_path()?),
        AgentTarget::Codex => inspect_codex(codex_config_path()?, codex_hooks_path()?),
    })
}

fn inspect_claude(config_path: PathBuf) -> AgentState {
    let config_exists = config_path.exists();
    let parsed = std::fs::read_to_string(&config_path)
        .map_err(|error| error.to_string())
        .and_then(|content| {
            serde_json::from_str::<serde_json::Value>(&content).map_err(|error| error.to_string())
        });
    let (hook, activation) = match parsed {
        Ok(settings) => match hooks::inspect_claude_pre_tool(&settings) {
            Ok(hook) => {
                let activation = activation_for_inspection(
                    &hook,
                    || activation::claude_activation(&settings),
                    "Claude Code",
                );
                (hook, activation)
            }
            Err(error) => (
                absent_hook(),
                Activation::Broken(format!("invalid Claude hook configuration: {error}")),
            ),
        },
        Err(_) if !config_exists => (
            absent_hook(),
            Activation::Broken("Claude Code settings file is absent".into()),
        ),
        Err(error) => (
            absent_hook(),
            Activation::Broken(format!("could not parse Claude Code settings: {error}")),
        ),
    };
    AgentState {
        config_path,
        config_exists,
        hook,
        activation,
    }
}

fn inspect_codex(config_path: PathBuf, hooks_path: PathBuf) -> AgentState {
    let config_exists = config_path.exists() || hooks_path.exists();
    let inline = match hooks::read_codex_config(&config_path) {
        Ok(document) => hooks::inspect_codex_pre_tool(&document),
        Err(error) => {
            return AgentState {
                config_path,
                config_exists,
                hook: absent_hook(),
                activation: Activation::Broken(format!(
                    "could not parse Codex configuration: {error}"
                )),
            };
        }
    };
    let json = if hooks_path.exists() {
        match std::fs::read_to_string(&hooks_path)
            .map_err(|error| error.to_string())
            .and_then(|content| {
                serde_json::from_str::<serde_json::Value>(&content)
                    .map_err(|error| error.to_string())
            })
            .and_then(|settings| {
                hooks::inspect_claude_pre_tool(&settings).map_err(|error| error.to_string())
            }) {
            Ok(inspection) => inspection,
            Err(error) => {
                return AgentState {
                    config_path: hooks_path,
                    config_exists,
                    hook: absent_hook(),
                    activation: Activation::Broken(format!(
                        "could not parse Codex hooks.json: {error}"
                    )),
                };
            }
        }
    } else {
        absent_hook()
    };
    let hook = combine_codex_sources(&inline, &json);
    let active_path = if json.ownership != HookOwnership::Absent {
        hooks_path
    } else {
        config_path
    };
    let activation = activation_for_inspection(
        &hook,
        || {
            let command = hook
                .command
                .as_deref()
                .expect("configured hook inspection carries its command");
            activation::query_codex_activation(command)
        },
        "Codex",
    );
    AgentState {
        config_path: active_path,
        config_exists,
        hook,
        activation,
    }
}

fn combine_codex_sources(inline: &HookInspection, json: &HookInspection) -> HookInspection {
    let direct_count = inline.direct_count + json.direct_count;
    let mediated_count = inline.mediated_count + json.mediated_count;
    let ownership = match (direct_count, mediated_count) {
        (0, 0) => HookOwnership::Absent,
        (1, 0) => HookOwnership::Direct,
        (0, 1) => HookOwnership::Mediated,
        _ => HookOwnership::Conflict,
    };
    let command = match ownership {
        HookOwnership::Direct | HookOwnership::Mediated => {
            inline.command.clone().or_else(|| json.command.clone())
        }
        _ => None,
    };
    HookInspection {
        ownership,
        command,
        direct_count,
        mediated_count,
    }
}

fn activation_for_inspection(
    hook: &HookInspection,
    active_probe: impl FnOnce() -> Activation,
    agent: &str,
) -> Activation {
    match hook.ownership {
        HookOwnership::Absent => Activation::Broken(format!(
            "no Sentinel PreToolUse hook is configured for {agent}"
        )),
        HookOwnership::Conflict => Activation::Broken(format!(
            "conflicting Sentinel hooks are configured for {agent} ({} direct, {} mediated)",
            hook.direct_count, hook.mediated_count
        )),
        HookOwnership::Direct | HookOwnership::Mediated => active_probe(),
    }
}

fn absent_hook() -> HookInspection {
    HookInspection {
        ownership: HookOwnership::Absent,
        command: None,
        direct_count: 0,
        mediated_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspection(
        ownership: HookOwnership,
        command: Option<&str>,
        direct_count: usize,
        mediated_count: usize,
    ) -> HookInspection {
        HookInspection {
            ownership,
            command: command.map(str::to_string),
            direct_count,
            mediated_count,
        }
    }

    #[test]
    fn pins_round_trip_and_an_older_state_file_reads_as_unpinned() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("install-state.json");
        let binary = dir.path().join("sentinel");
        let policy = dir.path().join("policy.toml");
        std::fs::write(&binary, b"binary bytes").unwrap();
        std::fs::write(&policy, "[policy]\nmode = \"enforce\"\n").unwrap();

        // a #92-era state file: sandbox record only, no pins
        std::fs::write(
            &state_path,
            r#"{"version":1,"sandbox":{"settings_path":"/h/.claude/settings.json","deny_read":["~/.ssh"],"deny_write":[]}}"#,
        )
        .unwrap();
        let old = load_install_state(&state_path).unwrap();
        assert!(!old.pinned());
        assert_eq!(old.binary_sha256, None);
        assert!(old.sandbox.is_some());

        let pinned = pin_digests(&state_path, &binary, &policy).unwrap();
        assert!(pinned.pinned());
        assert_eq!(
            pinned.binary_sha256.as_deref(),
            Some(sha256_file(&binary).unwrap().as_str())
        );
        assert_eq!(
            pinned.policy_sha256.as_deref(),
            Some(sha256_file(&policy).unwrap().as_str())
        );
        let reloaded = load_install_state(&state_path).unwrap();
        assert_eq!(reloaded, pinned);
        assert_eq!(
            reloaded.sandbox.as_ref().unwrap().deny_read,
            ["~/.ssh"],
            "pinning keeps the sandbox record"
        );
        assert_eq!(reloaded.binary_sha256.as_ref().unwrap().len(), 64);

        // the policy changes: refresh follows it and leaves the binary pin alone
        std::fs::write(&policy, "[policy]\nmode = \"audit\"\n").unwrap();
        assert!(refresh_policy_pin(&state_path, &policy).unwrap());
        let refreshed = load_install_state(&state_path).unwrap();
        assert_eq!(refreshed.binary_sha256, pinned.binary_sha256);
        assert_ne!(refreshed.policy_sha256, pinned.policy_sha256);
        assert_eq!(
            refreshed.policy_sha256.as_deref(),
            Some(sha256_file(&policy).unwrap().as_str())
        );

        clear_pins(&state_path).unwrap();
        let cleared = load_install_state(&state_path).unwrap();
        assert!(!cleared.pinned());
        assert!(cleared.sandbox.is_some());
        let raw = std::fs::read_to_string(&state_path).unwrap();
        assert!(
            !raw.contains("sha256"),
            "absent pins are not serialized: {raw}"
        );

        // no state file: nothing to refresh, nothing created
        let absent = dir.path().join("missing.json");
        assert!(!refresh_policy_pin(&absent, &policy).unwrap());
        clear_pins(&absent).unwrap();
        assert!(!absent.exists());
    }

    #[test]
    fn codex_sources_reconcile_to_one_hook_or_an_explicit_conflict() {
        let absent = absent_hook();
        let json = inspection(
            HookOwnership::Direct,
            Some("/bin/sentinel evaluate --agent codex"),
            1,
            0,
        );
        assert_eq!(
            combine_codex_sources(&absent, &json).ownership,
            HookOwnership::Direct
        );
        let both = combine_codex_sources(&json, &json);
        assert_eq!(both.ownership, HookOwnership::Conflict);
        assert_eq!(both.direct_count, 2);
        assert!(both.command.is_none());
    }
}
