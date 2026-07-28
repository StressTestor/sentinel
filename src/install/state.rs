use super::activation::{self, Activation};
use super::hooks::{self, HookInspection, HookOwnership};
use super::{claude_settings_path, codex_config_path, codex_hooks_path, AgentTarget};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AgentState {
    pub config_path: PathBuf,
    pub config_exists: bool,
    pub hook: HookInspection,
    pub activation: Activation,
}

pub fn inspect_agent(target: AgentTarget) -> AgentState {
    match target {
        AgentTarget::ClaudeCode => inspect_claude(),
        AgentTarget::Codex => inspect_codex(),
    }
}

fn inspect_claude() -> AgentState {
    let config_path = claude_settings_path();
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

fn inspect_codex() -> AgentState {
    let config_path = codex_config_path();
    let hooks_path = codex_hooks_path();
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
