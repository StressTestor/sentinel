//! `sentinel session-check`: the SessionStart integrity check (E1).
//!
//! Compares the live install with the pins `sentinel install` wrote into
//! `~/.sentinel/install-state.json`: the hook entry in the agent's settings,
//! the SHA-256 of the binary that entry points at, the SHA-256 of
//! `~/.sentinel/policy.toml`, and, when a sandbox bridge is recorded, the
//! projection drift the bridge inspection already computes for `doctor`.
//!
//! Contract (Claude Code SessionStart hooks): the hook cannot block anything.
//! Exit 0 always; stdout is added to the model's context, so every finding is
//! one short `sentinel: ...` line there and the same line on stderr for the
//! operator. A clean check prints nothing. `--json` prints a stable object
//! (`ok`, `findings`, `pins`) on stdout instead, with findings still on
//! stderr. Nothing here reads the hook payload beyond draining stdin, and no
//! digest or line carries a secret.
//!
//! Absent pins (an install from before this check) are reported in `--json`
//! and by `doctor`, never as a finding: an older install must keep working.

use crate::cli::SessionCheckArgs;
use crate::install::hooks::{classify_hook_command, split_shell_words, HookCommandKind};
use crate::install::sandbox;
use crate::install::state::{self, InstallState};
use crate::install::{self, AgentTarget};
use crate::policy::PolicyEngine;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// One mismatch between the live install and its pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `hook`, `binary`, `policy`, `sandbox`, or `state` (the check itself
    /// could not read something it needs)
    pub kind: &'static str,
    pub detail: String,
}

/// What the check compared against (the pins) and what it saw (live). Digests
/// are of files sentinel owns or installed, never of a payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pins {
    pub binary_sha256: Option<String>,
    pub policy_sha256: Option<String>,
    pub sandbox_recorded: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Live {
    pub hook_command: Option<String>,
    pub binary_path: Option<String>,
    pub binary_sha256: Option<String>,
    pub policy_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCheckReport {
    pub agent: &'static str,
    pub findings: Vec<Finding>,
    pub pins: Pins,
    pub live: Live,
}

impl SessionCheckReport {
    pub fn ok(&self) -> bool {
        self.findings.is_empty()
    }

    /// The stable `--json` shape: `ok`, `findings[{kind, detail}]`, `pins`.
    /// `live` and `agent` are additional and may grow; the first three keep
    /// their shape.
    pub fn to_json(&self) -> Value {
        json!({
            "ok": self.ok(),
            "agent": self.agent,
            "findings": self.findings.iter().map(|finding| json!({
                "kind": finding.kind,
                "detail": finding.detail,
            })).collect::<Vec<_>>(),
            "pins": {
                "binary_sha256": self.pins.binary_sha256,
                "policy_sha256": self.pins.policy_sha256,
                "sandbox_recorded": self.pins.sandbox_recorded,
            },
            "live": {
                "hook_command": self.live.hook_command,
                "binary_path": self.live.binary_path,
                "binary_sha256": self.live.binary_sha256,
                "policy_sha256": self.live.policy_sha256,
            },
        })
    }
}

/// Inputs the comparison needs, gathered with I/O by [`gather`] so the
/// comparison itself ([`compare`]) is pure and unit-testable.
#[derive(Debug, Clone)]
pub struct Observed {
    pub agent: &'static str,
    pub state: Result<InstallState, String>,
    pub config_path: PathBuf,
    pub config_exists: bool,
    pub hook: Result<install::hooks::HookInspection, String>,
    pub activation: Option<install::activation::Activation>,
    pub policy_path: PathBuf,
    pub policy_sha256: Result<String, String>,
    /// `None` when no bridge is recorded or the agent has no sandbox
    pub sandbox: Option<Result<sandbox::SandboxInspection, String>>,
}

pub fn run(args: SessionCheckArgs) -> Result<(), Box<dyn std::error::Error>> {
    drain_stdin();
    let report = match AgentTarget::parse(&args.agent) {
        Some(target) => compare(&gather(target)),
        None => SessionCheckReport {
            agent: "unknown",
            findings: vec![Finding {
                kind: "state",
                detail: format!(
                    "session-check does not support agent `{}` (use claude-code or codex)",
                    args.agent
                ),
            }],
            pins: Pins::default(),
            live: Live::default(),
        },
    };
    for finding in &report.findings {
        // the model's context on SessionStart is stdout; the operator reads
        // stderr. With --json, stdout is the object only.
        if !args.json {
            println!("sentinel: {}", finding.detail);
        }
        eprintln!("sentinel: {}", finding.detail);
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    }
    // never a non-zero exit: a SessionStart hook cannot block, and a failed
    // hook would only add noise to the session that the findings already carry
    Ok(())
}

/// A SessionStart hook receives a JSON payload on stdin. The check does not
/// need it; read it to the end (bounded) so the host never sees a broken pipe,
/// and never echo it. A terminal stdin is left alone.
fn drain_stdin() {
    use std::io::{IsTerminal, Read};
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return;
    }
    let mut sink = Vec::new();
    let _ = stdin.lock().take(1 << 20).read_to_end(&mut sink);
}

/// Everything the comparison needs, read from the live host.
pub fn gather(target: AgentTarget) -> Observed {
    let agent = target.evaluate_agent_arg();
    let state_result = state::install_state_path()
        .map_err(|error| error.to_string())
        .and_then(|path| state::load_install_state(&path).map_err(|error| error.to_string()));
    let policy_path = crate::common::home_dir()
        .map(|home| home.join(".sentinel/policy.toml"))
        .unwrap_or_else(|_| PathBuf::from("~/.sentinel/policy.toml"));
    let policy_sha256 = state::sha256_file(&policy_path).map_err(|error| error.to_string());
    let agent_state = state::inspect_agent(target).map_err(|error| error.to_string());
    let (config_path, config_exists, hook, activation) = match agent_state {
        Ok(agent_state) => (
            agent_state.config_path,
            agent_state.config_exists,
            Ok(agent_state.hook),
            Some(agent_state.activation),
        ),
        Err(error) => (PathBuf::new(), false, Err(error), None),
    };
    let sandbox = match (&state_result, target) {
        (Ok(state), AgentTarget::ClaudeCode) if state.sandbox.is_some() => {
            let engine = PolicyEngine::load(&policy_path).map_err(|error| error.to_string());
            Some(
                sandbox::bridge_status(&config_path, engine.as_ref().map_err(Clone::clone))
                    .and_then(|bridge| {
                        bridge
                            .map(|bridge| bridge.inspection)
                            .ok_or_else(|| "bridge record vanished during the check".to_string())
                    }),
            )
        }
        _ => None,
    };
    Observed {
        agent,
        state: state_result,
        config_path,
        config_exists,
        hook,
        activation,
        policy_path,
        policy_sha256,
        sandbox,
    }
}

/// The path the hook command executes: argv[0] of a direct entry, the
/// `--sentinel` operand of a Ghost bridge.
pub fn hooked_binary_path(command: &str) -> Option<String> {
    let argv = split_shell_words(command)?;
    match classify_hook_command(command) {
        HookCommandKind::DirectPre => argv.first().cloned(),
        HookCommandKind::GhostBridge => argv.get(3).cloned(),
        _ => None,
    }
}

fn short(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

/// Pure comparison of the observed state with the pins.
pub fn compare(observed: &Observed) -> SessionCheckReport {
    let mut findings = Vec::new();
    let mut pins = Pins::default();
    let mut live = Live::default();

    match &observed.state {
        Ok(state) => {
            pins.binary_sha256 = state.binary_sha256.clone();
            pins.policy_sha256 = state.policy_sha256.clone();
            pins.sandbox_recorded = state.sandbox.is_some();
        }
        Err(error) => findings.push(Finding {
            kind: "state",
            detail: format!("install state cannot be read: {error}"),
        }),
    }

    // the hook entry
    match &observed.hook {
        Ok(hook) => {
            use install::hooks::HookOwnership;
            match hook.ownership {
                HookOwnership::Absent if observed.config_exists => findings.push(Finding {
                    kind: "hook",
                    detail: format!(
                        "no sentinel PreToolUse hook is registered in {}; the guard is off for this session (re-run `sentinel install`)",
                        observed.config_path.display()
                    ),
                }),
                HookOwnership::Absent => findings.push(Finding {
                    kind: "hook",
                    detail: format!(
                        "{} is missing, so no sentinel hook is registered (re-run `sentinel install`)",
                        observed.config_path.display()
                    ),
                }),
                HookOwnership::Conflict => findings.push(Finding {
                    kind: "hook",
                    detail: format!(
                        "conflicting sentinel hook entries in {} ({} direct, {} mediated); run `sentinel install` to reconcile",
                        observed.config_path.display(),
                        hook.direct_count,
                        hook.mediated_count
                    ),
                }),
                HookOwnership::Direct | HookOwnership::Mediated => {
                    live.hook_command = hook.command.clone();
                }
            }
            if let Some(activation) = &observed.activation {
                if hook.ownership != HookOwnership::Absent
                    && hook.ownership != HookOwnership::Conflict
                    && !activation.healthy()
                {
                    findings.push(Finding {
                        kind: "hook",
                        detail: match activation.detail() {
                            Some(detail) => format!(
                                "the sentinel hook is registered but {}: {detail}",
                                activation.label()
                            ),
                            None => format!(
                                "the sentinel hook is registered but {} (check disableAllHooks and the host's hook trust)",
                                activation.label()
                            ),
                        },
                    });
                }
            }
        }
        Err(error) => findings.push(Finding {
            kind: "hook",
            detail: format!("agent configuration cannot be inspected: {error}"),
        }),
    }

    // the binary the hook runs
    if let Some(command) = &live.hook_command {
        match hooked_binary_path(command) {
            Some(path) => {
                live.binary_path = Some(path.clone());
                match state::sha256_file(Path::new(&path)) {
                    Ok(digest) => {
                        if let Some(pinned) = &pins.binary_sha256 {
                            if *pinned != digest {
                                findings.push(Finding {
                                    kind: "binary",
                                    detail: format!(
                                        "the sentinel binary at {path} differs from the one pinned at install (sha256 {} now, {} pinned); re-run `sentinel install` if you upgraded sentinel",
                                        short(&digest),
                                        short(pinned)
                                    ),
                                });
                            }
                        }
                        live.binary_sha256 = Some(digest);
                    }
                    Err(error) => findings.push(Finding {
                        kind: "binary",
                        detail: format!(
                            "the hook points at {path}, which cannot be read ({error}); the hook fails open for this session"
                        ),
                    }),
                }
            }
            None => findings.push(Finding {
                kind: "binary",
                detail: format!("the hook command `{command}` has no recognizable binary path"),
            }),
        }
    }

    // the policy
    match &observed.policy_sha256 {
        Ok(digest) => {
            if let Some(pinned) = &pins.policy_sha256 {
                if pinned != digest {
                    findings.push(Finding {
                        kind: "policy",
                        detail: format!(
                            "{} differs from the policy pinned at install (sha256 {} now, {} pinned); if the edit was yours, re-run `sentinel install` to re-pin it",
                            observed.policy_path.display(),
                            short(digest),
                            short(pinned)
                        ),
                    });
                }
            }
            live.policy_sha256 = Some(digest.clone());
        }
        Err(error) => findings.push(Finding {
            kind: "policy",
            detail: format!(
                "{} cannot be read ({error}); the hook denies every call under on_failure = closed",
                observed.policy_path.display()
            ),
        }),
    }

    // the sandbox bridge, when recorded
    if let Some(sandbox) = &observed.sandbox {
        match sandbox {
            Ok(inspection) => {
                if !inspection.keys_pinned() {
                    let flag = |value: Option<bool>| match value {
                        Some(true) => "true",
                        Some(false) => "false",
                        None => "unset",
                    };
                    findings.push(Finding {
                        kind: "sandbox",
                        detail: format!(
                            "sandbox keys differ from what install pinned (enabled={} failIfUnavailable={} allowUnsandboxedCommands={}); re-run `sentinel install --sandbox`",
                            flag(inspection.enabled),
                            flag(inspection.fail_if_unavailable),
                            flag(inspection.allow_unsandboxed_commands)
                        ),
                    });
                }
                if inspection.filesystem_disabled {
                    findings.push(Finding {
                        kind: "sandbox",
                        detail: "sandbox.filesystem.disabled is true, so every projected deny entry is inert".into(),
                    });
                }
                if inspection.drifted() {
                    findings.push(Finding {
                        kind: "sandbox",
                        detail: format!(
                            "sandbox projection drift: {} projected entries missing, {} stale sentinel-owned entries; re-run `sentinel install --sandbox`",
                            inspection.deny_read.missing.len() + inspection.deny_write.missing.len(),
                            inspection.deny_read.stale.len() + inspection.deny_write.stale.len()
                        ),
                    });
                }
            }
            Err(error) => findings.push(Finding {
                kind: "sandbox",
                detail: format!("the recorded sandbox bridge cannot be checked: {error}"),
            }),
        }
    }

    SessionCheckReport {
        agent: observed.agent,
        findings,
        pins,
        live,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::activation::Activation;
    use crate::install::hooks::{HookInspection, HookOwnership};
    use crate::install::sandbox::{ListDrift, SandboxInspection};
    use crate::install::state::SandboxRecord;

    /// an observed host where everything matches its pins, with the binary a
    /// real file so the digest path is exercised
    fn healthy(dir: &Path) -> Observed {
        let binary = dir.join("sentinel");
        std::fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "[policy]\nmode = \"enforce\"\n").unwrap();
        let state = InstallState {
            version: 1,
            sandbox: None,
            binary_sha256: Some(state::sha256_file(&binary).unwrap()),
            policy_sha256: Some(state::sha256_file(&policy).unwrap()),
        };
        Observed {
            agent: "claude-code",
            state: Ok(state),
            config_path: dir.join("settings.json"),
            config_exists: true,
            hook: Ok(HookInspection {
                ownership: HookOwnership::Direct,
                command: Some(format!("{} evaluate", binary.display())),
                direct_count: 1,
                mediated_count: 0,
            }),
            activation: Some(Activation::Active),
            policy_sha256: state::sha256_file(&policy).map_err(|e| e.to_string()),
            policy_path: policy,
            sandbox: None,
        }
    }

    fn kinds(report: &SessionCheckReport) -> Vec<&'static str> {
        report.findings.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn a_matching_install_has_no_findings_and_a_stable_json_shape() {
        let dir = tempfile::tempdir().unwrap();
        let observed = healthy(dir.path());
        let report = compare(&observed);
        assert!(report.ok(), "{:?}", report.findings);
        assert_eq!(report.live.binary_sha256, report.pins.binary_sha256);
        assert_eq!(report.live.policy_sha256, report.pins.policy_sha256);
        let json = report.to_json();
        assert_eq!(json["ok"], true);
        assert_eq!(json["findings"], json!([]));
        assert_eq!(json["pins"]["sandbox_recorded"], false);
        assert_eq!(
            json["pins"]["binary_sha256"],
            json!(report.pins.binary_sha256)
        );
        assert!(json["live"]["binary_path"].is_string());
    }

    #[test]
    fn unpinned_state_is_reported_not_failed() {
        let dir = tempfile::tempdir().unwrap();
        let mut observed = healthy(dir.path());
        observed.state = Ok(InstallState::default());
        let report = compare(&observed);
        assert!(report.ok(), "{:?}", report.findings);
        assert_eq!(report.pins, Pins::default());
        assert!(report.live.binary_sha256.is_some());
        assert_eq!(report.to_json()["pins"]["binary_sha256"], Value::Null);
    }

    #[test]
    fn each_mismatch_is_one_finding() {
        let dir = tempfile::tempdir().unwrap();

        let mut observed = healthy(dir.path());
        if let Ok(state) = &mut observed.state {
            state.binary_sha256 = Some("0".repeat(64));
        }
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["binary"]);
        assert!(report.findings[0]
            .detail
            .contains("differs from the one pinned"));

        let mut observed = healthy(dir.path());
        if let Ok(state) = &mut observed.state {
            state.policy_sha256 = Some("f".repeat(64));
        }
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["policy"]);
        assert!(report.findings[0]
            .detail
            .contains("re-run `sentinel install`"));

        let mut observed = healthy(dir.path());
        observed.hook = Ok(HookInspection {
            ownership: HookOwnership::Absent,
            command: None,
            direct_count: 0,
            mediated_count: 0,
        });
        observed.activation = Some(Activation::Broken("no hook".into()));
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["hook"]);
        assert!(report.findings[0]
            .detail
            .contains("no sentinel PreToolUse hook"));
        assert!(report.live.binary_sha256.is_none());

        let mut observed = healthy(dir.path());
        observed.activation = Some(Activation::Disabled);
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["hook"]);
        assert!(report.findings[0].detail.contains("disabled"));

        let mut observed = healthy(dir.path());
        observed.hook = Ok(HookInspection {
            ownership: HookOwnership::Direct,
            command: Some(format!(
                "{} evaluate",
                dir.path().join("gone/sentinel").display()
            )),
            direct_count: 1,
            mediated_count: 0,
        });
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["binary"]);
        assert!(
            report.findings[0].detail.contains("cannot be read"),
            "{}",
            report.findings[0].detail
        );

        let mut observed = healthy(dir.path());
        observed.policy_sha256 = Err("No such file".into());
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["policy"]);

        let mut observed = healthy(dir.path());
        observed.state = Err("not valid install state".into());
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["state"]);
        assert_eq!(report.pins, Pins::default());

        // several at once: every finding is listed, none swallows another
        let mut observed = healthy(dir.path());
        if let Ok(state) = &mut observed.state {
            state.binary_sha256 = Some("0".repeat(64));
            state.policy_sha256 = Some("f".repeat(64));
        }
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["binary", "policy"]);
        assert_eq!(report.to_json()["ok"], false);
        assert_eq!(report.to_json()["findings"][1]["kind"], "policy");
    }

    #[test]
    fn sandbox_drift_and_unpinned_keys_are_findings_when_a_bridge_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let pinned = SandboxInspection {
            enabled: Some(true),
            fail_if_unavailable: Some(true),
            allow_unsandboxed_commands: Some(false),
            filesystem_disabled: false,
            excluded_commands: vec!["gh *".into()],
            deny_read: ListDrift {
                present: 41,
                ..Default::default()
            },
            deny_write: ListDrift {
                present: 41,
                ..Default::default()
            },
        };
        let record = SandboxRecord {
            settings_path: dir.path().join("settings.json").display().to_string(),
            deny_read: vec!["~/.ssh".into()],
            deny_write: vec![],
            prior: Default::default(),
        };
        let mut observed = healthy(dir.path());
        if let Ok(state) = &mut observed.state {
            state.sandbox = Some(record);
        }
        observed.sandbox = Some(Ok(pinned.clone()));
        let report = compare(&observed);
        assert!(
            report.ok(),
            "excludedCommands is doctor's warning, not a finding: {:?}",
            report.findings
        );
        assert!(report.pins.sandbox_recorded);

        let mut drifted = pinned.clone();
        drifted.deny_read.missing = vec!["~/.aws".into()];
        observed.sandbox = Some(Ok(drifted));
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["sandbox"]);
        assert!(report.findings[0]
            .detail
            .contains("1 projected entries missing"));

        let mut weakened = pinned.clone();
        weakened.allow_unsandboxed_commands = Some(true);
        weakened.filesystem_disabled = true;
        observed.sandbox = Some(Ok(weakened));
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["sandbox", "sandbox"]);
        assert!(report.findings[0]
            .detail
            .contains("allowUnsandboxedCommands=true"));

        observed.sandbox = Some(Err("policy cannot load".into()));
        let report = compare(&observed);
        assert_eq!(kinds(&report), ["sandbox"]);
    }

    #[test]
    fn hooked_binary_path_follows_direct_and_ghost_entries() {
        assert_eq!(
            hooked_binary_path("/usr/local/bin/sentinel evaluate").as_deref(),
            Some("/usr/local/bin/sentinel")
        );
        assert_eq!(
            hooked_binary_path("'/Applications/My Tools/sentinel' evaluate --agent codex")
                .as_deref(),
            Some("/Applications/My Tools/sentinel")
        );
        assert_eq!(
            hooked_binary_path("ghost hook --sentinel /bridge/sentinel").as_deref(),
            Some("/bridge/sentinel")
        );
        assert_eq!(hooked_binary_path("sentinel session-check"), None);
        assert_eq!(hooked_binary_path("echo sentinel evaluate"), None);
    }
}
