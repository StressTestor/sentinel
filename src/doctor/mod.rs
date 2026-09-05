//! `sentinel doctor` - validate the full install chain and probe liveness.
//!
//! Honesty contract (the repo shipped a tier-honesty change; do not regress it):
//! doctor verifies ON-DISK CONFIGURATION plus a point-in-time liveness probe. The
//! canary spawns the HOOKED BINARY ITSELF with `evaluate --canary` and a known-bad
//! payload, and asserts THAT process's own output is a deny (nested deny JSON or
//! exit code 2) - it does NOT evaluate the policy in-process, so a shim that merely
//! prints "sentinel x.y" on --version cannot pass. It still reports "hook entry
//! present / binary path resolves / policy loads / the hooked binary denies a
//! known-bad input" - NEVER "active and defending". A chmod-x'd or deleted binary
//! fails OPEN silently mid-session (Claude Code only blocks on the hook's exit
//! code 2 / deny JSON; a missing binary exits 127 and the tool runs); the canary
//! detects that at check-time but cannot PREVENT an in-session tamper.

use crate::audit_trail::{self, AuditEvent};
use crate::cli::DoctorArgs;
use crate::evaluate::resolve_policy_path;
use crate::install::activation::Activation;
use crate::install::hooks::{HookCommandKind, HookOwnership};
use crate::install::{self, AgentTarget};
use crate::policy::PolicyEngine;
use serde_json::Value;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Err,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Ok => "OK",
            Level::Warn => "WARN",
            Level::Err => "ERR",
        }
    }
}

/// outcome of spawning the hooked binary against a synthetic known-bad call
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryRaw {
    /// the binary itself ran `evaluate --canary` and denied (nested deny JSON
    /// on ITS stdout, or the exit-2 block convention)
    Denied,
    /// the binary ran `evaluate --canary` to completion but produced no deny -
    /// its decision path is not blocking the known-bad (e.g. a no-op shim)
    NoDecision,
    /// the binary could not be spawned, does not identify as sentinel, or
    /// errored out before producing a decision - the tamper signal
    NotRunnable,
    /// there is no installed hook to probe
    NoHook,
}

pub struct PolicyInfo {
    pub mode: String,
    pub self_protect: bool,
}

pub struct DoctorReport {
    pub lines: Vec<(Level, String)>,
    pub trust_ramp: Option<String>,
    /// any ERR line → unhealthy (drives `--strict` exit code)
    pub healthy: bool,
}

pub struct HostHook {
    pub config_label: String,
    pub config_exists: bool,
    pub ownership: HookOwnership,
    pub command: Option<String>,
    pub activation: Activation,
}

/// Interpret the canary against the active mode. Returns (level, message). Because
/// the probe runs `evaluate --canary` (which reports the would-be decision even in
/// audit mode), NoDecision always means the decision path is broken - it is an
/// error in BOTH modes. Audit mode only downgrades a Denied to Warn ("would deny,
/// but audit only logs").
fn interpret_canary(is_audit: bool, raw: CanaryRaw) -> (Level, String) {
    match raw {
        CanaryRaw::NoHook => (Level::Err, "liveness: no sentinel hook installed to probe".into()),
        CanaryRaw::NotRunnable => (
            Level::Err,
            "liveness: the hooked binary is missing, not executable, or does not identify as sentinel - the guard appears disarmed".into(),
        ),
        // the hooked binary ran its decision path and did not deny - broken
        // regardless of mode (a no-op shim or a gutted policy lands here)
        CanaryRaw::NoDecision => (
            Level::Err,
            "liveness: the hooked binary does not deny a known-bad call (ssh key read) - enforcement is not protecting".into(),
        ),
        CanaryRaw::Denied if is_audit => (
            Level::Warn,
            "liveness: the hooked binary would deny a known-bad call, but audit mode only logs (set mode = \"enforce\" in ~/.sentinel/policy.toml to enforce)".into(),
        ),
        CanaryRaw::Denied => (
            Level::Ok,
            "liveness: the hooked binary identifies as sentinel and itself denies a known-bad call".into(),
        ),
    }
}

/// count "block"-action events within the last `days` days, optionally restricted
/// to one mode. The trust ramp filters to the current mode so "would have been
/// blocked, but you're in audit mode" can't silently fold in real denials from a
/// prior enforce session.
fn count_blocks_within_days(
    events: &[AuditEvent],
    now: chrono::DateTime<chrono::Utc>,
    days: i64,
    mode: Option<&str>,
) -> usize {
    let cutoff = now - chrono::Duration::days(days);
    events
        .iter()
        .filter(|e| e.action == "block")
        .filter(|e| mode.is_none_or(|m| e.mode.eq_ignore_ascii_case(m)))
        .filter(|e| {
            chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                .map(|ts| ts.with_timezone(&chrono::Utc) >= cutoff)
                .unwrap_or(false)
        })
        .count()
}

/// Pure assembly of the report from gathered inputs. Testable without I/O.
#[cfg(test)]
pub fn build_report(
    settings: Option<&Value>,
    policy: Result<PolicyInfo, String>,
    canary: CanaryRaw,
    block_count_7d: usize,
) -> DoctorReport {
    let hook = match settings {
        Some(settings) => match install::hooks::inspect_claude_pre_tool(settings) {
            Ok(inspection) => HostHook {
                config_label: "~/.claude/settings.json".into(),
                config_exists: true,
                ownership: inspection.ownership,
                command: inspection.command,
                activation: Activation::Active,
            },
            Err(error) => HostHook {
                config_label: "~/.claude/settings.json".into(),
                config_exists: true,
                ownership: HookOwnership::Absent,
                command: None,
                activation: Activation::Broken(error.to_string()),
            },
        },
        None => HostHook {
            config_label: "~/.claude/settings.json".into(),
            config_exists: false,
            ownership: HookOwnership::Absent,
            command: None,
            activation: Activation::Broken("settings absent".into()),
        },
    };
    build_report_for_host(&hook, policy, canary, block_count_7d)
}

pub fn build_report_for_host(
    hook: &HostHook,
    policy: Result<PolicyInfo, String>,
    canary: CanaryRaw,
    block_count_7d: usize,
) -> DoctorReport {
    let mut lines: Vec<(Level, String)> = Vec::new();

    // hook entry
    match hook.ownership {
        HookOwnership::Direct | HookOwnership::Mediated => {
            let kind = if hook.ownership == HookOwnership::Mediated {
                "mediated"
            } else {
                "direct"
            };
            lines.push((
                Level::Ok,
                format!(
                    "hook: {kind} Sentinel PreToolUse entry present in {}",
                    hook.config_label
                ),
            ));
            if let Some(command) = &hook.command {
                lines.push((Level::Ok, format!("command: {command}")));
            }
        }
        HookOwnership::Conflict => lines.push((
            Level::Err,
            format!(
                "hook: conflicting direct/mediated Sentinel entries in {}",
                hook.config_label
            ),
        )),
        HookOwnership::Absent if hook.config_exists => lines.push((
            Level::Err,
            format!(
                "hook: no Sentinel PreToolUse entry in {}",
                hook.config_label
            ),
        )),
        HookOwnership::Absent => {
            lines.push((Level::Err, format!("hook: no {}", hook.config_label)))
        }
    }

    match &hook.activation {
        Activation::Active => {
            lines.push((Level::Ok, "activation: host reports the hook active".into()))
        }
        Activation::ConfiguredNeedsTrust => lines.push((
            Level::Err,
            "activation: configured but not trusted; approve the Sentinel entry in `/hooks`".into(),
        )),
        Activation::Disabled => lines.push((
            Level::Err,
            "activation: host reports the Sentinel hook disabled".into(),
        )),
        Activation::Unverified(reason) => lines.push((
            Level::Err,
            format!("activation: could not verify host state - {reason}"),
        )),
        Activation::Broken(reason) => lines.push((
            Level::Err,
            format!("activation: broken configuration - {reason}"),
        )),
    }

    // policy
    let is_audit = match &policy {
        Ok(info) => {
            lines.push((Level::Ok, format!("policy: loads ({} mode)", info.mode)));
            if info.self_protect {
                lines.push((
                    Level::Ok,
                    "policy: self-protect rule present (~/.sentinel/policy.toml is guarded)".into(),
                ));
            } else {
                lines.push((
                    Level::Warn,
                    "policy: no self-protect rule for ~/.sentinel/policy.toml".into(),
                ));
            }
            info.mode == "audit"
        }
        Err(e) => {
            lines.push((Level::Err, format!("policy: cannot load - {e}")));
            false
        }
    };

    // liveness canary
    let mut canary_line = interpret_canary(is_audit, canary);
    if hook.ownership == HookOwnership::Mediated && canary == CanaryRaw::Denied {
        canary_line.1 = if is_audit {
            "liveness: the mediated hook bridge reached Sentinel's deny path, but audit mode only logs"
                .into()
        } else {
            "liveness: the mediated hook bridge itself denies a known-bad call".into()
        };
    }
    lines.push(canary_line);

    // audit trail (count is already restricted to the current mode by the caller)
    let verb = if is_audit { "would-block" } else { "blocked" };
    if block_count_7d > 0 {
        lines.push((
            Level::Ok,
            format!("audit: {block_count_7d} {verb} event(s) in the last 7 days"),
        ));
    } else {
        lines.push((
            Level::Ok,
            format!("audit: no {verb} events in the last 7 days"),
        ));
    }

    // trust ramp (audit mode only, and only if there's something to point at)
    let trust_ramp = if is_audit && block_count_7d > 0 {
        Some(format!(
            "{block_count_7d} call(s) in the last 7 days would have been blocked, but you're in audit mode. Set mode = \"enforce\" in ~/.sentinel/policy.toml to start blocking."
        ))
    } else {
        None
    };

    let healthy = !lines.iter().any(|(lvl, _)| *lvl == Level::Err);
    DoctorReport {
        lines,
        trust_ramp,
        healthy,
    }
}

/// the synthetic known-bad payload the canary feeds the hooked binary. An SSH
/// private-key read is denied by every shipped default policy.
const CANARY_INPUT: &str = r#"{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}"#;

/// Pure interpretation of one spawn of `<hooked binary> evaluate --canary` fed
/// the known-bad payload. Takes the raw observables (exit code, stdout, stderr)
/// so unit tests can drive every branch without a subprocess.
///
/// A deny is recognized through EITHER signal Claude Code itself honors:
///   - stdout parses as JSON with nested `hookSpecificOutput.permissionDecision
///     == "deny"`, or
///   - the process exits with code 2 (forward-compat for the exit-2 block
///     convention).
///
/// Caveat, handled conservatively: an OLDER hooked binary that predates
/// `--canary` makes clap reject the flag - and clap's usage errors ALSO exit
/// with code 2, which would otherwise be misread as a deny. Those errors are
/// recognizable ("unexpected argument" / usage text on stderr, never a real
/// block reason) and mapped to NotRunnable: we could not prove that binary's
/// decision path, so the canary flags "appears disarmed" rather than silently
/// passing. Re-running `sentinel install` (or pointing the hook at the current
/// binary) clears it. Better a false alarm than a spoofable HEALTHY.
fn classify_evaluate_probe(exit_code: Option<i32>, stdout: &str, stderr: &str) -> CanaryRaw {
    // primary signal: the binary's OWN stdout carries the nested deny contract
    if let Ok(v) = serde_json::from_str::<Value>(stdout.trim()) {
        let decision = v
            .get("hookSpecificOutput")
            .and_then(|h| h.get("permissionDecision"))
            .and_then(|d| d.as_str());
        if decision == Some("deny") {
            return CanaryRaw::Denied;
        }
    }
    // secondary signal: the exit-2 block convention - minus clap usage errors
    // (older binary without --canary; see the caveat above)
    if exit_code == Some(2) {
        let err = stderr.to_ascii_lowercase();
        if err.contains("unexpected argument") || err.contains("usage") {
            return CanaryRaw::NotRunnable;
        }
        return CanaryRaw::Denied;
    }
    if exit_code == Some(0) {
        // ran the decision path to completion and chose not to deny: the
        // known-bad is NOT being blocked (a no-op shim lands here)
        return CanaryRaw::NoDecision;
    }
    // crashed, was killed, or errored before producing a decision - the
    // decision path could not be proven, treat as the tamper signal
    CanaryRaw::NotRunnable
}

/// Probe liveness by exercising the hooked binary's OWN enforcement:
///   1. does it RUN and identify as sentinel? (`--version`) - catches the
///      deleted/`chmod -x`'d binary that would otherwise exit 127 and fail open
///      silently, and the hook repointed at some unrelated executable;
///   2. does THAT binary deny a known-bad call? - spawned as
///      `<binary> evaluate --canary` with the known-bad payload on stdin, and
///      the deny is asserted on the SPAWNED PROCESS's own output. `--canary`
///      runs the full decision path but skips the audit trail (no synthetic
///      event pollutes it) and reports the would-be deny even in audit mode.
///
/// Step 2 is what makes the canary authoritative: a shim that fakes `--version`
/// but no-ops `evaluate` reads NoDecision, never Denied. Evaluating the policy
/// in-process here (the old behavior) proved nothing about the hooked binary.
#[cfg(test)]
fn probe_canary(binary: &str, agent: &str) -> CanaryRaw {
    probe_direct_canary(&[
        binary.to_string(),
        "evaluate".into(),
        "--agent".into(),
        agent.into(),
    ])
}

fn probe_direct_canary(argv: &[String]) -> CanaryRaw {
    let Some((binary, configured_args)) = argv.split_first() else {
        return CanaryRaw::NotRunnable;
    };
    // The hooked binary must run AND identify as sentinel. Checking only the exit
    // code would green-light a hook repointed at a no-op (a script named
    // `sentinel` that exits 0) - the quiet disarm. clap prints "sentinel <ver>"
    // for --version across all versions, so require that marker in the output.
    let identifies = Command::new(binary)
        .arg("--version")
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("sentinel"))
        .unwrap_or(false);
    if !identifies {
        return CanaryRaw::NotRunnable;
    }

    let mut canary_args = configured_args.to_vec();
    if canary_args.first().map(String::as_str) != Some("evaluate") {
        return CanaryRaw::NotRunnable;
    }
    canary_args.insert(1, "--canary".into());
    let child = Command::new(binary)
        .args(canary_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => return CanaryRaw::NotRunnable,
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        // a child that exits without reading stdin (old binary, clap error)
        // yields EPIPE here - that is classified below, not a spawn failure
        let _ = stdin.write_all(CANARY_INPUT.as_bytes());
    }
    wait_for_probe(child)
}

fn probe_hook_command(command: &str, _target: AgentTarget) -> CanaryRaw {
    match install::hooks::classify_hook_command(command) {
        HookCommandKind::DirectPre => install::hooks::split_shell_words(command)
            .as_deref()
            .map(probe_direct_canary)
            .unwrap_or(CanaryRaw::NotRunnable),
        HookCommandKind::GhostBridge => {
            let Some(argv) = install::hooks::split_shell_words(command) else {
                return CanaryRaw::NotRunnable;
            };
            let Some((binary, args)) = argv.split_first() else {
                return CanaryRaw::NotRunnable;
            };
            let child = Command::new(binary)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            let mut child = match child {
                Ok(child) => child,
                Err(_) => return CanaryRaw::NotRunnable,
            };
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(CANARY_INPUT.as_bytes());
            }
            wait_for_probe(child)
        }
        _ => CanaryRaw::NotRunnable,
    }
}

fn wait_for_probe(mut child: std::process::Child) -> CanaryRaw {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return CanaryRaw::NotRunnable;
            }
            Err(_) => return CanaryRaw::NotRunnable,
        }
    }
    match child.wait_with_output() {
        Ok(out) => classify_evaluate_probe(
            out.status.code(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(_) => CanaryRaw::NotRunnable,
    }
}

pub fn run(args: DoctorArgs) -> Result<(), Box<dyn std::error::Error>> {
    let target = AgentTarget::parse(&args.agent)
        .ok_or_else(|| format!("unsupported doctor agent: {}", args.agent))?;
    let policy_path = resolve_policy_path()?;
    let state = install::state::inspect_agent(target)?;
    let hook = HostHook {
        config_label: state.config_path.display().to_string(),
        config_exists: state.config_exists,
        ownership: state.hook.ownership,
        command: state.hook.command.clone(),
        activation: state.activation.clone(),
    };

    // policy info
    let engine = PolicyEngine::load(&policy_path);
    let policy = match &engine {
        Ok(e) => Ok(PolicyInfo {
            mode: e.mode().to_string(),
            self_protect: e.has_self_protect_rule(),
        }),
        Err(e) => Err(e.to_string()),
    };

    let now = chrono::Utc::now();
    // restrict the count to the current mode so the trust ramp is accurate
    let mode_filter = engine.as_ref().ok().map(|e| e.mode().to_string());
    let block_count_7d =
        count_blocks_within_days(&audit_trail::read_events(), now, 7, mode_filter.as_deref());

    // canary: probe the binary the hook actually points at (that's the tamper
    // surface) by spawning ITS `evaluate --canary` against a known-bad payload
    // and asserting its own deny. --canary skips the audit trail, so the
    // synthetic probe leaves no events behind. NoHook if nothing is installed.
    let canary = match hook.command.as_deref() {
        Some(command) => probe_hook_command(command, target),
        None => CanaryRaw::NoHook,
    };

    let report = build_report_for_host(&hook, policy, canary, block_count_7d);

    if args.json {
        let arr: Vec<Value> = report
            .lines
            .iter()
            .map(|(lvl, msg)| serde_json::json!({"level": lvl.tag(), "message": msg}))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "healthy": report.healthy,
                "agent": target.evaluate_agent_arg(),
                "config": hook.config_label,
                "activation": hook.activation.label(),
                "checks": arr,
                "trust_ramp": report.trust_ramp,
            }))?
        );
    } else {
        for (lvl, msg) in &report.lines {
            println!("[{}] {msg}", lvl.tag());
        }
        if let Some(ramp) = &report.trust_ramp {
            println!();
            println!("{ramp}");
        }
        println!();
        println!("note: doctor checks on-disk config and a point-in-time probe, not live enforcement; a binary deleted mid-session fails open silently and cannot be prevented here.");
    }

    if args.strict && !report.healthy {
        return Err("doctor: one or more checks failed (--strict)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sentinel_settings() -> Value {
        json!({"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "/usr/local/bin/sentinel evaluate"}]}]}})
    }

    #[test]
    fn hooked_command_and_argument_parsing() {
        let s = sentinel_settings();
        let inspection = install::hooks::inspect_claude_pre_tool(&s).unwrap();
        assert_eq!(
            inspection.command.as_deref(),
            Some("/usr/local/bin/sentinel evaluate")
        );
        assert_eq!(
            install::hooks::split_shell_words("/usr/local/bin/sentinel evaluate").unwrap(),
            ["/usr/local/bin/sentinel", "evaluate"]
        );
        // a path with a space must not be split mid-path
        assert_eq!(
            install::hooks::split_shell_words("'/Applications/My Tools/sentinel' evaluate")
                .unwrap(),
            ["/Applications/My Tools/sentinel", "evaluate"]
        );
    }

    #[test]
    fn canary_audit_mode_denied_is_warn_not_error() {
        // a policy that WOULD deny, but in audit mode → warn (the expected state)
        let (lvl, _) = interpret_canary(true, CanaryRaw::Denied);
        assert_eq!(lvl, Level::Warn);
    }

    #[test]
    fn canary_enforce_deny_is_ok_no_decision_is_err() {
        assert_eq!(interpret_canary(false, CanaryRaw::Denied).0, Level::Ok);
        assert_eq!(interpret_canary(false, CanaryRaw::NoDecision).0, Level::Err);
    }

    #[test]
    fn canary_no_decision_is_error_in_audit_too() {
        // a policy that doesn't even deny a known-bad is broken regardless of mode
        assert_eq!(interpret_canary(true, CanaryRaw::NoDecision).0, Level::Err);
    }

    #[test]
    fn canary_binary_not_runnable_is_always_error() {
        assert_eq!(interpret_canary(true, CanaryRaw::NotRunnable).0, Level::Err);
        assert_eq!(
            interpret_canary(false, CanaryRaw::NotRunnable).0,
            Level::Err
        );
    }

    #[test]
    fn probe_rejects_disarmed_and_missing_binaries() {
        // THE repoint disarm: a hook pointing at a live binary that exits 0 but
        // does not identify as sentinel (e.g. a no-op named `sentinel`) must read
        // as NotRunnable - never a healthy OK. /bin/sh stands in for any non-sentinel.
        assert_eq!(
            probe_canary("/bin/sh", "claude-code"),
            CanaryRaw::NotRunnable
        );
        // a deleted/missing binary likewise
        assert_eq!(
            probe_canary("/nonexistent/sentinel", "claude-code"),
            CanaryRaw::NotRunnable
        );
    }

    /// THE regression test for the spoofable canary (finding #6), in pure form:
    /// a binary that runs `evaluate --canary` to completion (exit 0) but emits
    /// no deny - the no-op shim - must NOT read Denied. The old canary never
    /// looked at the binary's evaluate output at all, so this was unreachable.
    #[test]
    fn classify_noop_shim_output_is_no_decision_never_denied() {
        // shim prints nothing
        assert_eq!(
            classify_evaluate_probe(Some(0), "", ""),
            CanaryRaw::NoDecision
        );
        // shim parrots the allow shape
        assert_eq!(
            classify_evaluate_probe(Some(0), "{}", ""),
            CanaryRaw::NoDecision
        );
        // shim prints non-JSON noise
        assert_eq!(
            classify_evaluate_probe(Some(0), "sentinel 0.2.1", ""),
            CanaryRaw::NoDecision
        );
    }

    #[test]
    fn classify_nested_deny_json_is_denied() {
        let deny = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"SSH key access"}}"#;
        assert_eq!(
            classify_evaluate_probe(Some(0), deny, ""),
            CanaryRaw::Denied
        );
    }

    #[test]
    fn classify_flat_or_non_deny_decision_is_not_denied() {
        // the dead flat form Claude Code ignores must not count as a deny
        assert_eq!(
            classify_evaluate_probe(Some(0), r#"{"permissionDecision":"deny"}"#, ""),
            CanaryRaw::NoDecision
        );
        // an explicit non-deny decision is not a deny
        assert_eq!(
            classify_evaluate_probe(
                Some(0),
                r#"{"hookSpecificOutput":{"permissionDecision":"allow"}}"#,
                ""
            ),
            CanaryRaw::NoDecision
        );
    }

    #[test]
    fn classify_exit_2_block_convention_is_denied() {
        // forward-compat: a future binary may block via exit code 2 + stderr reason
        assert_eq!(
            classify_evaluate_probe(Some(2), "", "sentinel: blocked: SSH key access"),
            CanaryRaw::Denied
        );
    }

    #[test]
    fn classify_old_binary_clap_error_is_not_runnable_not_denied() {
        // an OLDER hooked binary without --canary: clap rejects the flag and
        // exits 2 - same code as the block convention. It must read NotRunnable
        // (conservative "appears disarmed"), never a spoof-friendly Denied.
        let clap_err = "error: unexpected argument '--canary' found\n\nUsage: sentinel evaluate\n\nFor more information, try '--help'.\n";
        assert_eq!(
            classify_evaluate_probe(Some(2), "", clap_err),
            CanaryRaw::NotRunnable
        );
    }

    #[test]
    fn classify_crash_or_signal_is_not_runnable() {
        // non-zero non-2 exit with no deny: decision path unproven
        assert_eq!(
            classify_evaluate_probe(Some(1), "", "panic"),
            CanaryRaw::NotRunnable
        );
        // killed by signal (no exit code)
        assert_eq!(
            classify_evaluate_probe(None, "", ""),
            CanaryRaw::NotRunnable
        );
    }

    #[test]
    fn classify_deny_json_wins_even_with_exit_2() {
        // both signals at once is still a deny
        let deny = r#"{"hookSpecificOutput":{"permissionDecision":"deny"}}"#;
        assert_eq!(
            classify_evaluate_probe(Some(2), deny, "blocked"),
            CanaryRaw::Denied
        );
    }

    #[test]
    fn healthy_install_passes_strict() {
        let report = build_report(
            Some(&sentinel_settings()),
            Ok(PolicyInfo {
                mode: "enforce".into(),
                self_protect: true,
            }),
            CanaryRaw::Denied,
            0,
        );
        assert!(
            report.healthy,
            "a sound enforce-mode install must be healthy"
        );
        assert!(report.trust_ramp.is_none());
    }

    #[test]
    fn missing_hook_fails_strict() {
        let report = build_report(
            None,
            Ok(PolicyInfo {
                mode: "enforce".into(),
                self_protect: true,
            }),
            CanaryRaw::NoHook,
            0,
        );
        assert!(!report.healthy, "no hook installed must fail --strict");
    }

    #[test]
    fn audit_mode_with_would_blocks_shows_trust_ramp() {
        let report = build_report(
            Some(&sentinel_settings()),
            Ok(PolicyInfo {
                mode: "audit".into(),
                self_protect: true,
            }),
            CanaryRaw::Denied,
            5,
        );
        assert!(report.trust_ramp.unwrap().contains("mode = \"enforce\""));
        // audit mode is healthy (it's a valid configured state), canary is warn not err
        assert!(report.healthy);
    }

    #[test]
    fn count_blocks_filters_action_and_window() {
        let now = chrono::Utc::now();
        let recent = (now - chrono::Duration::days(1)).to_rfc3339();
        let old = (now - chrono::Duration::days(30)).to_rfc3339();
        let ev = |action: &str, ts: &str| AuditEvent {
            timestamp: ts.into(),
            tool_name: "Read".into(),
            action: action.into(),
            reason: None,
            matched_rule: None,
            mode: "enforce".into(),
            call_id: None,
            tool_use_id: None,
            hook_phase: None,
        };
        let events = vec![
            ev("block", &recent),
            ev("block", &old),    // outside 7d window
            ev("warn", &recent),  // not a block
            ev("allow", &recent), // not a block
        ];
        assert_eq!(count_blocks_within_days(&events, now, 7, None), 1);
        // mode filter: the events are all enforce-mode, so audit count is 0
        assert_eq!(
            count_blocks_within_days(&events, now, 7, Some("enforce")),
            1
        );
        assert_eq!(count_blocks_within_days(&events, now, 7, Some("audit")), 0);
    }
}
