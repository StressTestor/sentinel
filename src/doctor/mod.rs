//! `sentinel doctor` - validate the full install chain and probe liveness.
//!
//! Honesty contract (the repo shipped a tier-honesty change; do not regress it):
//! doctor verifies ON-DISK CONFIGURATION plus a point-in-time liveness probe. It
//! reports "hook entry present / binary path resolves / policy loads / the binary
//! denies a known-bad input" - NEVER "active and defending". A chmod-x'd or
//! deleted binary fails OPEN silently mid-session (Claude Code only blocks on the
//! hook's exit code 2 / deny JSON; a missing binary exits 127 and the tool runs);
//! the canary detects that at check-time but cannot PREVENT an in-session tamper.

use crate::audit_trail::{self, AuditEvent};
use crate::cli::DoctorArgs;
use crate::evaluate::hook_schema::HookInput;
use crate::evaluate::resolve_policy_path;
use crate::policy::{Action, PolicyEngine};
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const SENTINEL_MARKER: &str = "sentinel evaluate";

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
    /// the binary ran and returned a deny decision on stdout
    Denied,
    /// the binary ran but returned no deny (allow / would-log)
    NoDecision,
    /// the binary could not be spawned (missing / not executable) - the tamper signal
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

fn hooked_command(settings: &Value) -> Option<String> {
    let arr = settings.get("hooks")?.get("PreToolUse")?.as_array()?;
    for entry in arr {
        if let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
            for h in hooks {
                if let Some(cmd) = h.get("command").and_then(|c| c.as_str()) {
                    if cmd.contains(SENTINEL_MARKER) {
                        return Some(cmd.to_string());
                    }
                }
            }
        }
    }
    None
}

/// the binary path is the hook command minus the trailing " evaluate" - strip the
/// suffix rather than splitting on whitespace, since a path can contain spaces.
fn binary_from_command(cmd: &str) -> &str {
    cmd.strip_suffix(" evaluate").unwrap_or(cmd).trim()
}

/// Interpret the canary against the active mode. Returns (level, message). In audit
/// mode "no decision" is the EXPECTED healthy state (audit logs, never blocks), so
/// it must not be an error.
fn interpret_canary(is_audit: bool, raw: CanaryRaw) -> (Level, String) {
    match raw {
        CanaryRaw::NoHook => (Level::Err, "liveness: no sentinel hook installed to probe".into()),
        CanaryRaw::NotRunnable => (
            Level::Err,
            "liveness: the hooked binary is missing, not executable, or does not identify as sentinel - the guard appears disarmed".into(),
        ),
        // the policy itself doesn't deny a known-bad call - broken regardless of mode
        CanaryRaw::NoDecision => (
            Level::Err,
            "liveness: the policy does not deny a known-bad call (ssh key read) - the policy is not protecting".into(),
        ),
        CanaryRaw::Denied if is_audit => (
            Level::Warn,
            "liveness: the policy would deny a known-bad call, but audit mode only logs (run 'sentinel install --enforce' to enforce)".into(),
        ),
        CanaryRaw::Denied => (
            Level::Ok,
            "liveness: hooked binary identifies as sentinel and the policy denies a known-bad call".into(),
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
pub fn build_report(
    settings: Option<&Value>,
    policy: Result<PolicyInfo, String>,
    canary: CanaryRaw,
    block_count_7d: usize,
) -> DoctorReport {
    let mut lines: Vec<(Level, String)> = Vec::new();

    // hook entry
    match settings {
        Some(s) if hooked_command(s).is_some() => {
            let cmd = hooked_command(s).unwrap();
            lines.push((Level::Ok, "hook: sentinel PreToolUse entry present in ~/.claude/settings.json".into()));
            lines.push((Level::Ok, format!("binary: hook invokes {}", binary_from_command(&cmd))));
        }
        Some(_) => lines.push((Level::Err, "hook: no sentinel PreToolUse entry in ~/.claude/settings.json (run 'sentinel install')".into())),
        None => lines.push((Level::Err, "hook: no ~/.claude/settings.json (run 'sentinel install')".into())),
    }

    // policy
    let is_audit = match &policy {
        Ok(info) => {
            lines.push((Level::Ok, format!("policy: loads ({} mode)", info.mode)));
            if info.self_protect {
                lines.push((Level::Ok, "policy: self-protect rule present (~/.sentinel/policy.toml is guarded)".into()));
            } else {
                lines.push((Level::Warn, "policy: no self-protect rule for ~/.sentinel/policy.toml".into()));
            }
            info.mode == "audit"
        }
        Err(e) => {
            lines.push((Level::Err, format!("policy: cannot load - {e}")));
            false
        }
    };

    // liveness canary
    lines.push(interpret_canary(is_audit, canary));

    // audit trail (count is already restricted to the current mode by the caller)
    let verb = if is_audit { "would-block" } else { "blocked" };
    if block_count_7d > 0 {
        lines.push((Level::Ok, format!("audit: {block_count_7d} {verb} event(s) in the last 7 days")));
    } else {
        lines.push((Level::Ok, format!("audit: no {verb} events in the last 7 days")));
    }

    // trust ramp (audit mode only, and only if there's something to point at)
    let trust_ramp = if is_audit && block_count_7d > 0 {
        Some(format!(
            "{block_count_7d} call(s) in the last 7 days would have been blocked, but you're in audit mode. Run 'sentinel install --enforce' to start blocking."
        ))
    } else {
        None
    };

    let healthy = !lines.iter().any(|(lvl, _)| *lvl == Level::Err);
    DoctorReport { lines, trust_ramp, healthy }
}

/// Probe liveness in two non-polluting, version-safe steps:
///   1. does the hooked binary actually RUN? (`--version`, present in every
///      version, never logs) - this catches the deleted/`chmod -x`'d binary that
///      would otherwise exit 127 and fail open silently;
///   2. would the policy DENY a known-bad call? - evaluated IN-PROCESS against the
///      loaded engine (no subprocess, so no synthetic event pollutes the audit
///      trail, and no version-specific subcommand is required of the hooked binary).
fn probe_canary(binary: &str, engine: Option<&PolicyEngine>) -> CanaryRaw {
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
    let input = r#"{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}"#;
    let denies = engine
        .and_then(|e| {
            serde_json::from_str::<HookInput>(input)
                .ok()
                .map(|hi| e.evaluate(&hi.to_tool_call()).action)
        })
        .map(|action| action == Action::Block)
        .unwrap_or(false);
    if denies {
        CanaryRaw::Denied
    } else {
        CanaryRaw::NoDecision
    }
}

fn read_settings(path: &PathBuf) -> Option<Value> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn run(args: DoctorArgs) -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let settings_path = PathBuf::from(&home).join(".claude").join("settings.json");
    let settings = read_settings(&settings_path);

    // policy info
    let policy_path = resolve_policy_path();
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
    // surface), evaluating the policy in-process. NoHook if nothing is installed.
    let canary = match settings.as_ref().and_then(hooked_command) {
        Some(cmd) => probe_canary(binary_from_command(&cmd), engine.as_ref().ok()),
        None => CanaryRaw::NoHook,
    };

    let report = build_report(settings.as_ref(), policy, canary, block_count_7d);

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
    fn hooked_command_and_binary_extraction() {
        let s = sentinel_settings();
        assert_eq!(hooked_command(&s).as_deref(), Some("/usr/local/bin/sentinel evaluate"));
        assert_eq!(binary_from_command("/usr/local/bin/sentinel evaluate"), "/usr/local/bin/sentinel");
        // a path with a space must not be split mid-path
        assert_eq!(binary_from_command("/Applications/My Tools/sentinel evaluate"), "/Applications/My Tools/sentinel");
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
        assert_eq!(interpret_canary(false, CanaryRaw::NotRunnable).0, Level::Err);
    }

    #[test]
    fn probe_rejects_disarmed_and_missing_binaries() {
        // THE repoint disarm: a hook pointing at a live binary that exits 0 but
        // does not identify as sentinel (e.g. a no-op named `sentinel`) must read
        // as NotRunnable - never a healthy OK. /bin/sh stands in for any non-sentinel.
        assert_eq!(probe_canary("/bin/sh", None), CanaryRaw::NotRunnable);
        // a deleted/missing binary likewise
        assert_eq!(probe_canary("/nonexistent/sentinel", None), CanaryRaw::NotRunnable);
    }

    #[test]
    fn healthy_install_passes_strict() {
        let report = build_report(
            Some(&sentinel_settings()),
            Ok(PolicyInfo { mode: "enforce".into(), self_protect: true }),
            CanaryRaw::Denied,
            0,
        );
        assert!(report.healthy, "a sound enforce-mode install must be healthy");
        assert!(report.trust_ramp.is_none());
    }

    #[test]
    fn missing_hook_fails_strict() {
        let report = build_report(
            None,
            Ok(PolicyInfo { mode: "enforce".into(), self_protect: true }),
            CanaryRaw::NoHook,
            0,
        );
        assert!(!report.healthy, "no hook installed must fail --strict");
    }

    #[test]
    fn idle_healthy_install_is_not_a_failure() {
        // zero denials + idle is the HEALTHY state, must not fail strict
        let report = build_report(
            Some(&sentinel_settings()),
            Ok(PolicyInfo { mode: "enforce".into(), self_protect: true }),
            CanaryRaw::Denied,
            0,
        );
        assert!(report.healthy);
    }

    #[test]
    fn audit_mode_with_would_blocks_shows_trust_ramp() {
        let report = build_report(
            Some(&sentinel_settings()),
            Ok(PolicyInfo { mode: "audit".into(), self_protect: true }),
            CanaryRaw::Denied,
            5,
        );
        assert!(report.trust_ramp.unwrap().contains("--enforce"));
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
        };
        let events = vec![
            ev("block", &recent),
            ev("block", &old),     // outside 7d window
            ev("warn", &recent),   // not a block
            ev("allow", &recent),  // not a block
        ];
        assert_eq!(count_blocks_within_days(&events, now, 7, None), 1);
        // mode filter: the events are all enforce-mode, so audit count is 0
        assert_eq!(count_blocks_within_days(&events, now, 7, Some("enforce")), 1);
        assert_eq!(count_blocks_within_days(&events, now, 7, Some("audit")), 0);
    }
}
