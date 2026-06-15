pub mod hook_schema;

use crate::audit_trail;
use crate::policy::{Action, PolicyEngine};
use hook_schema::HookInput;
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// PreToolUse hook output. Claude Code honors a block ONLY via the nested
/// `hookSpecificOutput` form below — a flat top-level `permissionDecision` is
/// silently ignored, which previously made every Sentinel block a no-op.
/// An absent `hookSpecificOutput` (the `allow()` form) carries no decision, so
/// Sentinel defers to Claude Code's normal permission flow rather than
/// auto-approving the call.
#[derive(Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput", skip_serializing_if = "Option::is_none")]
    hook_specific_output: Option<PreToolUseDecision>,
}

#[derive(Serialize)]
struct PreToolUseDecision {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: String,
}

impl HookOutput {
    /// No decision — defer to Claude Code's normal permission flow.
    pub fn allow() -> Self {
        HookOutput {
            hook_specific_output: None,
        }
    }

    /// Block the tool call via the nested PreToolUse contract Claude Code enforces.
    pub fn deny(reason: impl Into<String>) -> Self {
        HookOutput {
            hook_specific_output: Some(PreToolUseDecision {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: reason.into(),
            }),
        }
    }
}

/// run the evaluate pipeline: read stdin JSON, evaluate policy, write stdout JSON.
/// this is the hot path called by Claude Code's PreToolUse hook on every tool call.
///
/// `canary` is the dry-run mode used by `sentinel doctor`'s liveness probe: it
/// runs the FULL decision path (load policy, parse input, match rules) but
/// (a) never writes to the audit trail (the synthetic known-bad must not
///     pollute it), and
/// (b) reports the would-be decision as the nested deny JSON whenever the
///     matched rule's action is Block, REGARDLESS of audit/enforce mode —
///     the live hook in audit mode emits `{}` (it never blocks), which would
///     leave the probe blind to whether the decision path works at all.
/// With `canary == false` the behavior is exactly the live hook's.
pub fn run(canary: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Load the policy FIRST, so a degraded input (empty / unparseable stdin) can
    // honor the policy's on_failure posture instead of a hard-coded allow.
    let policy_path = resolve_policy_path();
    let engine = match PolicyEngine::load(&policy_path) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("failed to load policy: {e}");
            // can't load policy → can't make a safe decision → deny (and exit 2)
            deny_and_exit(format!("policy load failed: {e}"));
        }
    };

    // read JSON from stdin
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        // a read error is also an un-inspectable input, not a free pass
        degraded(&engine, "failed to read stdin");
    }

    if input.trim().is_empty() {
        degraded(&engine, "empty input");
    }

    // Parse the hook input. A payload sentinel can't understand is NOT a free
    // pass — it's a degraded input, handled per the policy's on_failure posture.
    let hook_input = match serde_json::from_str::<HookInput>(&input) {
        Ok(hi) => hi,
        Err(e) => {
            degraded(&engine, &format!("unparseable hook input: {e}"));
        }
    };

    // convert hook input to tool call
    let tool_call = hook_input.to_tool_call();

    // evaluate
    let decision = engine.evaluate(&tool_call);

    // self-protect (finding #5): the default policy keeps `.claude/settings.json`
    // at WARN tier, and warn = allowed — so a Write/Edit/MultiEdit that rewrites
    // the file to DROP the installed `sentinel evaluate` PreToolUse hook would
    // disarm the guard with only a warning. inspect the write's CONTENT and
    // escalate exactly the hook-removing ones to Block; ordinary settings edits
    // that preserve the hook keep their policy-assigned action. applied before
    // the canary/audit/enforce branches so all three see the escalated decision.
    let decision = crate::selfprotect::apply(decision, &hook_input.tool_input);

    // install-preflight (worm TTP): when the agent runs an install-like command
    // (`npm install`, `pnpm add`, `yarn`, `bun install`, …), inspect the
    // top-level package.json in the call's cwd and escalate a lifecycle script
    // that fetches-and-executes remote code (Block) or a non-registry dep source
    // alongside a lifecycle script (Warn). reads the manifest ONLY when the
    // command is install-like, so the hot path stays clean. applied before the
    // canary/audit/enforce branches so all three see the escalated decision.
    // HONEST LIMIT: sees only the TOP-LEVEL manifest — not poisoned transitive
    // dependency lifecycle scripts, which resolve during the install itself.
    let decision = crate::preflight::apply(
        decision,
        tool_call.command.as_deref(),
        hook_input.cwd.as_deref(),
    );

    if canary {
        // doctor's liveness probe: surface the would-be decision, skip the
        // audit trail. Block -> the nested deny JSON (even in audit mode);
        // anything else -> defer, same empty object as the live allow path.
        if decision.action == Action::Block {
            print_output(&HookOutput::deny(
                decision
                    .reason
                    .unwrap_or_else(|| "blocked by sentinel policy".into()),
            ));
        } else {
            print_output(&HookOutput::allow());
        }
        return Ok(());
    }

    // log to audit trail
    let _ = audit_trail::log_event(&audit_trail::AuditEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        tool_name: tool_call.tool_name.clone(),
        action: decision.action.to_string(),
        reason: decision.reason.clone(),
        matched_rule: decision.matched_rule.clone(),
        mode: engine.mode().to_string(),
    });

    // in audit mode, always allow but log
    if engine.is_audit_mode() {
        if decision.action != Action::Allow {
            tracing::info!(
                "AUDIT: would {} {} — {}",
                decision.action,
                tool_call.tool_name,
                decision.reason.as_deref().unwrap_or("no reason")
            );
        }
        print_output(&HookOutput::allow()); // audit mode never blocks
        return Ok(());
    }

    // enforce mode
    match decision.action {
        Action::Block => deny_and_exit(
            decision
                .reason
                .unwrap_or_else(|| "blocked by sentinel policy".into()),
        ),
        Action::Warn => {
            // warn = allow but log prominently
            eprintln!(
                "\x1b[33msentinel warning:\x1b[0m {} — {}",
                tool_call.tool_name,
                decision.reason.as_deref().unwrap_or("policy warning")
            );
            print_output(&HookOutput::allow());
        }
        Action::Allow => {
            print_output(&HookOutput::allow());
        }
    }

    Ok(())
}

fn print_output(output: &HookOutput) {
    if let Ok(json) = serde_json::to_string(output) {
        println!("{json}");
    }
}

/// Emit the nested deny JSON, mirror the reason to stderr, and exit 2. Never
/// returns. Exit code 2 is Claude Code's hard-block signal *independent of how
/// it parses stdout*, so this is belt-and-suspenders against the output-contract
/// drift that silently disarmed every block in 0.2.0 (the flat-JSON bug): even
/// if a future Claude Code ignores the JSON shape entirely, exit 2 still blocks.
fn deny_and_exit(reason: impl Into<String>) -> ! {
    let reason = reason.into();
    print_output(&HookOutput::deny(reason.clone()));
    let _ = io::stdout().flush(); // ensure the JSON lands before we exit
    eprintln!("sentinel: blocked — {reason}");
    std::process::exit(2);
}

/// Decide what to do with an input sentinel cannot evaluate (empty stdin,
/// unparseable JSON). Audit mode never blocks; otherwise the policy's
/// `on_failure` posture governs — "closed" (the default) denies rather than
/// waving an un-inspectable call through, "open" allows with a warning.
fn degraded(engine: &PolicyEngine, reason: &str) -> ! {
    if engine.is_audit_mode() || !engine.fail_closed() {
        tracing::warn!("{reason} — allowing (audit/fail-open)");
        print_output(&HookOutput::allow());
        std::process::exit(0);
    } else {
        tracing::warn!("{reason} — denying (fail-closed)");
        deny_and_exit(format!("{reason} — failing closed"));
    }
}

/// The policy path the hook reads on every call. Shared with `sentinel check`
/// so the dry-run can never drift from what the live hook actually evaluates.
pub(crate) fn resolve_policy_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".sentinel").join("policy.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claude Code honors a PreToolUse block ONLY when `permissionDecision` is
    /// nested under `hookSpecificOutput` with `hookEventName: "PreToolUse"` and
    /// `permissionDecisionReason`. A flat top-level `permissionDecision` is
    /// silently ignored — the bug that made every Sentinel block a no-op.
    #[test]
    fn deny_output_uses_nested_pretooluse_contract() {
        let out = HookOutput::deny("pipe to shell execution");
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&out).unwrap()).unwrap();

        let hso = &json["hookSpecificOutput"];
        assert_eq!(hso["hookEventName"], "PreToolUse");
        assert_eq!(hso["permissionDecision"], "deny");
        assert_eq!(hso["permissionDecisionReason"], "pipe to shell execution");
        // and NOT the dead flat form that Claude Code ignores
        assert!(
            json.get("permissionDecision").is_none(),
            "flat top-level permissionDecision is ignored by Claude Code"
        );
    }

    /// allow/warn must emit NO decision (empty object) so Sentinel defers to
    /// Claude Code's normal permission flow. Emitting `permissionDecision:"allow"`
    /// would AUTO-APPROVE every tool call Sentinel doesn't block — a privilege
    /// escalation, not a fix.
    #[test]
    fn allow_output_defers_to_normal_flow() {
        let s = serde_json::to_string(&HookOutput::allow()).unwrap();
        assert_eq!(s, "{}");
    }
}
