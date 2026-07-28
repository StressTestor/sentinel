pub mod hook_schema;
pub mod normalize;
pub mod pipeline;

use crate::audit_trail;
use crate::policy::{Action, PolicyDecision, PolicyEngine};
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
/// Which host agent's decision format `evaluate` emits. The decision pipeline is
/// identical across agents — only the deny output shape differs. A block always
/// also exits 2, the universal hard-block signal every supported agent honors,
/// so even one that ignores the stdout JSON is covered.
#[derive(Clone, Copy, PartialEq)]
pub enum AgentFormat {
    /// Nested `hookSpecificOutput.permissionDecision` JSON. Claude Code, and
    /// OpenAI Codex CLI — whose PreToolUse output contract is byte-for-byte the
    /// same (`~/.codex/config.toml` `[[hooks.PreToolUse]]`).
    ClaudeCode,
    /// `{"decision":"<token>","reason":...}` + exit 2. token `deny` for Gemini
    /// CLI (`BeforeTool`, `~/.gemini/settings.json`) and Crush (`PreToolUse`);
    /// `block` for the documented generic contract (also Codex's legacy form).
    Decision(&'static str),
}

impl AgentFormat {
    pub fn from_name(name: &str) -> AgentFormat {
        match name {
            // Codex's PreToolUse output is identical to Claude Code's nested shape
            "claude-code" | "codex" => AgentFormat::ClaudeCode,
            // Gemini CLI / Crush accept the {"decision":"deny",...} form
            "gemini" | "crush" => AgentFormat::Decision("deny"),
            // the documented generic contract (also accepted by Codex's legacy form)
            _ => AgentFormat::Decision("block"),
        }
    }
}

pub fn run(canary: bool, agent: &str) -> Result<(), Box<dyn std::error::Error>> {
    let format = AgentFormat::from_name(agent);
    // Load the policy FIRST, so a degraded input (empty / unparseable stdin) can
    // honor the policy's on_failure posture instead of a hard-coded allow.
    let policy_path = resolve_policy_path();
    let engine = match PolicyEngine::load(&policy_path) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("failed to load policy: {e}");
            // can't load policy → can't make a safe decision → deny (and exit 2)
            deny_and_exit(format!("policy load failed: {e}"), format);
        }
    };

    // Read once, then hand every host payload to the shared normalization and
    // decision pipeline. Parse/normalization failures retain the policy's
    // explicit on_failure posture rather than falling through as an allow.
    let mut input = String::new();
    let result = match io::stdin().read_to_string(&mut input) {
        Ok(_) => pipeline::evaluate_raw(&engine, &input),
        Err(error) => pipeline::degraded(&engine, format!("failed to read stdin: {error}")),
    };
    let decision = result.decision().clone();

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

    let call = match result.call() {
        Some(call) => call,
        None => {
            if let Some(reason) = result.degraded_reason() {
                tracing::warn!("{reason}");
            }
            emit_live_decision(&decision, "<uninspectable>", format, &engine);
            return Ok(());
        }
    };
    let tool_call = call.to_tool_call();

    // log to audit trail
    let _ = audit_trail::log_event(&audit_trail::AuditEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        tool_name: tool_call.tool_name.clone(),
        action: decision.action.to_string(),
        reason: decision.reason.clone(),
        matched_rule: decision.matched_rule.clone(),
        mode: engine.mode().to_string(),
        // correlate with the caller's own log when a wrapper (e.g. the ghost
        // bridge) tagged this call. read-only telemetry: absent or malformed
        // env never changes the decision and never touches stdout/stderr.
        call_id: audit_trail::call_id_from_env(),
        // the payload's per-call id joins this pre line to the call's post
        // line(s) — same value in both phases' payloads. telemetry only.
        tool_use_id: call.tool_use_id.clone(),
        hook_phase: Some("pre".into()),
    });

    emit_live_decision(&decision, &tool_call.tool_name, format, &engine);

    Ok(())
}

fn print_output(output: &HookOutput) {
    if let Ok(json) = serde_json::to_string(output) {
        println!("{json}");
    }
}

fn emit_live_decision(
    decision: &PolicyDecision,
    tool_name: &str,
    format: AgentFormat,
    engine: &PolicyEngine,
) {
    if engine.is_audit_mode() {
        if decision.action != Action::Allow {
            tracing::info!(
                "AUDIT: would {} {} — {}",
                decision.action,
                tool_name,
                decision.reason.as_deref().unwrap_or("no reason")
            );
        }
        print_output(&HookOutput::allow());
        return;
    }

    match decision.action {
        Action::Block => deny_and_exit(
            decision
                .reason
                .clone()
                .unwrap_or_else(|| "blocked by sentinel policy".into()),
            format,
        ),
        Action::Warn => {
            eprintln!(
                "\x1b[33msentinel warning:\x1b[0m {} — {}",
                tool_name,
                decision.reason.as_deref().unwrap_or("policy warning")
            );
            print_output(&HookOutput::allow());
        }
        Action::Allow => print_output(&HookOutput::allow()),
    }
}

/// Emit the nested deny JSON, mirror the reason to stderr, and exit 2. Never
/// returns. Exit code 2 is Claude Code's hard-block signal *independent of how
/// it parses stdout*, so this is belt-and-suspenders against the output-contract
/// drift that silently disarmed every block in 0.2.0 (the flat-JSON bug): even
/// if a future Claude Code ignores the JSON shape entirely, exit 2 still blocks.
fn deny_and_exit(reason: impl Into<String>, format: AgentFormat) -> ! {
    let reason = reason.into();
    match format {
        AgentFormat::ClaudeCode => print_output(&HookOutput::deny(reason.clone())),
        AgentFormat::Decision(token) => {
            println!(
                "{}",
                serde_json::json!({"decision": token, "reason": reason})
            );
        }
    }
    let _ = io::stdout().flush(); // ensure the JSON lands before we exit
    eprintln!("sentinel: blocked — {reason}");
    std::process::exit(2);
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
