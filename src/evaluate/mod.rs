pub mod hook_schema;

use crate::audit_trail;
use crate::policy::{Action, PolicyEngine};
use hook_schema::HookInput;
use serde::Serialize;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// run the evaluate pipeline: read stdin JSON, evaluate policy, write stdout JSON.
/// this is the hot path called by Claude Code's PreToolUse hook on every tool call.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Load the policy FIRST, so a degraded input (empty / unparseable stdin) can
    // honor the policy's on_failure posture instead of a hard-coded allow.
    let policy_path = resolve_policy_path();
    let engine = match PolicyEngine::load(&policy_path) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("failed to load policy: {e}");
            // can't load policy → can't make a safe decision → deny
            print_output(&HookOutput {
                permission_decision: Some("deny".into()),
                reason: Some(format!("policy load failed: {e}")),
            });
            return Ok(());
        }
    };

    // read JSON from stdin
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        // a read error is also an un-inspectable input, not a free pass
        print_output(&degraded(&engine, "failed to read stdin"));
        return Ok(());
    }

    if input.trim().is_empty() {
        print_output(&degraded(&engine, "empty input"));
        return Ok(());
    }

    // Parse the hook input. A payload sentinel can't understand is NOT a free
    // pass — it's a degraded input, handled per the policy's on_failure posture.
    let hook_input = match serde_json::from_str::<HookInput>(&input) {
        Ok(hi) => hi,
        Err(e) => {
            print_output(&degraded(&engine, &format!("unparseable hook input: {e}")));
            return Ok(());
        }
    };

    // convert hook input to tool call
    let tool_call = hook_input.to_tool_call();

    // evaluate
    let decision = engine.evaluate(&tool_call);

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
        print_output(&HookOutput {
            permission_decision: None, // no decision = allow
            reason: None,
        });
        return Ok(());
    }

    // enforce mode
    match decision.action {
        Action::Block => {
            print_output(&HookOutput {
                permission_decision: Some("deny".into()),
                reason: decision.reason,
            });
        }
        Action::Warn => {
            // warn = allow but log prominently
            eprintln!(
                "\x1b[33msentinel warning:\x1b[0m {} — {}",
                tool_call.tool_name,
                decision.reason.as_deref().unwrap_or("policy warning")
            );
            print_output(&HookOutput {
                permission_decision: None,
                reason: None,
            });
        }
        Action::Allow => {
            print_output(&HookOutput {
                permission_decision: None,
                reason: None,
            });
        }
    }

    Ok(())
}

fn print_output(output: &HookOutput) {
    if let Ok(json) = serde_json::to_string(output) {
        println!("{json}");
    }
}

/// Decide what to do with an input sentinel cannot evaluate (empty stdin,
/// unparseable JSON). Audit mode never blocks; otherwise the policy's
/// `on_failure` posture governs — "closed" (the default) denies rather than
/// waving an un-inspectable call through, "open" allows with a warning.
fn degraded(engine: &PolicyEngine, reason: &str) -> HookOutput {
    if engine.is_audit_mode() || !engine.fail_closed() {
        tracing::warn!("{reason} — allowing (audit/fail-open)");
        HookOutput {
            permission_decision: None,
            reason: None,
        }
    } else {
        tracing::warn!("{reason} — denying (fail-closed)");
        HookOutput {
            permission_decision: Some("deny".into()),
            reason: Some(format!("{reason} — failing closed")),
        }
    }
}

fn resolve_policy_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".sentinel").join("policy.toml")
}
