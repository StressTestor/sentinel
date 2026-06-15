//! `sentinel post-evaluate` — PostToolUse result-content inspection.
//!
//! A PreToolUse hook sees the tool *call*, never the bytes a Read/WebFetch/Bash
//! returns. So a credential that arrives in a tool RESULT (a fetched page body, a
//! build log, `git log` output, a file the path rules don't cover) is invisible
//! to the deny.paths/deny.commands layer. This hook runs on PostToolUse and scans
//! the result content for the same secret shapes deny.secrets knows.
//!
//! HONEST FRAMING — this is detection, NOT prevention. PostToolUse fires AFTER
//! the tool executed: the bytes already exist in the transcript. This hook can
//! only (a) log that a secret shape landed in a result and (b) inject an
//! `additionalContext` nudge asking the model not to reproduce/transmit it. The
//! model can ignore the nudge; the leak is not prevented. It never blocks (there
//! is nothing left to block), and it never echoes the matched secret value.

use crate::evaluate::resolve_policy_path;
use crate::policy::PolicyEngine;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

/// The PostToolUse payload Claude Code sends on stdin. We only need the result;
/// everything else is captured for forward-compatibility.
#[derive(Debug, Deserialize)]
struct PostHookInput {
    #[serde(default, alias = "tool_output", alias = "toolResponse")]
    tool_response: serde_json::Value,
    #[serde(flatten)]
    _extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct PostHookOutput {
    #[serde(rename = "hookSpecificOutput", skip_serializing_if = "Option::is_none")]
    hook_specific_output: Option<PostToolUseExtra>,
    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    system_message: Option<String>,
}

#[derive(Serialize)]
struct PostToolUseExtra {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "additionalContext")]
    additional_context: String,
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Any failure here is silent (empty object, exit 0). PostToolUse cannot block,
    // and a result we can't inspect is not something to fail loudly over — the
    // tool already ran.
    let engine = match PolicyEngine::load(&resolve_policy_path()) {
        Ok(e) => e,
        Err(_) => return emit_nothing(),
    };

    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() || input.trim().is_empty() {
        return emit_nothing();
    }
    let hook: PostHookInput = match serde_json::from_str(&input) {
        Ok(h) => h,
        Err(_) => return emit_nothing(),
    };

    // Stringify the whole result so a secret in any field (stdout, stderr, a
    // structured body) is scanned — mirrors the defense-in-depth raw_params scan.
    let blob = hook.tool_response.to_string();
    let mut kinds = engine.scan_result_secrets(&blob);
    if kinds.is_empty() {
        return emit_nothing();
    }
    kinds.sort_unstable();
    kinds.dedup();
    let kinds = kinds.join(", ");

    // Log the detection (action = "detect" — distinct from block/warn/allow).
    let _ = crate::audit_trail::log_event(&crate::audit_trail::AuditEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        tool_name: "PostToolUse".into(),
        action: "detect".into(),
        reason: Some(format!("secret shape in tool result: {kinds}")),
        matched_rule: Some("post-evaluate: result-secret".into()),
        mode: engine.mode().to_string(),
    });

    let out = PostHookOutput {
        hook_specific_output: Some(PostToolUseExtra {
            hook_event_name: "PostToolUse",
            additional_context: format!(
                "sentinel: this tool result contains a credential pattern ({kinds}). \
                 Do NOT reproduce, summarize, echo, or transmit it. Treat it as sensitive \
                 and continue without surfacing the value."
            ),
        }),
        system_message: Some(format!(
            "sentinel: detected a secret shape ({kinds}) in a tool result — \
             detection only, the read already happened."
        )),
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

/// Emit an empty object (no decision, no context) and return Ok.
fn emit_nothing() -> Result<(), Box<dyn std::error::Error>> {
    println!("{{}}");
    Ok(())
}
