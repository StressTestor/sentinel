//! `sentinel check` — dry-run a tool call against the policy and explain the
//! decision, WITHOUT executing or logging anything. It loads the same policy
//! file the hook reads and routes the input through the exact same
//! `HookInput::to_tool_call` + `PolicyEngine::evaluate` path, so what it prints
//! cannot drift from what the live hook does.
//!
//! Honest-output rule: the policy engine returns the *rule* decision, but the
//! live hook's behaviour also depends on mode. In audit mode every call is
//! allowed-and-logged regardless of the rule. `check` therefore reports BOTH
//! the rule decision and the effective outcome in the current mode, so a fresh
//! (audit-mode) install never prints "Block" while the real hook allows.

use crate::cli::CheckArgs;
use crate::evaluate::hook_schema::HookInput;
use crate::evaluate::resolve_policy_path;
use crate::policy::{Action, PolicyEngine};
use serde::Serialize;
use std::io::{IsTerminal, Read};

#[derive(Debug, Serialize)]
pub struct CheckOutcome {
    /// "audit" or "enforce"
    pub mode: String,
    /// the tool the call targets (extracted from the input)
    pub tool_name: String,
    /// what the deny/allow rules say in isolation
    pub rule_action: String,
    pub matched_rule: Option<String>,
    pub reason: Option<String>,
    /// the paths the engine extracted from the call (what deny.paths sees)
    pub extracted_paths: Vec<String>,
    /// the command the engine extracted, if any (what deny.commands sees)
    pub command: Option<String>,
    /// does the live hook DENY this call right now, given the current mode?
    pub blocks: bool,
    /// human-readable summary of the effective outcome in the current mode
    pub effective: String,
}

/// Evaluate one hook-input JSON against a loaded policy. Pure: no file writes,
/// no audit logging. This is the testable core of `check`.
pub fn evaluate_check(engine: &PolicyEngine, raw: &str) -> Result<CheckOutcome, String> {
    if raw.trim().is_empty() {
        return Err("no input — pass the hook JSON as an argument, via --file, or on stdin".into());
    }
    let hook_input: HookInput = serde_json::from_str(raw).map_err(|e| {
        format!(
            "input is not valid hook JSON: {e}\n\
             (note: on uninspectable input the live hook fail-closes and DENIES in enforce mode)"
        )
    })?;
    // A call with no tool_name can't be meaningfully evaluated — reject rather
    // than silently treating it as the "unknown" tool.
    if hook_input.tool_name.is_none() {
        return Err("input has no \"tool_name\" — not a tool call sentinel can evaluate".into());
    }

    let tool_call = hook_input.to_tool_call();
    let decision = engine.evaluate(&tool_call);

    // The engine evaluates the full extracted-candidate list (which can repeat a
    // path that appears in several fields); de-dup only the DISPLAY copy, order
    // preserved, so the explain output is clean without changing what was evaluated.
    let mut seen = std::collections::HashSet::new();
    let display_paths: Vec<String> = tool_call
        .paths
        .iter()
        .filter(|p| seen.insert((*p).clone()))
        .cloned()
        .collect();

    let audit = engine.is_audit_mode();
    let blocks = !audit && decision.action == Action::Block;
    let effective = match (audit, &decision.action) {
        (true, Action::Allow) => "allowed (audit mode: logged only, nothing would block)".to_string(),
        (true, other) => format!(
            "allowed (audit mode: would be {other} in enforce mode — logged only, not blocked)"
        ),
        (false, Action::Block) => "DENIED".to_string(),
        (false, Action::Warn) => "allowed with a warning (enforce mode)".to_string(),
        (false, Action::Allow) => "allowed (enforce mode)".to_string(),
    };

    Ok(CheckOutcome {
        mode: engine.mode().to_string(),
        tool_name: tool_call.tool_name,
        rule_action: decision.action.to_string(),
        matched_rule: decision.matched_rule,
        reason: decision.reason,
        extracted_paths: display_paths,
        command: tool_call.command,
        blocks,
        effective,
    })
}

pub fn run(args: CheckArgs) -> Result<(), Box<dyn std::error::Error>> {
    let raw = read_input(&args)?;

    let policy_path = resolve_policy_path();
    let engine = PolicyEngine::load(&policy_path).map_err(|e| {
        format!(
            "could not load policy at {}: {e}\n(run 'sentinel install' first)",
            policy_path.display()
        )
    })?;

    let outcome = evaluate_check(&engine, &raw)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        print_human(&outcome);
    }
    Ok(())
}

fn read_input(args: &CheckArgs) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(file) = &args.file {
        return Ok(std::fs::read_to_string(file)?);
    }
    if let Some(input) = &args.input {
        return Ok(input.clone());
    }
    // No argument and no --file: read stdin, but only if it's piped. On an
    // interactive terminal, blocking on read_to_string would look like a hang,
    // so error with usage instead.
    if std::io::stdin().is_terminal() {
        return Err(
            "no input: pass the hook JSON as an argument, with --file, or piped on stdin".into(),
        );
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

fn print_human(o: &CheckOutcome) {
    println!("tool:      {}", o.tool_name);
    if let Some(cmd) = &o.command {
        println!("command:   {cmd}");
    }
    if !o.extracted_paths.is_empty() {
        println!("paths:     {}", o.extracted_paths.join(", "));
    }
    println!("mode:      {}", o.mode);
    match &o.matched_rule {
        Some(rule) => {
            println!("rule:      {} -> {}", rule, o.rule_action);
            if let Some(reason) = &o.reason {
                println!("reason:    {reason}");
            }
        }
        None => println!("rule:      (no rule matched) -> {}", o.rule_action),
    }
    println!("effective: {}", o.effective);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::parse_policy;

    fn engine(mode: &str) -> PolicyEngine {
        let toml = format!(
            r#"
[policy]
mode = "{mode}"
on_failure = "closed"
default = "warn"

[[deny.paths]]
pattern = "~/.ssh/*"
action = "block"
reason = "SSH key access"
"#
        );
        PolicyEngine::from_config(parse_policy(&toml).unwrap())
    }

    fn check(mode: &str, raw: &str) -> Result<CheckOutcome, String> {
        evaluate_check(&engine(mode), raw)
    }

    #[test]
    fn enforce_mode_block_denies() {
        let o = check(
            "enforce",
            r#"{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}"#,
        )
        .unwrap();
        assert_eq!(o.rule_action, "block");
        assert!(o.blocks, "enforce + block must report a live deny");
        assert_eq!(o.effective, "DENIED");
        assert!(o.matched_rule.unwrap().contains("ssh") || o.reason.is_some());
    }

    #[test]
    fn audit_mode_does_not_block_even_on_a_block_rule() {
        // THE honesty fix: a fresh (audit) install must NOT claim it blocks.
        let o = check(
            "audit",
            r#"{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}"#,
        )
        .unwrap();
        assert_eq!(o.rule_action, "block", "the rule still says block");
        assert!(!o.blocks, "audit mode does not block — must not claim it does");
        assert!(o.effective.contains("audit mode"));
    }

    #[test]
    fn no_match_allows() {
        let o = check(
            "enforce",
            r#"{"tool_name":"Read","tool_input":{"file_path":"./src/main.rs"}}"#,
        )
        .unwrap();
        assert_eq!(o.rule_action, "allow");
        assert!(!o.blocks);
    }

    #[test]
    fn paths_are_extracted_via_the_real_path() {
        // proves check routes through HookInput::to_tool_call, not a reimpl
        let o = check(
            "enforce",
            r#"{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}"#,
        )
        .unwrap();
        assert!(o.extracted_paths.iter().any(|p| p.contains(".ssh/id_rsa")));
        assert_eq!(o.command.as_deref(), Some("cat ~/.ssh/id_rsa"));
        assert!(o.blocks, "the path mined from the command must hit the deny rule");
    }

    #[test]
    fn missing_tool_name_is_rejected() {
        assert!(check("enforce", "{}").is_err());
        assert!(check("enforce", r#"{"tool_input":{"file_path":"x"}}"#).is_err());
    }

    #[test]
    fn empty_and_invalid_input_error() {
        assert!(check("enforce", "").is_err());
        assert!(check("enforce", "not json {{{").is_err());
    }

    #[test]
    fn output_never_leaks_raw_params() {
        // the JSON contract must not include the full tool_input blob
        let o = check(
            "enforce",
            r#"{"tool_name":"Write","tool_input":{"file_path":"./x","content":"SUPERSECRETTOKEN"}}"#,
        )
        .unwrap();
        let json = serde_json::to_string(&o).unwrap();
        assert!(!json.contains("SUPERSECRETTOKEN"), "check must not echo Write content");
    }
}
