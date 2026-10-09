//! `sentinel policy-lint` - static checks on a policy file. Catches the mistakes
//! that quietly weaken a policy: a regex that doesn't compile (a dead rule), a
//! repeated pattern whose actions and ordering warrant review, and an
//! over-broad allow-list entry that widens a lockdown.
//!
//! It deliberately does NOT flag two rules that can both match the same input
//! (e.g. the intentional private-key-before-gcp_sa ordering in the defaults) -
//! that's design, not a bug. Only exact (section, pattern) duplicates are flagged.
//!
//! Best-effort warnings, not a proof of correctness: duplicate detection is
//! byte-exact (won't catch case- or trailing-slash-equivalent rules), broad-allow
//! detection is a fixed catch-all list, and path globs are not regex-validated.
//! The checks surface obvious mistakes; they don't model glob subsumption.

use crate::cli::LintArgs;
use crate::evaluate::resolve_policy_path;
use crate::policy::schema::is_valid_rule_id;
use crate::policy::PolicyEngine;
use regex::Regex;
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub error: bool,
    pub message: String,
}

fn is_broad_allow(pattern: &str) -> bool {
    matches!(
        pattern.trim(),
        "*" | "**" | "/*" | "/**" | "~" | "~/" | "~/**" | "**/*" | "./**"
    )
}

/// Run the static checks against a loaded policy. Pure. Testable.
pub fn lint_engine(engine: &PolicyEngine) -> Vec<Finding> {
    let rules = engine.rules();
    let mut findings = Vec::new();

    // 1. regexes that don't compile - a deny.commands/deny.secrets rule that can
    //    never match is a silent hole.
    for r in &rules {
        if matches!(r.section, "deny.commands" | "deny.secrets") {
            if let Err(e) = Regex::new(r.pattern) {
                findings.push(Finding {
                    error: true,
                    message: format!(
                        "{}: invalid regex {:?} (never matches): {e}",
                        r.section, r.pattern
                    ),
                });
            }
        }
    }

    // 2. Exact (section, pattern) duplicates. A warning holds its decision while
    //    evaluation continues, so a later blocking duplicate can still matter.
    //    Report repetition without claiming the later rule is unreachable.
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for r in &rules {
        if !seen.insert((r.section, r.pattern)) {
            findings.push(Finding {
                error: false,
                message: format!(
                    "{}: duplicate pattern {:?}; review the actions and ordering before removing either rule",
                    r.section, r.pattern
                ),
            });
        }
    }

    // 3. rule ids: an explicit id must use the bounded alphabet (it travels
    //    through audit lines and shell arguments), and two rules must not share
    //    one (`sentinel why` and future per-id overrides would be ambiguous).
    //    Derived ids are not checked here: they collide exactly when the
    //    (section, pattern) pair does, which check 2 already reports.
    let mut explicit_ids: HashSet<&str> = HashSet::new();
    for r in &rules {
        if !r.explicit_id {
            continue;
        }
        if !is_valid_rule_id(&r.id) {
            findings.push(Finding {
                error: true,
                message: format!(
                    "{}: rule id {:?} is invalid (1-128 chars of [A-Za-z0-9._/:-])",
                    r.section, r.id
                ),
            });
        }
        if !explicit_ids.insert(r.id.as_str()) {
            findings.push(Finding {
                error: true,
                message: format!(
                    "{}: duplicate rule id {:?}; ids must be unique across the policy",
                    r.section, r.id
                ),
            });
        }
    }

    // 4. over-broad allow entries - an allow-list with a catch-all defeats the
    //    point of a narrow allow + default=block lockdown.
    for r in &rules {
        if r.section == "allow.paths" && is_broad_allow(r.pattern) {
            findings.push(Finding {
                error: false,
                message: format!(
                    "allow.paths: {:?} matches almost everything and widens a lockdown allow-list",
                    r.pattern
                ),
            });
        }
    }

    findings
}

pub fn run(args: LintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = match args.policy {
        Some(path) => path,
        None => resolve_policy_path()?,
    };
    let engine = PolicyEngine::load(&path).map_err(|e| {
        format!(
            "could not load policy at {}: {e}\n(run 'sentinel install' first)",
            path.display()
        )
    })?;

    let findings = lint_engine(&engine);
    if findings.is_empty() {
        println!("{}: clean (no lint findings)", path.display());
        return Ok(());
    }

    let errors = findings.iter().filter(|f| f.error).count();
    for f in &findings {
        println!("[{}] {}", if f.error { "ERR" } else { "WARN" }, f.message);
    }
    println!();
    if errors > 0 {
        Err(format!("{errors} error-level lint finding(s)").into())
    } else {
        println!("{} warning(s), no errors", findings.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::defaults::default_policy_content;

    fn engine(toml: &str) -> PolicyEngine {
        PolicyEngine::from_toml_str(toml).unwrap()
    }

    #[test]
    fn shipped_default_policy_is_clean() {
        // THE guard: the shipped defaults (incl. the intentional private-key /
        // gcp_sa ordering) must produce ZERO findings, or lint is crying wolf.
        let e = PolicyEngine::from_toml_str(&default_policy_content("enforce")).unwrap();
        let findings = lint_engine(&e);
        assert!(
            findings.is_empty(),
            "default policy must lint clean; got: {findings:?}"
        );
    }

    #[test]
    fn invalid_regex_is_an_error() {
        let e = engine(
            "[policy]\nmode=\"enforce\"\n[[deny.commands]]\npattern = \"a(b\"\naction=\"block\"\nreason=\"x\"\n",
        );
        let findings = lint_engine(&e);
        assert!(findings
            .iter()
            .any(|f| f.error && f.message.contains("invalid regex")));
    }

    #[test]
    fn duplicate_warning_does_not_claim_a_reachable_block_is_dead() {
        for (first, second) in [("block", "warn"), ("warn", "block")] {
            let e = engine(&format!(
                "[policy]\nmode=\"enforce\"\n\
                 [[deny.commands]]\npattern='example'\naction='{first}'\nreason='{first}'\n\
                 [[deny.commands]]\npattern='example'\naction='{second}'\nreason='{second}'\n"
            ));
            let decision = e.evaluate(&crate::policy::ToolCall {
                tool_name: "Bash".into(),
                command: Some("example".into()),
                paths: Vec::new(),
                shell_expansion_paths: Vec::new(),
                raw_params: String::new(),
            });
            assert_eq!(decision.action, crate::policy::Action::Block);
            assert_eq!(decision.reason.as_deref(), Some("block"));

            let findings = lint_engine(&e);
            assert_eq!(findings.len(), 1);
            assert!(!findings[0].error);
            assert!(findings[0].message.contains("duplicate pattern"));
            assert!(!findings[0].message.contains("unreachable"));
        }
    }

    #[test]
    fn two_different_patterns_that_both_match_are_not_flagged() {
        // intentional overlap (like private-key before gcp_sa) must NOT be flagged
        let e = engine(
            "[policy]\nmode=\"enforce\"\n\
             [[deny.secrets]]\npattern='-----BEGIN [A-Z ]*PRIVATE KEY-----'\naction=\"block\"\nreason=\"a\"\n\
             [[deny.secrets]]\npattern='gserviceaccount'\naction=\"warn\"\nreason=\"b\"\n",
        );
        assert!(lint_engine(&e).is_empty());
    }

    #[test]
    fn invalid_and_duplicate_explicit_ids_are_errors() {
        let findings = lint_engine(&engine(
            r#"
[policy]
mode = "enforce"

[[deny.paths]]
id = "has space"
pattern = "~/.ssh/*"
action = "block"
reason = "r"

[[deny.paths]]
id = "dup"
pattern = "~/.aws/*"
action = "block"
reason = "r"

[[deny.commands]]
id = "dup"
pattern = 'rm -rf /'
action = "block"
reason = "r"
"#,
        ));
        let errors: Vec<&str> = findings
            .iter()
            .filter(|f| f.error)
            .map(|f| f.message.as_str())
            .collect();
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors[0].contains("rule id \"has space\" is invalid"));
        assert!(errors[1].contains("duplicate rule id \"dup\""));
    }

    #[test]
    fn derived_ids_are_not_reported_as_duplicates() {
        // two rules with the same (section, pattern) already get the duplicate
        // pattern warning; the id check must not double-report them as errors.
        let findings = lint_engine(&engine(
            r#"
[policy]
mode = "enforce"

[[deny.paths]]
pattern = "~/.ssh/*"
action = "warn"
reason = "r"

[[deny.paths]]
pattern = "~/.ssh/*"
action = "block"
reason = "r"
"#,
        ));
        assert!(findings.iter().all(|f| !f.error), "{findings:?}");
    }

    #[test]
    fn broad_allow_is_a_warning() {
        let e = engine(
            "[policy]\nmode=\"enforce\"\ndefault=\"block\"\n[[allow.paths]]\npattern=\"**\"\n",
        );
        let findings = lint_engine(&e);
        assert!(findings
            .iter()
            .any(|f| !f.error && f.message.contains("widens a lockdown")));
    }
}
