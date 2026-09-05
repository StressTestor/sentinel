//! `sentinel policy-diff` - show which bundled-default rules are MISSING from an
//! installed policy, so a user who installed before a hardening update can see
//! (and paste in) the new protections.
//!
//! Strictly read-only: it never writes the policy. (An in-place merge was
//! considered and rejected - serializing the parsed policy back to TOML drops
//! every rule due to the `#[serde(skip)]` design, which would silently disarm the
//! guard. Printing for manual paste sidesteps that entirely.)

use crate::cli::PolicyDiffArgs;
use crate::evaluate::resolve_policy_path;
use crate::install::defaults::default_policy_content;
use crate::policy::PolicyEngine;
use std::collections::HashSet;

/// (section, pattern, action, reason)
type RuleTuple = (String, String, String, String);

fn to_tuples(engine: &PolicyEngine) -> Vec<RuleTuple> {
    engine
        .rules()
        .into_iter()
        .map(|r| {
            (
                r.section.into(),
                r.pattern.into(),
                r.action.into(),
                r.reason.into(),
            )
        })
        .collect()
}

/// Default rules whose (section, pattern) identity is absent from the user policy.
fn missing_defaults(default: &[RuleTuple], user: &[RuleTuple]) -> Vec<RuleTuple> {
    let user_keys: HashSet<(&str, &str)> = user
        .iter()
        .map(|(s, p, _, _)| (s.as_str(), p.as_str()))
        .collect();
    default
        .iter()
        .filter(|(s, p, _, _)| !user_keys.contains(&(s.as_str(), p.as_str())))
        .cloned()
        .collect()
}

/// Quote a pattern the way the default file does: globs double-quoted, regexes
/// single-quoted literals (so backslashes aren't doubled and the pasted rule
/// matches its neighbours). Fall back to a double-quoted escaped form if the
/// regex itself contains a single quote (which can't live in a TOML literal).
fn quote_pattern(section: &str, pattern: &str) -> String {
    let is_regex = matches!(section, "deny.commands" | "deny.secrets");
    if is_regex && !pattern.contains('\'') {
        format!("'{pattern}'")
    } else {
        format!("{pattern:?}")
    }
}

fn format_rule((section, pattern, action, reason): &RuleTuple) -> String {
    let pat = quote_pattern(section, pattern);
    if section == "allow.paths" {
        format!("[[{section}]]\npattern = {pat}\nnote = {reason:?}\n")
    } else {
        format!("[[{section}]]\npattern = {pat}\naction = {action:?}\nreason = {reason:?}\n")
    }
}

pub fn run(args: PolicyDiffArgs) -> Result<(), Box<dyn std::error::Error>> {
    let user_path = match args.policy {
        Some(path) => path,
        None => resolve_policy_path()?,
    };
    let user = PolicyEngine::load(&user_path).map_err(|e| {
        format!(
            "could not load policy at {}: {e}\n(run 'sentinel install' first)",
            user_path.display()
        )
    })?;
    let default = PolicyEngine::from_toml_str(&default_policy_content("enforce"))?;

    let missing = missing_defaults(&to_tuples(&default), &to_tuples(&user));

    if missing.is_empty() {
        println!(
            "policy at {} already has every bundled-default rule (matched by section + pattern).",
            user_path.display()
        );
        println!(
            "note: this compares which rules exist, not their action/reason or the [policy] block;"
        );
        println!("a rule you've edited won't be flagged even if the default later tightened it.");
        return Ok(());
    }

    println!(
        "{} bundled-default rule(s) are missing from {} (matched by section + pattern):",
        missing.len(),
        user_path.display()
    );
    println!("review and paste any you want in (this command never writes your policy).");
    println!("note: this lists rules you don't have; it does not diff action/reason or [policy] settings.");
    println!();
    for rule in &missing {
        println!("{}", format_rule(rule));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(section: &str, pattern: &str) -> RuleTuple {
        (section.into(), pattern.into(), "block".into(), "r".into())
    }

    #[test]
    fn reports_only_rules_absent_from_user() {
        let default = vec![
            t("deny.paths", "~/.ssh/*"),
            t("deny.paths", "~/.npmrc"),
            t("deny.secrets", "AKIA"),
        ];
        let user = vec![t("deny.paths", "~/.ssh/*")];
        let missing = missing_defaults(&default, &user);
        let patterns: Vec<&str> = missing.iter().map(|(_, p, _, _)| p.as_str()).collect();
        assert_eq!(patterns, vec!["~/.npmrc", "AKIA"]);
    }

    #[test]
    fn identity_is_section_plus_pattern() {
        // same pattern in a different section is a different rule
        let default = vec![t("deny.paths", "x"), t("deny.commands", "x")];
        let user = vec![t("deny.paths", "x")];
        let missing = missing_defaults(&default, &user);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, "deny.commands");
    }

    #[test]
    fn up_to_date_policy_has_no_missing_rules() {
        let default = PolicyEngine::from_toml_str(&default_policy_content("enforce")).unwrap();
        let tuples = to_tuples(&default);
        // a policy identical to the default is missing nothing
        assert!(missing_defaults(&tuples, &tuples).is_empty());
    }

    #[test]
    fn a_bare_policy_is_missing_the_whole_default_pack() {
        let bare = PolicyEngine::from_toml_str("[policy]\nmode=\"enforce\"\n").unwrap();
        let default = PolicyEngine::from_toml_str(&default_policy_content("enforce")).unwrap();
        let missing = missing_defaults(&to_tuples(&default), &to_tuples(&bare));
        assert!(
            missing.len() > 10,
            "a bare policy should be missing the full default rule set"
        );
        // and the self-protect rule must be among the missing
        assert!(missing
            .iter()
            .any(|(_, p, _, _)| p.contains(".sentinel/policy.toml")));
    }

    #[test]
    fn format_rule_is_pasteable_toml() {
        for (section, pattern, action, reason) in [
            ("deny.paths", "~/.npmrc", "block", "npm auth"),
            (
                "deny.paths",
                r#"./a "quoted" path\*"#,
                "warn",
                "quoted path",
            ),
            ("deny.commands", r"example\s+value", "block", "regex"),
            ("deny.secrets", r"example's\s+value", "warn", "apostrophe"),
            (
                "allow.paths",
                "./src/**",
                "allow",
                "a \"quoted\" note\nwith a second line",
            ),
        ] {
            let rule = (section.into(), pattern.into(), action.into(), reason.into());
            let out = format_rule(&rule);
            let parsed = PolicyEngine::from_toml_str(&format!("[policy]\n{out}"))
                .unwrap_or_else(|error| panic!("rule must parse as policy TOML: {error}; {out:?}"));
            assert_eq!(to_tuples(&parsed), vec![rule]);
        }
    }

    #[test]
    fn regex_rules_are_single_quoted_to_match_the_file() {
        // a regex with backslashes must paste as a single-quoted literal (no \\),
        // matching how deny.commands/deny.secrets are written in the default file.
        let r = (
            "deny.commands".into(),
            r"rm\s+-rf\s+/".into(),
            "block".into(),
            "x".into(),
        );
        let out = format_rule(&r);
        assert!(out.contains(r"pattern = 'rm\s+-rf\s+/'"), "got: {out}");
    }
}
