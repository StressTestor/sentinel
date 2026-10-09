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
use crate::policy::overlay::{Overlay, OVERLAY_FILE_NAME};
use crate::policy::schema::is_valid_rule_id;
use crate::policy::PolicyEngine;
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub error: bool,
    pub message: String,
}

/// Whether a rule belongs to the self-protect family: anything that names
/// sentinel itself (`.sentinel/`, the binary paths, `sentinel-guard`,
/// `sentinel uninstall`, `audit-mcp --update`), or the agent's hook config
/// (`.claude/settings*`, the `~/.claude` directory). An overlay can never
/// downgrade one of these, whatever its tier.
pub fn is_self_protect_pattern(pattern: &str) -> bool {
    let lower = pattern.to_ascii_lowercase();
    lower.contains("sentinel")
        || lower.contains(".claude/settings")
        || lower.contains(r"\.claude(")
        || lower.contains(r"\.claude/")
        || lower.contains("/.claude/")
}

/// Whether a rule id names a fixed enforcement layer rather than a policy rule.
fn is_fixed_layer_id(id: &str) -> bool {
    id.starts_with("selfprotect:")
        || id.starts_with("preflight:")
        || id.starts_with("on_failure:")
        || id == "allow.paths:miss"
}

/// Whether `pattern` (an allow glob) stays inside `root`. `~` is expanded, the
/// path must be absolute, and the glob-free leading directory is canonicalized
/// when it exists so an alias of the project directory still counts. Patterns
/// with `..`, relative patterns, and anything outside the root are rejected.
fn allow_pattern_under_root(pattern: &str, root: &Path) -> bool {
    let expanded = match pattern.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(home) if !home.is_empty() => format!("{}/{rest}", home.trim_end_matches('/')),
            _ => return false,
        },
        None if pattern == "~" => return false,
        None => pattern.to_string(),
    };
    if !expanded.starts_with('/') {
        return false;
    }
    if expanded.split('/').any(|segment| segment == "..") {
        return false;
    }
    let root_text = root.to_string_lossy();
    let root_text = root_text.trim_end_matches('/');
    let under = |candidate: &str| {
        let candidate = candidate.trim_end_matches('/');
        candidate == root_text || candidate.starts_with(&format!("{root_text}/"))
    };
    if under(&expanded) {
        return true;
    }
    // the directory before the first glob metacharacter, resolved on disk
    let glob_at = expanded
        .find(['*', '?', '[', '{'])
        .unwrap_or(expanded.len());
    let literal = &expanded[..glob_at];
    let dir_end = literal.rfind('/').unwrap_or(0);
    let dir = if dir_end == 0 {
        "/"
    } else {
        &literal[..dir_end]
    };
    match std::fs::canonicalize(dir) {
        Ok(canonical) => {
            let rest = &expanded[dir_end..];
            under(&format!("{}{rest}", canonical.to_string_lossy()))
        }
        Err(_) => false,
    }
}

/// Lint a project overlay against the policy it will be applied to. Pure.
///
/// Error-level findings (any one of them stops `policy accept`, and makes an
/// already accepted overlay inert): a downgrade to anything but `warn`, of an
/// invalid or unknown rule id, of a fixed enforcement layer, of a self-protect
/// family rule, or of a block-tier `deny.secrets` rule; an allow pattern
/// outside the project root; an overlay deny rule with an `allow` action;
/// and anything `lint_engine` reports as an error on the merged policy
/// (invalid regexes, duplicate explicit ids).
pub fn lint_overlay(main: &PolicyEngine, overlay: &Overlay, project_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = main.rules();
    let mut seen_downgrades: HashSet<&str> = HashSet::new();

    for d in &overlay.downgrades {
        let id = d.rule.as_str();
        if !is_valid_rule_id(id) {
            findings.push(Finding {
                error: true,
                message: format!(
                    "downgrade: rule id {id:?} is invalid (1-128 chars of [A-Za-z0-9._/:-])"
                ),
            });
            continue;
        }
        if !d.to.eq_ignore_ascii_case("warn") {
            findings.push(Finding {
                error: true,
                message: format!(
                    "downgrade {id}: to = {:?} is not supported; an overlay can only downgrade to \"warn\"",
                    d.to
                ),
            });
        }
        if !seen_downgrades.insert(id) {
            findings.push(Finding {
                error: false,
                message: format!("downgrade {id}: listed more than once"),
            });
        }
        if is_fixed_layer_id(id) {
            findings.push(Finding {
                error: true,
                message: format!(
                    "downgrade {id}: a fixed enforcement layer (self-protect, preflight, failure posture) cannot be downgraded"
                ),
            });
            continue;
        }
        let Some(rule) = rules.iter().find(|r| r.id == id) else {
            findings.push(Finding {
                error: true,
                message: format!("downgrade {id}: no rule with this id in the policy"),
            });
            continue;
        };
        if is_self_protect_pattern(rule.pattern) {
            findings.push(Finding {
                error: true,
                message: format!(
                    "downgrade {id}: self-protect rule {} {:?} cannot be downgraded",
                    rule.section, rule.pattern
                ),
            });
            continue;
        }
        if rule.section == "deny.secrets" && rule.action.eq_ignore_ascii_case("block") {
            findings.push(Finding {
                error: true,
                message: format!(
                    "downgrade {id}: block-tier deny.secrets rule {:?} cannot be downgraded",
                    rule.pattern
                ),
            });
            continue;
        }
        if !rule.action.eq_ignore_ascii_case("block") {
            findings.push(Finding {
                error: false,
                message: format!(
                    "downgrade {id}: rule is already {}; the downgrade has no effect",
                    rule.action
                ),
            });
        }
    }

    for r in &overlay.allow_paths {
        if !allow_pattern_under_root(&r.pattern, project_root) {
            findings.push(Finding {
                error: true,
                message: format!(
                    "allow.paths: {:?} is outside the project root {} (overlay allow entries must be absolute paths under the project)",
                    r.pattern,
                    project_root.display()
                ),
            });
        }
    }
    if !overlay.allow_paths.is_empty() && !main.has_allow_list() {
        findings.push(Finding {
            error: false,
            message: "allow.paths: the policy has no allow list, so these entries have no effect"
                .into(),
        });
    }

    let overlay_actions = overlay
        .deny_paths
        .iter()
        .map(|r| ("deny.paths", &r.pattern, &r.action))
        .chain(
            overlay
                .deny_commands
                .iter()
                .map(|r| ("deny.commands", &r.pattern, &r.action)),
        )
        .chain(
            overlay
                .deny_secrets
                .iter()
                .map(|r| ("deny.secrets", &r.pattern, &r.action)),
        )
        .chain(
            overlay
                .deny_tools
                .iter()
                .map(|r| ("deny.tools", &r.pattern, &r.action)),
        );
    for (section, pattern, action) in overlay_actions {
        if !(action.eq_ignore_ascii_case("block") || action.eq_ignore_ascii_case("warn")) {
            findings.push(Finding {
                error: true,
                message: format!(
                    "{section}: {pattern:?} has action {action:?}; an overlay deny rule must be block or warn (it runs before the policy's own rules)"
                ),
            });
        }
    }

    // the merged policy's own checks, minus whatever the main policy already
    // reports on its own
    let base = lint_engine(main);
    for finding in lint_engine(&main.with_overlay(overlay, "overlay")) {
        if !base.contains(&finding) {
            findings.push(finding);
        }
    }
    findings
}

/// What is wrong with a `match = { ... }` block: keys outside the vocabulary,
/// a predicate with an empty list or string, or a block with no predicate.
/// Each is an error: the engine ignores an unknown key and an empty list can
/// never hold, so the rule would be weaker than it reads.
fn match_block_problems(spec: &crate::policy::schema::MatchSpec) -> Vec<String> {
    let mut problems = Vec::new();
    for key in spec.unknown.keys() {
        problems.push(format!(
            "match block has unknown key {key:?} (known: exec, has_flag, operand_under, piped_to, then_exec, interpreter_eval)"
        ));
    }
    if spec.is_empty() {
        problems.push("match block lists no predicate".into());
    }
    let lists = [
        ("exec", &spec.exec),
        ("has_flag", &spec.has_flag),
        ("piped_to", &spec.piped_to),
        ("then_exec", &spec.then_exec),
    ];
    for (name, list) in lists {
        if let Some(values) = list {
            if values.is_empty() || values.iter().any(String::is_empty) {
                problems.push(format!(
                    "match.{name} must be a non-empty list of non-empty strings"
                ));
            }
        }
    }
    if spec
        .operand_under
        .as_deref()
        .is_some_and(|dir| dir.trim_end_matches('/').is_empty())
    {
        problems.push("match.operand_under must name a directory".into());
    }
    if let Some(eval) = &spec.interpreter_eval {
        for key in eval.unknown.keys() {
            problems.push(format!(
                "match.interpreter_eval has unknown key {key:?} (known: interpreters, contains)"
            ));
        }
        if eval.interpreters.is_empty() || eval.interpreters.iter().any(String::is_empty) {
            problems.push(
                "match.interpreter_eval.interpreters must be a non-empty list of non-empty strings"
                    .into(),
            );
        }
        if eval.contains.is_empty() || eval.contains.iter().any(String::is_empty) {
            problems.push(
                "match.interpreter_eval.contains must be a non-empty list of non-empty strings"
                    .into(),
            );
        }
    }
    problems
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
    //    never match is a silent hole. A deny.commands rule may carry a `match`
    //    block instead of a pattern; one with neither, or with a malformed
    //    block (unknown key, empty list), is the same kind of hole.
    for r in &rules {
        if matches!(r.section, "deny.commands" | "deny.secrets") && !r.pattern.is_empty() {
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
        if r.section == "deny.commands" {
            match r.matcher {
                None if r.pattern.is_empty() => findings.push(Finding {
                    error: true,
                    message: format!(
                        "deny.commands: rule {} has neither a pattern nor a match block (never matches)",
                        r.id
                    ),
                }),
                Some(spec) => {
                    for problem in match_block_problems(spec) {
                        findings.push(Finding {
                            error: true,
                            message: format!("deny.commands: rule {}: {problem}", r.id),
                        });
                    }
                }
                None => {}
            }
        } else if r.pattern.is_empty() {
            findings.push(Finding {
                error: true,
                message: format!("{}: rule {} has an empty pattern", r.section, r.id),
            });
        }
    }

    // 2. Exact (section, pattern) duplicates. A warning holds its decision while
    //    evaluation continues, so a later blocking duplicate can still matter.
    //    Report repetition without claiming the later rule is unreachable.
    let mut seen: HashSet<(&str, String)> = HashSet::new();
    for r in &rules {
        if !seen.insert((r.section, r.display())) {
            findings.push(Finding {
                error: false,
                message: format!(
                    "{}: duplicate pattern {:?}; review the actions and ordering before removing either rule",
                    r.section,
                    r.display()
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

    let (findings, subject): (Vec<Finding>, PathBuf) = match &args.overlay {
        Some(overlay_arg) => {
            let overlay_path = if overlay_arg.is_dir() {
                overlay_arg.join(OVERLAY_FILE_NAME)
            } else {
                overlay_arg.clone()
            };
            let text = std::fs::read_to_string(&overlay_path)
                .map_err(|e| format!("could not read overlay {}: {e}", overlay_path.display()))?;
            let overlay = Overlay::parse(&text)?;
            let parent = overlay_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            let root = std::fs::canonicalize(&parent)
                .map_err(|e| format!("could not resolve project root {}: {e}", parent.display()))?;
            (lint_overlay(&engine, &overlay, &root), overlay_path)
        }
        None => (lint_engine(&engine), path),
    };
    let path = subject;
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
    fn match_blocks_are_validated() {
        let clean = engine(
            r#"
[policy]
mode = "enforce"

[[deny.commands]]
id = "a"
pattern = 'curl.*\|\s*sh'
match = { exec = ["curl"], piped_to = ["sh"] }
action = "block"
reason = "r"

[[deny.commands]]
id = "b"
match = { interpreter_eval = { interpreters = ["python3"], contains = ["os.system("] } }
action = "block"
reason = "r"
"#,
        );
        assert!(lint_engine(&clean).is_empty(), "{:?}", lint_engine(&clean));

        let broken = engine(
            r#"
[policy]
mode = "enforce"

[[deny.commands]]
id = "neither"
action = "block"
reason = "r"

[[deny.commands]]
id = "unknown-key"
match = { exec = ["curl"], pipes_to = ["sh"] }
action = "block"
reason = "r"

[[deny.commands]]
id = "empty-list"
match = { exec = [], then_exec = ["sh"] }
action = "block"
reason = "r"

[[deny.commands]]
id = "no-predicate"
match = {}
action = "block"
reason = "r"

[[deny.commands]]
id = "bad-eval"
match = { interpreter_eval = { interpreters = ["python3"], contains = [], extra = 1 } }
action = "block"
reason = "r"

[[deny.commands]]
id = "bad-dir"
match = { operand_under = "/" }
action = "block"
reason = "r"
"#,
        );
        let errors: Vec<String> = lint_engine(&broken)
            .into_iter()
            .filter(|f| f.error)
            .map(|f| f.message)
            .collect();
        let expect = [
            "rule neither has neither a pattern nor a match block",
            "rule unknown-key: match block has unknown key \"pipes_to\"",
            "rule empty-list: match.exec must be a non-empty list",
            "rule no-predicate: match block lists no predicate",
            "rule bad-eval: match.interpreter_eval has unknown key \"extra\"",
            "rule bad-eval: match.interpreter_eval.contains must be a non-empty list",
            "rule bad-dir: match.operand_under must name a directory",
        ];
        for needle in expect {
            assert!(
                errors.iter().any(|e| e.contains(needle)),
                "missing {needle:?} in {errors:?}"
            );
        }
        assert_eq!(errors.len(), expect.len(), "{errors:?}");
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

    const OVERLAY_POLICY: &str = r#"
[policy]
mode = "enforce"
default = "block"

[[deny.paths]]
id = "cred-paths/ssh"
pattern = "~/.ssh/*"
action = "block"
reason = "SSH key access"

[[deny.paths]]
id = "tripwire/settings"
pattern = "**/.claude/settings.json"
action = "warn"
reason = "settings write"

[[deny.commands]]
id = "fetch-exec/curl-pipe-sh"
pattern = 'curl\s+\S+\s*\|\s*sh'
action = "block"
reason = "pipe to shell"

[[deny.commands]]
id = "disarm/rm-sentinel"
pattern = '\brm\b.*\.sentinel/'
action = "block"
reason = "deleting ~/.sentinel"

[[deny.commands]]
id = "warn-only/scp"
pattern = '\bscp\b'
action = "warn"
reason = "scp"

[[deny.secrets]]
id = "secrets/aws"
pattern = 'AKIA[0-9A-Z]{16}'
action = "block"
reason = "AWS access key"

[[deny.secrets]]
id = "secrets/maybe"
pattern = 'gserviceaccount'
action = "warn"
reason = "service account"

[[allow.paths]]
pattern = "/other/**"
"#;

    fn overlay_errors(overlay: &str, root: &Path) -> Vec<String> {
        let e = engine(OVERLAY_POLICY);
        let o = Overlay::parse(overlay).unwrap();
        lint_overlay(&e, &o, root)
            .into_iter()
            .filter(|f| f.error)
            .map(|f| f.message)
            .collect()
    }

    fn downgrade(id: &str, to: &str) -> String {
        format!("[[downgrade]]\nrule = \"{id}\"\nto = \"{to}\"\nreason = \"r\"\n")
    }

    #[test]
    fn overlay_downgrade_of_an_ordinary_block_is_clean() {
        let root = tempfile::tempdir().unwrap();
        let errors = overlay_errors(&downgrade("fetch-exec/curl-pipe-sh", "warn"), root.path());
        assert!(errors.is_empty(), "{errors:?}");
        // the derived-id form is addressable too
        let derived = crate::policy::schema::rule_id(None, "deny.paths", "~/.ssh/*");
        let e = engine("[policy]\nmode=\"enforce\"\n[[deny.paths]]\npattern=\"~/.ssh/*\"\naction=\"block\"\nreason=\"r\"\n");
        let o = Overlay::parse(&downgrade(&derived, "warn")).unwrap();
        assert!(lint_overlay(&e, &o, root.path()).iter().all(|f| !f.error));
    }

    #[test]
    fn overlay_cannot_downgrade_self_protect_family_rules() {
        let root = tempfile::tempdir().unwrap();
        for id in ["disarm/rm-sentinel", "tripwire/settings"] {
            let errors = overlay_errors(&downgrade(id, "warn"), root.path());
            assert_eq!(errors.len(), 1, "{id}: {errors:?}");
            assert!(errors[0].contains("self-protect rule"), "{errors:?}");
        }
        for id in [
            "selfprotect:policy.toml-write",
            "preflight:x",
            "on_failure:closed",
        ] {
            let errors = overlay_errors(&downgrade(id, "warn"), root.path());
            assert!(
                errors.iter().any(|m| m.contains("fixed enforcement layer")),
                "{id}: {errors:?}"
            );
        }
        // every bundled rule that names sentinel or the hook config is covered
        let bundled = PolicyEngine::from_toml_str(&default_policy_content("enforce")).unwrap();
        let family: Vec<String> = bundled
            .rules()
            .iter()
            .filter(|r| is_self_protect_pattern(r.pattern))
            .map(|r| r.id.clone())
            .collect();
        assert!(
            family.len() >= 30,
            "expected the self-protect cluster, got {}",
            family.len()
        );
        for id in family {
            let o = Overlay::parse(&downgrade(&id, "warn")).unwrap();
            assert!(
                lint_overlay(&bundled, &o, root.path())
                    .iter()
                    .any(|f| f.error),
                "{id} must not be downgradable"
            );
        }
    }

    #[test]
    fn overlay_cannot_downgrade_a_block_tier_secret_rule() {
        let root = tempfile::tempdir().unwrap();
        let errors = overlay_errors(&downgrade("secrets/aws", "warn"), root.path());
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("block-tier deny.secrets"), "{errors:?}");
        // a warn-tier secret rule is not a block to begin with: no error
        let errors = overlay_errors(&downgrade("secrets/maybe", "warn"), root.path());
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn overlay_rejects_unknown_invalid_and_non_warn_downgrades() {
        let root = tempfile::tempdir().unwrap();
        let errors = overlay_errors(&downgrade("nope/missing", "warn"), root.path());
        assert!(errors[0].contains("no rule with this id"), "{errors:?}");
        let errors = overlay_errors(&downgrade("has space", "warn"), root.path());
        assert!(errors[0].contains("is invalid"), "{errors:?}");
        let errors = overlay_errors(&downgrade("fetch-exec/curl-pipe-sh", "allow"), root.path());
        assert!(
            errors[0].contains("only downgrade to \"warn\""),
            "{errors:?}"
        );
        // already-warn rule: a warning, not an error
        let e = engine(OVERLAY_POLICY);
        let o = Overlay::parse(&downgrade("warn-only/scp", "warn")).unwrap();
        let findings = lint_overlay(&e, &o, root.path());
        assert!(findings.iter().all(|f| !f.error), "{findings:?}");
        assert!(findings.iter().any(|f| f.message.contains("no effect")));
    }

    #[test]
    fn overlay_allow_patterns_must_stay_under_the_project_root() {
        let root = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let inside = format!(
            "[[allow.paths]]\npattern = \"{}/src/**\"\n",
            canonical.display()
        );
        assert!(overlay_errors(&inside, &canonical).is_empty());
        for outside in [
            "/etc/**".to_string(),
            "~/**".to_string(),
            "./src/**".to_string(),
            format!("{}/../**", canonical.display()),
            format!("{}-other/**", canonical.display()),
        ] {
            let text = format!("[[allow.paths]]\npattern = \"{outside}\"\n");
            let errors = overlay_errors(&text, &canonical);
            assert_eq!(errors.len(), 1, "{outside}: {errors:?}");
            assert!(errors[0].contains("outside the project root"), "{errors:?}");
        }
        // no allow list in the policy: a warning that the entries do nothing
        let e = engine("[policy]\nmode=\"enforce\"\n");
        let o = Overlay::parse(&inside).unwrap();
        let findings = lint_overlay(&e, &o, &canonical);
        assert!(findings.iter().all(|f| !f.error));
        assert!(findings.iter().any(|f| f.message.contains("no allow list")));
    }

    #[test]
    fn overlay_deny_additions_are_checked_and_cannot_be_allow_exceptions() {
        let root = tempfile::tempdir().unwrap();
        let errors = overlay_errors(
            "[[deny.commands]]\npattern = 'a(b'\naction = \"block\"\nreason = \"r\"\n",
            root.path(),
        );
        assert!(
            errors.iter().any(|m| m.contains("invalid regex")),
            "{errors:?}"
        );
        let errors = overlay_errors(
            "[[deny.paths]]\npattern = \"~/.ssh/*\"\naction = \"allow\"\nreason = \"r\"\n",
            root.path(),
        );
        assert!(
            errors.iter().any(|m| m.contains("must be block or warn")),
            "{errors:?}"
        );
        let errors = overlay_errors(
            "[[deny.commands]]\nid = \"fetch-exec/curl-pipe-sh\"\npattern = 'x'\naction = \"block\"\nreason = \"r\"\n",
            root.path(),
        );
        assert!(
            errors.iter().any(|m| m.contains("duplicate rule id")),
            "{errors:?}"
        );
        let errors = overlay_errors(
            "[[deny.tools]]\nid = \"project/mcp\"\npattern = \"mcp__x__*\"\naction = \"warn\"\nreason = \"r\"\n",
            root.path(),
        );
        assert!(errors.is_empty(), "{errors:?}");
    }
}
