use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policy: PolicySettings,
    #[serde(default, rename = "deny")]
    deny_paths_wrapper: Option<DenyWrapper>,
    #[serde(skip)]
    pub deny_paths: Vec<DenyPathRule>,
    #[serde(skip)]
    pub deny_commands: Vec<DenyCommandRule>,
    #[serde(skip)]
    pub deny_secrets: Vec<DenySecretRule>,
    #[serde(skip)]
    pub deny_tools: Vec<DenyToolRule>,
    #[serde(default, rename = "allow")]
    allow_wrapper: Option<AllowWrapper>,
    #[serde(skip)]
    pub allow_paths: Vec<AllowPathRule>,
}

// serde intermediate types to handle the nested TOML structure:
// [[deny.paths]], [[deny.commands]], [[deny.secrets]], [[allow.paths]]

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DenyWrapper {
    #[serde(default)]
    paths: Vec<DenyPathRule>,
    #[serde(default)]
    commands: Vec<DenyCommandRule>,
    #[serde(default)]
    secrets: Vec<DenySecretRule>,
    #[serde(default)]
    tools: Vec<DenyToolRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AllowWrapper {
    #[serde(default)]
    paths: Vec<AllowPathRule>,
}

impl PolicyConfig {
    #[cfg(test)]
    pub fn new(
        policy: PolicySettings,
        deny_paths: Vec<DenyPathRule>,
        deny_commands: Vec<DenyCommandRule>,
        deny_secrets: Vec<DenySecretRule>,
        allow_paths: Vec<AllowPathRule>,
    ) -> Self {
        Self {
            policy,
            deny_paths_wrapper: None,
            deny_paths,
            deny_commands,
            deny_secrets,
            deny_tools: Vec::new(),
            allow_wrapper: None,
            allow_paths,
        }
    }

    /// post-deserialize: flatten the serde wrappers into the top-level vecs
    pub fn finalize(mut self) -> Self {
        if let Some(deny) = self.deny_paths_wrapper.take() {
            self.deny_paths = deny.paths;
            self.deny_commands = deny.commands;
            self.deny_secrets = deny.secrets;
            self.deny_tools = deny.tools;
        }
        if let Some(allow) = self.allow_wrapper.take() {
            self.allow_paths = allow.paths;
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
    /// Bundled policy rule generation. Legacy policies omitted this marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// "audit" (log only) or "enforce" (block)
    #[serde(default = "default_mode")]
    pub mode: String,
    /// "closed" (kill agent on crash) or "open" (allow + warn)
    #[serde(default = "default_on_failure")]
    pub on_failure: String,
    /// default action for unmatched tool calls: "block", "warn", "allow"
    #[serde(default = "default_default")]
    pub default: String,
}

fn default_mode() -> String {
    "audit".into()
}
fn default_on_failure() -> String {
    "closed".into()
}
fn default_default() -> String {
    "warn".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyPathRule {
    /// Optional stable identifier for `sentinel why`, audit lines, and future
    /// per-rule overrides. Absent → derived from the section and pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub pattern: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyCommandRule {
    /// Optional stable identifier for `sentinel why`, audit lines, and future
    /// per-rule overrides. Absent → derived from the section and pattern (or
    /// the match block, for a rule without a pattern).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Regex over the command text. Empty when the rule is `match`-only.
    #[serde(default)]
    pub pattern: String,
    /// Structured predicates over the parsed command (`common::ast`), evaluated
    /// next to the regex: the rule fires when either matches. See
    /// `policy::predicate` for the vocabulary and the Unmodeled rules.
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub matcher: Option<MatchSpec>,
    pub action: String,
    pub reason: String,
}

impl DenyCommandRule {
    /// What identifies this rule when it has no explicit id: the pattern, or
    /// the canonical rendering of the match block for a match-only rule.
    pub fn identity(&self) -> String {
        if !self.pattern.is_empty() {
            return self.pattern.clone();
        }
        self.matcher
            .as_ref()
            .map(MatchSpec::canonical)
            .unwrap_or_default()
    }

    /// The rule text shown in `matched_rule` labels and `sentinel why`.
    pub fn display(&self) -> String {
        if !self.pattern.is_empty() {
            return self.pattern.clone();
        }
        self.matcher
            .as_ref()
            .map(|m| format!("match = {}", m.render()))
            .unwrap_or_default()
    }
}

/// The `match = { ... }` block of a `[[deny.commands]]` rule. Every listed
/// predicate must hold for one command segment (and, for `piped_to` and
/// `then_exec`, a later segment in the same scope). Unknown keys are kept so
/// `policy-lint` can report them; the engine ignores them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MatchSpec {
    /// Command basenames in command position, after the modeled wrappers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<Vec<String>>,
    /// Flags present on the command (`-o`, `-o<value>`, `--output`, `--output=<value>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_flag: Option<Vec<String>>,
    /// A literal operand (or redirect target) under this directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operand_under: Option<String>,
    /// A later element of the same pipeline whose exec is listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub piped_to: Option<Vec<String>>,
    /// A later segment of the same scope (after the pipeline) whose exec is listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub then_exec: Option<Vec<String>>,
    /// An interpreter's inline-code argument containing a needle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter_eval: Option<InterpreterEval>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct InterpreterEval {
    #[serde(default)]
    pub interpreters: Vec<String>,
    #[serde(default)]
    pub contains: Vec<String>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown: BTreeMap<String, toml::Value>,
}

impl MatchSpec {
    /// Whether any known predicate is set.
    pub fn is_empty(&self) -> bool {
        self.exec.is_none()
            && self.has_flag.is_none()
            && self.operand_under.is_none()
            && self.piped_to.is_none()
            && self.then_exec.is_none()
            && self.interpreter_eval.is_none()
    }

    /// A stable one-line form (JSON, fields in declaration order) used to
    /// derive a rule id when the rule has no pattern.
    pub fn canonical(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The block as it would be written in the policy, on one line.
    pub fn render(&self) -> String {
        let mut parts = Vec::new();
        let list = |values: &[String]| -> String {
            format!(
                "[{}]",
                values
                    .iter()
                    .map(|v| format!("{v:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        if let Some(v) = &self.exec {
            parts.push(format!("exec = {}", list(v)));
        }
        if let Some(v) = &self.has_flag {
            parts.push(format!("has_flag = {}", list(v)));
        }
        if let Some(v) = &self.operand_under {
            parts.push(format!("operand_under = {v:?}"));
        }
        if let Some(v) = &self.piped_to {
            parts.push(format!("piped_to = {}", list(v)));
        }
        if let Some(v) = &self.then_exec {
            parts.push(format!("then_exec = {}", list(v)));
        }
        if let Some(ie) = &self.interpreter_eval {
            parts.push(format!(
                "interpreter_eval = {{ interpreters = {}, contains = {} }}",
                list(&ie.interpreters),
                list(&ie.contains)
            ));
        }
        for key in self.unknown.keys() {
            parts.push(format!("{key} = ?"));
        }
        format!("{{ {} }}", parts.join(", "))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenySecretRule {
    /// Optional stable identifier for `sentinel why`, audit lines, and future
    /// per-rule overrides. Absent → derived from the section and pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub pattern: String,
    pub action: String,
    pub reason: String,
}

/// a rule matched against the tool NAME (e.g. `mcp__server__tool`, `Bash`).
/// MCP tool calls traverse the PreToolUse hook like any other, so this lets a
/// user block or warn a specific MCP server/tool by name. opt-in lockdown — no
/// such rule ships in the default policy (a default `mcp__*` block would be a
/// false positive for every MCP user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyToolRule {
    /// Optional stable identifier for `sentinel why`, audit lines, and future
    /// per-rule overrides. Absent → derived from the section and pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub pattern: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowPathRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub pattern: String,
    pub note: Option<String>,
}

/// The characters an explicit rule id may use. Ids appear in audit lines,
/// `sentinel why` output, and shell arguments, so the alphabet stays small.
pub fn is_valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':'))
}

/// The id a rule is addressed by: its explicit `id` when set, otherwise
/// `<section>:<first 8 hex of sha256(pattern)>`. The derived form is stable
/// across reorderings and edits to `action`/`reason`, and changes exactly when
/// the pattern changes, so an audit line written today still names the same
/// rule after a policy reorder.
pub fn rule_id(explicit: Option<&str>, section: &str, pattern: &str) -> String {
    if let Some(id) = explicit {
        return id.to_string();
    }
    format!("{section}:{}", pattern_digest8(pattern))
}

fn pattern_digest8(pattern: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(pattern.as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// parse a policy TOML string into a finalized PolicyConfig
#[cfg(test)]
pub fn parse_policy(toml_content: &str) -> Result<PolicyConfig, String> {
    let config: PolicyConfig =
        toml::from_str(toml_content).map_err(|e| format!("policy parse error: {e}"))?;
    Ok(config.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_policy() {
        let toml = r#"
[policy]
mode = "enforce"
on_failure = "closed"
default = "warn"

[[deny.paths]]
pattern = "~/.ssh/*"
action = "block"
reason = "SSH key access"

[[deny.paths]]
pattern = "~/.aws/*"
action = "block"
reason = "AWS credential access"

[[deny.commands]]
pattern = "rm -rf /.*"
action = "block"
reason = "recursive root deletion"

[[deny.secrets]]
pattern = "AKIA[0-9A-Z]{16}"
action = "block"
reason = "AWS access key"

[[allow.paths]]
pattern = "./src/**"
note = "project source"
"#;
        let config = parse_policy(toml).unwrap();
        assert_eq!(config.policy.mode, "enforce");
        assert_eq!(config.deny_paths.len(), 2);
        assert_eq!(config.deny_commands.len(), 1);
        assert_eq!(config.deny_secrets.len(), 1);
        assert_eq!(config.allow_paths.len(), 1);
    }

    #[test]
    fn parse_minimal_policy() {
        let toml = r#"
[policy]
mode = "audit"
"#;
        let config = parse_policy(toml).unwrap();
        assert_eq!(config.policy.mode, "audit");
        assert_eq!(config.policy.on_failure, "closed");
        assert!(config.deny_paths.is_empty());
    }

    #[test]
    fn explicit_id_parses_and_absent_id_derives_from_section_and_pattern() {
        let toml = r#"
[policy]
mode = "enforce"

[[deny.paths]]
id = "cred-paths/ssh"
pattern = "~/.ssh/*"
action = "block"
reason = "SSH key access"

[[deny.paths]]
pattern = "~/.aws/*"
action = "block"
reason = "AWS credential access"
"#;
        let config = parse_policy(toml).unwrap();
        assert_eq!(config.deny_paths[0].id.as_deref(), Some("cred-paths/ssh"));
        assert_eq!(config.deny_paths[1].id, None);
        let derived = rule_id(None, "deny.paths", "~/.aws/*");
        assert!(derived.starts_with("deny.paths:"), "{derived}");
        assert_eq!(derived.len(), "deny.paths:".len() + 8);
        // stable: same pattern, same id; different pattern, different id
        assert_eq!(derived, rule_id(None, "deny.paths", "~/.aws/*"));
        assert_ne!(derived, rule_id(None, "deny.paths", "~/.aws/**"));
        assert_ne!(derived, rule_id(None, "deny.commands", "~/.aws/*"));
        assert_eq!(rule_id(Some("x"), "deny.paths", "~/.aws/*"), "x");
    }

    #[test]
    fn rule_id_alphabet_is_bounded() {
        assert!(is_valid_rule_id("cred-paths/ssh"));
        assert!(is_valid_rule_id("fetch_exec.curl:v2"));
        assert!(!is_valid_rule_id(""));
        assert!(!is_valid_rule_id("has space"));
        assert!(!is_valid_rule_id("quote\""));
        assert!(!is_valid_rule_id(&"a".repeat(129)));
    }

    #[test]
    fn reject_invalid_toml() {
        let result = parse_policy("this is not toml {{{}}}");
        assert!(result.is_err());
    }

    #[test]
    fn match_block_parses_next_to_or_instead_of_a_pattern() {
        let toml = r#"
[policy]
mode = "enforce"

[[deny.commands]]
id = "fetch-exec/curl-pipe-sh"
pattern = 'curl.*\|\s*sh'
match = { exec = ["curl", "wget"], piped_to = ["sh", "bash"] }
action = "block"
reason = "pipe to shell"

[[deny.commands]]
match = { interpreter_eval = { interpreters = ["python3"], contains = ["os.system("] }, mystery = 1 }
action = "block"
reason = "inline exec"
"#;
        let config = parse_policy(toml).unwrap();
        let both = &config.deny_commands[0];
        assert_eq!(both.pattern, r"curl.*\|\s*sh");
        let spec = both.matcher.as_ref().unwrap();
        assert_eq!(
            spec.exec.as_deref(),
            Some(&["curl".to_string(), "wget".into()][..])
        );
        assert_eq!(
            spec.piped_to.as_deref(),
            Some(&["sh".to_string(), "bash".into()][..])
        );
        assert!(spec.unknown.is_empty());
        assert_eq!(both.identity(), both.pattern);
        assert_eq!(both.display(), both.pattern);

        let only = &config.deny_commands[1];
        assert!(only.pattern.is_empty());
        let spec = only.matcher.as_ref().unwrap();
        let eval = spec.interpreter_eval.as_ref().unwrap();
        assert_eq!(eval.interpreters, ["python3"]);
        assert_eq!(eval.contains, ["os.system("]);
        assert_eq!(spec.unknown.keys().collect::<Vec<_>>(), ["mystery"]);
        // identity is the canonical block, so the derived id is stable and
        // unique per block; display is the block as written
        assert_eq!(
            only.identity(),
            r#"{"interpreter_eval":{"interpreters":["python3"],"contains":["os.system("]},"mystery":1}"#
        );
        assert_eq!(
            only.display(),
            r#"match = { interpreter_eval = { interpreters = ["python3"], contains = ["os.system("] }, mystery = ? }"#
        );
        let id = rule_id(None, "deny.commands", &only.identity());
        assert!(id.starts_with("deny.commands:"));
        assert_ne!(id, rule_id(None, "deny.commands", ""));
        // a rule with neither is parseable (lint rejects it) and inert
        let bare = parse_policy(
            "[policy]\nmode=\"enforce\"\n[[deny.commands]]\naction=\"block\"\nreason=\"r\"\n",
        )
        .unwrap();
        assert!(bare.deny_commands[0].pattern.is_empty());
        assert!(bare.deny_commands[0].matcher.is_none());
    }
}
