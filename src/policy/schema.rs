use serde::{Deserialize, Serialize};

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
    /// per-rule overrides. Absent → derived from the section and pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub pattern: String,
    pub action: String,
    pub reason: String,
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
}
