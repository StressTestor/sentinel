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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AllowWrapper {
    #[serde(default)]
    paths: Vec<AllowPathRule>,
}

impl PolicyConfig {
    /// construct programmatically (for tests and from_config)
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
        }
        if let Some(allow) = self.allow_wrapper.take() {
            self.allow_paths = allow.paths;
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
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

fn default_mode() -> String { "audit".into() }
fn default_on_failure() -> String { "closed".into() }
fn default_default() -> String { "warn".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyPathRule {
    pub pattern: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyCommandRule {
    pub pattern: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenySecretRule {
    pub pattern: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowPathRule {
    pub pattern: String,
    pub note: Option<String>,
}

/// parse a policy TOML string into a finalized PolicyConfig
pub fn parse_policy(toml_content: &str) -> Result<PolicyConfig, String> {
    let config: PolicyConfig = toml::from_str(toml_content)
        .map_err(|e| format!("policy parse error: {e}"))?;
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
    fn reject_invalid_toml() {
        let result = parse_policy("this is not toml {{{}}}");
        assert!(result.is_err());
    }
}
