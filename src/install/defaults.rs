use super::InstallError;
use std::path::Path;

/// write the default policy.toml with sane deny rules.
/// does NOT overwrite if the file already exists.
pub fn write_default_policy(path: &Path, mode: &str) -> Result<(), InstallError> {
    if path.exists() {
        println!("policy file already exists at {}, skipping", path.display());
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| InstallError::WriteError(e.to_string()))?;
    }

    let content = default_policy_content(mode);
    std::fs::write(path, content)
        .map_err(|e| InstallError::WriteError(e.to_string()))
}

fn default_policy_content(mode: &str) -> String {
    format!(
        r#"# sentinel policy configuration
# docs: https://github.com/StressTestor/sentinel

[policy]
mode = "{mode}"          # "audit" (log only) or "enforce" (block)
on_failure = "closed"   # "closed" (kill agent on sentinel crash) or "open" (allow + warn)
default = "warn"        # default action for unmatched tool calls: "block", "warn", "allow"

# deny rules — evaluated first, in order. first match wins.

[[deny.paths]]
pattern = "~/.ssh/*"
action = "block"
reason = "SSH key access"

[[deny.paths]]
pattern = "~/.aws/*"
action = "block"
reason = "AWS credential access"

[[deny.paths]]
pattern = "~/.gnupg/*"
action = "block"
reason = "GPG keyring access"

[[deny.paths]]
pattern = "~/.config/gh/*"
action = "block"
reason = "GitHub CLI credential access"

[[deny.paths]]
pattern = "*/.env"
action = "warn"
reason = "environment file may contain secrets"

[[deny.paths]]
pattern = "*/.env.*"
action = "warn"
reason = "environment file may contain secrets"

[[deny.commands]]
pattern = 'rm\s+-rf\s+/.*'
action = "block"
reason = "recursive root deletion"

[[deny.commands]]
pattern = 'curl\s+.*\|\s*.*sh'
action = "block"
reason = "pipe to shell execution"

[[deny.commands]]
pattern = 'wget\s+.*\|\s*.*sh'
action = "block"
reason = "pipe to shell execution"

[[deny.commands]]
pattern = 'chmod\s+777\s+.*'
action = "warn"
reason = "world-writable permissions"

[[deny.secrets]]
pattern = 'AKIA[0-9A-Z]{{16}}'
action = "block"
reason = "AWS access key ID"

[[deny.secrets]]
pattern = 'ghp_[A-Za-z0-9]{{36}}'
action = "block"
reason = "GitHub personal access token"

[[deny.secrets]]
pattern = 'sk-[A-Za-z0-9]{{48}}'
action = "block"
reason = "OpenAI/Anthropic API key"

# allow rules — if present, paths not matching any allow rule get the default action.
# uncomment and customize for your project:

# [[allow.paths]]
# pattern = "./src/**"
# note = "project source"

# [[allow.paths]]
# pattern = "./tests/**"
# note = "test files"
"#
    )
}
