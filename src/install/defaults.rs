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
        std::fs::create_dir_all(parent).map_err(|e| InstallError::WriteError(e.to_string()))?;
    }

    let content = default_policy_content(mode);
    std::fs::write(path, content).map_err(|e| InstallError::WriteError(e.to_string()))
}

fn default_policy_content(mode: &str) -> String {
    format!(
        r#"# sentinel policy configuration
# docs: https://github.com/StressTestor/sentinel

[policy]
mode = "{mode}"          # "audit" (log only) or "enforce" (block)
on_failure = "closed"   # "closed" (kill agent on sentinel crash) or "open" (allow + warn)
default = "warn"        # default action for unmatched tool calls: "block", "warn", "allow"

# tier 2 heuristic analyzer (v0.2+). uncomment to tune.
# sensitivity:  low (fewer FPs, misses more) / medium (default) / high (catches more, more FPs)
# window_size:  how many recent tool calls the ring buffer retains (default: 50)
#
# [heuristic]
# sensitivity = "medium"
# window_size = 50
# block_on_high_confidence = true

# deny rules - evaluated first, in order. first match wins.

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
pattern = "~/.npmrc"
action = "block"
reason = "npm token file"

[[deny.paths]]
pattern = "~/.pypirc"
action = "block"
reason = "PyPI credential file"

[[deny.paths]]
pattern = "~/.kube/config"
action = "block"
reason = "Kubernetes config"

[[deny.paths]]
pattern = "~/.docker/config.json"
action = "block"
reason = "Docker registry auth config"

[[deny.paths]]
pattern = "~/.vault-token"
action = "block"
reason = "Vault token file"

[[deny.paths]]
pattern = "~/.config/gcloud/**"
action = "block"
reason = "GCP credential config"

[[deny.paths]]
pattern = "~/.azure/**"
action = "block"
reason = "Azure credential config"

[[deny.paths]]
pattern = "~/.netrc"
action = "block"
reason = "netrc credential file"

[[deny.paths]]
pattern = "/etc/passwd"
action = "block"
reason = "system password file"

[[deny.paths]]
pattern = "/etc/shadow"
action = "block"
reason = "system shadow password file"

[[deny.paths]]
pattern = "*/.env"
action = "warn"
reason = "environment file may contain secrets"

[[deny.paths]]
pattern = "*/.env.*"
action = "warn"
reason = "environment file may contain secrets"

[[deny.paths]]
pattern = "*/.claude/settings.json"
action = "warn"
reason = "AI agent hook config edit"

[[deny.paths]]
pattern = "*/.claude/setup.mjs"
action = "warn"
reason = "AI agent loader path"

[[deny.paths]]
pattern = "*/.claude/execution.js"
action = "warn"
reason = "AI agent execution shim"

[[deny.paths]]
pattern = "*/.vscode/tasks.json"
action = "warn"
reason = "VS Code task persistence surface"

[[deny.paths]]
pattern = "*/.vscode/setup.mjs"
action = "warn"
reason = "VS Code loader path"

[[deny.paths]]
pattern = "*/.continue/**"
action = "warn"
reason = "Continue config or prompt surface"

[[deny.paths]]
pattern = "*/.cursor/**"
action = "warn"
reason = "Cursor config or rule surface"

[[deny.paths]]
pattern = "*/.codex/**"
action = "warn"
reason = "Codex local config surface"

[[deny.paths]]
pattern = "*/.github/workflows/**"
action = "warn"
reason = "CI workflow edit"

[[deny.commands]]
pattern = 'rm\s+-rf\s+/(\s|$|[^~])'
action = "block"
reason = "recursive root deletion"

[[deny.commands]]
pattern = 'rm\s+-rf\s+~/\.(ssh|aws|gnupg|config|netrc)'
action = "block"
reason = "recursive deletion of credential directory"

[[deny.commands]]
pattern = 'curl\s+.*\|\s*.*sh'
action = "block"
reason = "pipe to shell execution"

[[deny.commands]]
pattern = 'wget\s+.*\|\s*.*sh'
action = "block"
reason = "pipe to shell execution"

[[deny.commands]]
pattern = '(npm|pnpm|yarn|bun)\s+(install|add|ci).*(curl|wget|bunx|node\s+setup\.mjs)'
action = "block"
reason = "package manager bootstrap of remote loader"

[[deny.commands]]
pattern = 'bun(\s+install|\s+add|\s+x).*(https?://|setup\.mjs)'
action = "block"
reason = "bun loader bootstrap"

[[deny.commands]]
pattern = 'curl\s+.*@~?/?\.?(ssh|aws|gnupg|netrc|config)'
action = "block"
reason = "curl exfiltration of credential file"

[[deny.commands]]
pattern = 'curl\s+.*@/etc/(passwd|shadow)'
action = "block"
reason = "curl exfiltration of system file"

[[deny.commands]]
pattern = 'env\s*\|\s*grep\s+-i?\s*(key|secret|token|pass|auth)'
action = "block"
reason = "environment variable exfiltration"

[[deny.commands]]
pattern = 'gh\s+auth\s+token'
action = "block"
reason = "GitHub auth token disclosure"

[[deny.commands]]
pattern = '(169\.254\.169\.254|metadata\.google\.internal|metadata/instance)'
action = "block"
reason = "cloud metadata credential access"

[[deny.commands]]
pattern = 'find\s+/\s.*-name.*(credentials|id_rsa|\.pem|\.key).*'
action = "block"
reason = "filesystem scan for credential files"

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

# allow rules - if present, paths not matching any allow rule get the default action.
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
