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
pattern = "~/.netrc"
action = "block"
reason = "netrc credential file"

[[deny.paths]]
pattern = "/etc/passwd"
action = "block"
reason = "system password file"

[[deny.paths]]
pattern = "/etc/shadow*"
action = "block"
reason = "system shadow password file (incl. backups like /etc/shadow-)"

[[deny.paths]]
pattern = "/etc/master.passwd"
action = "block"
reason = "macOS shadowed password hashes"

[[deny.paths]]
pattern = "/proc/*/environ"
action = "block"
reason = "process environment (env-var exfil via file read)"

[[deny.paths]]
pattern = "*/.env"
action = "warn"
reason = "environment file may contain secrets"

[[deny.paths]]
pattern = "*/.env.*"
action = "warn"
reason = "environment file may contain secrets"

[[deny.commands]]
pattern = 'rm\s+-rf\s+/(\s|$|[^~])'
action = "block"
reason = "recursive root deletion"

[[deny.commands]]
pattern = 'rm\s+-rf\s+~/\.(ssh|aws|gnupg|config|netrc)'
action = "block"
reason = "recursive deletion of credential directory"

[[deny.commands]]
pattern = '\b(curl|wget|fetch)\b[^|]*\|\s*[a-z/]*sh\b'
action = "block"
reason = "pipe to shell execution"

[[deny.commands]]
pattern = '<\(\s*(curl|wget|fetch)\b'
action = "block"
reason = "process substitution of a remote fetch into a shell"

[[deny.commands]]
pattern = '\$\(\s*(curl|wget|fetch)\b'
action = "block"
reason = "command substitution of a remote fetch"

[[deny.commands]]
pattern = '\b(curl|wget|fetch)\b.*-[oO]\b.*[;&|].*\b(ba|z|da)?sh\b'
action = "block"
reason = "staged fetch-then-run (download then execute)"

[[deny.commands]]
pattern = 'base64\s+-{{1,2}}d\w*\b.*\|\s*[a-z/]*sh\b'
action = "block"
reason = "base64-decode piped to shell"

[[deny.commands]]
pattern = '\b(python3?|perl|ruby|node|php|osascript)\b\s+-\w*[ce]\b.*(urllib|requests|socket|httplib|http\.client|net/http|open-uri|os\.system|\bexec\b|\beval\b|popen|subprocess|child_process)'
action = "block"
reason = "interpreter fetch-exec / inline remote code execution"

[[deny.commands]]
pattern = '`\s*(curl|wget|fetch)\b'
action = "block"
reason = "backtick substitution of a remote fetch"

[[deny.commands]]
pattern = 'curl\s+.*@~?/?\.?(ssh|aws|gnupg|netrc|config)'
action = "block"
reason = "curl exfiltration of credential file"

[[deny.commands]]
pattern = 'curl\s+.*@/etc/(passwd|shadow|master\.passwd)'
action = "block"
reason = "curl exfiltration of system file"

[[deny.commands]]
pattern = '(?i)\b(env|printenv|set|export|declare)\b\s*\|\s*grep\b.*(key|secret|token|pass|auth|aws|gcp|azure|cred|api|access|private)'
action = "block"
reason = "environment variable exfiltration"

[[deny.commands]]
pattern = '\bfind\b\s+(/|~|\$HOME|\.)\S*.*-i?name\b.*(credentials|id_rsa|id_ed25519|id_ecdsa|authorized_keys|\.pem|\.key|\.gpg|\.kdbx)'
action = "block"
reason = "filesystem scan for credential files"

[[deny.commands]]
pattern = '\b(locate|mdfind)\b.*(credentials|id_rsa|id_ed25519|id_ecdsa|authorized_keys|\.pem|secring|\.kdbx)'
action = "block"
reason = "credential filesystem scan via locate/mdfind"

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
