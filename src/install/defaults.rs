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

# --- shai-hulud / Miasma agent-side hardening: self-protect + credential coverage ---
# Everything below fires only on the AGENT's own tool calls. The supply-chain worms
# in this family run their real payload inside npm/pip lifecycle-script CHILD
# processes, which never traverse the PreToolUse hook - Sentinel cannot see that.
# These rules cover the prompt-injection-drives-the-agent variant of the same TTPs,
# not the worm self-propagating. See README "what this does and doesn't catch".

# self-protect: a prompt-injected agent must not be able to weaken Sentinel's own
# policy. Only the agent's tool-call writes are blocked - your own
# `vim ~/.sentinel/policy.toml` and `sentinel install` (writes via std::fs, not a
# tool call) are unaffected. Reconfigure outside the guarded session. This raises
# the cost of the obvious disarm; a path built from a shell variable or written by
# a subprocess can still get through.
[[deny.paths]]
pattern = "~/.sentinel/policy.toml"
action = "block"
reason = "Sentinel's own enforcement policy - agent writes blocked so an injected agent can't disable the guard mid-session (reconfigure outside the agent)"

[[deny.paths]]
pattern = "~/.npmrc"
action = "block"
reason = "npm auth token (.npmrc holds _authToken)"

[[deny.paths]]
pattern = "~/.kube/config"
action = "block"
reason = "kubeconfig cluster credentials (default location)"

[[deny.paths]]
pattern = "~/.config/gcloud/*"
action = "block"
reason = "gcloud credentials (application_default_credentials.json, legacy_credentials)"

[[deny.paths]]
pattern = "~/.azure/*"
action = "block"
reason = "Azure CLI tokens (accessTokens.json / msal cache)"

[[deny.paths]]
pattern = "*/.env"
action = "warn"
reason = "environment file may contain secrets"

[[deny.paths]]
pattern = "*/.env.*"
action = "warn"
reason = "environment file may contain secrets"

# agent-config / persistence tripwires - warn, not block: developers legitimately
# edit these via an agent, so blocking would be a false positive. They surface a
# write for review without breaking normal config work.
[[deny.paths]]
pattern = "**/.claude/settings.json"
action = "warn"
reason = "agent write to Claude Code settings (hook/permission surface) - review for unexpected changes"

[[deny.paths]]
pattern = "**/.claude/settings.local.json"
action = "warn"
reason = "agent write to Claude Code local settings (hook/permission surface) - review for unexpected changes"

[[deny.paths]]
pattern = "~/.codex/*"
action = "warn"
reason = "agent write to Codex CLI config - review for unexpected changes"

[[deny.paths]]
pattern = "~/.gemini/*"
action = "warn"
reason = "agent write to Gemini CLI config - review for unexpected changes"

[[deny.paths]]
pattern = "**/.vscode/tasks.json"
action = "warn"
reason = "agent write to VS Code tasks.json (auto-run-on-open surface) - review for unexpected changes"

# warn (not block): matches any path ending in `kubeconfig` (a project-local
# `kubeconfig`, `admin.kubeconfig`, etc.) - a common kind/k3s/eks convention that
# developers read and edit, so blocking would be a false positive. Mirrors the
# */.env warn posture. The default-location ~/.kube/config IS a clean block above.
[[deny.paths]]
pattern = "**/kubeconfig"
action = "warn"
reason = "possible kubeconfig cluster credentials - review before access"

[[deny.paths]]
pattern = "~/Library/LaunchAgents/*.plist"
action = "warn"
reason = "agent writes a macOS user LaunchAgent (login-persistence unit) - review; devs also script launchd agents"

[[deny.paths]]
pattern = "~/.config/systemd/user/*.service"
action = "warn"
reason = "agent writes a systemd user service (login-persistence unit) - review; devs also script user units"

[[deny.commands]]
pattern = 'rm\s+-rf\s+/(\s|$|[^~])'
action = "block"
reason = "recursive root deletion"

[[deny.commands]]
pattern = 'rm\s+-rf\s+~/\.(ssh|aws|gnupg|config|netrc)'
action = "block"
reason = "recursive deletion of credential directory"

[[deny.commands]]
pattern = 'rm\s+-rf\s+(~|\$HOME)/?(\s|$)'
action = "block"
reason = "recursive deletion of the entire home directory"

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
pattern = '\b(env|printenv|set|export|declare)\b\s*\|\s*(curl|wget|nc|ncat|telnet|fetch)\b'
action = "block"
reason = "environment piped straight to the network (exfiltration)"

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

# agent-driven self-propagation tripwires - warn: these also fire on every
# legitimate release / repo creation, so they surface for review rather than block.
[[deny.commands]]
pattern = '\b(npm|pnpm|yarn|bun)\s+(-\S+\s+)*publish\b'
action = "warn"
reason = "agent invoked a package `publish` - could be a propagation/dead-drop step; also fires on every legitimate release"

[[deny.commands]]
pattern = '\bnpm\s+token\s+(create|revoke)\b'
action = "warn"
reason = "agent created/revoked an npm token - could be propagation credential setup; also fires on legit token management"

[[deny.commands]]
pattern = '\bgh\s+repo\s+create\b.*(--public(?:\s|$)|--visibility[= ]public\b)'
action = "warn"
reason = "agent invoked `gh repo create --public` - could host a payload / dead-drop; also fires on legit public-repo creation"

[[deny.secrets]]
pattern = '\b(AKIA|ASIA)[0-9A-Z]{{16}}\b'
action = "block"
reason = "AWS access key ID (long-term AKIA + temporary ASIA)"

[[deny.secrets]]
pattern = '(gh[posru]_[A-Za-z0-9]{{36,}}|github_pat_[A-Za-z0-9_]{{40,}})'
action = "block"
reason = "GitHub token (classic or fine-grained PAT)"

[[deny.secrets]]
pattern = '\bsk-(ant-)?[A-Za-z0-9_-]{{20,}}'
action = "block"
reason = "OpenAI / Anthropic API key"

[[deny.secrets]]
pattern = 'npm_[A-Za-z0-9]{{36}}'
action = "block"
reason = "npm access token"

[[deny.secrets]]
pattern = '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
action = "block"
reason = "private key material"

# credential-content coverage expansion - high-confidence secret formats (block).
# MUST stay AFTER the private-key rule above: a GCP service-account file matches
# both the private-key rule (block) and the gcp_sa rule below (warn); first match
# wins, so the private key has to be reached first or it silently downgrades.
# Also note deny.paths is evaluated before deny.secrets: a secret written INTO a
# warn-tier path (e.g. ~/.claude/settings.json) returns warn, not block - the path
# rule matches first. This is intended and mirrors the existing */.env behavior.
[[deny.secrets]]
pattern = 'AccountKey=[A-Za-z0-9+/]{{86}}=='
action = "block"
reason = "Azure Storage account key in a connection string"

[[deny.secrets]]
pattern = 'SharedAccessKey=[A-Za-z0-9+/]{{40,}}='
action = "block"
reason = "Azure Service Bus / Event Hubs SAS key in a connection string"

[[deny.secrets]]
pattern = 'client-key-data:\s*[A-Za-z0-9+/]{{200,}}={{0,2}}'
action = "block"
reason = "kubeconfig client private key (base64 client-key-data)"

# lower-confidence credential signatures - warn, not block, so they don't
# false-block ordinary code (e.g. a public referer-restricted API key, or an
# `hvs.<ident>` member access in Vault-integration code).
[[deny.secrets]]
pattern = '(?i)private_key_id.*@[a-z0-9.-]+\.gserviceaccount\.com'
action = "warn"
reason = "content resembles a GCP service-account key file (private_key_id + gserviceaccount.com)"

[[deny.secrets]]
pattern = '\bAIza[0-9A-Za-z_-]{{35}}\b'
action = "warn"
reason = "Google API key in written content (may be a referer-restricted public client key)"

[[deny.secrets]]
pattern = '\bhvs\.[A-Za-z0-9_-]{{24,}}'
action = "warn"
reason = "possible HashiCorp Vault service token (hvs.) - also appears as member access in Vault-integration code"

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::parse_policy;
    use crate::policy::{Action, PolicyEngine, ToolCall};

    // These tests exercise the ACTUAL generated default policy end-to-end through
    // the real PolicyEngine::evaluate. The per-rule matcher semantics are covered
    // by unit tests in policy/matcher.rs; what's verified HERE is the assembled
    // file - rule ordering, cross-rule shadowing, and tier (block vs warn) - which
    // is exactly where a single-rule view can't catch a regression.

    fn engine() -> PolicyEngine {
        let cfg = parse_policy(&default_policy_content("enforce"))
            .expect("the generated default policy must parse");
        PolicyEngine::from_config(cfg)
    }

    fn path_call(path: &str) -> ToolCall {
        ToolCall {
            tool_name: "Write".into(),
            command: None,
            paths: vec![path.into()],
            raw_params: "{}".into(),
        }
    }

    fn secret_call(raw: &str) -> ToolCall {
        ToolCall {
            tool_name: "Write".into(),
            command: None,
            paths: vec![],
            raw_params: raw.into(),
        }
    }

    // Route through the real hook extraction so a path embedded in the command
    // (e.g. `rm -f ~/.sentinel/policy.toml`) is mined into `paths` exactly as
    // production does - a direct ToolCall with empty paths would not exercise the
    // deny.paths coverage of command-borne paths.
    fn cmd_call(cmd: &str) -> ToolCall {
        let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": cmd}});
        serde_json::from_value::<crate::evaluate::hook_schema::HookInput>(input)
            .expect("hook input must deserialize")
            .to_tool_call()
    }

    // A Write carries BOTH a target path and content, routed through the real
    // extraction so paths and raw_params are populated exactly as production does.
    fn write_call(path: &str, content: &str) -> ToolCall {
        let input =
            serde_json::json!({"tool_name": "Write", "tool_input": {"file_path": path, "content": content}});
        serde_json::from_value::<crate::evaluate::hook_schema::HookInput>(input)
            .expect("hook input must deserialize")
            .to_tool_call()
    }

    fn action_of(call: &ToolCall) -> Action {
        engine().evaluate(call).action
    }

    // ── self-protect: block Sentinel's own policy, allow audit-log reads ────────

    #[test]
    fn self_protect_blocks_policy_writes() {
        // ~ form is portable: pattern and candidate both expand with runtime HOME.
        assert_eq!(action_of(&path_call("~/.sentinel/policy.toml")), Action::Block);
        let decision = engine().evaluate(&path_call("~/.sentinel/policy.toml"));
        assert!(
            decision.matched_rule.unwrap().contains(".sentinel"),
            "must be attributed to the self-protect rule"
        );
        // rm of the policy file (mined from a Bash command) is the same rule
        assert_eq!(action_of(&cmd_call("rm -f ~/.sentinel/policy.toml")), Action::Block);
    }

    #[test]
    fn self_protect_does_not_block_audit_log_reads() {
        // THE skeptic-fix: reading the audit trail is the intended observability
        // workflow - narrowing the block to policy.toml must leave it allowed.
        assert_eq!(action_of(&path_call("~/.sentinel/audit.jsonl")), Action::Allow);
    }

    #[test]
    fn self_protect_does_not_overmatch_siblings() {
        assert_eq!(action_of(&path_call("~/.sentinelrc")), Action::Allow);
    }

    // ── cred-content ordering: a GCP SA file must BLOCK via the pre-existing pem
    //    rule, NOT downgrade to the gcp_sa warn rule appended after it ───────────

    #[test]
    fn gcp_service_account_file_blocks_via_private_key_rule() {
        let sa = r#"{"type":"service_account","private_key_id":"abc","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----\n","client_email":"svc@proj.iam.gserviceaccount.com"}"#;
        let decision = engine().evaluate(&secret_call(sa));
        assert_eq!(decision.action, Action::Block, "SA file carries a private key → must block");
        assert!(
            decision.matched_rule.unwrap().contains("PRIVATE KEY"),
            "must be the private-key block rule, not the gcp_sa warn rule (ordering guard)"
        );
    }

    #[test]
    fn gcp_sa_reference_without_key_warns() {
        // a reference that resembles an SA file but carries no private key body
        // falls through to the gcp_sa WARN rule - proves the warn rule works and
        // is only shadowed by pem when an actual key is present.
        let ref_only = r#"{"private_key_id":"abc","client_email":"svc@proj.iam.gserviceaccount.com"}"#;
        assert_eq!(action_of(&secret_call(ref_only)), Action::Warn);
    }

    // ── credential-content blocks (high-confidence formats) ─────────────────────

    #[test]
    fn azure_keys_block() {
        let acct = format!("DefaultEndpointsProtocol=https;AccountKey={}==;", "A".repeat(86));
        assert_eq!(action_of(&secret_call(&acct)), Action::Block);
        let sas = format!("Endpoint=sb://x;SharedAccessKey={}=", "A".repeat(44));
        assert_eq!(action_of(&secret_call(&sas)), Action::Block);
    }

    #[test]
    fn kubeconfig_client_key_data_blocks() {
        let kube = format!("client-key-data: {}==", "A".repeat(200));
        assert_eq!(action_of(&secret_call(&kube)), Action::Block);
    }

    #[test]
    fn secret_in_ordinary_path_blocks_but_warn_path_shadows() {
        // A realistic Write carries a path AND content. deny.paths is evaluated
        // before deny.secrets, so the SAME secret resolves differently by target:
        let azure = format!("AccountKey={}==", "A".repeat(86));
        // into an ordinary file → the block secret rule fires
        assert_eq!(action_of(&write_call("./src/cfg.rs", &azure)), Action::Block);
        // into a warn-tier path → the path rule matches first → warn, not block.
        // Intended (mirrors */.env); asserting reality, not forcing it to block.
        assert_eq!(action_of(&write_call("~/.claude/settings.json", &azure)), Action::Warn);
    }

    // ── credential-content warns (lower-confidence; must not block ordinary code)

    #[test]
    fn vault_hvs_warns_not_blocks() {
        // demoted from block: `hvs.<24+ ident>` is also ordinary member access.
        let tok = format!("vault_token = hvs.{}", "A".repeat(24));
        assert_eq!(action_of(&secret_call(&tok)), Action::Warn);
        // short member access must not trip it at all
        assert_eq!(action_of(&secret_call("client.hvs.read()")), Action::Allow);
    }

    #[test]
    fn google_api_key_warns() {
        let key = format!("apiKey: AIza{}", "A".repeat(35));
        assert_eq!(action_of(&secret_call(&key)), Action::Warn);
    }

    // ── credential file paths ───────────────────────────────────────────────────

    #[test]
    fn credential_paths_block() {
        assert_eq!(action_of(&path_call("~/.npmrc")), Action::Block);
        assert_eq!(action_of(&path_call("~/.kube/config")), Action::Block);
        assert_eq!(action_of(&path_call("~/.config/gcloud/application_default_credentials.json")), Action::Block);
        assert_eq!(action_of(&path_call("~/.azure/accessTokens.json")), Action::Block);
    }

    #[test]
    fn project_local_kubeconfig_warns_not_blocks() {
        // demoted from block: a project file literally named `kubeconfig` is a
        // common kind/k3s/eks convention - mirror the shipped */.env warn posture.
        assert_eq!(action_of(&path_call("./testdata/kubeconfig")), Action::Warn);
        assert_eq!(action_of(&path_call("/Users/x/repo/charts/kubeconfig")), Action::Warn);
    }

    // ── agent-config / persistence tripwires (warn) ─────────────────────────────

    #[test]
    fn agent_config_writes_warn() {
        assert_eq!(action_of(&path_call("~/.claude/settings.json")), Action::Warn);
        assert_eq!(action_of(&path_call("./project/.claude/settings.local.json")), Action::Warn);
        assert_eq!(action_of(&path_call("~/.codex/config.toml")), Action::Warn);
        assert_eq!(action_of(&path_call("~/.gemini/settings.json")), Action::Warn);
        assert_eq!(action_of(&path_call("./repo/.vscode/tasks.json")), Action::Warn);
    }

    #[test]
    fn persistence_unit_writes_warn() {
        assert_eq!(action_of(&path_call("~/Library/LaunchAgents/com.evil.agent.plist")), Action::Warn);
        assert_eq!(action_of(&path_call("~/.config/systemd/user/evil.service")), Action::Warn);
    }

    // ── self-propagation command tripwires (warn) - incl. the pnpm -r form ──────

    #[test]
    fn publish_commands_warn_including_monorepo_forms() {
        assert_eq!(action_of(&cmd_call("npm publish")), Action::Warn);
        assert_eq!(action_of(&cmd_call("pnpm -r publish")), Action::Warn);
        assert_eq!(action_of(&cmd_call("pnpm --filter=x publish")), Action::Warn);
        assert_eq!(action_of(&cmd_call("npm token create")), Action::Warn);
        assert_eq!(action_of(&cmd_call("gh repo create foo --public")), Action::Warn);
    }

    #[test]
    fn publish_regex_does_not_overmatch() {
        // the broadened (-\S+\s+)* must consume only leading FLAG tokens, not words
        assert_eq!(action_of(&cmd_call("npm run publish-docs")), Action::Allow);
        assert_eq!(action_of(&cmd_call("npm run publish")), Action::Allow);
        assert_eq!(action_of(&cmd_call("yarn workspace foo publish")), Action::Allow);
        assert_eq!(action_of(&cmd_call("npm install left-pad")), Action::Allow);
        assert_eq!(action_of(&cmd_call("gh repo create foo --private")), Action::Allow);
        assert_eq!(action_of(&cmd_call("gh repo clone foo")), Action::Allow);
    }

    // ── zero-FP baselines: everyday dev actions sail through ────────────────────

    #[test]
    fn ordinary_actions_allowed() {
        assert_eq!(action_of(&path_call("./src/main.rs")), Action::Allow);
        assert_eq!(action_of(&path_call("~/.kube/notes.md")), Action::Allow);
        assert_eq!(action_of(&cmd_call("cargo build --release")), Action::Allow);
    }
}
