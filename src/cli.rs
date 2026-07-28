use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sentinel", about = "runtime defense for CLI AI agents")]
#[command(version, propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// run the versioned attack corpus against a real agent
    Audit(AuditArgs),

    /// install Sentinel hooks into Claude Code or Codex + write default policy
    Install(InstallArgs),

    /// remove direct Sentinel hooks from one host agent
    Uninstall(UninstallArgs),

    /// evaluate a tool call against the policy (called by the PreToolUse hook)
    Evaluate(EvaluateArgs),

    /// scan a tool RESULT for secret shapes (called by the PostToolUse hook; detection only)
    #[command(name = "post-evaluate")]
    PostEvaluate,

    /// show current config, active hooks, policy summary
    Status(StatusArgs),

    /// dry-run a tool call against the policy and explain the decision (no execution, no logging)
    Check(CheckArgs),

    /// replay a pinned set of attacks through the policy and assert each is caught (CI gate)
    Verify(VerifyArgs),

    /// validate the full install chain (hook, binary, policy) and probe liveness
    Doctor(DoctorArgs),

    /// show which bundled-default rules are missing from your policy (read-only)
    #[command(name = "policy-diff")]
    PolicyDiff(PolicyDiffArgs),

    /// static-check a policy for dead rules, invalid regexes, and over-broad allows
    #[command(name = "policy-lint")]
    PolicyLint(LintArgs),

    /// safely migrate a published Sentinel policy to the current bundled revision
    #[command(name = "policy-migrate")]
    PolicyMigrate(PolicyMigrateArgs),

    /// discover MCP server configuration and compare it with an explicit trust baseline
    #[command(name = "audit-mcp")]
    AuditMcp(AuditMcpArgs),
}

#[derive(clap::Args, Debug)]
pub struct AuditMcpArgs {
    /// emit the server list + findings as JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// explicitly accept the current discovered server set as the trusted baseline
    #[arg(long, default_value_t = false)]
    pub update: bool,

    /// exit non-zero if any new or changed server is found (for CI / scheduled checks)
    #[arg(long, default_value_t = false)]
    pub strict: bool,
}

#[derive(clap::Args, Debug)]
pub struct EvaluateArgs {
    /// canary/dry-run for `sentinel doctor`: run the full decision path and report
    /// the would-be decision (deny JSON even in audit mode) WITHOUT writing to the
    /// audit trail. not for use as the live hook command.
    #[arg(long, default_value_t = false)]
    pub canary: bool,

    /// host agent whose decision format to emit. `claude-code` (default) replies
    /// with the nested PreToolUse hookSpecificOutput JSON; `generic` replies with
    /// a simple `{"decision":"block","reason":...}` and relies on exit code 2.
    /// Both signal a block via exit 2, so any agent honoring exit codes is covered.
    #[arg(long, default_value = "claude-code")]
    pub agent: String,
}

#[derive(clap::Args, Debug)]
pub struct LintArgs {
    /// lint a specific policy file instead of the installed ~/.sentinel/policy.toml
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct PolicyDiffArgs {
    /// diff a specific policy file instead of the installed ~/.sentinel/policy.toml
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("migration_action")
        .required(true)
        .multiple(false)
        .args(["check", "apply"])
))]
pub struct PolicyMigrateArgs {
    /// report whether migration is needed without writing; exits non-zero when needed
    #[arg(long, default_value_t = false)]
    pub check: bool,

    /// migrate atomically after creating a backup and validating the result
    #[arg(long, default_value_t = false)]
    pub apply: bool,

    /// migrate a specific policy instead of ~/.sentinel/policy.toml
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct DoctorArgs {
    /// host agent whose install chain to inspect
    #[arg(long, default_value = "claude-code")]
    pub agent: String,

    /// exit non-zero if any check fails (for use as a CI/cron gate)
    #[arg(long, default_value_t = false)]
    pub strict: bool,

    /// emit a JSON report instead of human-readable output
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    /// verify a specific policy file instead of the bundled default policy
    #[arg(long)]
    pub policy: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct CheckArgs {
    /// the PreToolUse hook JSON to evaluate, e.g. '{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}'
    /// (if omitted and --file is not given, reads from stdin)
    pub input: Option<String>,

    /// read the hook JSON from a file instead of an argument
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// emit a stable JSON result instead of human-readable output
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(clap::Args, Debug)]
pub struct AuditArgs {
    /// agent runtime to audit
    #[arg(long, default_value = "claude")]
    pub agent: AgentType,

    /// path to a reviewed attack corpus directory (defaults to the bundled versioned corpus)
    #[arg(long)]
    pub corpus: Option<PathBuf>,

    /// output format
    #[arg(long, default_value = "terminal")]
    pub format: OutputFormat,

    /// write JSON report to file
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// DANGEROUS: allow the audited agent to run tools directly on this host without containment
    #[arg(long, default_value_t = false)]
    pub unsafe_host: bool,

    /// maximum seconds allowed for each agent turn
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_seconds: u64,
}

#[derive(clap::Args, Debug)]
pub struct InstallArgs {
    /// install in AUDIT mode (log only, never block). The default is ENFORCE -
    /// a security tool that ships disabled protects nobody.
    #[arg(long, default_value_t = false)]
    pub audit: bool,

    /// deprecated: enforce is now the default. Accepted for back-compat, no effect.
    #[arg(long, default_value_t = false, hide = true)]
    pub enforce: bool,

    /// also register the PostToolUse result-scan hook (detection-only, opt-in):
    /// flags secret shapes that land in a tool RESULT. higher-FP than the policy
    /// layer, so it is off by default.
    #[arg(long = "result-scan", default_value_t = false)]
    pub result_scan: bool,

    /// host agent to install for. `claude-code` (default) and `codex` are managed
    /// natively; any other name prints the generic integration contract and
    /// writes the default policy.
    #[arg(long, default_value = "claude-code")]
    pub agent: String,
}

#[derive(clap::Args, Debug)]
pub struct UninstallArgs {
    /// host agent to uninstall from (`claude-code` or `codex`)
    #[arg(long, default_value = "claude-code")]
    pub agent: String,
}

#[derive(clap::Args, Debug)]
pub struct StatusArgs {
    /// host agent whose install state to report
    #[arg(long, default_value = "claude-code")]
    pub agent: String,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum AgentType {
    Claude,
    Codex,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Json,
}
