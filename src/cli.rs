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
    /// run attack corpus against an agent in a sandbox
    Audit(AuditArgs),

    /// install sentinel hooks into Claude Code + write default policy
    Install(InstallArgs),

    /// remove sentinel hooks from Claude Code
    Uninstall,

    /// evaluate a tool call against the policy (called by the PreToolUse hook)
    Evaluate(EvaluateArgs),

    /// scan a tool RESULT for secret shapes (called by the PostToolUse hook; detection only)
    #[command(name = "post-evaluate")]
    PostEvaluate,

    /// wrap an agent process in a pty proxy (generic adapter)
    Wrap(WrapArgs),

    /// fetch latest attack corpus
    #[command(name = "corpus-update")]
    CorpusUpdate,

    /// show current config, active hooks, policy summary
    Status,

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
}

#[derive(clap::Args, Debug)]
pub struct EvaluateArgs {
    /// canary/dry-run for `sentinel doctor`: run the full decision path and report
    /// the would-be decision (deny JSON even in audit mode) WITHOUT writing to the
    /// audit trail. not for use as the live hook command.
    #[arg(long, default_value_t = false)]
    pub canary: bool,
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
pub struct DoctorArgs {
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

    /// path to attack corpus directory
    #[arg(long)]
    pub corpus: Option<PathBuf>,

    /// sandbox backend to use (auto-detects if not specified)
    #[arg(long)]
    pub sandbox: Option<SandboxType>,

    /// output format
    #[arg(long, default_value = "terminal")]
    pub format: OutputFormat,

    /// write JSON report to file
    #[arg(long)]
    pub output: Option<PathBuf>,
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
}

#[derive(clap::Args, Debug)]
pub struct WrapArgs {
    /// command to wrap (e.g., "claude" or "codex")
    #[arg(trailing_var_arg = true)]
    pub agent_command: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum AgentType {
    Claude,
    Codex,
    Openhands,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum SandboxType {
    Docker,
    #[cfg(target_os = "linux")]
    Nsjail,
    #[cfg(target_os = "macos")]
    MacosSandbox,
    Degraded,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Terminal,
    Json,
}
