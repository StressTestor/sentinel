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
    Evaluate,

    /// wrap an agent process in a pty proxy (generic adapter)
    Wrap(WrapArgs),

    /// fetch latest attack corpus
    #[command(name = "corpus-update")]
    CorpusUpdate,

    /// show current config, active hooks, policy summary
    Status,
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
    /// start in enforce mode instead of audit mode
    #[arg(long, default_value_t = false)]
    pub enforce: bool,
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
