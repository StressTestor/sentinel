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
