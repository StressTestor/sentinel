mod audit;
mod audit_trail;
#[allow(dead_code)]
mod classifier;
mod cli;
mod common;
mod corpus;
mod evaluate;
#[allow(dead_code)]
mod heuristic;
mod install;
mod policy;
mod wrap;

use clap::Parser;
use cli::{Cli, Command};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Audit(args) => audit::run(args).await,
        Command::Install(args) => {
            install::run_install(args.enforce)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        }
        Command::Uninstall => {
            install::run_uninstall()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        }
        Command::Evaluate => evaluate::run(),
        Command::Wrap(args) => wrap::run_wrap(&args.agent_command),
        Command::CorpusUpdate => {
            println!("sentinel corpus update — not yet implemented");
            println!("for now, manually update ~/.sentinel/corpus/core/");
            Ok(())
        }
        Command::Status => run_status(),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run_status() -> Result<(), Box<dyn std::error::Error>> {
    println!("sentinel v{}", env!("CARGO_PKG_VERSION"));
    println!();

    // check if installed
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let settings_path = format!("{home}/.claude/settings.json");
    let policy_path = format!("{home}/.sentinel/policy.toml");
    let audit_path = format!("{home}/.sentinel/audit.jsonl");

    if std::path::Path::new(&settings_path).exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        if content.contains("sentinel evaluate") {
            println!("hooks:   installed (PreToolUse in ~/.claude/settings.json)");
        } else {
            println!("hooks:   not installed (run 'sentinel install')");
        }
    } else {
        println!("hooks:   not installed (no ~/.claude/settings.json)");
    }

    if std::path::Path::new(&policy_path).exists() {
        let content = std::fs::read_to_string(&policy_path)?;
        if content.contains("mode = \"enforce\"") {
            println!("policy:  {} (enforce mode)", policy_path);
        } else {
            println!("policy:  {} (audit mode)", policy_path);
        }
    } else {
        println!("policy:  not configured (run 'sentinel install')");
    }

    if std::path::Path::new(&audit_path).exists() {
        let line_count = std::fs::read_to_string(&audit_path)?
            .lines()
            .count();
        println!("audit:   {} events logged", line_count);
    } else {
        println!("audit:   no events yet");
    }

    Ok(())
}
