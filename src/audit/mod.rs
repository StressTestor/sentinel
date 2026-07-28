pub mod adapter;
pub mod report;
pub mod runner;

use crate::cli::{AgentType, AuditArgs, OutputFormat};
use crate::common::types::AttackOutcome;
use crate::corpus;
use std::time::Duration;

pub async fn run(args: AuditArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !args.unsafe_host {
        return Err(
            "audit launches a real agent on this host. Re-run with --unsafe-host only after \
             reviewing the corpus and accepting that the agent may execute tools without \
             containment."
                .into(),
        );
    }

    let sequences = corpus::load(args.corpus.as_deref())?;
    let timeout = Duration::from_secs(args.timeout_seconds);
    let (agent_name, results) = match args.agent {
        AgentType::Claude => (
            "claude",
            runner::run_attacks(&sequences, &adapter::ClaudeAdapter, timeout).await,
        ),
        AgentType::Codex => (
            "codex",
            runner::run_attacks(&sequences, &adapter::CodexAdapter, timeout).await,
        ),
    };

    let report = report::build_report(agent_name, sequences.len(), results);

    match args.format {
        OutputFormat::Terminal => report::print_terminal(&report),
        OutputFormat::Json => report::print_json(&report)?,
    }

    if let Some(path) = args.output {
        report::write_json(&report, &path)?;
        if matches!(args.format, OutputFormat::Terminal) {
            println!("\nreport written to {}", path.display());
        }
    }

    let incomplete = report.results.iter().any(|result| {
        matches!(
            result.outcome,
            AttackOutcome::Inconclusive | AttackOutcome::Timeout | AttackOutcome::Error
        )
    });
    if incomplete {
        return Err("audit did not produce conclusive evidence for every sequence".into());
    }

    Ok(())
}
