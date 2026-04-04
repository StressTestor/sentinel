pub mod report;
pub mod runner;
pub mod sandbox;

use crate::cli::AuditArgs;
use crate::corpus;

pub async fn run(args: AuditArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("sentinel audit v{}", env!("CARGO_PKG_VERSION"));
    println!();

    // resolve corpus path
    let corpus_path = corpus::resolve_corpus_path(args.corpus.as_deref());
    let sequences = corpus::load_corpus(&corpus_path)?;

    println!("loaded {} attack sequences", sequences.len());
    println!("agent: {:?}", args.agent);

    // detect sandbox
    let sandbox = sandbox::detect_sandbox(args.sandbox)?;
    println!("sandbox: {}", sandbox.name());

    // run attacks
    let results = runner::run_attacks(&sequences, &*sandbox).await?;

    // generate report
    let report = report::build_report(
        &format!("{:?}", args.agent),
        sequences.len(),
        results,
    );

    // output
    match args.format {
        crate::cli::OutputFormat::Terminal => report::print_terminal(&report),
        crate::cli::OutputFormat::Json => report::print_json(&report)?,
    }

    if let Some(path) = args.output {
        report::write_json(&report, &path)?;
        println!("\nreport written to {}", path.display());
    }

    Ok(())
}
