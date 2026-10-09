use clap::Parser;
use sentinel_guard::cli::{Cli, Command, PolicyAction};
use sentinel_guard::{
    audit, audit_mcp, check, common, doctor, evaluate, install, lint, policy, policy_diff,
    policy_migrate, post_evaluate, session_check, verify, why,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        // Several commands expose machine-readable stdout contracts (hook
        // decisions and `--json`). Diagnostics must never corrupt those
        // streams, even when RUST_LOG enables warnings or debug output.
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Audit(args) => audit::run(args).await,
        Command::Install(args) => install::run_install(
            install::InstallOptions {
                audit: args.audit,
                result_scan: args.result_scan,
                sandbox: args.sandbox,
            },
            &args.agent,
        )
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>),
        Command::Uninstall(args) => install::run_uninstall(&args.agent)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>),
        Command::Evaluate(args) => evaluate::run(args.canary, &args.agent),
        Command::PostEvaluate => post_evaluate::run(),
        Command::Status(args) => run_status(&args.agent),
        Command::Check(args) => check::run(args),
        Command::Why(args) => why::run(args),
        Command::Verify(args) => verify::run(args),
        Command::Doctor(args) => doctor::run(args),
        Command::SessionCheck(args) => session_check::run(args),
        Command::PolicyDiff(args) => policy_diff::run(args),
        Command::PolicyLint(args) => lint::run(args),
        Command::PolicyMigrate(args) => policy_migrate::run(args),
        Command::AuditMcp(args) => audit_mcp::run(args),
        Command::Policy(args) => match args.action {
            PolicyAction::Accept(args) => policy::overlay::run_accept(args),
        },
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run_status(agent: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("sentinel v{}", env!("CARGO_PKG_VERSION"));
    println!();

    let target = install::AgentTarget::parse(agent)
        .ok_or_else(|| format!("unsupported status agent: {agent}"))?;
    let home = common::home_dir()?;
    let state = install::state::inspect_agent(target)?;
    println!("agent:    {}", target.label());
    println!("config:   {}", state.config_path.display());
    println!("hook:     {:?}", state.hook.ownership);
    println!("active:   {}", state.activation.label());
    if let Some(detail) = state.activation.detail() {
        println!("detail:   {detail}");
    }

    let policy_path = home.join(".sentinel/policy.toml");
    let audit_path = home.join(".sentinel/audit.jsonl");

    let engine = policy::PolicyEngine::load(&policy_path)
        .map_err(|error| format!("policy at {} cannot load: {error}", policy_path.display()))?;
    println!("policy:   {} ({})", policy_path.display(), engine.mode());
    for line in policy::overlay::status_lines(&engine) {
        println!("{line}");
    }

    if target == install::AgentTarget::ClaudeCode {
        match install::sandbox::bridge_status(&state.config_path, Ok(&engine))? {
            Some(bridge) => {
                println!("sandbox:  {}", install::sandbox::summary_line(&bridge));
                for (pattern, reason) in &bridge.projection.hook_only {
                    println!("          hook-only: {pattern} ({reason})");
                }
                for (pattern, reason) in &bridge.projection.withheld {
                    println!("          withheld: {pattern} ({reason})");
                }
            }
            None => {
                println!("sandbox:  bridge not installed (opt-in: `sentinel install --sandbox`)")
            }
        }
    }

    if std::path::Path::new(&audit_path).exists() {
        let line_count = std::fs::read_to_string(&audit_path)?.lines().count();
        println!("audit:    {} events logged", line_count);
    } else {
        println!("audit:    no events yet");
    }

    if !state.activation.healthy() {
        return Err(format!(
            "{} hook is configured but not proven active ({})",
            target.label(),
            state.activation.label()
        )
        .into());
    }

    Ok(())
}
