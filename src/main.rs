mod audit;
mod cli;
mod common;
mod corpus;

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
        Command::Status => {
            println!("sentinel v{}", env!("CARGO_PKG_VERSION"));
            println!("status: not yet installed");
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
