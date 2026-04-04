// generic pty proxy adapter for agents without native hook systems.
// fallback adapter — Claude Code uses PreToolUse hooks instead.
// implementation deferred until a second agent runtime is prioritized.

pub fn run_wrap(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("sentinel wrap is not yet implemented.");
    eprintln!("use 'sentinel install' for Claude Code (PreToolUse hook adapter).");
    eprintln!("pty proxy for generic agents is coming in a future release.");
    std::process::exit(1);
}
