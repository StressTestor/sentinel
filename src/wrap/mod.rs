/// generic pty proxy adapter for agents without native hook systems.
/// wraps the agent process in a pseudo-terminal, intercepts shell commands
/// before execution, and applies the policy engine.
///
/// this is the fallback adapter. the Claude Code adapter uses PreToolUse hooks
/// instead (faster, more precise, structured JSON). the pty proxy is for
/// OpenHands, custom agents, and any terminal-based tool without a hook system.
///
/// implementation deferred — the pty proxy requires:
/// - portable-pty for terminal allocation
/// - byte stream parsing to identify command boundaries
/// - SIGWINCH forwarding for terminal resize
/// - raw mode passthrough for interactive sessions
///
/// the Claude Code PreToolUse hook adapter covers the primary use case.
/// pty proxy ships when a second agent runtime is prioritized.

pub fn run_wrap(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("sentinel wrap is not yet implemented.");
    eprintln!("use 'sentinel install' for Claude Code (PreToolUse hook adapter).");
    eprintln!("pty proxy for generic agents is coming in a future release.");
    std::process::exit(1);
}
