// generic pty proxy adapter for agents with NO tool-call hook at all.
// not the path for most agents: sentinel hooks structured tool calls directly
// via per-agent adapters (see `evaluate --agent`). a pty proxy would see only
// terminal bytes, not structured tool calls, so it cannot enforce policy the way
// the hook adapters do — which is why it stays unbuilt.

pub fn run_wrap(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("sentinel wrap (generic pty proxy) is not implemented.");
    eprintln!();
    eprintln!("most agents don't need it — sentinel hooks tool calls directly:");
    eprintln!("  Claude Code:               sentinel install");
    eprintln!("  Codex / Gemini / Crush:    sentinel install --agent <name>  (prints the hook config)");
    eprintln!("  any command-hook agent:    sentinel evaluate --agent generic");
    eprintln!();
    eprintln!("a pty proxy only helps an agent with no tool-call hook at all, and even");
    eprintln!("then it sees terminal bytes, not structured calls — so it can't enforce");
    eprintln!("policy the way the adapters do. tracked, not yet built.");
    std::process::exit(1);
}
