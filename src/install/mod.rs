pub mod defaults;
pub mod hooks;

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InstallError {
    #[error("failed to read settings: {0}")]
    ReadError(String),
    #[error("failed to write settings: {0}")]
    WriteError(String),
    #[error("sentinel binary not found in PATH")]
    BinaryNotFound,
}

pub fn run_install(audit: bool, result_scan: bool, agent: &str) -> Result<(), InstallError> {
    // verify sentinel binary is in PATH
    let sentinel_path = which_sentinel()?;
    println!("sentinel binary: {}", sentinel_path.display());

    // Non-Claude-Code agents: sentinel can't auto-configure an arbitrary agent's
    // hook system, so print the generic integration contract and write the policy.
    if agent != "claude-code" {
        return install_generic(&sentinel_path, audit, agent);
    }

    // install hooks into ~/.claude/settings.json
    let settings_path = claude_settings_path();
    hooks::install_hook(&settings_path, &sentinel_path)?;
    println!("installed PreToolUse hook in {}", settings_path.display());

    // opt-in: register the PostToolUse result-scan hook (detection only)
    if result_scan {
        hooks::install_post_hook(&settings_path, &sentinel_path)?;
        println!("installed PostToolUse result-scan hook (detection only)");
    }

    // write default policy. ENFORCE is the default: a security tool that ships in
    // log-only mode protects nobody, and the most direct attack on a guard you
    // can disable is to just leave it disabled. `--audit` opts back into log-only.
    let policy_path = sentinel_dir().join("policy.toml");
    let mode = if audit { "audit" } else { "enforce" };
    let wrote = defaults::write_default_policy(&policy_path, mode)?;

    if wrote {
        println!("wrote default policy to {}", policy_path.display());
        println!("mode: {mode}");
        println!();
        if audit {
            println!("sentinel is in AUDIT mode - logging what WOULD be blocked, but NOT blocking.");
            println!("to enforce: re-run `sentinel install` (enforce is the default),");
            println!("or set mode = \"enforce\" in ~/.sentinel/policy.toml");
        } else {
            println!("sentinel is ENFORCING - tool calls that match a block rule are denied.");
            println!("if a rule is too strict, set mode = \"audit\" in ~/.sentinel/policy.toml");
            println!("(or reinstall with --audit) and tune it.");
        }
    } else {
        // write_default_policy skips an existing file: do NOT claim a mode we did
        // not set. An existing audit-mode user upgrading is NOT silently flipped.
        println!("existing policy preserved at {} (mode unchanged).", policy_path.display());
        println!("run `sentinel status` to see the active mode; edit the policy to change it.");
    }

    println!();
    println!("done. sentinel is now active.");

    Ok(())
}

/// Print the generic integration contract for an agent sentinel can't
/// auto-configure, and write the default policy so the engine has rules. The
/// engine is agent-agnostic; any agent that runs a command hook and honors exit
/// codes can drive it via `sentinel evaluate --agent generic`.
fn install_generic(sentinel_path: &Path, audit: bool, agent: &str) -> Result<(), InstallError> {
    let policy_path = sentinel_dir().join("policy.toml");
    let mode = if audit { "audit" } else { "enforce" };
    defaults::write_default_policy(&policy_path, mode)?;
    let bin = sentinel_path.display();

    // Per-agent integration snippets. These are printed (not auto-written): the
    // engine is verified, but each agent's config format is not live-tested here,
    // so the user pastes a known-good snippet rather than risk a corrupted config.
    println!();
    match agent {
        "codex" => {
            println!("OpenAI Codex CLI — add to ~/.codex/config.toml:");
            println!();
            println!("    [[hooks.PreToolUse]]");
            println!("    matcher = \".*\"");
            println!("    [[hooks.PreToolUse.hooks]]");
            println!("    type = \"command\"");
            println!("    command = \"{bin} evaluate --agent codex\"");
            println!();
            println!("(Codex's PreToolUse output contract matches sentinel's exactly.)");
        }
        "gemini" => {
            println!("Gemini CLI — add to ~/.gemini/settings.json under \"hooks\":");
            println!();
            println!("    \"BeforeTool\": [{{ \"matcher\": \".*\", \"hooks\": [");
            println!("      {{ \"type\": \"command\", \"command\": \"{bin} evaluate --agent gemini\" }}");
            println!("    ] }}]");
        }
        "crush" => {
            println!("Crush — add to crush.json under \"hooks\":");
            println!();
            println!("    \"PreToolUse\": [{{ \"name\": \"sentinel\", \"matcher\": \".*\",");
            println!("      \"command\": \"{bin} evaluate --agent crush\" }}]");
        }
        "opencode" => {
            println!("opencode has no external command hook. drop a JS plugin shim at");
            println!("~/.config/opencode/plugin/sentinel.ts that shells out to:");
            println!();
            println!("    {bin} evaluate --agent generic");
            println!();
            println!("and throws on a non-zero exit (deny).");
        }
        "aider" => {
            println!("Aider has no scriptable pre-tool hook, so it is not supported:");
            println!("its only pre-execution gate is an interactive Y/N, and lint/test");
            println!("commands run AFTER edits and cannot block. (honest non-coverage.)");
        }
        _ => {
            println!("'{agent}' is not auto-configured. wire it into the agent's");
            println!("pre-tool-execution command hook with:");
            println!();
            println!("    {bin} evaluate --agent generic");
            println!();
            println!("contract: tool call as JSON on stdin ({{\"tool_name\",\"tool_input\"}});");
            println!("exit 2 + {{\"decision\":\"block\",\"reason\":...}} = block, exit 0 = allow.");
        }
    }
    println!();
    println!("default policy written to {} (mode: {mode}).", policy_path.display());
    Ok(())
}

pub fn run_uninstall() -> Result<(), InstallError> {
    let settings_path = claude_settings_path();
    hooks::uninstall_hook(&settings_path)?;
    println!("removed sentinel hooks from {}", settings_path.display());
    println!("policy file preserved at ~/.sentinel/policy.toml");
    Ok(())
}

fn which_sentinel() -> Result<PathBuf, InstallError> {
    // check if sentinel is in PATH
    let output = std::process::Command::new("which")
        .arg("sentinel")
        .output()
        .map_err(|_| InstallError::BinaryNotFound)?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Ok(PathBuf::from(path));
    }

    // fallback: use current executable path
    std::env::current_exe().map_err(|_| InstallError::BinaryNotFound)
}

fn claude_settings_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".claude").join("settings.json")
}

fn sentinel_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".sentinel")
}
