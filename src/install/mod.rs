pub mod defaults;
pub mod hooks;

use std::path::PathBuf;
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

pub fn run_install(enforce: bool) -> Result<(), InstallError> {
    // verify sentinel binary is in PATH
    let sentinel_path = which_sentinel()?;
    println!("sentinel binary: {}", sentinel_path.display());

    // install hooks into ~/.claude/settings.json
    let settings_path = claude_settings_path();
    hooks::install_hook(&settings_path, &sentinel_path)?;
    println!("installed PreToolUse hook in {}", settings_path.display());

    // write default policy
    let policy_path = sentinel_dir().join("policy.toml");
    let mode = if enforce { "enforce" } else { "audit" };
    defaults::write_default_policy(&policy_path, mode)?;
    println!("wrote default policy to {}", policy_path.display());
    println!("mode: {mode}");

    if !enforce {
        println!();
        println!("sentinel is in AUDIT mode — logging what would be blocked but not blocking.");
        println!("to enable enforcement: sentinel install --enforce");
        println!("or edit ~/.sentinel/policy.toml and set mode = \"enforce\"");
    }

    println!();
    println!("done. sentinel is now active.");

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
