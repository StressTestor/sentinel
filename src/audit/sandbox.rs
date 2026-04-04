use crate::cli::SandboxType;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("docker is not available: {0}")]
    DockerUnavailable(String),
    #[error("sandbox execution failed: {0}")]
    ExecutionError(String),
}

/// trait for sandbox backends
pub trait Sandbox: Send + Sync {
    fn name(&self) -> &str;

    /// execute a command inside the sandbox, return stdout
    fn exec(&self, command: &str, env: &HashMap<String, String>) -> Result<String, SandboxError>;
}

/// degraded mode: runs commands directly with a warning.
/// no actual isolation — only for testing when no sandbox is available.
pub struct DegradedSandbox;

impl Sandbox for DegradedSandbox {
    fn name(&self) -> &str {
        "degraded (no isolation)"
    }

    fn exec(&self, command: &str, _env: &HashMap<String, String>) -> Result<String, SandboxError> {
        tracing::warn!("running in degraded mode — no sandbox isolation");
        let output = std::process::Command::new("sh")
            .args(["-c", command])
            .output()
            .map_err(|e| SandboxError::ExecutionError(e.to_string()))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// detect the best available sandbox backend
pub fn detect_sandbox(
    explicit: Option<SandboxType>,
) -> Result<Box<dyn Sandbox>, SandboxError> {
    if let Some(st) = explicit {
        return match st {
            SandboxType::Degraded => {
                eprintln!("warning: running in degraded mode. no sandbox isolation.");
                eprintln!("         attack sequences will execute WITHOUT containment.");
                eprintln!("         this is for testing only. use --sandbox docker for real audits.\n");
                Ok(Box::new(DegradedSandbox))
            }
            SandboxType::Docker => {
                check_docker()?;
                Ok(Box::new(DockerSandbox))
            }
            #[cfg(target_os = "linux")]
            SandboxType::Nsjail => {
                todo!("nsjail sandbox not yet implemented")
            }
            #[cfg(target_os = "macos")]
            SandboxType::MacosSandbox => {
                todo!("macos sandbox not yet implemented")
            }
        };
    }

    // auto-detect: try docker first, fall back to degraded
    if check_docker().is_ok() {
        tracing::info!("auto-detected docker sandbox");
        return Ok(Box::new(DockerSandbox));
    }

    eprintln!("warning: no sandbox backend detected. falling back to degraded mode.");
    eprintln!("         install docker for proper isolation.\n");
    Ok(Box::new(DegradedSandbox))
}

fn check_docker() -> Result<(), SandboxError> {
    let output = std::process::Command::new("docker")
        .arg("info")
        .output()
        .map_err(|_| SandboxError::DockerUnavailable("docker command not found".into()))?;

    if !output.status.success() {
        return Err(SandboxError::DockerUnavailable(
            "docker daemon not running".into(),
        ));
    }
    Ok(())
}

/// docker sandbox with selective egress allowlisting
pub struct DockerSandbox;

impl Sandbox for DockerSandbox {
    fn name(&self) -> &str {
        "docker (network-isolated)"
    }

    fn exec(&self, command: &str, env: &HashMap<String, String>) -> Result<String, SandboxError> {
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--network=none".to_string(), // TODO: replace with selective egress allowlist
            "--memory=512m".to_string(),
            "--cpus=1".to_string(),
        ];

        for (k, v) in env {
            args.push("-e".to_string());
            args.push(format!("{k}={v}"));
        }

        args.extend([
            "ubuntu:latest".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            command.to_string(),
        ]);

        let output = std::process::Command::new("docker")
            .args(&args)
            .output()
            .map_err(|e| SandboxError::ExecutionError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::ExecutionError(stderr.to_string()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}
