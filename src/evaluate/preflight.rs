use crate::common::normalize::normalize_for_detection;
use crate::policy::{Action, PackageManager, PolicyDecision, ToolCall};
use std::path::{Path, PathBuf};

const NODE_LIFECYCLE_KEYS: [&str; 3] = ["preinstall", "postinstall", "prepare"];
const LOADER_TOKENS: [&str; 8] = [
    "setup.mjs",
    ".claude/setup.mjs",
    ".vscode/setup.mjs",
    "bun install",
    "bun add",
    "bunx",
    "curl ",
    "wget ",
];

pub fn inspect_workspace(tool_call: &ToolCall) -> Option<PolicyDecision> {
    if !tool_call.install_like {
        return None;
    }

    let cwd = std::env::current_dir().ok()?;
    inspect_workspace_at(tool_call, &cwd)
}

fn inspect_workspace_at(tool_call: &ToolCall, cwd: &Path) -> Option<PolicyDecision> {
    let candidates = manifest_candidates(&cwd, tool_call);

    for path in candidates {
        if !path.exists() {
            continue;
        }
        if let Some(decision) = inspect_manifest(&path) {
            return Some(decision);
        }
    }

    None
}

fn manifest_candidates(cwd: &Path, tool_call: &ToolCall) -> Vec<PathBuf> {
    let mut out = match tool_call.package_manager {
        Some(PackageManager::Npm)
        | Some(PackageManager::Pnpm)
        | Some(PackageManager::Yarn)
        | Some(PackageManager::Bun) => vec![cwd.join("package.json")],
        Some(PackageManager::Pip) | Some(PackageManager::Uv) => {
            vec![cwd.join("pyproject.toml"), cwd.join("setup.py")]
        }
        None => vec![
            cwd.join("package.json"),
            cwd.join("pyproject.toml"),
            cwd.join("setup.py"),
        ],
    };

    if let Some(command) = &tool_call.command {
        let tokens: Vec<&str> = command.split_whitespace().collect();
        for (index, token) in tokens.iter().enumerate() {
            if let Some(path) = token.strip_prefix("--prefix=") {
                push_manifest_roots(&mut out, cwd.join(path), tool_call.package_manager.as_ref());
                continue;
            }
            if let Some(path) = token.strip_prefix("--directory=") {
                push_manifest_roots(&mut out, cwd.join(path), tool_call.package_manager.as_ref());
                continue;
            }
            if matches!(*token, "--prefix" | "--directory" | "-C") {
                if let Some(next) = tokens.get(index + 1) {
                    push_manifest_roots(
                        &mut out,
                        cwd.join(next),
                        tool_call.package_manager.as_ref(),
                    );
                }
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

fn push_manifest_roots(out: &mut Vec<PathBuf>, root: PathBuf, manager: Option<&PackageManager>) {
    match manager {
        Some(PackageManager::Npm)
        | Some(PackageManager::Pnpm)
        | Some(PackageManager::Yarn)
        | Some(PackageManager::Bun) => out.push(root.join("package.json")),
        Some(PackageManager::Pip) | Some(PackageManager::Uv) => {
            out.push(root.join("pyproject.toml"));
            out.push(root.join("setup.py"));
        }
        None => {
            out.push(root.join("package.json"));
            out.push(root.join("pyproject.toml"));
            out.push(root.join("setup.py"));
        }
    }
}

fn inspect_manifest(path: &Path) -> Option<PolicyDecision> {
    let content = std::fs::read_to_string(path).ok()?;
    let normalized = normalize_for_detection(&content);

    let finding = match path.file_name().and_then(|name| name.to_str()) {
        Some("package.json") => inspect_package_json(&content, &normalized),
        Some("pyproject.toml") | Some("setup.py") => inspect_python_manifest(&normalized),
        _ => None,
    }?;

    Some(PolicyDecision {
        action: Action::Block,
        reason: Some(format!(
            "workspace preflight blocked install: {} ({finding})",
            path.display()
        )),
        matched_rule: Some(format!("preflight: {}", path.display())),
    })
}

fn inspect_package_json(content: &str, normalized: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let scripts = value.get("scripts")?.as_object()?;
    let has_remote_dep = normalized.contains("github:")
        || normalized.contains("git+https://github.com")
        || normalized.contains("https://");
    let has_optional_deps = value
        .get("optionalDependencies")
        .and_then(|deps| deps.as_object())
        .map(|deps| !deps.is_empty())
        .unwrap_or(false);

    for key in NODE_LIFECYCLE_KEYS {
        if let Some(script) = scripts.get(key).and_then(|value| value.as_str()) {
            let script_norm = normalize_for_detection(script);
            let loader_count = LOADER_TOKENS
                .iter()
                .filter(|token| script_norm.contains(**token))
                .count();
            if loader_count > 0 {
                return Some(format!("{key} script bootstraps loader"));
            }
            if (has_remote_dep || has_optional_deps)
                && (script_norm.contains("node ")
                    || script_norm.contains("bun")
                    || script_norm.contains("curl ")
                    || script_norm.contains("wget "))
            {
                return Some(format!("{key} script pairs with remote dependency dropper"));
            }
        }
    }

    if normalized.contains("a mini shai-hulud has appeared")
        || normalized.contains("a gift from teampcp")
        || normalized.contains("firedalazer")
    {
        return Some("contains stable Mini Shai-Hulud IOC".into());
    }

    None
}

fn inspect_python_manifest(normalized: &str) -> Option<String> {
    let has_remote_exec = normalized.contains("subprocess")
        && (normalized.contains("curl ")
            || normalized.contains("wget ")
            || normalized.contains("python -c")
            || normalized.contains("os.system"));
    let has_supply_chain_markers = normalized.contains("a mini shai-hulud has appeared")
        || normalized.contains("firedalazer")
        || normalized.contains("setup.mjs")
        || normalized.contains("bun");

    if has_remote_exec && has_supply_chain_markers {
        return Some("python install surface executes remote loader".into());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PackageManager, ToolAccess};
    use tempfile::TempDir;

    fn install_tool_call(command: &str) -> ToolCall {
        ToolCall {
            tool_name: "Bash".into(),
            command: Some(command.into()),
            paths: vec![],
            raw_params: format!(r#"{{"command":"{command}"}}"#),
            write_payload: None,
            access: ToolAccess::Execute,
            package_manager: Some(PackageManager::Npm),
            install_like: true,
        }
    }

    #[test]
    fn blocks_malicious_package_json() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"preinstall":"node setup.mjs"},"optionalDependencies":{"loader":"github:evil/dropper"}}"#,
        )
        .unwrap();

        let decision = inspect_workspace_at(&install_tool_call("npm install"), dir.path());

        assert!(decision.is_some());
        assert!(decision.unwrap().reason.unwrap().contains("preflight"));
    }

    #[test]
    fn ignores_clean_package_json() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"test":"cargo test --lib"},"dependencies":{"serde":"1.0"}}"#,
        )
        .unwrap();

        let decision = inspect_workspace_at(&install_tool_call("npm install"), dir.path());

        assert!(decision.is_none());
    }
}
