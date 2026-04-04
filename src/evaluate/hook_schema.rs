use crate::policy::ToolCall;
use serde::Deserialize;

/// the JSON structure Claude Code sends to PreToolUse hooks on stdin.
/// we deserialize flexibly to handle schema changes gracefully.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    #[serde(alias = "tool", alias = "toolName")]
    pub tool_name: Option<String>,

    #[serde(default)]
    pub tool_input: serde_json::Value,

    // capture everything else for forward compatibility
    #[serde(flatten)]
    pub _extra: serde_json::Map<String, serde_json::Value>,
}

impl HookInput {
    /// convert to a ToolCall for policy evaluation.
    /// extracts paths and commands from the tool input based on tool type.
    pub fn to_tool_call(&self) -> ToolCall {
        let tool_name = self.tool_name.clone().unwrap_or_else(|| "unknown".into());
        let raw_params = self.tool_input.to_string();

        let mut command = None;
        let mut paths = Vec::new();

        match tool_name.as_str() {
            "Bash" => {
                // Bash tool has a "command" field
                if let Some(cmd) = self.tool_input.get("command").and_then(|v| v.as_str()) {
                    command = Some(cmd.to_string());
                    // extract paths from command (basic heuristic)
                    paths.extend(extract_paths_from_command(cmd));
                }
            }
            "Read" | "Write" | "Edit" => {
                // file tools have a "file_path" or "path" field
                for key in &["file_path", "path", "filePath"] {
                    if let Some(p) = self.tool_input.get(*key).and_then(|v| v.as_str()) {
                        paths.push(p.to_string());
                    }
                }
            }
            "Glob" => {
                if let Some(p) = self.tool_input.get("pattern").and_then(|v| v.as_str()) {
                    paths.push(p.to_string());
                }
            }
            "Grep" => {
                if let Some(p) = self.tool_input.get("path").and_then(|v| v.as_str()) {
                    paths.push(p.to_string());
                }
            }
            _ => {
                // unknown tool — scan all string values for paths
                extract_all_paths(&self.tool_input, &mut paths);
            }
        }

        ToolCall {
            tool_name,
            command,
            paths,
            raw_params,
        }
    }
}

/// extract file paths from a shell command string (basic heuristic).
/// looks for arguments that look like file paths.
fn extract_paths_from_command(cmd: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for token in cmd.split_whitespace() {
        // skip flags
        if token.starts_with('-') {
            continue;
        }
        // looks like a path if it contains / or ~ or .
        if token.contains('/') || token.starts_with('~') || token.starts_with('.') {
            paths.push(token.to_string());
        }
    }
    paths
}

/// recursively scan a JSON value for strings that look like file paths
fn extract_all_paths(value: &serde_json::Value, paths: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            if s.contains('/') || s.starts_with('~') {
                paths.push(s.clone());
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                extract_all_paths(v, paths);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_all_paths(v, paths);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bash_tool_call() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "cat ~/.ssh/id_rsa"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let tc = input.to_tool_call();
        assert_eq!(tc.tool_name, "Bash");
        assert_eq!(tc.command.as_deref(), Some("cat ~/.ssh/id_rsa"));
        assert!(tc.paths.contains(&"~/.ssh/id_rsa".to_string()));
    }

    #[test]
    fn parse_read_tool_call() {
        let json = r#"{"tool_name": "Read", "tool_input": {"file_path": "/etc/passwd"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let tc = input.to_tool_call();
        assert_eq!(tc.tool_name, "Read");
        assert!(tc.paths.contains(&"/etc/passwd".to_string()));
    }

    #[test]
    fn parse_edit_tool_call() {
        let json = r#"{"tool_name": "Edit", "tool_input": {"file_path": "./src/main.rs", "old_string": "foo", "new_string": "bar"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let tc = input.to_tool_call();
        assert_eq!(tc.tool_name, "Edit");
        assert!(tc.paths.contains(&"./src/main.rs".to_string()));
    }

    #[test]
    fn graceful_on_unknown_fields() {
        let json = r#"{"tool_name": "NewTool", "tool_input": {}, "some_future_field": true}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let tc = input.to_tool_call();
        assert_eq!(tc.tool_name, "NewTool");
    }

    #[test]
    fn handle_missing_tool_name() {
        let json = r#"{"tool_input": {"command": "ls"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        let tc = input.to_tool_call();
        assert_eq!(tc.tool_name, "unknown");
    }

    #[test]
    fn extract_paths_from_bash_command() {
        let paths = extract_paths_from_command("cat ~/.aws/credentials /etc/passwd -n");
        assert!(paths.contains(&"~/.aws/credentials".to_string()));
        assert!(paths.contains(&"/etc/passwd".to_string()));
        assert!(!paths.iter().any(|p| p.starts_with('-')));
    }
}
