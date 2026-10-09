//! self-protect for the sandbox bridge: a typed settings write that weakens
//! the sandbox sentinel installed is a block, in the same shape as hook
//! removal.
//!
//! Active ONLY when `~/.sentinel/install-state.json` records a sandbox bridge.
//! Without the record, nothing in this module changes a decision: the sandbox
//! keys are then the user's own business.
//!
//! The comparison is before/after on the file being written, never "the
//! resulting document lacks X". A file that already carried a weak value (a
//! project settings file with `allowUnsandboxedCommands: true` from before the
//! bridge) can still take an unrelated edit, and an entry the operator removed
//! by hand is doctor's drift report, not a block on the next unrelated edit.

use crate::install::state::SandboxRecord;
use serde_json::Value;

/// why a write was judged to weaken the sandbox
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weakening(pub String);

fn sandbox_flag(document: &Value, key: &str) -> Option<bool> {
    document
        .get("sandbox")
        .and_then(|sandbox| sandbox.get(key))
        .and_then(Value::as_bool)
}

fn string_list(document: &Value, path: &[&str]) -> Vec<String> {
    let mut current = document;
    for key in path {
        let Some(next) = current.get(key) else {
            return Vec::new();
        };
        current = next;
    }
    current
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Compare the document a mutation produces with the one on disk. `owned`
/// carries the sentinel-written deny entries when `after` is the file the
/// bridge was installed into, and is empty for any other Claude settings file.
pub fn weakening(
    before: &Value,
    after: &Value,
    owned: Option<&SandboxRecord>,
) -> Option<Weakening> {
    // the three pinned keys: a weak explicit value that was not there before,
    // or dropping the pinned value (Claude Code's default then applies, which
    // is the weak direction for each of them)
    let keys: [(&str, bool, bool); 3] = [
        // (key, weak explicit value, value the bridge pins)
        ("enabled", false, true),
        ("allowUnsandboxedCommands", true, false),
        ("failIfUnavailable", false, true),
    ];
    for (key, weak, pinned) in keys {
        let was = sandbox_flag(before, key);
        let now = sandbox_flag(after, key);
        if now == Some(weak) && was != Some(weak) {
            return Some(Weakening(format!("sets sandbox.{key} to {weak}")));
        }
        if was == Some(pinned) && now.is_none() {
            return Some(Weakening(format!(
                "removes sandbox.{key} (the host default is the weaker setting)"
            )));
        }
    }
    let disabled = |document: &Value| {
        document
            .get("sandbox")
            .and_then(|s| s.get("filesystem"))
            .and_then(|f| f.get("disabled"))
            .and_then(Value::as_bool)
            == Some(true)
    };
    if disabled(after) && !disabled(before) {
        return Some(Weakening(
            "sets sandbox.filesystem.disabled, which turns off every deny entry".into(),
        ));
    }
    let excluded_before = string_list(before, &["sandbox", "excludedCommands"]);
    let excluded_after = string_list(after, &["sandbox", "excludedCommands"]);
    if let Some(added) = excluded_after
        .iter()
        .find(|entry| !excluded_before.contains(entry))
    {
        return Some(Weakening(format!(
            "adds `{added}` to sandbox.excludedCommands, which runs it with full access outside every deny entry"
        )));
    }
    let record = owned?;
    for (list, owned_entries) in [
        ("denyRead", &record.deny_read),
        ("denyWrite", &record.deny_write),
    ] {
        let live = string_list(before, &["sandbox", "filesystem", list]);
        let next = string_list(after, &["sandbox", "filesystem", list]);
        if let Some(removed) = owned_entries
            .iter()
            .find(|entry| live.contains(entry) && !next.contains(entry))
        {
            return Some(Weakening(format!(
                "removes the sentinel-owned entry `{removed}` from sandbox.filesystem.{list}"
            )));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::state::SandboxPrior;
    use serde_json::json;

    fn record() -> SandboxRecord {
        SandboxRecord {
            settings_path: "/home/t/.claude/settings.json".into(),
            deny_read: vec!["~/.ssh".into(), "~/.aws".into()],
            deny_write: vec!["~/.ssh".into(), "~/.sentinel/policy.toml".into()],
            prior: SandboxPrior::default(),
        }
    }

    fn installed() -> Value {
        json!({
            "model": "opus",
            "hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [
                {"type": "command", "command": "/usr/local/bin/sentinel evaluate"}
            ]}]},
            "sandbox": {
                "enabled": true,
                "failIfUnavailable": true,
                "allowUnsandboxedCommands": false,
                "filesystem": {
                    "denyRead": ["~/.ssh", "~/.aws"],
                    "denyWrite": ["~/.ssh", "~/.sentinel/policy.toml"]
                }
            }
        })
    }

    #[test]
    fn each_weakening_edit_is_named() {
        let before = installed();
        type Edit = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Edit)> = vec![
            (
                "enabled",
                Box::new(|v| v["sandbox"]["enabled"] = json!(false)),
            ),
            (
                "enabled",
                Box::new(|v| {
                    v["sandbox"].as_object_mut().unwrap().remove("enabled");
                }),
            ),
            (
                "allowUnsandboxedCommands",
                Box::new(|v| v["sandbox"]["allowUnsandboxedCommands"] = json!(true)),
            ),
            (
                "allowUnsandboxedCommands",
                Box::new(|v| {
                    v["sandbox"]
                        .as_object_mut()
                        .unwrap()
                        .remove("allowUnsandboxedCommands");
                }),
            ),
            (
                "failIfUnavailable",
                Box::new(|v| v["sandbox"]["failIfUnavailable"] = json!(false)),
            ),
            (
                "filesystem.disabled",
                Box::new(|v| v["sandbox"]["filesystem"]["disabled"] = json!(true)),
            ),
            (
                "excludedCommands",
                Box::new(|v| v["sandbox"]["excludedCommands"] = json!(["gh *"])),
            ),
            (
                "denyRead",
                Box::new(|v| v["sandbox"]["filesystem"]["denyRead"] = json!(["~/.ssh"])),
            ),
            (
                "denyWrite",
                Box::new(|v| v["sandbox"]["filesystem"]["denyWrite"] = json!(["~/.ssh"])),
            ),
            (
                "enabled",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("sandbox");
                }),
            ),
        ];
        for (key, edit) in cases {
            let mut after = before.clone();
            edit(&mut after);
            let found = weakening(&before, &after, Some(&record()));
            assert!(found.is_some(), "{key}: {after}");
            assert!(found.unwrap().0.contains(key), "{key}");
        }
    }

    #[test]
    fn edits_that_keep_every_sentinel_key_are_not_weakening() {
        let before = installed();
        let mut after = before.clone();
        after["model"] = json!("sonnet");
        after["sandbox"]["filesystem"]["denyRead"]
            .as_array_mut()
            .unwrap()
            .push(json!("~/mine"));
        after["sandbox"]["network"] = json!({"allowedDomains": ["crates.io"]});
        assert_eq!(weakening(&before, &after, Some(&record())), None);
        // a user-owned entry may be removed: sentinel did not write it
        let mut after = before.clone();
        after["sandbox"]["filesystem"]["denyRead"] = json!(["~/.ssh", "~/.aws"]);
        assert_eq!(weakening(&before, &after, Some(&record())), None);
        // identical rewrite
        assert_eq!(weakening(&before, &before, Some(&record())), None);
    }

    #[test]
    fn a_file_that_already_carried_the_weak_value_can_take_unrelated_edits() {
        // a project settings file from before the bridge: allowUnsandboxedCommands
        // was already true there, so changing the model is not an escalation
        let before = json!({"sandbox": {"allowUnsandboxedCommands": true}, "model": "opus"});
        let mut after = before.clone();
        after["model"] = json!("sonnet");
        assert_eq!(weakening(&before, &after, None), None);
        // an entry already missing on disk (drift) is doctor's job, not a block
        let mut drifted = installed();
        drifted["sandbox"]["filesystem"]["denyRead"] = json!(["~/.aws"]);
        let mut after = drifted.clone();
        after["model"] = json!("sonnet");
        assert_eq!(weakening(&drifted, &after, Some(&record())), None);
    }

    #[test]
    fn a_fresh_project_file_with_a_weak_key_is_weakening() {
        // the file did not exist (empty document) and the write introduces a
        // project-scope override
        let before = json!({});
        let after = json!({"sandbox": {"enabled": false}});
        assert!(weakening(&before, &after, None).is_some());
        let after = json!({"sandbox": {"excludedCommands": ["npm *"]}});
        assert!(weakening(&before, &after, None).is_some());
        // explicit strong values are fine
        let after = json!({"sandbox": {"enabled": true, "allowUnsandboxedCommands": false}});
        assert_eq!(weakening(&before, &after, None), None);
    }
}
