pub mod automata;
pub mod context;
pub mod patterns;
pub mod sensitivity;

use crate::policy::{Action, PolicyDecision};
use automata::PatternMatcher;
use context::ContextWindow;
use patterns::DEFAULT_PATTERNS;
use sensitivity::Sensitivity;

/// Tier 2 heuristic analyzer.
/// uses aho-corasick automata compiled from the seed pattern set at
/// construction, plus a file-backed ring buffer for multi-turn context.
pub struct HeuristicAnalyzer {
    matcher: PatternMatcher,
    context: ContextWindow,
    sensitivity: Sensitivity,
}

#[derive(Debug, Clone)]
pub struct HeuristicResult {
    pub confidence: f64, // 0.0 to 1.0
    pub matched_patterns: Vec<String>,
    pub context_flags: Vec<String>,
}

impl HeuristicResult {
    pub fn suspicious(&self, sensitivity: Sensitivity) -> bool {
        self.confidence > sensitivity.threshold()
    }
}

impl HeuristicAnalyzer {
    /// construct with the default seed pattern set.
    pub fn new(context_path: &std::path::Path, capacity: usize, sensitivity: Sensitivity) -> Self {
        let patterns: Vec<String> = DEFAULT_PATTERNS.iter().map(|s| s.to_string()).collect();
        let matcher = PatternMatcher::new(&patterns);
        let context = ContextWindow::load_or_create_with_capacity(context_path, capacity);
        Self {
            matcher,
            context,
            sensitivity,
        }
    }

    /// analyze content: push into ring buffer, run pattern matcher,
    /// check multi-turn drift, return confidence + matched data.
    pub fn analyze(&mut self, content: &str) -> HeuristicResult {
        self.context.push(content);
        let matched = self.matcher.find_matches(content);
        let context_flags = self.check_context_drift();
        let confidence = compute_confidence(matched.len(), context_flags.len());
        HeuristicResult {
            confidence,
            matched_patterns: matched,
            context_flags,
        }
    }

    /// merge tier 2 result into tier 1 decision.
    /// - tier 1 Block stays Block (tier 2 never downgrades).
    /// - tier 2 not suspicious (confidence <= threshold): tier 1 unchanged.
    /// - tier 2 suspicious: escalate Allow -> Warn, Warn -> Warn. never Block.
    pub fn merge_with_policy(
        &self,
        t1: PolicyDecision,
        t2: &HeuristicResult,
    ) -> PolicyDecision {
        if t1.action == Action::Block {
            return t1;
        }
        if !t2.suspicious(self.sensitivity) {
            return t1;
        }
        // join both signals so SIEM consumers see the full picture.
        // (prior version dropped context_flags when matched_patterns was non-empty.)
        let mut parts: Vec<&str> = t2.matched_patterns.iter().map(|s| s.as_str()).collect();
        parts.extend(t2.context_flags.iter().map(|s| s.as_str()));
        let matched_summary = parts.join(",");
        let t1_reason = t1.reason.clone().unwrap_or_else(|| "tier1: allow".into());
        let t1_rule = t1
            .matched_rule
            .clone()
            .unwrap_or_else(|| "tier1: none".into());
        PolicyDecision {
            action: Action::Warn, // Allow -> Warn; Warn -> Warn
            reason: Some(format!(
                "{t1_reason} + tier2 heuristic (confidence {:.2})",
                t2.confidence
            )),
            matched_rule: Some(format!("{t1_rule} | tier2: {matched_summary}")),
        }
    }

    fn check_context_drift(&self) -> Vec<String> {
        let mut flags = Vec::new();
        let turns = self.context.recent_turns();

        if turns.len() < 2 {
            return flags;
        }

        let last = turns.last().unwrap();
        let has_sensitive_ref = last.contains("ssh")
            || last.contains("aws")
            || last.contains("credentials")
            || last.contains("password")
            || last.contains("secret")
            || last.contains("token")
            || last.contains("/etc/passwd")
            || last.contains(".env");

        let prev_benign = turns[..turns.len() - 1]
            .iter()
            .all(|t| !t.contains("ssh") && !t.contains("aws") && !t.contains("credentials"));

        if has_sensitive_ref && prev_benign {
            flags.push("behavioral_drift: benign context followed by sensitive access".into());
        }

        flags
    }

    pub fn save(&self) {
        self.context.save();
    }
}

fn compute_confidence(pattern_matches: usize, context_flags: usize) -> f64 {
    let base = match pattern_matches {
        0 => 0.0,
        1 => 0.4,
        2 => 0.6,
        3 => 0.8,
        _ => 0.95,
    };
    let context_boost = context_flags as f64 * 0.2;
    (base + context_boost).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_path(dir: &TempDir, name: &str) -> std::path::PathBuf {
        dir.path().join(name)
    }

    fn t1_allow() -> PolicyDecision {
        PolicyDecision {
            action: Action::Allow,
            reason: None,
            matched_rule: None,
        }
    }

    fn t1_warn() -> PolicyDecision {
        PolicyDecision {
            action: Action::Warn,
            reason: Some("tier1 warn".into()),
            matched_rule: Some("tier1 rule".into()),
        }
    }

    fn t1_block() -> PolicyDecision {
        PolicyDecision {
            action: Action::Block,
            reason: Some("tier1 block".into()),
            matched_rule: Some("tier1 rule".into()),
        }
    }

    #[test]
    fn merge_tier1_block_always_wins() {
        let dir = TempDir::new().unwrap();
        let analyzer = HeuristicAnalyzer::new(&tmp_path(&dir, "ctx.bin"), 50, Sensitivity::High);
        let t2 = HeuristicResult {
            confidence: 0.99,
            matched_patterns: vec!["ignore previous instructions".into()],
            context_flags: vec![],
        };
        let merged = analyzer.merge_with_policy(t1_block(), &t2);
        assert_eq!(merged.action, Action::Block);
    }

    #[test]
    fn merge_not_suspicious_preserves_tier1() {
        let dir = TempDir::new().unwrap();
        let analyzer = HeuristicAnalyzer::new(&tmp_path(&dir, "ctx.bin"), 50, Sensitivity::Medium);
        let t2 = HeuristicResult {
            confidence: 0.1, // below medium threshold 0.3
            matched_patterns: vec![],
            context_flags: vec![],
        };
        let merged = analyzer.merge_with_policy(t1_allow(), &t2);
        assert_eq!(merged.action, Action::Allow);
    }

    #[test]
    fn merge_suspicious_escalates_allow_to_warn() {
        let dir = TempDir::new().unwrap();
        let analyzer = HeuristicAnalyzer::new(&tmp_path(&dir, "ctx.bin"), 50, Sensitivity::Medium);
        let t2 = HeuristicResult {
            confidence: 0.6,
            matched_patterns: vec!["ignore previous instructions".into()],
            context_flags: vec![],
        };
        let merged = analyzer.merge_with_policy(t1_allow(), &t2);
        assert_eq!(merged.action, Action::Warn);
        let reason = merged.reason.unwrap();
        assert!(reason.contains("tier2"));
        assert!(reason.contains("0.60"));
    }

    #[test]
    fn merge_suspicious_keeps_warn_at_warn() {
        let dir = TempDir::new().unwrap();
        let analyzer = HeuristicAnalyzer::new(&tmp_path(&dir, "ctx.bin"), 50, Sensitivity::Medium);
        let t2 = HeuristicResult {
            confidence: 0.95,
            matched_patterns: vec!["jailbreak".into(), "dan mode".into()],
            context_flags: vec![],
        };
        let merged = analyzer.merge_with_policy(t1_warn(), &t2);
        assert_eq!(merged.action, Action::Warn, "tier2 must not escalate to Block in 1.0");
    }

    #[test]
    fn merge_records_matched_patterns_in_matched_rule() {
        let dir = TempDir::new().unwrap();
        let analyzer = HeuristicAnalyzer::new(&tmp_path(&dir, "ctx.bin"), 50, Sensitivity::Medium);
        let t2 = HeuristicResult {
            confidence: 0.6,
            matched_patterns: vec!["system prompt".into()],
            context_flags: vec![],
        };
        let merged = analyzer.merge_with_policy(t1_allow(), &t2);
        let rule = merged.matched_rule.unwrap();
        assert!(rule.contains("tier2"));
        assert!(rule.contains("system prompt"));
    }
}
