pub mod automata;
pub mod context;

use automata::PatternMatcher;
use context::ContextWindow;

/// Tier 2 heuristic analyzer.
/// uses aho-corasick automata compiled from the PromptPressure corpus
/// and a file-backed ring buffer for multi-turn context.
pub struct HeuristicAnalyzer {
    matcher: PatternMatcher,
    context: ContextWindow,
}

#[derive(Debug, Clone)]
pub struct HeuristicResult {
    pub suspicious: bool,
    pub confidence: f64, // 0.0 to 1.0
    pub matched_patterns: Vec<String>,
    pub context_flags: Vec<String>,
}

impl HeuristicAnalyzer {
    pub fn new(corpus_patterns: &[String], context_path: &std::path::Path) -> Self {
        let matcher = PatternMatcher::new(corpus_patterns);
        let context = ContextWindow::load_or_create(context_path);
        Self { matcher, context }
    }

    /// analyze a tool call's content for injection patterns.
    /// checks both the current input and multi-turn context.
    pub fn analyze(&mut self, content: &str) -> HeuristicResult {
        // record this turn in context
        self.context.push(content);

        // pattern matching against corpus
        let matched = self.matcher.find_matches(content);

        // check multi-turn context for drift
        let context_flags = self.check_context_drift();

        // compute confidence based on number and type of matches
        let confidence = compute_confidence(matched.len(), context_flags.len());

        HeuristicResult {
            suspicious: confidence > 0.3,
            confidence,
            matched_patterns: matched,
            context_flags,
        }
    }

    fn check_context_drift(&self) -> Vec<String> {
        let mut flags = Vec::new();
        let turns = self.context.recent_turns();

        if turns.len() < 2 {
            return flags;
        }

        // check for escalation patterns across turns
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

    /// flush context to disk
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
