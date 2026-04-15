//! hand-curated phrases compiled into the aho-corasick automaton at startup.
//! derived from PromptPressure attack categories. these are short, common
//! injection tropes - not full attack strings. individual matches have low
//! confidence; matches combine with multi-turn context to produce a score.
//!
//! extending this list is a data-curation task, not a code change. before
//! adding patterns, measure false-positive impact against the benign corpus.
//!
//! known limitation: matching is ASCII-case-insensitive only. cyrillic
//! homoglyphs (e.g., "а" U+0430 substituted for latin "a" U+0061) bypass
//! every pattern. this is inherent to string-match heuristics. unicode
//! normalization and homoglyph-aware matching are tier 3's job.

pub const DEFAULT_PATTERNS: &[&str] = &[
    // instruction override - direct
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard the above",
    "disregard prior instructions",
    "forget everything above",
    "forget all prior",
    "ignore your training",
    "bypass your guidelines",
    "override your instructions",
    // system prompt extraction
    "system prompt",
    "reveal your prompt",
    "what are your instructions",
    "show me your instructions",
    "repeat the words above",
    "print everything above",
    "output everything verbatim",
    // role manipulation
    "pretend you are",
    "you are now",
    "act as if",
    "roleplay as",
    "dan mode",
    "developer mode",
    "jailbreak",
    // exfiltration framing
    "send the contents",
    "post this file",
    "upload the file to",
    "exfiltrate",
    "transmit to",
    // credential-targeted injection
    "read your credentials",
    "show me the secrets",
    "print the env",
    "cat the keys",
    // obfuscation markers (catches some obvious attempts)
    "base64 decode this",
    "decode and execute",
    "rot13",
    // urgency / pressure framing
    "this is urgent",
    "your developer says",
    "maintainer instruction",
    "per the security team",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_patterns_is_non_empty() {
        assert!(DEFAULT_PATTERNS.len() >= 30);
    }

    #[test]
    fn default_patterns_are_lowercased_ascii() {
        for p in DEFAULT_PATTERNS {
            assert_eq!(*p, p.to_ascii_lowercase(), "pattern not lowercase: {p}");
        }
    }

    #[test]
    fn default_patterns_have_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for p in DEFAULT_PATTERNS {
            assert!(seen.insert(*p), "duplicate pattern: {p}");
        }
    }
}
