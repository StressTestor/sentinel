#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_guard::common::shell::brace_expand_checked;

/// The cap the policy engine uses for every brace inspection.
const CAP: usize = 64;

// Properties: never panics; with the engine's cap the result is either an
// explicit error or a list of at most CAP expansions, never a silently
// truncated partial list. A word without an opening brace is returned as is.
fuzz_target!(|data: &[u8]| {
    let Ok(word) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(expansions) = brace_expand_checked(word, CAP) {
        assert!(
            expansions.len() <= CAP,
            "{} expansions exceed the cap for {word:?}",
            expansions.len()
        );
        if !word.contains('{') {
            assert_eq!(expansions, vec![word.to_string()]);
        }
    }
});
