#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_guard::common::shell::shell_tokens;

// Properties: never panics; when the command tokenizes, every token is a valid
// Rust string (UTF-8 by construction) and the summed token length stays
// bounded by the input length plus one byte per line break, the only place the
// tokenizer synthesizes a `;` token that was not in the input.
fuzz_target!(|data: &[u8]| {
    let Ok(command) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(tokens) = shell_tokens(command) {
        let total: usize = tokens.iter().map(String::len).sum();
        let line_breaks = command.chars().filter(|c| matches!(c, '\n' | '\r')).count();
        assert!(
            total <= command.len() + line_breaks,
            "token bytes {total} exceed input {} plus {line_breaks} line breaks",
            command.len()
        );
        for token in &tokens {
            assert!(std::str::from_utf8(token.as_bytes()).is_ok());
        }
    }
});
