#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_guard::common::ast::{parse, ParseError, MAX_COMMAND_BYTES};
use std::time::{Duration, Instant};

// Properties: the tree-sitter walk never panics; a parse is bounded in time
// (the C parser runs on attacker-controlled text, so a pathological input
// must not stall the hook); an input over the size cap is refused without
// being parsed; every literal word's text is bounded by the input length (a
// literal can only lose quoting and escapes, never gain bytes); and the
// atoms never exceed the input plus one byte per line break.
fuzz_target!(|data: &[u8]| {
    let Ok(command) = std::str::from_utf8(data) else {
        return;
    };
    let started = Instant::now();
    let result = parse(command);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "parse of {} bytes took {elapsed:?}",
        command.len()
    );
    match result {
        Err(ParseError::TooLarge { bytes }) => {
            assert!(bytes > MAX_COMMAND_BYTES);
        }
        Err(_) => {}
        Ok(program) => {
            for segment in &program.segments {
                for word in segment.words.iter().chain(segment.assignments.iter()) {
                    if word.is_literal() {
                        assert!(
                            word.text.len() <= command.len(),
                            "literal {:?} longer than the input",
                            word.text
                        );
                    }
                }
            }
            let line_breaks = command.chars().filter(|c| matches!(c, '\n' | '\r')).count();
            let atoms: usize = program.atoms().iter().map(String::len).sum();
            assert!(
                atoms <= command.len() + line_breaks,
                "atom bytes {atoms} exceed input {} plus {line_breaks} line breaks",
                command.len()
            );
        }
    }
});
