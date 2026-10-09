#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_guard::common::shell::decode_obfuscation;

// Properties: never panics, and decoding is idempotent: running the decoder on
// its own output changes nothing. The engine decodes exactly once, so a second
// pass that still finds something to decode would mean the first pass emitted
// text that the shell reads differently from what was decoded.
fuzz_target!(|data: &[u8]| {
    let Ok(command) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(decoded) = decode_obfuscation(command) {
        assert_ne!(decoded, command, "Some(..) must mean the text changed");
        assert_eq!(
            decode_obfuscation(&decoded),
            None,
            "decode is not idempotent for {command:?}: first pass gave {decoded:?}"
        );
    }
});
