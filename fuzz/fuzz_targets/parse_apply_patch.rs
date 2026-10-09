#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_guard::evaluate::normalize::parse_apply_patch;

// Property: never panics on arbitrary patch text. Malformed input must come
// back as an explicit error, which the pipeline turns into a degraded verdict.
fuzz_target!(|data: &[u8]| {
    let Ok(patch) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_apply_patch(patch);
});
