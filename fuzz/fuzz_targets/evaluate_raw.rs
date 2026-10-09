#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_guard::evaluate::pipeline::evaluate_raw;
use sentinel_guard::install::defaults::default_policy_content;
use sentinel_guard::policy::PolicyEngine;
use std::sync::OnceLock;

static ENGINE: OnceLock<PolicyEngine> = OnceLock::new();

fn engine() -> &'static PolicyEngine {
    ENGINE.get_or_init(|| {
        PolicyEngine::from_toml_str(&default_policy_content("enforce"))
            .expect("bundled enforce policy parses")
    })
}

// Property: the whole hook pipeline (parse, normalize, policy, self-protect,
// autorun, preflight) never panics on arbitrary stdin text. Invalid input must
// surface as a degraded result, not as a crash whose exit code the host reads
// as a verdict.
fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let _ = evaluate_raw(engine(), raw);
});
