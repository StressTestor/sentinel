//! tier 2 benchmark harness.
//!
//! loads every .jsonl session fixture from tests/fixtures/{benign,attack-multiturn,fp-stress},
//! runs each through the full tier 1 + tier 2 pipeline with sensitivity = medium,
//! and asserts three invariants:
//!   1. benign FP rate <5%  (tests/fixtures/benign/: sessions MUST NOT trigger)
//!   2. attack FN rate <10% (tests/fixtures/attack-multiturn/: sessions MUST trigger)
//!   3. fp-stress coverage: every session MUST trigger
//!      (tests/fixtures/fp-stress/: these legitimately contain broad pattern
//!      phrases; this assertion verifies the heuristic actually fires on them,
//!      so pattern coverage doesn't regress silently.)
//!
//! evaluate_for_test deliberately does NOT call analyzer.save(), keeping each
//! session isolated from filesystem state. cross-session state is not part of
//! tier 2's v0.2 contract.

use sentinel_guard::evaluate::{evaluate_for_test, hook_schema::HookInput};
use sentinel_guard::heuristic::{sensitivity::Sensitivity, HeuristicAnalyzer};
use sentinel_guard::policy::schema::{DenyPathRule, PolicyConfig, PolicySettings};
use sentinel_guard::policy::{Action, PolicyDecision, PolicyEngine};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn build_engine() -> PolicyEngine {
    PolicyEngine::from_config(PolicyConfig::new(
        PolicySettings {
            mode: "enforce".into(),
            on_failure: "closed".into(),
            default: "warn".into(),
        },
        vec![DenyPathRule {
            pattern: "~/.ssh/*".into(),
            action: "block".into(),
            reason: "ssh".into(),
        }],
        vec![],
        vec![],
        vec![],
    ))
}

/// run one session end-to-end. returns true if any tool call produced
/// a Warn or Block decision.
fn run_session(fixture: &Path) -> bool {
    let content = fs::read_to_string(fixture)
        .unwrap_or_else(|e| panic!("read {}: {e}", fixture.display()));
    let dir = TempDir::new().unwrap();
    let engine = build_engine();
    let mut analyzer = HeuristicAnalyzer::new(
        &dir.path().join("ctx.bin"),
        50,
        Sensitivity::Medium,
    );

    let mut triggered = false;
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let hi: HookInput = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("parse {}:{}: {e}\nline: {line}", fixture.display(), i + 1)
        });
        let decision: PolicyDecision = evaluate_for_test(&hi, &engine, &mut analyzer);
        if decision.action != Action::Allow {
            triggered = true;
        }
    }
    triggered
}

fn fixtures_in(dir: &str) -> Vec<PathBuf> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(dir);
    let mut out = Vec::new();
    for entry in fs::read_dir(&base).unwrap_or_else(|e| panic!("read_dir {}: {e}", base.display())) {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("jsonl") {
            out.push(p);
        }
    }
    out.sort();
    assert!(!out.is_empty(), "no .jsonl fixtures in {}", base.display());
    out
}

#[test]
fn benign_corpus_fp_rate_under_5_percent_at_medium() {
    let fixtures = fixtures_in("benign");
    let total = fixtures.len();
    let false_positives: usize = fixtures.iter().filter(|f| run_session(f)).count();

    let fp_rate = false_positives as f64 / total as f64;
    assert!(
        fp_rate < 0.05,
        "FP rate {:.1}% exceeds 5% threshold ({}/{} benign sessions triggered at sensitivity=medium). corpus is small ({} sessions), so any FP fails the benchmark.",
        fp_rate * 100.0,
        false_positives,
        total,
        total
    );
}

#[test]
fn attack_multiturn_fn_rate_under_10_percent_at_medium() {
    let fixtures = fixtures_in("attack-multiturn");
    let total = fixtures.len();
    let false_negatives: usize = fixtures.iter().filter(|f| !run_session(f)).count();

    let fn_rate = false_negatives as f64 / total as f64;
    assert!(
        fn_rate < 0.10,
        "FN rate {:.1}% exceeds 10% threshold ({}/{} attack sessions slipped past at sensitivity=medium)",
        fn_rate * 100.0,
        false_negatives,
        total
    );
}

#[test]
fn fp_stress_corpus_all_trigger_at_medium() {
    // fp-stress fixtures intentionally contain broad patterns in legitimate
    // contexts (system prompt, developer mode, upload the file to, transmit to,
    // act as if). they are NOT false-positive candidates -- they are pattern
    // coverage tests. every one MUST trigger; if any doesn't, the pattern set
    // has regressed or been softened.
    let fixtures = fixtures_in("fp-stress");
    let total = fixtures.len();
    let not_triggered: Vec<&PathBuf> = fixtures.iter().filter(|f| !run_session(f)).collect();

    assert!(
        not_triggered.is_empty(),
        "fp-stress coverage gap: {}/{} sessions did not trigger tier 2. pattern set may have regressed. offenders: {:?}",
        not_triggered.len(),
        total,
        not_triggered
    );
}
