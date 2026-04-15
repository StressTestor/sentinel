//! process-level tests exercising `sentinel evaluate` through actual stdin/stdout.
//! covers the boundary paths that evaluate_for_test (unit tests) can't:
//! empty stdin, unknown schema, policy load failure.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn empty_stdin_passes_through_as_allow() {
    // empty stdin = graceful degradation: no decision key (which the hook
    // interprets as allow), with a "pass-through" reason in the tracing log.
    Command::cargo_bin("sentinel")
        .unwrap()
        .arg("evaluate")
        .write_stdin("")
        .assert()
        .success()
        // no "deny" decision in stdout on empty input
        .stdout(predicate::str::contains("deny").not());
}

#[test]
fn unknown_schema_passes_through_as_allow() {
    // Unknown top-level shape. Our HookInput uses #[serde(flatten)] catch-all
    // with default tool_input, so most "unknown schemas" actually parse.
    // Pass a syntactically invalid JSON instead to force the unknown-schema path.
    Command::cargo_bin("sentinel")
        .unwrap()
        .arg("evaluate")
        .write_stdin("not valid json at all {{{")
        .assert()
        .success()
        .stdout(predicate::str::contains("deny").not());
}
