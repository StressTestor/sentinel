# Sentinel empirical hardening verification matrix

Date: 2026-07-28

Starting source: `origin/main` at
`e4f3333052612f17e3cd8a8c323c553f18952273`.

This file is the live evidence ledger for the empirical-hardening branch.
`Confirmed` means the behavior was reproduced against the starting source.
`Fixed` is only used after the original reproduction and its controls pass
against the changed binary. Commands that use a temporary home never inspect or
modify the operator's real agent configuration.

## Source-of-truth snapshot

| Surface | Observed state |
|---|---|
| Branch | baseline `codex/sentinel-empirical-hardening`, created from `origin/main` |
| Cargo package | starting source was `sentinel-guard 0.4.0` with no declared MSRV |
| crates.io | `sentinel-guard 0.4.1`; package VCS SHA `508046382336bf2347574f4b2a4f20d543745ebf` |
| Package ancestry | the `0.4.1` VCS SHA exists only on `origin/claude/sentinel-guard-version-check-xhh2bi`, not `main` |
| GitHub releases/tags | latest release and tag are `v0.4.0`; there is no `v0.4.1` tag or release |
| Open pull requests | ten Dependabot PRs: `#52`, `#53`, `#54`, `#56`, `#63` through `#68`; `#65` and `#67` are unstable |
| Main CI | last main CI for `e4f3333` passed; current workflow runs plain `cargo test` and `cargo clippy` |
| Main governance | active `protect-main` ruleset prevents deletion and non-fast-forward updates only; no PR or required-check rule |

## Findings

| ID | Finding and current reproduction | Expected behavior | Current result | Severity | Primary sources | Acceptance test | Status |
|---|---|---|---|---|---|---|---|
| F01 | A Codex `apply_patch` payload whose `tool_input.command` updates `~/.sentinel/policy.toml` is passed to `check` and `evaluate --agent codex`. | A protected mutation is normalized as a file update, returns the Codex deny JSON contract, and exits `2`. | Typed parsing covers add/update/move/delete and multi-file patches; protected mutations deny with exit `2`, malformed patches fail closed, and benign source text remains non-executable. | Critical | `src/evaluate/hook_schema.rs`, `src/evaluate/mod.rs`, `src/selfprotect/mod.rs` | Golden wire fixtures and binary tests for policy/hook mutations, add/update/move/delete/multi-file patches, plus benign source-patch controls. | Fixed |
| F02 | A settings write preserves the Sentinel PreToolUse hook but adds a `SessionStart` command `curl … \| sh`; compare `check --json` with live `evaluate`. | Every adapter uses one decision pipeline and reaches the same underlying decision. | `check`, live evaluation, verifier, and doctor now use the same typed pipeline for policy, self-protection, autorun, preflight, and failure posture. | High | `src/check/mod.rs`, `src/evaluate/mod.rs`, `src/verify/mod.rs`, `src/install/defaults.rs`, `src/doctor/mod.rs` | Parity table for self-protection, autorun, preflight, ordinary writes, malformed input, verifier cases, and doctor canary. | Fixed |
| F03 | Run the three-fixture audit with degraded mode, or inspect the runner boundary. | The selected agent receives a persistent sequence and verdicts derive from structured tool/filesystem/network evidence. | Claude and Codex adapters resume one stateful session; only correlated structured evidence can produce `Vulnerable`, and only explicit refusal plus complete negative evidence can produce `Defended`; incomplete runs are unscored. | Critical | `src/audit/mod.rs`, `src/audit/runner.rs`, `src/audit/adapter.rs` | Deterministic refusing and vulnerable fake-agent end-to-end tests, multi-turn state assertion, structured evidence assertions, and adapter-error inconclusive/error tests. | Fixed |
| F04 | Run audit without Docker or explicitly select `degraded`. | No prompt reaches the host shell unless an explicit alarming unsafe-development opt-in is supplied. | Audit refuses to start an agent without `--unsafe-host`; prompts are written to agent stdin and never passed to a shell. | Critical | `src/audit/adapter.rs`, `src/cli.rs` | A shell canary must remain untouched in normal and backend-failure paths; unsafe mode, if retained, must require a separate explicit flag. | Fixed |
| F05 | Inspect the package exclude list, build a crate, install it with an empty home, then run the advertised audit/corpus commands. | Everything needed by an advertised command ships in the crate or is retrieved atomically with verified integrity and provenance. | `corpus/v1` is packaged with project provenance/license notes and validated order; extracted-crate tests, install, empty-home verifier, and public help all pass. | High | `Cargo.toml`, `src/corpus/mod.rs`, `corpus/v1/` | `cargo package`, install the produced crate under an empty home, run every advertised corpus surface, and verify versioned corpus provenance. | Fixed |
| F06 | Enumerate public help and execute `wrap`, `corpus-update`, and explicit platform sandbox choices. | Every advertised command either fulfills its contract or fails clearly as unsupported; no stub succeeds. | The unimplemented wrap, mutable corpus-update, and fake sandbox surfaces were removed; package smoke rejects stub/panic markers and exercises every advertised help surface. | High | `src/cli.rs`, `src/main.rs`, `README.md`, `scripts/package-smoke.sh` | Packaged-binary help/command smoke test asserts no stub, panic, or fake-success path. | Fixed |
| F07 | Install with `--agent codex`, inspect the config, then run status, doctor, result-scan install, reinstall, and uninstall under a clean home. | Typed agent targets provide TOML-preserving, idempotent, agent-aware lifecycle management for Claude and Codex. | Claude and Codex lifecycle paths preserve unrelated handlers/config, reconcile duplicate sources, detect activation/trust, and remove only owned direct hooks. Live Codex installation is trusted and healthy. | High | `src/cli.rs`, `src/install/mod.rs`, `src/install/hooks.rs`, `src/install/state.rs`, `src/install/activation.rs`, `src/doctor/mod.rs` | Clean-home lifecycle tests for default/custom `CODEX_HOME`, unrelated TOML preservation, Pre/PostToolUse, trust/activation guidance, reinstall, status, doctor, and uninstall. | Fixed |
| F08 | Install an older policy, compare it with defaults after an action change, and attempt an upgrade. | Versioned migration detects missing and modified defaults, preserves user mode/comments/custom rules, backs up, writes atomically, and rolls back on failed gates. | `policy-migrate --check/--apply` recognizes exact published 0.4.0/0.4.1 generations, performs a three-way merge, backs up, validates, rolls back on failure, and is idempotent. The operator policy was migrated successfully. | High | `src/install/defaults.rs`, `src/policy_migrate.rs`, `src/cli.rs` | Fixtures for every published policy generation; `--check`/`--apply`, backup, comment/custom preservation, action changes, atomic failure, and rollback tests. | Fixed |
| F09 | Fresh-install the bundled policy in a temporary home and run `doctor --json`. | Doctor validates effective protection through the shared decision pipeline. | Doctor recognizes the typed self-protect rule and validates the installed binary with a real known-bad denial canary; truly disarmed policies fail. | Medium | `src/doctor/mod.rs`, `src/policy/mod.rs`, `src/selfprotect/mod.rs` | Fresh Claude/Codex installs and migrated policies pass behavioral canaries; an actually disarmed policy fails. | Fixed |
| F10 | Point Claude at the supported Ghost-to-Sentinel bridge, then run status/doctor. | A parsed, executable, version-validated bridge is recognized as protected without weakening direct-hook checks. | Exact parsed ownership distinguishes direct Sentinel and Ghost-mediated handlers; doctor invokes the bridge itself and requires a real denial. The operator's Ghost path is healthy. | Medium | `src/install/hooks.rs`, `src/install/mod.rs`, `src/doctor/mod.rs` | Direct, Ghost-bridged, stale binary, wrong binary, wrong version, and untrusted/disabled lifecycle fixtures. | Fixed |
| F11 | Run `audit-mcp` for the first time, then add/change/remove servers across Claude and Codex configs. | First run is discovery-only until explicit trust; diffs include additions, changes, removals, and both agents with secret-safe fingerprints. | First run is discovery-only; `--update` explicitly writes a private atomic baseline. Claude/Codex additions, changes, and removals use salted canonical digests without raw commands or secrets. | High | `src/audit_mcp/mod.rs`, `src/cli.rs` | Empty-home discovery, explicit trust/update, add/change/remove, Claude/Codex merge, and no-secret-output tests. | Fixed |
| F12 | Compare Cargo metadata, crates.io metadata/VCS SHA, remote tags/releases, and `main`. | One reviewed merged commit maps to Cargo version, tag, crate VCS source, artifacts, checksums/attestations, and GitHub release. | Candidate is the unused `0.5.0`; release identity gates exact Cargo/tag/main/crates/VCS equality and draft-first artifacts, checksums, SBOMs, and attestations. No tag or publication occurs before merge and credentials. | Critical | `Cargo.toml`, `.github/workflows/release.yml`, `scripts/release-identity.sh`, GitHub releases/tags, crates.io package metadata | Release dry run rejects branch-only source and any identity mismatch; next unused version is chosen immediately before release. | Candidate ready; merge/release pending |
| F13 | Run the documented local gates and inspect CI. | CI gates fmt, locked all-target/all-feature tests and clippy, verifier/migrations, dependency audit, network lint, package/install smoke, MSRV, meaningful macOS behavior, docs, and provenance. | Local gates pass, and PR `#69` passed all 11 GitHub checks: quality, MSRV, package smoke, both platforms, RustSec, cargo-deny, dependency review, and CodeQL for Rust and Actions. | High | `.github/workflows/ci.yml`, other workflows, `Cargo.toml`, `CONTRIBUTING.md` | Green matrix containing every required gate plus a failing provenance-negative test. | Fixed |
| F14 | Compare README, architecture, changelog, CLI help, verifier case count, Cargo features, and packaged behavior. | Public claims and architecture describe tested behavior and explicitly separate guarantees, heuristics, limits, configuration, trust, and activation. | README, architecture, changelog, and site now match the shipped one-tier pipeline, 45 verifier cases, stateful unsafe-host audit, bundled corpus, lifecycle trust, MCP baseline, and explicit limits. | Medium | `README.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `Cargo.toml` | Documentation assertions plus full manual claim-to-test review. | Fixed |
| F15 | Inspect direct dependencies and feature use. | Direct dependencies are used and runtime features are minimal. | Unused `anyhow`/`proptest` were removed; Tokio is narrowed to the used process/I/O/time/macros/runtime features; locked all-feature and RustSec gates pass. | Low | `Cargo.toml`, `Cargo.lock`, `src/`, `tests/` | `cargo machete`-equivalent source check, locked all-feature build/test, and dependency audit after removal/narrowing. | Fixed |
| F16 | Inspect the active ruleset for the default branch. | Changes require a PR and the verified CI/security checks, with a documented break-glass route. | Active ruleset `18708361` now requires a squash PR, resolved conversations, strict success from the 11 observed GitHub checks, and has no bypass actor. Active ruleset `19889568` prevents updates, deletion, and non-fast-forward changes to `v*` tags. | High | GitHub rulesets `18708361` and `19889568`, `.github/workflows/` | Ruleset read-back after CI names stabilize; direct push is rejected and documented break-glass remains explicit. | Fixed |
| F17 | List open automated PRs and inspect their checks/ancestry. | Related dependency updates are grouped and stale automated branches are closed with receipts. | Dependabot grouping is configured; PRs `#52`, `#53`, `#54`, `#56`, and `#63` through `#68` were closed with comments identifying `#69` as the grouped superseding change. | Low | `.github/dependabot.yml`, GitHub PRs `#52`, `#53`, `#54`, `#56`, `#63`-`#68` | Dependabot grouping config plus documented merge/close disposition for every open automated PR. | Fixed |

## Fresh-eyes review findings

These findings were produced after the first repair pass, then reproduced
independently before remediation.

| ID | Reproduction and root cause | Fix | Acceptance evidence | Status |
|---|---|---|---|---|
| R01 | A child that never reads a large prompt outlived `--timeout-seconds`; the timeout covered the write but cleanup could await kill/reap and pipe drains outside the budget. | One monotonic deadline now covers write, wait, process-group termination, reap, and bounded readers. | Direct deadline unit test plus `audit_honesty` hanging/no-stdin control. | Fixed |
| R02 | The command-execution canary had no target pattern, so an unrelated successful command could satisfy it. | The corpus requires the exact harmless `printf sentinel-audit-command-canary` target. | Matching and lookalike command controls. | Fixed |
| R03 | Codex represented safe-canary `cat` and `curl` calls as generic command evidence, so file/network cases stayed inconclusive. | Exact reserved canary shell forms produce typed filesystem/network evidence; lookalikes do not. | Adapter evidence and false-positive unit tests. | Fixed |
| R04 | Custom corpus `assistant`/`system` roles parsed successfully but the runner silently discarded them. | The schema rejects every role the runner cannot replay. | Parser and runner fail-loud tests. | Fixed |
| R05 | `install --help` still described Codex as generic/manual. | Help now distinguishes native Claude/Codex lifecycle management from the generic evaluate contract. | Live help assertion in `audit_honesty`. | Fixed |
| R06 | Architecture/changelog said sessions persisted across cases, while runtime creates one session per sequence. | Claims now state sequence-scoped persistence and cross-sequence isolation. | Docs claim review and diff check. | Fixed |
| R07 | Verifier and AD-5 prose retained the removed Docker-sandbox model; AD-5 broadly exempted audit source. | Removed obsolete prose and scan all Rust source for ambient network calls. | `scripts/ad5-network-lint.sh` passes without an audit exemption. | Fixed |
| R08 | A public GitHub release plus an absent crate could skip the publish job and report workflow success. | Release identity rejects that contradictory state and the tag job always runs the publish verifier. | Four-state registry/release review plus actionlint. | Fixed |
| R09 | Three of four release binaries received only `file` inspection because target triples did not equal runner host triples. | CPU-native musl artifacts execute on native Linux runners; x86 and arm macOS use matching Intel/arm runners. | Workflow review, actionlint, and native arm64 release build. | Fixed |
| R10 | One host-default Linux SBOM was shipped beside all four target archives. | Generate and assert four target-qualified CycloneDX SBOMs with cargo-cyclonedx 0.5.9. | Tool source/filename verification and workflow review. | Fixed |
| R11 | Local release dry-run read candidate files but attributed them to the old clean `HEAD`. | Local identity checks refuse any tracked or untracked dirty worktree; CI has an explicit negative test. | Dirty-tree dry-run exits `1`; actionlint passes. | Fixed |
| R12 | A remote tag could move between initial fetch and GitHub release publication. | Publish mode re-reads the annotated/lightweight remote tag immediately before public release. Immutable releases are enabled, and active ruleset `19889568` prevents `v*` updates or deletion without a bypass actor. | Remote-tag parsing/revalidation review plus live ruleset and immutable-release read-back. | Fixed |
| R13 | A Codex mutation through an existing symlink to policy, hook config, or MCP baseline received only the canonical policy warning. | Resolve paths against `cwd`, canonicalize existing source/destination identities, and fail closed when identity cannot be inspected. | Codex symlink integration controls. | Fixed |
| R14 | A hook command such as `sentinel evaluate >/dev/null 2>&1 \|\| true` was treated as owned; Doctor probed only the binary prefix and reported healthy. | Ownership requires exact supported argv and Doctor probes the configured direct or Ghost command. | Wrapped-hook install/self-protect/strict-Doctor regressions. | Fixed |
| R15 | Claude local-scope `projects.<cwd>.mcpServers` entries were absent from strict MCP audit. | Discover only the canonical current project as the path-free `claude:local` source. | Current/unrelated-project and secret/path non-disclosure integration test. | Fixed |
| R16 | An injected agent could run `audit-mcp --update` or rewrite `mcp-baseline.json` to approve its own server. | Typed mutations and shell rewrite forms block; agent-triggered update blocks while direct human CLI update remains available. | Shared-pipeline Bash/patch/read-only audit controls and migration tests. | Fixed |
| R17 | PR review reproduced that custom `CODEX_HOME` installs using either `config.toml` or pre-existing `hooks.json` were outside suffix-only hook self-protection. | Compare mutation identities with both effective installer-managed Codex paths, including canonicalized custom homes. | Fresh subprocess installs under both custom-home layouts; deleting either active config denies with the Codex wire contract. | Fixed |
| R18 | PR review found that a canonical empty-file Add operation was rejected as malformed. | Preserve the typed Add mutation with `MutationContent::Full(String::new())` so policy checks still inspect its destination. | Zero-byte Add parser regression plus full mutation suite. | Fixed |
| R19 | PR review reproduced that Claude Bash executions of the file/network canaries emitted only generic command evidence. | Reuse the exact, lookalike-resistant shell-canary classifier for completed Claude and Codex events. | Claude file-read and failed-`.invalid` network-attempt evidence regression plus existing lookalike controls. | Fixed |

## Before-fix receipts

### F01: Codex protected patch bypass

With a freshly installed bundled policy under a temporary home:

```text
sentinel check --json <codex-apply-patch>
rule_action: warn
blocks: false

sentinel evaluate --agent codex < <codex-apply-patch>
stdout: {}
exit: 0
```

### F02: decision-pipeline divergence

For a settings write that preserves Sentinel but adds a malicious SessionStart
autorun:

```text
sentinel check --json <payload>
rule_action: warn
blocks: false

sentinel evaluate --agent codex < <payload>
permissionDecision: deny
exit: 2
```

### F09: doctor false warning

For the freshly installed bundled policy:

```text
level: WARN
message: policy: no self-protect rule for ~/.sentinel/policy.toml
```

## After-fix receipts

### Local release-candidate gates

```text
cargo test --locked --all-targets --all-features -- --test-threads=4
348 unit + 49 integration passed

cargo clippy --locked --all-targets --all-features -- -D warnings
passed

cargo +1.85.0 check --locked --all-targets --all-features
passed

cargo audit
0 vulnerable packages

./scripts/package-smoke.sh
extracted package tests, install, VCS identity, 45/45 verifier, and public commands passed
```

### Installed operator state

```text
sentinel policy-migrate --apply
migrated draft revision 2026-07-28 policy to revision 2026-07-28.1 with backup

sentinel policy-migrate --check
current policy revision 2026-07-28.1

sentinel doctor --agent codex --strict --json
sentinel 0.5.0; healthy: true; activation: active; hook source: ~/.codex/hooks.json; trust: trusted

sentinel doctor --agent claude-code --strict --json
healthy: true; activation: active; hook source: ~/.claude/settings.json; Ghost bridge canary denied
```

### GitHub governance

```text
PR #69: 11/11 checks passed
protect-main ruleset 18708361: PR + resolved conversations + strict required checks; no bypass actor
protect-release-tags ruleset 19889568: v* update/deletion/non-fast-forward denied; no bypass actor
immutable releases: enabled
release environment: required reviewer + v* tag policy; CARGO_REGISTRY_TOKEN absent
Dependabot PRs #52, #53, #54, #56, #63-#68: closed as superseded by #69
```
