# Changelog

All notable changes to sentinel-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project uses semantic
versioning.

## [0.2.0] - 2026-06-01

Five new subcommands and a supply-chain hardening pass for the default policy.

### Added
- `sentinel check '<hook-json>'` - dry-run a tool call against the installed policy and explain the decision. Prints the matched rule plus the effective outcome in the current mode, so a fresh audit-mode install shows "would be blocked in enforce mode" rather than a bare "Block". Read-only: no execution, no audit logging.
- `sentinel verify` - replay a pinned set of attacks (and benign baselines) through the real evaluate path and assert each behaves as expected. Exits non-zero on any miss, and is wired into CI as a regression gate. Checks the installed policy if present, else the bundled default.
- `sentinel doctor [--strict]` - validate the full install chain (hook entry present, the hooked binary runs and identifies as sentinel, the policy loads, the self-protect rule is present) and probe liveness. Detects a disarmed guard (deleted or repointed hook). Surfaces an audit-to-enforce trust ramp from the audit trail. `--strict` exits non-zero on real failures, never on a healthy idle install.
- `sentinel policy-diff` - print the bundled-default rules missing from an installed policy, as pasteable TOML. Read-only; reaches installs that predate a hardening update (install never overwrites an existing policy).
- `sentinel policy-lint` - static-check a policy for invalid regexes (dead rules), exact-duplicate unreachable patterns, and over-broad allow-list entries.
- shai-hulud / Miasma agent-side hardening rules in the default policy: self-protect of `~/.sentinel/policy.toml`, expanded credential coverage (`~/.npmrc`, `~/.kube/config`, `~/.config/gcloud`, `~/.azure`, plus GCP / Azure / Vault / kubeconfig secret content), and warn-tier tripwires for agent-driven persistence and package-publish TTPs.

### Changed
- Install writes (`~/.claude/settings.json`, `~/.sentinel/policy.toml`) are now atomic: serialize, write a temp file, then rename. A failed write can no longer truncate the real file.

### Fixed
- The `.env` deny rule now uses `**/.env` (and `**/.env.*`) so absolute, deep paths like `/Users/me/app/config/.env` match. The previous `*/.env` only matched a single-segment prefix.

### Notes on scope (honest limits)
- Sentinel intercepts the agent's own tool calls. It does not, and cannot, inspect npm/pip lifecycle-script child processes, so it covers the prompt-injection-drives-the-agent variant of these supply-chain TTPs, not a worm self-propagating.
- Binary-tamper protection is detection (via `doctor` at check time), not prevention: a binary deleted mid-session fails open silently.

## [0.1.0]

- Initial release: PreToolUse policy engine with deny rules for paths (glob), commands (regex), and secrets; audit and enforce modes; fail-closed posture on un-inspectable input; path canonicalization (`~`/`$HOME`/symlink/case); and a prompt-injection attack-corpus audit harness.
