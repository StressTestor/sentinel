# sentinel improvement plan

Date: 2026-10-08
Base: `main` at `089e0b8` (sentinel-guard 0.5.0 + unreleased hardening batch)

This is a sequenced engineering plan, not a commitment to ship everything.
Each workstream lists its goal, design, files, acceptance gate, and the
confidence tag on the claim it depends on. Tags: **Solid** (verified in
docs or code this session), **Directional** (shape is right, specifics
need a spike), **Vibes** (unverified; nothing below ships on a Vibes claim).

## what this plan is reacting to

| observation | source | tag |
|---|---|---|
| command enforcement is regex over text plus an argv classifier; assembled commands carry no literal token | README "structural ceiling", `src/policy/matcher.rs` | Solid |
| a PreToolUse hook never sees child processes (npm lifecycle scripts, `python -c` children) | README, ARCHITECTURE.md | Solid |
| 1 true positive in 96 recovered blocks; payload recovery covered 14% of block/warn events | `docs/policy-fp-audit-2026-08.md` | Solid |
| no fuzz or property tests on the hand-written tokenizer, ANSI-C decoder, brace expander (`proptest` was removed in F15) | tree, verification matrix | Solid |
| Claude Code ships an OS-level Bash sandbox (Seatbelt / bubblewrap) with `sandbox.filesystem.denyRead` / `denyWrite`, network domain allowlists, `failIfUnavailable`, `allowUnsandboxedCommands`; it covers shell commands only, and hooks run outside it | code.claude.com/docs/en/sandboxing, settings-reference | Solid |
| PreToolUse hooks can return `hookSpecificOutput.updatedInput`, which replaces the whole tool input object | code.claude.com/docs/en/hooks | Solid |
| `updatedInput` rewriting Bash `command` specifically works | verified live on Claude Code 2.1.295 in the cloud session (see the S4 note): a second PreToolUse hook rewrote `echo S2_ORIGINAL` to `echo S2_REWRITTEN` and the rewritten command ran | Solid |
| Codex PreToolUse supports input modification | could not reach OpenAI docs from this environment | Vibes, do not build on it |

## design principles that do not move

1. Deterministic only. No heuristic or model tier in the decision path.
2. Zero false positives on block rules. Dual-use goes to warn.
3. Local and offline. AD-5 lint stays green.
4. Honest docs. Every new layer gets its own "what it cannot do" paragraph,
   and `scripts/docs-claims-check.sh` keeps numeric claims pinned.
5. User-owned policy. Nothing here rewrites an installed `policy.toml`
   outside `policy-migrate`.

## workstreams

### A. effects floor: bridge the policy into the host sandbox

**Goal.** Close the child-process blind spot without sentinel reading shell.
A credential read that happens inside `npm install`, `python -c`, or a
runtime-assembled command is denied by the kernel, not by a regex.

**Why bridge instead of build.** Claude Code's sandbox already exists, is
maintained upstream (`@anthropic-ai/sandbox-runtime`), uses bubblewrap on
Linux (bind-mount masking, so "deny this subtree" is expressible) and
Seatbelt on macOS (SBPL `deny file-read* (subpath ...)`). A sentinel-owned
Landlock wrapper would have to approximate deny rules through sibling
enumeration because Landlock is allow-list only (Solid: Landlock semantics;
`landlock` crate 0.4.7, ABI v4 TCP port rules from Linux 6.7). That is more
code for a weaker result on the agent that matters most.

**Design.**

- `sentinel install --sandbox` (Claude Code only, opt-in in 0.6.0):
  - compiles the policy's directory-shaped `deny.paths` rules into
    `sandbox.filesystem.denyRead` and `denyWrite` entries. Only rules the
    sandbox can express are compiled (literal paths, `~`-prefixed subtrees,
    `/**` suffixes). Glob-in-middle rules (`/proc/*/environ`, `**/*.kdbx`)
    stay hook-only and are reported as such.
  - sets `sandbox.enabled: true`, `sandbox.failIfUnavailable: true`,
    `sandbox.allowUnsandboxedCommands: false`.
  - adds `~/.sentinel/policy.toml`, `mcp-baseline.json`, the sentinel
    binary path, and `~/.claude/settings.json` to `denyWrite` (self-protect
    at the kernel layer; the hook keeps the content-aware check for the
    agent's own Write/Edit tools, which the sandbox does not cover).
  - reconciles like the hook installer: existing user entries are kept,
    sentinel-owned entries are tagged and replaced, never duplicated.
- `sentinel status` and `doctor --strict` gain a sandbox row: enabled,
  failIfUnavailable, allowUnsandboxedCommands, and a diff between the
  policy's compiled projection and the live `denyRead`/`denyWrite` lists.
  Drift is a doctor failure.
- `selfprotect` learns the sandbox keys: a settings edit that flips
  `sandbox.enabled` to false, sets `allowUnsandboxedCommands: true`, adds
  an `excludedCommands` entry, or removes a sentinel-owned deny entry is a
  block (same escalation rule as hook removal today).
- `policy-migrate --apply` regenerates the projection when rules change.
- `sentinel audit` corpus gains a `v2` case class: a child-process read
  (a script file written then executed, `sh -c` inside `npm run`) that the
  hook cannot see. Verdict logic stays evidence-based; the case documents
  which layer is expected to catch it.

**Fallback track A2 (later, demand-driven).** A `sentinel launch -- <agent>`
Landlock wrapper for agents without a native sandbox (generic, Gemini,
Crush). Whole-process restriction, directory rules only, no network rules
(port-only TCP filtering cannot separate `git push` from `curl` exfil).
Not scheduled until A is shipped and someone asks.

**Files.** `src/install/hooks.rs` (settings reconciliation), new
`src/install/sandbox.rs` (projection compiler), `src/selfprotect/mod.rs`,
`src/doctor/mod.rs`, `src/install/state.rs`, `src/policy_migrate.rs`,
`corpus/v2/`, README + ARCHITECTURE sandbox section.

**Acceptance.**
- Unit: projection compiler table test over every bundled `deny.paths`
  rule: compiled, or listed as hook-only with the reason.
- Integration (`tests/sandbox_install.rs`): clean-home install, reinstall
  idempotence, user entries preserved, uninstall removes only owned entries.
- Self-protect: Write/Edit/`sed -i` fixtures for each weakening edit deny
  with exit 2; a settings edit that keeps all sentinel keys stays warn.
- Live (manual, recorded in this directory): Claude Code 2.1.x with the
  bridge enabled, `bash -c 'cat ~/.ssh/id_rsa'` inside a script file is
  denied by the sandbox with the hook never seeing the read.
- Docs: a "sandbox layer: what it cannot do" paragraph (file tools, MCP
  servers, hooks run outside; Windows unsandboxed; network allowlist is
  domain-level, not content-level).

**Risks.** Hook-before-sandbox ordering is inferred, not documented
(Directional). If the sandbox applies before hooks, nothing changes for
this design, since the hook does not depend on it. Settings schema drift
upstream: pin the key names in a fixture and let `doctor` report unknown
keys rather than fail closed.

### B. make blocks explainable and overridable without disabling the guard

**Goal.** Turn the 95% FP block rate into a loop the operator can close in
seconds, so enforce mode stays on.

**B1. Witness logging.**
- `AuditEvent` gains `rule_id: Option<String>` and `witness: Option<String>`
  (`serde(default)`, `skip_serializing_if`, same compat discipline as
  `call_id`).
- `PolicyDecision` carries the matched candidate: the canonicalized path for
  `deny.paths`, the de-obfuscated command segment for `deny.commands`
  (truncated to 256 chars), the tool name for `deny.tools`. `deny.secrets`
  never logs the match; it logs the rule id only.
- Rule ids: new optional `id` field on every rule struct in
  `src/policy/schema.rs`. Bundled defaults get stable ids
  (`cred-paths/ssh`, `fetch-exec/curl-pipe-sh`). Absent id falls back to
  `<family>:<sha256(pattern)[..8]>` so user rules are addressable too.
- `check --json` prints the same fields. CI parity test: `check` and
  `evaluate` produce identical `rule_id` and `witness` for the verify set.

**B2. `sentinel why`.**
- `sentinel why --last` / `sentinel why <tool_use_id>` reads the audit
  trail, prints rule id, rule text and reason from the installed policy,
  the witness, and the exact overlay line that would downgrade it (B3).
- Read-only. No replay of the payload (not stored by design).

**B3. Accepted project overlays.**
- File: `<project>/.sentinel.toml`. Grammar:
  - `[[downgrade]] rule = "<id>" to = "warn" reason = "..."`
  - `[[allow.paths]]` restricted to patterns under the project root
  - `[[deny.*]]` additions, same schema as the main policy
  - lint rejects any downgrade of a self-protect rule or a block-tier
    `deny.secrets` rule.
- Trust model mirrors the MCP baseline: an overlay is ignored until
  `sentinel policy accept [path]` stores its salted SHA-256 digest in
  `~/.sentinel/overlays.json`. A changed or unaccepted overlay is ignored
  with one stderr line, and `status` lists it. The agent invoking
  `policy accept` is blocked by self-protect (same mechanism as R16 for
  `audit-mcp --update`).
- `evaluate` loads the overlay for the payload `cwd` only. No parent-dir
  walk in v1 (keeps the attack surface to one file whose digest is pinned).

**Files.** `src/audit_trail/mod.rs`, `src/policy/mod.rs`,
`src/policy/schema.rs`, `src/install/defaults.rs` (ids), `src/check/mod.rs`,
new `src/why/mod.rs`, new `src/policy/overlay.rs`, `src/selfprotect/mod.rs`,
`src/lint/mod.rs`, `src/cli.rs`.

**Acceptance.**
- Every bundled rule has a unique id (test), and `policy-migrate` carries
  ids forward for exact-generation policies.
- Overlay tests: unaccepted ignored, accepted applied, digest mismatch
  ignored, self-protect downgrade rejected by lint, agent-driven `accept`
  denied with exit 2, overlay outside `cwd` not loaded.
- A second FP audit (same method as August) after one month of witness
  data. Target is a measurable drop in blocks-per-week on benign work
  without any verify case regressing. The number is the acceptance gate
  for flipping any default in 0.7.0.

### C. test the parsers like an attacker

**C1. Fuzz targets.** `fuzz/` crate with `cargo-fuzz` targets for
`shell_tokens`, `decode_obfuscation`, `brace_expand_checked`,
`parse_apply_patch`, and `evaluate_raw` with the bundled policy. Properties:
no panic, bounded output size, idempotent de-obfuscation
(`decode(decode(x)) == decode(x)`). Nightly CI job, 10 minutes per target,
corpus checked in under `fuzz/corpus/`.

**C2. Differential testing against bash.** A grammar-driven generator
(quotes, backslashes, `$'..'`, `${IFS}`, braces, sequences, nested groups,
`cd` chains with `&&`/`;`/`||`) emits argument fragments. Each fragment is
run as `bash -c 'printf "%s\0" '"$fragment"` under a scratch `HOME`,
`set -f` off, no network, and the resulting words are compared to
sentinel's resolved candidates. Only `printf` ever executes. Divergences
are triaged as bypass (sentinel under-resolves), FP (over-resolves), or
documented non-goal. Runs as an `--ignored` test locally and in the
nightly job. Seeds include the 64 verify cases and the August FP corpus.

**C3. Hook-contract pinning.** `tests/fixtures/hooks/` currently holds
Codex fixtures only. Add version-stamped Claude Code PreToolUse /
PostToolUse / SessionStart payloads (2.1.207 is the last verified
version). A weekly scheduled workflow reads the published
`@anthropic-ai/claude-code` version and opens an issue when it moves past
the pinned one, so re-verification is a tracked task rather than a
surprise.

**Files.** `fuzz/`, `tests/differential_shell.rs`,
`.github/workflows/nightly.yml`, `tests/fixtures/hooks/claude-*.json`.

**Acceptance.** Fuzz targets run clean for the nightly budget; the
differential harness reports zero unexplained divergences on the seed set
before any C2-found bug is fixed, then stays at zero.

### D. rules over a parse, not regex over text

**Goal.** Replace the hand tokenizer with a real bash parser and move the
longest regexes to structured predicates, so a reviewer can read a rule.

**Candidate parser.** `brush-parser` 0.4.0 (MIT, pure Rust, updated
2026-05, from the brush shell). Alternative: `tree-sitter-bash` 0.25.1
(needs a C toolchain, which the MSRV and musl release builds tolerate but
do not love). Decide in spike S3.

**Design.**
- New `src/common/ast.rs`: parse to the crate's AST, walk it into the
  existing `NormalizedToolCall` candidates (command segments, operands,
  `cd` tracking, redirections). The current tokenizer stays as the
  fallback when the parser rejects input, so coverage can only grow.
- New rule shape in `deny.commands`, additive to `pattern`:
  ```toml
  [[deny.commands]]
  id = "fetch-exec/curl-to-shell"
  match = { exec = ["curl","wget","fetch"], output_to_file = true,
            then_exec = ["sh","bash","zsh","source"] }
  action = "block"
  ```
  The predicate vocabulary starts small: `exec`, `has_flag`, `operand_under`,
  `piped_to`, `then_exec`, `interpreter_eval`. Each predicate is a function
  over the AST with its own positive and negative test table.
- Unmodeled constructs (`eval`, command substitution in command position,
  process substitution feeding a modeled tool) produce an explicit
  `Unmodeled` outcome that follows `on_failure`. Scope is narrow on
  purpose: `git commit -m "$(date)"` is an operand, not a command, and
  stays allowed. The FP corpus from B gates this.
- Migrate the five longest regexes first (`defaults.rs` lines 561, 589,
  599, 607, 614 at this base). Keep the regex alongside for one release;
  verify asserts both forms agree on the pinned set, then the regex goes.

**Acceptance.** Parse coverage on the verify set and FP corpus reported as a
number in the PR; zero verify regressions; every migrated rule has a
negative test for its nearest legitimate command (CONTRIBUTING rule, now
enforced by a test that fails when a predicate rule lacks one).

### E. smaller items

- **E1. SessionStart integrity check.** `sentinel session-check` as a
  SessionStart hook: compares binary digest, policy digest, hook entries,
  and (after A) the sandbox projection to the values pinned at install.
  SessionStart cannot block (Solid), so a mismatch is surfaced through
  `additionalContext` and stderr, and `doctor` reports it. Pinned digests
  live in `~/.sentinel/install-state.json`, written by install, denyWrite
  under A.
- **E2. TOCTOU note.** Document that `matches_command` resolves symlinks at
  hook time and a concurrently running process can change them before
  execution. A is the mitigation; without it, this is a residual.
- **E3. Module split.** `src/install/defaults.rs` and
  `src/policy/matcher.rs` are each near 3,000 lines. Split defaults into
  per-family files (`defaults/cred_paths.toml`, `defaults/fetch_exec.toml`,
  ...) concatenated by `include_str!` in a fixed order, each with a sibling
  test table. Pure refactor, verified by a byte-identical
  `default_policy_content()` test before and after.

## spikes (1 PR each, no product code)

| id | question | exit criterion |
|---|---|---|
| S1 | Can bubblewrap/Seatbelt deny rules express every directory-shaped bundled rule? Which rules are hook-only? | table of every bundled `deny.paths` rule: compiled, or hook-only with the reason |
| S2 | Does `updatedInput` rewrite Bash `command`, and does `cd` / `export` persistence survive a wrapped command? | rewrite: answered yes on 2.1.295 (S4 note). `cd` / `export` persistence under a wrapper: still open; only matters for A2 |
| S3 | brush-parser vs tree-sitter-bash: parse coverage on verify set + FP corpus, build cost on MSRV 1.85 and musl | numbers in a doc, decision recorded |
| S4 | Does Claude Code apply the sandbox before or after PreToolUse hooks? | observed ordering with a logging hook |

## sequencing

```
M0  spikes S1, S3, S4                          (parallel, 1 PR each)
M1  B1 witness logging + rule ids + B2 why     (no behavior change; ships first)
M2  C1 fuzz + C2 differential + C3 pinning     (nightly job; fixes land as they appear)
M3  A sandbox bridge, opt-in                   (depends on S1, S4)
M4  B3 accepted overlays                       (depends on B1 ids)
M5  E1 session-check, E3 module split          (E3 can land any time)
M6  D parser + predicate rules                 (depends on S3, C2 harness, B FP corpus)
M7  A2 Landlock launch                         (only on demand)
```

M6 status (first PR, `feat/m6-parser`, 2026-10-09): tree-sitter-bash 0.25.1
with `tree-sitter-language` pinned to 0.1.7 (MSRV 1.85 checks). Parse
coverage, measured by `tests/ast_candidates.rs`: 49/49 Bash commands of the
verify set, 119/119 commands of the 2026-08 FP corpus
(`tests/policy_fp_regression.rs`), 391/400 seeded fragments from the C2
grammar (the 9 rejected all contain an ANSI-C body ending in an escaped
backslash before a later quote, a scanner limit of the grammar; they use the
tokenizer path), 52/55 hand-written shell shapes (the 3 rejected are the
deliberate syntax-error cases). Candidate sets from the parse-backed and
tokenizer path miners are identical on all 623 commands; the known-divergence
table is empty. Vocabulary landed: `exec`, `has_flag`, `operand_under`,
`piped_to`, `then_exec`, `interpreter_eval`. Four bundled regexes carry a
`match` block next to the regex (pipe to shell, staged fetch then run,
interpreter network I/O, interpreter shell execution); over the verify set and
FP corpus the block never fires where the regex does not, 32 of 42 touched
pairs agree, and the 10 regex-only pairs are a shell pipe quoted inside a
Python string, the normalizer's fetched-file execution correlation, and bare
`exec(`/`eval(`/`system(` calls, each listed in `tests/predicate_agreement.rs`.
The subprocess argv rule, the fetch-and-exec co-occurrence rule and the
credential-read rule stay regex-only because `contains` is a disjunction of
substrings and they need a conjunction or an argv-shape needle; widening the
vocabulary for them is the next step, after one release with both forms.
Build cost on the 4-core CI-class box: clean `cargo build --release` 117 s
before, 115 s after (the C grammar compiles in parallel with the Rust
dependencies); release binary 5,122,456 bytes before, 6,703,232 bytes after
(1.58 MB more, the tree-sitter runtime plus the bash parser tables).

Release mapping:
- **0.6.0**: M1, M2, M3 (opt-in), M5. Defaults unchanged.
- **0.7.0**: M4, flip `install` to `--sandbox` by default on Claude Code
  once the second FP audit and a month of sandbox telemetry are in this
  directory. M6 lands when its coverage numbers clear the gate, not on a
  date.

Every milestone that touches a public claim updates README, ARCHITECTURE,
CHANGELOG, and `docs/index.html` in the same PR, and
`scripts/docs-claims-check.sh` is extended to pin any new count.

## non-goals

- Host-level network filtering inside sentinel. The host sandbox's domain
  allowlist is the only network control; sentinel reports its state and
  does not duplicate it.
- Windows.
- Any attempt to see inside a lifecycle script from the hook. The sandbox
  bridge is the answer to that; the hook never will be.
- A second classifier tier of any kind.
