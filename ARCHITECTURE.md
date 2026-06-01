# architecture

last updated: 2026-06-01

## overview

sentinel is a runtime defense tool for CLI AI agents. it intercepts tool calls before execution and enforces security policy. the primary adapter hooks into Claude Code's PreToolUse system via `~/.claude/settings.json`. a generic pty proxy adapter covers agents without native hooks.

## stack

| layer | technology | version |
|-------|-----------|---------|
| language | Rust | 2021 edition |
| CLI | clap | 4.x |
| serialization | serde, toml, serde_json | 1.x |
| docker API | bollard | 0.19 |
| async runtime | tokio | 1.x |
| pattern matching | aho-corasick | 1.x |
| regex | regex | 1.x |
| context persistence | bincode | 1.x |
| terminal output | colored | 2.x |
| error handling | thiserror, anyhow | 2.x / 1.x |
| logging | tracing + tracing-subscriber | 0.1 / 0.3 |
| testing | built-in + assert_cmd, tempfile, predicates | - |

## directory structure

```
sentinel/
├── Cargo.toml
├── ARCHITECTURE.md         <- you are here
├── README.md
├── src/
│   ├── main.rs             CLI entry, subcommand dispatch
│   ├── cli.rs              clap arg definitions
│   ├── common/
│   │   ├── mod.rs
│   │   └── types.rs        shared types (AttackSequence, AuditReport, etc.)
│   ├── corpus/
│   │   ├── mod.rs          corpus loader (embedded + filesystem override)
│   │   └── parser.rs       TOML attack sequence parser
│   ├── audit/
│   │   ├── mod.rs          audit orchestrator
│   │   ├── sandbox.rs      sandbox trait + backend detection
│   │   ├── runner.rs       attack sequence executor
│   │   └── report.rs       terminal + JSON report generator
│   ├── policy/
│   │   ├── mod.rs          policy engine (Tier 1: deny-first evaluation)
│   │   ├── schema.rs       TOML policy schema + parsing
│   │   └── matcher.rs      glob path matching, regex command/secret matching
│   ├── evaluate/
│   │   ├── mod.rs          sentinel evaluate entry (stdin JSON -> policy -> stdout JSON)
│   │   └── hook_schema.rs  Claude Code PreToolUse hook JSON schema
│   ├── check/
│   │   └── mod.rs          sentinel check: dry-run/explain a tool call (read-only)
│   ├── verify/
│   │   └── mod.rs          sentinel verify: pinned attack regression set (CI gate)
│   ├── doctor/
│   │   └── mod.rs          sentinel doctor: install-chain validation + liveness probe
│   ├── policy_diff/
│   │   └── mod.rs          sentinel policy-diff: default rules missing from a policy (read-only)
│   ├── lint/
│   │   └── mod.rs          sentinel policy-lint: dead-rule / bad-regex / broad-allow checks
│   ├── install/
│   │   ├── mod.rs          sentinel install / uninstall orchestrator
│   │   ├── hooks.rs        read/merge + atomic (temp+rename) write of ~/.claude/settings.json
│   │   └── defaults.rs     default policy.toml generator
│   ├── heuristic/
│   │   ├── mod.rs          Tier 2 heuristic analyzer
│   │   ├── automata.rs     aho-corasick pattern compilation
│   │   └── context.rs      file-backed ring buffer (bincode)
│   ├── classifier/
│   │   └── mod.rs          Tier 3 LLM classifier stub (Ollama/cloud)
│   ├── wrap/
│   │   └── mod.rs          generic pty proxy adapter stub
│   └── audit_trail/
│       └── mod.rs          JSONL event logger
├── tests/
│   └── fixtures/
│       └── corpus/         test attack sequences (3 TOML files)
├── docs/                   live attack demo + github pages site
│   ├── index.html          write-up + attack matrix (published to stresstestor.github.io/sentinel)
│   ├── target.html         poisoned "CloudSync" docs page with 20+ embedded injections
│   ├── run-attacks.sh      replays every injection through `sentinel evaluate`
│   ├── live-demo.cast      asciinema recording of the replay
│   ├── live-demo.gif       animated capture used in README
│   └── record-*.sh         demo recording helpers
└── .github/
    └── workflows/
        └── ci.yml          cargo test + cross-compile
```

## key patterns

### defense pipeline

Enforcement today is **Tier 1 only**. Tiers 2 and 3 exist in the tree but are
not wired into the `evaluate` hot path — see status below.

```
Tool call arrives (via PreToolUse hook)
     │
     └── Tier 1: Policy Engine  [ACTIVE — runs on every call]
         tool input -> ToolCall (command + canonicalized paths, extracted for
         every tool type, not just "Bash"). deny-first evaluation:
           - deny paths: glob, with ~ / $HOME / symlink / case canonicalization
             and recursive directory coverage
           - deny commands: regex over the raw + a normalized form (rm-flag
             canonicalization), covering pipe-to-shell / fetch-exec variants
           - deny secrets: regex over the request payload
         un-inspectable input (empty / unparseable stdin) fails per on_failure
         ("closed" by default → deny). zero false positives by design.

   Tier 2: Heuristic Analyzer  [IMPLEMENTED, NOT WIRED]
         aho-corasick over the PromptPressure corpus + a file-backed multi-turn
         context buffer. `src/heuristic/` is complete but has no call site on
         the evaluate path. Wiring it needs a concurrency-safe context buffer
         (parallel hooks race on the ring-buffer file) and a false-positive
         budget. Tracked as a follow-up.

   Tier 3: LLM Classifier  [PLANNED — interface stub]
         `src/classifier/` defines the interface; `classify()` returns None.
         not implemented.
```

> Honesty note: the policy engine (Tier 1) is the line of defense. The earlier
> "three-tier defense" framing oversold tiers 2/3 — they're scaffolding, not
> active mitigations. Treat anything Tier 1 doesn't catch as not caught.

### default policy coverage

`install/defaults.rs` generates the default `policy.toml`. Beyond the baseline
(credential paths, recursive deletion, pipe-to-shell, secret patterns) it ships a
shai-hulud / Miasma supply-chain hardening pack, organized by honesty tier:

- **block (zero-FP):** self-protect of `~/.sentinel/policy.toml`; expanded
  credential paths (`~/.npmrc`, `~/.kube/config`, `~/.config/gcloud/`, `~/.azure/`)
  and secret content (GCP service-account, Azure storage/SAS, Vault, kubeconfig key).
- **warn (dual-use tripwires):** writes to other agents' hook configs
  (`.claude/settings*.json`, `~/.codex`, `~/.gemini`, `.vscode/tasks.json`),
  LaunchAgent / systemd-user persistence units, project-local `kubeconfig`, and
  `npm/pnpm/yarn/bun publish` / `npm token` / `gh repo create --public`.

Structural limit, by design: the PreToolUse hook only sees the agent's own tool
calls. The worm's real payload runs in npm/pip lifecycle-script child processes,
which never traverse the hook, so this pack covers the prompt-injection-drives-the-
agent variant of the TTPs, not the worm self-propagating. The secret rules sit
**after** the private-key rule so a GCP SA file (which matches both) blocks via the
key rule rather than downgrading to the GCP-SA warn; an assembled-policy test in
`install/defaults.rs` pins that ordering.

### Claude Code adapter (PreToolUse hook)

```
Claude Code decides to use a tool
     │
     ├── PreToolUse hook fires
     │   stdin: { tool_name, tool_input, ... }
     │
     ├── sentinel evaluate reads stdin JSON
     │   parses tool call, extracts paths/commands
     │   evaluates against policy.toml
     │
     └── stdout: { permissionDecision: "allow" | "deny" }
```

installed by `sentinel install` which writes hook config to `~/.claude/settings.json`.
the hook entry uses `matcher: ".*"` to intercept all tool types.
idempotent: running install twice doesn't duplicate hooks.

### audit mode vs enforce mode

- **audit** (default): log what WOULD be blocked, don't actually block. builds trust.
- **enforce**: actively block tool calls that match deny rules.

### failure modes

| failure | behavior |
|---------|----------|
| sentinel crash | fail-closed (configurable to open) |
| policy parse / load error | deny (can't make a safe decision) |
| empty / unparseable / unreadable stdin | per `on_failure`: deny when "closed" (default), allow+warn when "open" |
| policy file absent | deny |

## commands

| command | what it does |
|---------|-------------|
| `cargo test` | run all unit + integration tests |
| `cargo test --features proptest` | run property-based tests (slower) |
| `cargo build --release` | build optimized binary |
| `cargo clippy` | lint |
| `sentinel audit --corpus ./tests/fixtures/corpus --sandbox degraded` | test audit with fixture corpus |
| `sentinel install` | install PreToolUse hook (audit mode) |
| `sentinel install --enforce` | install with enforcement |
| `sentinel uninstall` | remove hooks |
| `sentinel check '<hook-json>'` | dry-run a tool call against the policy and explain the decision (read-only) |
| `sentinel verify [--policy <file>]` | replay a pinned attack set through the policy, assert each is caught; non-zero exit on miss (CI gate) |
| `sentinel doctor [--strict] [--json]` | validate the install chain (hook entry, binary runs, policy loads, self-protect rule) + probe liveness; detects a disarmed guard; `--strict` exits non-zero on any failure |
| `sentinel policy-diff [--policy <file>]` | print bundled-default rules missing from an installed policy, for manual paste (read-only; reaches users who installed before a hardening update) |
| `sentinel policy-lint [--policy <file>]` | static-check a policy: invalid regexes (dead rules), exact-duplicate/unreachable patterns, over-broad allow entries; non-zero exit on an error-level finding |
| `sentinel status` | show config + hooks |
| `SENTINEL=./target/release/sentinel ./docs/run-attacks.sh` | replay 20+ injections from docs/target.html through the hook layer |

CI runs `cargo run -- verify` as an attack-regression gate alongside `cargo test` + `cargo clippy -- -D warnings` (see `.github/workflows/ci.yml`).

## publishing

- crate name: `sentinel-guard` (binary is still `sentinel`). `sentinel` was taken on crates.io.
- installed via `cargo install sentinel-guard`.
- github pages site served from `docs/index.html` at stresstestor.github.io/sentinel.

---

last updated: 2026-06-01 by StressTestor (release v0.2.0: check/verify/doctor/policy-diff/policy-lint + Miasma hardening)
