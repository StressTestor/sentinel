# architecture

last updated: 2026-05-22

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
| normalization | html-escape, unicode-normalization | 0.2 / 0.1 |
| context persistence | bincode | 1.x |
| concurrency | fs2 | 0.4 |
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
│   ├── lib.rs              library entry point (re-exports for integration tests)
│   ├── main.rs             CLI entry, subcommand dispatch
│   ├── cli.rs              clap arg definitions
│   ├── common/
│   │   ├── mod.rs
│   │   ├── normalize.rs    shared text normalization (NFKC, entity decode, zero-width stripping)
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
│   │   ├── hook_schema.rs  Claude Code PreToolUse hook JSON schema + richer ToolCall extraction
│   │   └── preflight.rs    workspace manifest inspection for install-like package manager commands
│   ├── install/
│   │   ├── mod.rs          sentinel install / uninstall orchestrator
│   │   ├── hooks.rs        read/merge/write ~/.claude/settings.json
│   │   └── defaults.rs     default policy.toml generator
│   ├── heuristic/
│   │   ├── mod.rs          Tier 2 analyzer + normalized high-confidence merge logic
│   │   ├── automata.rs     aho-corasick pattern compilation
│   │   ├── context.rs      file-backed ring buffer (bincode + flock + atomic rename)
│   │   ├── patterns.rs     DEFAULT_PATTERNS + Mini Shai-Hulud strong-signal sets
│   │   └── sensitivity.rs  Sensitivity enum + threshold mapping
│   ├── classifier/
│   │   └── mod.rs          Tier 3 LLM classifier stub (Ollama/cloud)
│   ├── wrap/
│   │   └── mod.rs          generic pty proxy adapter stub
│   └── audit_trail/
│       └── mod.rs          JSONL event logger
├── tests/
│   ├── fixtures/
│   │   ├── corpus/         attack sequences for audit runner (3 TOML)
│   │   ├── benign/         benign Claude Code sessions for tier 2 FP benchmark (.jsonl)
│   │   ├── fp-stress/      sessions with "broad" phrases in legit context - must trigger (coverage)
│   │   ├── attack-multiturn/  multi-turn attack sequences for tier 2 FN benchmark (.jsonl)
│   │   └── mini-shai-hulud/   worm-shaped persistence/exfil/workflow fixtures (.jsonl)
│   ├── evaluate_process.rs process-level evaluate tests (preflight + enforce behavior)
│   └── tier2_benchmark.rs  FP/FN + fp-stress + Mini Shai-Hulud coverage harness
├── scripts/
│   └── ad5-network-lint.sh  CI lint: no ambient network calls in src/
├── docs/                   live attack demo + github pages site
│   ├── index.html          write-up + attack matrix (published to stresstestor.github.io/sentinel)
│   ├── target.html         poisoned "CloudSync" docs page with classic prompt injections + worm payloads
│   ├── run-attacks.sh      replays classic prompt injections plus Mini Shai-Hulud persistence/install cases
│   ├── run-benign.sh       replays normal maintenance flows that should stay allowed
│   ├── live-demo.cast      asciinema recording of the replay
│   ├── live-demo.gif       animated capture used in README
│   └── record-*.sh         demo recording helpers
└── .github/
    └── workflows/
        └── ci.yml          cargo test + cross-compile
```

## key patterns

### three-tier defense pipeline

```
Tool call arrives (via PreToolUse hook or pty proxy)
     │
     ├── Tier 1: Policy Engine (<1ms)
     │   deterministic TOML rules. deny paths (glob), deny commands (regex),
     │   deny secrets (regex). deny-first evaluation. zero false positives.
     │
     ├── Tier 2: Heuristic Analyzer (<10ms)
     │   normalized matching (NFKC, entity decode, zero-width stripping)
     │   + aho-corasick automata + structured persistence/install/exfil signals.
     │   multi-turn context ring buffer. medium confidence -> Warn.
     │   high-confidence worm signals -> Block when enabled.
     │
     └── Tier 3: LLM Classifier (100-500ms, opt-in)
         secondary model call for ambiguous inputs.
         local Ollama or cloud API. stub implementation.
```

### tier 2 pipeline integration (v0.3 hardening)

tier 2 now sits behind an install-command preflight and receives richer tool context. sequence:

1. `HookInput::to_tool_call()` extracts command, paths, write payload, access type, package-manager family, and install-like command classification.
2. `evaluate::preflight::inspect_workspace(&tool_call)` runs first for install-like package-manager commands. it inspects only likely local manifests (`package.json`, `pyproject.toml`, `setup.py`) in the current workspace or explicit `--prefix` / `-C` roots. high-confidence install hooks block immediately.
3. if preflight passes, tier 1 `PolicyEngine::evaluate(&tool_call)` runs as before.
4. if tier 1 did not already block, build a `HeuristicAnalyzer` from `engine.heuristic_settings().sanitized()`.
5. analyzer input is `tool_call.combined_content()`:
   - bash command
   - write/edit payload when present
   - raw tool params JSON
6. the analyzer runs:
   - normalized matching (HTML entity decode, zero-width stripping, NFKC, lowercase)
   - PromptPressure phrase matching
   - structured Mini Shai-Hulud signal detection for install hooks, `.claude/settings.json`, `.vscode/tasks.json`, workflow abuse, and exfiltration
   - multi-turn context drift scoring
7. merge rules:
   - tier 1 Block: unchanged
   - no heuristic hit: unchanged
   - medium-confidence heuristic hit: Allow -> Warn, Warn -> Warn
   - high-confidence heuristic hit: Allow/Warn -> Block when `block_on_high_confidence = true`
8. ring buffer persisted via `analyzer.save()` before returning.

configuration (`policy.toml`):

```toml
[heuristic]
sensitivity = "medium"   # low (0.7) / medium (0.3) / high (0.15)
window_size = 50
block_on_high_confidence = true
```

ring buffer file at `~/.sentinel/context.bin` is protected by an `fs2` advisory
flock on `~/.sentinel/context.bin.lock` plus atomic temp-file rename on write.
safe under concurrent `sentinel evaluate` processes (multiple Claude Code windows).

### AD-5 enforcement (v0.2)

`scripts/ad5-network-lint.sh` greps `src/` for outbound-network imports
(`reqwest`, `hyper::`, `TcpStream`, `TcpListener`, `UdpSocket`, sibling HTTP
clients). runs in CI before `cargo test`. allowlist is currently empty - grows
as v0.3 (Ollama under `src/classifier/`) and v0.4 (git-sync, audit sinks) add
opt-in network modules.

the lint protects the "100% local, no data leaves your machine" claim from
accidental regressions. default-install outbound network = zero.

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
| policy parse error | refuse to start |
| corpus corruption | fall back to Tier 1 only |
| unknown hook schema | pass-through + warning |
| context file corrupt | reset ring buffer + warning |

## commands

| command | what it does |
|---------|-------------|
| `cargo test` | run all unit + integration tests |
| `cargo test --features proptest` | run property-based tests (slower) |
| `cargo test --test tier2_benchmark` | run tier 2 FP/FN + fp-stress + Mini Shai-Hulud coverage benchmark |
| `cargo build --release` | build optimized binary |
| `cargo clippy` | lint |
| `bash scripts/ad5-network-lint.sh` | AD-5 lint: scan src/ for ambient network calls |
| `sentinel audit --corpus ./tests/fixtures/corpus --sandbox degraded` | test audit with fixture corpus |
| `sentinel install` | install PreToolUse hook (audit mode) |
| `sentinel install --enforce` | install with enforcement |
| `sentinel uninstall` | remove hooks |
| `sentinel status` | show config + hooks |
| `SENTINEL=./target/release/sentinel ./docs/run-attacks.sh` | replay classic prompt injections plus Mini Shai-Hulud cases from docs/target.html through the hook layer |
| `SENTINEL=./target/release/sentinel ./docs/run-benign.sh` | replay normal maintenance tasks that should stay allowed |

## publishing

- crate name: `sentinel-guard` (binary is still `sentinel`). `sentinel` was taken on crates.io.
- installed via `cargo install sentinel-guard`.
- github pages site served from `docs/index.html` at stresstestor.github.io/sentinel.
