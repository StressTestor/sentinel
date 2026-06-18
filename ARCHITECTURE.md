# architecture

last updated: 2026-06-16

## overview

sentinel is a runtime defense tool for CLI AI agents. it intercepts tool calls before execution and enforces security policy. the engine is agent-agnostic; per-agent adapters translate each host's hook contract. the primary adapter hooks into Claude Code's PreToolUse system via `~/.claude/settings.json`; `evaluate --agent <name>` also speaks OpenAI Codex CLI (byte-for-byte the same nested output), Gemini CLI / Crush (`{"decision":"deny"}`), and a generic exit-code contract for any command-hook agent. a block always also exits 2, the universal hard-block signal. (a pty proxy for agents with no hook at all is intentionally unbuilt — it would see terminal bytes, not structured tool calls.)

## stack

| layer | technology | version |
|-------|-----------|---------|
| language | Rust | 2021 edition |
| CLI | clap | 4.x |
| serialization | serde, toml, serde_json | 1.x |
| async runtime | tokio | 1.x |
| regex | regex | 1.x |
| text normalization | unicode-normalization, html-escape | 0.1 / 0.2 |
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
│   │   ├── normalize.rs    encoded-text normalization (HTML-entity decode, Unicode format-char strip, NFKC) — secret path only
│   │   ├── shell.rs        shell de-obfuscation (ANSI-C $'\xHH' escapes, ${IFS} desugar, brace expansion) — path/command path
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
│   │   ├── mod.rs          sentinel evaluate entry (stdin JSON -> policy -> selfprotect -> preflight -> stdout JSON); --canary dry-run for doctor
│   │   └── hook_schema.rs  Claude Code PreToolUse hook JSON schema; command extraction incl. exec-named MCP tools; explicit `cwd` field
│   ├── selfprotect/
│   │   └── mod.rs          content-aware escalation: block a config write that removes sentinel's hook OR injects a malicious autorun command (hook / MCP server) across any agent + MCP config (JSON/TOML)
│   ├── preflight/
│   │   └── mod.rs          install-preflight: on an install-like command, resolve the effective install dir (follow literal cd / --prefix) and inspect that package.json's lifecycle scripts + dep sources for the worm TTP
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
│   ├── post_evaluate/
│   │   └── mod.rs          sentinel post-evaluate: PostToolUse result-secret detection + nudge (opt-in, detection only)
│   ├── audit_mcp/
│   │   └── mod.rs          sentinel audit-mcp: read-only TOFU enumerator of configured MCP servers (flags new/changed launch commands)
│   ├── install/
│   │   ├── mod.rs          sentinel install / uninstall orchestrator
│   │   ├── hooks.rs        read/merge + atomic (temp+rename) write of ~/.claude/settings.json
│   │   └── defaults.rs     default policy.toml generator
│   ├── wrap/
│   │   └── mod.rs          generic pty proxy adapter stub
│   └── audit_trail/
│       └── mod.rs          JSONL event logger
├── tests/
│   └── fixtures/
│       └── corpus/         test attack sequences (3 TOML files)
├── scripts/
│   └── ad5-network-lint.sh AD-5 lint: greps src/ for outbound-network imports
│                           outside the allowlist (src/audit only); CI gate
├── docs/                   live attack demo + github pages site
│   ├── index.html          write-up + attack matrix (published to stresstestor.github.io/sentinel)
│   ├── target.html         poisoned "CloudSync" docs page with 20+ embedded injections
│   ├── run-attacks.sh      replays every injection through `sentinel evaluate`
│   ├── live-demo.cast      asciinema recording of the replay
│   ├── live-demo.gif       animated capture used in README
│   └── record-*.sh         demo recording helpers
└── .github/
    └── workflows/
        └── ci.yml          AD-5 lint + cargo test + verify gate + cross-compile
```

## key patterns

### defense pipeline

Sentinel is **one deterministic tier, by design**. There is no heuristic scoring
and no ML in the decision path. The engine is the whole product: every decision
is a rule you can read, not a confidence number. If the policy engine does not
catch something, it is not caught, and that is a property you can reason about.

(History: the project was scaffolded with a Tier-2 aho-corasick heuristic
analyzer and a Tier-3 LLM classifier stub. Both were removed. The heuristic
tier's drift signal only ever fired on calls Tier 1 already blocked, and a model
in the hot path would break both the zero-false-positive promise and the
local/offline guarantee. The 3 deterministic checks worth keeping from the
heuristic branch were extracted into Tier 1 before it was archived.)

```
Tool call arrives (via PreToolUse hook)
     │
     └── Policy Engine  [the only tier; runs on every call]
         tool input -> ToolCall (command + canonicalized paths, extracted for
         every tool type, not just "Bash"; paths are ALSO mined from the
         shell-de-obfuscated command). deny-first evaluation:
           - deny tools: glob over the tool NAME (e.g. `mcp__evil__*`), so an MCP
             server/tool can be blocked/warned by name. opt-in (no default rule).
           - deny paths: glob, with ~ / $HOME / symlink / case canonicalization,
             recursive directory coverage, glob-candidate de-globbing, and brace
             expansion ({a,b} -> both real files)
           - deny commands: regex over the raw + an rm-flag-canonicalized form +
             a shell-de-obfuscated form (ANSI-C $'\xHH' escapes, ${IFS} desugar),
             covering pipe-to-shell / fetch-exec / exfil variants
           - deny secrets: regex over the raw request payload AND a normalized
             form (HTML-entity decode, Unicode format-char strip — the full Cf
             set incl. bidi isolates/ALM plus the whole TAG block — NFKC fold),
             so an entity-encoded / format-char-injected / fullwidth-spelled
             token can't dodge the rule. additive: raw is checked first, never
             replaced. normalized once per evaluate, reused across all rules.
         ORDERING: a deny.paths WARN is held, not returned immediately, so a
         deny.commands BLOCK overrides it (rm of settings.json, curl of .env).
         deny.secrets is consulted only when nothing else matched, preserving
         "a secret in a warn-tier path stays warn" (the .env case).
         SCOPE: `common/shell` de-obfuscation handles transforms the shell
         actually resolves (ANSI-C/IFS/brace). Unicode homoglyph/fullwidth
         folding is deliberately NOT applied to commands/paths — the shell never
         resolves `ｃat` or `/ｅtc/passwd` to a real target, so folding them would
         only add false positives. `common/normalize` (Unicode/entity) stays
         scoped to the secret-content path, where the consumer DOES decode it.
         un-inspectable input (empty / unparseable stdin) fails per on_failure
         ("closed" by default → deny). zero false positives by design.
```

> Honesty note: the policy engine is the line of defense. Treat anything it does
> not catch as not caught. There is no second layer to fall back on, and that is
> deliberate - a deterministic block you can audit beats a probabilistic one you
> can't.

### default policy coverage

`install/defaults.rs` generates the default `policy.toml`. Beyond the baseline
(credential paths, recursive deletion, pipe-to-shell, secret patterns) it ships a
shai-hulud / Miasma supply-chain hardening pack, organized by honesty tier:

- **block (zero-FP):** self-protect of `~/.sentinel/policy.toml` and the `sentinel`
  binary install paths (`~/.cargo/bin`, `~/.local/bin`, `/usr/local/bin`,
  `/opt/homebrew/bin`); binary tamper-by-name (`rm "$(command -v sentinel)"`);
  expanded credential paths (`~/.npmrc`, `~/.kube/config`, `~/.config/gcloud/`,
  `~/.azure/`) and secret content (GCP service-account, Azure storage/SAS, Vault,
  kubeconfig key); curl/wget data-exfil whose payload is a command substitution,
  an `@file`, a secret-looking env var, or an upload flag (`-T`/`--upload-file`/
  `--post-file`), plus `>/dev/tcp` and `nc <file`.
- **warn (dual-use tripwires):** plain `curl/wget --data`/`-d` (common in API
  testing); writes to other agents' hook configs (`.claude/settings*.json`,
  `~/.codex`, `~/.gemini`, `.vscode/tasks.json`), CI workflows
  (`.github/workflows/*` - auto-run-on-push + secrets/OIDC surface), LaunchAgent /
  systemd-user persistence units, project-local `kubeconfig`, and
  `npm/pnpm/yarn/bun publish` / `npm token` / `gh repo create --public`.

Round-two attacker-audit additions (block unless noted): broadened credential
stores (docker/podman auth, git-credentials, HF/crates tokens, pgpass/my.cnf,
rclone/oci/doctl/fly/databricks/terraform, macOS user+system Keychains, all major
browser profile data, 1Password/Bitwarden/pass/KeePass, crypto wallets, editor
`state.vscdb`); exfil with no network pipe (`gpg --export-secret-keys`, `security
dump-keychain`/`find-*-password -w`, `dscl -read … Password`; env-to-file /
secret-`printenv` / `git credential fill` / `defaults read` secret-name = warn);
guard-disarm via `chmod`/`chflags`/`strip`/`truncate`/`install`/redirect on the
binary, `sentinel uninstall`, `rm ~/.claude`|`~/.sentinel`, and shell rewrites of
`settings.json` (`sed -i`/redirect/`tee`); egress channels (DNS command-sub query
block + TXT/ANY warn, git credential-in-URL block + literal-URL push warn,
scp/rsync/rclone/cloud-upload warn, curl glued-flag exfil block, secret-in-URL/
header warn); interpreter runtime-path credential reads.

The matcher also fail-safes a **glob-bearing candidate path**: a path that itself
carries shell glob metacharacters (`~/.s*h/id_rsa`, `~/.ss[h]/id_rsa`) is projected
onto a deny rule's literal prefix and matched, so a candidate the shell would expand
onto a protected target can't dodge the anchored rule. Hook-removal protection
(`src/selfprotect/`) runs after policy evaluation: a Write/Edit/MultiEdit to
`.claude/settings(.local).json` that drops the `sentinel evaluate` hook escalates
warn → block; hook-preserving edits keep their policy action. The Bash-child form
of the same disarm (`sed -i`/redirect/`tee` rewriting settings.json) — which
selfprotect's content check cannot see — is covered by deny.commands rules
instead. `sentinel check` applies the same `selfprotect` + `preflight` escalations
as the live `evaluate` path, so its dry-run can't under-report the live hook.

### install-preflight (worm TTP)

`src/preflight/` runs immediately after self-protect on the evaluate path. A
PreToolUse hook cannot see npm/pip lifecycle scripts — they run in a child
process of `npm install`, which never crosses the hook. The one point the hook
CAN act is when the **agent itself** runs an install-like command. At that moment
preflight reads the top-level `package.json` in the call's `cwd` and inspects it.

- **trigger** (the only thing that does any I/O): the command is an install-like
  invocation at a command position — `npm install|i|ci|add`, `pnpm install|i|add`,
  bare `yarn` / `yarn install|add`, `bun install|add`. NOT `npm run`/`test`/
  `publish`/`ls`, `npx`, or a package-manager name appearing as an argument
  (`echo npm install`). `cwd` is plumbed as an explicit field on `HookInput`
  (Claude Code sends it; it previously only landed in `_extra`).
- **signals inspected:** ONLY the `scripts` lifecycle values (`preinstall`,
  `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`) and the
  dependency **version specifiers**. NEVER `repository`/`homepage`/`funding`/
  `author` URLs — matching those was the abandoned tier-2 branch's false positive
  (it did `contains("https://")` over the whole manifest, so any repo URL + a
  postinstall got blocked).
- **BLOCK** (near-zero FP): a lifecycle script value that fetches-and-executes
  remote code — `curl|wget|fetch` piped to a shell, `$(curl…)`/backtick-curl,
  `base64 -d | sh`, an interpreter (`node -e`/`python -c`/…) doing a network
  fetch+exec, `eval` of fetched content, or a fetch from a raw IP. Conceptually
  mirrors the curl/fetch deny.commands in the default policy, but applied ONLY to
  the script string.
- **WARN** (medium): a dependency whose version specifier is a raw URL /
  `git+http(s)` / `git://` / tarball / IP host AND a lifecycle script is present.
  Registry semver, `workspace:`, `file:`, `npm:` aliases, and `github:owner/repo`
  shorthand are trusted.
- **ALLOW** (no warn-spam): everything else, including ordinary lifecycle scripts
  (`husky install`, `node-gyp rebuild`, `node scripts/build.js`) with registry
  deps. cwd absent, manifest missing, or manifest unparseable → do nothing (you
  cannot block a normal install over a manifest you can't read). Escalation is
  one-directional (Block > Warn > Allow); an existing Block is never downgraded.

> **Honest limit, by design:** preflight inspects ONLY the top-level manifest in
> the command's cwd. It CANNOT see a poisoned **transitive** dependency's
> lifecycle script — those resolve during the install, not in the top-level
> package.json. So it catches the agent writing/installing a manifest whose OWN
> lifecycle script is malicious, or a direct dep added from a suspicious
> non-registry source. It does NOT catch the worm arriving via a poisoned
> transitive dep. Pure core (`inspect`/`is_install_like`) is unit-tested without
> the filesystem; the `apply` wrapper does the cwd read.
>
> **Second honest limit:** preflight resolves the directory the install actually
> runs in by following a single literal `cd <dir>` or cwd flag
> (`--prefix`/`-C`/`--cwd`/`--dir`) off the session cwd. What it will not do is
> guess at a directory it cannot prove: a non-literal target (a shell variable, a
> glob, a command substitution) or more than one directory change makes the
> install dir ambiguous, so preflight skips rather than inspect a manifest it
> can't be sure is the right one. Skipping errs toward not blocking a normal
> install, never toward reading an attacker-chosen manifest. So the residual is
> "in an ambiguous case I see no manifest", not "I can be pointed at the wrong
> one".

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
     └── stdout (deny):  { "hookSpecificOutput": { "hookEventName": "PreToolUse",
     │                       "permissionDecision": "deny", "permissionDecisionReason": ... } }
     │                    AND exit code 2 — the universal hard-block signal, honored
     │                    even if the JSON shape is ignored (belt-and-suspenders
     │                    against the 0.2.0 silent-death). `--agent generic|gemini`
     │                    emit `{"decision":"block|deny",...}` instead; exit 2 is the
     │                    constant across every adapter.
     └── stdout (allow): {}   (no decision → defer to Claude Code's normal flow)
```

> Gotcha: Claude Code only honors a PreToolUse block via the **nested**
> `hookSpecificOutput.permissionDecision` form above. A flat top-level
> `permissionDecision` (pre-0.2.1) is silently ignored — the policy decides and
> the audit log records `block`, but the tool call runs anyway. Allow/warn emit
> an empty object on purpose: emitting `permissionDecision: "allow"` would
> auto-approve every un-blocked call instead of deferring to the normal prompt.
> `tests/hook_contract.rs` pins this wire shape end-to-end through the real binary.

installed by `sentinel install` which writes hook config to `~/.claude/settings.json`.
the hook entry uses `matcher: ".*"` to intercept all tool types.
idempotent: running install twice doesn't duplicate hooks.

### audit mode vs enforce mode

- **enforce** (default): actively block tool calls that match deny rules. a
  security tool that ships in log-only mode protects nobody.
- **audit** (`--audit`): log what WOULD be blocked, don't actually block. for
  watching first. `status` prints a warning whenever enforcement is off.

`sentinel install` never overwrites an existing `~/.sentinel/policy.toml`
(`write_default_policy` returns wrote/skipped), so upgrading an audit-mode user
never silently flips them to enforce.

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
| `bash scripts/ad5-network-lint.sh` | AD-5 lint: fail if outbound-network imports appear in src/ outside the allowlist (src/audit) |
| `sentinel audit --corpus ./tests/fixtures/corpus --sandbox degraded` | test audit with fixture corpus |
| `sentinel install` | install PreToolUse hook (enforce mode, the default) |
| `sentinel install --audit` | install in audit mode (log only) |
| `sentinel uninstall` | remove hooks |
| `sentinel check '<hook-json>'` | dry-run a tool call against the policy and explain the decision (read-only) |
| `sentinel verify [--policy <file>]` | replay a pinned attack set through the policy, assert each is caught; non-zero exit on miss (CI gate) |
| `sentinel doctor [--strict] [--json]` | validate the install chain (hook entry, binary runs, policy loads, self-protect rule) + probe liveness; the canary spawns the hooked binary as `evaluate --canary` and asserts its own deny (catches a no-op shim that fakes `--version`), without polluting the audit trail; `--strict` exits non-zero on any failure |
| `sentinel policy-diff [--policy <file>]` | print bundled-default rules missing from an installed policy, for manual paste (read-only; reaches users who installed before a hardening update) |
| `sentinel policy-lint [--policy <file>]` | static-check a policy: invalid regexes (dead rules), exact-duplicate/unreachable patterns, over-broad allow entries; non-zero exit on an error-level finding |
| `sentinel status` | show config + hooks |
| `SENTINEL=./target/release/sentinel ./docs/run-attacks.sh` | replay 20+ injections from docs/target.html through the hook layer |

CI runs the AD-5 network-call lint (`scripts/ad5-network-lint.sh` — enforces the README's "no ambient network calls" claim by grepping src/ for reqwest/hyper/Tcp\*/Udp\*/bollard imports outside the `src/audit` allowlist) and `cargo run -- verify` as an attack-regression gate, alongside `cargo test` + `cargo clippy -- -D warnings` (see `.github/workflows/ci.yml`).

## publishing

- crate name: `sentinel-guard` (binary is still `sentinel`). `sentinel` was taken on crates.io.
- installed via `cargo install sentinel-guard`.
- github pages site served from `docs/index.html` at stresstestor.github.io/sentinel.

---

last updated: 2026-06-16 by StressTestor (tier gut: removed the unwired Tier-2 heuristic analyzer (`src/heuristic/`) and Tier-3 LLM classifier stub (`src/classifier/`) plus their heuristic-only deps (`aho-corasick`, `bincode`); sentinel is now one deterministic tier by design, no dead scaffolding in the tree. v0.4.0: exit-2 second enforcement channel; multi-agent adapters via `evaluate --agent` (claude-code/codex/gemini/crush/generic) + `install --agent` host snippets; `post-evaluate` PostToolUse result-secret detection (opt-in); `deny.tools` name-match + `audit-mcp` TOFU enumerator; autorun-injection guard generalized across every agent + MCP config (JSON/TOML); install-preflight follows the effective install dir (literal cd / --prefix). two octo-debate passes drove the autorun-injection generalization + preflight install-dir resolution. prior round-two attacker-audit hardening: enforce-by-default install with --audit opt-out + non-overwrite blast-radius guard; held-warn engine ordering so a deny.commands BLOCK overrides a deny.paths WARN; shell de-obfuscation (ANSI-C/IFS/brace) wired into path extraction + command matching; broadened credential stores, no-network-pipe exfil, guard-disarm (binary tamper verbs, sentinel uninstall, config-dir deletion, shell settings-strip), DNS/git/egress channels, interpreter runtime-path cred reads; sentinel check now mirrors selfprotect+preflight; verify gate 20 -> 41 cases. prior: install-preflight review pass: newline counts as a command boundary in the install trigger — multi-line commands no longer evade it; documented the session-cwd manifest limit (cd/--prefix installs read a manifest preflight did not inspect); prior pass: on an install-like command, inspect <cwd>/package.json lifecycle scripts + dep sources for the worm fetch-exec TTP — top-level manifest only, never transitive deps; explicit `cwd` field on HookInput; wired after self-protect on the evaluate path; prior pass: encoded-secret normalization — full Unicode Cf + TAG-block strip, computed once per evaluate, secret path only; warn-tier tripwire for `.github/workflows/*`; AD-5 network-call lint added as a CI gate; red-team hardening — glob-candidate matcher fix, curl/wget data-exfil rules, binary self-protect, content-aware hook-removal block, authoritative doctor canary, exec-named MCP command extraction)
