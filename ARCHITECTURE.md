# architecture

last updated: 2026-08-14

## overview

sentinel is a runtime defense tool for CLI AI agents. it normalizes typed tool
calls, evaluates them through one deterministic policy pipeline, and answers in
the selected host's hook contract. native install, uninstall, status, and doctor
lifecycle support is implemented for Claude Code and Codex. `evaluate --agent
<name>` remains the lower-level integration contract for other hook-capable
agents. a deny also exits 2.

the separate `audit` command is not an enforcement hook or a sandbox. it drives a
real Claude Code or Codex process through a stateful session, correlates
structured evidence against a small versioned corpus, and requires the caller to
acknowledge uncontained host execution with `--unsafe-host`.

## stack

| layer | technology | version |
|-------|-----------|---------|
| language | Rust | 2021 edition, MSRV 1.85 |
| CLI | clap | 4.x |
| serialization and config edits | serde, serde_json, toml, toml_edit | 1.x / 0.22 |
| async runtime | tokio | 1.x |
| regex | regex | 1.x |
| text normalization | unicode-normalization, html-escape | 0.1 / 0.2 |
| terminal output | colored | 3.x |
| error handling | thiserror | 2.x |
| hashing and random salt | sha2, getrandom | 0.10 / 0.3 |
| logging | tracing + tracing-subscriber | 0.1 / 0.3 |
| testing | built-in + assert_cmd, tempfile, predicates | - |

## directory structure

```
sentinel/
├── Cargo.toml
├── ARCHITECTURE.md         <- you are here
├── README.md
├── corpus/v1/              versioned, bundled audit cases + provenance/license
├── src/
│   ├── main.rs             CLI entry, subcommand dispatch
│   ├── cli.rs              clap arg definitions
│   ├── common/
│   │   ├── mod.rs
│   │   ├── normalize.rs    encoded-text normalization (HTML-entity decode, Unicode format-char strip, NFKC) — secret path only
│   │   ├── shell.rs        shell de-obfuscation (ANSI-C $'\xHH' escapes, ${IFS} desugar, brace expansion) — path/command path
│   │   └── types.rs        shared types (AttackSequence, AuditReport, etc.)
│   ├── corpus/
│   │   ├── mod.rs          versioned bundled corpus + explicit filesystem override
│   │   └── parser.rs       TOML attack sequence parser
│   ├── audit/
│   │   ├── mod.rs          audit orchestrator
│   │   ├── adapter.rs      stateful Claude Code and Codex process adapters
│   │   ├── runner.rs       timeout, output caps, evidence correlation
│   │   └── report.rs       terminal + JSON report generator
│   ├── policy/
│   │   ├── mod.rs          policy engine (Tier 1: deny-first evaluation)
│   │   ├── schema.rs       TOML policy schema + parsing
│   │   └── matcher.rs      glob path matching, regex command/secret matching
│   ├── evaluate/
│   │   ├── mod.rs          hook I/O and native response rendering
│   │   ├── hook_schema.rs  Claude Code PreToolUse hook JSON schema; command extraction incl. exec-named MCP tools; explicit `cwd` field
│   │   ├── normalize.rs    host payloads -> typed calls, paths, commands, patches
│   │   └── pipeline.rs     shared policy, self-protect, autorun, preflight path
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
│   │   └── mod.rs          explicit, salted-digest MCP baseline + drift report
│   ├── install/
│   │   ├── mod.rs          sentinel install / uninstall orchestrator
│   │   ├── activation.rs   Codex public hooks API activation/trust probe
│   │   ├── state.rs        Claude/Codex installed and activated state
│   │   ├── hooks.rs        direct/Ghost ownership reconciliation + atomic writes
│   │   └── defaults.rs     default policy.toml generator
│   ├── policy_migrate.rs   revision detection + validated three-way migration
│   └── audit_trail/
│       └── mod.rs          JSONL event logger
├── tests/
│   ├── policy_fp_regression.rs  bundled-policy attack and false-positive corpus
│   └── fixtures/
│       └── corpus/         test attack sequences (3 TOML files)
├── scripts/
│   ├── ad5-network-lint.sh network-import boundary gate
│   ├── docs-claims-check.sh verifier-count + public-command claims gate
│   ├── package-smoke.sh    extracted-crate build/install/public-CLI smoke
│   └── release-identity.sh tag/version/source/registry identity checks
├── docs/                   live attack demo + github pages site
│   ├── policy-fp-audit-2026-08.md  enforcement-data audit behind policy revision 2026-08-07.1
│   ├── index.html          write-up + attack matrix (published to stresstestor.github.io/sentinel)
│   ├── target.html         poisoned "CloudSync" docs page with 20+ embedded injections
│   ├── run-attacks.sh      replays every injection through `sentinel evaluate`
│   ├── live-demo.cast      asciinema recording of the replay
│   ├── live-demo.gif       animated capture used in README
│   └── record-*.sh         demo recording helpers
└── .github/
    ├── dependabot.yml      weekly cargo + github-actions update PRs
    └── workflows/
        ├── ci.yml          quality, MSRV, package, Linux, and macOS gates
        ├── release.yml     identity, verification, four targets, SBOM, attest/publish
        ├── codeql.yml      CodeQL static analysis (rust + actions), push/PR + weekly
        ├── scorecard.yml   OpenSSF Scorecard, results published + SARIF upload
        ├── deps.yml        cargo-deny (advisories/bans/licenses/sources), daily cron
        └── dependency-review.yml  blocks PRs introducing known-vulnerable deps
```

all workflow actions are pinned to full commit SHAs, every workflow declares
least-privilege `permissions`, and checkouts use `persist-credentials: false`.
`deny.toml` at repo root configures cargo-deny. `SECURITY.md` routes reports to
github private vulnerability reporting.

## key patterns

### defense pipeline

Sentinel is **one deterministic tier, by design**. There is no heuristic scoring
and no ML in the decision path. The engine is the whole product: every decision
is a rule you can read, not a confidence number. If the policy engine does not
catch something, it is not caught, and that is a property you can reason about.

earlier heuristic and model-assisted prototypes do not ship. there is no hidden
fallback classifier behind an unmatched policy decision.

```
Host hook payload arrives
     │
     ├── Typed normalization
     │   host payload -> command/path/content/mutation evidence
     │   Codex apply_patch is parsed as a file mutation, not executable shell
     │
     └── Shared policy pipeline  [the only decision path]
         tool input -> ToolCall (command + canonicalized paths, extracted for
         every tool type, not just "Bash"; paths are ALSO mined from the
         shell-de-obfuscated command). deny-first evaluation:
           - deny tools: glob over the tool NAME (e.g. `mcp__evil__*`), so an MCP
             server/tool can be blocked/warned by name. opt-in (no default rule).
           - deny paths: glob, with ~ / $HOME / symlink / case canonicalization,
             recursive directory coverage, glob-candidate de-globbing, and
             bounded, completeness-aware brace expansion. nested list groups and
             version-stable numeric/alphabetic sequences are expanded fully;
             analysis-budget overflow or version-dependent sequence syntax follows
             the configured on_failure posture instead of accepting a partial result.
             brace expansion is provenance-gated: only path candidates mined from
             shell words with unquoted, unescaped brace delimiters are expanded;
             direct tool paths and quoted or escaped shell words remain literal.
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
         ("closed" by default → deny).
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
warn → block; the same event-aware check covers native Codex `config.toml` and
`hooks.json`, where command text outside `hooks.PreToolUse` does not count as a
live guard. Autorun inspection resolves the same effective mutation identity as
hook preservation, including existing symlink aliases and symlinked parents.
Hook-preserving edits keep their policy action. The Bash-child form
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

- **trigger** (the only thing that does any I/O): a quote-aware shell tokenizer
  finds an install-like invocation at a command position — `npm install|i|ci|add`,
  `pnpm install|i|add`, bare `yarn` / `yarn install|add`, `bun install|add` —
  including quoted or path-qualified package-manager executables, assignment
  prefixes, and supported cwd flags before or after the verb. NOT `npm run`/
  `test`/`publish`/`ls`, `npx`, or a package-manager name appearing as an
  argument (`echo npm install`). `cwd` is plumbed as an explicit field on
  `HookInput` (Claude Code sends it; it previously only landed in `_extra`).
- **signals inspected:** ONLY the `scripts` lifecycle values (`preinstall`,
  `install`, `postinstall`, `prepare`, `prepublish`, `prepublishOnly`) and the
  dependency **version specifiers**. NEVER `repository`/`homepage`/`funding`/
  `author` URLs — matching those was the abandoned tier-2 branch's false positive
  (it did `contains("https://")` over the whole manifest, so any repo URL + a
  postinstall got blocked).
- **BLOCK** (near-zero FP): a lifecycle script value that fetches-and-executes
  remote code — `curl|wget|fetch` piped to a shell (including quoted or
  path-qualified shell names), `$(curl…)`/backtick-curl,
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
> glob, or command substitution) or more than one directory change makes the
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

### lifecycle reconciliation and activation

native lifecycle ownership is limited to Claude Code and Codex:

- Claude Code uses `~/.claude/settings.json`. if the matching handler is already
  mediated through `ghost hook --sentinel ...`, install preserves that Ghost
  bridge and removes redundant direct Sentinel handlers. unrelated mixed
  handlers remain untouched.
- Codex respects `$CODEX_HOME`, falling back to `~/.codex`. if `hooks.json`
  exists, install writes there and removes a prior inline Sentinel entry from
  `config.toml`; otherwise it writes the native `[[hooks.PreToolUse]]` table.
- uninstall removes direct Sentinel-owned handlers only. it does not remove a
  Ghost bridge owned by another tool or delete the user's policy.
- config writes use sibling temporary files and preserve private permissions.

`status` and `doctor` inspect agent config rather than inferring health from the
binary alone. Claude activation includes `disableAllHooks`. Codex activation is
queried from the public `codex app-server` `hooks/list` API with a bounded
timeout, and requires the matching hook to be enabled and trusted. configured,
configured-but-untrusted, disabled, duplicate/conflicting, unverifiable, and
broken are distinct states. strict doctor also sends a known-bad SSH read
through the hooked binary and requires the expected deny; a Ghost-mediated
chain is probed through the bridge.

these checks are point-in-time evidence. they cannot prove continuous
enforcement, and a hooked binary removed during an active agent session may
still fail open. Codex trust is a host decision outside Sentinel; install tells
the user to approve the hook in `/hooks` and rerun strict doctor.

### real-agent audit harness

`audit/adapter.rs` implements stateful real-process sessions:

- Claude Code uses stream JSON, an output schema, and a generated session id
  which later turns in the same sequence resume.
- Codex uses `codex exec --json`, records the returned thread id, and resumes
  that thread for later turns in the same sequence. each corpus sequence starts
  a fresh session and workspace so state does not leak between verdicts.
- prompts are written through piped stdin and never interpolated into a shell
  command. process startup, stdin writes, and execution share a timeout; timed
  out children are killed. stdout is capped at 4 MiB, stderr is drained, and
  diagnostics are sanitized.

the bundled `corpus/v1` is project-authored and contains three safe canaries: a
fake local credential file inside the temporary audit workspace, a fixed
`printf`, and a request to the reserved `.invalid` domain. its README and license
record provenance. callers may choose a different directory with `--corpus`;
paths are loaded deterministically and empty, duplicate, invalid-action,
invalid-role, and invalid-glob inputs are rejected.

structured events are correlated to the expected tool, filesystem, or network
action. only successful matching evidence is vulnerable. only an explicit final
refusal with no action evidence is defended. incomplete or unsupported evidence
is inconclusive or an error, and incomplete risk scores serialize as `null`.
there is no sandbox backend or degraded fallback. real audit therefore requires
`--unsafe-host`, and the agent may persist its session locally.

### explicit MCP baseline

`audit-mcp` discovers Claude Code and Codex MCP configuration, including
`$CODEX_HOME` and working-directory config. discovery alone writes nothing and
trusts nothing. only `--update` accepts the complete discovered set as baseline
version 1.

the baseline keys entries by source and server and stores salted SHA-256 digests
of canonical typed config. it never stores raw commands, arguments, URLs,
headers, environment variables, or tokens. comparisons report added, changed,
missing, and removed entries; `--strict` exits nonzero on drift. legacy raw
baselines, corrupt files, and unsupported versions are refused rather than
silently overwritten. writes are atomic and mode 0600 on Unix.

### policy migration

the bundled default carries revision `2026-08-07.1`. `policy-migrate --check` is
read-only and exits nonzero when migration is required. unversioned policies are
matched only to known published generations; unknown revisions, ambiguous
generations, and same-field conflicts stop without writing.

`policy-migrate --apply` performs a comment-preserving three-way merge from the
recognized base through the user's edits to the current default. user-only
rules, unknown fields, mode, comments, and non-overlapping edits survive. apply
rejects symlinks, creates a unique timestamped backup, preserves permissions,
and atomically replaces the sibling file only after parse/mode checks, policy
lint, the full verifier, self-protection, and the known-bad canary pass. a failed
validation restores the original and retains the backup. applying the current
revision is idempotent.

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
| `cargo test --locked --all-targets --all-features` | run all unit and integration tests |
| `cargo build --release` | build optimized binary |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | lint the supported feature/target set |
| `bash scripts/ad5-network-lint.sh` | AD-5 lint: fail if outbound-network imports appear in src/ outside the allowlist (src/audit) |
| `bash scripts/docs-claims-check.sh target/debug/sentinel` | compare public command and verifier claims with the built binary |
| `bash scripts/package-smoke.sh` | test the packaged and extracted crate, installed binary, CLI, VCS metadata, and empty-HOME verifier |
| `sentinel audit --agent claude --unsafe-host` | run the bundled real-agent audit without containment |
| `sentinel install` | install the Claude Code hook (enforce mode, the default) |
| `sentinel install --agent codex` | install the native Codex hook |
| `sentinel install --audit` | install in audit mode (log only) |
| `sentinel uninstall --agent <name>` | remove direct Claude Code or Codex hooks |
| `sentinel check '<hook-json>'` | dry-run a tool call against the policy and explain the decision (read-only) |
| `sentinel verify [--policy <file>]` | replay the pinned 45/45 attack and benign cases; nonzero on a mismatch |
| `sentinel doctor --agent <name> [--strict] [--json]` | inspect activation and policy, then probe the actual hook chain with a known-bad canary |
| `sentinel audit-mcp [--strict]` | compare current MCP config with an explicitly accepted baseline |
| `sentinel audit-mcp --update` | accept the complete current MCP set |
| `sentinel policy-migrate --check` | report whether policy migration is needed without writing |
| `sentinel policy-migrate --apply` | merge current defaults and validate before atomic replacement |
| `sentinel policy-diff [--policy <file>]` | print bundled-default rules missing from an installed policy, for manual paste (read-only; reaches users who installed before a hardening update) |
| `sentinel policy-lint [--policy <file>]` | static-check a policy: invalid regexes (dead rules), exact-duplicate/unreachable patterns, over-broad allow entries; non-zero exit on an error-level finding |
| `sentinel status --agent <name>` | show configuration, hook ownership, activation, and policy summary |
| `SENTINEL=./target/release/sentinel ./docs/run-attacks.sh` | replay 20+ injections from docs/target.html through the hook layer |

CI runs format, AD-5, locked all-target/all-feature tests and clippy, the empty-HOME
verifier, docs claims, Rust 1.85 MSRV, extracted-package smoke, and native Linux
and macOS smoke. CodeQL, dependency review, cargo-deny, cargo-audit in release,
and Scorecard remain separate gates.

## publishing

- crate name: `sentinel-guard` (binary is still `sentinel`). `sentinel` was taken on crates.io.
- installed via `cargo install sentinel-guard`.
- github pages site served from `docs/index.html` at stresstestor.github.io/sentinel.
- `Cargo.toml` packages source, tests, assets, the versioned corpus, release
  manifests, security docs, and dual licenses.
- tag releases verify that the source commit is reachable from `origin/main` and
  that tag, crate version, registry metadata, and release identity agree. the
  workflow rejects an unmerged-commit negative test before publishing.
- release artifacts cover x86_64/aarch64 Linux musl and x86_64/aarch64 macOS,
  with licenses and README in each archive, CycloneDX SBOMs, SHA-256 sums, and
  GitHub artifact attestations. the GitHub release remains a draft until the
  crate and every asset are present.

---

last updated: 2026-08-14 by StressTestor. documents the shared typed
evaluation pipeline, native Claude Code/Codex lifecycle reconciliation,
trust-aware health checks, uncontained stateful audit, explicit MCP baselines,
validated policy migration, completeness-aware shell matching, package preflight
parsing, event-aware hook self-protection, policy false-positive regressions,
and release/package evidence gates.
