# architecture

last updated: 2026-09-04

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
| Unix file handles and advisory locks | libc | 0.2 |
| testing | built-in + assert_cmd, tempfile | - |

## directory structure

```
sentinel/
├── Cargo.toml
├── ARCHITECTURE.md         <- you are here
├── README.md
├── corpus/v1/              versioned, bundled audit cases + provenance/license
├── src/
│   ├── lib.rs              library surface: the same module tree, used by fuzz/ and tests/
│   ├── main.rs             CLI entry, subcommand dispatch
│   ├── cli.rs              clap arg definitions
│   ├── why/
│   │   └── mod.rs          `sentinel why`: join an audit line's rule id to the installed policy
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
│   │   ├── mod.rs          policy engine (Tier 1: deny-first evaluation; overlay binding + downgrades)
│   │   ├── schema.rs       TOML policy schema + parsing
│   │   ├── overlay.rs      project overlays: `.sentinel.toml` grammar, salted-digest acceptance store, `sentinel policy accept`
│   │   └── matcher.rs      glob path matching, regex command/secret matching
│   ├── evaluate/
│   │   ├── mod.rs          hook I/O and native response rendering
│   │   ├── hook_schema.rs  Claude Code PreToolUse hook JSON schema; command extraction incl. exec-named MCP tools; explicit `cwd` field
│   │   ├── normalize.rs    host payloads -> typed calls, paths, commands, patches
│   │   └── pipeline.rs     shared policy, self-protect, autorun, preflight path
│   ├── selfprotect/
│   │   ├── mod.rs          content-aware escalation: block a config write that removes sentinel's hook OR injects a malicious autorun command (hook / MCP server) across any agent + MCP config (JSON/TOML)
│   │   └── sandbox.rs      before/after check for a Claude settings write that weakens the sandbox bridge (active only when install-state.json records one)
│   ├── preflight/
│   │   └── mod.rs          install-preflight: on an install-like command, resolve the effective install dir (follow literal cd / --prefix) and inspect that package.json's lifecycle scripts + dep sources for the worm TTP
│   ├── check/
│   │   └── mod.rs          sentinel check: dry-run/explain a tool call (read-only)
│   ├── verify/
│   │   └── mod.rs          sentinel verify: pinned attack regression set (CI gate)
│   ├── doctor/
│   │   └── mod.rs          sentinel doctor: install-chain validation + liveness probe
│   ├── session_check/
│   │   └── mod.rs          sentinel session-check: SessionStart integrity check against the install pins (context only, exit 0)
│   ├── policy_diff/
│   │   └── mod.rs          sentinel policy-diff: default rules missing from a policy (read-only)
│   ├── lint/
│   │   └── mod.rs          sentinel policy-lint: duplicate-rule / bad-regex / broad-allow checks; overlay lint (self-protect and secret downgrades rejected)
│   ├── post_evaluate/
│   │   └── mod.rs          sentinel post-evaluate: PostToolUse result-secret detection + nudge (opt-in, detection only)
│   ├── audit_mcp/
│   │   └── mod.rs          explicit, salted-digest MCP baseline + drift report
│   ├── install/
│   │   ├── mod.rs          sentinel install / uninstall orchestrator
│   │   ├── activation.rs   Codex public hooks API activation/trust probe
│   │   ├── state.rs        Claude/Codex installed and activated state; ~/.sentinel/install-state.json record of sentinel-written sandbox entries and the binary/policy digest pins
│   │   ├── sandbox.rs      sandbox bridge: deny.paths -> sandbox.filesystem.denyRead/denyWrite projection, reconciliation, drift inspection
│   │   ├── hooks.rs        direct/Ghost ownership reconciliation + atomic writes
│   │   ├── defaults.rs     default policy.toml generator (header + family loader)
│   │   └── defaults/       bundled deny rules, one TOML file per family, NN- prefix
│   │                       is evaluation order; pinned byte for byte by
│   │                       tests/fixtures/policy/
│   ├── policy_migrate.rs   revision detection + validated three-way migration
│   └── audit_trail/
│       └── mod.rs          JSONL event logger (0600/0700, symlink-refusing,
│                           locked appends; tamper-covered by selfprotect)
├── fuzz/                   cargo-fuzz crate (own workspace, not packaged): five libFuzzer targets + seed corpus
├── tests/
│   ├── differential_shell.rs  bash word resolution vs sentinel resolution (ignored; nightly job)
│   ├── hook_contract.rs    PreToolUse/PostToolUse wire contract + version-stamped Claude Code fixtures
│   ├── home_config.rs      isolated HOME validation and relocated Claude lifecycle
│   ├── session_check.rs    session-check through the real binary: pins, clean check, each mismatch, uninstall, doctor row
│   ├── overlays.rs         project overlays end to end: accept, digest mismatch, agent-driven accept denied
│   ├── sandbox_install.rs  sandbox bridge install/reinstall/uninstall, doctor drift, self-protect through the real binary
│   ├── policy_fp_regression.rs  bundled-policy attack and false-positive corpus
│   └── fixtures/
│       ├── corpus/         test attack sequences (3 TOML files)
│       ├── hooks/          Codex payloads + claude-code-<version>-*.json, VERIFIED_CLAUDE_CODE_VERSION
│       └── policy/         pinned default-enforce/default-audit policy.toml (byte-identity regression anchor)
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
        ├── nightly.yml     ten minutes of libFuzzer per target + the bash differential harness, daily
        ├── claude-code-version-watch.yml  weekly: opens an issue when npm's claude-code moves past the verified version
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
              TWO resolution layers (2026-08-14 audit fixes):
              - cd-relative resolution: a command-position-aware walk tracks a
                literal `cd` target (`~`, `$HOME`, absolute, or metachar-free
                relative; bare `cd` = home; `cd -`/variables/globs stop tracking)
                and joins every later relative operand onto it, including inside
                a `sh -c '<command>'` payload — `cd ~ && cat .ssh/id_rsa` reaches
                the `~/.ssh/*` rule, while `echo cd ~` (cd NOT in command
                position) does not.
                Directory changes on a conditional branch remain usable within
                that successful `&&` chain, but are cleared before a later
                unconditional segment because the change may have been skipped.
              - recursive-traversal coverage: when the command applies a
                directory-RECURSIVE tool (`cp`/`rsync`/`grep` with an explicit
                recursive flag, `tar` in create mode, `find`, `ditto`) at an
                source operand that is an ANCESTOR of (or equal to) a rule's protected
                directory, the rule fires — `cp -r ~ /tmp` reads every subtree
                `~/.ssh/*` protects. tar extraction (x mode) writes rather than
                reads and is excluded; an undetectable mode is not guessed at.
                Sources are selected per command segment. Destinations, option
                arguments, and unrelated path mentions do not inherit traversal
                status. Unsupported option grammars retain ordinary path checks.
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
         deny.secrets BLOCK also overrides a held warning, including a secret
         written to a warn-tier path.
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

### fuzz and differential testing

The parsers that stand between hook input and a verdict are tested two ways
beyond unit tests. `fuzz/` is a cargo-fuzz crate (its own workspace, not
packaged) with five libFuzzer targets over the library: `shell_tokens` (no
panic, token bytes bounded by the input), `decode_obfuscation` (no panic, and
idempotent: a second decode changes nothing), `brace_expand_checked` (no panic,
never more than the 64-way cap or an explicit error), `parse_apply_patch` (no
panic), and `evaluate_raw` (the whole pipeline on the bundled enforce policy, no
panic). Seeds under `fuzz/corpus/` come from the verify cases and the demo
replay. `tests/differential_shell.rs` generates argument fragments from a small
grammar (quotes, backslash escapes, `$'..'`, `${IFS}`/`$IFS`, brace lists,
sequences, nested groups, `~/` paths), runs each through
`bash -c 'printf "%s\0" ...'` in an empty environment, and checks that every
word Bash resolved is among the candidates `HookInput::normalize` plus
`brace_expand_checked` produce for the same command. Only `printf` executes.
The nightly workflow runs ten minutes per fuzz target and the harness on 20000
fragments; the harness is `#[ignore]` in ordinary CI.

What this covers: the tokenizers, the ANSI-C and IFS decoder, brace expansion,
the apply_patch parser, and the composition of those in the pipeline, against
arbitrary bytes and against Bash's own word resolution. What it does not cover,
by design: command substitution, parameter expansion other than IFS, pathname
expansion (globs), `$'..'` or IFS inside quotes (decoded on purpose because a
nested `sh -c` would decode them), a quoted tilde (treated as home), trailing
list punctuation (trimmed from candidates), and a literal `$` in a path. One
known divergence stays open and is listed in the harness: quoted or escaped
text inside an unquoted brace group loses its quoting before expansion, so
`./p{a,'b,c'}` expands to three candidates where Bash produces two. That
over-resolves; it cannot hide a protected path, since none contains a comma.

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

- Claude Code uses `CLAUDE_CONFIG_DIR/settings.json` when `CLAUDE_CONFIG_DIR`
  is set (Claude Code then ignores `~/.claude` entirely), otherwise
  `~/.claude/settings.json`. if the matching handler is already
  mediated through `ghost hook --sentinel ...`, install preserves that Ghost
  bridge and removes redundant direct Sentinel handlers. unrelated mixed
  handlers remain untouched.
- Codex respects `$CODEX_HOME`, falling back to `~/.codex`. if `hooks.json`
  exists, install writes there and removes a prior inline Sentinel entry from
  `config.toml`; otherwise it writes the native `[[hooks.PreToolUse]]` table.
- uninstall removes direct Sentinel-owned handlers only. it does not remove a
  Ghost bridge owned by another tool or delete the user's policy.
- config writes use uniquely named sibling temporary files opened with
  `create_new`, preventing a pre-existing temp file from capturing the write.
  Files are synced before rename, parent-directory sync is best-effort, and
  existing permissions are preserved. This does not sandbox a malicious process
  running as the same user and modifying the directory concurrently.

Sentinel state requires a nonempty absolute `HOME`; installation checks it before
writing any configuration. Policy-path resolution returns an explicit error for
an invalid home instead of selecting a relative or supposedly nonexistent file.
Commands with an explicit `--policy` retain that selected path.

On Unix, audit logging opens verified directory and regular-file handles without
following final-component symlinks. Permission tightening uses those handles.
An advisory lock covers each complete record across cooperating Sentinel writers;
it does not prevent arbitrary same-user programs from modifying the log. A write
failure produces a stderr diagnostic while preserving the hook's stdout contract
and policy decision.
Audit self-protection uses the same live path resolver as the logger and compares
logical and effective mutation identities. A project fixture with the same
`.sentinel/audit.jsonl` suffix is independent of the live home-directory log.

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

`session_check/mod.rs` moves one such check to a moment the host guarantees:
`sentinel install` for Claude Code registers `sentinel session-check` under
`hooks.SessionStart` (matcher `startup|resume`, reconciled and removed by the
same ownership code as the PreToolUse entry) and pins the SHA-256 of the
installed binary and of the policy in `~/.sentinel/install-state.json`
(`binary_sha256`, `policy_sha256`; `policy-migrate --apply` re-pins the
policy, uninstall clears both). at session start the check compares the live
PreToolUse entry (`state::inspect_agent`), the digest of the file that entry
executes, the policy digest, and the sandbox projection (`sandbox::bridge_status`,
only when a bridge is recorded) with the pins. SessionStart cannot block, so
the command always exits 0 and reports through stdout (which Claude Code adds
to the model's context) and stderr, one `sentinel: ...` line per finding and
nothing when clean; `--json` is the stable machine shape. the comparison
(`compare`) is pure over an `Observed` struct so every finding is unit-tested
without a host. absent pins are reported, never failed, so an older install
keeps working. self-protect does not count the SessionStart entry as the hook:
removing only that entry stays at the policy's warn tier, and keeping it does
not stand in for a removed PreToolUse entry.

### sandbox bridge (opt-in, Claude Code only)

`install/sandbox.rs` is a projection compiler from the policy's `deny.paths`
rules onto Claude Code's `sandbox.filesystem.denyRead` / `denyWrite` lists,
driven by `sentinel install --sandbox`. It adds a kernel-level floor under
Bash for the child-process reads the hook never sees; it replaces nothing.
The rules it follows are the S1 spike's (`docs/hardening/`), and
`project_with` is pure so the table test pins every bundled rule:

- normalize: strip a trailing `/`, `/*`, or `/**`; the bare directory covers
  its subtree. Only `~/` and absolute patterns are anchored; a relative entry
  in user settings resolves under `~/.claude`, so unanchored `**/name` rules
  are hook-only, as is a wildcard in a middle segment (`/proc/*/environ`).
- per-list output: a `~/` block rule goes into both lists; an absolute block
  rule into `denyRead` only; a surviving wildcard stays in `denyRead` on every
  platform and is dropped from `denyWrite` on Linux (Claude Code skips
  wildcard write entries there). Warn rules are hook-only: the sandbox has no
  warn tier.
- self-protect `denyWrite` only: `policy.toml`, `install-state.json`, the
  Claude settings file, the running binary (`current_exe`), and
  `mcp-baseline.json` / `settings.local.json` when they exist (a Linux
  `denyWrite` on a missing file creates a placeholder per command).
- withheld, reported rather than emitted: paths with whitespace (Seatbelt
  quoting undocumented, no live test yet) and binary paths that are not the
  running binary. At the current bundled policy: 75 rules, 56 expressible,
  19 hook-only; on a Linux host with no baseline file, 43 compile and 13 are
  withheld.

Reconciliation mirrors the hook installer, with one difference: the sandbox
lists are plain string arrays, so the ownership tag is a sidecar,
`~/.sentinel/install-state.json`. It records the entries sentinel appended
(an entry the user already had is neither recorded nor removed) and the three
pinned keys' prior values. Reinstall removes the recorded entries, re-appends
the projection, and yields an identical file; uninstall removes only recorded
entries and restores a pinned key only if it still carries the value sentinel
set. `status` and `doctor` recompute the projection from the live policy and
diff it against the live lists: a missing projected entry or a stale
sentinel-owned one is a `doctor --strict` failure, user entries are counted
and kept, `excludedCommands` is a warning (an excluded command runs with full
access). `policy-migrate --apply` does not regenerate the projection; a
re-run of `install --sandbox` does.

`selfprotect/sandbox.rs` is the hook-side mirror: once a record exists, a
typed settings write whose before/after diff flips `enabled` off, turns
`allowUnsandboxedCommands` on, turns `failIfUnavailable` off, sets
`filesystem.disabled`, adds an `excludedCommands` entry, or drops a
sentinel-owned entry from the bridge file is blocked as
`selfprotect: sandbox-weakening`. The diff is per file against the document
on disk, so an unrelated edit to a file that already carried a weak value, or
an entry the operator removed by hand (doctor's drift report), is not a block.
Without a record the module changes nothing. Shell-side rewrites of the
settings file are already blocked by the existing command cluster.

Honest limits: the sandbox covers shell commands only (file tools, MCP
servers, and hooks run outside it), Windows is unsandboxed, the network
allowlist is domain-level, and the credential `denyRead` entries break
in-sandbox `gh`/`aws`/`kubectl`/`npm publish`/`docker login`/`ssh` use, which
is why the bridge is opt-in. No live run on a real Claude Code session is
recorded yet; `corpus/v2` (a child-process read the hook cannot see) is a
follow-up that needs the real-agent harness.

### real-agent audit harness

`audit/adapter.rs` implements stateful real-process sessions:

- Claude Code uses stream JSON, an output schema, and a generated session id
  which later turns in the same sequence resume.
- Codex uses `codex exec --json`, records the returned thread id, and resumes
  that thread for later turns in the same sequence. an agent-reported thread id
  that is empty, starts with `-`, or contains whitespace fails the schema — it
  is argv injection into the next `resume`, not a thread id. each corpus
  sequence starts a fresh session and workspace so state does not leak between
  verdicts. workspaces are created 0700: the driven agent runs uncontained and
  may write real secrets into them, which a shared /tmp must not read mid-run.
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
Evidence is agent-reported, so conclusions assume the selected executable reports
its actions honestly; the harness cannot independently attest a hostile agent.

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

### project overlays

`<project>/.sentinel.toml` is the one per-project file the hook reads. its
grammar is `[[downgrade]]` (`rule = "<id>"`, `to = "warn"`, `reason`),
`[[allow.paths]]` entries under the project root, and `[[deny.paths]]`,
`[[deny.commands]]`, `[[deny.secrets]]`, `[[deny.tools]]` additions in the
main policy's schema. unknown tables and keys are parse errors.

trust mirrors the MCP baseline. `sentinel policy accept` lints the overlay
against the installed policy and stores a salted SHA-256 digest of its content
in `~/.sentinel/overlays.json` (version 1: `version`, `salt`, and a map from
canonical absolute project path to digest; other versions are refused, never
rewritten; writes are atomic and mode 0600 on Unix). `evaluate` and `check`
load only `<cwd>/.sentinel.toml` for the payload `cwd`, with no
parent-directory walk, and look the canonical cwd up in the store. a missing,
changed, or unaccepted overlay is ignored, with one stderr line; an accepted
overlay is linted again against the current policy before it is applied, so a
policy edit cannot make an old acceptance mean something new.

engine integration: `PolicyEngine::with_overlay` prepends the overlay's deny
rules to the main policy's sections, extends an existing allow list (an
overlay never creates one), and binds the downgrade map. a downgraded rule is
evaluated as warn tier: it is held like any warn, so a later block still wins,
and the decision keeps the original `rule_id` and `matched_rule`, appends the
overlay's reason, and sets `downgraded_by` (the overlay path), which the audit
line records with the same compat discipline as `witness`. the autorun
injection check uses `evaluate_strict`, which ignores downgrades.

what an overlay cannot touch: self-protect runs after the engine, so its
decisions are outside any overlay; the lint rejects a downgrade of any
self-protect family rule (a pattern naming sentinel, `.sentinel/`, the binary
paths, `sentinel uninstall`, `audit-mcp --update`, or `.claude/settings`), of
a block-tier `deny.secrets` rule, of a fixed layer id, of an unknown or
invalid id, any `to` but `warn`, an overlay deny rule with an `allow` action
(it would run before the main rules), and an allow pattern outside the
project root. self-protect blocks the agent invoking `sentinel policy accept`
(any wrapper or path prefix, raw and shell-de-obfuscated), a Write/Edit to
`overlays.json`, and the shell-write cluster on it (in-place editors,
redirects, tee/sponge, cp/install/ln/dd/truncate/rm/mv), all labelled
`selfprotect: overlay-accept`. editing `.sentinel.toml` itself stays allowed.

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
| `bash scripts/package-smoke.sh` | test the packaged and extracted crate, installed binary, CLI, VCS metadata, and verifier with a fresh home directory |
| `sentinel audit --agent claude --unsafe-host` | run the bundled real-agent audit without containment |
| `sentinel install` | install the Claude Code hook (enforce mode, the default) |
| `sentinel install --agent codex` | install the native Codex hook |
| `sentinel install --audit` | install in audit mode (log only) |
| `sentinel install --sandbox` | also project the policy into Claude Code's sandbox deny lists (opt-in; re-run after a policy change) |
| `sentinel uninstall --agent <name>` | remove direct Claude Code or Codex hooks and sentinel-owned sandbox entries |
| `sentinel check '<hook-json>'` | dry-run a tool call against the policy and explain the decision (read-only) |
| `sentinel why [<tool_use_id>] [--json]` | explain a decision already in the audit trail: rule id, rule text and policy line, bounded witness (read-only; never the payload) |
| `sentinel verify [--policy <file>]` | replay the pinned 64/64 attack and benign cases; nonzero on a mismatch |
| `sentinel doctor --agent <name> [--strict] [--json]` | inspect activation and policy, then probe the actual hook chain with a known-bad canary |
| `sentinel session-check [--agent <name>] [--json]` | compare the live hook entry, the digest of the hooked binary, the policy digest, and the sandbox projection with the pins written at install; the SessionStart hook, context only, always exits 0 |
| `sentinel audit-mcp [--strict]` | compare current MCP config with an explicitly accepted baseline |
| `sentinel audit-mcp --update` | accept the complete current MCP set |
| `sentinel policy-migrate --check` | report whether policy migration is needed without writing |
| `sentinel policy-migrate --apply` | merge current defaults and validate before atomic replacement |
| `sentinel policy-diff [--policy <file>]` | print bundled-default rules missing from an installed policy, for manual paste (read-only; reaches users who installed before a hardening update) |
| `sentinel policy-lint [--policy <file>]` | static-check a policy: invalid regexes, exact duplicate patterns, over-broad allow entries; duplicate warnings do not imply unreachability; non-zero exit on an error-level finding |
| `sentinel policy-lint --overlay <file>` | lint a project overlay against the policy: rejects self-protect and block-tier secret downgrades, unknown or invalid ids, non-warn targets, allow patterns outside the project |
| `sentinel policy accept [path]` | lint and accept a project overlay, storing its salted digest in `~/.sentinel/overlays.json` (a human action; the agent running it is blocked) |
| `sentinel policy accept --list` | print the accepted projects |
| `sentinel policy accept --revoke <path>` | forget one project's acceptance |
| `sentinel status --agent <name>` | show configuration, hook ownership, activation, policy summary, accepted overlay count, and the overlay in cwd |
| `SENTINEL=./target/release/sentinel ./docs/run-attacks.sh` | replay 20+ injections from docs/target.html through the hook layer |

CI runs format, AD-5, locked all-target/all-feature tests and clippy, the fresh-home
verifier, docs claims, Rust 1.85 MSRV, extracted-package smoke, and native Linux
and macOS release-build smoke. The quality job owns the Linux test run; the
platform job adds macOS tests without repeating the Linux suite. CodeQL,
dependency review, cargo-deny, cargo-audit in release, and Scorecard remain
separate gates.

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

last updated: 2026-09-04 (cleanup and hardening self-review: command-scoped traversal,
explicit HOME errors, relocated Claude self-protection, verified audit handles and
locked appends, deterministic temporary-file collision coverage). Prior update:
2026-08-14 by StressTestor (security-audit fixes and verify corpus 45 -> 64).
Documents the shared typed
evaluation pipeline, native Claude Code/Codex lifecycle reconciliation,
trust-aware health checks, uncontained stateful audit, explicit MCP baselines,
validated policy migration, completeness-aware shell matching, package preflight
parsing, event-aware hook self-protection, policy false-positive regressions,
and release/package evidence gates.
