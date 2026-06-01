# sentinel

[![CI](https://github.com/StressTestor/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/StressTestor/sentinel/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/sentinel-guard.svg)](https://crates.io/crates/sentinel-guard)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/StressTestor/sentinel)

runtime defense for CLI AI agents. intercepts tool calls before execution and enforces security policy.

![sentinel blocking credential exfiltration, rm -rf, curl|sh, and AWS keys](demo.gif)

## live demo

there's a single HTML page at [`docs/target.html`](docs/target.html) styled to look like normal "CloudSync" tool documentation. every section of that page is poisoned with a different prompt injection: HTML comments, white-on-white text, zero-width Unicode, `display:none` divs, HTML entity encoding, link title attributes, tiny-font spans, fake "agent instruction" blockquotes. 20+ attack payloads total.

`docs/run-attacks.sh` replays every injection against `sentinel evaluate`:

```bash
./target/release/sentinel install --enforce
SENTINEL=./target/release/sentinel ./docs/run-attacks.sh
```

![20 attacks, 20 blocks](docs/live-demo.gif)

20/20 attacks blocked at the hook layer, before any tool ran. full write-up and attack matrix at [`docs/index.html`](docs/index.html) (or [stresstestor.github.io/sentinel](https://stresstestor.github.io/sentinel/)).

## the problem

CLI agents like Claude Code and Codex have file system access, shell execution, and code modification capabilities. prompt injection can make them exfiltrate credentials, delete files, or modify production configs. the model-level safety layer is provably insufficient: DeepSeek R1 scored 0/10 on harmful refusals in adversarial evaluation.

nobody is defending at the runtime layer. sentinel fixes that.

## how it works

sentinel hooks into Claude Code's PreToolUse system. every tool call (Bash, Edit, Write, Read) passes through sentinel before execution. sentinel evaluates the call against your security policy and either allows, warns, or blocks it.

```
you type a prompt
     │
     claude code decides to run: cat ~/.aws/credentials
     │
     sentinel intercepts the tool call
     │
     policy says: ~/.aws/* → BLOCK (credential access)
     │
     tool call denied. credentials safe.
```

## install

```bash
cargo install sentinel-guard
sentinel install          # audit mode (logs only, doesn't block)
sentinel install --enforce  # enforcement mode (blocks violations)
```

(the crate name is `sentinel-guard` because `sentinel` was already taken on crates.io. the binary is still `sentinel`.)

that's it. sentinel writes a PreToolUse hook into `~/.claude/settings.json` and a default policy with sane deny rules (credential paths, recursive deletion, pipe-to-shell, secret patterns).

## audit mode (default)

sentinel starts in audit mode. it logs what WOULD be blocked but doesn't actually block anything. you see the log and think "wow, sentinel would have caught 3 dangerous actions today." when you're ready, switch to enforce mode.

## audit your agent

before installing the defense layer, see how vulnerable your agent actually is:

```bash
sentinel audit --agent claude
```

this runs the PromptPressure attack corpus (220+ adversarial sequences across 8 behavioral dimensions) against your agent in a sandbox. the report shows exactly where your agent is vulnerable.

## policy

the default policy lives at `~/.sentinel/policy.toml`:

```toml
[policy]
mode = "audit"
on_failure = "closed"
default = "warn"

[[deny.paths]]
pattern = "~/.ssh/*"
action = "block"
reason = "SSH key access"

[[deny.commands]]
pattern = 'rm\s+-rf\s+/.*'
action = "block"
reason = "recursive root deletion"

[[deny.secrets]]
pattern = 'AKIA[0-9A-Z]{16}'
action = "block"
reason = "AWS access key in command args"
```

deny rules evaluate first. glob patterns for paths, regex for commands and secrets.

## defense tiers

| tier | what | status |
|------|------|--------|
| 1. policy | deterministic deny/allow rules — path canonicalization, shell-aware command matching, secret patterns, fail-closed on un-inspectable input | **active** — runs on every tool call |
| 2. heuristic | aho-corasick patterns from the attack corpus + multi-turn context | **implemented, not yet wired** into the hook path (see roadmap) |
| 3. LLM classifier | secondary model for ambiguous inputs | **planned** — interface only, not implemented |

Enforcement today is the Tier-1 policy engine. It's the deterministic, zero-false-positive layer and it's what blocks the attacks in the demo. Tiers 2 and 3 are scaffolding for defense-in-depth: the heuristic analyzer is written but isn't called on the evaluate hot path yet (wiring it needs a concurrency-safe context buffer and a false-positive budget), and the LLM classifier is an interface stub. Don't rely on 2 or 3 being active.

## supply-chain hardening (and what it can't do)

the self-propagating npm/pypi worms in the shai-hulud / Miasma family inject persistence and steal credentials through package lifecycle scripts. the default policy now covers the part of that an agent runtime can actually see:

- **self-protect.** the agent can't write `~/.sentinel/policy.toml`. a guard that lets an injected agent flip itself to audit mode is not a guard. blocked at the tool-call layer (your own editor, and `sentinel install`, are unaffected since they don't go through the hook).
- **credential coverage.** more credential files and secret formats: `~/.npmrc`, `~/.kube/config`, `~/.config/gcloud/`, `~/.azure/` (block), plus GCP / Azure / Vault / kubeconfig secret content in writes.
- **warn-level tripwires** for the agent-driven version of the TTPs: writes to other agents' hook configs (`.claude/settings.json`, `~/.codex`, `~/.gemini`, `.vscode/tasks.json`), LaunchAgent / systemd-user persistence units, and `npm publish` / `npm token` / `gh repo create --public`. these are warn, not block, because developers do all of them legitimately.

now the part nobody else says out loud:

**sentinel hooks the agent's tool calls. it does not and cannot see npm lifecycle scripts.** when the worm's payload runs, it runs inside a child process of `npm install`, not as an agent tool call. that never crosses the PreToolUse hook. so these rules catch the case where a prompt injection drives *the agent itself* into writing a LaunchAgent or exfiltrating a credential. they do not catch the worm propagating on its own. anything that claims a runtime hook stops a lifecycle-script worm is lying to you.

two more honest caveats:

- the self-protect block is porous, and it only covers `policy.toml`. the more complete disable vector is removing sentinel's own PreToolUse hook entry from `~/.claude/settings.json`. that path is `warn`, not block: you can't path-isolate one entry inside a dual-use file without false-blocking every legit settings edit, so a hook-removal is surfaced but allowed. a path assembled from a shell variable, or a write from a subprocess, also gets through. this raises the cost of disarming sentinel; it is not tamper-proof. content-aware protection of the hook entry is a follow-up.
- `sentinel install` does **not** overwrite an existing `~/.sentinel/policy.toml`, and the default is audit mode. if you already have a policy, these new rules won't appear until you regenerate it, and nothing blocks until you switch to `--enforce`.

## commands

```
sentinel audit            run attack corpus against your agent
sentinel install          install hooks + default policy (audit mode)
sentinel install --enforce  install with enforcement
sentinel uninstall        remove hooks
sentinel evaluate         evaluate a tool call (called by the hook)
sentinel check '<json>'   dry-run a tool call against the policy and explain the decision
sentinel verify           replay pinned attacks through the policy, assert each is caught
sentinel doctor [--strict] validate the install chain + probe liveness (detects a disarmed guard)
sentinel policy-diff      show which bundled-default rules your policy is missing (read-only)
sentinel status           show config, hooks, policy summary
sentinel corpus-update    fetch latest attack corpus
```

`sentinel verify` is also wired into CI as a regression gate: a fixed bypass that silently reopens, or a new rule that starts false-blocking benign dev work, turns the build red.

## built with

- [PromptPressure](https://github.com/StressTestor/promptpressure) attack corpus (220+ sequences, 8 behavioral dimensions)
- Rust for near-zero latency in the hook path
- Claude Code's PreToolUse hook system for structured interception

## license

MIT OR Apache-2.0
