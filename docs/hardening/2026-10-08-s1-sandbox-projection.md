# S1: projecting bundled deny.paths rules onto the Claude Code sandbox

Date: 2026-10-08
Spike: S1 from `docs/hardening/2026-10-08-improvement-plan.md` (workstream A, effects floor)
Base: `main` at `089e0b8`
Scope: documentation only. No product code. No live test was run; every claim
below is tagged **Solid** (the docs state it, quoted with URL) or
**Directional** (consistent with the docs but not stated by them, needs the
live test in M3).

The question S1 answers: can `sandbox.filesystem.denyRead` / `denyWrite`
express every directory-shaped bundled `deny.paths` rule, and which rules stay
hook-only.

Sources read this session:

- https://code.claude.com/docs/en/sandboxing (fetched in full)
- https://code.claude.com/docs/en/settings-reference (fetched in four 100k
  character chunks; the `sandbox` entries are in chunk 2)
- https://code.claude.com/docs/en/permissions (Read and Edit rule syntax, symlink
  handling, where a saved permission goes)
- https://code.claude.com/docs/en/permission-modes (protected paths)
- `src/install/defaults.rs` at `089e0b8` (75 `[[deny.paths]]` rules)
- `src/policy/matcher.rs` (sentinel's own glob semantics, for the comparison)

## What the docs say about the four filesystem lists

Every quote is verbatim. "Not documented" means the page does not say.

### Path prefixes

Settings reference, "Sandbox path prefixes":

> Paths in `allowWrite`, `denyWrite`, `denyRead`, `allowRead`, and
> `credentials.files` resolve by their prefix:

| Prefix | Meaning | Example |
|---|---|---|
| `/` | Absolute path from filesystem root | `/tmp/build` stays `/tmp/build` |
| `~/` | Relative to home directory | `~/.kube` becomes `$HOME/.kube` |
| `./` or no prefix | Relative to the project root for project settings, or to `~/.claude` for user settings | `./output` in `.claude/settings.json` resolves to `<project-root>/output` |

> The `//path` prefix for absolute paths also works. If you use single-slash
> `/path` expecting project-relative resolution, switch to `./path`. This
> syntax differs from Read and Edit permission rules, which use `//path` for
> absolute and `/path` for project-relative: sandbox filesystem paths use
> standard conventions, so `/tmp/build` is an absolute path.

So `~` expands (Solid), `/` is absolute (Solid), and an entry with no prefix in
`~/.claude/settings.json` is anchored at `~/.claude`, which is where
`sentinel install` writes (`src/install/mod.rs::claude_settings_path`). A
`**/name` pattern copied into user settings would therefore mean
`~/.claude/**/name`, not "anywhere". That is the reason the `**/` rules below
are hook-only.

### Trailing slash and trailing `/**`

> Claude Code strips a trailing slash from a directory path, so `~/.aws` and
> `~/.aws/` match the same directory. Before v2.1.224, Claude Code passed the
> trailing slash through to the sandbox, and Claude could still read or write
> paths under a `denyRead` or `denyWrite` entry written with one.

> Claude Code also removes a trailing `/**`, so `~/build/**` and `~/build`
> cover the same directory.

Solid: a directory entry covers its subtree. The projection should emit the
bare directory (no trailing `/` or `/**`) so it is correct on versions before
2.1.224 as well.

### Wildcards

> Whether a wildcard such as `*` works depends on which list the entry is in
> and on the platform:
>
> * **`allowWrite` and `denyWrite`**: on macOS, wildcards work. On Linux and
>   WSL2, the sandbox mounts concrete paths, so Claude Code skips an entry that
>   contains `*`, `?`, or `[` once the trailing `/**` is removed, and that entry
>   has no effect. Claude Code adds the paths from your `Edit` permission rules
>   to these lists, so the same limit applies to them, and the **Config** tab of
>   `/sandbox` warns about `Edit` and `Read` permission rules that contain
>   wildcards.
> * **`denyRead` and `allowRead`**: wildcards work on every platform. On Linux
>   and WSL2, Claude Code expands a read entry to the concrete paths it
>   matches, which it doesn't do for the write lists.

The only wildcard shape the docs show is `~/**/.env` (sandboxing page, overlap
table, and the `allowRead` entry). A `*` inside a segment such as
`*1password*` or a trailing `shadow*` is not shown. "Expands a read entry to
the concrete paths it matches" means a Linux `denyRead` wildcard is resolved
when the sandbox configuration is built, not when a path is opened. What
happens to a path that first appears after that is not documented.

### Files versus directories

Not documented as a rule. The examples use both: `~/.aws/credentials` and
`~/.env` (files), `~/.kube`, `~/.ssh`, `~/` (directories). The `credentials`
section says a `mask` entry falls back to `deny` for "a directory path, a glob
pattern", which implies `deny` accepts both. Treated as Solid for plain files
and directories.

### Deny versus allow precedence

Sandboxing page, "Configure sandboxing":

> When read rules overlap, the rule with the narrower path applies:

| Example rules | Result |
|---|---|
| `"denyRead": ["~/"]` with `"allowRead": ["~/projects"]` | `~/projects` is readable and the rest of the home directory stays blocked. The narrower allow re-opens that part of the denied region |
| `"allowRead": ["~/"]` with `"denyRead": ["~/.env"]` | `~/.env` stays blocked and the rest of the home directory is readable. The deny holds inside a wider allow, so a broad allow can't silently re-expose a secret |
| `"allowRead": ["~/"]` with `"denyRead": ["~/**/.env"]` | Every `.env` under the home directory stays blocked and the rest is readable. A wildcard deny holds inside a wider allow the same way an exact path does |

Settings reference, `allowRead`:

> An exact or wildcard `denyRead` entry stays blocked inside a broader
> `allowRead`, as the overlap table shows. When a wildcard `denyRead` entry
> such as `~/**/.env` matches a directory, Claude Code blocks reads of its
> contents as well. Before v2.1.236 on macOS, Claude Code re-opened the paths a
> wildcard `denyRead` entry matched wherever a broader `allowRead` entry
> covered them, and left a matched directory's contents readable.

Settings reference, `denyWrite`:

> Block sandboxed commands from writing to specific paths, including paths
> inside a directory that is otherwise writable.

Solid: a deny entry wins over an overlapping allow, on both lists. The
version gate (2.1.236 on macOS) matters for wildcard entries only.

### Merging across settings files

> Claude Code merges entries across every settings scope the session loads,
> and adds the paths from your `Read(...)` deny permission rules.
> (`denyRead` entry; `denyWrite` says the same for `Edit(...)` deny rules)

> A `deny` entry only ever narrows access, so any scope can add one, but no
> scope can remove one that another scope added. (`credentials` section)

Solid: a project `.claude/settings.json` cannot remove a user-level deny
entry, which is what the self-protect design needs. Note that sentinel's
reconciliation (keep user entries, replace tagged sentinel entries) operates
on one file; the merge across files is Claude Code's.

### Symlinks

Sandboxing page, "Protected paths":

> If a symlink appears at a protected settings file's path during the session,
> the sandbox also denies writes to the file it points to, starting with the
> next command.

That is the only sandbox symlink statement, and it covers the built-in
protected list, not user `denyRead` / `denyWrite` entries. How the sandbox
treats a symlink that points into a denied directory from a readable one (for
example `./project/key -> ~/.ssh/id_rsa`) is **not documented** for the
sandbox. The permissions page documents it for Read/Edit rules only:

> **Deny rules**: apply when either the requested path or the file it resolves
> to matches. A symlink that points to a denied file is itself denied.

That statement is about the permission layer (file tools and recognized
Bash file commands), not the OS sandbox. Directional expectation: bubblewrap
masks the real inode's mount path, so a symlink into a masked subtree
resolves to a masked path at open time; Seatbelt matches on the canonical
path. Live test needed.

### What the sandbox does not cover

> The sandbox covers shell commands only. Claude's file tools, MCP servers,
> and hooks run outside it.

> A `denyRead` entry doesn't stop the Read tool, and `allowedDomains` doesn't
> limit WebFetch

> Other processes Claude Code starts: command hooks, local MCP servers,
> plugin monitors, LSP servers, and helper commands such as your status line
> command and `apiKeyHelper` run with your full access

Solid. This is why the plan keeps the hook for Write/Edit and why none of the
projection replaces a hook rule; it adds a second layer under Bash.

### Default boundaries

> **Default write behavior**: read and write access to the current working
> directory and its subdirectories, any directories you've added with
> `--add-dir`, `/add-dir`, or `permissions.additionalDirectories`, plus the
> per-user temp directory that `$TMPDIR` points to

> **Default read behavior**: read access to the entire computer, except
> certain denied directories. This default still allows reading credential
> files, so protect credentials you don't want commands to read.

> There is no built-in credential deny list, so only the files and variables
> you list are restricted.

Solid. Two consequences for the projection: `denyRead` entries do real work
(credentials are readable by default), while `denyWrite` entries outside the
working directory only matter when the operator has widened writes
(`allowWrite`, `additionalDirectories`, or a session started in `~`).

### Built-in protected paths (write side)

> **In `~/.claude`, or the directory `CLAUDE_CONFIG_DIR` points to**: most of
> its contents, plus `~/.claude.json` and the `.credentials.json` credential
> store

> There is no way to exempt one of these paths: an `allowWrite` entry or an
> `Edit` allow rule that covers the path doesn't lift the protection. The only
> way to turn the protection off is `filesystem.disabled`, which turns off
> filesystem isolation for every path.

Solid: `~/.claude/settings.json` is already write-denied inside the sandbox
("most of its contents" is not an exact list, so an explicit entry is still
worth emitting; see the self-protect section).

### Non-existent paths on Linux

Sandboxing page, troubleshooting:

> On Linux and WSL2, the sandbox holds a write denial on a file that doesn't
> exist yet by creating a 0-byte read-only placeholder there while a sandboxed
> command runs. The sandbox removes the placeholder afterward. If a session is
> killed before that cleanup runs, for example by SIGKILL, the placeholders
> stay behind. Later sessions bind the placeholders read-only again on every
> start, so a settings write such as saving a permission choice fails at a
> path where a placeholder remains.

Solid, and it shapes the self-protect list: every `denyWrite` entry for a file
that does not exist creates a placeholder per command, and a stale one blocks
Claude Code's own later write to that path. What happens when the placeholder
cannot be created (a path under `/usr/local/bin` or `/opt/homebrew/bin` as a
non-root user) is **not documented**. The behavior of a `denyRead` entry whose
path does not exist (macOS-only paths on a Linux host) is **not documented**.

### Version gates seen in the docs

| Behavior | Requires |
|---|---|
| trailing slash stripped from deny entries | 2.1.224 |
| wildcard `denyRead` holds inside a broader `allowRead` on macOS | 2.1.236 |
| excluded settings source drops its sandbox lists | 2.1.246 |
| stale placeholder files flagged by `claude doctor` | 2.1.257 |
| user `allowUnsandboxedCommands: false` holds against a project `true` | 2.1.285 |

The plan's last verified Claude Code version is 2.1.207. The projection as
written below assumes 2.1.224 or later; `doctor` should read the version.

## Sentinel's own semantics, for the comparison

From `src/policy/matcher.rs`:

- a deny rule with a trailing `/*` covers the subtree and the directory
  itself ("a credential dir can't be dodged with a nested path or by naming
  the bare dir");
- `/**` is the same recursive match;
- `*` matches within one segment, `**` across segments;
- `~` expands to `HOME`, and `/Users/$USER`, `$HOME`-style spellings are
  resolved to the same path before matching.

So the sandbox equivalent of `~/x/*` and `~/x/**` is the bare directory
`~/x`. A rule is "directory-shaped" when, after stripping a trailing `/*` or
`/**`, no `*`, `?`, or `[` remains and it starts with `~/` or `/`.

Two differences that no projection removes:

1. Sentinel's rule fires when the command text names the path. The sandbox
   denies every open of the path by any process in the command. A tool that
   reads its own config (`gh`, `aws`, `kubectl`, `npm` with `~/.npmrc`,
   `cargo publish`, `docker login`, git credential helpers) works under the
   hook and fails under the projected `denyRead`. The docs' answer for that
   case is `sandbox.credentials.files` with `"mode": "mask"` (Linux and WSL2
   only; on macOS a masked file is denied) or `excludedCommands`, which runs
   the tool with full access. That is a product decision for M3, not a spike
   question, but it is the main reason the projection should start opt-in.
2. The sandbox has no warn tier. Compiling a `warn` rule into a deny list
   turns a review signal into a hard block and breaks "dual-use goes to warn".
   Warn rules therefore stay hook-only, with the two self-protect exceptions
   the plan calls out, where only the write side is projected.

## Projection rules used in the table

- **block, directory-shaped, under `~/`**: emit the bare path in both
  `denyRead` and `denyWrite`. Read is the credential leak; write is tamper
  (`~/.ssh/authorized_keys`, `~/.npmrc` registry redirect).
- **block, directory-shaped, absolute system path**: `denyRead` only.
  Writes there are already outside the default writable set, and a
  `denyWrite` on a path that may not exist raises the placeholder question
  for no gain.
- **block, wildcard remaining after normalization**: `denyRead` only (Linux
  skips wildcard write entries). Tagged Directional unless the wildcard shape
  is the documented `~/**/name` shape.
- **block, `**/` prefix with no anchor**: hook-only. In user settings the
  entry would anchor at `~/.claude`.
- **warn**: hook-only, except the two self-protect files, which get
  `denyWrite` only.
- **sentinel binary paths**: `denyWrite` only, and only the one path that is
  the running binary (`std::env::current_exe()`, which install already
  resolves). The other three are hook-only on that host.

Confidence: **Solid** when every syntax element in the emitted entry is
quoted above (prefix `~/` or `/`, no wildcard, or a wildcard in a
`denyRead` entry). **Directional** when the entry depends on something the
docs do not state (spaces in a path, a partial-segment wildcard, unlink
semantics of a file `denyWrite`, placeholder behavior for a missing path).

## Rule map

Pattern and reason are copied from `src/install/defaults.rs`. "Entry" is the
exact string the compiler would emit. "both" means the same entry in
`denyRead` and `denyWrite`.

### Credential and secret stores (block)

| # | pattern | action | projection | entry or reason | tag |
|---|---|---|---|---|---|
| 1 | `~/.ssh/*` | block | both | `~/.ssh` | Solid |
| 2 | `~/.aws/*` | block | both | `~/.aws` | Solid |
| 3 | `~/.gnupg/*` | block | both | `~/.gnupg` | Solid |
| 4 | `~/.config/gh/*` | block | both | `~/.config/gh` | Solid |
| 5 | `~/.netrc` | block | both | `~/.netrc` | Solid |
| 6 | `/etc/passwd` | block | denyRead | `/etc/passwd` | Solid |
| 7 | `/etc/shadow*` | block | denyRead | `/etc/shadow*` (wildcard; Linux expands at config build, so a backup created later is not covered until the next build) | Solid |
| 8 | `/etc/master.passwd` | block | denyRead | `/etc/master.passwd` (macOS only; behavior of a missing path on Linux not documented) | Solid |
| 9 | `/proc/*/environ` | block | hook-only | wildcard in a middle segment; Linux `denyRead` would expand to the PIDs present at config build, and the PIDs inside a bubblewrap sandbox are the ones that matter. Not expressible as a stable entry | n/a |
| 16 | `~/.npmrc` | block | both | `~/.npmrc` | Solid |
| 17 | `~/.kube/config` | block | both | `~/.kube/config` | Solid |
| 18 | `~/.config/gcloud/*` | block | both | `~/.config/gcloud` | Solid |
| 19 | `~/.azure/*` | block | both | `~/.azure` | Solid |
| 20 | `~/.docker/config.json` | block | both | `~/.docker/config.json` | Solid |
| 21 | `~/.dockercfg` | block | both | `~/.dockercfg` | Solid |
| 22 | `~/.config/containers/auth.json` | block | both | `~/.config/containers/auth.json` | Solid |
| 23 | `~/.git-credentials` | block | both | `~/.git-credentials` | Solid |
| 24 | `~/.config/git/credentials` | block | both | `~/.config/git/credentials` | Solid |
| 25 | `~/.cache/huggingface/token` | block | both | `~/.cache/huggingface/token` | Solid |
| 26 | `~/.huggingface/token` | block | both | `~/.huggingface/token` | Solid |
| 27 | `~/.cargo/credentials.toml` | block | both | `~/.cargo/credentials.toml` | Solid |
| 28 | `~/.cargo/credentials` | block | both | `~/.cargo/credentials` | Solid |
| 29 | `~/.pgpass` | block | both | `~/.pgpass` | Solid |
| 30 | `~/.pg_service.conf` | block | both | `~/.pg_service.conf` | Solid |
| 31 | `~/.my.cnf` | block | both | `~/.my.cnf` | Solid |
| 32 | `~/.mylogin.cnf` | block | both | `~/.mylogin.cnf` | Solid |
| 33 | `~/.config/rclone/rclone.conf` | block | both | `~/.config/rclone/rclone.conf` | Solid |
| 34 | `~/.oci/*` | block | both | `~/.oci` | Solid |
| 35 | `~/.config/doctl/*` | block | both | `~/.config/doctl` | Solid |
| 36 | `~/.config/fly/*` | block | both | `~/.config/fly` | Solid |
| 37 | `~/.databrickscfg` | block | both | `~/.databrickscfg` | Solid |
| 38 | `~/.terraform.d/credentials.tfrc.json` | block | both | `~/.terraform.d/credentials.tfrc.json` | Solid |
| 39 | `~/Library/Keychains/*` | block | both | `~/Library/Keychains` (macOS only) | Solid |
| 40 | `/Library/Keychains/*` | block | denyRead | `/Library/Keychains` (macOS only) | Solid |
| 41 | `**/globalStorage/state.vscdb` | block | hook-only | unanchored `**/`; in user settings it would mean `~/.claude/**/globalStorage/state.vscdb`. A `~/**/globalStorage/state.vscdb` rewrite is the documented `~/**/name` shape but covers home only and forces a home-tree walk on Linux at every config build | n/a |
| 42 | `~/Library/Cookies/*` | block | both | `~/Library/Cookies` (macOS only) | Solid |
| 43 | `~/Library/Application Support/Google/Chrome/**` | block | both | `~/Library/Application Support/Google/Chrome` (space in path not documented) | Directional |
| 44 | `~/Library/Application Support/Chromium/**` | block | both | `~/Library/Application Support/Chromium` (space in path) | Directional |
| 45 | `~/Library/Application Support/BraveSoftware/**` | block | both | `~/Library/Application Support/BraveSoftware` (space in path) | Directional |
| 46 | `~/Library/Application Support/Microsoft Edge/**` | block | both | `~/Library/Application Support/Microsoft Edge` (spaces in path) | Directional |
| 47 | `~/Library/Application Support/Firefox/**` | block | both | `~/Library/Application Support/Firefox` (space in path) | Directional |
| 48 | `~/Library/Application Support/Arc/User Data/**` | block | both | `~/Library/Application Support/Arc/User Data` (spaces in path) | Directional |
| 49 | `~/.config/google-chrome/**` | block | both | `~/.config/google-chrome` | Solid |
| 50 | `~/.config/chromium/**` | block | both | `~/.config/chromium` | Solid |
| 51 | `~/.config/BraveSoftware/**` | block | both | `~/.config/BraveSoftware` | Solid |
| 52 | `~/.mozilla/firefox/**` | block | both | `~/.mozilla/firefox` | Solid |
| 53 | `~/Library/Application Support/1Password/**` | block | both | `~/Library/Application Support/1Password` (space in path) | Directional |
| 54 | `~/Library/Group Containers/*1password*/**` | block | denyRead | `~/Library/Group Containers/*1password*` (partial-segment wildcard, not a documented shape; `denyWrite` would be skipped on Linux, which is moot for a macOS path) | Directional |
| 55 | `~/.config/op/**` | block | both | `~/.config/op` | Solid |
| 56 | `~/.password-store/**` | block | both | `~/.password-store` | Solid |
| 57 | `~/Library/Application Support/Bitwarden/**` | block | both | `~/Library/Application Support/Bitwarden` (space in path) | Directional |
| 58 | `**/*.kdbx` | block | hook-only | unanchored `**/` plus a suffix glob; same reasoning as #41 | n/a |
| 59 | `~/.ethereum/keystore/**` | block | both | `~/.ethereum/keystore` | Solid |
| 60 | `**/wallet.dat` | block | hook-only | unanchored `**/`; same reasoning as #41 | n/a |

### Sentinel self-protect (the plan's denyWrite group)

| # | pattern | action | projection | entry or reason | tag |
|---|---|---|---|---|---|
| 10 | `~/.sentinel/policy.toml` | warn | denyWrite | `~/.sentinel/policy.toml`. Reads stay open (backup, inspect). File exists after install, so no placeholder | Solid |
| 11 | `~/.sentinel/mcp-baseline.json` | warn | denyWrite | `~/.sentinel/mcp-baseline.json`. Created by `audit-mcp --update`, not by install, so on a fresh host the entry names a missing file and Linux creates a placeholder per command. Either create an empty baseline at install or emit the entry only when the file exists | Directional |
| 12 | `~/.cargo/bin/sentinel` | block | denyWrite, conditional | emit only when it is `current_exe()`. Whether a file `denyWrite` also blocks `rm` / `mv` of that file (which need write on the parent directory) is not documented; Linux binds the file read-only, which should make unlink fail with EBUSY, and Seatbelt `file-write*` includes unlink, but neither is stated | Directional |
| 13 | `~/.local/bin/sentinel` | block | denyWrite, conditional | as #12 | Directional |
| 14 | `/usr/local/bin/sentinel` | block | denyWrite, conditional | as #12; when absent, a placeholder in `/usr/local/bin` cannot be created by a non-root user and the result is not documented | Directional |
| 15 | `/opt/homebrew/bin/sentinel` | block | denyWrite, conditional | as #12 and #14 | Directional |

Not a bundled rule, added by the plan:

| target | projection | entry or reason | tag |
|---|---|---|---|
| `~/.claude/settings.json` | denyWrite | `~/.claude/settings.json`. Redundant with the built-in protected list ("most of" `~/.claude`), which cannot be exempted, but explicit so `doctor` can diff it and so it holds if the upstream list changes. If `CLAUDE_CONFIG_DIR` is set, emit `<CLAUDE_CONFIG_DIR>/settings.json` instead, matching `claude_settings_path()` | Solid |
| `~/.sentinel/install-state.json` (E1) | denyWrite | same file-exists reasoning as #10; written by install, so it exists | Solid |

### Agent configuration and persistence surfaces (warn, hook-only)

| # | pattern | action | projection | reason | tag |
|---|---|---|---|---|---|
| 61 | `**/.env` | warn | hook-only | warn has no sandbox equivalent; also unanchored | n/a |
| 62 | `**/.env.*` | warn | hook-only | as #61 | n/a |
| 63 | `**/.claude/settings.json` | warn | hook-only | warn; the sandbox's built-in protected list already denies writes to `.claude` settings files in the working directory and above, and in `~/.claude` | n/a |
| 64 | `**/.claude/settings.local.json` | warn | hook-only | as #63 | n/a |
| 65 | `**/.claude/skills/**` | warn | hook-only | as #63 (`.claude/skills` is in the built-in list) | n/a |
| 66 | `**/.claude/agents/**` | warn | hook-only | as #63 (`.claude/agents` is in the built-in list) | n/a |
| 67 | `**/.claude/hooks/**` | warn | hook-only | as #63 (`.claude/hooks` is in the built-in list) | n/a |
| 68 | `**/.mcp.json` | warn | hook-only | as #63 (`.mcp.json` is in the built-in list) | n/a |
| 69 | `~/.codex/*` | warn | hook-only | warn; directory-shaped, so `~/.codex` would compile if the operator ever wants a hard block | n/a |
| 70 | `~/.gemini/*` | warn | hook-only | as #69 | n/a |
| 71 | `**/.vscode/tasks.json` | warn | hook-only | warn; `.vscode` in the working directory is in the built-in protected list | n/a |
| 72 | `**/.github/workflows/*` | warn | hook-only | warn, unanchored, and a hard deny would block ordinary CI edits | n/a |
| 73 | `**/kubeconfig` | warn | hook-only | warn, unanchored | n/a |
| 74 | `~/Library/LaunchAgents/*.plist` | warn | hook-only | warn; suffix glob | n/a |
| 75 | `~/.config/systemd/user/*.service` | warn | hook-only | warn; suffix glob | n/a |

## Self-protect targets and Claude Code's own writes

Does a `denyWrite` entry for `~/.claude/settings.json` break Claude Code's own
writes to that file?

What the docs say Claude Code writes, and where:

- `~/.claude/settings.json` (user settings): `/advisor`, `/fast`, `/effort`
  and the `/model` effort slider (`modelSettings`), `/config` rows
  (`fileCheckpointingEnabled`, `editorMode`, `autoUpdatesChannel`, several
  others), `/remote-env`, `pluginConfigs`, and
  `skipDangerousModePermissionPrompt` when the bypass dialog is accepted.
- `.claude/settings.local.json` at the repository root: the `/sandbox` panel
  ("When you select a mode in the panel, Claude Code saves it to your
  project's local settings at `.claude/settings.local.json`"), "Yes, and
  don't ask again" for Bash commands and WebFetch domains ("Claude Code saves
  the rule to `.claude/settings.local.json` at the root of the git
  repository"), MCP server approvals, `/skills`.
- `~/.claude.json`: `/config` toggles such as `respectGitignore`.

Whether the sandbox's `denyWrite` affects those writes: **not stated
directly**, but it follows from two Solid statements. The sandbox "covers
shell commands only", and the processes that run outside it "run with your
full access". Claude Code's own settings writes are made by the Claude Code
process, not by a sandboxed command, so a `denyWrite` entry does not apply to
them. The built-in protected list already denies sandboxed writes to
`~/.claude` "most of its contents", and Claude Code still saves `/config`
choices to `~/.claude/settings.json` with the sandbox on, which is consistent
with the same reading.

The one documented way a `denyWrite` entry can interfere is the Linux
placeholder: a `denyWrite` entry for a file that does not exist creates a
0-byte read-only placeholder during each sandboxed command, and a placeholder
left behind by a killed session makes "a settings write such as saving a
permission choice" fail at that path. `~/.claude/settings.json` exists on any
host where sentinel is installed (the hook lives in it), so that case does
not arise for it. It does arise for `~/.sentinel/mcp-baseline.json` and for
the three sentinel binary paths that are not the running binary, which is why
the table emits those conditionally.

One more interaction worth recording: sentinel's hook already blocks
shell-level rewrites of `.claude/settings.json` (`sed -i`, `tee`,
redirects, `cp` over it; the "policy.toml command cluster" in
`defaults.rs`). The sandbox entry makes the same outcome hold for a rewrite
that happens inside a script the hook never sees. The two layers agree on the
verdict, so no FP risk is added.

## Summary

### Counts

75 bundled `[[deny.paths]]` rules at `089e0b8`: 58 block, 17 warn.

| outcome | count | rules |
|---|---|---|
| compiled, both lists, Solid | 37 | #1-5, 16-39, 42, 49-52, 55, 56, 59 |
| compiled, denyRead only, Solid | 4 | #6, 7, 8, 40 |
| compiled, both lists, Directional (spaces in path) | 8 | #43-48, 53, 57 |
| compiled, denyRead only, Directional (partial-segment wildcard) | 1 | #54 |
| compiled, denyWrite only (self-protect) | 6 | #10, 11 (warn), #12-15 (block, one emitted per host) |
| hook-only, block | 4 | #9, 41, 58, 60 |
| hook-only, warn | 15 | #61-75 |

Compiled: 56 of 75 (43 Solid, 13 Directional). Hook-only: 19 (4 block, 15
warn). Of the 58 block rules, 54 have a sandbox expression and 4 do not. Every
hook-only block rule is hook-only for the same reason: an unanchored `**/`
prefix or a wildcard in a middle segment. The `**/` rules could be projected
as `~/**/<name>` in a later release (documented shape), at the cost of
home-only coverage and a home-tree expansion on Linux.

The plan's description of the compilable set ("literal paths, `~`-prefixed
subtrees, `/**` suffixes") holds. The one addition the docs force is the
split by list: a wildcard survives in `denyRead` on every platform but is
skipped in `denyWrite` on Linux, so the compiler needs per-list output rather
than one list copied twice.

### Open questions only a live test can answer

1. **Unlink and rename under a file `denyWrite`.** Does `rm ~/.cargo/bin/sentinel`
   or `mv other ~/.cargo/bin/sentinel` fail when the entry names the file,
   on both bubblewrap and Seatbelt? The self-protect value of the binary entry
   depends on it. Test: `allowWrite: ["~/.cargo/bin"]` plus the `denyWrite`
   entry, then `rm`, `mv`, `cp` over, `ln -sf`, and `install` from a
   sandboxed script.
2. **Missing paths.** What does each platform do with a `denyRead` or
   `denyWrite` entry whose path does not exist (macOS-only paths on Linux,
   `/usr/local/bin/sentinel` when the binary is elsewhere, a missing
   `mcp-baseline.json`)? Silent skip, placeholder, error, or sandbox start
   failure. This decides whether the compiler filters by existence or emits
   the full set.
3. **Symlinks into a denied subtree.** With `denyRead: ["~/.ssh"]`, does
   `cat ./key` succeed when `./key -> ~/.ssh/id_rsa` and `.` is the writable
   working directory? Also the reverse: a symlink created inside the sandbox
   after the configuration was built. The docs state symlink following only
   for the built-in protected list.
4. **Wildcard `denyRead` on Linux after new paths appear.** `/etc/shadow*`
   and the `~/**/<name>` shapes expand at config build. Does a file created
   during the session get covered before the next build, and when is the
   configuration rebuilt (per command, per settings edit)?
5. **Hook ordering (S4).** Whether PreToolUse runs before the sandbox applies
   does not change this projection, but it decides whether the audit trail
   sees a denied read or only the sandbox's error text.
6. **Tool breakage under the projected denies.** Which of `gh`, `aws`,
   `kubectl`, `npm`, `cargo publish`, `docker login`, `git push` over HTTPS
   with a credential helper, and `ssh` fail inside the sandbox once the
   credential entries are live, on each platform. The docs predict all of
   them. The number decides how loudly the opt-in has to warn.
7. **Paths with spaces and the `*1password*` segment** on Seatbelt: generated
   SBPL must quote them; nothing in the docs confirms it.

### Recommended minimal projection for a first opt-in release

Emit only Solid entries, keep the sandbox lists honest about what they
contain, and let the hook keep everything else.

`denyRead` and `denyWrite` (37 entries): rules #1-5, 16-39, 42, 49-52, 55, 56,
59 as bare paths. Document that `gh`, `aws`, `kubectl`, `npm` with a
tokened `~/.npmrc`, `cargo publish`, `docker login`, git credential helpers,
and `ssh` key reads fail inside the sandbox once these are on, and point at
`sandbox.credentials.files` `mask` (Linux and WSL2) or `excludedCommands`
(full access, the operator's call) as the escape routes.

`denyRead` only (4 entries): `/etc/passwd`, `/etc/shadow*`,
`/etc/master.passwd`, `/Library/Keychains`. Keep `/etc/master.passwd` and
`/Library/Keychains` in the list until question 2 says missing paths are a
problem; drop them per platform if it does.

`denyWrite` only (3 entries on a fresh host, 4 after `audit-mcp --update`):
`~/.sentinel/policy.toml`, `~/.sentinel/install-state.json`,
`<config dir>/settings.json`, the resolved running binary path, and
`~/.sentinel/mcp-baseline.json` only when the file exists (or create an
empty baseline at install so it always does).

Hold back for a second release, pending the live test: the eight
space-bearing macOS paths (#43-48, 53, 57) and `*1password*` (#54), which
are Directional only on syntax grounds and cost nothing to add once one
Seatbelt run confirms them; a `~/**/` rewrite of #41, 58, 60 once question 4
is answered.

Settings to set alongside, as the plan already lists: `sandbox.enabled:
true`, `sandbox.failIfUnavailable: true`,
`sandbox.allowUnsandboxedCommands: false`. The last one also makes the
sandbox admin-required only from managed settings or `--settings`; from user
settings it holds against a project `true` (2.1.285 or later) without the
repository locks, so `doctor` should report the three keys and the version
rather than assume the locks are in force.

What `doctor --strict` should diff: the live `sandbox.filesystem.denyRead`
and `denyWrite` arrays in `claude_settings_path()` against this projection,
plus `sandbox.excludedCommands` (any entry is a report line, since an
excluded command runs with full access and bypasses every entry above).
