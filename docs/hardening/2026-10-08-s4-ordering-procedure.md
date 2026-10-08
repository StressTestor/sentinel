# S4 spike: sandbox versus PreToolUse ordering

Date: 2026-10-08
Status: blocked in the cloud session; procedure recorded for a local run

## question

When Claude Code's Bash sandbox is enabled, does the PreToolUse hook run
before the sandbox wraps the command, after it, or inside it? The sandbox
bridge in the improvement plan does not depend on the answer, but two
things do: whether `updatedInput` from a hook is what the sandbox sees, and
whether a hook can observe sandbox state for `doctor`.

## why it did not run here

The sandbox needs `bubblewrap` and `socat` on Linux (documented at
https://code.claude.com/docs/en/sandboxing). Neither is installed in the
session container, and the session has no interactive Claude Code login.
Nothing about the ordering can be observed without a sandbox that starts.

## procedure (about ten minutes on a laptop)

1. Build sentinel: `cargo build --release`.
2. Create a scratch home so no real config is touched:

   ```bash
   export H=$(mktemp -d); export HOME=$H
   mkdir -p $H/.claude
   ```

3. Write a settings file with the sandbox on and a logging hook. The hook
   records its own view of the process tree and the tool input it was given.

   ```json
   {
     "sandbox": { "enabled": true, "failIfUnavailable": true },
     "hooks": {
       "PreToolUse": [{
         "matcher": "Bash",
         "hooks": [{ "type": "command",
                     "command": "sh -c 'cat > /tmp/s4-hook-in.json; ps -o pid,ppid,comm -p $$ -p $PPID > /tmp/s4-hook-ps.txt; cat /proc/self/status | grep -i -E \"seccomp|nonewprivs\" > /tmp/s4-hook-status.txt; exit 0'" }]
       }]
     }
   }
   ```

   Save it as `$H/.claude/settings.json`.

4. Run one Bash tool call headlessly:

   ```bash
   claude -p 'run exactly this shell command and nothing else: cat /proc/self/status | grep -i -E "seccomp|nonewprivs" > /tmp/s4-tool-status.txt; ps -o pid,ppid,comm -p $$ > /tmp/s4-tool-ps.txt'
   ```

5. Compare:
   - `/tmp/s4-hook-status.txt` versus `/tmp/s4-tool-status.txt`. If the tool
     shows `Seccomp: 2` or `NoNewPrivs: 1` and the hook shows neither, the hook
     ran outside the sandbox (expected from "hooks run with your full access").
   - `/tmp/s4-hook-in.json`: confirm the hook saw the original `command`.
   - Repeat with a second hook that returns
     `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{"command":"echo REWRITTEN > /tmp/s4-rewrite.txt"}}}`
     and check whether `/tmp/s4-rewrite.txt` exists. If it does, `updatedInput`
     rewrites a Bash `command` and the rewritten command is what ran under the
     sandbox. This also answers spike S2.

6. Record the Claude Code version (`claude --version`) and the three results
   in this file, and update the Directional claims in the improvement plan.

## what to write down

| check | result | version |
|---|---|---|
| hook process is outside the sandbox | | |
| hook sees the original command | | |
| `updatedInput` rewrites Bash `command` | | |
| rewritten command runs sandboxed | | |
