#!/usr/bin/env bash
# record-demo.sh — records the live attack demo as an asciicast + gif.
#
# left pane:  run-attacks.sh replaying every injection from docs/index.html
# right pane: tail -f on ~/.sentinel/audit.jsonl showing sentinel's live verdicts
#
# requires: asciinema, agg, tmux
# output:   docs/live-demo.cast  docs/live-demo.gif

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

for tool in asciinema agg tmux; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing: $tool"
    exit 1
  fi
done

# ensure enforce-mode sentinel is installed
./target/release/sentinel install --enforce >/dev/null

# clean audit log
mkdir -p "$HOME/.sentinel"
: > "$HOME/.sentinel/audit.jsonl"

CAST="$ROOT/docs/live-demo.cast"
GIF="$ROOT/docs/live-demo.gif"
rm -f "$CAST" "$GIF"

SESSION="sentinel-demo-$$"

# the command that runs inside asciinema — starts a tmux split and drives both panes
tmux new-session -d -s "$SESSION" -x 180 -y 40
tmux send-keys -t "$SESSION" "clear && echo '── sentinel: runtime defense for CLI agents ──' && echo && echo 'replaying every prompt injection embedded in docs/index.html' && echo && sleep 2 && SENTINEL=./target/release/sentinel ./docs/run-attacks.sh" C-m
tmux split-window -h -t "$SESSION"
tmux send-keys -t "$SESSION".1 "clear && echo '── audit log (tail -f) ──' && echo && tail -f ~/.sentinel/audit.jsonl | jq -r '\"[\" + .timestamp + \"] \" + .action + \" \" + .tool_name + \" — \" + (.reason // \"\")'" C-m
tmux select-pane -t "$SESSION".0

# record by attaching asciinema to the tmux session
asciinema rec "$CAST" \
  --overwrite \
  --idle-time-limit 2 \
  --command "tmux attach -t $SESSION"

tmux kill-session -t "$SESSION" 2>/dev/null || true

# render to gif
agg --theme asciinema --font-size 14 "$CAST" "$GIF"

echo
echo "done:"
echo "  cast: $CAST"
echo "  gif:  $GIF ($(du -h "$GIF" | cut -f1))"
