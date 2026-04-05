#!/usr/bin/env bash
# record-simple.sh — single-pane recording of run-attacks.sh
# quick version that doesn't need tmux. good for README embeds + twitter.

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

./target/release/sentinel install --enforce >/dev/null

CAST="$ROOT/docs/live-demo.cast"
GIF="$ROOT/docs/live-demo.gif"
rm -f "$CAST" "$GIF"

asciinema rec "$CAST" \
  --overwrite \
  --idle-time-limit 1 \
  --command "bash -c '
    clear
    echo
    echo \"── sentinel: runtime defense for CLI AI agents ──\"
    echo
    echo \"replaying every prompt injection embedded in docs/index.html\"
    echo \"(a single HTML page with 20+ hidden attempts to exfiltrate credentials)\"
    echo
    sleep 2
    SENTINEL=./target/release/sentinel ./docs/run-attacks.sh
    echo
    echo \"every attack blocked at the hook layer — before any tool ran.\"
    echo
    sleep 2
  '"

agg --theme asciinema --font-size 14 "$CAST" "$GIF"

echo
echo "done:"
echo "  cast: $CAST ($(du -h "$CAST" | cut -f1))"
echo "  gif:  $GIF  ($(du -h "$GIF" | cut -f1))"
