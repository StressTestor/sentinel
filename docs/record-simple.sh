#!/usr/bin/env bash
# record-simple.sh — single-pane recording of the v0.4.0 attack replay.
# Renders docs/live-demo.{cast,gif,mp4}. Good for the README hero + social.
#
# Runs against an isolated temp HOME holding the FRESH default policy, so the
# demo shows the zero-config story and never touches your real ~/.sentinel.

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SENT="$ROOT/target/release/sentinel"
[ -x "$SENT" ] || { echo "build the binary first: cargo build --release"; exit 1; }

# fresh default policy (enforce mode) in a throwaway HOME
DEMO_HOME="$(mktemp -d)"
trap 'rm -rf "$DEMO_HOME"' EXIT
HOME="$DEMO_HOME" "$SENT" install >/dev/null 2>&1

CAST="$ROOT/docs/live-demo.cast"
GIF="$ROOT/docs/live-demo.gif"
MP4="$ROOT/docs/live-demo.mp4"
rm -f "$CAST" "$GIF" "$MP4"

asciinema rec "$CAST" \
  --overwrite \
  --idle-time-limit 1 \
  --window-size 100x28 \
  --command "bash -c '
    clear
    echo
    echo \"── sentinel: runtime defense for CLI AI agents (v0.4.0) ──\"
    echo
    echo \"replaying every prompt injection embedded in docs/target.html,\"
    echo \"plus the de-obfuscation cases new in v0.4.0, all on the default policy\"
    echo
    sleep 1
    HOME=\"$DEMO_HOME\" SENTINEL=\"$SENT\" ./docs/run-attacks.sh
    echo
    echo \"every attack blocked at the hook layer, before any tool ran.\"
    echo
    sleep 1.5
  '"

RAW="$GIF.raw"
agg --theme asciinema --font-size 14 "$CAST" "$RAW"

# mp4 from the full-quality render (even dimensions + yuv420p for broad playback)
ffmpeg -y -i "$RAW" -movflags +faststart -pix_fmt yuv420p \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" "$MP4" >/dev/null 2>&1

# optimized assets: live-demo.gif (full) + demo.gif (smaller README hero)
if command -v gifsicle >/dev/null 2>&1; then
  gifsicle -O3 --lossy=110 "$RAW" -o "$GIF"
  gifsicle -O3 --lossy=170 --scale 0.5 "$RAW" -o "$ROOT/demo.gif"
  rm -f "$RAW"
else
  mv "$RAW" "$GIF"
  cp "$GIF" "$ROOT/demo.gif"
fi

echo
echo "done:"
echo "  cast:     $CAST ($(du -h "$CAST" | cut -f1))"
echo "  live gif: $GIF  ($(du -h "$GIF" | cut -f1))"
echo "  hero gif: $ROOT/demo.gif ($(du -h "$ROOT/demo.gif" | cut -f1))"
echo "  mp4:      $MP4  ($(du -h "$MP4" | cut -f1))"
