#!/usr/bin/env bash
# ad5-network-lint.sh - enforce "no ambient network calls" claim.
#
# Greps all Rust source for outbound-network imports. No source subtree is
# exempt. If a future opt-in network feature needs an exception, scope it to
# the narrowest exact path and document the reason alongside its tests.
#
# usage: bash scripts/ad5-network-lint.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"

# Forbidden import/type/macro names. Docker daemon clients are included because
# daemon access is network-equivalent.
FORBIDDEN_PATTERN='reqwest|hyper::|TcpStream|TcpListener|UdpSocket|ureq::|isahc::|attohttpc::|surf::|bollard::'

echo "AD-5 lint: scanning $SRC for ambient network calls..."

# use `grep -rE` (POSIX) rather than ripgrep so the lint runs on minimal CI.
# scan only .rs files and skip target/.
matches="$(grep -rEn "$FORBIDDEN_PATTERN" \
    --include='*.rs' \
    --exclude-dir=target \
    "$SRC" || true)"

if [[ -n "$matches" ]]; then
    echo "AD-5 VIOLATION: outbound-network imports found in src/:" >&2
    echo "$matches" >&2
    echo "" >&2
    echo "if this is intentional, add a narrowly scoped, reviewed exception" >&2
    echo "with a justification and tests." >&2
    exit 1
fi

echo "AD-5 lint: clean. no ambient network calls in src/."
