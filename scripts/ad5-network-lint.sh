#!/usr/bin/env bash
# ad5-network-lint.sh - enforce "no ambient network calls" claim.
#
# greps src/ for outbound-network imports. fails if any appear outside
# the allowlist (opt-in network modules). the allowlist grows as later
# releases add opt-in network features:
#   v0.3 - src/classifier/      (local Ollama)
#   v0.4 - src/policy/sync/     (git-distributed policy)
#   v0.4 - src/audit_trail/sinks/  (webhook/syslog sinks)
#
# usage: bash scripts/ad5-network-lint.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"

# forbidden import/type/macro names. literal grep - one per line.
FORBIDDEN_PATTERN='reqwest|hyper::|TcpStream|TcpListener|UdpSocket|ureq::|isahc::|attohttpc::|surf::'

# allowlist: paths that are permitted to use the above (opt-in network paths).
# v0.2: empty. update as later versions add opt-in network features.
declare -a ALLOWLIST=()

echo "AD-5 lint: scanning $SRC for ambient network calls..."

# use `grep -rE` (POSIX) rather than ripgrep so the lint runs on minimal CI.
# scan only .rs files, skip target/, skip allowlisted modules.
matches="$(grep -rEn "$FORBIDDEN_PATTERN" \
    --include='*.rs' \
    --exclude-dir=target \
    "$SRC" || true)"

if [[ -n "$matches" ]]; then
    echo "AD-5 VIOLATION: outbound-network imports found outside allowlist:" >&2
    echo "$matches" >&2
    echo "" >&2
    echo "if this is an intentional opt-in network feature, add the module path" >&2
    echo "to the ALLOWLIST in scripts/ad5-network-lint.sh" >&2
    exit 1
fi

echo "AD-5 lint: clean. no ambient network calls in src/."
