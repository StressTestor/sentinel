#!/usr/bin/env bash
# ad5-network-lint.sh - enforce "no ambient network calls" claim.
#
# greps src/ for outbound-network imports. fails if any appear outside
# the allowlist (opt-in network modules). the allowlist grows as later
# releases add opt-in network features:
#   current - src/audit/        (docker sandbox; talks to the docker daemon)
#   future  - src/classifier/   (local Ollama)
#   future  - src/policy/sync/  (git-distributed policy)
#   future  - src/audit_trail/sinks/  (webhook/syslog sinks)
#
# usage: bash scripts/ad5-network-lint.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"

# forbidden import/type/macro names. literal grep - one per line.
# bollard:: is included: it's a declared dependency (Cargo.toml) that speaks
# to the docker daemon, so a `use bollard::` outside the audit path is egress.
FORBIDDEN_PATTERN='reqwest|hyper::|TcpStream|TcpListener|UdpSocket|ureq::|isahc::|attohttpc::|surf::|bollard::'

# allowlist: paths that are permitted to use the above (opt-in network paths).
#
# src/audit - the `sentinel audit` sandbox is the one intentional network
#   user: it drives docker for container isolation (today via the docker CLI
#   subprocess; bollard is declared in Cargo.toml for the docker API). it is
#   opt-in (only runs on `sentinel audit`), never on the evaluate hook path.
#
# everything else in src/ - including the entire hook path (evaluate/,
# policy/, selfprotect/, heuristic/, install/) - must stay network-free.
declare -a ALLOWLIST=(
    "src/audit"
)

# build grep exclusion flags from the allowlist. --exclude-dir matches
# basename only, which is fine since our allowlist paths point at unique
# leaf directories under src/.
exclude_args=()
for path in "${ALLOWLIST[@]:-}"; do
    exclude_args+=(--exclude-dir="$(basename "$path")")
done

echo "AD-5 lint: scanning $SRC for ambient network calls..."

# use `grep -rE` (POSIX) rather than ripgrep so the lint runs on minimal CI.
# scan only .rs files, skip target/, skip allowlisted modules.
matches="$(grep -rEn "$FORBIDDEN_PATTERN" \
    --include='*.rs' \
    --exclude-dir=target \
    "${exclude_args[@]}" \
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
