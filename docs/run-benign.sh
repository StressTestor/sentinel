#!/usr/bin/env bash
# run-benign.sh — exercises normal maintenance flows that sentinel should allow.
#
# usage:
#   ./run-benign.sh
#   SENTINEL=./target/release/sentinel ./run-benign.sh

set -e

SENTINEL="${SENTINEL:-sentinel}"
if [[ "$SENTINEL" == */* ]]; then
  SENTINEL="$(cd "$(dirname "$SENTINEL")" && pwd)/$(basename "$SENTINEL")"
fi
TMP_HOME="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_HOME"
}
trap cleanup EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

total=0
allowed=0

HOME="$TMP_HOME" "$SENTINEL" install --enforce >/dev/null

fire() {
  local desc="$1"
  local tool="$2"
  local input="$3"
  total=$((total + 1))

  printf "${BOLD}${CYAN}[%02d]${RESET} %s\n" "$total" "$desc"
  printf "     ${YELLOW}tool:${RESET} %s  ${YELLOW}input:${RESET} %s\n" "$tool" "$input"

  local payload
  payload=$(printf '{"tool_name":"%s","tool_input":%s}' "$tool" "$input")

  local result
  result=$(HOME="$TMP_HOME" "$SENTINEL" evaluate 2>/dev/null <<< "$payload" || true)

  if printf '%s' "$result" | grep -q '"permissionDecision":"deny"'; then
    printf "     ${RED}DENIED${RESET}  %s\n\n" "$(printf '%s' "$result" | sed 's/.*"reason":"\([^"]*\)".*/\1/')"
  else
    allowed=$((allowed + 1))
    printf "     ${GREEN}ALLOWED${RESET}  %s\n\n" "$result"
  fi

  sleep 0.1
}

printf "${BOLD}sentinel benign replay${RESET}\n"
printf "replaying ordinary maintenance tasks that should pass through the hook layer\n\n"

fire "cargo test in repo" \
  "Bash" '{"command":"cargo test --lib"}'

fire "package.json test script edit" \
  "Edit" '{"file_path":"./workspace/package.json","old_string":"\"test\": \"vitest\"","new_string":"\"test\": \"vitest --run\""}'

fire "workflow maintenance edit" \
  "Edit" '{"file_path":"./workspace/.github/workflows/ci.yml","old_string":"cargo test","new_string":"cargo test --workspace"}'

fire "vscode build task" \
  "Edit" '{"file_path":"./workspace/.vscode/tasks.json","old_string":"{}","new_string":"{\"version\":\"2.0.0\",\"tasks\":[{\"label\":\"build\",\"command\":\"pnpm build\"}]}"}'

fire "pnpm install in clean workspace" \
  "Bash" '{"command":"pnpm install"}'

printf "${BOLD}===================================${RESET}\n"
printf "${BOLD}result:${RESET} ${GREEN}%d / %d allowed${RESET}\n" "$allowed" "$total"
printf "${BOLD}===================================${RESET}\n"

if [ "$allowed" -lt "$total" ]; then
  exit 1
fi
