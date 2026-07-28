#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

sentinel_bin="${1:-target/debug/sentinel}"
if [[ ! -x "$sentinel_bin" ]]; then
  echo "docs claims: build the sentinel binary first" >&2
  exit 1
fi

check_root="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-doc-claims.XXXXXX")"
trap 'rm -rf "$check_root"' EXIT

verify_output="$(HOME="$check_root/home" "$sentinel_bin" verify)"
verified_ratio="$(
  sed -n 's/^ok: \([0-9][0-9]*\/[0-9][0-9]*\) attack.*/\1/p' <<<"$verify_output" \
    | tail -n 1
)"
if [[ -z "$verified_ratio" ]]; then
  echo "docs claims: could not read the verifier case count" >&2
  exit 1
fi

claim_files=(README.md ARCHITECTURE.md docs/index.html)
for claim_file in "${claim_files[@]}"; do
  [[ -f "$claim_file" ]] || continue
  while IFS= read -r claimed_ratio; do
    if [[ "$claimed_ratio" != "$verified_ratio" ]]; then
      echo "docs claims: $claim_file says verify is $claimed_ratio; binary says $verified_ratio" >&2
      exit 1
    fi
  done < <(
    grep -Ei 'verify' "$claim_file" \
      | grep -Eo '[0-9]+/[0-9]+' \
      || true
  )
done

if grep -Eini \
  '220\+[[:space:]]+(adversarial|attack)|aho-corasick automata from attack corpus|local llm|three[- ]tier' \
  README.md ARCHITECTURE.md docs/index.html; then
  echo "docs claims: public documentation contains a removed or unshipped product claim" >&2
  exit 1
fi

help_output="$("$sentinel_bin" --help)"
documented_commands="$(
  {
    awk '
      /^## commands$/ { in_commands = 1; next }
      in_commands && /^## / { exit }
      in_commands && /^sentinel[[:space:]]+[a-z][a-z0-9-]*/ { print $2 }
    ' README.md
    grep -Eho '`sentinel[[:space:]]+[a-z][a-z0-9-]*' \
      README.md ARCHITECTURE.md docs/index.html \
      | sed -E 's/^`sentinel[[:space:]]+//'
  } | sort -u
)"
while IFS= read -r command_name; do
  [[ -n "$command_name" ]] || continue
  if ! grep -Eq "^[[:space:]]+${command_name}[[:space:]]" <<<"$help_output"; then
    echo "docs claims: documentation names missing command 'sentinel $command_name'" >&2
    exit 1
  fi
done <<<"$documented_commands"

echo "docs claims: verifier count, shipped tiers, and documented commands match"
