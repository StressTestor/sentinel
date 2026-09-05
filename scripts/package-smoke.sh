#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

smoke_root="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-package-smoke.XXXXXX")"
trap 'rm -rf "$smoke_root"' EXIT

package_args=(package --locked)
if [[ "${SENTINEL_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_args+=(--allow-dirty)
fi

cargo "${package_args[@]}"

crate_file="$(
  find target/package -maxdepth 1 -type f -name 'sentinel-guard-*.crate' -print \
    | sort \
    | tail -n 1
)"
if [[ -z "$crate_file" ]]; then
  echo "package smoke: cargo did not produce a sentinel-guard crate" >&2
  exit 1
fi

tar -xzf "$crate_file" -C "$smoke_root"
package_source="$(
  find "$smoke_root" -mindepth 1 -maxdepth 1 -type d -name 'sentinel-guard-*' -print \
    | head -n 1
)"
if [[ -z "$package_source" ]]; then
  echo "package smoke: could not locate the extracted crate source" >&2
  exit 1
fi

vcs_file="$package_source/.cargo_vcs_info.json"
if [[ ! -f "$vcs_file" ]]; then
  echo "package smoke: .cargo_vcs_info.json is missing" >&2
  exit 1
fi

expected_sha="${SENTINEL_EXPECTED_VCS_SHA:-$(git rev-parse HEAD)}"
packaged_sha="$(sed -n 's/.*"sha1":[[:space:]]*"\([^"]*\)".*/\1/p' "$vcs_file")"
if [[ "$packaged_sha" != "$expected_sha" ]]; then
  echo "package smoke: packaged VCS SHA $packaged_sha does not match $expected_sha" >&2
  exit 1
fi

CARGO_TARGET_DIR="$smoke_root/package-test-target" \
  cargo test \
    --locked \
    --manifest-path "$package_source/Cargo.toml" \
    --all-targets \
    --all-features

install_root="$smoke_root/install"
CARGO_TARGET_DIR="$smoke_root/install-target" \
  cargo install --locked --path "$package_source" --root "$install_root"

sentinel_bin="$install_root/bin/sentinel"
if [[ ! -x "$sentinel_bin" ]]; then
  echo "package smoke: installed sentinel binary is missing" >&2
  exit 1
fi

package_version="$(
  cargo metadata --locked --no-deps --format-version 1 \
    | jq -r '.packages[] | select(.name == "sentinel-guard") | .version'
)"
actual_version="$("$sentinel_bin" --version)"
if [[ "$actual_version" != "sentinel $package_version" ]]; then
  echo "package smoke: binary version '$actual_version' does not match $package_version" >&2
  exit 1
fi

help_output="$("$sentinel_bin" --help)"
printf '%s\n' "$help_output"
if grep -Eqi 'not yet implemented|unimplemented|coming soon' <<<"$help_output"; then
  echo "package smoke: public help advertises a stub" >&2
  exit 1
fi

while IFS= read -r command_name; do
  [[ -n "$command_name" && "$command_name" != "help" ]] || continue
  "$sentinel_bin" "$command_name" --help >/dev/null
done < <(
  awk '
    /^Commands:/ { in_commands = 1; next }
    in_commands && /^[[:space:]]{2}[a-z0-9][a-z0-9-]*[[:space:]]/ { print $1; next }
    in_commands && !/^[[:space:]]/ { exit }
  ' <<<"$help_output"
)

if grep -R -n -E 'todo!\(|unimplemented!\(|not yet implemented' "$package_source/src"; then
  echo "package smoke: packaged runtime contains a stub or panic placeholder" >&2
  exit 1
fi

empty_home="$smoke_root/home"
mkdir -p "$empty_home"
HOME="$empty_home" "$sentinel_bin" verify

echo "package smoke: packaged tests, VCS identity, install, verifier, and public commands passed"
