#!/usr/bin/env bash
set -euo pipefail

mode="${1:---dry-run}"
case "$mode" in
  --dry-run | --publish) ;;
  *)
    echo "usage: $0 [--dry-run|--publish]" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for required_command in cargo curl gh git jq python3 tar; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "release identity: missing required command $required_command" >&2
    exit 1
  fi
done

release_repo="${SENTINEL_RELEASE_REPO:-StressTestor/sentinel}"
crate_name="sentinel-guard"
source_sha="${GITHUB_SHA:-$(git rev-parse HEAD)}"
source_ref="${GITHUB_REF:-}"

if [[ -z "${GITHUB_SHA:-}" ]] \
  && [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "release identity: local verification requires a clean committed worktree" >&2
  exit 1
fi

git cat-file -e "${source_sha}^{commit}"
if ! git show-ref --verify --quiet refs/remotes/origin/main; then
  echo "release identity: origin/main is not available; fetch the canonical main branch" >&2
  exit 1
fi
if ! git merge-base --is-ancestor "$source_sha" refs/remotes/origin/main; then
  echo "release identity: $source_sha is not reachable from canonical origin/main" >&2
  exit 1
fi

package_metadata="$(cargo metadata --locked --no-deps --format-version 1)"
package_version="$(
  jq -r --arg name "$crate_name" \
    '.packages[] | select(.name == $name) | .version' \
    <<<"$package_metadata"
)"
if [[ -z "$package_version" || "$package_version" == "null" ]]; then
  echo "release identity: could not resolve the Cargo package version" >&2
  exit 1
fi
release_tag="v${package_version}"

if [[ "$mode" == "--publish" ]]; then
  if [[ "$source_ref" != "refs/tags/$release_tag" ]]; then
    echo "release identity: publish requires refs/tags/$release_tag, got '$source_ref'" >&2
    exit 1
  fi
elif [[ -n "$source_ref" && "$source_ref" != "refs/heads/main" ]]; then
  echo "release identity: dry runs must be dispatched from main, got '$source_ref'" >&2
  exit 1
fi

if git show-ref --tags --verify --quiet "refs/tags/$release_tag"; then
  tagged_sha="$(git rev-parse "refs/tags/$release_tag^{commit}")"
  if [[ "$tagged_sha" != "$source_sha" ]]; then
    echo "release identity: $release_tag points to $tagged_sha, not $source_sha" >&2
    exit 1
  fi
elif [[ "$mode" == "--publish" ]]; then
  echo "release identity: publish tag $release_tag is missing" >&2
  exit 1
fi

if [[ "$mode" == "--publish" ]]; then
  remote_tag_refs="$(
    git ls-remote --tags origin \
      "refs/tags/$release_tag" \
      "refs/tags/$release_tag^{}"
  )"
  remote_tag_sha="$(
    awk '$2 ~ /\^\{\}$/ { print $1; found = 1 } END { if (!found) exit 1 }' \
      <<<"$remote_tag_refs" 2>/dev/null \
      || awk -v ref="refs/tags/$release_tag" '$2 == ref { print $1 }' \
        <<<"$remote_tag_refs"
  )"
  if [[ -z "$remote_tag_sha" || "$remote_tag_sha" != "$source_sha" ]]; then
    echo "release identity: remote $release_tag points to '${remote_tag_sha:-missing}', not $source_sha" >&2
    exit 1
  fi
fi

identity_root="$(mktemp -d "${TMPDIR:-/tmp}/sentinel-release-identity.XXXXXX")"
trap 'rm -rf "$identity_root"' EXIT
user_agent="sentinel-release-identity/1.0 ($release_repo)"
curl_args=(
  -A "$user_agent"
  --connect-timeout 10
  --max-time 45
  --retry 3
  --retry-all-errors
  --retry-delay 2
)

version_response="$identity_root/version.json"
version_status="$(
  curl "${curl_args[@]}" -sS -o "$version_response" -w '%{http_code}' \
    "https://crates.io/api/v1/crates/$crate_name/$package_version"
)"

crate_published=false
if [[ "$version_status" == "200" ]]; then
  crate_published=true
  published_crate="$identity_root/$crate_name-$package_version.crate"
  curl "${curl_args[@]}" -fsSL \
    "https://static.crates.io/crates/$crate_name/$crate_name-$package_version.crate" \
    -o "$published_crate"
  published_vcs_sha="$(
    tar -xOf "$published_crate" \
      "$crate_name-$package_version/.cargo_vcs_info.json" \
      | jq -r '.git.sha1'
  )"
  if [[ "$published_vcs_sha" != "$source_sha" ]]; then
    echo "release identity: crates.io $package_version came from $published_vcs_sha, not $source_sha" >&2
    exit 1
  fi
elif [[ "$version_status" == "404" ]]; then
  registry_response="$identity_root/crate.json"
  curl "${curl_args[@]}" -fsSL \
    "https://crates.io/api/v1/crates/$crate_name" \
    -o "$registry_response"
  registry_max="$(jq -r '.crate.max_version' "$registry_response")"
  python3 - "$package_version" "$registry_max" <<'PY'
import re
import sys

candidate, current = sys.argv[1:3]
stable = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
if not stable.fullmatch(candidate):
    raise SystemExit(f"release identity: candidate {candidate!r} is not a stable semver")
if not stable.fullmatch(current):
    raise SystemExit(f"release identity: registry max {current!r} is not a stable semver")
if tuple(map(int, candidate.split("."))) <= tuple(map(int, current.split("."))):
    raise SystemExit(
        f"release identity: candidate {candidate} is not newer than crates.io {current}"
    )
PY
else
  cat "$version_response" >&2
  echo "release identity: crates.io returned HTTP $version_status" >&2
  exit 1
fi

release_exists=false
release_draft=false
if gh release view "$release_tag" --repo "$release_repo" \
  --json tagName,isDraft,url >"$identity_root/release.json" 2>/dev/null; then
  release_exists=true
  release_draft="$(jq -r '.isDraft' "$identity_root/release.json")"
fi

if [[ "$release_exists" == "true" \
  && "$release_draft" != "true" \
  && "$crate_published" != "true" ]]; then
  echo "release identity: public $release_tag exists but crates.io $package_version is missing" >&2
  exit 1
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "version=$package_version"
    echo "tag=$release_tag"
    echo "sha=$source_sha"
    echo "crate_published=$crate_published"
    echo "release_exists=$release_exists"
    echo "release_draft=$release_draft"
  } >>"$GITHUB_OUTPUT"
fi

echo "release identity: version=$package_version tag=$release_tag sha=$source_sha"
echo "release identity: crate_published=$crate_published release_exists=$release_exists release_draft=$release_draft"
