#!/usr/bin/env bash
# Assert that a built release archive, and the built Docker image, carry what they should
# and nothing they should not.
#
# Called by BOTH CIs (.github/workflows/ci.yml and .forgejo/workflows/ci.yml). It lives
# here rather than inline in either so the two cannot diverge.
#
# Usage:
#   bash scripts/verify-artifacts.sh archive [<path.7z>]   # defaults to newest logstotal-*.7z
#   bash scripts/verify-artifacts.sh image [<tag>]         # defaults to logstotal:ci
#
# Exits non-zero with a ::error:: annotation on the first failure. Safe to run locally.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

# The verdict, then the annotation. `::error::` is a GitHub Actions instruction — it is
# what puts the message on the pull request's Files tab — so it is not decoration and does
# not go through the palette; it is also invisible when this is run locally, which is the
# other half of the reason the human line exists beside it.
fail() {
  v_fail "$1"
  echo "::error::$1" >&2
  exit 1
}

# Paths that must never appear in a shipped artifact: secrets, operator state, and the
# gitignored local development notes. The notes are a pair — a guard listing one of them
# passes while the other ships.
FORBIDDEN_EXACT=(.env deploy.env docker-compose.override.yml CLAUDE.md CLAUDE-internals.md)
FORBIDDEN_PREFIX=(deploy-envs backups data .bin site)

verify_archive() {
  local archive="${1:-}"
  if [ -z "$archive" ]; then
    # shellcheck disable=SC2012  # our own archive names are version-stamped and shell-safe
    archive=$(ls -1t logstotal-*.7z 2>/dev/null | head -1 || true)
  fi
  [ -n "$archive" ] || fail "no logstotal-*.7z archive found to verify"
  [ -f "$archive" ] || fail "archive not found: $archive"
  command -v 7z >/dev/null 2>&1 || fail "7z not found (install p7zip)"

  info "inspecting $(value "$archive")"
  local listing
  listing=$(mktemp)
  # `7z l -ba -slt` emits one `Path = <name>` line per entry, which is exact. The
  # human-readable listing has a fixed-width column layout that differs between p7zip and
  # the 7zz static build, so matching against it guesses at whitespace.
  7z l -ba -slt "$archive" | sed -n 's/^Path = //p' | sort >"$listing"
  info "entries: $(wc -l <"$listing" | tr -d ' ')"

  # The template must ship: it is what the docs tell operators to copy.
  grep -qx '.env.example' "$listing" || {
    grep -i env "$listing" | head
    fail ".env.example missing from the archive"
  }
  # And the application itself, or the archive is an empty shell that installs cleanly.
  grep -qx 'app/main.py' "$listing" || fail "app/main.py missing from the archive"
  # The command runner, and the go-task it runs on for every Linux host. Without the tarballs
  # an archive still installs where there is a network, which is exactly why it would pass
  # every other check and then fail on the offline host a bundle was built for.
  grep -qx 'logstotal' "$listing" || fail "the ./logstotal runner is missing from the archive"
  local platform
  for platform in linux_amd64 linux_arm64; do
    grep -qx "tools/go-task/task_${platform}.tar.gz" "$listing" ||
      fail "tools/go-task/task_${platform}.tar.gz missing — package.sh must not be run with PACKAGE_SKIP_GO_TASK for a release"
  done

  local entry
  for entry in "${FORBIDDEN_EXACT[@]}"; do
    grep -qx "$entry" "$listing" && fail "$entry present in the archive"
  done
  for entry in "${FORBIDDEN_PREFIX[@]}"; do
    grep -q "^${entry}/" "$listing" && fail "${entry}/ present in the archive"
  done
  # Recursive: the vendored rule sets arrive as clones, and a bare `.git` pattern misses
  # tools/hayabusa/rules/.git — 103 MB of pack files.
  grep -qE '(^|/)\.git/' "$listing" && fail "a .git directory is present in the archive"

  # The release origin stamp. Only CI passes RELEASE_REPO_URL, so this is a warning locally
  # and a failure in CI: an archive published without it leaves every host installed from it
  # resolving upgrades against the built-in default, which is wrong for any self-hosted
  # instance — and nothing about that failure names this archive as the cause.
  if grep -qx '.release-origin' "$listing"; then
    v_pass "release origin stamped"
  elif [ -n "${CI:-}" ]; then
    fail ".release-origin missing — pass RELEASE_REPO_URL to scripts/package.sh"
  else
    note "no .release-origin (locally built archive; CI stamps it)"
  fi

  # No executable filter. 7-Zip 21+ applies an ARM64 BCJ filter to the vendored ARM
  # binaries, and the p7zip that scripts/deploy-bootstrap.sh installs on every host cannot
  # decode it — `ERROR: Unsupported Method`, exit 2, no detection binaries on disk. The
  # archive has to open with the tool the docs tell people to install, so package.sh passes
  # -mf=off and this is what keeps it there.
  local filtered
  filtered=$(7z l -slt "$archive" 2>/dev/null | sed -n 's/^Method = //p' | grep -iE 'arm|bcj|delta|ppc|sparc|ia64' | head -1 || true)
  [ -z "$filtered" ] || fail "archive uses an executable filter ($filtered) — package.sh must pass -mf=off.
The ARM64 one in particular (Method 0A) postdates the p7zip on every target host."

  rm -f "$listing"
  v_pass "archive contents verified"
  info "$(v_tally)"
}

verify_image() {
  local tag="${1:-logstotal:ci}"
  command -v docker >/dev/null 2>&1 || fail "docker not found"

  local path
  for path in "${FORBIDDEN_EXACT[@]}" "${FORBIDDEN_PREFIX[@]}"; do
    if docker run --rm --entrypoint sh "$tag" -c "test -e /app/$path" 2>/dev/null; then
      fail "/app/$path is present in the image"
    fi
  done
  docker run --rm --entrypoint sh "$tag" -c "test -f /app/app/main.py" \
    || fail "the image is missing the application"
  docker run --rm --entrypoint sh "$tag" -c "test -f /app/.env.example" \
    || fail "the image is missing the .env template"
  # Same recursive .git check as the archive, for the same 103 MB reason.
  if docker run --rm --entrypoint sh "$tag" -c "find /app -name .git -maxdepth 6 | grep -q ." 2>/dev/null; then
    fail "a .git directory is present in the image"
  fi
  v_pass "image contents verified"
  info "$(v_tally)"
}

case "${1:-}" in
  archive) verify_archive "${2:-}" ;;
  image) verify_image "${2:-}" ;;
  *)
    echo "usage: $0 {archive|image} [path-or-tag]" >&2
    exit 2
    ;;
esac
