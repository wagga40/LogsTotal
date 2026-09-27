#!/usr/bin/env bash
# Everything a release hands to an operator: the compose files, the image, the archive.
#
# Unexercised, a .dockerignore gap ships credentials and a database dump inside every
# image unnoticed. It lives in a script rather than as
# `cmds:` in the Taskfile for one concrete reason: it has to borrow the `.env` slot, and
# borrowing without a trap that gives it back is how a developer loses their configuration.
#
# Usage:  bash scripts/ci-artifacts.sh
# Env:    IMAGE_TAG   image tag to build and inspect (default logstotal:ci)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

cd "$REPO_ROOT"

IMAGE_TAG="${IMAGE_TAG:-logstotal:ci}"

require_cmd docker "Install Docker Engine + the compose plugin."

# `scripts/package.sh` rebuilds app/static/vendor/tailwind-built.css and rewrites
# base.html; it restores base.html itself, but the stylesheet is its build output and it
# leaves that in place. Verifying must not mutate the tree, so it is snapshotted here.
CSS_BUILT="app/static/vendor/tailwind-built.css"
CSS_SNAPSHOT=$(mktemp)
cp "$CSS_BUILT" "$CSS_SNAPSHOT" 2>/dev/null || true

cleanup() {
  local rc=$?
  docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
  rm -f "${REPO_ROOT}"/logstotal-*.7z
  [ -s "$CSS_SNAPSHOT" ] && cp "$CSS_SNAPSHOT" "$CSS_BUILT"
  rm -f "$CSS_SNAPSHOT"
  ci_env_return
  return $rc
}
trap cleanup EXIT

step "Compose files parse"
# Both declare `env_file: .env`, which does not exist in a fresh checkout — Compose then
# refuses to render the config at all. The example is the documented starting point, so it
# is what this validates against.
ci_env_borrow
docker compose config -q
docker compose -f docker-compose.worker.yml config -q
info "both compose files render"

step "The image builds"
docker build -t "$IMAGE_TAG" .

step "The image carries no secrets or operator state"
bash scripts/verify-artifacts.sh image "$IMAGE_TAG"

step "The release archive builds"
# Tailwind first, or package.sh leaves base.html in dev mode and the archive serves the Play
# CDN, and the archive CI verifies would not be the archive a release publishes.
# scripts/ci-provision.sh puts a cached copy in place on a runner; this is the fallback for a
# local run. Deliberately NOT PACKAGE_USE_COMMITTED_CSS: that ships the stylesheet in the
# tree without recompiling, and the whole point here is that CI compiles what it verifies.
if [ ! -x tools/tailwind/tailwindcss ]; then
  lt_task tailwind:install
fi
# Stamp the release origin the same way the release workflows do, so the archive CI
# verifies is the same SHAPE as the one a release publishes — including `.release-origin`,
# which verify-artifacts.sh requires under CI. Both GitHub Actions and Forgejo Actions set
# these; locally they are unset, package.sh stamps nothing, and the check downgrades to a
# note. That asymmetry is deliberate: only a build that could become a release should be
# held to carrying the stamp.
if [ -z "${RELEASE_REPO_URL:-}" ] && [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  RELEASE_REPO_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}"
  export RELEASE_REPO_URL
fi
bash scripts/package.sh

step "The archive carries the template and no secrets"
bash scripts/verify-artifacts.sh archive

header "ARTIFACTS VERIFIED"
