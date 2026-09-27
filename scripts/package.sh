#!/usr/bin/env bash
# Build a deployment archive for LogsTotal (logstotal-<version>.7z).
#
# Produces a clean .7z in the current directory containing only what a target
# server needs — no .env, *.db, uploads/, .venv/, logs/, caches, tests/, or
# tools/tailwind/. Builds production CSS first (when the Tailwind CLI is present),
# then restores dev-mode CSS. It does NOT write VERSION: that is the release tool's job,
# and a build that rewrites a tracked file leaves `git status` dirty for every caller — which
# is also why the CSS mode is restored by a trap, not by a block at the end.
#
# Usage:
#   bash scripts/package.sh
#
# Env:
#   PACKAGE_USE_COMMITTED_CSS=true   with no Tailwind CLI, ship app/static/vendor/
#                                    tailwind-built.css as it stands instead of the Play CDN.
#                                    An explicit choice: nothing here can prove that file
#                                    matches these templates. See the CSS mode block below.
#
# Prerequisites:
#   - 7z (brew install p7zip on macOS, apt install p7zip-full on Linux)
#   - requirements.txt (run task lock first if missing)
#
# `set -e`, no pipefail. Assumes the repo root is the current working directory.

set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# ── Prerequisites ──
if ! command -v 7z >/dev/null 2>&1; then
  die "7z not found. Install: brew install p7zip (macOS) or apt install p7zip-full (Linux)"
fi
if [ ! -f requirements.txt ]; then
  die "requirements.txt not found. Run: ./logstotal lock"
fi

# ── Working-tree restoration ──
# ONE trap, registered once, before anything that can dirty the tree. Bash keeps only the
# LAST trap per signal, so the `.release-origin` cleanup and the CSS-mode restore below
# cannot each install their own — the second would silently disarm the first. Each sets a
# flag here instead.
#
# A trap, not a tail block: `task css:build` rewrites app/templates/base.html, a TRACKED file,
# and every way out of the script between there and the end — a failed 7z, an unreadable
# VERSION, a Ctrl-C — would otherwise leave the working tree switched to production mode.
STAMPED_ORIGIN=no
CSS_FLIPPED=no

cleanup() {
  local rc=$?
  if [ "$STAMPED_ORIGIN" = yes ]; then
    rm -f "$RELEASE_ORIGIN_FILE"
  fi
  if [ "$CSS_FLIPPED" = yes ]; then
    info "restoring dev mode"
    lt_task css:dev || warn "'./logstotal css:dev' failed — app/templates/base.html is left pointing at the compiled stylesheet. Run './logstotal css:dev' by hand."
  fi
  return $rc
}
trap cleanup EXIT

# ── CSS mode ──
# Which of the two stylesheets this archive serves, and the message must be true about it:
# this is the only place an operator learns which one they got.
CSS_BUILT="app/static/vendor/tailwind-built.css"

# base.html's OWN MODE is the discriminator, never the mere existence of the stylesheet.
# Same rule as the Dockerfile's css stage, for the same reason: tailwind-built.css is
# TRACKED, so every checkout has one whether or not it matches that checkout's templates.
base_html_is_prod() { [ -f app/templates/base.html ] && grep -q 'vendor/tailwind-built.css' app/templates/base.html; }

if [ -x tools/tailwind/tailwindcss ]; then
  info "building production CSS"
  lt_task css:build
  CSS_FLIPPED=yes
elif base_html_is_prod; then
  [ -s "$CSS_BUILT" ] || die "app/templates/base.html loads ${CSS_BUILT}, but that file is missing or empty.
       This tree renders unstyled as it stands, so the archive would too.
       Run './logstotal css:dev' for the Play CDN, or './logstotal tailwind:install && ./logstotal css:build'."
  note "Tailwind CLI not found, but base.html already loads $(value "$CSS_BUILT")" \
    "($(wc -c <"$CSS_BUILT" | tr -d ' ') bytes) — the archive ships that stylesheet, unchanged." \
    "It was NOT recompiled here. If a template changed since it was built, run" \
    "'./logstotal tailwind:install' and re-run './logstotal package'."
elif truthy "${PACKAGE_USE_COMMITTED_CSS:-}"; then
  [ -s "$CSS_BUILT" ] || die "PACKAGE_USE_COMMITTED_CSS=true, but ${CSS_BUILT} is missing or empty.
       Run './logstotal tailwind:install && ./logstotal css:build' to produce one."
  note "PACKAGE_USE_COMMITTED_CSS=true — pointing base.html at the committed stylesheet" \
    "($(wc -c <"$CSS_BUILT" | tr -d ' ') bytes) without recompiling it."
  lt_task css:prod
  CSS_FLIPPED=yes
  note "Tailwind emits only the classes it found in the templates AT THE TIME IT LAST" \
    "RAN, so a class added since is absent and those elements render unstyled, with" \
    "no error anywhere. './logstotal tailwind:install' is the build that cannot be stale."
else
  # The CLI is gitignored, so on a fresh clone or a runner without it this is the branch that
  # runs. It is not a failure — the app is fully correct this way — and the note says what the
  # archive contains rather than shouting about what it does not.
  note "tools/tailwind/tailwindcss not found — this archive serves Tailwind from the Play" \
    "CDN bundle it ships (app/static/vendor/tailwind.js). Every class renders; the cost" \
    "is a ~120 KB gzipped compiler running in the browser on every page load." \
    "" \
    "${CSS_BUILT} is committed and sits right there, but nothing" \
    "here can check that it matches these templates — Tailwind emits only the" \
    "classes it saw when it ran — and a stale stylesheet drops styling silently." \
    "So it is not used unless you ask. Two ways to production CSS:" \
    "  ./logstotal tailwind:install && ./logstotal package        # compile it here (one download)" \
    "  PACKAGE_USE_COMMITTED_CSS=true ./logstotal package  # ship the committed file as-is"
fi

# Named for the version, not the build date. A date-stamped asset is not a stable
# download URL: `docs/runbooks/upgrading.md` gives operators a copy-paste
# `releases/download/vX.Y.Z/logstotal-….7z`, which a date stamp would silently rename on a
# `workflow_dispatch` rebuild of the same tag — and two releases on one day would collide.
# Read from the committed VERSION manifest — the same file app/config.py reads at
# startup — so the archive name and the version the app reports can never disagree.
ARCHIVE_VERSION=$(read_version_file)
# Loud, not "${ARCHIVE_VERSION:-unknown}". Packaging only READS the manifest, so the guard
# lives at the read. An empty value names the archive logstotal-unknown.7z and ships an
# app whose /health reports the in-code default — a build must fail on that, not relabel it.
[ -n "$ARCHIVE_VERSION" ] || die "could not read a version from ./VERSION — refusing to build logstotal-unknown.7z.
       VERSION is written by './logstotal release:prepare'. On a release checkout it should
       hold a single line: version: X.Y.Z"
ARCHIVE=$(package_basename "$ARCHIVE_VERSION")

# The go-task this release runs on, for every Linux architecture, verified against the pin in
# scripts/lib/task_bin.sh. It is what lets ./logstotal work on a host with no network — an
# offline bundle carries this archive whole — and with nothing installed first. Downloaded
# here, not committed: a pin bump would otherwise add its tarballs to history for good.
#
# PACKAGE_SKIP_GO_TASK=true builds without them, for a throwaway archive on a machine with no
# network. Hosts installed from it then need a network or their own go-task, and
# scripts/verify-artifacts.sh fails such an archive, so a release cannot be one.
# shellcheck source=scripts/lib/task_bin.sh
. "$SCRIPT_DIR/lib/task_bin.sh"
if truthy "${PACKAGE_SKIP_GO_TASK:-}"; then
  warn "PACKAGE_SKIP_GO_TASK=true — this archive carries no go-task; hosts installed from it need a network or their own go-task ${LT_TASK_MIN_VERSION}+."
else
  lt_task_stage_bundled "$(pwd)" || die "the archive needs go-task ${LT_TASK_VERSION} under ${LT_TASK_BUNDLE_DIR}/ and could not fetch it.
       Copy task_linux_amd64.tar.gz and task_linux_arm64.tar.gz from
       ${LT_TASK_URL_BASE}/v${LT_TASK_VERSION}/ into ${LT_TASK_BUNDLE_DIR}/ and re-run,
       or build without it: PACKAGE_SKIP_GO_TASK=true."
  ok "go-task ${LT_TASK_VERSION} staged for $(value "$LT_TASK_BUNDLED_PLATFORMS")"
fi

# Stamp the server this archive is published from, so the deployment it becomes can resolve
# its own upgrades. An archive install has no .git, so release_repo_url() has nothing to
# derive from and falls back to a built-in default that is wrong for every self-hosted
# instance; an SSH origin cannot be normalised to a web URL at all (no scheme, no port).
#
# Only when the caller passes it, and only from CI: both release workflows have
# `${{ github.server_url }}/${{ github.repository }}`, which is the server that is about to
# hold the asset. A locally built package stamps nothing rather than guessing from an origin
# that may be an unreachable normalisation of an SSH URL.
if [ -n "${RELEASE_REPO_URL:-}" ]; then
  printf 'url: %s\n' "${RELEASE_REPO_URL%/}" > "$RELEASE_ORIGIN_FILE"
  ok "stamped ${RELEASE_ORIGIN_FILE}: $(value "${RELEASE_REPO_URL%/}")"
  # Removed on exit: it belongs to the archive, not to the working tree. The removal is done
  # by cleanup() above — one trap for the whole script, because a second `trap … EXIT` here
  # would replace it rather than add to it.
  STAMPED_ORIGIN=yes
fi
# deploy-envs/, backups/, fleet/, certs/ and testkit/ hold live secrets (certs/ is the
# PROXY_TLS=custom key mount), production data or one host's own architecture — none of it
# may ship. They are gitignored, so they never show up in a diff; exclude them by name. The
# `-x!` excludes are anchored to the archive root and are *not* recursive: `-x!.env` does
# not cover an env file nested in one of those directories, so the directory itself goes.
# .env.example is NOT excluded — it is the template the instructions below tell the
# operator to copy, and a `.env.*` glob would swallow it.
# deploy.env is operator config (DEPLOY_HOSTS, SSH_IDENTITY). CLAUDE.md and
# CLAUDE-internals.md are gitignored local development notes and are excluded as a pair.
# The rest is build and editor detritus.
# `-mf=off` disables the executable filters, and it is not a tuning knob — it is what makes
# the published archive readable by the 7z every target host actually has.
#
# scripts/ci-provision.sh installs 7zz from 7-zip.org AS `7z`, so releases are built by
# 7-Zip 21+, which applies the ARM64 BCJ filter to the vendored ARM binaries.
# scripts/deploy-bootstrap.sh installs `p7zip-full`, which is p7zip 17.05 or older and
# predates that filter: it reports `ERROR: Unsupported Method` for those five entries and
# exits 2, having extracted everything else. So a filtered archive, extracted the way
# docs/install/prerequisites.md tells operators to — and the way deploy-multiserver.sh does on every
# host — would produce a tree with no detection binaries and a failure naming a compression
# method.
#
# Measured on the two ARM binaries: filtered 6,664,598 bytes and p7zip exit 2; unfiltered
# 7,150,467 bytes and p7zip exit 0. Roughly 7% larger, and it opens.
7z a -mx=9 -mmt=on -ms=on -mf=off "$ARCHIVE" . \
  '-x!.env' \
  '-x!.env.deploy.sha256' \
  '-x!.env.bak' \
  '-x!.env.local' \
  '-x!.env.prod' \
  '-x!.env.production' \
  '-x!.env.staging' \
  '-x!deploy.env' \
  '-x!docker-compose.override.yml' \
  '-x!CLAUDE.md' \
  '-x!CLAUDE-internals.md' \
  '-xr!.coverage' \
  '-xr!htmlcov' \
  '-xr!.github' \
  '-xr!.forgejo' \
  '-xr!.cursor' \
  '-xr!.superpowers' \
  '-xr!*.db' \
  '-xr!uploads' \
  '-xr!data' \
  '-x!deploy-envs' \
  '-x!fleet' \
  '-x!certs' \
  '-x!backups' \
  '-x!testkit' \
  '-xr!.venv' \
  '-x!.bin' \
  '-x!site' \
  '-xr!logs' \
  '-xr!.git' \
  '-xr!.gitignore' \
  '-xr!.DS_Store' \
  '-xr!.__*' \
  '-xr!__MACOSX' \
  '-xr!.Spotlight-V100' \
  '-xr!.Trashes' \
  '-xr!.fseventsd' \
  '-xr!.pdm-python' \
  '-xr!.vscode' \
  '-xr!.claude' \
  '-xr!tests' \
  '-xr!tools/tailwind*' \
  '-xr!__pycache__' \
  '-xr!*.pyc' \
  '-xr!*.pyo' \
  '-xr!.pytest_cache' \
  '-xr!.ruff_cache' \
  '-xr!logstotal-*.7z' \
  '-xr!logstotal-*.7z.sha256' \
  '-xr!logstotal.db*'
# Written beside the archive so the release workflow can publish it, and so an operator
# copying the archive onto media can copy its checksum too. See common.sh's note on what a
# checksum does and does not prove.
printf '%s  %s\n' "$(file_sha256 "$ARCHIVE")" "$(basename "$ARCHIVE")" > "${ARCHIVE}.sha256"

banner_open
kv "Created" "$ARCHIVE"
kv "Checksum" "${ARCHIVE}.sha256"
printf '\n'
printf '  Deploy on target server:\n'
printf '    7z x %s -o/opt/logstotal\n' "$ARCHIVE"
printf '    cd /opt/logstotal\n'
printf '    ./logstotal quickstart        # .env, all secrets, preflight, up, health — one command\n'
printf '\n'
printf '    Or the manual equivalent:\n'
printf '      cp .env.example .env  # then edit: set SECRET_KEY, ADMIN_EMAIL, ADMIN_PASSWORD\n'
printf '      ./logstotal docker:up\n'
banner_close
