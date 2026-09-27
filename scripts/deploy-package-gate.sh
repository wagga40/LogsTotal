#!/usr/bin/env bash
# Package gate for a fleet deploy — decides whether to build a fresh
# logstotal-*.7z before the deploy runs.
#
# Reads DEPLOY_PACKAGE and DEPLOY_DRY_RUN through deploy_env_load, exactly as
# scripts/deploy-multiserver.sh does right after it, so `DEPLOY_DRY_RUN=true` in
# deploy.env governs both halves of the task — this one never builds a real package
# inside a dry run.
#
# Env (all optional; caller env wins over deploy.env):
#   BUNDLE           deploy from a self-contained bundle: the archive plus every image,
#                    for a host with no network at all (scripts/bundle.sh builds one)
#   VERSION          deploy that published release, downloading it once here
#   ARCHIVE          deploy exactly this archive (path or https URL); no release lookup
#   DEPLOY_PACKAGE   explicit archive path — nothing is built
#   DEPLOY_DRY_RUN   true: decide nothing, build nothing
#   DEPLOY_REBUILD   true/false: force or forbid the rebuild, overriding the staleness
#                    check below. There is no prompt to skip — see the note there.
#   DEPLOY_ALLOW_DOWNGRADE  true: deploy a tree older than the last release deployed from
#                    here. Refused by default — see the downgrade guard below.
#   DEPLOY_ENV_FILE  defaults file (default: deploy.env)

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

deploy_env_load DEPLOY_PACKAGE DEPLOY_DRY_RUN DEPLOY_REBUILD DEPLOY_ALLOW_DOWNGRADE

# Refuse to push a release older than the one this workstation last deployed.
#
# `task upgrade` in package mode stages nothing locally — the fleet gets the
# published archive — so the checkout's VERSION still names the release it upgraded FROM.
# A bare `task deploy` afterwards would package that tree and push it, which is
# a DOWNGRADE of production reported as an ordinary deploy, with a filename that looks right
# because it is named for the tree it was built from.
# `2>/dev/null` AFTER the input redirection does not suppress its failure: the shell
# applies redirections left to right and reports `< missing-file` before stderr has been
# moved anywhere. On a host that has never been upgraded — every first deploy — that would
# print a bare "No such file or directory" naming an internal bookkeeping file, so the
# redirections are ordered the other way round.
last_deployed=$(tr -d '[:space:]' 2>/dev/null < backups/.last-deployed-release || true)
tree_version=$(read_version_file)
if [ -z "${BUNDLE:-}${ARCHIVE:-}${VERSION:-}${DEPLOY_PACKAGE:-}" ] && [ -n "$last_deployed" ] && [ -n "$tree_version" ] && [ "$last_deployed" != "$tree_version" ]; then
  newest=$(printf '%s\n%s\n' "$last_deployed" "$tree_version" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
  if [ "$newest" = "$last_deployed" ]; then
    # Not die(): the message is the same either way, and DEPLOY_ALLOW_DOWNGRADE turns
    # this from a refusal into a warning — so it is printed once, to stderr, and only the
    # exit differs. warn() carries the embedded newlines exactly as die() does.
    warn "this tree is ${tree_version}, but the last release deployed from here was ${last_deployed}.
       Deploying it would push an OLDER release over the fleet.

       To upgrade:            ./logstotal upgrade
       To go back on purpose: ./logstotal upgrade VERSION=${tree_version}
       To deploy this tree anyway: DEPLOY_ALLOW_DOWNGRADE=true ./logstotal deploy"
    truthy "${DEPLOY_ALLOW_DOWNGRADE:-false}" || exit 1
    warn "DEPLOY_ALLOW_DOWNGRADE=true — continuing."
  fi
fi

if truthy "${DEPLOY_DRY_RUN:-false}"; then
  info "(dry-run: skipping package build/check)"
  exit 0
fi

if [ -n "${DEPLOY_PACKAGE:-}" ]; then
  info "using DEPLOY_PACKAGE=$(value "$DEPLOY_PACKAGE")"
  exit 0
fi

# ── Deploying a BUNDLE ───────────────────────────────────────────────────────
#
# A bundle is the release archive plus every image it needs. Opened here, once, on the
# machine running the deploy: the archive is handed on as DEPLOY_PACKAGE the way any other
# would be, and the image tarballs are left beside it for deploy-multiserver.sh to copy to
# each host and `docker load` there.
#
# Unpacked rather than shipped whole because the archive and the images travel differently:
# the archive is extracted into a staging directory and rsynced, the images are loaded into
# a daemon. One transport for both would mean every host unpacking the whole ~430 MB bundle
# to reach the 125 MB archive inside it.
if [ -n "${BUNDLE:-}" ]; then
  [ -f "$BUNDLE" ] || die "BUNDLE not found: ${BUNDLE}"
  require_cmd 7z "A bundle is a .7z, like the release archive inside it."

  bash "$SCRIPT_DIR/bundle.sh" verify "$BUNDLE"
  bundle_dir="$(pwd)/.bundle"
  rm -rf "$bundle_dir"
  mkdir -p "$bundle_dir"
  info "opening $(basename "$BUNDLE")"
  7z x -y -o"$bundle_dir" "$BUNDLE" >/dev/null

  [ -f "${bundle_dir}/bundle-manifest.json" ] ||
    die "no bundle-manifest.json inside ${BUNDLE} — is it a LogsTotal bundle?
       Check it first with: ./logstotal bundle:verify -- ${BUNDLE}"

  bundle_archive=$(run_py -c \
    "import json,sys;print(json.load(open(sys.argv[1]))['archive'])" \
    "${bundle_dir}/bundle-manifest.json")
  [ -f "${bundle_dir}/${bundle_archive}" ] ||
    die "the manifest names ${bundle_archive} and the bundle does not contain it."

  info "deploying from the bundle: $(value "$bundle_archive")"
  info "  images will be loaded on each host from .bundle/images/"
  exit 0
fi

# ── Deploying a PUBLISHED release ────────────────────────────────────────────
#
# `task deploy VERSION=1.0.0` and `task deploy ARCHIVE=<path or URL>`, the same two knobs
# `task upgrade` already answers — because "which release" is the same question whether it
# is the first install or the fifth, and answering it two different ways is how an operator
# ends up deploying something other than what they upgraded to last week.
#
# Without this a deploy could only ship THIS TREE, repackaged — right on a developer's
# checkout and wrong everywhere else: an operator who downloaded and extracted a release
# would get a rebuild of it rather than the artifact CI published and tested — and
# on a host with no Tailwind CLI, `task package` produces one with development CSS.
if [ -n "${ARCHIVE:-}" ] || [ -n "${VERSION:-}" ]; then
  target="${ARCHIVE:-}"
  if [ -z "$target" ]; then
    tag="v${VERSION#v}"
    is_release_tag "$tag" || die "VERSION=${VERSION} is not X.Y.Z."
    # `|| rc=$?`, because a bare call is a plain command and `set -e` kills the script on a
    # non-zero return — BEFORE the case below can read it, leaving both arms unreachable:
    # an unpublished VERSION or an unreachable release server would exit 2 with NOTHING on
    # stdout or stderr, from the FIRST command of `task deploy`.
    rc=0
    release_artifact_exists "$tag" || rc=$?
    case $rc in
      1) die "no package published for ${tag} at $(release_repo_url).
       Pick another with VERSION=X.Y.Z, or point at a file with ARCHIVE=<path>." ;;
      2) warn "could not reach $(release_repo_url) to check ${tag} — trying anyway." ;;
    esac
    target=$(release_package_url "$tag")
  fi

  case "$(basename "${target%%\?*}")" in
    *.7z) ;;
    *) die "a fleet deploy needs a .7z package — every host extracts it with 7z.
       Got: $(basename "$target")" ;;
  esac

  if echo "$target" | grep -qE '^https?://'; then
    # Downloaded ONCE, here, and scp'd to every host — not fetched per host. Hosts on a
    # closed network never reach the release server at all, which is the point.
    dest="$(pwd)/$(basename "${target%%\?*}")"
    if [ -f "$dest" ]; then
      ok "already downloaded: $(basename "$dest")"
    else
      info "curl -fL ${target}"
      curl -fL "${CURL_DOWNLOAD_OPTS[@]}" "$target" -o "$dest"
      verify_downloaded_artifact "$dest" "$target"
    fi
    target="$dest"
  fi
  [ -f "$target" ] || die "ARCHIVE not found: ${target}"

  # No handoff needed. This runs as a separate process before deploy-multiserver.sh, so it
  # cannot export anything — but the download lands in the current directory under its
  # published name, and resolve_package already picks the newest `logstotal-*.7z` there.
  # The freshly written file is newest by definition.
  info "deploying the published release: $(value "$(basename "$target")")"
  exit 0
fi

# shellcheck disable=SC2012  # newest-first by mtime; the names are generated
# (logstotal-<version>.7z), so there is nothing for `find -print0` to protect against.
existing=$(ls -t logstotal-*.7z 2>/dev/null | head -1 || true)

if [ -z "$existing" ]; then
  info "no logstotal-*.7z found — building package"
  lt_task package
  exit 0
fi

info "found existing package: $(value "$existing")"

# An explicit answer skips the prompt entirely — the only way a cron/CI caller can
# say what it wants.
if [ -n "${DEPLOY_REBUILD:-}" ]; then
  if truthy "$DEPLOY_REBUILD"; then
    info "DEPLOY_REBUILD=${DEPLOY_REBUILD} — rebuilding."
    lt_task package
  else
    info "DEPLOY_REBUILD=${DEPLOY_REBUILD} — using $existing"
  fi
  exit 0
fi

# No prompt. `read -r reply </dev/tty` blocks forever whenever a terminal exists — and this
# runs as the FIRST step of a fleet deploy, right before the archive is pushed, where a hang
# looks like "the deploy hangs when it pushes files".
#
# It is also a question the operator cannot answer better than we can. The archive is named
# for the version it carries, so "is it current?" is a fact, not a preference: reuse it when
# it matches this tree exactly, rebuild when it cannot be shown to.
# DEPLOY_REBUILD remains the override for anyone who disagrees.
#
# Two questions, and neither needs git — which a control plane, where upgrades run, does
# not have.
#
# A name match: package.sh derives BOTH the archive filename and the app's reported version
# from the same `version:` line, so they cannot disagree — and with upgrades restricted to
# published releases, the version string IS the code identity.
#
# A -newer sweep for "you edited code since you packaged": editing a file updates its
# mtime, so no dirty-tree test is needed.
stale_reason=""
# read_version_file swallows its own failure, and must: this script runs under
# `set -euo pipefail`, so a missing VERSION makes sed exit non-zero, pipefail propagates it,
# and the assignment would abort the whole gate before it can report the reason — the one
# thing it exists to do.
want=$(read_version_file)
if [ ! -f VERSION ]; then
  stale_reason="no VERSION file to compare against"
elif [ -z "$want" ]; then
  stale_reason="VERSION carries no version: line"
elif [ "$existing" != "$(package_basename "$want")" ]; then
  stale_reason="the newest archive is ${existing}, this tree is ${want}"
else
  newer=$(find app alembic scripts workflows config Taskfile.yml requirements.txt \
    Dockerfile docker-compose.yml VERSION -newer "$existing" -print 2>/dev/null | head -1 || true)
  if [ -n "$newer" ]; then
    stale_reason="the archive predates ${newer}"
  fi
fi

if [ -z "$stale_reason" ]; then
  ok "using $(value "$existing") (matches VERSION ${want}, and no source file is newer than it)"
else
  info "rebuilding: ${stale_reason}."
  info "  (set DEPLOY_REBUILD=false to reuse $existing anyway)"
  lt_task package
fi
