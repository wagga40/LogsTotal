#!/usr/bin/env bash
# Version-upgrade helper for LogsTotal (single-host Docker, multi-server).
#
# Thin action dispatcher for the upgrade:* Taskfile tasks; shared fragments come from
# scripts/lib/common.sh. The composed steps shell out to sibling tasks
# (task backup / env:diff / package / deploy:* / health:remote / doctor:docker /
# upgrade:stage-code).
#
# Usage:
#   bash scripts/upgrade.sh <action>
#
# Actions:
#   stage-code    Shared code-staging step (git checkout REF or archive overlay);
#                 re-entered as `task upgrade:stage-code` by the two flows below
#   docker        End-to-end single-host Docker upgrade (backup → stage → build → migrate → up → health)
#   multiserver   End-to-end multi-server upgrade (preflight → backup → stage/package → deploy → migrate → smoke)
#
# Environment consumed (values normally arrive via the Taskfile dispatchers,
# which bridge `task upgrade REF=v` and `REF=v task upgrade`
# into env — caller env always
# wins over the CLI template var):
#   VERSION       Pin a published release (1.0.0 or v1.0.0). Default: the latest one.
#   REF           An arbitrary git ref. Refused unless it is vX.Y.Z or ALLOW_UNRELEASED=true.
#   ALLOW_UNRELEASED  true: allow a branch/sha. Unsupported — see release_resolve_ref.
#   RELEASE_REPO_URL  Where releases live. Default: this checkout's own origin, normalised
#                 to https (a GitHub clone and a Forgejo clone each need no configuration).
#   SKIP_IF_CURRENT   true: exit 0 before the backup when already at the resolved release
#                 AND it is running (docker: this host; multiserver: every host in scope).
#   RESTAGE_IF_CURRENT  true: restage the release that is already installed AND running.
#                 Without it that case is REFUSED — re-running is a full rebuild and
#                 restart, which on a fleet is a rolling restart of every host. "Current,
#                 but nothing running" is the repair flow: it needs neither knob and
#                 always proceeds.
#   ARCHIVE       Path or https URL to a .zip/.tar.gz/.7z (archive mode; skips resolution).
#   BUNDLE        Path to a bundle: the release archive plus every image it needs, for a
#                 host with no network at all. Implies SOURCE=bundle. Built by
#                 scripts/bundle.sh on a machine that HAS a network.
#   HEALTH_URL    docker: base URL for the post-upgrade health probe (default http://localhost:8000).
#   SKIP_BACKUP   docker/multiserver: true skips the backup step (NOT RECOMMENDED).
#   DEPLOY_HOSTS  multiserver: comma-separated host list (first = control plane). Required.
#   SSH_IDENTITY / DEPLOY_REMOTE_DIR / DEPLOY_PACKAGE / DEPLOY_STOP / DEPLOY_KEEPENV / DEPLOY_START
#                 multiserver: passed through to the SSH steps and the fleet deploy.
#   DEPLOY_SMOKE_STRICT / DEPLOY_HEALTH_CONFIRMED
#                 set BY this script for its own smoke step, never by an operator: the first
#                 asks deploy-smoke.sh for a distinguishable exit code, the second tells it
#                 the control plane already reported healthy from inside its own network.
#
# `set -e`, no `set -o pipefail`, no `set -u`: the staging pipelines and `... || true`
# guards rely on non-zero upstream statuses not aborting the script. Assumes the repo root
# is the current working directory. python3 only.

set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# _source_kind — what the banner calls this run. ONE place, so the outer flow, the staging
# step and anything that reports on a run cannot describe the same run differently. It reads
# SOURCE, not just ARCHIVE: without that the outer banner would say `release` while
# stage-code says `archive` for the same upgrade — on every run, under the package default.
_source_kind() {
  case "${SOURCE:-}" in
    bundle)  printf 'bundle' ;;
    archive) printf 'archive' ;;
    git)     if is_release_tag "${REF:-}"; then printf 'git'; else printf 'git, unreleased'; fi ;;
    package) printf 'package' ;;
    *)
      # Called before _resolve_source (a bare `task upgrade:stage-code`).
      if [ -n "${BUNDLE:-}" ]; then printf 'bundle'
      elif [ -n "${ARCHIVE:-}" ]; then printf 'archive'
      elif is_release_tag "${REF:-}"; then printf 'release'
      else printf 'unreleased'
      fi
      ;;
  esac
}

# _resolve_source — decide WHERE the code comes from, and say so out loud.
#
# `package` is the default everywhere, a checkout included: the published .7z is the
# artifact CI built and tested, with the production stylesheet compiled in, and it is what
# production should run. Three refusals keep that honest, and they are
# refusals rather than warnings because each names a run that cannot do what it says.
_resolve_source() {
  local requested="${SOURCE:-}"
  case "$requested" in
    ""|package|git|archive|bundle) ;;
    *)
      # Strict, because SOURCE is a short generic name a caller's shell may already export.
      # Validating it turns ambient pollution into a message instead of a silent wrong mode.
      die "SOURCE=${requested} is not a source. One of:
         package   the published release archive (the default)
         git       a detached checkout of the release tag (needs .git here)
         archive   implied by ARCHIVE=<path|url>
         bundle    implied by BUNDLE=<path> — the archive plus every image it needs" ;;
  esac

  # BUNDLE= implies SOURCE=bundle, exactly as ARCHIVE= implies SOURCE=archive, and for the
  # same reason: naming a file IS the answer to "where does the code come from", so making
  # the operator say it twice only creates a way to disagree with themselves.
  if [ -n "${BUNDLE:-}" ]; then
    [ -n "${ARCHIVE:-}" ] && die "ARCHIVE= and BUNDLE= ask for different things.
       Drop one: a bundle CONTAINS an archive, along with every image it needs."
    [ "$requested" = "git" ] && die "SOURCE=git and BUNDLE= ask for different things."
    [ -f "$BUNDLE" ] || die "BUNDLE not found: ${BUNDLE}"
    SOURCE=bundle
    export SOURCE
    return 0
  fi
  [ "$requested" = "bundle" ] && die "SOURCE=bundle needs BUNDLE=<path> to name the file."

  if [ -n "${ARCHIVE:-}" ]; then
    [ "$requested" = "git" ] && die "SOURCE=git and ARCHIVE= ask for different things.
       Drop one: ARCHIVE= stages that exact file, SOURCE=git checks out the release tag."
    SOURCE=archive
    export SOURCE
    return 0
  fi
  [ "$requested" = "archive" ] && die "SOURCE=archive needs ARCHIVE=<path|url> to name the file."

  # An unreleased ref has no published package — the URL would be
  # .../releases/download/main/logstotal-main.7z, which cannot exist. Only git can stage one.
  if [ -n "${REF:-}" ] && ! is_release_tag "$REF"; then
    [ "$requested" = "package" ] && die "SOURCE=package cannot stage REF=${REF}: only a published
       release has a package. Use SOURCE=git, or pin a release with VERSION=X.Y.Z."
    SOURCE=git
  else
    SOURCE="${requested:-package}"
  fi

  if [ "$SOURCE" = "git" ] && [ ! -d .git ]; then
    die "SOURCE=git needs a git checkout, and there is no .git in $(pwd).
       This install came from a release archive — leave SOURCE unset to upgrade from one."
  fi
  export SOURCE
}

# _announce_source — one line saying where the code is coming from and how to change it,
# so an operator can tell which source they got and how to ask for the other.
_announce_source() {
  case "${SOURCE:-}" in
    package)
      if [ -d .git ]; then
        echo "  source: package (the published release archive) — this is a git checkout;"
        echo "          SOURCE=git checks out the release tag instead. The overlay will show"
        echo "          up in git status; git checkout -- . resets it."
      else
        echo "  source: package (the published release archive)"
      fi
      ;;
    git)     echo "  source: git (detached checkout of ${REF}) — SOURCE=package uses the published archive" ;;
    archive) echo "  source: archive (${ARCHIVE})" ;;
  esac
}

# _resolve_once — resolve the release for this whole run and export it to the
# `task upgrade:stage-code` subprocess.
#
# Once, in the outermost flow, deliberately: the banner, the already-current check and the
# checkout must all see one answer, and a release published mid-run must not change it
# between the parent and the child.
_resolve_once() {
  ARCHIVE="${ARCHIVE:-}"
  REF=$(release_resolve_ref) || exit 1
  # Settle the source here too, so the outer banner names the same one the staging step
  # will use, and so a contradictory request is refused before the backup rather than after.
  _resolve_source
  export VERSION REF ALLOW_UNRELEASED RELEASE_REPO_URL ARCHIVE SOURCE
  export _UPGRADE_REF_RESOLVED=1
  if [ "$SOURCE" = bundle ]; then
    bash "$SCRIPT_DIR/bundle.sh" verify "$BUNDLE"
    require_cmd 7z "Install 7zip to open the bundle."
    local bundle_stage
    bundle_stage=$(mktemp -d "$(pwd)/.bundle-stage.XXXXXX")
    7z x -y -o"$bundle_stage" "$BUNDLE" >/dev/null
    rm -rf .bundle
    mv "$bundle_stage" .bundle
    _UPGRADE_BUNDLE_ARCHIVE="$(pwd)/.bundle/$(run_py -c 'import json; print(json.load(open(".bundle/bundle-manifest.json"))["archive"])')"
    export DEPLOY_PACKAGE="$_UPGRADE_BUNDLE_ARCHIVE"
  fi
}

# _local_running_containers — how many containers this install has up, or "0".
#
# The local twin of host_installed_release's second field, and literally the same pipeline:
# it runs common.sh::compose_running_count_cmd here rather than over ssh, so the local
# answer and the remote one cannot drift. `|| true` rather than `|| printf 0`, because
# `grep -c .` prints 0 AND exits 1 when nothing matches, so a fallback appends a SECOND
# zero and the field arrives as "0\n0".
#
# Anything it cannot measure — no docker, no compose file, a daemon that is down — comes
# back empty and every caller reads that as zero, i.e. as the repair case. That is the
# inverse of deploy-preflight.sh's "never report OK for something you could not measure",
# and correct here because the failure modes are opposite: there an unmeasured value must
# not print OK, here an unmeasured value must not block a repair.
_local_running_containers() {
  eval "$(compose_running_count_cmd)" || true
}

# _gate_already_current WHAT — the shared answer to "you asked for the release you already
# have, and it is up".
#
# ONE function for both scopes. A single-host upgrade and a fleet upgrade asking different
# questions about the same situation is worse than either asking the wrong one.
#
# It is reached ONLY when the release matches AND something is running. "Current with
# nothing running" is what a half-finished upgrade leaves, and it never gets here — it
# falls through and restages, with no knob and no question. That
# is what keeps the REPAIR flow open, and the refusal below names it so an operator staring
# at the message can tell which case they are in.
#
# A REFUSAL, not a prompt. `read -r reply </dev/tty` is not usable in this script, measured
# both ways: with no controlling terminal (cron, and most CI) it fails the redirection, so
# a bare read exits 1 under `set -e` mid-flow and a guarded one leaks
# "/dev/tty: Device not configured"; and with a controlling terminal that nobody will type
# into it BLOCKS FOREVER — `ssh -t`, or an operator whose ~/.ssh/config sets
# `RequestTTY yes`, which host_installed_release documents as a real configuration. Do not
# add a prompt.
#
# Every line goes to stderr, including the guidance: a refusal split across two streams
# arrives interleaved in anything that captures them separately, and this block only reads
# correctly in order.
_gate_already_current() {
  local what="$1" restarts="$2"

  # The override is read HERE, not at either call site, so the two scopes cannot come to
  # disagree about what answers the question.
  if truthy "${RESTAGE_IF_CURRENT:-}"; then
    echo "  RESTAGE_IF_CURRENT=true — restaging the release already installed."
    return 0
  fi

  {
    echo ""
    # Not `warn`: this whole block is already inside `{ … } >&2`, and warn adds its own
    # redirect. Same look, through the one palette that a pipe can turn off.
    printf '%sWARN:%s %s\n' "${C_BOLD}${C_YELLOW}" "$C_OFF" "$what"
    echo "  Re-running is not a no-op: it rebuilds, migrates and restarts ${restarts}."
    echo ""
    echo "  Restage it anyway:            RESTAGE_IF_CURRENT=true ./logstotal upgrade"
    echo "  Meant a different release:    ./logstotal upgrade VERSION=X.Y.Z   (./logstotal upgrade:plan first)"
    echo "  Scheduled run, make it a no-op: SKIP_IF_CURRENT=true ./logstotal upgrade"
    echo ""
  } >&2
  die "already current and running — refusing without RESTAGE_IF_CURRENT=true.
       A half-finished upgrade leaves the code current and NOTHING running. That is the
       repair flow, it is never refused, and this is not it."
}

# _report_installed_version — installed vs what is about to be staged.
#
# Already-current does NOT exit when the deployment is DOWN, because this flow is also the
# REPAIR flow: a half-finished upgrade leaves the code current and the containers stopped,
# and "nothing to do" would strand exactly the operator who most needs it. When it is UP
# there is nothing to repair, so the run is refused unless RESTAGE_IF_CURRENT says
# otherwise. SKIP_IF_CURRENT=true is the idempotent no-op a cron caller wants, and it exits
# BEFORE the backup rather than after.
_report_installed_version() {
  local installed target running
  installed=$(read_version_file)
  [ -n "$installed" ] || return 0
  is_release_tag "${REF:-}" || return 0
  target="${REF#v}"

  if [ "$installed" = "$target" ]; then
    # Running is measured BEFORE SKIP_IF_CURRENT is honoured, so the two scopes answer the
    # same question in the same order. Skipping a stopped deployment is how a nightly cron
    # leaves a half-finished upgrade half-finished forever, and the fleet survey does not
    # either — see test_a_current_version_with_nothing_running_is_not_current.
    running=$(_local_running_containers)
    if [ "${running:-0}" -gt 0 ] 2>/dev/null; then
      info "Installed $(value "$installed"), target $(value "$REF") — already current, ${running} container(s) up."
      if truthy "${SKIP_IF_CURRENT:-}"; then
        info "SKIP_IF_CURRENT=true — nothing to do."
        exit 0
      fi
      _gate_already_current "this host is already running ${target}." "this host"
    else
      info "Installed $(value "$installed"), target $(value "$REF") — already current, but nothing is running."
      info "  That is the shape a half-finished upgrade leaves. Restaging it is the repair."
    fi
  elif [ "$(printf '%s\n%s\n' "$installed" "$target" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)" = "$installed" ]; then
    warn "${installed} -> ${target} is a DOWNGRADE. Migrations do not run backwards: if a
      release between the two applied a destructive migration you must restore the
      pre-upgrade database backup after staging — docs/runbooks/upgrading.md#when-rollback-is-unsafe"
  fi
}

# ── stage-code (was: task upgrade:stage-code) ─────────────────────────────────

do_stage_code() {
  local rc
  ARCHIVE="${ARCHIVE:-}"
  # The composed flows resolve first and export _UPGRADE_REF_RESOLVED; a bare
  # `task upgrade:stage-code` resolves for itself.
  if [ -z "${_UPGRADE_REF_RESOLVED:-}" ]; then
    REF=$(release_resolve_ref) || exit 1
  fi

  _resolve_source

  # The dirty-tree refusal, for EVERY source, ahead of the branch. Git mode is guarded by git
  # itself — `git checkout` refuses to clobber a modified tracked file — but package mode has
  # no such backstop: `rsync` has no "would be overwritten" abort, so an unguarded overlay
  # silently destroys uncommitted work, and package is the default on a checkout too.
  if [ -d .git ] && { ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; }; then
    die "working tree has uncommitted changes. Commit or stash before upgrading.
       Checked for every source: the package overlay rsyncs over your tree, and unlike
       git checkout there is nothing to refuse it."
  fi

  # Package mode: the published release asset for the ref we resolved.
  if [ "$SOURCE" = "package" ]; then
    # A TAG IS NOT A RELEASE. release_latest_tag reads tags, and a tag whose release job
    # failed resolves like any other — under git that merely checks out the tag, here it
    # 404s at download, after the backup has been taken. Ask before committing to it.
    # `|| rc=$?`, never a bare call: under `set -e` a function returning non-zero aborts
    # the script BEFORE `case $?` can read it, leaving every arm below dead and an
    # unreachable release server exiting silently.
    rc=0
    release_artifact_exists "$REF" || rc=$?
    case $rc in
      1) die "no package published for ${REF} at $(release_repo_url)
       The tag exists but its release asset does not — a release job that did not finish
       looks exactly like this. Pick another release with VERSION=X.Y.Z, or stage the tag
       from git with SOURCE=git." ;;
      2) warn "could not reach $(release_repo_url) to check the package for ${REF} — trying anyway." ;;
    esac
    # Require 7z rather than falling back to a source zip. That zip is
    # the COMMITTED tree, whose base.html is the Play-CDN dev bundle — a JIT compiler running
    # in the browser on every page load. `SOURCE=package` has to mean one artifact, or the
    # word means something different on each flow.
    command -v 7z >/dev/null 2>&1 || die "SOURCE=package needs 7z to open the release asset.
       Install it (apt install p7zip-full / brew install p7zip), or use SOURCE=git.
       Without it the download falls back to the source zip, which ships development CSS
       and is not the artifact CI published."
    ARCHIVE=$(release_package_url "$REF")
    info "source: package — $(package_basename "$REF")"
  fi

  # _archive_ext URL_OR_PATH — the archive suffix, or "" when it is not one we handle.
  #
  # An explicit case, not a regex: `.tar.gz` is two suffixes and every leftmost-longest
  # pattern gets it wrong. Query strings and directory prefixes are stripped first, so a
  # signed download URL (…/logstotal-<version>.7z?token=…) still resolves.
  _archive_ext() {
    local name="${1%%\?*}"
    name="${name##*/}"
    case "$name" in
      *.tar.gz) printf '.tar.gz' ;;
      *.tgz)    printf '.tgz' ;;
      *.zip)    printf '.zip' ;;
      *.7z)     printf '.7z' ;;
      *)        printf '' ;;
    esac
  }

  _extract_archive() {
    local archive="$1" dest="$2"
    case "$archive" in
      *.zip)
        if command -v unzip >/dev/null 2>&1; then
          unzip -q "$archive" -d "$dest"
        elif command -v 7z >/dev/null 2>&1; then
          7z x "$archive" -o"$dest" -y >/dev/null
        else
          python3 -m zipfile -e "$archive" "$dest"
        fi
        ;;
      *.tar.gz|*.tgz)
        tar -xzf "$archive" -C "$dest"
        ;;
      *.7z)
        if ! command -v 7z >/dev/null 2>&1; then
          die "7z required to extract .7z archives (brew install p7zip / apt install p7zip-full)."
        fi
        # Capture rather than discard. 7z exits 2 having extracted MOST of the tree, so a
        # partial extraction that dropped only the detection binaries would otherwise reach
        # the rsync overlay looking like a success. The one failure worth naming is a filter the
        # local 7z cannot decode: an archive built by 7-Zip 21+ carries the ARM64 filter,
        # and p7zip reports it as `Unsupported Method` against a path, never as a version
        # problem. package.sh passes -mf=off so releases from this project do not, but an
        # older release, or someone else's archive, still can.
        local out rc=0
        out=$(7z x "$archive" -o"$dest" -y 2>&1) || rc=$?
        if [ "$rc" -ne 0 ]; then
          printf '%s\n' "$out" | tail -20
          if printf '%s' "$out" | grep -q 'Unsupported Method'; then
            # `7z` with no arguments prints a BLANK first line, so `head -1` yields "".
            die "this 7z cannot decode the archive ($(7z 2>&1 | grep -m1 -oE '7-Zip[^:]*' | tr -d '\n')).
       The entries above use an executable filter added in 7-Zip 21; p7zip predates it and
       stops after extracting everything else, which is why the tree looks almost complete.
       Install a current 7-Zip (https://www.7-zip.org/download.html — the 7zz binary), or
       stage this release from git with SOURCE=git."
          fi
          die "extracting $(basename "$archive") failed (7z exit ${rc})."
        fi
        ;;
      *)
        die "unsupported archive type: $archive (expected .zip, .tar.gz, or .7z)"
        ;;
    esac
  }

  if [ -n "$ARCHIVE" ]; then
    header "upgrade:stage-code ($(_source_kind)) → ${ARCHIVE}"
    WORK=$(mktemp -d)
    LOCAL_ARCHIVE="$ARCHIVE"
    if echo "$ARCHIVE" | grep -qE '^https?://'; then
      EXT=$(_archive_ext "$ARCHIVE")
      # Refuse rather than guessing: defaulting an unrecognised URL to .zip would download
      # an extension-less URL as a .zip and then fail to extract it as one.
      [ -n "$EXT" ] || die "cannot tell the archive type of ${ARCHIVE} — expected .zip, .tar.gz, .tgz or .7z.
       Download it first and pass the local path: ./logstotal upgrade ARCHIVE=/path/to/file.7z"
      LOCAL_ARCHIVE="${WORK}/download${EXT}"
      info "curl -fL ${ARCHIVE}"
      curl -fL "${CURL_DOWNLOAD_OPTS[@]}" "$ARCHIVE" -o "$LOCAL_ARCHIVE"
      verify_downloaded_artifact "$LOCAL_ARCHIVE" "$ARCHIVE"
    fi
    if [ ! -f "$LOCAL_ARCHIVE" ]; then
      die "archive not found: $ARCHIVE"
    fi
    EXTRACT="$WORK/extract"
    mkdir -p "$EXTRACT"
    info "extract $(basename "$LOCAL_ARCHIVE")"
    _extract_archive "$LOCAL_ARCHIVE" "$EXTRACT"
    STAGED="$EXTRACT"
    TOPLEVEL=$(find "$EXTRACT" -mindepth 1 -maxdepth 1 2>/dev/null)
    if [ "$(echo "$TOPLEVEL" | wc -l | tr -d ' ')" -eq 1 ]; then
      SINGLE=$(echo "$TOPLEVEL" | head -1)
      if [ -f "$SINGLE/Taskfile.yml" ]; then
        STAGED="$SINGLE"
        info "strip top-level dir: $(basename "$SINGLE")"
      fi
    fi
    # What the overlay must not touch, whichever shape this install is.
    # `.release-origin` is excluded and then reinstated below, deliberately. It records the
    # server this deployment upgrades from, and --delete would remove it whenever the
    # incoming archive does not carry one, so the host would silently fall back to the
    # built-in default on its NEXT upgrade.
    OVERLAY_EXCLUDES=(--exclude=.env --exclude=.env.deploy.sha256 --exclude=data --exclude=uploads --exclude=backups
      --exclude=.bundle --exclude=certs --exclude=deploy-envs --exclude=deploy.env --exclude=.git
      --exclude=.venv --exclude=.bin --exclude=docker-compose.override.yml --exclude='*.db' --exclude='logstotal-*.7z'
      --exclude="$RELEASE_ORIGIN_FILE")

    # On a checkout, keep the tree's OWN base.html and built stylesheet. The archive ships
    # them in production mode (package.sh runs css:build, archives, then restores dev mode)
    # while HEAD holds the Play-CDN block — so overlaying them leaves the tree permanently
    # dirty, and the next `SOURCE=git` run dies on the guard above naming no file. It costs
    # nothing: the Dockerfile rebuilds both in its css stage and copies them over whatever
    # `COPY . .` laid down, so what is on disk here never reaches the image.
    if [ -d .git ]; then
      OVERLAY_EXCLUDES+=(--exclude=app/templates/base.html --exclude=app/static/vendor/tailwind-built.css)
    fi

    # --delete, but only where the release is the complete definition of the directory.
    #
    # A release archive IS the whole tree, so on an archive install --delete is right
    # everywhere: it is what retires files renamed or removed upstream. On a CHECKOUT it
    # would be wrong everywhere — package.sh excludes tests/,
    # .github/ and .gitignore, so a full --delete would wipe tracked files the archive never
    # claimed to carry. There, git is what reconciles removals.
    #
    # alembic/versions/ gets --delete either way, and that one is not cosmetic. Without it
    # `task upgrade VERSION=<older>` leaves the newer revisions on disk,
    # get_head_revision() resolves head to a migration the installed code does not contain,
    # and the migrate step rolls the SCHEMA FORWARD while the operator rolls the code back.
    # Several shipped migrations are destructive, and this is the documented rollback path.
    # Compare content, as rollback does: different releases can contain files with the
    # same size and mtime. The default quick check can silently keep the old VERSION
    # or application code while reporting a successful upgrade.
    if [ -d .git ]; then
      info "rsync staged tree over $(pwd) (--delete on alembic/versions only; git owns the rest)"
      rsync -a --checksum "${OVERLAY_EXCLUDES[@]}" "$STAGED"/ ./
      if [ -d "$STAGED/alembic/versions" ]; then
        rsync -a --checksum --delete "$STAGED"/alembic/versions/ ./alembic/versions/
      fi
    else
      info "rsync staged tree over $(pwd) (--delete; the archive is the whole tree)"
      rsync -a --checksum --delete "${OVERLAY_EXCLUDES[@]}" "$STAGED"/ ./
    fi
    # A stamp in the incoming archive wins — a release moved to another forge has to be
    # able to say so — but its ABSENCE must not erase what the host already knew.
    if [ -f "${STAGED}/${RELEASE_ORIGIN_FILE}" ]; then
      cp "${STAGED}/${RELEASE_ORIGIN_FILE}" "./${RELEASE_ORIGIN_FILE}"
      info "release origin: $(release_repo_url) (from the archive)"
    elif [ -f "$RELEASE_ORIGIN_FILE" ]; then
      info "release origin: $(release_repo_url) (kept; this archive carries none)"
    fi

    # The staged tree's own VERSION is authoritative. Nothing regenerates it: a release
    # archive ships the manifest its release was cut with, and a tree that arrives without
    # one falls back to app/config.py's in-code default rather than inventing a number.
    [ -f VERSION ] || warn "the staged tree has no VERSION file — /health will report the in-code default."
  elif [ -d .git ]; then
    header "upgrade:stage-code ($(_source_kind)) → ${REF}"
    info "git fetch --all --tags"
    REF_NAME="${REF#origin/}"
    FETCH_RC=0
    # The same prompt guards as git_ls_remote_tags, for the same reason: a private remote
    # asks for a username and waits, and here BOTH streams are captured, so the operator
    # watches a command that has printed "git fetch --all --tags" and then says nothing
    # ever again. No timeout addresses that — the call is not slow, it is waiting.
    #
    # No hard ceiling on this one, unlike the ls-remote: a fetch legitimately transfers a
    # repository. `http.lowSpeedLimit`/`lowSpeedTime` bound the way it can *stall* — they
    # do not bound the connect (measured), so a blackholed remote still costs the kernel's
    # SYN timeout here. That is bounded, slow, and only reachable from a git checkout,
    # never from a control plane.
    FETCH_OUT=$(
      GIT_TERMINAL_PROMPT=0 \
        GIT_ASKPASS=/bin/echo \
        SSH_ASKPASS=/bin/echo \
        GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=${RELEASE_NET_TIMEOUT} -o StrictHostKeyChecking=accept-new" \
        git -c credential.helper= -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=60 \
        fetch --all --tags 2>&1
    ) || FETCH_RC=$?
    if [ -n "$FETCH_OUT" ]; then printf '%s\n' "$FETCH_OUT"; fi
    if [ "$FETCH_RC" -ne 0 ]; then
      # git refuses to move a tag that already exists here, and ONE such tag fails the
      # WHOLE fetch — including every tag this upgrade never looks at. Refusing is right:
      # --force would silently rewrite whichever side is correct, and a release tag is the
      # one thing an upgrade must not guess at. Aborting the run is not right. By this point
      # preflight has passed and a verified backup has been taken, and the operator is being
      # stopped by `! [rejected] vX.Y.Z -> vX.Y.Z (would clobber existing tag)` — a line that
      # names a tag and nothing else: not that an upgrade halted, not which side is wrong,
      # not that the tag has nothing to do with the release being deployed.
      CLOBBERED=$(printf '%s\n' "$FETCH_OUT" |
        sed -n 's/.*\[rejected\][[:space:]]*\([^ ]*\).*would clobber existing tag.*/\1/p' | sort -u | tr '\n' ' ')
      if [ -z "$CLOBBERED" ]; then
        die "git fetch failed, and not over a tag conflict. The upgrade needs it."
      fi
      echo ""
      echo "  These tags differ between this checkout and the server: ${CLOBBERED}"
      echo "  Inspect one:   git rev-parse <tag>^{}   vs   git ls-remote --tags origin <tag>"
      echo "  Keep yours:    git push --force origin refs/tags/<tag>"
      echo "  Take theirs:   git tag -d <tag> && git fetch --tags origin"
      echo "  Neither is done for you — each destroys one of the two answers."
      case " ${CLOBBERED}" in
        *" ${REF_NAME} "*)
          echo ""
          die "${REF_NAME} is the release being deployed, and the two copies disagree.
       Checking out this one would install something other than the published
       ${REF_NAME}. Resolve that tag, then re-run the upgrade."
          ;;
      esac
      echo ""
      warn "none of them is ${REF_NAME}, so the upgrade continues — the tag it needs
      fetched cleanly. The disagreement above is still worth settling."
    fi
    if git show-ref --verify --quiet "refs/remotes/origin/${REF_NAME}" 2>/dev/null; then
      info "git checkout --detach origin/${REF_NAME}"
      git checkout --detach "origin/${REF_NAME}"
    else
      info "git checkout ${REF}"
      git checkout "$REF"
    fi
  else
    die "nothing to stage — no archive, no checkout, and no release resolved.

  ./logstotal upgrade VERSION=X.Y.Z
  ./logstotal upgrade ARCHIVE=/path/to/logstotal-X.Y.Z.7z"
  fi
}

# ── Code snapshots (single host) ──────────────────────────────────────────────
#
# Like the fleet — deploy-multiserver.sh snapshots every host's tree before extracting over
# it — a single host keeps a rollback point that `task upgrade:rollback` restores and
# consumes. Re-running the upgrade with an older version is no substitute: it needs the
# network, needs that release to still be published, and cannot remove a file the newer
# release added.
#
# Snapshots live under backups/, not in a new top-level releases/ directory, and that is
# load-bearing rather than tidy-minded. `backups/` is ALREADY in .gitignore, .dockerignore,
# package.sh's excludes, verify-artifacts.sh's forbidden prefixes and every remote_snapshot
# rsync exclude — so a snapshot cannot be committed, baked into an image, shipped inside a
# release archive, or copied into another snapshot. A top-level directory would need all
# five taught about it, and one of them could never arrive: package.sh excludes .gitignore,
# so a checkout upgraded by package overlay would never receive the ignore rule, and
# scripts/release.py counts untracked files.

# _newest_snapshot — path of the most recent snapshot, or "".
#
# Names lead with the zero-padded timestamp, so a lexical sort IS chronological order.
# Leading with the VERSION would not be an ordering: "1.10.0" sorts before "1.9.0", so
# `upgrade:rollback` would pick an older snapshot over the newest, and the prune, which
# takes from the HEAD of the same list, would delete the newest snapshots instead of the
# oldest — invisible until a version crosses a 9 → 10 boundary.
_newest_snapshot() {
  # shellcheck disable=SC2012  # the names are generated (<timestamp>-<version>), so there
  # is nothing for `find -print0` to protect against, and the lexical sort IS the ordering.
  ls -d "${SNAPSHOT_ROOT}"/*/ 2>/dev/null | tail -1 | sed 's#/$##' || true
}

# _snapshot_code — copy the installed tree aside so upgrade:rollback has something to
# restore. Fails the upgrade if it cannot: an operator told they can roll back, who finds
# out otherwise while already recovering, is worse off than one told up front. That is the
# fleet's rule (deploy-multiserver.sh refuses to continue without a rollback point) and it
# applies here for the same reason.
_snapshot_code() {
  local installed newest
  installed=$(read_version_file)
  if [ -z "$installed" ]; then
    warn "no readable VERSION — skipping the code snapshot (nothing to label it with)."
    return 0
  fi

  # Re-running an upgrade that is already current is the REPAIR flow, and it must not evict
  # the rollback point. Without this, a second run snapshots the new release over the old
  # one and `task upgrade:rollback` quietly becomes a no-op.
  newest=$(_newest_snapshot)
  if [ -n "$newest" ] && [ "$(read_version_file "$newest")" = "$installed" ]; then
    info "snapshot: $(basename "$newest") already holds ${installed} — keeping it"
    return 0
  fi

  command -v rsync >/dev/null 2>&1 || die "rsync is required to snapshot the current release for rollback.
       Install it (apt install rsync / brew install rsync), or re-run with SKIP_SNAPSHOT=true
       to upgrade with no local rollback point."

  local dest stamp
  stamp=$(date +%Y%m%d-%H%M%S)
  # <timestamp>-<version>, timestamp first: see _newest_snapshot for why the other way
  # round is not an ordering.
  dest="${SNAPSHOT_ROOT}/${stamp}-${installed}"
  mkdir -p "$dest"
  local excludes=()
  while IFS= read -r line; do excludes+=("$line"); done < <(snapshot_excludes)
  if ! rsync -a "${excludes[@]}" ./ "${dest}/"; then
    rm -rf "$dest"
    die "snapshot failed — refusing to upgrade with no rollback point.
       Re-run with SKIP_SNAPSHOT=true to accept that."
  fi
  info "snapshot: ${dest} (rollback point for ${installed})"

  # Prune, oldest first. Same knob as the fleet — one concept, one number to reason about.
  local keep total
  keep="${DEPLOY_KEEP_RELEASES:-$(deploy_env_default DEPLOY_KEEP_RELEASES)}"
  keep="${keep:-3}"
  # shellcheck disable=SC2012,SC2010  # generated names; lexical order is chronological
  total=$(ls -d "${SNAPSHOT_ROOT}"/*/ 2>/dev/null | grep -c . || true)
  if [ "${total:-0}" -gt "$keep" ]; then
    # shellcheck disable=SC2012  # same
    ls -d "${SNAPSHOT_ROOT}"/*/ | head -n "$(( total - keep ))" | xargs rm -rf
    echo "  pruned to ${keep} snapshots"
  fi
}

# _revision_files [DIR] — every alembic revision filename under DIR, sorted.
# A glob loop rather than `ls | xargs basename`: the names are ours, but the loop is both
# shorter and correct for a directory that does not exist yet.
_revision_files() {
  local dir="${1:-.}" f
  for f in "${dir%/}"/alembic/versions/*.py; do
    [ -e "$f" ] || continue
    basename "$f"
  done | sort
}

# ── rollback (task upgrade:rollback) ──────────────────────────────────────────

do_rollback() {
  local snap installed target
  snap=$(_newest_snapshot)
  [ -n "$snap" ] || die "no snapshot to roll back to (${SNAPSHOT_ROOT}/ is empty).
       Snapshots are written by ./logstotal upgrade, starting with the next one.
       To go back without one: ./logstotal upgrade VERSION=X.Y.Z"

  installed=$(read_version_file)
  target=$(read_version_file "$snap")
  header "upgrade:rollback → ${target:-?} (from ${installed:-?})"

  # A code rollback across a migration is the one case where restoring the tree alone is
  # unsafe: the database stays stamped at the newer revision, and app/migrations.py refuses
  # to boot past a revision it can no longer find on disk. Compare the revision FILES, which
  # is cheap and needs no database connection.
  local lost
  lost=$(comm -23 <(_revision_files .) <(_revision_files "$snap") | tr '\n' ' ')
  if [ -n "${lost// /}" ]; then
    local compatible=false backend db_path
    backend=$(run_py "$SCRIPT_DIR/backup_lifecycle.py" backend)
    if [ "$backend" = sqlite ]; then
      if db_path=$(resolve_sqlite_target) && DATABASE_URL="sqlite:///$db_path" BACKUP_CONTEXT=host run_py "$SCRIPT_DIR/db_target.py" rollback "$snap"; then compatible=true; fi
    elif [ -f docker-compose.yml ] && command -v docker >/dev/null 2>&1; then
      if docker compose run --rm --no-deps -T --pull never web python3 scripts/db_target.py rollback "$snap" --context host; then compatible=true; fi
    elif run_py "$SCRIPT_DIR/db_target.py" rollback "$snap"; then
      compatible=true
    fi
    [ "$compatible" = true ] || die "${installed:-this release} applied migrations that ${target:-the snapshot} does not contain:
         ${lost}
       Restoring the code alone would leave the database stamped at a revision the restored
       app cannot find, and it will refuse to boot. Restore the pre-upgrade database first:
         ./logstotal restore:sqlite BACKUP_FILE=backups/<file>.db      (or restore:postgres)
       then re-run this. See docs/runbooks/upgrading.md#when-rollback-is-unsafe."
  fi

  command -v rsync >/dev/null 2>&1 || die "rsync is required to restore a snapshot."

  # --delete: a rollback that leaves the
  # newer release's files behind has not rolled anything back. The excludes are what keep
  # .env, data/, uploads/ and backups/ (which holds this very snapshot) out of its reach.
  #
  # --checksum is not an optimisation setting; without it a rollback silently restores the
  # WRONG CONTENT. rsync's default quick check skips a file whose size and whole-second
  # mtime both match, and a snapshot preserves the original mtimes (-a) while the upgrade
  # that replaced them ran moments later. A VERSION manifest is one short line, so two
  # consecutive releases produce files of IDENTICAL size — it is the likeliest file in the
  # tree to collide, and a fast machine hits exactly that: the rollback prints "restored ...
  # (consumed)" and then reports the version it just rolled back FROM. Compare content instead.
  local excludes=()
  while IFS= read -r line; do excludes+=("$line"); done < <(snapshot_excludes)
  if ! rsync -a --checksum --delete "${excludes[@]}" "${snap}/" ./; then
    die "restore failed — the snapshot is kept at ${snap} so you can retry."
  fi

  # Only after a verified restore. Consuming it is what makes a second rollback go back a
  # second release, the deploy:rollback semantics.
  rm -rf "$snap"
  info "restored ${snap} (consumed)"

  # A tree restore changes nothing on its own: no code is bind-mounted, so the containers
  # keep running the image built from the newer release. Printing success here without
  # rebuilding is the silently-false success the fleet's rollback tests exist to stop.
  info "docker compose build"
  docker compose build
  info "docker compose up -d"
  docker compose up -d
  info "waiting 10s for services to settle"
  sleep 10
  HEALTH_URL="${HEALTH_URL:-http://localhost:8000}" lt_task health:remote

  upgrade_done rollback "${HEALTH_URL:-http://localhost:8000}"
}

# ── the single-host path, reached by `task upgrade` when no fleet is named ─────

# upgrade_done FLOW URL — the closing summary.
#
# What is now installed and where to look, after ten numbered steps with an outage in the
# middle. The version is read back from VERSION on disk rather than from the ref that was
# resolved, so it reports what actually landed.
upgrade_done() {
  local flow="$1" url="${2:-}" installed
  installed=$(read_version_file)
  banner_open
  # "now running X" is read from the LOCAL VERSION file. For docker that is the same box, so
  # it is a measurement. For multiserver it is not: the fleet is a set of other machines this
  # never asked, and with ARCHIVE= the local tree is not even staged, so the number can be the
  # release you upgraded FROM. Say where the number came from rather than overstating it.
  #
  # "this machine's VERSION", not "this checkout": run from the control plane there is no
  # checkout — the toolkit that installed it is meant to be deleted, and often has been.
  if [ "$flow" = "multiserver" ]; then
    kv "upgrade complete (fleet)" "staged ${installed:-(unknown: VERSION unreadable)}"
    printf '    (this machine'"'"'s VERSION; confirm the fleet with ./logstotal deploy:status)\n'
  elif [ "$flow" = "rollback" ]; then
    kv "upgrade:rollback complete" "now running ${installed:-(unknown: VERSION unreadable)}"
    printf '    The database was NOT touched. If the release you left behind applied migrations\n'
    printf '    you need undone, restore the pre-upgrade backup: docs/runbooks/upgrading.md#rollback\n'
  else
    kv "upgrade complete (this host)" "now running ${installed:-(unknown: VERSION unreadable)}"
  fi
  [ -n "$url" ] && kv "Reachable at" "$url"
  printf '\n'
  printf '  Check it:\n'
  case "$flow" in
    docker) printf '    ./logstotal doctor:docker            # in-container preflight\n' ;;
    multiserver) printf '    ./logstotal deploy:status            # compose ps + /health on every host\n' ;;
  esac
  printf '    ./logstotal version                  # version, commit and migration head\n'
  # No column comment on this one: the URL is variable-length, so an aligned trailer only
  # lines up for whatever host it was written against.
  [ -n "$url" ] && printf '    %s/admin\n' "$url"
  printf '\n'
  printf '  If something is wrong: docs/runbooks/upgrading.md names the rollback for this path.\n'
  banner_close
}

# _adopt_staged_task_bin — after staging, run later tasks with the go-task the NEW release
# pins.
#
# Staging replaces the tree this upgrade is running in, Taskfile included, but every nested
# `lt_task` still names the go-task the upgrade started with. A release that moves its pin
# ahead of a Taskfile feature would then fail its own env:diff / health / doctor steps, after
# the migration. Its own ./logstotal answers which binary to use, from the tarball its archive
# carries, so this works offline. A tree staged from before the wrapper keeps the old one.
_adopt_staged_task_bin() {
  [ -x ./logstotal ] || return 0
  local bin
  if bin=$(./logstotal --task-path) && [ -n "$bin" ]; then
    export LOGSTOTAL_TASK_BIN="$bin"
  else
    warn "the staged release could not resolve its go-task; continuing with ${LOGSTOTAL_TASK_BIN:-task}."
  fi
}

do_docker() {
  HEALTH_URL="${HEALTH_URL:-http://localhost:8000}"
  SKIP_BACKUP="${SKIP_BACKUP:-false}"
  _resolve_once

  if [ -n "$ARCHIVE" ]; then
    header "upgrade: this host ($(_source_kind)) → ${ARCHIVE}"
  else
    header "upgrade: this host ($(_source_kind)) → ${REF}"
  fi
  _announce_source
  _report_installed_version
  mkdir -p backups
  STAMP=$(date +%Y%m%d-%H%M%S)
  lt_task version > "backups/pre-upgrade-version-${STAMP}.txt" 2>&1 || true
  info "pre-upgrade version recorded: $(value "backups/pre-upgrade-version-${STAMP}.txt")"

  # 1. Backup
  if [ "$SKIP_BACKUP" = "true" ]; then
    warn "SKIP_BACKUP=true — proceeding without a backup."
  else
    info "./logstotal backup (verified — dump + integrity check + receipt)"
    lt_task backup
  fi

  # 2. Snapshot the installed tree. After the backup, so a failure here costs nothing that
  # was not already secured; before staging, because staging is what destroys it.
  if truthy "${SKIP_SNAPSHOT:-}"; then
    warn "SKIP_SNAPSHOT=true — this upgrade will have no local rollback point."
  else
    _snapshot_code
  fi

  # 3. Stage code (git checkout REF or archive overlay). export REF ARCHIVE (done
  # above) bridges them through the upgrade:stage-code dispatcher's env-wins read.
  if [ "$SOURCE" = bundle ]; then
    BUNDLE='' SOURCE=archive ARCHIVE="$_UPGRADE_BUNDLE_ARCHIVE" bash "$SCRIPT_DIR/upgrade.sh" stage-code
  else
    lt_task upgrade:stage-code
  fi
  _adopt_staged_task_bin

  # 4. env:diff (informational)
  echo ""
  info "New config keys since your .env:"
  lt_task env:diff

  # 5. Use the exact images supplied by an offline bundle.
  if [ "$SOURCE" = bundle ]; then
    for image in .bundle/images/*.tar; do docker load -i "$image"; done
    export LOGSTOTAL_IMAGE_TAG="${REF#v}" LOGSTOTAL_NO_BUILD=true LOGSTOTAL_BUNDLED_IMAGES=true
    mkdir -p data
    printf 'tag=%s\n' "$LOGSTOTAL_IMAGE_TAG" > data/.bundle-images
    tmp_env=$(mktemp)
    awk '!/^LOGSTOTAL_(BUNDLED_IMAGES|IMAGE_TAG)=/' .env > "$tmp_env"
    printf 'LOGSTOTAL_BUNDLED_IMAGES=true\nLOGSTOTAL_IMAGE_TAG=%s\n' "$LOGSTOTAL_IMAGE_TAG" >> "$tmp_env"
    mv "$tmp_env" .env
  else
    if [ -f data/.bundle-images ]; then
      rm -f data/.bundle-images
      tmp_env=$(mktemp)
      awk '!/^LOGSTOTAL_(BUNDLED_IMAGES|IMAGE_TAG)=/' .env > "$tmp_env"
      mv "$tmp_env" .env
      unset LOGSTOTAL_IMAGE_TAG LOGSTOTAL_NO_BUILD LOGSTOTAL_BUNDLED_IMAGES
    fi
    info "docker compose build"
    docker compose build
  fi

  # 6. Stop the app before touching the schema. On the default SQLite backend an
  # Alembic batch migration rebuilds a table copy→drop→rename, and a worker
  # committing Finding rows through that window either loses them or dies on
  # "database is locked" (app/database.py::SQLITE_BUSY_TIMEOUT_MS, 15s). Redis/Postgres
  # stay up so the `compose run` below still resolves its dependencies.
  info "docker compose stop web worker (schema changes must not race a live worker)"
  docker compose stop web worker

  # 7. Apply migrations (also adopts legacy pre-Alembic databases safely)
  info "docker compose run --rm web python3 -m app.migrations"
  docker compose run --rm --no-deps --pull never web python3 -m app.migrations

  # 8. Restart with the new image.
  info "docker compose up -d"
  if [ "$SOURCE" = bundle ]; then
    docker compose up -d --no-build --pull never
  else
    docker compose up -d
  fi
  info "waiting 10s for services to settle"
  sleep 10

  # 9. Post-upgrade health probe
  HEALTH_URL="$HEALTH_URL" lt_task health:remote

  # 10. In-container preflight (FAILS the upgrade on doctor FAIL)
  info "doctor:docker (post-upgrade preflight)"
  lt_task doctor:docker

  # 11. Done
  upgrade_done docker "${HEALTH_URL:-http://localhost:8000}"
}

# _survey_fleet — ask every host in scope what it is running, record it, and honour
# SKIP_IF_CURRENT.
#
# SKIP_IF_CURRENT, the downgrade warning and backups/pre-upgrade-version-*.txt, for a fleet.
# `_report_installed_version` cannot serve here: it reads the LOCAL VERSION, which for a
# fleet describes the workstation and not the deployment.
#
# One remote command per host, over the ControlMaster connection the rest of the run reuses.
_survey_fleet() {
  local target hosts_csv scope host ver run line current=1 measured=0
  target="${REF#v}"

  # DEPLOY_ONLY narrows the deploy, so it narrows the question.
  hosts_csv="${DEPLOY_ONLY:-$DEPLOY_HOSTS}"
  scope=$(printf '%s' "$hosts_csv" | tr ',' ' ')

  if truthy "${DEPLOY_DRY_RUN:-}"; then
    info "fleet survey skipped (DEPLOY_DRY_RUN)"
    return 0
  fi

  mkdir -p backups
  local stamp record
  stamp=$(date +%Y%m%d-%H%M%S)
  record="backups/pre-upgrade-version-${stamp}.txt"
  {
    printf 'upgraded_at: %s\n' "$stamp"
    printf 'target: %s\n' "${REF:-${ARCHIVE:-unknown}}"
    printf 'source: %s\n' "$(_source_kind)"
    printf 'release_server: %s\n' "$(release_repo_url)"
    printf 'scope: %s\n' "$hosts_csv"
  } > "$record"

  info "fleet before this upgrade:"
  for host in $scope; do
    line=$(host_installed_release "$host" "$REMOTE_DIR")
    ver="${line%%|*}"
    run="${line##*|}"
    if [ -z "$ver" ]; then
      # Never report OK for something that could not be measured — deploy-preflight.sh's
      # rule, where an unreadable value prints `?` and counts as a failure.
      printf '    %-28s %s\n' "$host" "? (no VERSION readable)"
      printf 'host %s: version=? running=?\n' "$host" >> "$record"
      current=0
      continue
    fi
    measured=1
    printf '    %-28s %s (%s container(s) up)\n' "$host" "$ver" "${run:-0}"
    printf 'host %s: version=%s running=%s\n' "$host" "$ver" "${run:-0}" >> "$record"
    [ "$ver" = "$target" ] || current=0
    [ "${run:-0}" -gt 0 ] 2>/dev/null || current=0
  done
  echo "  recorded: ${record}"

  is_release_tag "${REF:-}" || return 0

  if [ "$measured" = "1" ] && [ "$current" = "1" ]; then
    info "  every host in scope is already running ${target} with containers up."
    if truthy "${SKIP_IF_CURRENT:-}"; then
      info "SKIP_IF_CURRENT=true — nothing to do."
      exit 0
    fi
    # The same gate the docker flow uses, for the same reason and with the same wording.
    # `current` is already "version matches AND containers are up" for every host, so a
    # scope with a stopped host never reaches here — that is the REPAIR flow and it
    # redeploys with no question asked.
    _gate_already_current "every host in scope is already running ${target}." \
      "every host in scope, one after another"
  fi
}

# ── the fleet path, reached by `task upgrade` when one IS ─────────────────────

do_multiserver() {
  local rc
  ARCHIVE="${ARCHIVE:-}"
  SKIP_BACKUP="${SKIP_BACKUP:-false}"

  # deploy.env provides defaults for values not already set — same precedence as
  # deploy-preflight.sh / deploy-smoke.sh / deploy-multiserver.sh (caller env wins).
  DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"

  # Hosts as POSITIONALS, never a go-task `env:` bridge — the same rule, and the same
  # reason, as scripts/deploy-fleet.sh. The bridge exports the key even when the template
  # resolves empty, and deploy_env_load skips a key that is merely SET, so it would kill the
  # deploy.env workflow for everyone who does not pass hosts.
  #
  # A CLI variable is worse than useless: go-task never exports one to the shell, so
  # `task upgrade DEPLOY_HOSTS="cp,w1"` would fall through to deploy.env and UPGRADE THE
  # FLEET NAMED THERE. Not an abort: a different fleet.
  local from_args
  from_args=$(hosts_from_args "$@")
  [ -n "$from_args" ] && DEPLOY_HOSTS="$from_args"
  DEPLOY_HOSTS="${DEPLOY_HOSTS:-$(deploy_env_default DEPLOY_HOSTS)}"
  # LAST: the control plane's own record of its fleet.
  #
  # This is what makes `task upgrade` work when run ON the control plane with
  # no deploy.env — which is the normal case, because deploy.env is written by whoever ran
  # the deploy and package.sh deliberately keeps it out of the archive. Explicit
  # configuration still wins: positionals, then the environment, then deploy.env, then
  # this. A record is what answers when there is nothing else, never what overrides.
  if [ -z "${DEPLOY_HOSTS:-}" ]; then
    DEPLOY_HOSTS=$(fleet_hosts "${DEPLOY_REMOTE_DIR:-$(deploy_env_default DEPLOY_REMOTE_DIR)}")
    [ -n "${DEPLOY_HOSTS:-}" ] && echo "→ fleet: ${DEPLOY_HOSTS} (from this host's fleet record)"
  fi
  SSH_IDENTITY="${SSH_IDENTITY:-$(deploy_env_default SSH_IDENTITY)}"
  DEPLOY_REMOTE_DIR="${DEPLOY_REMOTE_DIR:-$(deploy_env_default DEPLOY_REMOTE_DIR)}"
  # DEPLOY_ONLY narrows every phase of the deploy to a subset, so the currency check has to
  # see it too — otherwise it measures hosts this run never touches and reports the fleet
  # current because the ones being left alone are.
  DEPLOY_ONLY="${DEPLOY_ONLY:-$(deploy_env_default DEPLOY_ONLY)}"
  export DEPLOY_ENV_FILE DEPLOY_HOSTS DEPLOY_REMOTE_DIR
  [ -n "${DEPLOY_ONLY:-}" ] && export DEPLOY_ONLY
  [ -n "${SSH_IDENTITY:-}" ] && export SSH_IDENTITY

  if [ -z "${DEPLOY_HOSTS:-}" ]; then
    die "DEPLOY_HOSTS is required. Name the hosts:
         ./logstotal upgrade -- cp.example.com w1.example.com
       or put DEPLOY_HOSTS in ${DEPLOY_ENV_FILE}.
       On a control plane this is normally answered by its own fleet record;
       there is none at $(fleet_manifest_path "${DEPLOY_REMOTE_DIR:-/opt/logstotal}")."
  fi
  # Resolution comes AFTER the DEPLOY_HOSTS check above, deliberately: a missing host list
  # is a configuration error the operator can fix instantly, and it must not be reported
  # behind a network lookup that may itself fail.
  _resolve_once

  # Derived here rather than beside CP below, because the refusal that follows needs it and
  # must fire before anything runs — not after the control-plane backup.
  REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/logstotal}"

  # Running this ON the control plane, over the install it is running from, is the NORMAL
  # case. Extracting over DEPLOY_REMOTE_DIR in place would rewrite these scripts under the
  # descriptor bash is reading them from, so phase 3 stages beside the install and rsyncs
  # across; rsync renames rather than truncates, so the running script finishes on the bytes
  # it started with. See lib/install.sh.
  #
  # What the rename does NOT protect is a sibling script this one dispatches to AFTER the
  # overlay has replaced it — and that is exactly what happens below, where the smoke step
  # runs `bash "$SCRIPT_DIR/deploy-smoke.sh"` at the end of a flow whose middle replaced
  # that file. Pin them to a copy taken now.
  if hosts_have_local "$DEPLOY_HOSTS"; then
    pin_run_dir
  fi

  # Package mode: hand the fleet the PUBLISHED package. No checkout, no `task package`, and
  # no Tailwind/7z build toolchain on the workstation — and it ships the CI-built artifact
  # rather than a local rebuild of it, which is a stronger identity than any sha we could
  # stamp. It is the default even on a checkout, which can ask for git staging with
  # SOURCE=git.
  if [ "$SOURCE" = "package" ]; then
    is_release_tag "${REF:-}" || die "REF=${REF:-} is not a published release, so there is no
       package to hand the fleet. Pin one with VERSION=X.Y.Z, or use SOURCE=git."
    # `|| rc=$?`, never a bare call: under `set -e` a function returning non-zero aborts
    # the script BEFORE `case $?` can read it, leaving every arm below dead and an
    # unreachable release server exiting silently.
    rc=0
    release_artifact_exists "$REF" || rc=$?
    case $rc in
      1) die "no package published for ${REF} at $(release_repo_url)
       The tag exists but its release asset does not. Pick another release with VERSION=X.Y.Z,
       or build one locally with SOURCE=git." ;;
      2) warn "could not reach $(release_repo_url) to check the package for ${REF} — trying anyway." ;;
    esac
    ARCHIVE=$(release_package_url "$REF")
    info "using the published package for ${REF}"
  fi

  if [ -n "$ARCHIVE" ]; then
    header "upgrade: fleet ($(_source_kind)) → ${ARCHIVE}"
  else
    header "upgrade: fleet ($(_source_kind)) → ${REF}"
  fi
  _announce_source

  # Control-plane / SSH derivation — shared by the survey, backup, migration and doctor
  # steps. Hoisted above preflight
  # because the survey below has to run BEFORE the control-plane backup, and SKIP_IF_CURRENT
  # has to be able to exit before either.
  CP=$(first_host)
  build_ssh_opts

  # cp_exec CMD — run CMD on the control plane, honouring the `local` sentinel.
  # Through host_exec, the wrapper deploy-multiserver.sh uses, rather than ssh directly —
  # or a control plane named `local` would have backup, migrate and doctor connect to a
  # host called "local" while every other step runs here.
  cp_exec() { host_exec "$CP" "$1"; }

  # 1. What the fleet is running now.
  #
  # For a fleet "installed version" is not this workstation's VERSION — under the package
  # default the local tree is never staged at all, so it is often the release you are
  # upgrading FROM, or nothing. It is each host's ${REMOTE_DIR}/VERSION, which
  # deploy-preflight.sh already reads; the survey shares that read so SKIP_IF_CURRENT can
  # answer before the control-plane backup rather than after it.
  _survey_fleet

  # 2. deploy:preflight
  lt_task deploy:preflight

  # 2. Verified backup on the control plane (unless skipped)
  if [ "$SKIP_BACKUP" = "true" ]; then
    warn "SKIP_BACKUP=true — proceeding without a control-plane backup."
  else
    info "verified backup on ${CP} (./logstotal backup)"
    # ./logstotal where the control plane has it; a control plane installed before the
    # wrapper existed still has the go-task it was bootstrapped with.
    cp_exec "cd ${REMOTE_DIR} && if [ -x ./logstotal ]; then ./logstotal backup; else task backup; fi"
  fi

  # 3. Stage code (git) OR reuse ARCHIVE=.7z. export REF ARCHIVE (above) bridges
  # them through the upgrade:stage-code dispatcher's env-wins read.
  if [ -n "$ARCHIVE" ]; then
    # The remote hosts extract with `7z x`, so this one really must be a .7z — unlike
    # the single-host path, which rsyncs a tree over the install dir and accepts
    # any supported archive. Say so rather than failing on every host in phase 3.
    case "$ARCHIVE" in
      *.7z) ;;
      *) die "a fleet upgrade needs a .7z package — each host extracts it with 7z.
       Got: $(basename "$ARCHIVE"). Use the release asset: logstotal-<version>.7z" ;;
    esac
    if echo "$ARCHIVE" | grep -qE '^https?://'; then
      # Script-scope, not a local: the single EXIT trap (_lt_cleanup) fires after this
      # function returns, so a `local` would already be out of scope when it reads this.
      PKG_DIR=$(mktemp -d)
      PKG="${PKG_DIR}/$(basename "${ARCHIVE%%\?*}")"
      info "curl -fL ${ARCHIVE}"
      curl -fL "${CURL_DOWNLOAD_OPTS[@]}" "$ARCHIVE" -o "$PKG"
      verify_downloaded_artifact "$PKG" "$ARCHIVE"
      ARCHIVE="$PKG"
    elif [ ! -f "$ARCHIVE" ]; then
      die "ARCHIVE not found: $ARCHIVE"
    fi
    info "using package: $ARCHIVE (skipping checkout + ./logstotal package)"
    export DEPLOY_PACKAGE="$ARCHIVE"
  elif [ "$SOURCE" != bundle ]; then
    lt_task upgrade:stage-code
    _adopt_staged_task_bin
  fi

  # 4. env:diff (informational, local — the CP's real .env lives remotely)
  # `--optional`: this host is a workstation and need not have a `.env` at all. Without it
  # the step would exit 1 on a perfectly normal fleet, and `set -e` above would turn an
  # informational print into a failed upgrade — after the backup and the checkout.
  echo ""
  info "New config keys — review these against each host's env file (the control plane's real .env lives remotely):"
  lt_task env:diff -- --optional

  # 5. Package (git mode only) OR reuse the passed-through ARCHIVE
  if [ -z "$ARCHIVE" ] && [ "$SOURCE" != bundle ]; then
    info "./logstotal package"
    lt_task package
  else
    info "skipping ./logstotal package (ARCHIVE=${ARCHIVE})"
  fi

  # 6. Phased deploy across all hosts
  if [ -n "$ARCHIVE" ]; then
    export DEPLOY_PACKAGE="$ARCHIVE"
  elif [ -z "${DEPLOY_PACKAGE:-}" ]; then
    # task package just ran — pass the newest archive explicitly so the deploy
    # doesn't stop to ask about re-building it.
    # shellcheck disable=SC2012  # newest-by-mtime
    NEWEST=$(ls -t logstotal-*.7z 2>/dev/null | head -1 || true)
    if [ -n "$NEWEST" ]; then export DEPLOY_PACKAGE="$NEWEST"; fi
  fi
  # Safe upgrade defaults: a normal upgrade stops the stacks (workers first),
  # keeps each host's .env, and restarts behind the control-plane health
  # gate — no undocumented flags required. Set any of these explicitly to override.
  export DEPLOY_STOP="${DEPLOY_STOP:-true}"
  export DEPLOY_KEEPENV="${DEPLOY_KEEPENV:-true}"
  export DEPLOY_START="${DEPLOY_START:-true}"
  info "fleet deploy (DEPLOY_STOP=${DEPLOY_STOP} DEPLOY_KEEPENV=${DEPLOY_KEEPENV} DEPLOY_START=${DEPLOY_START})"
  # The two scripts directly, never through go-task. An upgrade has, by this point,
  # replaced the tree it is running in — so re-entering go-task would read the NEW
  # Taskfile, and an upgrader that depends on the task names of the version it is
  # installing is an upgrader a rename can break. $SCRIPT_DIR is pinned for the same reason.
  # A bundle goes to the gate whole: it is the one source the gate itself unpacks, because
  # the archive and the images inside travel to the hosts by different routes.
  if [ "${SOURCE:-}" = "bundle" ]; then
    export BUNDLE
    info "source: bundle — $(basename "$BUNDLE")"
  fi

  # VERSION and ARCHIVE are answered by NOW — either DEPLOY_PACKAGE points at the release
  # this flow downloaded, or `task package` has just built one from the staged tree. Left
  # set, the gate would read them as "which release should I deploy" and resolve the whole
  # question a second time, against a release server it may not be able to reach.
  #
  # They mean the same thing in both places, which is the point; they are just answered
  # once, here, rather than twice.
  [ "${SOURCE:-}" = "bundle" ] || unset VERSION ARCHIVE
  bash "$SCRIPT_DIR/deploy-package-gate.sh"
  DEPLOY_ACTION=deploy bash "$SCRIPT_DIR/deploy-multiserver.sh"

  # 7. Migrations on the control plane only (workers skip)
  info "migrations on ${CP} (CP only — workers skip)"
  # Through the entrypoint in env-only mode, or the command would not see the DATABASE_URL
  # the web container derived at boot and would migrate an empty SQLite file instead.
  cp_exec "cd ${REMOTE_DIR} && docker compose exec -T -e LOGSTOTAL_ENTRYPOINT_ENV_ONLY=1 web /docker-entrypoint.sh python3 -m app.migrations"

  # 8. In-container preflight on the control plane (FAILS the upgrade on doctor FAIL)
  info "doctor:docker on ${CP} (post-migration preflight)"
  cp_exec "cd ${REMOTE_DIR} && docker compose exec -T -e LOGSTOTAL_ENTRYPOINT_ENV_ONLY=1 web /docker-entrypoint.sh python3 scripts/doctor.py --in-container"

  # 9. Smoke test (/health)
  #
  # Run directly, not through `task deploy:smoke`: go-task collapses every non-zero exit to
  # 201, and the whole point here is telling 1 (something was measured and it failed) from 2
  # (nothing could be measured). deploy-fleet.sh calls it the same way for the same reason.
  #
  # Credentials are bridged the way deploy-fleet.sh bridges them. deploy.env keeps the
  # basic-auth username and never the plaintext, so this only helps when the operator passed
  # DEPLOY_BASIC_AUTH_PASSWORD on this invocation — which is exactly why exit 2 exists.
  info "deploy-smoke.sh"
  # DEPLOY_SMOKE_STRICT here, and nowhere an operator types. Run by hand the smoke test
  # exits 0 when checks were skipped rather than failed — "Failed to run task deploy:smoke"
  # for checks nobody attempted reads as a broken deployment. A CALLER still needs to know,
  # so it asks for the distinguishable exit and decides for itself: this one warns.
  # The fleet deploy above gated on the control plane's own /health, probed from the host
  # itself. So an endpoint unreachable from HERE is a fact about the route from this
  # machine, not an outage — see the note at deploy-smoke.sh's /health probe.
  export DEPLOY_HEALTH_CONFIRMED=true
  smoke_rc=0
  if [ -n "${DEPLOY_BASIC_AUTH_USER:-}" ] && [ -n "${DEPLOY_BASIC_AUTH_PASSWORD:-}" ]; then
    DEPLOY_SMOKE_STRICT=true BASIC_AUTH_USER="$DEPLOY_BASIC_AUTH_USER" BASIC_AUTH_PASS="$DEPLOY_BASIC_AUTH_PASSWORD" \
      bash "$SCRIPT_DIR/deploy-smoke.sh" || smoke_rc=$?
  else
    DEPLOY_SMOKE_STRICT=true bash "$SCRIPT_DIR/deploy-smoke.sh" || smoke_rc=$?
  fi

  # 2 means the smoke test could not reach anything to measure — the deployment answered and
  # asked for credentials nobody supplied. That is a statement about the check, not about the
  # upgrade: migrations ran, the control plane passed an in-container doctor run at step 8,
  # and failing here would report a successful upgrade as broken.
  if [ "$smoke_rc" -eq 2 ]; then
    warn "the upgrade completed; its final verification could not run (see above)."
    echo "       Verify it yourself with:"
    echo "         DEPLOY_BASIC_AUTH_PASSWORD='...' ./logstotal deploy:smoke"
  elif [ "$smoke_rc" -ne 0 ]; then
    exit "$smoke_rc"
  fi

  # Record what this workstation last pushed to a fleet.
  #
  # In package mode nothing local is staged, so the checkout's VERSION still names the
  # release you upgraded FROM. A later bare `task deploy` from the same tree then
  # builds a package from it and pushes that — a silent DOWNGRADE of production, reported as
  # a normal deploy. deploy-package-gate.sh reads this file and refuses.
  if is_release_tag "${REF:-}"; then
    mkdir -p backups
    printf '%s\n' "${REF#v}" > backups/.last-deployed-release
  fi

  upgrade_done multiserver ""
}

# ── plan (task upgrade:plan) ──────────────────────────────────────────────────
#
# Read-only. ALWAYS exits 0, and every failure becomes a printed verdict rather than a
# non-zero status — `task deploy:plan`'s contract, for the same reason: a command whose job
# is to tell you what would happen is useless if the answer can be "it crashed". It carries
# no `preconditions:` in the Taskfile either, since a failed precondition exits 201.
#
# It answers the three questions every upgrade answers — which release, where the code comes
# from, what gets restarted — and it reuses _source_kind and release_repo_url_source rather
# than forming a second opinion, so the plan and the run cannot disagree.
do_plan() {
  set +e

  local rc installed target source_kind repo repo_arm artifact topology cmd hosts
  installed=$(read_version_file)
  installed="${installed:-?}"

  repo=$(release_repo_url 2>/dev/null)
  repo_arm=$(release_repo_url_source 2>/dev/null)

  # Resolution can legitimately fail — offline, nothing published, a bad pin. Say so and
  # keep going; every later line degrades to "?" rather than taking the whole command down.
  #
  # ONE resolution, not two: each release_resolve_ref call is a `git ls-remote` or a paged
  # releases API walk — on a slow link, the whole runtime of `upgrade:plan`. A temp file is
  # what lets one invocation yield both stderr and stdout separately.
  local resolve_err resolve_err_file
  resolve_err_file=$(mktemp)
  target=$(release_resolve_ref 2>"$resolve_err_file")
  resolve_err=$(cat "$resolve_err_file")
  rm -f "$resolve_err_file"
  REF="$target"

  _resolve_source 2>/dev/null
  source_kind=$(_source_kind)

  # The same shape deploy:plan's settings block uses: the value emphasised, its
  # provenance dimmed beside it. Every one of these is a question an operator came here to
  # answer, so none of them may read in the same grey as the prose under them.
  printf '\n'
  printf '  installed  %s\n' "$(value "$installed")"
  if [ -n "${ARCHIVE:-}" ]; then
    printf '  target     %s\n' "$(value "$ARCHIVE")"
  elif [ -n "$target" ]; then
    printf '  target     %s\n' "$(value "$target")"
  else
    printf '  target     %s  (could not resolve)\n' "$(value '?')"
    [ -n "$resolve_err" ] && printf '%s\n' "$resolve_err" | sed 's/^/             /'
  fi
  printf '  server     %s   %s\n' "$(value "${repo:-?}")" "${C_CYAN}(from ${repo_arm:-?})${C_OFF}"
  printf '  source     %s\n' "$(value "${source_kind:-?}")"

  # Reachability, which is the question behind most upgrade failures — answered here
  # without starting an upgrade and taking a backup first.
  if [ -n "${ARCHIVE:-}" ] && [ -z "${target:-}" ]; then
    artifact="(an explicit archive; not checked)"
  elif [ "${SOURCE:-}" = "git" ]; then
    artifact="(git checkout of ${target:-?}; no download)"
  elif [ -n "$target" ]; then
    # Guarded like the other two, even though `set +e` at the top of do_plan already makes
    # a bare call survive here. Safety that depends on a line 70 above it is not safety —
    # it is the same bug waiting for someone to scope that `set +e` more tightly.
    rc=0
    release_artifact_exists "$target" || rc=$?
    # The verdict is tinted, not the filename: "NOT PUBLISHED" is the line that decides
    # whether `task upgrade` can work at all.
    case $rc in
      0) artifact="$(value "$(package_basename "$target")") — ${C_GREEN}reachable${C_OFF}" ;;
      1) artifact="$(value "$(package_basename "$target")") — ${C_RED}NOT PUBLISHED at that server${C_OFF}" ;;
      *) artifact="$(value "$(package_basename "$target")") — ${C_YELLOW}could not reach the server${C_OFF}" ;;
    esac
  else
    artifact="?"
  fi
  printf '  artifact   %s\n' "$artifact"

  # What would be restarted — answered by asking the SAME function `task upgrade` asks, so
  # the plan cannot describe something other than what the upgrade would do.
  #
  # deploy.env alone is not enough: on a control plane there is none — it belongs to whoever
  # ran the deploy, and package.sh keeps it out of the archive — so a plan reading only it
  # would say "single host" about a machine where `task upgrade` upgrades three.
  hosts=$(_fleet_scope)
  if [ -n "$hosts" ] && [ "$hosts" != "${hosts%%,*}" ]; then
    topology="fleet — $(printf '%s' "$hosts" | tr ',' ' ' | wc -w | tr -d ' ') hosts"
    if [ "${FLEET_ADOPTED:-}" = "yes" ]; then
      topology="${topology}, from the fleet record on ${FLEET_FROM}"
    elif [ -z "$(deploy_env_default DEPLOY_HOSTS 2>/dev/null)" ]; then
      topology="${topology}, from this host's own fleet record"
    fi
    cmd="./logstotal upgrade   # this fleet"
  elif [ -f docker-compose.yml ]; then
    topology="single host (docker-compose.yml)"
    cmd="./logstotal upgrade"
  else
    topology="? (no docker-compose.yml here)"
    cmd="./logstotal upgrade   # from the install directory"
  fi
  printf '  restarts   %s\n' "$(value "$topology")"

  # The single most useful thing a plan can say, and the one thing the run will refuse on.
  # Hedged deliberately: `installed` is THIS machine's VERSION, which on a workstation
  # driving a fleet is not the fleet's — the same caveat the line above it already carries,
  # and why this says "would refuse if" rather than "will refuse".
  if [ -n "$target" ] && [ "$installed" = "${target#v}" ]; then
    printf '  note       this is the release already installed. If it is also RUNNING the\n'
    printf '             upgrade refuses, because re-running rebuilds and restarts for no\n'
    printf '             change. RESTAGE_IF_CURRENT=true restages it, SKIP_IF_CURRENT=true\n'
    printf '             makes it a no-op. Current with nothing running is the repair flow\n'
    printf '             and is never refused.\n'
  fi
  printf '  would run  %s\n' "$(value "$cmd")"
  printf '\n'

  if [ -d "$SNAPSHOT_ROOT" ]; then
    local snap
    snap=$(_newest_snapshot)
    [ -n "$snap" ] && printf '  rollback   %s (./logstotal upgrade:rollback)\n\n' "$(value "$(read_version_file "$snap")")"
  fi

  printf '  Nothing was changed. Pin a release with VERSION=X.Y.Z, or choose a source with\n'
  printf '  SOURCE=package (default) or SOURCE=git.\n\n'
  exit 0
}

# ── Main ──────────────────────────────────────────────────────────────────────

# ONE EXIT trap, because bash keeps only the last one registered and a second silently
# cancels the first. Everything
# that needs removing on the way out is named here, and each producer sets its variable
# at SCRIPT scope so the trap can still read it after the function returns.
_lt_cleanup() {
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
  [ -n "${PKG_DIR:-}" ] && rm -rf "$PKG_DIR"
  unpin_run_dir
  return 0
}
trap _lt_cleanup EXIT

# _fleet_scope [HOST...] — the host list an `upgrade` should act on, or "".
#
# Empty means "this machine alone", which is the single-host Docker upgrade. Anything else
# is a fleet. The chain is the one every deploy action uses — positionals, then the
# environment, then deploy.env, then this host's own fleet record — so `task upgrade` on a
# control plane finds its fleet, and on a laptop with a one-box install finds nothing and
# upgrades that box.
#
# A one-entry fleet naming only this machine is NOT a fleet: `local` alone, or a single
# host that is the control plane, still goes through the fleet path deliberately, because
# that path is what writes the fleet record and runs the preflight. The distinction that
# matters is "is there a host list at all", not how long it is.
_fleet_scope() {
  local from_args
  from_args=$(hosts_from_args "$@")
  [ -n "$from_args" ] && { printf '%s' "$from_args"; return 0; }
  [ -n "${DEPLOY_HOSTS:-}" ] && { printf '%s' "$DEPLOY_HOSTS"; return 0; }
  local from_file
  from_file=$(deploy_env_default DEPLOY_HOSTS)
  [ -n "$from_file" ] && { printf '%s' "$from_file"; return 0; }
  fleet_hosts "${DEPLOY_REMOTE_DIR:-$(deploy_env_default DEPLOY_REMOTE_DIR)}"
}

main() {
  # Above everything, so FLEET_FROM reaches _fleet_scope, do_plan and do_multiserver alike.
  # _fleet_options memoises the record's options on first read, so adopting later would give
  # hosts from the remote record and settings from this machine.
  fleet_adopt

  local action="${1:-}"
  [ "$#" -gt 0 ] && shift

  # `upgrade` and `multiserver` take positionals (hosts). Anything else reaching another
  # action is a typo that would otherwise be swallowed in silence.
  case "$action" in
    upgrade | multiserver | rollback) ;;
    *) [ "$#" -eq 0 ] || die "bash scripts/upgrade.sh ${action} takes no arguments (got: $*).
       Host lists belong to the upgrade itself: ./logstotal upgrade -- cp w1 w2" ;;
  esac

  case "$action" in
    stage-code)  do_stage_code ;;
    docker)      do_docker ;;
    multiserver) do_multiserver "$@" ;;
    rollback)
      # ONE rollback verb, for the same reason there is one upgrade verb: whether a
      # rollback touches this host or a fleet is a fact about the machine, not a choice, and
      # a wrong pick between two verbs would be silent both ways.
      DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"
      _rb_scope=$(_fleet_scope "$@")
      if [ -n "$_rb_scope" ]; then
        info "scope: the fleet (${_rb_scope})"
        DEPLOY_HOSTS="$_rb_scope" DEPLOY_ACTION=rollback \
          bash "$SCRIPT_DIR/deploy-multiserver.sh"
      else
        info "scope: this host alone (no fleet named, and no fleet record here)"
        do_rollback
      fi
      ;;
    plan)        do_plan ;;
    upgrade)
      # ONE verb, because the choice is a fact about the machine: does it have a fleet to
      # upgrade? The single-host flow on a control plane would upgrade the control plane and
      # leave every worker on the old release, running against a migrated database.
      DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"
      local scope
      scope=$(_fleet_scope "$@")
      if [ -n "$scope" ]; then
        do_multiserver "$@"
      else
        info "scope: this host alone (no fleet named, and no fleet record here)"
        do_docker
      fi
      ;;
    *)
      echo "Usage: bash scripts/upgrade.sh {upgrade|plan|rollback|stage-code} [host...]" >&2
      exit 1
      ;;
  esac
}

main "$@"
