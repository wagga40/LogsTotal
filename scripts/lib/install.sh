#!/usr/bin/env bash
# shellcheck shell=bash
#
# How a release lands on a host (developer / ops).
#
# The rule this file exists to enforce: NEVER write a release directly over a tree that
# something is currently reading. Extract beside it, then rsync across.
#
# ── Why rsync and not 7z ─────────────────────────────────────────────────────
#
# `7z x -aoa` opens each target with O_TRUNC and rewrites it IN PLACE — same inode, new
# bytes. bash executes a script through an open file descriptor and seeks within it as it
# goes, so replacing the bytes under that descriptor derails the run somewhere
# unpredictable rather than failing.
#
# rsync, without --inplace, writes `.name.XXXXXX` in the destination directory and
# rename()s it over the target. rename() unlinks the old directory entry but the inode
# survives as long as any process holds it open — so the running script reads the old
# bytes through to the end, and the next process gets the new ones. It is the mechanism
# upgrade.sh relies on to overlay a staged tree over its own $(pwd), exercised against a
# live stack by ci-deploy-smoke.sh.
#
# Three things follow, and all three are load-bearing:
#
#   1. NEVER --inplace, --append or --append-verify. Any of them turns the rename back
#      into a truncating write, silently.
#      tests/test_deploy_install.py greps the whole tree for them.
#   2. The staging directory must sit on the SAME FILESYSTEM as the install, or rename()
#      cannot be atomic. Putting it inside the install directory guarantees that.
#   3. A script must not decide, mid-run, which of its siblings exist — see pin_run_dir.

# stage_dir INSTALL — where an incoming release is unpacked, beside what it will replace.
#
# A dotted name inside the install dir: same filesystem (see 2 above), predictable enough
# to clean up by name after an interrupted run, and excluded from the overlay so that
# `--delete` does not remove the directory it is reading from.
stage_dir() {
  printf '%s/.stage' "${1%/}"
}

# overlay_excludes — everything the release does not own.
#
# The instance's own state, plus the fleet record. Every one of these lives inside the
# install directory and must survive an upgrade that otherwise deletes anything the
# incoming release does not carry.
#
# `docker-compose.override.yml` is the operator's own Compose change (docs/security.md's
# Docker-socket hardening is one); no release ships it, so --delete would drop it silently
# and the next start would undo the hardening.
#
# `.bin` is the go-task ./logstotal extracted — possibly the very binary running this
# upgrade. A release never carries it, so --delete would otherwise remove it mid-run.
#
# `logstotal-*.7z` is here because a control plane upgrading ITSELF downloads the release
# into the install directory — so the overlay would otherwise delete the archive it was
# just extracted from, and a retry would have to fetch it again over a link that may be
# the reason the first attempt failed.
overlay_excludes() {
  printf '%s\n' \
    --exclude=.env --exclude=.env.deploy.sha256 --exclude=data --exclude=uploads --exclude=backups \
    --exclude=.bundle --exclude=certs --exclude=deploy-envs --exclude=deploy.env \
    --exclude=releases --exclude=fleet --exclude=.stage --exclude=.bin \
    --exclude=docker-compose.override.yml \
    --exclude='logstotal-*.7z' \
    --exclude='*.db'
}

# overlay_exclude_args — the same list, shell-quoted per item for a remote command line.
# Quoted individually so `--exclude=*.db` arrives as a pattern rather than being globbed
# by either shell on the way.
overlay_exclude_args() {
  local out="" e
  while IFS= read -r e; do
    out="${out} $(shquote "$e")"
  done <<EOF
$(overlay_excludes)
EOF
  printf '%s' "${out# }"
}

# pin_run_dir — copy this run's scripts aside and point SCRIPT_DIR at the copy.
#
# rsync's rename keeps the *currently executing* script readable, but it does not help a
# script that dispatches to a SIBLING after the overlay has replaced it. upgrade.sh does
# exactly that: it runs `bash "$SCRIPT_DIR/deploy-smoke.sh"` at the end of a flow whose
# middle replaced that file.
#
# One `cp -a` at the top of a run buys complete immunity: every sibling dispatch resolves
# to the code that started, whatever the overlay does underneath. Handing off to the NEW
# code is then a deliberate act with a name, not an accident of timing.
#
# Sets SCRIPT_DIR and _LT_RUN_DIR; registers no trap, because the caller owns EXIT.
pin_run_dir() {
  local src="${1:-$SCRIPT_DIR}"
  _LT_RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/logstotal-run.XXXXXX")
  cp -a "$src/." "$_LT_RUN_DIR/"
  SCRIPT_DIR="$_LT_RUN_DIR"
}

# unpin_run_dir — remove the copy pin_run_dir made, if any.
unpin_run_dir() {
  [ -n "${_LT_RUN_DIR:-}" ] && rm -rf "$_LT_RUN_DIR"
  _LT_RUN_DIR=""
}
