#!/usr/bin/env bash
# The control plane's record of its own fleet — read it, or fetch it (developer / ops).
#
# `show`  prints the record on THIS machine, from ${DEPLOY_REMOTE_DIR}/fleet/manifest.json.
#         On a control plane that is the fleet it belongs to; run from a workstation with
#         no install, it says so rather than pretending.
#
# `pull`  fetches the record from a control plane and writes a local deploy.env from it.
#         This is what makes the record useful from somewhere else: a machine that has
#         never seen this fleet can then drive every deploy task against it. Secrets are
#         NOT fetched — they never leave the machine that generated them — so a pulled
#         configuration can deploy, inspect and remove, but cannot regenerate env files.
#
# Configuration (env vars from the caller always override deploy.env values):
#   DEPLOY_HOSTS       pull: the control plane to fetch from, when no host is given as an
#                      argument. The first entry is used.
#   DEPLOY_REMOTE_DIR  Install dir on the host (default /opt/logstotal).
#   DEPLOY_ENV_FILE    Path to defaults file (default: deploy.env in cwd).
#   DEPLOY_DRY_RUN     truthy: trace instead of connecting.
#   FORCE              pull: `yes` overwrites an existing deploy.env.
#   SSH_IDENTITY       Path to SSH private key (optional).
#
# Usage:
#   bash scripts/fleet.sh show
#   bash scripts/fleet.sh pull [user@host]

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"
# Adopt a remote fleet record when FLEET_FROM names a control plane. ABOVE the first
# deploy.env read, always: _fleet_options memoises the record's options on first read, so a
# later adoption is silently half-applied — hosts from the remote record, settings from this
# machine. See lib/fleet_record.sh::fleet_adopt.
fleet_adopt
deploy_env_load DEPLOY_HOSTS DEPLOY_REMOTE_DIR DEPLOY_DRY_RUN SSH_IDENTITY

DEPLOY_REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/logstotal}"
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-false}"

ACTION="${1:-show}"
shift || true

case "$ACTION" in
  show)
    path=$(fleet_manifest_path "$DEPLOY_REMOTE_DIR")
    if [ ! -f "$path" ]; then
      info "No fleet record at ${path}."
      echo "  A control plane writes one on every deploy. If this machine is not one,"
      echo "  fetch its record instead:   ./logstotal fleet:pull -- <control-plane-host>"
      exit 0
    fi
    run_py "$SCRIPT_DIR/fleet_manifest.py" --file "$path" show
    ;;

  pull)
    build_ssh_opts
    HOST="${1:-}"
    if [ -z "$HOST" ]; then
      HOST=$(first_host 2>/dev/null || true)
      [ -n "$HOST" ] || die "Name the control plane to pull from: ./logstotal fleet:pull -- cp.example.com
       (or set DEPLOY_HOSTS, whose first entry is the control plane)."
    fi

    # Refuse to overwrite: a deploy.env may hold settings this record knows nothing about
    # — the same rule deploy-fleet.sh's init follows, for the same reason.
    if [ -f "$DEPLOY_ENV_FILE" ] && [ "${FORCE:-}" != "yes" ]; then
      die "${DEPLOY_ENV_FILE} already exists. Move it aside, or re-run with FORCE=yes.
       It may hold settings the fleet record does not carry."
    fi

    work=$(mktemp -d "${TMPDIR:-/tmp}/logstotal-fleetpull.XXXXXX")
    trap 'rm -rf "$work"' EXIT

    step "fetching the fleet record from ${HOST}"
    if truthy "$DEPLOY_DRY_RUN"; then
      info "DRY-RUN copy ${HOST}:${DEPLOY_REMOTE_DIR}/fleet/manifest.json → ${DEPLOY_ENV_FILE}"
      exit 0
    fi
    host_copy_from "$HOST" "${DEPLOY_REMOTE_DIR}/fleet/manifest.json" "${work}/manifest.json" \
      || die "no fleet record on ${HOST} at ${DEPLOY_REMOTE_DIR}/fleet/manifest.json.
       A control plane writes one on every deploy — has this fleet been deployed yet?
       Check with: ./logstotal deploy:status"

    run_py "$SCRIPT_DIR/fleet_manifest.py" --file "${work}/manifest.json" deploy-env > "$DEPLOY_ENV_FILE"
    info "Wrote ${DEPLOY_ENV_FILE} from ${HOST}'s fleet record:"
    run_py "$SCRIPT_DIR/fleet_manifest.py" --file "${work}/manifest.json" show | sed 's/^/  /'
    echo ""
    info "Secrets were NOT fetched, and are not in that file — they stay on the machine"
    info "that generated them. This configuration can deploy, inspect and remove; it"
    info "cannot regenerate per-host env files (./logstotal deploy:env)."
    ;;

  *)
    die "Unknown action: ${ACTION} (use: show | pull)"
    ;;
esac
