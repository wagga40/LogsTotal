#!/usr/bin/env bash
# Push each host's generated .env into place (developer / ops).
#
# Reads deploy-envs/<host>.env (written by task deploy:env) and installs it as
# ${DEPLOY_REMOTE_DIR}/.env on the matching host. Skipping it on even one host makes
# preflight WARN and the deploy then fail on `env_file: .env`.
#
# The copy lands in /tmp first and is moved into place with `install -m 600`. A direct
# scp to .env would leave a world-readable file holding SECRET_KEY, the database
# password and the S3 keys for as long as the transfer takes.
#
# It REFUSES to overwrite an .env already on a host unless DEPLOY_ENV_PUSH_FORCE=yes,
# and reports the key NAMES (never values) that exist there but not locally. Pushing
# over a hand-tuned production env file is the most destructive thing this tooling can
# do, and it is silent.
#
# The exception is a file whose content matches its last-pushed fingerprint. Refusing to refresh our own
# output would mean a first run that pushed a bad value and then failed protects that bad
# value on every retry, with the operator seeing the same unrelated error each time.
#
# Usage:
#   bash scripts/deploy-env-push.sh
#
# Configuration (env vars from the caller always override deploy.env values):
#   DEPLOY_HOSTS            Comma-separated host list; `host`, `user@host`, or `local`.
#   DEPLOY_REMOTE_DIR       Install dir on each host (default /opt/logstotal).
#   DEPLOY_ENV_DIR          Where the generated files live (default deploy-envs).
#   DEPLOY_ENV_PUSH_FORCE   `yes`: overwrite an existing remote .env.
#   DEPLOY_ENV_FILE         Path to defaults file (default: deploy.env in cwd).
#   DEPLOY_DRY_RUN          truthy: trace instead of connecting.
#   SSH_IDENTITY            Path to SSH private key (optional).
#
# `set -eu`, no pipefail — the key-diff pipelines below must survive an empty side.

set -eu

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"
deploy_env_load DEPLOY_HOSTS DEPLOY_REMOTE_DIR DEPLOY_ENV_DIR DEPLOY_ENV_PUSH_FORCE DEPLOY_DRY_RUN SSH_IDENTITY

DEPLOY_REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/logstotal}"
DEPLOY_ENV_DIR="${DEPLOY_ENV_DIR:-deploy-envs}"
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-false}"

[ -n "${DEPLOY_HOSTS:-}" ] || die "DEPLOY_HOSTS is required (comma-separated host list; set it or put it in ${DEPLOY_ENV_FILE})"

build_ssh_opts

# slug_for HOST — the filename deploy_fleet_env.py wrote for this host. Kept in step
# with its slugify(); a divergence here silently pushes the wrong host's file.
slug_for() {
  printf '%s' "${1#*@}" | sed 's/[^A-Za-z0-9._-]/_/g'
}

REFUSED=""
PUSHED=0

push_host() {
  local host=$1 idx=$2 role src remote_keys local_keys extra tmp
  role="worker"
  [ "$idx" -eq 0 ] && role="control-plane"
  src="${DEPLOY_ENV_DIR}/$(slug_for "$host").env"
  step "${host} (${role}): push .env"

  if [ ! -f "$src" ]; then
    die "No env file for ${host} at ${src}. Generate one first: ./logstotal deploy:env"
  fi

  # Dry-run makes no connections, so every host reads as fresh — the same convention
  # check_running uses in deploy-multiserver.sh.
  if ! truthy "$DEPLOY_DRY_RUN" && [ "${DEPLOY_ENV_PUSH_FORCE:-}" != "yes" ]; then
    if host_exec "$host" "test -f ${DEPLOY_REMOTE_DIR}/.env" >/dev/null 2>&1; then
      remote_keys=$(host_exec "$host" "grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' ${DEPLOY_REMOTE_DIR}/.env | tr -d '='" 2>/dev/null | sort -u || true)
      local_keys=$(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$src" | tr -d '=' | sort -u || true)
      extra=$(comm -23 <(printf '%s\n' "$remote_keys") <(printf '%s\n' "$local_keys") | tr '\n' ' ' || true)
      extra=$(printf '%s' "$extra" | tr -d '[:space:]')

      # Only refresh files whose contents still match the last successful push.
      # A generated marker does not prove that an operator left the values alone.
      local current previous proposed
      current=$(host_exec "$host" "$(declare -f file_sha256); file_sha256 $(shquote "${DEPLOY_REMOTE_DIR}/.env")")
      previous=$(host_exec "$host" "cat ${DEPLOY_REMOTE_DIR}/.env.deploy.sha256 2>/dev/null" || true)
      proposed=$(file_sha256 "$src")
      if [ "$current" = "$proposed" ]; then
        info "${host}: .env already matches — kept unchanged"
        return 0
      fi
      if [ -n "$previous" ] && [ "$current" = "$previous" ]; then
        info "${host}: refreshing the .env this generated earlier"
      else
        warn "${host}: ${DEPLOY_REMOTE_DIR}/.env already exists — not overwriting."
        if [ -n "$extra" ]; then
          warn "${host}: it holds keys ${src} does not: ${extra}"
        fi
        warn "${host}: keep it, or overwrite with: DEPLOY_ENV_PUSH_FORCE=yes ./logstotal deploy:env"
        REFUSED="${REFUSED} ${host}"
        return 0
      fi
    fi
  fi

  tmp="/tmp/logstotal-env.$$"
  host_copy_to "$src" "$host" "$tmp"
  # Unprivileged first, elevating only if that fails. The target is often already owned
  # by the deploying user — `task deploy:bootstrap` chowns it — and reaching for sudo
  # unconditionally turns a working setup into a password prompt the deploy cannot answer.
  # The trailing `rm` must not become the command's exit status: ending `...; rm -f ${tmp}`
  # would let a failed install — `sudo: a password is required` is the one that happens —
  # return 0 and be announced as installed, leaving the host with a stale .env, or none.
  if ! host_exec "$host" "mkdir -p ${DEPLOY_REMOTE_DIR} 2>/dev/null && install -m 600 ${tmp} ${DEPLOY_REMOTE_DIR}/.env 2>/dev/null || { sudo -n mkdir -p ${DEPLOY_REMOTE_DIR} && sudo -n install -m 600 ${tmp} ${DEPLOY_REMOTE_DIR}/.env; }; rc=\$?; rm -f ${tmp}; exit \$rc"; then
    die "Could not write ${DEPLOY_REMOTE_DIR}/.env on ${host}. Nothing further was deployed.
The host has no configuration, or an old one, so continuing would deploy it against the wrong secrets.
Usually this is write permission: deploy as root@${host#*@}, or give the SSH user passwordless sudo."
  fi
  local fingerprint
  fingerprint=$(file_sha256 "$src")
  if ! host_exec "$host" "(umask 077; printf '%s\n' '$fingerprint' > ${DEPLOY_REMOTE_DIR}/.env.deploy.sha256) 2>/dev/null || printf '%s\n' '$fingerprint' | sudo -n tee ${DEPLOY_REMOTE_DIR}/.env.deploy.sha256 >/dev/null"; then
    die "Could not record the .env fingerprint on ${host}; the next changed push will require DEPLOY_ENV_PUSH_FORCE=yes."
  fi
  info "${host}: installed ${DEPLOY_REMOTE_DIR}/.env (mode 600)"
  PUSHED=$((PUSHED + 1))
}

header "Push env files"
IDX=0
for HOST in $(printf '%s' "${DEPLOY_HOSTS}" | tr ',' '\n'); do
  HOST=$(printf '%s' "$HOST" | xargs)
  [ -z "$HOST" ] && continue
  push_host "$HOST" "$IDX"
  IDX=$((IDX + 1))
done

if [ -n "$REFUSED" ]; then
  info "Pushed ${PUSHED} file(s); kept the existing .env on:${REFUSED}"
else
  info "Pushed ${PUSHED} file(s)."
fi
