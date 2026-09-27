#!/usr/bin/env bash
# Per-host .env generation for a LogsTotal fleet (developer / ops).
#
# A thin dispatcher: it reads the DEPLOY_* knobs (env, then deploy.env) and hands them
# to scripts/deploy_fleet_env.py, which owns the whole matrix. The generator is Python
# because an N-host matrix of secrets and cross-host URLs is not legible in shell and
# because it has to be unit-testable without SSH — the gen_secrets.py / proxy_enable.py
# / backup_lifecycle.py shape.
#
# Usage:
#   bash scripts/deploy-env-fleet.sh
#
# Configuration (env vars from the caller always override deploy.env values):
#   DEPLOY_HOSTS             Comma-separated host list; the first is the control plane.
#   DEPLOY_CP_ADDRESS        Address workers use to reach the control plane. When unset
#                            and there is no VPN map, it is DISCOVERED: what the control
#                            plane's name resolves to from a worker, else the control
#                            plane's own default-route address. Set it to override.
#   DEPLOY_CP_BIND_ADDRESS   IP the control plane binds its Redis/PG/S3 relays to. Docker
#                            binds ports by address, never by name, so this defaults to
#                            the control-plane address only when that is an IP, and to
#                            0.0.0.0 otherwise.
#   DEPLOY_ADMIN_EMAIL       Control-plane admin login (default admin@example.com).
#   DEPLOY_DOMAIN            Setting it turns the Caddy proxy on.
#   DEPLOY_PROXY_TLS         How that proxy terminates TLS: acme (default), internal
#                            (Caddy's own CA — no DNS, no port 80, no internet), custom
#                            (your certificate from ./certs), or off (plain HTTP).
#   DEPLOY_ACME_EMAIL        Certificate-authority contact address. DEPLOY_PROXY_TLS=acme
#                            only; the other three never contact a CA.
#   DEPLOY_BASIC_AUTH_USER   Caddy basic-auth username.
#   DEPLOY_BASIC_AUTH_HASH   Its bcrypt hash. Never the plaintext — scripts/deploy-fleet.sh
#                            hashes DEPLOY_BASIC_AUTH_PASSWORD on the control plane.
#   DEPLOY_REMOTE_DIR        Install dir on each host (default /opt/logstotal). Read only to
#                            ask whether the control plane ALREADY runs a release, which
#                            decides whether generating fresh secrets would break it.
#   DEPLOY_ENV_DIR           Where the generated files go (default deploy-envs). Shared
#                            with task deploy:env, which reads the same variable.
#   DEPLOY_HUEY_WORKERS      Worker threads per worker host (default 4).
#   DEPLOY_ENV_FORCE         truthy: regenerate every shared secret. Logs every session
#                            out and breaks existing worker credentials.
#   DEPLOY_ENV_FILE          Path to defaults file (default: deploy.env in cwd).
#   DEPLOY_DRY_RUN           truthy: skip the address discovery below, which needs to
#                            talk to the hosts. The generator itself still runs.
#
# `set -eu`, no pipefail — deploy_env_default's grep must be allowed to miss.

set -eu

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"
deploy_env_load \
  DEPLOY_HOSTS DEPLOY_ENV_DIR DEPLOY_CP_ADDRESS DEPLOY_CP_BIND_ADDRESS DEPLOY_ADMIN_EMAIL DEPLOY_DOMAIN DEPLOY_PROXY_TLS DEPLOY_ACME_EMAIL \
  DEPLOY_BASIC_AUTH_USER DEPLOY_BASIC_AUTH_HASH DEPLOY_HUEY_WORKERS DEPLOY_ENV_FORCE

[ -n "${DEPLOY_HOSTS:-}" ] || die "DEPLOY_HOSTS is required (comma-separated host list; set it or put it in ${DEPLOY_ENV_FILE})"

DEPLOY_ENV_DIR="${DEPLOY_ENV_DIR:-deploy-envs}"
build_ssh_opts

# ── Discover where the control plane actually is ─────────────────────────────
#
# Two different addresses are needed and they are not the same question:
#
#   * the one workers dial   — must be reachable FROM A WORKER, so the worker is who
#     gets asked. A name in DEPLOY_HOSTS is frequently an ~/.ssh/config alias or a
#     laptop-only DNS entry, and pushing that into a worker's DATABASE_URL produces a
#     fleet that resolves nothing and sits in `pending` with no clue why.
#   * the one the relays bind — must be an address the control plane HOLDS, because
#     Docker binds ports by address and refuses a name outright.
#
# Both are answerable from the hosts themselves, so they are answered here rather than
# left to the operator.

CP_HOST="${DEPLOY_HOSTS%%,*}"
CP_NAME="${CP_HOST#*@}"
VPN_MAP="${DEPLOY_ENV_DIR}/vpn.json"

if [ -z "${DEPLOY_CP_ADDRESS:-}" ] && [ ! -f "$VPN_MAP" ] && ! truthy "${DEPLOY_DRY_RUN:-}"; then
  FOUND=""
  # Ask a worker first — its answer is the one that has to be right.
  REST="${DEPLOY_HOSTS#*,}"
  if [ "$REST" != "$DEPLOY_HOSTS" ]; then
    for PEER in $(printf '%s' "$REST" | tr ',' '\n'); do
      PEER=$(printf '%s' "$PEER" | xargs)
      [ -n "$PEER" ] || continue
      is_local_host "$PEER" && continue
      CANDIDATE=$(resolve_from "$PEER" "$CP_NAME")
      if is_ipv4 "$CANDIDATE"; then
        FOUND="$CANDIDATE"
        info "Control plane resolves to ${FOUND} from ${PEER}"
        break
      fi
    done
  fi
  # Otherwise ask the control plane where it lives.
  if [ -z "$FOUND" ]; then
    CANDIDATE=$(host_primary_address "$CP_HOST")
    if is_ipv4 "$CANDIDATE"; then
      FOUND="$CANDIDATE"
      info "Control plane reports its own address as ${FOUND}"
    fi
  fi
  if [ -n "$FOUND" ]; then
    DEPLOY_CP_ADDRESS="$FOUND"
  else
    warn "Could not determine an address for the control plane (${CP_NAME}) from any host."
    warn "Set DEPLOY_CP_ADDRESS=<the address workers will use>, or run: ./logstotal deploy:vpn"
  fi
fi

# The bind address has to be one the control plane actually holds; anything else and
# `docker compose up` fails with `invalid IP address`. Binding every interface is the
# honest fallback, and the generator says so.
if [ -z "${DEPLOY_CP_BIND_ADDRESS:-}" ] && [ -n "${DEPLOY_CP_ADDRESS:-}" ] && ! truthy "${DEPLOY_DRY_RUN:-}"; then
  if host_addresses "$CP_HOST" | grep -qxF "$DEPLOY_CP_ADDRESS"; then
    DEPLOY_CP_BIND_ADDRESS="$DEPLOY_CP_ADDRESS"
  else
    info "${DEPLOY_CP_ADDRESS} is not on an interface of ${CP_NAME} (NAT or a VPN endpoint) — binding every interface instead"
    # Say it AND do it. Printing the line without setting the value would leave the
    # generator on its own default, which returns the CP address verbatim whenever it is an
    # IP literal — from there it cannot know the address is not on the host — and the
    # deploy would run to its last step and die on a raw Docker error:
    # `failed to bind host port <ip>:6379/tcp: cannot assign requested address`.
    # shellcheck disable=SC2034  # read below, where the generator's arguments are built
    DEPLOY_CP_BIND_ADDRESS="0.0.0.0"
  fi
fi

# DEPLOY_ENV_DIR has to reach the generator too: deploy-env-push.sh reads it when it
# looks for what to push, so a generator writing to the default while the push looks
# elsewhere means "No env file for <host>" on a run that just produced one.
# Generating fresh secrets for a fleet that is ALREADY DEPLOYED is silent data loss.
#
# The secrets file is the only copy of POSTGRES_PASSWORD, and PostgreSQL sets that password
# once, when its data directory is initialised. So a run that generates a new one against an
# existing volume produces an install that starts, connects, and fails:
#
#   FATAL: password authentication failed for user "logstotal"
#
# — in the web container's log, after a deploy that reported every step green until the
# health gate timed out. The same is true of SECRET_KEY (every session invalidated) and the
# S3 keys (Garage rejects the worker).
#
# DEPLOY_ENV_FORCE warns about exactly this, and losing the file has the same effect — the
# more likely way to arrive here: it is gitignored, it lives on one machine, and nothing
# else on the fleet has a copy.
# A pulled record carries no secrets, by design — they never leave the machine that
# generated them. So the env steps cannot run from one: deploy_fleet_env.py MINTS a fresh
# SECRET_KEY, POSTGRES_PASSWORD and REDIS_PASSWORD when secrets.json is absent, and
# deploy-env-push.sh will push that over a working remote .env because it carries the
# generator marker. PostgreSQL sets its password once, when its data directory is created,
# so the new one authenticates against nothing and the fleet fails health after looking green.
#
# Keyed on FLEET_ADOPTED rather than on the missing file: losing deploy-envs/ locally is a
# deliberate recovery path that already warns at length in deploy-env-fleet.sh, and an
# operator who arrived there chose it. Adopting a remote record is not that — nobody
# expected this laptop to hold the fleet's secrets.
_refuse_env_generation_from_an_adopted_record() {
  [ "${FLEET_ADOPTED:-}" = "yes" ] || return 0
  [ -f "${DEPLOY_ENV_DIR:-deploy-envs}/secrets.json" ] && return 0
  die "this fleet was adopted from ${FLEET_FROM}, and generating env files needs its secrets.
       They never leave the machine that made them, so fresh ones would be minted here and
       pushed over a working fleet — PostgreSQL would then authenticate against nothing.

       An adopted record can upgrade, inspect, smoke-test and remove a fleet. To change env
       files, run from the machine holding deploy-envs/, or copy that directory here."
}
_refuse_env_generation_from_an_adopted_record

if [ ! -f "${DEPLOY_ENV_DIR}/secrets.json" ] && ! truthy "${DEPLOY_DRY_RUN:-}"; then
  _installed=$(host_installed_release "$CP_HOST" "${DEPLOY_REMOTE_DIR:-/opt/logstotal}" 2>/dev/null || true)
  case "$_installed" in
    "" | "|"*) ;;  # nothing installed there: a first deploy, which is what this is for
    *)
      warn "No ${DEPLOY_ENV_DIR}/secrets.json here, but ${CP_NAME} already runs ${_installed%%|*}."
      echo "       Fresh secrets will be generated, and they will NOT match what is already"
      echo "       deployed: PostgreSQL sets its password once, when its data directory is"
      echo "       created, so the new one authenticates against nothing. The deploy will look"
      echo "       green until the control plane fails its health check."
      echo ""
      echo "       If you have the original ${DEPLOY_ENV_DIR}/ from the machine that deployed"
      echo "       this fleet, restore it and re-run. If it is genuinely gone, the database"
      echo "       password has to be changed to match — or the volume recreated, which"
      echo "       destroys its contents. Continuing anyway."
      ;;
  esac
fi

ARGS=(--hosts "$DEPLOY_HOSTS" --out-dir "$DEPLOY_ENV_DIR" --state "${DEPLOY_ENV_DIR}/secrets.json" --addresses "$VPN_MAP")
[ -n "${DEPLOY_CP_ADDRESS:-}" ] && ARGS+=(--cp-address "$DEPLOY_CP_ADDRESS")
[ -n "${DEPLOY_CP_BIND_ADDRESS:-}" ] && ARGS+=(--cp-bind-address "$DEPLOY_CP_BIND_ADDRESS")
[ -n "${DEPLOY_ADMIN_EMAIL:-}" ] && ARGS+=(--admin-email "$DEPLOY_ADMIN_EMAIL")
[ -n "${DEPLOY_DOMAIN:-}" ] && ARGS+=(--domain "$DEPLOY_DOMAIN")
[ -n "${DEPLOY_ACME_EMAIL:-}" ] && ARGS+=(--acme-email "$DEPLOY_ACME_EMAIL")
[ -n "${DEPLOY_PROXY_TLS:-}" ] && ARGS+=(--proxy-tls "$DEPLOY_PROXY_TLS")
[ -n "${DEPLOY_BASIC_AUTH_USER:-}" ] && ARGS+=(--basic-auth-user "$DEPLOY_BASIC_AUTH_USER")
[ -n "${DEPLOY_BASIC_AUTH_HASH:-}" ] && ARGS+=(--basic-auth-hash "$DEPLOY_BASIC_AUTH_HASH")
[ -n "${DEPLOY_HUEY_WORKERS:-}" ] && ARGS+=(--huey-workers "$DEPLOY_HUEY_WORKERS")
truthy "${DEPLOY_ENV_FORCE:-}" && ARGS+=(--force)

run_py "$SCRIPT_DIR/deploy_fleet_env.py" "${ARGS[@]}"
