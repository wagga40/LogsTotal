#!/usr/bin/env bash
# Remote /health probe for LogsTotal (developer / ops).
#
# Calls ${HEALTH_URL}/health and reports the parsed app/version/database/redis/
# storage/workers status. Used by task upgrade:*; task health is the
# localhost-default shorthand for this.
#
# Usage:
#   HEALTH_URL=https://logs.example.com bash scripts/health-remote.sh
#
# Environment consumed:
#   HEALTH_URL        Base URL of the deployment (required, e.g. http://localhost:8000).
#   BASIC_AUTH_USER   Basic-auth user when behind Caddy basicauth (optional).
#   BASIC_AUTH_PASS   Basic-auth password (optional).
#
# Exits non-zero if the response is not 200 or if any subsystem reports error.
# No pipefail — the jq-optional grep fallbacks pipe through commands whose
# non-zero status must not abort the script. Assumes the repo root is the
# current working directory.

set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

if [ -z "${HEALTH_URL:-}" ]; then
  die "HEALTH_URL is required (e.g. HEALTH_URL=http://localhost:8000)."
fi
AUTH=()
if [ -n "${BASIC_AUTH_USER:-}" ]; then
  AUTH=(-u "${BASIC_AUTH_USER}:${BASIC_AUTH_PASS:-}")
fi
# `-s`, never `-sf`. With `-f` curl prints nothing on a 4xx/5xx and exits non-zero, so
# /health returning 503 — a deployment whose database or Redis is down, i.e. the exact state
# this check exists to name — would come back as an empty body reported as "unreachable",
# and the breakdown below, which says WHICH subsystem is down, would never print. The
# breakdown is the whole point: the app answers 503 and still tells you why.
RESPONSE=$(curl -s --max-time 10 -w '\n%{http_code}' "${AUTH[@]}" "${HEALTH_URL%/}/health" 2>/dev/null || true)
CODE=$(printf '%s' "$RESPONSE" | tail -1 | tr -d '[:space:]')
BODY=$(printf '%s' "$RESPONSE" | sed '$d')

if [ -z "$CODE" ] || [ "$CODE" = "000" ]; then
  v_fail "$(value "${HEALTH_URL%/}/health") — no response at all (DNS, connection, timeout or TLS)"
  exit 1
fi
if [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
  v_unknown "$(value "${HEALTH_URL%/}/health") — HTTP ${CODE}: the deployment answered, behind HTTP basic auth." \
    "Nothing behind the proxy was measured. Set BASIC_AUTH_USER and BASIC_AUTH_PASS and re-run."
  exit 1
fi
# A body that is not our health document cannot be read as subsystem states — an error page
# from a proxy is not evidence that the database is down.
if ! printf '%s' "$BODY" | grep -q '"app"'; then
  v_unknown "$(value "${HEALTH_URL%/}/health") — HTTP ${CODE}, and the response is not a health document." \
    "Nothing was measured. Most often a proxy answering for an application that is not up."
  exit 1
fi
if command -v jq >/dev/null 2>&1; then
  STATUS=$(echo "$BODY" | jq -r '.app // "missing"')
  VERSION=$(echo "$BODY" | jq -r '.version // "?"')
  DB=$(echo "$BODY" | jq -r '.database // "?"')
  REDIS=$(echo "$BODY" | jq -r '.redis // "?"')
  STORAGE=$(echo "$BODY" | jq -r '.storage // "?"')
  WORKERS=$(echo "$BODY" | jq -r '.workers // "?"')
else
  STATUS=$(echo "$BODY" | grep -oE '"app":"[^"]+"' | head -1 | cut -d'"' -f4)
  VERSION=$(echo "$BODY" | grep -oE '"version":"[^"]+"' | head -1 | cut -d'"' -f4)
  DB=$(echo "$BODY" | grep -oE '"database":"[^"]+"' | head -1 | cut -d'"' -f4)
  REDIS=$(echo "$BODY" | grep -oE '"redis":"[^"]+"' | head -1 | cut -d'"' -f4)
  STORAGE=$(echo "$BODY" | grep -oE '"storage":"[^"]+"' | head -1 | cut -d'"' -f4)
  WORKERS=$(echo "$BODY" | grep -oE '"workers":[0-9]+' | head -1 | cut -d':' -f2)
fi
step "Health readout"
# The six readings, then the verdict. They stay a plain aligned block rather than six
# v_pass/v_unknown lines: a `?` here means the KEY was absent, and rendering that as a
# per-subsystem UNKNOWN would put four verdicts on screen for one unreadable response.
# The single verdict below says that once, correctly.
#
# Bold-value formatting keeps the plain 6-space / 2-space alignment tests pin
# (tests/test_deploy_check_scripts.py: `  app:      ok`, `  workers:  2`)
# and still differentiates key from value — `kv` would repad to col 22 and break both.
printf "  app:      %s\n" "$(value "${STATUS:-?}")"
printf "  version:  %s\n" "$(value "${VERSION:-?}")"
printf "  database: %s\n" "$(value "${DB:-?}")"
printf "  redis:    %s\n" "$(value "${REDIS:-?}")"
printf "  storage:  %s\n" "$(value "${STORAGE:-?}")"
printf "  workers:  %s\n" "$(value "${WORKERS:-?}")"
# A `?` above means the key was absent, not that the subsystem is broken. Folding the two
# together would print "one or more subsystems unhealthy" for a body we simply could not read —
# a definite negative verdict about three components nobody asked about.
UNKNOWN=""
for pair in "app:${STATUS:-?}" "database:${DB:-?}" "redis:${REDIS:-?}" "storage:${STORAGE:-?}"; do
  [ "${pair#*:}" = "?" ] && UNKNOWN="${UNKNOWN} ${pair%%:*}"
done
# Exit 1, not `exit $(v_status)`. verdict.sh returns 0 when some checks passed and others
# are UNKNOWN — right for a preflight that lists what it could not measure and continues,
# wrong here: `task upgrade` gates on this probe (upgrade.sh, twice), and "answered 200 but
# reported nothing for redis" must not clear that gate. The vocabulary is shared; the exit
# contract is this script's own.
if [ -n "$UNKNOWN" ]; then
  v_unknown "/health answered ${CODE} but reported nothing for:${UNKNOWN}"
  exit 1
fi
if [ "$CODE" != "200" ] || [ "${STATUS}" != "ok" ] || [ "${DB}" != "ok" ] || [ "${REDIS}" != "ok" ] || ! echo "${STORAGE}" | grep -q '^ok'; then
  v_fail "one or more subsystems unhealthy (HTTP ${CODE}) — see the lines above for which."
  exit 1
fi
v_pass "all subsystems healthy."
