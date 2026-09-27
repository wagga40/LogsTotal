#!/usr/bin/env bash
# Post-deploy smoke check for LogsTotal (developer / ops).
#
# Probes a running instance to verify it is healthy after deployment: /health
# (DB + Redis + storage), the homepage (/), and the auth login page.
#
# Usage:
#   bash scripts/deploy-smoke.sh
#
# Target URL resolution (each also read from deploy.env when not in the env;
# caller env always wins):
#   1. SMOKE_URL   Explicit full URL (e.g. https://logs.example.com).
#   2. DOMAIN / DEPLOY_DOMAIN  proxy deployments — derives https://$DOMAIN, or http:// when the
#                  proxy serves plain HTTP.
#
# PROXY_TLS / DEPLOY_PROXY_TLS (default acme) decide that scheme and whether the
# certificate is verified. `internal` and `custom` serve one no public CA vouches for, so
# the probes add -k: this is a reachability check against a host we just deployed, and
# refusing to look would report 000 for every internal deployment — indistinguishable from dead.
#   3. DEPLOY_HOSTS  First host — derives http://<host>:8000 (a user@ prefix is stripped;
#                    the `local` sentinel resolves to localhost).
#   4. http://localhost:8000  Fallback for local dev.
#
# BASIC_AUTH_USER + BASIC_AUTH_PASS (plaintext, the health-remote.sh spelling — Caddy's
# own key is BASIC_AUTH_HASH) add credentials to every probe. Without them, turning on
# Caddy basic auth makes all six checks return 401 and a perfectly healthy fleet report
# SMOKE FAILED — a failure this script would otherwise invent rather than detect.
# DEPLOY_BASIC_AUTH_USER and DEPLOY_BASIC_AUTH_PASSWORD are the deploy.env spellings of the
# two, read as fallbacks. The password is read from the file as well as the environment:
# deploy.env offers it as a setting, and a smoke test that refused to read what the deploy
# itself reads would 401 against a fleet whose password is sitting right there.
#
# DEPLOY_SMOKE_STRICT truthy: exit non-zero when nothing could be measured, instead of 0.
#
# DEPLOY_HEALTH_CONFIRMED is set ONLY by a caller that has already verified the control
# plane's /health from inside the network (deploy-fleet.sh and upgrade.sh, after
# deploy-multiserver.sh's health gate). It downgrades an unreachable endpoint from a
# failure to "could not verify" — see the note at the /health probe for why that is safe
# there and unsafe here.
#
# DEPLOY_ENV_FILE overrides the defaults file (default: deploy.env in cwd).
#
# DEPLOY_REMOTE_DIR is where this host's fleet record lives (default /opt/logstotal). It is
# the last source consulted for DOMAIN, PROXY_TLS, the basic-auth username and the host
# list — after the environment and after deploy.env — which is what lets a bare
# `task deploy:smoke` work ON a control plane, where deploy.env belongs to whoever ran the
# deploy and package.sh keeps it out of the archive.
#
# DEPLOY_DRY_RUN truthy: print the target and make no requests — deploy-fleet.sh runs this
# unguarded as step 8/8, so the dry-run contract depends on it.
#
# Exit codes:
#   0  every check passed — OR nothing could be measured (see below)
#   1  something was measured and it failed — the deployment has a problem
#   2  nothing could be measured, under DEPLOY_SMOKE_STRICT=true
#
# Four verdict words on the check lines, and they are not interchangeable: OK measured and
# good, FAIL measured and bad, SKIP not measured, UNKNOWN nothing answered at all. Only FAIL
# is counted, and only FAIL decides the exit status.
#
# Skipped is not failed. When HTTP basic auth turns every probe into a 401 and no
# credentials were supplied, nothing behind the proxy is measured — and the run exits 0 by
# default, because `task deploy:smoke` printing "Failed to run task" for checks that were
# never attempted says the deployment is broken when what happened is that nobody supplied
# a password. The verdict is stated loudly in the output either way; the exit status is not
# the place to report it.
#
# DEPLOY_SMOKE_STRICT=true restores a non-zero exit (2) for automation that must treat
# "unverified" as a failure — a release pipeline that gates on this, for instance.
#
# NOTE go-task collapses every non-zero exit to 201, so a caller that needs to tell 1 from 2
# must run this script directly rather than through `task deploy:smoke`.
#
# The probes use `curl -s`, never `-sf`. With `-f` curl writes nothing on a 4xx/5xx and
# exits non-zero, so the `|| echo "000"` fallback would always win: a 503 from /health — the
# exact case this script exists to catch — would read as "000", indistinguishable from a host
# that never answered. Without `-f`, "000" means what it reads as: no response at all.
#
# No pipefail — the curl probes lean on `|| echo "000"` guards where a non-zero
# curl status must not abort the script. Assumes the repo root is the current
# working directory.

set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"

# The four settings the fleet record can answer, through the shared loader: environment,
# then deploy.env, then the record. Only these four — deploy_env_load treats a key that is
# merely SET (even to empty) as answered, which is right for a DEPLOY_* key and wrong for
# the bare spellings below, whose whole idiom is that empty means "fall through".
#
# On a control plane there is no deploy.env — it belongs to whoever ran the deploy and
# package.sh keeps it out of the archive — so without the record this would warn "no
# SMOKE_URL, DOMAIN or DEPLOY_HOSTS set", fall back to http://localhost:8000, which behind
# Caddy is bound to loopback on purpose, and report SMOKE FAILED on a healthy fleet.
# Adopt a remote fleet record when FLEET_FROM names a control plane. ABOVE the first
# deploy.env read, always: _fleet_options memoises the record's options on first read, so a
# later adoption is silently half-applied — hosts from the remote record, settings from this
# machine. See lib/fleet_record.sh::fleet_adopt.
fleet_adopt
deploy_env_load DEPLOY_REMOTE_DIR DEPLOY_DOMAIN DEPLOY_PROXY_TLS DEPLOY_BASIC_AUTH_USER

SMOKE_URL="${SMOKE_URL:-$(deploy_env_default SMOKE_URL)}"
DOMAIN="${DOMAIN:-$(deploy_env_default DOMAIN)}"
# deploy.env spells it DEPLOY_DOMAIN. Without the bridge, `task deploy:smoke` and the smoke
# step of `task upgrade` would not know the deployment has a domain, fall through to
# http://<control-plane-ip>:8000, and time out: behind Caddy the app is bound to
# 127.0.0.1:8000 on purpose, so that address is dropped rather than refused.
DOMAIN="${DOMAIN:-${DEPLOY_DOMAIN:-$(deploy_env_default DEPLOY_DOMAIN)}}"
# How the control plane's proxy terminates TLS, which decides both the scheme below and
# whether curl can verify the certificate. Without it every internal deployment would fail
# its own smoke test: `internal` and `custom` serve a certificate this machine has no reason
# to trust, and `off` does not serve https at all — a healthy fleet reporting 000 across the
# board, which reads as "the deploy is dead".
PROXY_TLS="${PROXY_TLS:-$(deploy_env_default PROXY_TLS)}"
PROXY_TLS="${PROXY_TLS:-${DEPLOY_PROXY_TLS:-$(deploy_env_default DEPLOY_PROXY_TLS)}}"
PROXY_TLS="${PROXY_TLS:-acme}"
# The host list takes the other route: the record keeps hosts in hosts[], while
# deploy_env_load's record rung reads options{} — so `deploy_env_load DEPLOY_HOSTS` returns
# nothing however the key list is written. See resolve_deploy_hosts in lib/common.sh.
resolve_deploy_hosts
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-$(deploy_env_default DEPLOY_DRY_RUN)}"
BASIC_AUTH_USER="${BASIC_AUTH_USER:-$(deploy_env_default BASIC_AUTH_USER)}"
BASIC_AUTH_USER="${BASIC_AUTH_USER:-${DEPLOY_BASIC_AUTH_USER:-$(deploy_env_default DEPLOY_BASIC_AUTH_USER)}}"
BASIC_AUTH_PASS="${BASIC_AUTH_PASS:-$(deploy_env_default BASIC_AUTH_PASS)}"
# The environment first, then deploy.env — the precedence every other key here uses, and
# the same order deploy-fleet.sh resolves it in, so the two cannot disagree about which
# password the fleet was deployed with.
BASIC_AUTH_PASS="${BASIC_AUTH_PASS:-${DEPLOY_BASIC_AUTH_PASSWORD:-$(deploy_env_default DEPLOY_BASIC_AUTH_PASSWORD)}}"

# An array, so the credentials never pass through a shell word-splitting round.
CURL_AUTH=()
if [ -n "${BASIC_AUTH_USER:-}" ] && [ -n "${BASIC_AUTH_PASS:-}" ]; then
  CURL_AUTH=(-u "${BASIC_AUTH_USER}:${BASIC_AUTH_PASS}")
fi

# `-k` for the two modes that serve a certificate no CA vouches for. This is a reachability
# probe against a host we just deployed, not a trust decision — and refusing to look would
# leave "is it up?" unanswerable on every internal deployment. `acme` keeps full
# verification, because there a bad certificate is a real finding.
CURL_TLS=()
case "$PROXY_TLS" in
  internal | custom) CURL_TLS=(-k) ;;
esac

if [ -n "${SMOKE_URL:-}" ]; then
  BASE_URL="$SMOKE_URL"
elif [ -n "${DOMAIN:-}" ]; then
  # PROXY_TLS=off means Caddy is in front on plain HTTP; https:// there is a connection
  # refused, not a certificate problem.
  if [ "$PROXY_TLS" = "off" ]; then
    BASE_URL="http://${DOMAIN}"
  else
    BASE_URL="https://${DOMAIN}"
  fi
elif [ -n "${DEPLOY_HOSTS:-}" ]; then
  CONTROL_PLANE=$(echo "$DEPLOY_HOSTS" | cut -d',' -f1 | xargs)
  CONTROL_PLANE="${CONTROL_PLANE#*@}"
  # `local` is a sentinel meaning "this machine", not a hostname — resolving it would
  # ask DNS for a host called `local` and report the deployment dead.
  if is_local_host "$CONTROL_PLANE"; then
    CONTROL_PLANE="localhost"
  else
    # A DEPLOY_HOSTS entry is an SSH destination, and an SSH destination is not
    # necessarily a name DNS knows: `w0` may be an ~/.ssh/config alias whose real
    # HostName is w0.example.org. ssh resolves it, curl does not — so a perfectly
    # healthy fleet would report FAILs and "000", which reads as a dead deployment
    # rather than an unresolvable name.
    #
    # `ssh -G` asks the local ssh client what it would use, without connecting. Falls
    # back to the literal entry when ssh is absent or has nothing to say.
    if command -v ssh >/dev/null 2>&1; then
      RESOLVED=$(ssh -G "$CONTROL_PLANE" 2>/dev/null | awk '$1 == "hostname" { print $2; exit }')
      if [ -n "${RESOLVED:-}" ] && [ "$RESOLVED" != "$CONTROL_PLANE" ]; then
        info "${CONTROL_PLANE} is an SSH alias for ${RESOLVED} — probing that."
        CONTROL_PLANE="$RESOLVED"
      fi
    fi
  fi
  BASE_URL="http://${CONTROL_PLANE}:8000"
else
  BASE_URL="http://localhost:8000"
  # Say so. With nothing configured, announcing a localhost target and then reporting
  # FAILs for a deployment it never contacted would read as "the deploy is broken" rather
  # than "you did not tell me where it is".
  warn "no SMOKE_URL, DOMAIN or DEPLOY_HOSTS set (checked the environment, ${DEPLOY_ENV_FILE}, and this host's fleet record) — falling back to localhost."
  warn "If you meant to smoke-test a remote deployment, set SMOKE_URL=https://host or DEPLOY_HOSTS=..."
fi
# `Smoke-testing:` stays a bare prose line rather than the shared `kv` primitive: kv's
# 22-col label pad would break the tests that assert `Smoke-testing: <url>` with a single
# space. Colour the URL via `value()` so the target still stands out.
printf 'Smoke-testing: %s\n' "$(value "$BASE_URL")"
# Where the target came from, whenever it was the host list rather than an explicit URL.
# On a control plane the answer is "this host's fleet record", and an operator who has just
# been told a fleet is unhealthy should not have to guess which fleet was probed.
if [ -z "${SMOKE_URL:-}" ] && [ -z "${DOMAIN:-}" ] && [ -n "${FLEET_HOSTS_SOURCE:-}" ]; then
  printf '               (control plane of %s, from %s)\n' "$(value "$DEPLOY_HOSTS")" "$(value "$FLEET_HOSTS_SOURCE")"
fi

# deploy-fleet.sh calls this unguarded as step 8/8, so without this guard
# `DEPLOY_DRY_RUN=true task deploy` would fire real HTTP requests at the first DEPLOY_HOSTS
# entry — contradicting docs/install/fleet.md's "connect to nothing" — and a dry run against
# an unreachable fleet would report SMOKE FAILED, which reads as a broken dry run.
if truthy "${DEPLOY_DRY_RUN:-false}"; then
  printf '%s(dry-run: would probe /health, /, /auth/login — making no requests)%s\n' "$C_CYAN" "$C_OFF"
  exit 0
fi

# Probe one URL. Sets PROBE_CODE (three digits, "000" when nothing answered) and PROBE_RC
# (curl's own exit status).
#
# Not `$(curl -w '%{http_code}' ... || echo "000")`: on a transport failure curl writes
# "000" itself AND exits non-zero, so the guard would append a second one and the report
# would read `FAIL /health (000000)` — a code that matches nothing. The test shim exits 0,
# so no test takes that path.
probe() {
  local rc=0
  PROBE_CODE=$(curl -s "${CURL_AUTH[@]+"${CURL_AUTH[@]}"}" "${CURL_TLS[@]+"${CURL_TLS[@]}"}" -o /dev/null -w "%{http_code}" --max-time 10 "$1" 2>/dev/null) || rc=$?
  PROBE_RC="$rc"
  [ -n "${PROBE_CODE:-}" ] || PROBE_CODE="000"
}

# "000" says only that nothing answered. curl's exit status says which layer failed, which
# is the difference between "fix DNS" and "the certificate is not issued yet".
probe_reason() {
  case "$1" in
    0) printf '' ;;
    6) printf ' — could not resolve the host (DNS)' ;;
    7) printf ' — connection refused or no route: is the proxy running, is the port open?' ;;
    28) printf ' — timed out' ;;
    35 | 51 | 60) printf ' — TLS failed: no certificate this machine trusts. With PROXY_TLS=acme, Caddy may not have obtained one yet — check ./logstotal docker:logs:proxy on the control plane' ;;
    *) printf ' — curl exit %s' "$1" ;;
  esac
}

#: Nothing measurable was reached. 0 unless the caller asked for strictness — see the
#: exit-code note in the header.
DEPLOY_SMOKE_STRICT="${DEPLOY_SMOKE_STRICT:-$(deploy_env_default DEPLOY_SMOKE_STRICT)}"
if truthy "${DEPLOY_SMOKE_STRICT:-false}"; then EXIT_UNVERIFIED=2; else EXIT_UNVERIFIED=0; fi

# The tally. Two counters and no third: FAIL is the only one with any authority, gating the
# `SMOKE FAILED` branch and its exit 1, and PASS exists to be printed beside it. A SKIP is
# deliberately counted by NEITHER — it is the absence of a measurement, and adding it to
# either total would state a verdict about a check that was never made. So the rule for
# every arm below is: increment only when a real response was read and understood.
PASS=0
FAIL=0

# Health endpoint.
#
# A `000` — curl reached no HTTP response at all: DNS did not resolve, the connection was
# refused, the request timed out — is a FAILURE here and must stay one. Run on its own,
# this script has no way to tell a dead application from an unroutable address, and
# "a dead host is not an unverifiable one" is the rule that keeps the auth-wall leniency
# below from swallowing a real outage.
#
# The callers that DO know the difference are deploy-fleet.sh and upgrade.sh: both gate on
# the control plane's own
# /health BEFORE they get here — probed from the host itself, inside the network, by
# deploy-multiserver.sh::wait_for_health. Once that has passed, a workstation that cannot
# reach the same endpoint is reporting a fact about the route between here and there, not
# about the deployment: a fleet behind a WireGuard mesh publishes nothing to the outside,
# by design, and that is the DEFAULT topology.
#
# So the knowledge lives where it exists. DEPLOY_HEALTH_CONFIRMED is set by those two
# callers and by nothing else; without it, `000` fails.
UNREACHABLE=no
probe "$BASE_URL/health"
HEALTH_CODE="$PROBE_CODE"

# A 401 is not an outage. It is the proxy answering — over a certificate curl accepted —
# with "prove who you are", which means TLS, DNS, the port and Caddy are all working. The
# one thing it does NOT tell us is anything about the application behind it, because Caddy
# replies before proxying. So it is still a failure to VERIFY, but reporting it the same way
# as a dead host sends the operator to debug a healthy fleet.
#
# Decided BEFORE the verdict below, and that ordering is the whole point: decided after,
# the else arm would claim the 401 first — `FAIL /health (401)` opening a run whose every
# other line reads SKIP and whose verdict is COULD NOT VERIFY, with a FAIL tally that
# disagrees with the exit code.
#
# Reads HEALTH_CODE, not PROBE_CODE: the two are equal here, and only one of them stays that
# way. `probe` reassigns PROBE_CODE, so a probe inserted above this line would silently
# re-aim the auth decision at a different response.
AUTH_WALL=no
if [ "$HEALTH_CODE" = "401" ] || [ "$HEALTH_CODE" = "403" ]; then
  AUTH_WALL=yes
fi

if [ "$PROBE_CODE" = "200" ]; then
  printf '  %sOK%s   /health (%s)\n' "$C_GREEN" "$C_OFF" "$PROBE_CODE"
  PASS=$((PASS + 1))
elif [ "$PROBE_CODE" = "000" ] && truthy "${DEPLOY_HEALTH_CONFIRMED:-false}"; then
  UNREACHABLE=yes
  printf '  %sUNKNOWN%s /health — no response%s\n' "$C_CYAN" "$C_OFF" "$(probe_reason "$PROBE_RC")"
elif [ "$AUTH_WALL" = "yes" ]; then
  # SKIP, not UNKNOWN, and the four words are not interchangeable. UNKNOWN is this run's
  # word for "nothing answered, and a caller who can see inside the network says that is a
  # fact about the route" — but something did answer here, and said precisely what it
  # wanted. What went unmeasured is the application behind the proxy, which is exactly what
  # SKIP means on the six lines below; this one carries their reason string verbatim so the
  # whole run reads as one vocabulary. Deliberately NOT counted: see the tally note above.
  printf '  %sSKIP%s /health (%s) — not measured (authentication required)\n' "$C_CYAN" "$C_OFF" "$HEALTH_CODE"
else
  printf '  %sFAIL%s /health (%s%s)\n' "$C_RED" "$C_OFF" "$PROBE_CODE" "$(probe_reason "$PROBE_RC")"
  FAIL=$((FAIL + 1))
fi

# Reached whenever neither the environment nor deploy.env carried a password — the usual
# case when the fleet was deployed with one passed for that run alone.
if [ "$AUTH_WALL" = "yes" ]; then
  echo ""
  if [ ${#CURL_AUTH[@]} -eq 0 ]; then
    warn "the deployment is up and behind HTTP basic auth, and no credentials were supplied."
    echo "       Everything below this line could not be measured — not a single check reached"
    echo "       the application. Re-run with the password, or set it in deploy.env:"
    echo ""
    echo "         DEPLOY_BASIC_AUTH_PASSWORD='...' ./logstotal deploy:smoke"
  else
    warn "the credentials supplied were rejected by the proxy (${HEALTH_CODE})."
    echo "       Check BASIC_AUTH_USER against DEPLOY_BASIC_AUTH_USER, and that the password"
    echo "       matches the BASIC_AUTH_HASH the control plane was deployed with."
  fi
  echo ""
fi

# Health detail.
#
# Every verdict below is read out of this ONE response body. When it could not be obtained,
# they are not failures — they are unmeasured, and printing "FAIL database subsystem" for a
# database nothing ever asked about sends the operator to debug a healthy component. This is
# the mirror of the rule deploy-preflight.sh already follows in the other direction: never
# report OK for something you could not measure.
HEALTH_BODY=$(curl -s "${CURL_AUTH[@]+"${CURL_AUTH[@]}"}" "${CURL_TLS[@]+"${CURL_TLS[@]}"}" --max-time 10 "$BASE_URL/health" 2>/dev/null || echo "{}")

# Did a health DOCUMENT arrive — not merely a response? Gating on the auth wall alone would
# be too narrow, leaving every other cause reporting invented failures. A 502
# from a proxy whose app container is down, a 404 from a wrong path, a transfer truncated
# mid-body, the "{}" fallback after a transport error — each leaves a body that matches
# none of the greps below, and each would print three confident subsystem failures and a
# worker diagnosis. `"app"` is in every real health response and in none of those.
#
# Note this only suppresses verdicts we could not make. A genuine 503 CARRYING a body is
# still read normally: FAIL database / OK redis / OK storage, which is the whole point of
# asking.
# Decided PER KEY, not per document. A document-level flag is the wrong granularity: a body
# truncated mid-transfer still carries "app", so it would pass a whole-document check and
# then produce three confident subsystem failures under an "OK /health (200)" line — the single
# most misleading output this script could emit. Asking whether THIS field arrived is the
# only test that separates "the value says not-ok" from "there was no value".
health_has_key() { printf '%s' "$HEALTH_BODY" | grep -q "\"$1\""; }

health_unmeasured_reason() {
  if [ "$AUTH_WALL" = "yes" ]; then
    printf 'authentication required'
  elif [ "$HEALTH_CODE" = "000" ]; then
    printf 'nothing answered — see /health above'
  elif [ "$HEALTH_CODE" = "200" ]; then
    printf 'the response did not carry it — truncated, or not a health document'
  else
    printf '/health returned %s, not a health document' "$HEALTH_CODE"
  fi
}

for CHECK in database redis storage; do
  if echo "$HEALTH_BODY" | grep -q "\"$CHECK\":\"ok"; then
    printf '  %sOK%s   %s subsystem\n' "$C_GREEN" "$C_OFF" "$CHECK"
    PASS=$((PASS + 1))
  elif ! health_has_key "$CHECK"; then
    printf '  %sSKIP%s %s subsystem — not measured (%s)\n' "$C_CYAN" "$C_OFF" "$CHECK" "$(health_unmeasured_reason)"
  else
    printf '  %sFAIL%s %s subsystem\n' "$C_RED" "$C_OFF" "$CHECK"
    FAIL=$((FAIL + 1))
  fi
done

# Workers. /health carries "workers": N and "workers_ok"; unread, a fleet whose remote
# workers are connected to nothing passes every gate and finishes with "SMOKE PASSED".
# Their containers run, so the deploy's
# own worker check is satisfied; the control plane answers 200, so /health is satisfied;
# and the only symptom is that no job ever leaves `pending`. Asking the control plane how
# many workers registered is the one cheap question that catches a fleet wired to nothing.
#
# "unknown" is what /health reports when Redis cannot be reached to count them — already
# covered by the redis check above, so it is not double-counted as a worker failure.
WORKERS=$(printf '%s' "$HEALTH_BODY" | sed -n 's/.*"workers":[[:space:]]*\([0-9]*\).*/\1/p')
if printf '%s' "$HEALTH_BODY" | grep -q '"workers_ok":[[:space:]]*true'; then
  printf '  %sOK%s   workers registered (%s)\n' "$C_GREEN" "$C_OFF" "$(value "${WORKERS:-?}")"
  PASS=$((PASS + 1))
elif printf '%s' "$HEALTH_BODY" | grep -q '"workers":[[:space:]]*"unknown"'; then
  printf '  %sINFO%s workers could not be counted (Redis unreachable — see above)\n' "$C_CYAN" "$C_OFF"
elif ! health_has_key "workers"; then
  printf '  %sSKIP%s workers — not measured (%s)\n' "$C_CYAN" "$C_OFF" "$(health_unmeasured_reason)"
else
  printf '  %sFAIL%s no workers registered — jobs would stay in pending\n' "$C_RED" "$C_OFF"
  echo "       check each worker: ./logstotal deploy:logs, and that its .env reaches the control plane"
  FAIL=$((FAIL + 1))
fi

# Homepage
probe "$BASE_URL/"
if [ "$PROBE_CODE" = "200" ]; then
  printf '  %sOK%s   / homepage (%s)\n' "$C_GREEN" "$C_OFF" "$PROBE_CODE"
  PASS=$((PASS + 1))
elif [ "$AUTH_WALL" = "yes" ] && { [ "$PROBE_CODE" = "401" ] || [ "$PROBE_CODE" = "403" ]; }; then
  printf '  %sSKIP%s / homepage — not measured (authentication required)\n' "$C_CYAN" "$C_OFF"
else
  printf '  %sFAIL%s / homepage (%s%s)\n' "$C_RED" "$C_OFF" "$PROBE_CODE" "$(probe_reason "$PROBE_RC")"
  FAIL=$((FAIL + 1))
fi

# Auth login page
probe "$BASE_URL/auth/login"
if [ "$PROBE_CODE" = "200" ]; then
  printf '  %sOK%s   /auth/login (%s)\n' "$C_GREEN" "$C_OFF" "$PROBE_CODE"
  PASS=$((PASS + 1))
elif [ "$AUTH_WALL" = "yes" ] && { [ "$PROBE_CODE" = "401" ] || [ "$PROBE_CODE" = "403" ]; }; then
  printf '  %sSKIP%s /auth/login — not measured (authentication required)\n' "$C_CYAN" "$C_OFF"
else
  printf '  %sFAIL%s /auth/login (%s%s)\n' "$C_RED" "$C_OFF" "$PROBE_CODE" "$(probe_reason "$PROBE_RC")"
  FAIL=$((FAIL + 1))
fi

echo ""
# Still a non-zero exit — nothing was verified, and a verification step that could not run
# must not report success. But "SMOKE FAILED: 0 passed, 7 failed" is a claim about the
# deployment, and this is a claim about the check: the fleet answered, over a certificate
# curl accepted, and asked for credentials. Reported as SMOKE FAILED it would read as an
# outage.
# Verdict prefix stays LITERAL in the printf format (never a %s arg) so tests can grep
# for "SMOKE COULD NOT VERIFY" / "SMOKE FAILED" / "SMOKE PASSED" in stdout. Colour is
# applied around the whole prefix; plain output is byte-identical (C_* empty off a TTY).
if [ "$UNREACHABLE" = "yes" ]; then
  printf '%sSMOKE COULD NOT VERIFY:%s %s never answered%s.\n' "${C_BOLD}${C_YELLOW}" "$C_OFF" "$(value "$BASE_URL")" "$(probe_reason "$PROBE_RC")"
  echo "  The control plane reported healthy from inside its own network moments ago —"
  echo "  that is what the deploy gates on — so this is a fact about the route from HERE,"
  echo "  not about the deployment. A fleet behind a WireGuard mesh publishes nothing to"
  echo "  the outside, by design, and that is the default."
  echo "  To check it from a machine on the network:"
  echo "    ./logstotal deploy:status"
  echo "    SMOKE_URL=http://<reachable-address>:8000 ./logstotal deploy:smoke"
  if [ "$EXIT_UNVERIFIED" -eq 0 ]; then
    echo "  (exiting 0: nothing failed, nothing was measured. DEPLOY_SMOKE_STRICT=true to fail instead.)"
  fi
  exit "$EXIT_UNVERIFIED"
elif [ "$AUTH_WALL" = "yes" ]; then
  printf '%sSMOKE COULD NOT VERIFY:%s the deployment answered, but behind HTTP basic auth.\n' "${C_BOLD}${C_YELLOW}" "$C_OFF"
  echo "  TLS, DNS, the port and the proxy are all working — that is what a 401 proves."
  echo "  Nothing behind the proxy was measured, so none of the above is evidence of a fault."
  echo "  Re-run with the password to actually check it:"
  echo "    DEPLOY_BASIC_AUTH_PASSWORD='...' ./logstotal deploy:smoke"
  if [ "$EXIT_UNVERIFIED" -eq 0 ]; then
    echo "  (exiting 0: nothing failed, it was skipped. DEPLOY_SMOKE_STRICT=true to fail instead.)"
  fi
  exit "$EXIT_UNVERIFIED"
elif [ "$FAIL" -gt 0 ]; then
  printf '%sSMOKE FAILED:%s %s passed, %s failed.\n' "${C_BOLD}${C_RED}" "$C_OFF" "$(value "$PASS")" "$(value "$FAIL")"
  exit 1
else
  printf '%sSMOKE PASSED:%s all %s checks OK.\n' "${C_BOLD}${C_GREEN}" "$C_OFF" "$(value "$PASS")"
fi
