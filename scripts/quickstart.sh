#!/usr/bin/env bash
# Guided first Docker deploy for LogsTotal (quickstart).
#
# Everything a fresh Docker deployment needs, in order, idempotent (safe to
# re-run — never overwrites existing .env values):
#   1. verify docker + compose + daemon, and validate the HTTPS request if there is one
#   2. create .env from .env.example (only if missing)
#   3. ensure COOKIE_INSECURE is right for the chosen scheme (plain HTTP or TLS)
#   4. QUICKSTART_PROFILE=postgres (optional): activate COMPOSE_PROFILES=postgres
#      + POSTGRES_PASSWORD in .env so the next step fills the password
#   4b. DOMAIN set (optional): put Caddy in front via scripts/proxy_enable.py
#   5. generate all secrets incl. ADMIN_PASSWORD (gen-secrets --write)
#   5b. create the ./data, ./uploads and ./backups bind-mount dirs (Docker would
#       otherwise create them root-owned and `task backup` could not write)
#   6. docker compose build
#   7. in-container doctor preflight (aborts before starting on FAIL)
#   8. docker compose up -d
#   9. poll /health until ready
# Needs only Docker — no Python venv on the host.
#
# Usage:
#   bash scripts/quickstart.sh                              # SQLite, plain HTTP (default)
#   QUICKSTART_PROFILE=postgres bash scripts/quickstart.sh  # PostgreSQL instead
#   DOMAIN=logs.example.com ACME_EMAIL=you@example.com bash scripts/quickstart.sh   # + HTTPS
#   DOMAIN=logs.internal QUICKSTART_TLS=internal bash scripts/quickstart.sh         # + internal CA
#
# Environment consumed:
#   QUICKSTART_PROFILE   unset/empty (SQLite, default) or 'postgres'.
#   DOMAIN               set it to put Caddy in front; unset means plain HTTP on :8000.
#   QUICKSTART_TLS       acme (default) | internal | custom | off. DOMAIN only.
#   ACME_EMAIL           required when the mode is acme.
#
# `set -e`, no pipefail.
# Assumes the repo root is the current working directory.

set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# ── 1. Docker readiness, and the HTTPS request ──
case "${QUICKSTART_PROFILE:-}" in
  ''|postgres) ;;
  *)
    die "unsupported QUICKSTART_PROFILE='${QUICKSTART_PROFILE}' — supported values: unset/empty (SQLite, default), 'postgres'."
    ;;
esac

# Validated HERE, not at step 4b. `set -e` is on, and proxy_enable.py refuses acme
# without an email — reaching that at step 4b aborts having already created and
# edited .env, which reads as "it half-ran and then told me about a typo".
WANT_PROXY=no
PROXY_MODE="${QUICKSTART_TLS:-acme}"
if [ -n "${DOMAIN:-}" ]; then
  WANT_PROXY=yes
  case "$PROXY_MODE" in
    acme|internal|custom|off) ;;
    *)
      die "unsupported QUICKSTART_TLS='${QUICKSTART_TLS}' — supported values: acme (default), internal, custom, off."
      ;;
  esac
  if [ "$PROXY_MODE" = "acme" ] && [ -z "${ACME_EMAIL:-}" ]; then
    die "ACME_EMAIL is required for PROXY_TLS=acme — Let's Encrypt needs a contact address.
       Either: DOMAIN=${DOMAIN} ACME_EMAIL=you@example.com ./logstotal quickstart
       Or a mode that needs no CA: DOMAIN=${DOMAIN} QUICKSTART_TLS=internal ./logstotal quickstart"
  fi
elif [ -n "${ACME_EMAIL:-}" ]; then
  die "ACME_EMAIL is set but DOMAIN is not, so no proxy would be configured and the
       address would be silently ignored. Set DOMAIN too, or unset ACME_EMAIL."
fi
command -v docker >/dev/null 2>&1 || die "docker not found — install it: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "docker compose v2 not available — update Docker."
docker info >/dev/null 2>&1 || die "Docker daemon not running — start Docker, then re-run: ./logstotal quickstart"
ok "Docker ready"

# ── 2. .env from .env.example (only if missing) ──
if [ ! -f .env ]; then
  cp .env.example .env
  ok "Created .env from $(value .env.example)"
else
  ok ".env already exists (kept as-is)"
fi

# ── 3. COOKIE_INSECURE ──
# Skipped entirely when a proxy was asked for: step 4b writes that value together with
# the ENABLE_HSTS that matches the TLS mode. Writing true here first would leave a
# comment above the key saying the opposite of the value it ends up holding.
if [ "$WANT_PROXY" = "yes" ]; then
  ok "COOKIE_INSECURE left to the proxy step (TLS mode: $(value "$PROXY_MODE"))"
elif grep -qE '^COOKIE_INSECURE=' .env; then
  ok "COOKIE_INSECURE already set ($(grep -E '^COOKIE_INSECURE=' .env | head -1)) — respecting your choice"
else
  printf '\n# Set by ./logstotal quickstart: plain HTTP on :8000 needs non-Secure cookies or login fails.\n# Set back to false when you move behind HTTPS (COMPOSE_PROFILES=proxy).\nCOOKIE_INSECURE=true\n' >> .env
  ok "Set COOKIE_INSECURE=true (quickstart serves plain HTTP — revert when you add HTTPS)"
fi

# ── 4. QUICKSTART_PROFILE=postgres: activate COMPOSE_PROFILES + POSTGRES_PASSWORD ──
if [ "${QUICKSTART_PROFILE:-}" = "postgres" ]; then
  info "QUICKSTART_PROFILE=$(value postgres) — activating COMPOSE_PROFILES + POSTGRES_PASSWORD in .env"
  # COMPOSE_PROFILES is not a secret gen-secrets knows about, so it has to be set here.
  # POSTGRES_PASSWORD gen-secrets would append by itself (write_env appends a key that is
  # absent or commented out) — activating it here keeps both .env edits in one place.
  if grep -qE '^COMPOSE_PROFILES=.*postgres' .env; then
    ok "COMPOSE_PROFILES already includes postgres"
  elif grep -qE '^COMPOSE_PROFILES=' .env; then
    CURRENT=$(grep -E '^COMPOSE_PROFILES=' .env | head -1 | cut -d'=' -f2-)
    NEW_VALUE="${CURRENT:+${CURRENT},}postgres"
    TMP=$(mktemp)
    awk -v newval="COMPOSE_PROFILES=${NEW_VALUE}" '/^COMPOSE_PROFILES=/{print newval; next} {print}' .env > "$TMP" && mv "$TMP" .env
    ok "Set COMPOSE_PROFILES=${NEW_VALUE}"
  else
    printf '\nCOMPOSE_PROFILES=postgres\n' >> .env
    ok "Activated COMPOSE_PROFILES=postgres"
  fi
  if grep -qE '^POSTGRES_PASSWORD=' .env; then
    ok "POSTGRES_PASSWORD already active — gen-secrets will fill it next if still empty/placeholder"
  else
    printf '\nPOSTGRES_PASSWORD=\n' >> .env
    ok "Activated empty POSTGRES_PASSWORD= (gen-secrets will fill it next)"
  fi
fi

# ── 4b. HTTPS: put Caddy in front ──
# Must run AFTER .env exists (proxy_enable.py refuses a missing file) and BEFORE the
# unset below, which blanks DOMAIN/ACME_EMAIL out of this shell.
PROXY_DOMAIN="${DOMAIN:-}"   # captured before the unset below blanks DOMAIN
if [ "$WANT_PROXY" = "yes" ]; then
  info "DOMAIN=$(value "$DOMAIN") — putting Caddy in front (PROXY_TLS=$(value "$PROXY_MODE"))"
  PROXY_ARGS=(--domain "$DOMAIN" --tls "$PROXY_MODE")
  [ -n "${ACME_EMAIL:-}" ] && PROXY_ARGS+=(--acme-email "$ACME_EMAIL")
  run_py scripts/proxy_enable.py "${PROXY_ARGS[@]}"
fi

# ── 5. Generate secrets (fills only empty/placeholder keys) ──
info "Generating secrets (only fills empty/placeholder keys)"
run_py scripts/gen_secrets.py --write

# The compose steps below must interpolate .env from the FILE, not from this
# process's stale environment: go-task's dotenv preloaded the OLD .env into the
# environment at startup, and shell env takes precedence over the .env file in
# compose interpolation — without the unset, e.g. Redis would start with the
# stale (empty) password while the app uses the freshly generated one.
# COMPOSE_PROFILES is included for the same reason, since QUICKSTART_PROFILE=postgres
# may have just activated it in .env; DOMAIN/ACME_EMAIL/PROXY_TLS for the same reason
# after step 4b wrote them. One unset, before the first compose invocation, persists for
# the rest of the script.
unset SECRET_KEY ADMIN_PASSWORD POSTGRES_PASSWORD REDIS_PASSWORD S3_ACCESS_KEY S3_SECRET_KEY GARAGE_RPC_SECRET GARAGE_ADMIN_TOKEN COOKIE_INSECURE COMPOSE_PROFILES DOMAIN ACME_EMAIL PROXY_TLS

# ── 5b. Bind-mount directories ──
# docker-compose.yml mounts ./data, ./uploads, ./backups and ./certs. A fresh clone has none of
# them, so Docker creates them itself — owned by root — and `task backup` then cannot
# write into backups/. Creating them here means they belong to the operator.
mkdir -p data uploads backups certs

# ── 6. docker compose build ──
info "docker compose build"
docker compose build

# ── 7. Preflight (doctor inside the web container) ──
info "Preflight (doctor inside the web container)"
docker compose run --rm web python3 scripts/doctor.py --in-container

# ── 8. docker compose up -d ──
info "docker compose up -d"
docker compose up -d

# ── 9. Poll /health until ready ──
PORT=$(grep -E '^WEB_PORT=' .env | head -1 | cut -d'=' -f2- ); PORT="${PORT:-8000}"
# WEB_PORT may be a compose mapping like 127.0.0.1:8000:8000 — take the host port.
case "$PORT" in *:*) PORT=$(echo "$PORT" | awk -F: '{print $(NF-1)}');; esac
URL="http://localhost:${PORT}"
info "Waiting for $(value "${URL}/health") ..."
# shellcheck disable=SC2034  # fixed-count retry timer — the loop index is deliberately unused (verbatim from the Taskfile block)
for i in $(seq 1 30); do
  if curl -fsS "${URL}/health" >/dev/null 2>&1; then
    ADMIN_EMAIL_VAL=$(grep -E '^ADMIN_EMAIL=' .env | head -1 | cut -d'=' -f2-)
    banner_open
    if [ "$WANT_PROXY" = "yes" ]; then
      # The poll above reached the APP on loopback, not Caddy. Say so: with acme,
      # Caddy may still be negotiating with Let's Encrypt, and a bare "it is up"
      # next to a URL that does not load yet is the wrong thing to copy.
      kv "LogsTotal is up" "https://${PROXY_DOMAIN}"
      printf '    (the app answered on 127.0.0.1:%s; if that URL does not load yet,\n' "$PORT"
      printf '     Caddy is still getting a certificate — watch it with: ./logstotal docker:logs:proxy)\n'
    else
      kv "LogsTotal is up" "$URL"
    fi
    kv "Admin login" "${ADMIN_EMAIL_VAL:-admin@example.com}"
    kv "Password" "printed above by gen-secrets — or: ./logstotal show-admin-password"
    printf '\n'
    printf '  Next steps:\n'
    printf '    ./logstotal doctor:docker      # full post-deploy check\n'
    printf '    ./logstotal docker:logs        # follow logs\n'
    if [ "$WANT_PROXY" = "yes" ]; then
      printf '    https://%s/admin   # dashboard + system status\n' "$PROXY_DOMAIN"
    else
      printf '    %s/admin            # dashboard + system status\n' "$URL"
    fi
    printf '\n'
    printf '  Going further:\n'
    if [ "$WANT_PROXY" != "yes" ]; then
      printf '    HTTPS:        DOMAIN=... ACME_EMAIL=... ./logstotal proxy:enable\n'
    fi
    printf '    PostgreSQL:   re-run as QUICKSTART_PROFILE=postgres ./logstotal quickstart (see docs/install/single-host.md#with-postgresql)\n'
    printf '    Worker sizing: ./logstotal recommend-scaling\n'
    printf '    First day:    docs/runbooks/health-and-logs.md#first-day-after-deploy\n'
    banner_close
    exit 0
  fi
  sleep 2
done
die "${URL}/health not responding after 60s — check: ./logstotal docker:logs"
