#!/bin/sh
set -e

# LOGSTOTAL_ENTRYPOINT_ENV_ONLY=1 — for a command run INSIDE an already-running container
# (`docker compose exec … /docker-entrypoint.sh <cmd>`): derive DATABASE_URL and
# SYNC_DATABASE_URL exactly as the container's own boot did, then drop to appuser and run
# <cmd>. Nothing else: no ownership fix (a recursive chown of uploads/ on every call), no
# socket group, no wait for PostgreSQL. It exists because the URLs below are exported to the
# process this script starts and to nothing else, so a plain `docker compose exec web …` sees
# only .env — and on a default install that means an empty ./logstotal.db inside the
# container rather than the real database. The script's own messages go to stderr in this
# mode, so <cmd>'s output stays parseable.
ENV_ONLY=false
if [ "${LOGSTOTAL_ENTRYPOINT_ENV_ONLY:-}" = "1" ]; then
    ENV_ONLY=true
    exec 3>&1 1>&2
fi

# LOGSTOTAL_ENTRYPOINT_DRYRUN=1 is a test-only seam: it skips the privileged
# prelude (chown / Docker-socket group setup) and the PostgreSQL reachability
# wait, prints the DATABASE_URL / SYNC_DATABASE_URL the script would export, and
# exits 0 before exec. Lets tests/test_docker_entrypoint.py pin the DB
# auto-detection without Docker or root. Never set this in a real deployment.

# Align with task validate-env: refuse placeholder or too-short SECRET_KEY
if [ -z "$SECRET_KEY" ] || [ "${#SECRET_KEY}" -lt 8 ]; then
    echo "ERROR: SECRET_KEY must be set to at least 8 characters (see .env.example)."
    exit 1
fi
case "$SECRET_KEY" in
    change-me-in-production | change-me-to-a-long-random-string-in-production)
        echo "ERROR: SECRET_KEY is still a placeholder — set a random value in .env."
        exit 1
        ;;
esac
case "$SECRET_KEY" in
    change-me*)
        echo "ERROR: SECRET_KEY must not start with change-me — set a random value in .env."
        exit 1
        ;;
esac

if [ "${LOGSTOTAL_ENTRYPOINT_DRYRUN:-}" != "1" ] && [ "$ENV_ONLY" = false ]; then
    # Fix ownership of bind-mounted directories so appuser can write to them.
    chown -R appuser:appgroup /app/uploads /data 2>/dev/null || true

    # If the Docker socket is mounted, match appuser's group to the socket's GID
    # so the worker can spawn sibling tool containers.
    if [ -S /var/run/docker.sock ]; then
        SOCK_GID=$(stat -c '%g' /var/run/docker.sock)
        if ! getent group "$SOCK_GID" >/dev/null 2>&1; then
            addgroup --system --gid "$SOCK_GID" dockersock
        fi
        SOCK_GROUP=$(getent group "$SOCK_GID" | cut -d: -f1)
        adduser appuser "$SOCK_GROUP" 2>/dev/null || true
    fi
fi

# profile_enabled NAME → success if NAME is an exact member of the
# comma-separated COMPOSE_PROFILES list (whitespace around entries ignored).
# POSIX-safe; same semantics as the `.split(",")`/`.strip()` parsing in
# app/system_checks.py and scripts/backup_lifecycle.py.
profile_enabled() {
    _want="$1"
    _rest="${COMPOSE_PROFILES:-},"
    while [ -n "$_rest" ]; do
        _item="${_rest%%,*}"
        _rest="${_rest#*,}"
        _item="${_item#"${_item%%[![:space:]]*}"}"
        _item="${_item%"${_item##*[![:space:]]}"}"
        [ "$_item" = "$_want" ] && return 0
    done
    return 1
}

# ── Database URL auto-detection ────────────────────────────────────────────
# Precedence:
# 1. Explicit DATABASE_URL (remote workers / external services) — always wins.
# 2. Bundled compose PostgreSQL — engaged only when POSTGRES_PASSWORD is set AND
#    ( the 'postgres' compose profile is enabled OR an external POSTGRES_HOST is
#    set ). COMPOSE_PROFILES is the reference for whether the BUNDLED postgres
#    service is in play: POSTGRES_PASSWORD alone is NOT enough. A password left
#    behind by `task gen-secrets -- --write` (which appends one when the key is
#    commented out) must not silently make the app wait 30 s for a `postgres`
#    host that compose never started — a crash loop.
# 3. SQLite fallback for single-node Docker.
#
# Older .env templates shipped DATABASE_URL=sqlite+aiosqlite:///./logstotal.db
# uncommented. When that exact template value is still present but PostgreSQL
# mode actually engages, the SQLite line is template residue, not a choice —
# prefer PostgreSQL loudly instead of silently running on (and backing up) the
# wrong database. A custom SYNC_DATABASE_URL marks the SQLite pair as deliberate
# and disables this override.
#
# Resolve the PostgreSQL gate once, shared by the residue override and the main
# precedence below.
pg_mode=false
pg_ignored_password=false
if [ -n "$POSTGRES_PASSWORD" ]; then
    if profile_enabled postgres || [ -n "${POSTGRES_HOST:-}" ]; then
        pg_mode=true
    else
        pg_ignored_password=true
    fi
fi

if [ "$DATABASE_URL" = "sqlite+aiosqlite:///./logstotal.db" ] && [ "$pg_mode" = true ]; then
    case "${SYNC_DATABASE_URL:-}" in
        "" | "sqlite:///./logstotal.db")
            echo "WARNING: DATABASE_URL is the legacy .env template default (relative SQLite) but PostgreSQL mode is enabled — using PostgreSQL. Comment out the DATABASE_URL line in .env to silence this warning."
            DATABASE_URL=""
            SYNC_DATABASE_URL=""
            ;;
    esac
fi
if [ -n "$DATABASE_URL" ]; then
    # SQLAlchemy relative SQLite URLs use three slashes after the scheme (e.g.
    # sqlite+aiosqlite:///./logstotal.db). They resolve under WORKDIR (/app),
    # which is not writable by appuser — only /data and /app/uploads are.
    # Rewrite to the bind-mounted /data path (same as unset DATABASE_URL).
    case "$DATABASE_URL" in
        sqlite+aiosqlite:///:memory:*) ;;
        sqlite+aiosqlite:////*) ;;
        sqlite+aiosqlite:///*)
            echo "Docker: SQLite DATABASE_URL is a relative path; using /data/logstotal.db (persisted, writable by appuser)."
            export DATABASE_URL="sqlite+aiosqlite:////data/logstotal.db"
            export SYNC_DATABASE_URL="sqlite:////data/logstotal.db"
            ;;
    esac
    if [ -z "$SYNC_DATABASE_URL" ]; then
        SYNC_DATABASE_URL="$(printf '%s' "$DATABASE_URL" | sed -e 's/+asyncpg//' -e 's/+aiosqlite//')"
        export SYNC_DATABASE_URL
    fi
elif [ "$pg_mode" = true ]; then
    PG_USER="${POSTGRES_USER:-logstotal}"
    PG_DB="${POSTGRES_DB:-logstotal}"
    PG_HOST="${POSTGRES_HOST:-postgres}"
    PG_PORT="${POSTGRES_PORT:-5432}"

    export DATABASE_URL="postgresql+asyncpg://${PG_USER}:${POSTGRES_PASSWORD}@${PG_HOST}:${PG_PORT}/${PG_DB}"
    export SYNC_DATABASE_URL="postgresql+psycopg2://${PG_USER}:${POSTGRES_PASSWORD}@${PG_HOST}:${PG_PORT}/${PG_DB}"

    if [ "${LOGSTOTAL_ENTRYPOINT_DRYRUN:-}" != "1" ] && [ "$ENV_ONLY" = false ]; then
        echo "PostgreSQL mode: waiting for ${PG_HOST}:${PG_PORT}..."
        tries=0
        until python3 -c "import socket; socket.create_connection(('${PG_HOST}', ${PG_PORT}), timeout=2)" 2>/dev/null; do
            tries=$((tries + 1))
            if [ "$tries" -ge 30 ]; then
                echo "ERROR: PostgreSQL not reachable after 30 s — aborting."
                exit 1
            fi
            sleep 1
        done
        echo "PostgreSQL is reachable."
    fi
else
    # Always use /data (bind-mounted) for SQLite in Docker so the DB persists.
    # Do not honor a local-dev sqlite DATABASE_URL from .env inside Docker unless
    # it was explicitly passed through as the runtime DATABASE_URL.
    if [ "$pg_ignored_password" = true ]; then
        echo "WARNING: POSTGRES_PASSWORD is set but the 'postgres' compose profile is not enabled and no external POSTGRES_HOST/DATABASE_URL is configured — using SQLite. Add 'postgres' to COMPOSE_PROFILES (or set POSTGRES_HOST / DATABASE_URL) to use PostgreSQL."
    fi
    export DATABASE_URL="sqlite+aiosqlite:////data/logstotal.db"
    export SYNC_DATABASE_URL="sqlite:////data/logstotal.db"
fi

if [ "${LOGSTOTAL_ENTRYPOINT_DRYRUN:-}" = "1" ]; then
    echo "DRYRUN: DATABASE_URL=${DATABASE_URL}"
    echo "DRYRUN: SYNC_DATABASE_URL=${SYNC_DATABASE_URL}"
    exit 0
fi

if [ "$ENV_ONLY" = true ]; then
    exec 1>&3 3>&-
fi
exec gosu appuser "$@"
