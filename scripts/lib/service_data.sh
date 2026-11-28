# shellcheck shell=bash
# service_data.sh — rolling back across a one-way change to a bundled service's data.
#
# A code rollback restores files. Three services this project bundles keep data that a
# newer release changed in a way the older one cannot read back:
#
#   postgres  1.4 moved the bundled database from PostgreSQL 16 (postgres_data) to 19
#             (postgres19_data). The 16 volume is left as the upgrade found it.
#   redis     Redis 8 writes an RDB file Redis 7 refuses to load, so the restored stack's
#             Redis would crash-loop on it.
#   garage    Garage 2.5 migrated its metadata one way; garage-entrypoint.sh kept a copy of
#             the metadata as the older release left it (meta/.pre-garage-2.5).
#
# Used by scripts/upgrade.sh (single host) and, on the control plane over ssh,
# scripts/deploy-multiserver.sh (fleet). Self-contained on purpose — the fleet sources it
# in a remote shell that has not sourced common.sh — so it prints with plain echo.

# service_data_crossings SNAPSHOT [CURRENT] — one word per boundary a rollback from the
# tree in CURRENT (default .) to the one in SNAPSHOT would cross: postgres, redis, garage.
# Read from the files each tree would run, plus which services this host's compose actually
# starts, so an install that never ran the bundled PostgreSQL or Garage is not told about
# them.
service_data_crossings() {
  local snap="$1" cur="${2:-.}" active
  active=$(cd "$cur" 2>/dev/null && docker compose config --services 2>/dev/null) || active=""

  if grep -q 'postgres19_data:/var/lib/postgresql' "$cur/docker-compose.yml" 2>/dev/null \
    && ! grep -q 'postgres19_data' "$snap/docker-compose.yml" 2>/dev/null \
    && printf '%s\n' "$active" | grep -qx postgres; then
    echo postgres
  fi

  local cur_redis snap_redis
  cur_redis=$(_service_data_redis_major "$cur/docker-compose.yml")
  snap_redis=$(_service_data_redis_major "$snap/docker-compose.yml")
  if [ -n "$cur_redis" ] && [ -n "$snap_redis" ] && [ "$snap_redis" -lt "$cur_redis" ]; then
    echo redis
  fi

  if _service_data_garage_at_least_2_5 "$cur/Dockerfile.garage" \
    && ! _service_data_garage_at_least_2_5 "$snap/Dockerfile.garage" \
    && printf '%s\n' "$active" | grep -qx garage; then
    echo garage
  fi
}

# service_data_pg16_cluster — does this project's PostgreSQL 16 volume (postgres_data) still
# hold a cluster? Asked of its contents, never its name: postgres-migrate mounts the volume, so
# Compose creates it on every `up` — empty on a fresh 1.4 install, and empty again after an
# operator removed it once they were done with rollback. Read through postgres-migrate, the one
# service that mounts it (at /old); run from a 1.4+ tree. stdin is detached because `compose
# run` attaches it by default and would swallow the rest of a `bash -s` heredoc, or the
# terminal's input.
service_data_pg16_cluster() {
  docker compose run --rm --no-deps -T --entrypoint sh postgres-migrate \
    -c 'test -s /old/PG_VERSION' </dev/null >/dev/null 2>&1
}

# service_data_pg16_volume — the PostgreSQL 16 volume's name while it still holds a cluster,
# for doctor's leftover-volume notice; nothing otherwise. Nothing, too, on an install whose
# compose does not run the bundled PostgreSQL: asking there would create the volumes.
service_data_pg16_volume() {
  local project
  docker compose config --services 2>/dev/null | grep -qx postgres-migrate || return 0
  service_data_pg16_cluster || return 0
  project=$(docker compose config 2>/dev/null | sed -n 's/^name: *//p' | head -1)
  printf '%s_postgres_data\n' "${project:-logstotal}"
}

# service_data_pg16_gone — why a rollback across the move to PostgreSQL 19 is refused once
# the 16 cluster is gone, whatever ROLLBACK_DATA says: there is nothing to go back to.
# PostgreSQL 16 would initialise an empty cluster in the empty volume, the older release would
# boot on an empty database, and the next upgrade would discard the 19 cluster — the only
# copy — to move that empty one across.
service_data_pg16_gone() {
  echo "  - PostgreSQL: postgres_data no longer holds the PostgreSQL 16 cluster this release moved"
  echo "    off (it was removed after the upgrade), so the older release would start on an empty"
  echo "    database. ROLLBACK_DATA=previous cannot accept that: stay on this release, or rebuild"
  echo "    the older one from a database backup taken before the upgrade."
}

_service_data_redis_major() {
  sed -n 's/.*[^a-z/]redis:\([0-9][0-9]*\)[.-].*/\1/p' "$1" 2>/dev/null | head -1
}

_service_data_garage_at_least_2_5() {
  local v major minor
  v=$(sed -n 's/.*dxflrs\/garage:v\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' "$1" 2>/dev/null | head -1)
  [ -n "$v" ] || return 1
  major=${v%%.*}
  minor=${v#*.}
  [ "$major" -gt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -ge 5 ]; }
}

# service_data_explain CROSSING... — what accepting each crossing costs, for the refusal.
service_data_explain() {
  local c
  for c in "$@"; do
    case "$c" in
      postgres)
        echo "  - PostgreSQL: the older release runs PostgreSQL 16 on postgres_data, which holds the"
        echo "    database as it was when this release first started. Everything written since stays"
        echo "    in postgres19_data, unused, and the next upgrade replaces it with a fresh copy of"
        echo "    postgres_data." ;;
      redis)
        echo "  - Redis: Redis 7 cannot read Redis 8's data file. It is set aside (dump.rdb.from-redis-8)"
        echo "    and Redis starts empty: queued jobs are dropped and fail once their queue window"
        echo "    (HUEY_QUEUE_EXPIRY) passes; caches rebuild themselves." ;;
      garage)
        echo "  - Garage: its metadata goes back to the copy taken before Garage 2.5 first started."
        echo "    Objects stored since then are no longer listed — uploads and tool outputs of jobs"
        echo "    run after the upgrade — though their bytes stay in garage_data." ;;
    esac
  done
}

# service_data_revert CROSSING... — make the bundled services' data readable by the older
# release. Run from the CURRENT tree, before it is restored over: these use its compose
# file, whose services still name the volumes. Stops what it touches; the rollback's own
# `docker compose up -d` starts everything again on the restored release.
service_data_revert() {
  local c
  # Nothing may write to the data being set back while it is set back.
  docker compose stop web worker >/dev/null 2>&1 || true
  for c in "$@"; do
    case "$c" in
      postgres)
        echo "service data: marking the PostgreSQL 19 cluster superseded (the next upgrade moves postgres_data again)"
        # The marker postgres-migrate.sh reads as "this 19 cluster is not current": the next
        # upgrade discards it and moves postgres_data across afresh, instead of reviving
        # rows the rollback has just abandoned.
        docker compose stop postgres >/dev/null 2>&1 || true
        docker compose run --rm --no-deps -T --entrypoint sh postgres-migrate \
          -c 'if [ -s /new/19/docker/PG_VERSION ]; then touch /new/.logstotal-restore-pending; fi' ;;
      redis)
        echo "service data: setting Redis 8's data file aside (dump.rdb.from-redis-8)"
        # Stopped first: Redis writes its RDB on shutdown, which would put a fresh Redis 8
        # file back after the move.
        docker compose stop redis >/dev/null 2>&1 || true
        docker compose run --rm --no-deps -T --entrypoint sh redis \
          -c 'if [ -e /data/dump.rdb ]; then mv -f /data/dump.rdb /data/dump.rdb.from-redis-8; fi' ;;
      garage)
        echo "service data: restoring Garage's pre-2.5 metadata"
        docker compose stop garage >/dev/null 2>&1 || true
        # The newer metadata is moved aside, not deleted.
        docker compose run --rm --no-deps -T --entrypoint sh garage -c '
          set -e
          cd /var/lib/garage/meta
          [ -d .pre-garage-2.5 ] || { echo "no pre-2.5 copy to restore" >&2; exit 1; }
          rm -rf .from-garage-2.5
          mkdir .from-garage-2.5
          for e in *; do [ -e "$e" ] && mv "$e" .from-garage-2.5/; done
          cp -a .pre-garage-2.5/. .
          rm -rf .pre-garage-2.5 .logstotal-garage-version' ;;
    esac
  done
}
