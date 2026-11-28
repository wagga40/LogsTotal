#!/bin/sh
# postgres-migrate.sh — the one-time move of a PostgreSQL 16 cluster onto PostgreSQL 19.
#
# Runs as the `postgres-migrate` one-shot service, in the postgres:16-alpine image, before
# the `postgres` (19) service may start. It never writes to the old cluster's files beyond
# what a normal start/stop of that cluster writes, so the old volume stays a working
# PostgreSQL 16 cluster: the rollback path.
#
# Volumes, as mounted by docker-compose.yml:
#   /old  ← postgres_data       the PostgreSQL 16 cluster (PGDATA itself)
#   /new  ← postgres19_data     the PostgreSQL 19 volume root; its PGDATA is /new/19/docker
#   /out  ← postgres_migration  mounted by `postgres` at /docker-entrypoint-initdb.d
#
# The postgres image runs /docker-entrypoint-initdb.d/* exactly once: when its data
# directory is empty. That is the migration moment, so this script's whole job is to put
# a verified dump and the script that loads it there, or to leave the directory empty.
#
# States, decided from the volumes alone, so every `docker compose up` re-runs this safely:
#   new cluster present, no pending marker  → migrated (or a fresh 19 install): clean up, exit 0
#   new cluster present, pending marker     → an earlier restore did not finish, or a
#                                             rollback superseded it: discard the new cluster
#                                             and migrate again
#   no old cluster                          → fresh install, nothing to migrate: exit 0
#   otherwise                               → dump the old cluster and publish it
set -eu

OLD=/old
NEW_PGDATA=/new/19/docker
PENDING=/new/.logstotal-restore-pending
OUT=/out
# NOT *.sql.gz: the image runs every *.sql, *.sql.gz, *.sh … in /docker-entrypoint-initdb.d
# itself, so a dump named that way was restored a second time after the loader had already
# restored it, failed on "type already exists", and crashed the first start. The image
# ignores this extension; only the loader reads it.
DUMP="$OUT/logstotal-pg16.dump.gz"
LOADER="$OUT/10-logstotal-restore.sh"

log() { printf 'postgres-migrate: %s\n' "$*"; }
die() { printf 'postgres-migrate: ERROR: %s\n' "$*" >&2; exit 1; }

: "${POSTGRES_USER:=logstotal}"
: "${POSTGRES_DB:=logstotal}"

# The 19 image runs its init scripts as `postgres` (uid 70 in both alpine images), and the
# loader below must be able to delete the pending marker from the volume root. When this
# service is first to mount postgres19_data, the volume root is created root-owned.
chown postgres:postgres /new

if [ -s "$NEW_PGDATA/PG_VERSION" ] && [ ! -e "$PENDING" ]; then
  if [ -e "$DUMP" ] || [ -e "$LOADER" ]; then
    rm -f "$DUMP" "$LOADER"
    log "PostgreSQL 19 cluster is in place; removed the migration dump"
  fi
  exit 0
fi

if [ -s "$NEW_PGDATA/PG_VERSION" ] && [ -e "$PENDING" ]; then
  # Set by an unfinished restore, or by upgrade:rollback (scripts/lib/service_data.sh),
  # which leaves this cluster behind as no longer current. Discarded only when there is a
  # 16 cluster to move again: without one, the 19 cluster is the only copy of the database,
  # whatever the marker says. postgres refuses to start while the marker stands, so this
  # stops the stack with the reason in the log instead of starting it empty.
  [ -s "$OLD/PG_VERSION" ] || die "the PostgreSQL 19 cluster is marked not current ($PENDING), but postgres_data holds no PostgreSQL 16 cluster to move again; refusing to discard the only copy of the database. If the 19 cluster is the one to keep, delete that marker from the postgres19_data volume."
  log "the PostgreSQL 19 cluster is not current (an unfinished restore, or a rollback since); discarding it and moving the PostgreSQL 16 data again"
  rm -rf "$NEW_PGDATA"
fi

if [ ! -s "$OLD/PG_VERSION" ]; then
  log "no PostgreSQL 16 cluster to migrate (fresh install)"
  rm -f "$DUMP" "$LOADER" "$PENDING"
  exit 0
fi

old_major=$(cat "$OLD/PG_VERSION")
[ "$old_major" = 16 ] || die "the old volume holds a PostgreSQL $old_major cluster; this migration reads 16 only"

log "migrating the PostgreSQL 16 cluster to PostgreSQL 19 (one time; the old volume is left untouched)"
tmp="$OUT/.logstotal-pg16.dump.gz.partial"
rm -f "$tmp"

if PGPASSWORD="${POSTGRES_PASSWORD:-}" pg_isready -q -h postgres -p 5432 -U "$POSTGRES_USER" -d "$POSTGRES_DB" 2>/dev/null; then
  # The normal single-host upgrade: compose starts this service before it replaces the old
  # `postgres` container, so the old server is still up. Dump through it — never start a
  # second server on a data directory another container is serving.
  clients=$(PGPASSWORD="${POSTGRES_PASSWORD:-}" psql -h postgres -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc \
    "select count(*) from pg_stat_activity where datname = current_database() and pid <> pg_backend_pid() and backend_type = 'client backend'" 2>/dev/null || echo 0)
  if [ "${clients:-0}" != 0 ]; then
    die "$clients other connection(s) to the old database are open. Rows they write after the dump would be lost.
       Stop the app first:  docker compose stop web worker   (./logstotal upgrade does this for you)"
  fi
  log "dumping through the running PostgreSQL 16 server"
  # --no-owner/--no-acl: the 19 cluster's POSTGRES_USER restores and owns everything, as
  # it did in 16. A plain single-database dump — the format backup:postgres writes.
  PGPASSWORD="${POSTGRES_PASSWORD:-}" pg_dump --no-owner --no-acl -h postgres -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip -c > "$tmp"
else
  # The old server is down (a fleet redeploy runs `docker compose down` first). Start it
  # privately: no TCP listener, socket in /tmp, so nothing else can reach it while it runs.
  #
  # A server shutting down cleanly removes postmaster.pid last, so give a container compose
  # is still stopping time to finish before deciding. PostgreSQL's own guard against a
  # second postmaster cannot see across containers (separate PID and IPC namespaces).
  for _ in $(seq 1 60); do
    [ -e "$OLD/postmaster.pid" ] || break
    sleep 1
  done
  if [ -e "$OLD/postmaster.pid" ]; then
    log "old cluster was not shut down cleanly; PostgreSQL will recover it on start"
  fi
  mkdir -p /tmp/pgmig && chown postgres:postgres /tmp/pgmig
  su-exec postgres pg_ctl -D "$OLD" -w -t 120 -l /tmp/pgmig/server.log \
    -o "-c listen_addresses='' -c unix_socket_directories=/tmp/pgmig" start \
    || { cat /tmp/pgmig/server.log >&2; die "could not start the PostgreSQL 16 cluster"; }
  trap 'su-exec postgres pg_ctl -D "$OLD" -m fast -w stop >/dev/null 2>&1 || true' EXIT
  log "dumping through a private PostgreSQL 16 server"
  su-exec postgres pg_dump --no-owner --no-acl -h /tmp/pgmig -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip -c > "$tmp"
  su-exec postgres pg_ctl -D "$OLD" -m fast -w stop >/dev/null
  trap - EXIT
fi

# pg_dump writes this line last; a dump cut short by a crash or a full disk does not have it.
gunzip -c "$tmp" | tail -n 5 | grep -q -- '-- PostgreSQL database dump complete' \
  || die "the dump is incomplete; nothing was published and the old cluster is unchanged"

cat > "$LOADER" <<'EOF'
# Written by postgres-migrate.sh. The postgres image SOURCES this once, during the first
# initialisation of the PostgreSQL 19 data directory, with its temporary server running.
DUMP=/docker-entrypoint-initdb.d/logstotal-pg16.dump.gz
PENDING=/var/lib/postgresql/.logstotal-restore-pending
if [ -f "$DUMP" ]; then
  echo "logstotal: restoring the PostgreSQL 16 database into PostgreSQL 19"
  if gunzip -c "$DUMP" | docker_process_sql --single-transaction; then
    rm -f "$PENDING"
    echo "logstotal: restore complete"
  else
    # Leave nothing a restart could mistake for a finished cluster: the marker stays, so
    # the next `docker compose up` discards this directory and migrates again.
    echo "logstotal: restore FAILED; the PostgreSQL 16 volume is unchanged" >&2
    exit 1
  fi
fi
EOF

mv "$tmp" "$DUMP"
touch "$PENDING"
log "dump published ($(du -h "$DUMP" | cut -f1) compressed); PostgreSQL 19 will load it on first start"
