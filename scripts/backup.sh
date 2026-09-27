#!/usr/bin/env bash
# Backup / restore helper for LogsTotal (database + uploads).
#
# Thin action dispatcher for the backup:* and restore:* Taskfile tasks; shared
# fragments come from scripts/lib/common.sh.
#
# Usage:
#   bash scripts/backup.sh <action>
#
# Actions:
#   auto              Auto-detect backend -> dump -> verify that artifact -> receipt
#   sqlite            Timestamped SQLite snapshot into backups/
#   postgres          pg_dump (or the running compose postgres container) into backups/
#   uploads           tar.gz the uploads/ directory into backups/
#   verify            Check backup archive integrity (newest in backups/ by default)
#   prune             Delete backups/ files older than BACKUP_RETENTION_DAYS
#   restore-sqlite    Restore logstotal.db from a SQLite backup
#   restore-postgres  Restore PostgreSQL from a .sql.gz dump
#
# Environment consumed:
#   BACKUP_FILE            verify / restore-*: explicit backup path (else newest in backups/)
#   FORCE=yes              restore-*: override the refuse-while-app-running guard
#   BACKUP_RETENTION_DAYS  prune: age threshold in days (default 14; 0 = prune everything)
#   DATABASE_URL, POSTGRES_HOST/PORT/USER/DB/PASSWORD
#                          postgres / restore-postgres: connection info for host libpq tools
#
# No `set -o pipefail` — several actions rely on pipelines (e.g.
# `gunzip -c | head -c | grep -q`) where a SIGPIPE / non-zero upstream status
# must not abort the script. Assumes the repo root is the current working
# directory.

set -e

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# ── auto (was: task backup) ───────────────────────────────────────────────────

do_auto() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found."
  BACKEND=$(python3 scripts/backup_lifecycle.py backend)
  header "Backup ($(value "$BACKEND"))"
  if [ "$BACKEND" = "postgres" ]; then
    lt_task backup:postgres
  else
    lt_task backup:sqlite
  fi
  ARTIFACT=$(cat backups/.last-backup-path 2>/dev/null || true)
  if [ -z "$ARTIFACT" ] || [ ! -f "$ARTIFACT" ]; then
    die "backup subtask did not record an artifact path (backups/.last-backup-path)."
  fi
  info "verifying $(value "$ARTIFACT")"
  BACKUP_FILE="$ARTIFACT" lt_task backup:verify
  python3 scripts/backup_lifecycle.py receipt --backend "$BACKEND" --artifact "$ARTIFACT"
  banner_open
  kv "Database backup verified" "$ARTIFACT"
  printf '\n'
  printf '  A complete backup is three things:\n'
  printf '    1. database — done (receipt: backups/last-verified.json)\n'
  printf '    2. uploads  — ./logstotal backup:uploads   (S3/Garage deployments: back up the object store instead)\n'
  printf '    3. .env     — copy it somewhere safe (SECRET_KEY + DB credentials; included in no archive)\n'
  banner_close
}

# ── sqlite (was: task backup:sqlite) ──────────────────────────────────────────

do_sqlite() {
  DB=$(resolve_sqlite_target)
  info "SQLite target: $DB"
  [ -f "$DB" ] || die "no SQLite database found at the configured path: $DB"
  mkdir -p backups
  STAMP=$(backup_stamp)
  DEST="backups/logstotal-${STAMP}.db"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB" ".backup '${DEST}'"
  elif [ -f docker-compose.yml ] && docker compose config --services 2>/dev/null | grep -qx web; then
    info "host sqlite3 not found — backing up via the web container (Python sqlite3 module)"
    case "$DB" in
      "$(pwd)/data/"*) CONTAINER_DB="/data/${DB#"$(pwd)/data/"}" ;;
      "$(pwd)/uploads/"*) CONTAINER_DB="/app/uploads/${DB#"$(pwd)/uploads/"}" ;;
      *) die "Install sqlite3 on the host to back up this path: $DB" ;;
    esac
    CONTAINER_TMP="/data/.backup-${STAMP}.db"
    # scripts/ is in the image (Dockerfile does `COPY . .`). Kept in a file rather than an
    # inline heredoc so the copy direction is covered by tests — see the module docstring.
    #
    # The snapshot is **streamed out** rather than moved on the host. `docker-entrypoint.sh`
    # chowns the bind-mounted `data/` to the container's uid 999, so the snapshot lands
    # owned by 999 in a directory the host user cannot write — and `mv` needs to unlink
    # from that directory, not just read the file, so on a stock `task quickstart`
    # deployment it would fail `task backup` — the *mandatory* pre-upgrade step — with
    # "Permission denied". Redirecting to $DEST writes into `backups/`, which the
    # host user owns, so no bind-mount ownership is involved at all.
    #
    # One container run: snapshot, cat, clean up. The -shm/-wal siblings are removed too —
    # SQLite creates them beside the snapshot, and left there they litter `data/`.
    # `--entrypoint sh` bypasses docker-entrypoint.sh, which writes setup notices to
    # **stdout** — those bytes would land at the head of the streamed file and make it "not
    # a SQLite database". Nothing the entrypoint does is needed to read a file with python3.
    docker compose run --rm -T --entrypoint sh web -c \
      "python3 /app/scripts/sqlite_snapshot.py '$CONTAINER_DB' '$CONTAINER_TMP' >/dev/null && cat '$CONTAINER_TMP' && rm -f '$CONTAINER_TMP' '$CONTAINER_TMP'-shm '$CONTAINER_TMP'-wal" \
      > "$DEST"
  else
    die "sqlite3 not found on host and no Docker web service available for in-container backup.
Install sqlite3, or run this from a Docker deployment directory with compose configured."
  fi
  assert_sqlite_artifact_populated "$DEST" "$DB"
  record_backup_artifact "$DEST"
  SIZE=$(artifact_size "$DEST")
  ok "backup created: $(value "$DEST") (${SIZE}) from ${DB}"
}

# ── postgres (was: task backup:postgres) ──────────────────────────────────────

do_postgres() {
  mkdir -p backups
  STAMP=$(backup_stamp)
  DEST="backups/logstotal-pg-${STAMP}.sql.gz"

  resolve_pg_conn

  # Dump to a temp file first so a pg_dump failure cannot leave a
  # valid-looking (gzip of nothing) artifact behind.
  TMP_SQL=$(mktemp)
  trap 'rm -f "$TMP_SQL"' EXIT
  if configured_postgres_container; then
    # A running compose postgres service is the most reliable path: its port
    # is usually not published to the host, so host pg_dump could not connect
    # even when installed. A non-Compose install has no compose service and
    # falls through to host tools below.
    info "dumping via the running postgres container"
    if [ -n "$PG_URL" ]; then
      docker compose exec -T postgres pg_dump "$PG_URL" > "$TMP_SQL"
    else
      docker compose exec -T postgres pg_dump -U "$PG_USER" "$PG_DB" > "$TMP_SQL"
    fi
  elif command -v pg_dump >/dev/null 2>&1; then
    if [ -n "$PG_URL" ]; then
      pg_dump "$PG_URL" > "$TMP_SQL"
    elif [ -n "${POSTGRES_PASSWORD:-}" ]; then
      PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" "$PG_DB" > "$TMP_SQL"
    else
      die "Set DATABASE_URL or POSTGRES_PASSWORD to connect to PostgreSQL."
    fi
  else
    die "pg_dump not found on host and no running compose postgres service to dump through.
Install postgresql-client, or start the stack (./logstotal docker:up) and re-run."
  fi
  gzip -c "$TMP_SQL" > "$DEST"
  record_backup_artifact "$DEST"
  SIZE=$(artifact_size "$DEST")
  ok "backup created: $(value "$DEST") (${SIZE})"
}

# ── uploads (was: task backup:uploads) ────────────────────────────────────────

do_uploads() {
  if [ ! -d uploads ] || [ -z "$(ls -A uploads 2>/dev/null)" ]; then
    note "uploads/ is empty or missing — nothing to archive." \
      "S3/Garage deployments store files in the object store; back that up instead."
    exit 0
  fi
  mkdir -p backups
  STAMP=$(backup_stamp)
  DEST="backups/logstotal-uploads-${STAMP}.tar.gz"
  tar -czf "$DEST" uploads
  SIZE=$(artifact_size "$DEST")
  ok "backup created: $(value "$DEST") (${SIZE})"
}

# ── verify (was: task backup:verify) ──────────────────────────────────────────

do_verify() {
  BACKUP="${BACKUP_FILE:-}"
  if [ -z "$BACKUP" ]; then
    # shellcheck disable=SC2012  # verbatim from the Taskfile block; newest-by-mtime
    BACKUP=$(ls -t backups/*.db backups/*.sql.gz backups/*.tar.gz 2>/dev/null | head -1 || true)
  fi
  if [ -z "$BACKUP" ] || [ ! -f "$BACKUP" ]; then
    die "no backup files found in backups/ (looked for *.db, *.sql.gz, *.tar.gz).
Create one first: ./logstotal backup:sqlite | ./logstotal backup:postgres | ./logstotal backup:uploads"
  fi
  # PASS/FAIL through verdict.sh, but the exit stays this script's own: `task backup` runs
  # dump → verify → receipt and writes the receipt only if this returned 0, so a verdict
  # tally that forgives an unmeasured check would stamp "verified" on an artifact nobody
  # read. There is exactly one check here, so there is no tally to print either.
  info "Verifying $(value "$BACKUP")"
  case "$BACKUP" in
    *.sql.gz)
      if ! gzip -t "$BACKUP" 2>/dev/null; then
        v_fail "$BACKUP is not a valid gzip archive."
        exit 1
      fi
      if [ ! -s "$BACKUP" ]; then
        v_fail "$BACKUP is empty."
        exit 1
      fi
      if gunzip -c "$BACKUP" 2>/dev/null | head -c 4096 | grep -q "PostgreSQL database dump"; then
        v_pass "$BACKUP is a valid, non-empty PostgreSQL dump."
      else
        v_fail "$BACKUP does not contain the expected 'PostgreSQL database dump' header — likely not a pg_dump output."
        exit 1
      fi
      ;;
    *.tar.gz)
      if tar -tzf "$BACKUP" > /dev/null 2>&1; then
        v_pass "$BACKUP is a listable tar.gz archive."
      else
        v_fail "$BACKUP is not a valid tar.gz archive (tar -tzf failed)."
        exit 1
      fi
      ;;
    *.db)
      [ -s "$BACKUP" ] || die "$BACKUP is empty — refusing to verify or restore it."
      TMP=$(mktemp)
      trap 'rm -f "$TMP"' EXIT
      cp "$BACKUP" "$TMP"
      # `if VAR=$(...); then` (not a bare assignment) so a non-zero PRAGMA/python
      # exit doesn't abort the script before we get to print our own FAIL line —
      # this script runs under set -e.
      if PY_OUT=$(run_py -c "import sqlite3,sys; con=sqlite3.connect('$TMP'); objects=con.execute('SELECT count(*) FROM sqlite_master').fetchone()[0]; rows=con.execute('PRAGMA integrity_check;').fetchall(); con.close(); ok=objects>0 and len(rows)==1 and rows[0][0]=='ok'; print('ok' if ok else 'FAIL:' + ';'.join(r[0] for r in rows)); sys.exit(0 if ok else 1)" 2>&1); then PY_RC=0; else PY_RC=$?; fi
      if [ "$PY_RC" -eq 0 ] && [ "$PY_OUT" = "ok" ]; then
        v_pass "$BACKUP passed PRAGMA integrity_check (ok)."
      else
        # Only the last line (sqlite3 error / our own FAIL summary) — not a full traceback.
        v_fail "$BACKUP failed integrity check — $(printf '%s\n' "$PY_OUT" | tail -1)"
        exit 1
      fi
      ;;
    *)
      v_fail "cannot determine backup type for $BACKUP (expected a .db, .sql.gz, or .tar.gz file)."
      exit 1
      ;;
  esac
}

# ── prune (was: task backup:prune) ────────────────────────────────────────────

do_prune() {
  RETENTION="${BACKUP_RETENTION_DAYS-14}"
  # Under bash `[ garbage -le 0 ]` errors out ("integer expression expected"),
  # but the guard stays because an explicit, friendly error beats bash's own
  # failure mode — without it a typo'd BACKUP_RETENTION_DAYS could otherwise slip
  # into the prune-EVERYTHING branch. Digits only: explicitly empty or
  # whitespace-padded values fail here too (unset still defaults to 14).
  case "$RETENTION" in
    ''|*[!0-9]*)
      die "BACKUP_RETENTION_DAYS must be a non-negative integer (got '$RETENTION')."
      ;;
  esac
  if [ ! -d backups ] || [ -z "$(ls -A backups 2>/dev/null)" ]; then
    info "backups/ is empty or missing — nothing to prune."
    exit 0
  fi
  if [ "$RETENTION" -le 0 ]; then
    MATCHES=$(find backups -maxdepth 1 -type f)
  else
    MATCHES=$(find backups -maxdepth 1 -type f -mtime "+$((RETENTION - 1))")
  fi
  if [ -z "$MATCHES" ]; then
    info "No backup files older than ${RETENTION} day(s) in backups/ — nothing to prune."
    exit 0
  fi
  COUNT=$(echo "$MATCHES" | grep -c .)
  info "Found ${COUNT} file(s) older than ${RETENTION} day(s) in backups/:"
  echo "$MATCHES" | while IFS= read -r f; do
    echo "  Deleting: $f"
    rm -f "$f"
  done
  ok "Pruned ${COUNT} file(s)."
}

# ── restore-sqlite (was: task restore:sqlite) ─────────────────────────────────

do_restore_sqlite() {
  # Works with both invocation styles: task restore:sqlite BACKUP_FILE=x  and  BACKUP_FILE=x task restore:sqlite
  BACKUP="${BACKUP_FILE:-}"
  if [ -z "$BACKUP" ]; then
    # shellcheck disable=SC2012  # verbatim from the Taskfile block; newest-by-mtime
    BACKUP=$(ls -t backups/logstotal-*.db 2>/dev/null | head -1 || true)
  fi
  if [ -z "$BACKUP" ] || [ ! -f "$BACKUP" ]; then
    die "No backup file found. Set BACKUP_FILE or place backups in backups/"
  fi
  # Refuse to overwrite a live database unless explicitly forced.
  refuse_if_app_running "restore:sqlite"
  info "verifying backup before restore"
  BACKUP_FILE="$BACKUP" lt_task backup:verify
  DB=$(resolve_sqlite_target)
  mkdir -p "$(dirname "$DB")"
  cp "$BACKUP" "$DB"
  rm -f "${DB}-wal" "${DB}-shm"
  ok "Restored $(value "$DB") from: ${BACKUP}"
}

# ── restore-postgres (was: task restore:postgres) ─────────────────────────────

do_restore_postgres() {
  # Works with both invocation styles: task restore:postgres BACKUP_FILE=x  and  BACKUP_FILE=x task restore:postgres
  BACKUP="${BACKUP_FILE:-}"
  if [ -z "$BACKUP" ]; then
    # shellcheck disable=SC2012  # verbatim from the Taskfile block; newest-by-mtime
    BACKUP=$(ls -t backups/logstotal-pg-*.sql.gz 2>/dev/null | head -1 || true)
  fi
  if [ -z "$BACKUP" ] || [ ! -f "$BACKUP" ]; then
    die "No backup file found. Set BACKUP_FILE or place backups in backups/"
  fi
  # Refuse to overwrite a live database unless explicitly forced.
  refuse_if_app_running "restore:postgres"
  info "verifying backup before restore"
  BACKUP_FILE="$BACKUP" lt_task backup:verify

  resolve_pg_conn

  # psql exits 0 even when every statement in the dump failed, and the `gunzip |
  # psql` pipeline reports gunzip's status, not psql's — together those would let a
  # totally failed restore print "Restored from: ...". ON_ERROR_STOP makes psql
  # fail loudly, --single-transaction leaves the target untouched when it does,
  # and each pipeline runs in its own `set -o pipefail` subshell (the script as a
  # whole deliberately runs without pipefail — see the header).
  # pg_dump here is always a plain single-database dump (no -C, no \connect), so
  # wrapping it in one transaction is safe.
  PSQL_RESTORE_OPTS="-X -v ON_ERROR_STOP=1 --single-transaction"
  # shellcheck disable=SC2086  # PSQL_RESTORE_OPTS is a fixed flag list, intentionally split
  if configured_postgres_container; then
    # Same rationale as backup:postgres: the compose service's port is
    # usually not published to the host — the container is the reliable path.
    info "restoring via the running postgres container"
    if [ -n "$PG_URL" ]; then
      PG_RESTORE_ARGS=("$PG_URL")
    else
      PG_RESTORE_ARGS=(-U "$PG_USER" "$PG_DB")
    fi
    ( set -o pipefail; gunzip -c "$BACKUP" | docker compose exec -T postgres psql $PSQL_RESTORE_OPTS "${PG_RESTORE_ARGS[@]}" ) \
      || die "Restore failed — the database was left unchanged (--single-transaction rolled back)."
  elif command -v psql >/dev/null 2>&1; then
    if [ -n "$PG_URL" ]; then
      ( set -o pipefail; gunzip -c "$BACKUP" | psql $PSQL_RESTORE_OPTS "$PG_URL" ) \
        || die "Restore failed — the database was left unchanged (--single-transaction rolled back)."
    elif [ -n "${POSTGRES_PASSWORD:-}" ]; then
      ( set -o pipefail; gunzip -c "$BACKUP" | PGPASSWORD="$POSTGRES_PASSWORD" psql $PSQL_RESTORE_OPTS -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" "$PG_DB" ) \
        || die "Restore failed — the database was left unchanged (--single-transaction rolled back)."
    else
      die "Set DATABASE_URL or POSTGRES_PASSWORD to connect to PostgreSQL."
    fi
  else
    die "psql not found on host and no running compose postgres service to restore through.
Install postgresql-client, or start the postgres service and re-run."
  fi
  ok "Restored from: $(value "$BACKUP")"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
  case "${1:-}" in
    auto)             do_auto ;;
    sqlite)           do_sqlite ;;
    postgres)         do_postgres ;;
    uploads)          do_uploads ;;
    verify)           do_verify ;;
    prune)            do_prune ;;
    restore-sqlite)   do_restore_sqlite ;;
    restore-postgres) do_restore_postgres ;;
    *)
      echo "Usage: bash scripts/backup.sh {auto|sqlite|postgres|uploads|verify|prune|restore-sqlite|restore-postgres}" >&2
      exit 1
      ;;
  esac
}

main "$@"
