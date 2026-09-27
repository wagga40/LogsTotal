# Backup and restore

How to take, verify, schedule and restore backups of a LogsTotal instance.

Commands run on the deployment host (the control plane, for a fleet), from the install directory.

## Backups & restore

```bash
./logstotal backup              # detect the database → dump → verify that file → write a receipt
./logstotal backup:sqlite       # → backups/logstotal-YYYYMMDD-HHMMSS.db
./logstotal backup:postgres     # → backups/logstotal-pg-YYYYMMDD-HHMMSS.sql.gz
./logstotal backup:uploads      # → backups/logstotal-uploads-YYYYMMDD-HHMMSS.tar.gz (the stored log files)
./logstotal backup:verify       # check the newest backup, or BACKUP_FILE=...
./logstotal backup:prune        # delete backups older than BACKUP_RETENTION_DAYS (default 14)
./logstotal restore:sqlite      # restore the newest SQLite backup, or BACKUP_FILE=...
./logstotal restore:postgres    # restore the newest PostgreSQL dump, or BACKUP_FILE=...
```

`./logstotal backup` is the one to use. It works out which database the instance really uses, the same way the Docker entrypoint does: an explicit `DATABASE_URL` wins; otherwise PostgreSQL is used only when `POSTGRES_PASSWORD` is set **and** either `postgres` is in `COMPOSE_PROFILES` or `POSTGRES_HOST` names an external server. So a leftover password never makes it dump the wrong database. It then dumps, verifies the file it just wrote, and records a receipt in `backups/last-verified.json` (database type, file name, UTC time and app version — no credentials). A failed dump or a failed verification fails the command. `./logstotal upgrade` runs it before every upgrade.

### What a complete backup contains

1. **The database** — `./logstotal backup`: jobs, findings, entities, users.
2. **The uploaded files** — `./logstotal backup:uploads` with local storage. With S3 or Garage, back up the bucket or the Garage data volume instead.
3. **`.env`** — it holds `SECRET_KEY` (losing it signs everyone out and, unless `ENRICHMENT_ENCRYPTION_KEY` is set, makes the stored enrichment and AI provider tokens unreadable) and the database credentials. No release archive or backup task includes it: keep a copy in your secrets manager.

### Verifying a backup

`./logstotal backup:verify` checks a file by its name:

- `.db` (SQLite) — copies it to a temporary file, never the live database, and runs `PRAGMA integrity_check`. It passes when the result is `ok` and the schema is not empty.
- `.sql.gz` (PostgreSQL) — the gzip data is intact, not empty, and starts with the `PostgreSQL database dump` header.
- `.tar.gz` (uploads) — `tar` can list the whole archive.

It checks the newest file in `backups/` unless you pass `BACKUP_FILE=path/to/file`, and exits non-zero on any failure. This checks the file, not that the data can be recovered — see [Rehearse a restore](#rehearse-a-restore).

## Schedule backups

| Deployment | How often | Notes |
|------------|-----------|-------|
| Single host | Daily | A SQLite backup is safe while the app runs; run a PostgreSQL dump when load is low |
| Fleet | Daily, on the control plane | Back up PostgreSQL and the Garage data volume separately |

A crontab entry for a daily verified backup, followed by removing backups older than 14 days:

```cron
0 3 * * * cd /opt/logstotal && ./logstotal backup && ./logstotal --yes backup:prune
```

- `--yes` answers the confirmation `backup:prune` asks for. To keep backups for longer, set the variable in front of the command: `BACKUP_RETENTION_DAYS=30 ./logstotal --yes backup:prune`. `BACKUP_RETENTION_DAYS=0` deletes every file in `backups/`.
- Pruning deletes only files directly under `backups/`, never the release snapshots in `backups/releases/`.
- Cron runs with a minimal `PATH`. `./logstotal` brings its own copy of Task, but `docker` — and `pg_dump`/`psql` for an external PostgreSQL server — must be on the `PATH` cron uses; set `PATH=` at the top of the crontab if they are elsewhere.
- Send the output somewhere you will read it, and alert on a non-zero exit.
- This covers the database only. Schedule the uploads (or object store) and a copy of `.env` separately.

## Select the correct target

`DATABASE_URL` selects the database. For SQLite, `BACKUP_CONTEXT=docker` or `BACKUP_CONTEXT=host` says whether the path is the Docker one or a host one; set it whenever both a development database and a Docker one exist on the machine. The Docker database `/data/logstotal.db` is `./data/logstotal.db` on the host, including when restoring into a missing file. A custom path outside the standard mounts needs a host path and `BACKUP_CONTEXT=host`.

The tasks print the SQLite path they use. For PostgreSQL, an explicit external `DATABASE_URL` is used even if a bundled database container is running. An external server needs `pg_dump` and `psql` on the host (`apt install postgresql-client`).

## Restore SQLite on Docker

Choose the backup to restore and keep a separate copy of the current database. Stop both application services so nothing writes during the restore:

```bash
docker compose stop web worker
BACKUP_CONTEXT=docker ./logstotal restore:sqlite BACKUP_FILE=backups/logstotal-YYYYMMDD-HHMMSS.db
./logstotal docker:up
./logstotal doctor:docker
```

The restore asks for confirmation, verifies the backup first, and refuses an empty file or one with no schema. It also refuses while the app is running; `FORCE=yes` overrides that.

If it reports `Permission denied`, the data directory is owned by the container's user. Run the restore from a shell that can write to it, from the same install directory and with `BACKUP_CONTEXT=docker`.

## Restore PostgreSQL on Docker

Run on the control plane. Stop every fleet worker first (`./logstotal deploy:stop` stops a whole fleet), then the local application services. Keep PostgreSQL running: `./logstotal docker:down` would remove the container used below.

The target must be an **empty database**: a plain SQL dump creates tables, it does not replace existing ones. This example uses the bundled database's default user, `logstotal`, and restores into a new database so the current one stays available:

```bash
docker compose stop web worker
docker compose up -d postgres
docker compose exec -T postgres createdb -U logstotal logstotal_recovered
DATABASE_URL='' POSTGRES_DB=logstotal_recovered \
  ./logstotal restore:postgres BACKUP_FILE=backups/logstotal-pg-YYYYMMDD-HHMMSS.sql.gz
```

With a different PostgreSQL user, use it in `createdb` and set `POSTGRES_USER` for the restore. For an external server, have its administrator create the empty database and pass its connection URL to the restore.

After a successful restore, set `POSTGRES_DB=logstotal_recovered` in the control plane's `.env`, and update any explicit `DATABASE_URL` and `SYNC_DATABASE_URL` on **every host** to the new database. Recreate the control plane, check it with `./logstotal doctor:docker`, then start the workers. Keep the old database until you have checked record counts, sign-in, uploads and an analysis. If the restore fails, it rolls back as one transaction; leave the application stopped and read the error before retrying.

To recover onto an older release, put the matching code back **before starting the application** — see [Rollback](upgrading.md#rollback). Starting newer code against the restored database would migrate it forward again.

## Rehearse a restore

`./logstotal backup:verify` proves a file is intact, not that the instance can be recovered from it. From time to time, restore onto a separate instance, compare record counts, sign in, open an uploaded file and run a sample analysis. Record which backup you tested and how long recovery took. Never point a rehearsal worker at the production Redis or object store.

---

**Related:** [Upgrade and roll back](upgrading.md) · [Storage and retention](storage.md) · [Move from SQLite to PostgreSQL](sqlite-to-postgres.md)
