# Move from SQLite to PostgreSQL

How to move an existing single-host installation's data from SQLite to PostgreSQL.

A single host starts on SQLite. A fleet needs PostgreSQL, and **System checks** (and `./logstotal doctor:docker`) warn once SQLite is used by more than one worker process.

> [!WARNING]
> **Do not use `sqlite3 .dump | psql`.** UUIDs, booleans and auto-increment columns are stored differently by the two databases. The copy below goes through the application's own data model, so each value is written with the type PostgreSQL expects.

## Docker procedure

Run on the deployment host, from the install directory. You need a verified backup and enough disk space for both databases. Keep Redis running, and stop the application so nothing writes:

```bash
docker compose stop web worker
BACKUP_CONTEXT=docker ./logstotal backup:sqlite
```

In `.env`, add `postgres` to `COMPOSE_PROFILES` (keep any other profiles you use) and set a strong `POSTGRES_PASSWORD`. Comment out any SQLite `DATABASE_URL` and `SYNC_DATABASE_URL` lines, so the container selects PostgreSQL. Do not start the web service yet: it would fill the new database before the copy.

```bash
docker compose up -d postgres
docker compose run --rm --no-deps web python3 -m app.migrations
docker compose run --rm --no-deps web sh -c \
  'python3 scripts/sqlite_to_postgres.py --sqlite-url sqlite:////data/logstotal.db --postgres-url "$SYNC_DATABASE_URL"'
```

These run inside the application image, where the SQLite file is mounted at `/data` and PostgreSQL is reachable as `postgres:5432`. No PostgreSQL port on the host and no other tooling is needed.

The copy should end with `OK — every table matched on row count`. Then start the application and check it:

```bash
./logstotal docker:up
./logstotal doctor:docker
```

## Development checkout

Stop `./logstotal dev` and `./logstotal worker`, take a backup, and create an empty PostgreSQL database you can reach. Create the schema, then copy:

```bash
SYNC_DATABASE_URL=postgresql+psycopg2://logstotal:PASS@localhost:5432/logstotal \
  pdm run python3 -m app.migrations
./logstotal db:to-postgres -- \
  --sqlite-url sqlite:///logstotal.db \
  --postgres-url postgresql+psycopg2://logstotal:PASS@localhost:5432/logstotal
```

Before restarting, point both database URLs at PostgreSQL: `+asyncpg` for `DATABASE_URL`, `+psycopg2` for `SYNC_DATABASE_URL`.

## If the copy fails

The copy commits one table at a time, so a failed run can leave part of the data in PostgreSQL, and the copy refuses to write into a database that already holds rows. Keep the application stopped, recreate an empty PostgreSQL database, correct the error and run the copy again. To give up instead, restore the original SQLite settings in `.env` and start the application on the SQLite file, which the copy never changes.

The copy compares the row count of every table and exits non-zero on any difference. It also moves each ID sequence past the copied rows, so new records cannot collide with copied ones.

Keep the SQLite file and the backup until you have confirmed that uploads work, `/admin` shows the expected job and user counts, and `./logstotal doctor:docker` passes. Nothing deletes them for you.

---

**Related:** [Database migrations](migrations.md) · [Back up and restore](backup-and-restore.md) · [Configuration](../configuration.md)
