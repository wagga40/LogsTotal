# Database migrations

What the web service does to the database schema when it starts, and what to do when that fails.

Nothing needs to be run by hand after an upgrade: the web service brings the schema up to date every time it starts. Workers never change the schema.

## What happens at startup

| Database state | What startup does |
|----------------|-------------------|
| Empty | Creates the schema and records it as current |
| Tables but no migration record (created with `AUTO_MIGRATE=false`) | Compares the tables with what this release expects. If they match, records the schema as current. If not, records nothing, logs a warning and starts anyway; `/health`, **System checks** and `./logstotal doctor:docker` then report `migrations: unmanaged` |
| Behind the current release | Applies the pending migrations before serving any request |
| Current | Nothing |

When several web services start at once, one takes a lock in Redis and migrates; the others wait for it to finish before serving. A web service that waits more than 10 minutes refuses to start.

The migration state is shown to administrators in `/health` (the `migrations` field) and in **System checks** on `/admin`.

## If a migration fails

**The web service refuses to start** rather than serve a half-migrated database. On Docker this shows as a restart loop, with the error in the web log:

```bash
docker compose logs web | grep -A5 -i alembic
```

Then either:

1. Restore the backup taken before the upgrade and roll the code back — see [Rollback](upgrading.md#rollback) — or
2. Fix the cause and restart the web service.

While you investigate, `AUTO_MIGRATE=false` in `.env` lets the web service start without migrating: it creates missing tables but applies no migrations. Do not leave it that way — later releases will be missing their schema changes.

## `migrations: unmanaged`

The database has tables but no migration record, and they do not match what this release expects. Compare the schema with the release and reconcile the differences by hand. Then record the schema as current and restart the web service:

```bash
docker compose run --rm --no-deps web python3 -m alembic stamp head
docker compose restart web
```

On a development checkout, `./logstotal db:stamp -- head` does the same.

---

**Related:** [Upgrade and roll back](upgrading.md) · [Back up and restore](backup-and-restore.md) · [Troubleshooting](../troubleshooting.md)
