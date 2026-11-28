# Upgrade and roll back

How to move an installation to a newer release, and how to go back if something is wrong.

Run every command on the deployment host — for a fleet, on the control plane — from the install directory.

## Before you upgrade

1. **Read the [changelog](https://github.com/wagga40/LogsTotal/blob/main/CHANGELOG.md)** for every release between yours and the target.
2. **Check health.** `./logstotal health` prints `OK   all subsystems healthy.`
3. **Let background tasks finish.** On `/admin/tasks`, no backfill or cleanup should be `running`.
4. **Preview the upgrade.** `./logstotal upgrade:plan` — see below.

You do not need to take a backup first: `./logstotal upgrade` runs `./logstotal backup` itself, which dumps the database, checks the dump with `./logstotal backup:verify` and records it in `backups/last-verified.json`. The upgrade stops if that backup fails. Do not rely on an older scheduled backup instead.

## Upgrade

```bash
./logstotal upgrade:plan
./logstotal upgrade
```

`./logstotal upgrade:plan` changes nothing. It shows the installed release, the release it would install, where it would download it from, whether the download is available, and what would be restarted:

```console
$ ./logstotal upgrade:plan
  installed  X.Y.Z
  target     vX.Y.Z+1
  server     https://github.com/wagga40/LogsTotal   (from .release-origin)
  source     package
  artifact   logstotal-X.Y.Z+1.7z — reachable
  restarts   single host (docker-compose.yml)
  would run  ./logstotal upgrade
```

It always exits 0, so it is safe in a script: a problem is printed as a line of output rather than returned as an error.

On a single host, `./logstotal upgrade` then:

1. records the current release in `backups/pre-upgrade-version-<stamp>.txt`;
2. takes and verifies a database backup;
3. copies the installed release to `backups/releases/` so it can be [rolled back](#rollback);
4. installs the new release over the install directory;
5. lists new and unknown `.env` keys (`./logstotal env:diff`) — informational only;
6. stops `web` and `worker`, applies database migrations, and starts the new version;
7. checks `/health` and runs `./logstotal doctor:docker`, and fails if either fails.

`.env`, `data/`, `uploads/`, `backups/` and `certs/` are never touched.

### Fleets

Run on the control plane, `./logstotal upgrade` upgrades **every host in the fleet**. It finds the hosts in this order: hosts named after `--`, the `DEPLOY_HOSTS` environment variable, `deploy.env`, and finally the fleet record the control plane keeps — see [What the control plane knows](../reference/fleet.md#what-the-control-plane-knows). With none of them, it upgrades this host alone.

For a fleet it checks every host, backs up the control plane, stops the workers and then the control plane, installs the release on each host, starts the control plane (which applies migrations as it starts), starts the workers once the control plane is healthy, and runs `./logstotal deploy:smoke`.

From a workstation, name the hosts, or name the control plane with `FLEET_FROM` and let its fleet record supply the rest (`FLEET_FROM` is described in the same [Fleet reference](../reference/fleet.md) section):

```bash
./logstotal upgrade -- cp.example.com w1.example.com
FLEET_FROM=cp.example.com ./logstotal upgrade
```

`DEPLOY_ONLY=<host>` limits every step to some of the hosts.

> [!IMPORTANT]
> Pass hosts after `--` or as an environment variable, never as `./logstotal upgrade DEPLOY_HOSTS=...`. A value written that way does not reach the upgrade script, which then takes the hosts from `deploy.env` or the fleet record instead.

### Options

| Variable | Effect |
|----------|--------|
| `SKIP_BACKUP=true` | Skips the database backup. Not recommended. |
| `SKIP_SNAPSHOT=true` | Skips the release snapshot, so `./logstotal upgrade:rollback` has nothing to restore. |
| `HEALTH_URL` | Where the single-host health check looks (default `http://localhost:8000`). |

The release variables below work either way round: `./logstotal upgrade VERSION=X.Y.Z` and `VERSION=X.Y.Z ./logstotal upgrade`.

## Which release

Upgrades install published releases. With no options you get the newest one.

| Variable | Effect |
|----------|--------|
| *(none)* | The newest published release. |
| `VERSION=X.Y.Z` | That release. Also how you move **back** to an older one. |
| `ARCHIVE=<path or URL>` | Exactly that release archive, with no lookup — for a host with no internet access. |
| `SKIP_IF_CURRENT=true` | Exit successfully, before the backup, if every host in scope already runs the target release. For scheduled upgrades. |
| `RESTAGE_IF_CURRENT=true` | Reinstall the release that is already installed and running (see below). |
| `ALLOW_UNRELEASED=true REF=<ref>` | Install a branch or commit from git. **Unsupported**: nothing then records which commit is running. |

Any other `REF=` is refused: only `vX.Y.Z` tags are releases.

If the target is the release already installed, the result depends on whether the deployment is running:

| State | What happens |
|-------|--------------|
| Already current, **containers running** | **Refused**, because reinstalling rebuilds, migrates and restarts for no change — on a fleet, every host. Use `RESTAGE_IF_CURRENT=true` to do it anyway, or `SKIP_IF_CURRENT=true` to make it a no-op. |
| Already current, **nothing running** | **Proceeds.** This is what an interrupted upgrade leaves behind, and reinstalling repairs it. |

The upgrade never asks a question on the terminal, so it can run from cron, CI or `ssh`. `./logstotal upgrade:plan` tells you in advance whether it would be refused.

**Going back to an older release** with `VERSION=` warns you, because migrations do not run backwards. Prefer `./logstotal upgrade:rollback` — see [Rollback](#rollback).

To see which release is running:

```bash
./logstotal version                                             # on the host
HEALTH_URL=https://logs.example.com ./logstotal health:remote   # from anywhere
```

## Where the code comes from

| | |
|---|---|
| `SOURCE=package` (default) | Downloads the published `logstotal-<version>.7z`, the tested release with the production stylesheet built in. Needs no git. |
| `SOURCE=git` | Checks out the release tag. Needs a git checkout. |
| `ARCHIVE=<path or URL>` | Uses exactly that archive. |

In package mode the archive is unpacked into a temporary directory and copied over the installation with `rsync`. On an archive installation, files the new release no longer ships are removed; on a git checkout they are left for git to handle. Migration files the target release does not ship are always removed, so going back a release cannot leave newer migrations behind.

On a git checkout, the package files show up in `git status`. `git checkout -- .` resets them, or use `SOURCE=git`. A checkout with uncommitted changes is refused before anything is installed.

> [!NOTE]
> With `SOURCE=git`, a tag that exists locally with a different commit than on the server stops the upgrade if it is the release being installed; other conflicting tags are only reported. Compare `git rev-parse <tag>^{}` with `git ls-remote --tags origin <tag>`, then either `git tag -d <tag> && git fetch --tags origin` to take the server's tag, or `git push --force origin refs/tags/<tag>` to keep yours.

### Where releases come from

Releases are looked up and downloaded from one server. `./logstotal upgrade:plan` shows which one, and why. The first of these that is set wins:

1. `RELEASE_REPO_URL` in the environment.
2. `.release-origin` in the install directory, written into every release archive.
3. `RELEASE_REPO_URL` in `deploy.env`.
4. The control plane's fleet record.
5. The git `origin` remote, converted to an https address.
6. `https://github.com/wagga40/LogsTotal`.

Do not put `RELEASE_REPO_URL` in `.env`: it would override the value you pass on the command line.

> [!NOTE]
> An `ssh://` or `git@` origin is converted to `https://` on the same host, without a port. For a self-hosted server that is often the wrong address; set `RELEASE_REPO_URL` in `deploy.env`. Any Gitea- or Forgejo-compatible server works like GitHub. Any other server needs `logstotal-<version>.7z` published under `releases/download/<tag>/`; otherwise use `ARCHIVE=`.

A tag is not a release: package mode checks the archive exists before the backup, so a release still being published is reported up front.

## Moving an existing 0.x installation to 1.0

An installation older than 1.0 was set up from another release server, and the `.release-origin` file in its install directory outranks `deploy.env`. Name the new server in the environment for this one upgrade. Before 1.0 there is no `./logstotal`, so use `task` (0.10 or later):

```bash
cd /opt/logstotal
RELEASE_REPO_URL=https://github.com/wagga40/LogsTotal task upgrade:plan
RELEASE_REPO_URL=https://github.com/wagga40/LogsTotal task upgrade
```

The 1.0 release brings its own `.release-origin`, so later upgrades need nothing extra.

A **git checkout** cannot follow, because 1.0 starts a new git history. Take a backup, stop the stack, move the old directory aside and clone 1.0 into the same path — the directory name is the Docker Compose project name, which the PostgreSQL, Redis and Garage volumes are named after. Copy `.env`, `data/`, `uploads/`, `backups/` and `certs/` across, then start it with `./logstotal docker:up`.

## Migrations

The web service applies database migrations when it starts — see [Database migrations](migrations.md). `./logstotal upgrade` adds what a plain restart cannot: a verified backup, a snapshot to roll back to, and health checks. Do not upgrade a fleet by redeploying with `./logstotal deploy`: it takes no backup first.

On a single host, the upgrade stops `web` and `worker` before migrating, because migrations must not run while the application writes. On a fleet, only the control plane migrates: workers never touch the schema, and they start after the control plane is healthy. To apply a fleet's migrations outside an upgrade, stop the fleet and start it again; `./logstotal deploy:stop` stops the workers first, and `./logstotal deploy:start` starts the control plane first:

```bash
./logstotal deploy:stop
./logstotal deploy:start
```

<!-- destructive-migrations -->
Five migrations rename or remove something, so older code cannot run on the database they leave: `a3c7e2f91d04` renames `workerpolicy.pickup_weight` to `max_concurrent_jobs`, `c9d4e1f7a2b3` drops the threat-landscape tables, `e23ff92ada52` drops the `watchlist_event` table, `c8f24a1b6d90` drops the `user.theme` column, and `f3a91c2e7d40` moves each finding's rule text into a shared `rule_text` table and drops `finding.rule_content`. Rolling back across any of them needs the pre-upgrade database backup, which is one reason `./logstotal upgrade` always takes one. The last one's own downgrade is lossless (`pdm run -- alembic downgrade e064602640a4` writes every finding's rule text back, decoding compressed rows), but it runs from the new code, before the old code is installed.

## PostgreSQL 19

Releases before 1.4 bundled PostgreSQL 16, in the `postgres_data` volume. The bundled
server is now PostgreSQL 19, in a new volume, `postgres19_data`. A PostgreSQL data
directory cannot be opened by a newer major version, so the move is a dump and a restore,
and it happens by itself the first time the new release starts:

1. The `postgres-migrate` service starts first, in the PostgreSQL 16 image. It dumps the
   database from the old cluster — through the running PostgreSQL 16 server if there still
   is one, otherwise through a private server it starts on the old volume — and checks that
   the dump is complete.
2. The PostgreSQL 19 server initialises `postgres19_data` and loads that dump, in one
   transaction, before it accepts connections. The web service waits for it.

Nothing is written to `postgres_data`, so it stays a working PostgreSQL 16 cluster: it is
what [`./logstotal upgrade:rollback`](#rollback) returns to. Every later start finds the new
cluster in place and skips the move. It only concerns the bundled server
(`COMPOSE_PROFILES=postgres`); an external PostgreSQL is yours to upgrade. CI tests the
app against PostgreSQL 19.

- **Let `./logstotal upgrade` do it.** It stops `web` and `worker` first, so nothing writes
  to PostgreSQL 16 while it is being dumped. If the old server is still answering when the
  move starts and other clients are connected to it, the move refuses rather than dump a
  database that is still changing.
- **It takes as long as a dump and a restore of your database.** The new server is not
  healthy until the restore finishes, and the app waits for it.
- **If the restore fails, PostgreSQL 19 refuses to start** rather than serve an empty
  database, with a message saying so. `docker compose up -d` discards the incomplete
  cluster and moves the data again; the PostgreSQL 16 volume is unchanged throughout.
- **The old volume stays until you remove it.** `./logstotal doctor:docker` mentions it
  while it still holds the PostgreSQL 16 database; the System tab cannot, because the web
  container cannot look inside Docker volumes. Once you will not roll back past this
  release, delete it:

  ```bash
  docker compose rm -f postgres-migrate      # its stopped container still uses the volume
  docker volume rm logstotal_postgres_data   # the prefix is your compose project name
  ```

  The next start creates `postgres_data` again, empty, because `postgres-migrate` mounts
  it. An empty volume takes no space and doctor does not report it. From then on a rollback
  past 1.4 is refused: there is no PostgreSQL 16 database left to return to (see
  [Service data](#service-data)).

## Rollback

**Rolling back the code restores a local snapshot. Rolling back the database means restoring a backup.** They are separate steps, and most rollbacks need only the first.

### Roll back the code

Every `./logstotal upgrade` copies the installed release to `backups/releases/<stamp>-<version>/` before installing anything, keeping the newest `DEPLOY_KEEP_RELEASES` copies (default 3). To go back to the newest copy:

```bash
./logstotal upgrade:rollback
```

It restores the snapshot, removing files the newer release added, then rebuilds the image and restarts. `.env`, `data/`, `uploads/` and `backups/` are never touched. Each rollback **consumes** the snapshot it restores, so running it twice goes back two releases.

It refuses when the release you are leaving applied migrations the snapshot does not know: the database would stay at the newer schema and the older code would not start. Restore the database first — see [When rollback is unsafe](#when-rollback-is-unsafe).

On a control plane, `./logstotal upgrade:rollback` rolls back **the whole fleet**, choosing the hosts the same way `./logstotal upgrade` does. Set `DEPLOY_STOP=true DEPLOY_START=true` so each host is stopped before its files are restored and started after:

```bash
DEPLOY_STOP=true DEPLOY_START=true ./logstotal upgrade:rollback
DEPLOY_STOP=true DEPLOY_START=true ./logstotal upgrade:rollback -- cp.example.com w1.example.com
```

A fleet rollback makes the same check against the control plane's database before it stops any host. If the upgrade changed the database, restore it first.

Without a snapshot (the upgrade ran with `SKIP_SNAPSHOT=true`, or the snapshots have been used up), install the older release again. The previous version is in `backups/pre-upgrade-version-*.txt`:

```bash
./logstotal upgrade VERSION=<previous-version>
./logstotal upgrade ARCHIVE=/path/to/logstotal-<previous-version>.7z
```

### Service data

Three bundled services keep data a newer release changed in a way the older one cannot
read back. Rolling back across one of them is refused until you say the data written since
the upgrade may go:

```bash
ROLLBACK_DATA=previous ./logstotal upgrade:rollback
```

| Crossing | What `ROLLBACK_DATA=previous` does |
|---|---|
| PostgreSQL 16 → 19 (1.4) | The older release runs on `postgres_data` again, the database as it was when 1.4 first started. Rows written since stay in `postgres19_data`, unused; the 19 cluster is marked superseded, so the next upgrade copies `postgres_data` across afresh instead of reviving them. |
| Redis 7 → 8 (1.4) | Redis 7 cannot read Redis 8's data file, so it is set aside as `dump.rdb.from-redis-8` and Redis starts empty. Queued jobs are dropped and fail once `HUEY_QUEUE_EXPIRY` passes; caches rebuild themselves. |
| Garage → 2.5 or later (1.4) | Its metadata goes back to the copy `garage-entrypoint.sh` took before Garage 2.5 first ran; the newer metadata is kept beside it as `meta/.from-garage-2.5`. Objects stored since the upgrade — the uploads and tool outputs of jobs run after it — are no longer listed, though their bytes stay in `garage_data`. |

Once `postgres_data` no longer holds the PostgreSQL 16 database — you removed it after the
move — a rollback across PostgreSQL is refused even with `ROLLBACK_DATA=previous`, because
the older release would start on an empty database. Stay on this release, or install the
older one and load a database backup taken before the upgrade into it
([Restore the database](#restore-the-database)).

It applies only to services the host runs: an SQLite install with local storage only meets
the Redis row. On a fleet, the check runs on the control plane before any host is stopped,
and the data is set back there before its files are restored. If you need what was written
since, move forward rather than back.

### Restore the database

Only needed if the upgrade applied migrations you need undone. Stop the stack, then restore the backup the upgrade took:

```bash
./logstotal restore:sqlite BACKUP_FILE=backups/logstotal-YYYYMMDD-HHMMSS.db        # SQLite
./logstotal restore:postgres BACKUP_FILE=backups/logstotal-pg-YYYYMMDD-HHMMSS.sql.gz  # PostgreSQL
./logstotal docker:up
```

Both check the backup with `./logstotal backup:verify` before restoring. The full procedures, including PostgreSQL's empty-database requirement, are in [Back up and restore](backup-and-restore.md).

### When rollback is unsafe

| Migration kind | Can the old code run on the new database? |
|----------------|-------------------------------------------|
| New table, nullable column or index | Yes |
| New `NOT NULL` column with a default | Usually; the old code ignores the column |
| Dropped table or column | **No** — the data is gone |
| Renamed column | **No** — the old code looks for the old name |

To roll back across a migration that removed or renamed something: stop the stack, restore the pre-upgrade backup, then restore the old code with `./logstotal upgrade:rollback`. Do not try to downgrade the schema with Alembic.

### Rolling back the analysis-confidence migration

Migration `b8d46f1e932a` adds nullable provenance and diagnostics columns and the `PARTIAL` task status. Older code cannot read `PARTIAL` rows, so the release that applies it is a special case of the table above. Older workers cannot read them either: `./logstotal upgrade` stops every worker before migrating, and if you upgrade any other way, stop them yourself first.

`./logstotal upgrade:rollback` refuses to cross this migration, on a single host and on a fleet. Restoring the pre-upgrade backup is the simplest way back. To keep the jobs analysed since the upgrade, downgrade the schema while the new code is still installed, then roll the code back:

```bash
docker compose stop web worker
docker compose run --rm web python3 -m alembic downgrade a76e3b9c214d
./logstotal upgrade:rollback
```

On a fleet, stop it with `./logstotal deploy:stop`, open the control plane's install directory with `./logstotal deploy:shell` and run the same `docker compose run` there, then roll back with `DEPLOY_STOP=true DEPLOY_START=true ./logstotal upgrade:rollback`. On a development checkout, the downgrade is `pdm run alembic downgrade a76e3b9c214d`.

The downgrade turns partial tasks into failed ones and keeps their findings. It drops the provenance and diagnostics columns. PostgreSQL keeps the unused `PARTIAL` enum label, which older code never reads.

Uploaded files are never changed by a rollback or a database restore, and neither is the
object store — except Garage's metadata when a rollback crosses Garage 2.5 with
`ROLLBACK_DATA=previous` (see [Service data](#service-data)). Files uploaded after the
restored backup stay in storage without a database row; `/admin/storage` reports them as
orphans — see [Storage and retention](storage.md#orphaned-files).

## After you upgrade

1. `HEALTH_URL=https://logs.example.com ./logstotal health:remote` reports the new version and every subsystem `ok`.
2. `/admin/tasks` shows no new failures.
3. `/admin/workers` lists every worker host, none paused, with fresh heartbeats.
4. Upload a small log and check that its job completes.

If something fails, keep `./logstotal version`, the `./logstotal health` output and `docker compose logs --tail 200 web`, then fix forward or [roll back](#rollback).

New settings arrive commented out in `.env.example` with a safe default, so you only need to act to change one. `./logstotal env:diff`, which the upgrade runs, lists them along with any key in your `.env` that LogsTotal does not recognise.

---

**Related:** [Database migrations](migrations.md) · [Back up and restore](backup-and-restore.md) · [Fleet reference](../reference/fleet.md) · [Troubleshooting](../troubleshooting.md)
