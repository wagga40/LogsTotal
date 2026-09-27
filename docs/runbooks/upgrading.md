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
Four migrations rename or remove something, so older code cannot run on the database they leave: `a3c7e2f91d04` renames `workerpolicy.pickup_weight` to `max_concurrent_jobs`, `c9d4e1f7a2b3` drops the threat-landscape tables, `e23ff92ada52` drops the `watchlist_event` table, and `c8f24a1b6d90` drops the `user.theme` column. Rolling back across any of them needs the pre-upgrade database backup, which is one reason `./logstotal upgrade` always takes one.

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

A fleet rollback does not check migrations. If the upgrade changed the database, restore it first.

Without a snapshot (the upgrade ran with `SKIP_SNAPSHOT=true`, or the snapshots have been used up), install the older release again. The previous version is in `backups/pre-upgrade-version-*.txt`:

```bash
./logstotal upgrade VERSION=<previous-version>
./logstotal upgrade ARCHIVE=/path/to/logstotal-<previous-version>.7z
```

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

Uploaded files and the object store are never changed by a rollback or a database restore. Files uploaded after the restored backup stay in storage without a database row; `/admin/storage` reports them as orphans — see [Storage and retention](storage.md#orphaned-files).

## After you upgrade

1. `HEALTH_URL=https://logs.example.com ./logstotal health:remote` reports the new version and every subsystem `ok`.
2. `/admin/tasks` shows no new failures.
3. `/admin/workers` lists every worker host, none paused, with fresh heartbeats.
4. Upload a small log and check that its job completes.

If something fails, keep `./logstotal version`, the `./logstotal health` output and `docker compose logs --tail 200 web`, then fix forward or [roll back](#rollback).

New settings arrive commented out in `.env.example` with a safe default, so you only need to act to change one. `./logstotal env:diff`, which the upgrade runs, lists them along with any key in your `.env` that LogsTotal does not recognise.

---

**Related:** [Database migrations](migrations.md) · [Back up and restore](backup-and-restore.md) · [Fleet reference](../reference/fleet.md) · [Troubleshooting](../troubleshooting.md)
