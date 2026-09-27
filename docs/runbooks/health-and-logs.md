# Health, logs and first-day checks

How to tell whether an instance is healthy, where its logs are, and what to check on the first day after a deploy.

Commands run on the deployment host, from the install directory, unless a step says otherwise.

## Reading `/health`

Every deployment serves `GET /health` without authentication. An administrator who is signed in sees:

```json
{
  "app":        "ok",
  "version":    "1.0.0",
  "database":   "ok",
  "redis":      "ok",
  "storage":    "ok (local)",
  "migrations": "e7b2c4a91f38 → e7b2c4a91f38 (at_head)",
  "workers":    3,
  "workers_ok": true
}
```

The endpoint returns **HTTP 200** when `database`, `redis` and `storage` are all `ok`, and **HTTP 503** otherwise.

| Field | Meaning |
|-------|---------|
| `app` | Always `ok` while the web process answers. |
| `version` | The installed release, read from the `VERSION` file. Use it to confirm an upgrade landed. |
| `database` | `error` when the database is unreachable or rejects `SELECT 1`. |
| `redis` | `error` when Redis is unreachable. Jobs can be submitted but no worker picks them up. |
| `storage` | `error` when the S3 bucket is unreachable, or when a write/read/delete probe of the local `uploads/` directory fails. The backend name in brackets is shown to administrators only. |
| `migrations` | Administrators only. `current → head (state)`. `at_head` is healthy; `behind` means the web service has not migrated yet (restart it); `unmanaged` means the schema could not be adopted — see [Database migrations](migrations.md). Does not affect the status code. |
| `workers` | Number of live worker processes registered in Redis. `0` means no job can start. |
| `workers_ok` | `false` when `workers` is `0`. The status code stays 200 so an orchestrator does not restart the web tier when workers scale to zero; alert on this field instead. |

The migration revision and the storage backend are withheld from anonymous callers. `./logstotal health`, `./logstotal health:remote`, `./logstotal deploy:smoke` and the Compose healthcheck are all anonymous, and check only the status code and the ungated fields.

Probe the local instance with `./logstotal health`. From a workstation, `HEALTH_URL=https://logs.example.com ./logstotal health:remote`; behind Caddy basic auth, add `BASIC_AUTH_USER` and `BASIC_AUTH_PASS`.

## Logs

On Docker, each service logs to the Docker log driver, rotated at 10 MB × 3 files per service:

```bash
docker compose logs --tail 200 web          # the last 200 lines
docker compose logs --tail 200 worker
./logstotal docker:logs:web                 # follow; Ctrl-C to stop
./logstotal docker:logs:worker
```

On a standalone worker host, use `./logstotal docker:worker-logs`, which follows the worker stack.

`LOG_LEVEL`, `LOG_FORMAT` (`text` or `json`) and `REQUEST_LOG_ENABLED` control what is written — see [Configuration](../configuration.md). Every error page shows a **Reference** id, also sent as the `X-Request-ID` response header; search the logs for it to find the request a user is reporting.

## First day after deploy

Run this once, right after the stack comes up. The **Getting started** card on the `/admin` Overview tab tracks the password, worker, first-analysis and production-warning steps, and the **System** tab shows each worker host's effective concurrency.

1. **Sign in.** The admin password is printed once, at the end of the install. `./logstotal show-admin-password` reads it back from `.env` (for a fleet, on the machine you deployed from: `ENV_FILE=deploy-envs/<control-plane>.env ./logstotal show-admin-password`). It shows the password the account was created with; if it has been changed since, reset it at `/admin/users`.
2. **Preflight.** `./logstotal doctor:docker` runs the checks inside the web container and should end with `READY` and no `FAIL`. It checks configuration (including reverse-proxy and multi-server settings), secrets, the default admin password, the database, Redis (reachability and eviction policy), storage, migrations, disk, queue backlog and the detection tool binaries, and prints the fix for anything broken. The same checks appear on `/admin` under **System checks**.
3. **Health.** `./logstotal health` (or `health:remote` from a workstation) returns HTTP 200 with the expected `version` and at least one worker.
4. **A worker is live.** `/admin/workers` lists at least one host with a recent heartbeat. With no worker, jobs stay `PENDING`.
5. **End to end.** Upload one of the shipped [sample logs](https://github.com/wagga40/LogsTotal/blob/main/samples/README.md) and confirm the job reaches `completed`. `samples/windows/bitsadmin.evtx` exercises all three Windows engines; `samples/linux/syslog_intrusion.log` exercises ChopChopGo. The nine samples cover all eight supported log types, so running each one shows which workflows work on this host.
6. **No default admin password.** `/admin` shows no red password banner (see [User and role management](account-recovery.md#user-and-role-management)).
7. **Disk baseline.** `du -sh uploads/ data/` records your starting footprint.
8. **Backups scheduled.** `crontab -l | grep backup` shows a backup job. If not, add one — see [Schedule backups](backup-and-restore.md#schedule-backups).
9. **Right-size the workers.** Run `./logstotal recommend-scaling` and compare with your `HUEY_WORKERS`. `-- --apply` writes the `.env` settings and `-- --apply-workflows` the per-tool `threads:`; recommendations are per host. See [Scaling](../scaling.md).

## Monitoring

| What to watch | How | Healthy | Act when |
|---------------|-----|---------|----------|
| Subsystems | `curl -s https://logs.example.com/health` | HTTP 200, all `ok` | any `error` → [Troubleshooting](../troubleshooting.md#runtime-and-operations) |
| Workers | `workers_ok` in `/health`, or `/admin/workers` | at least one, fresh heartbeat | `0` or stuck → [Stuck job recovery](workers.md#stuck-job-recovery) |
| Queue backlog | `/admin/workers` (queued count) or `/admin/tasks` | drains steadily | stays high → add a worker or raise `HUEY_WORKERS` |
| Scheduled tasks | **Scheduled** tab on `/admin/tasks` | each ran within the last day | a missed run → no worker was up; see [Storage and retention](storage.md#automatic-row-retention) |
| Disk | `du -sh uploads/ data/`, or `/admin/storage` | well under the volume size | nearing full → [Storage and retention](storage.md) |
| CPU vs sizing | `./logstotal recommend-scaling` against the current `.env` | peak load ≈ cores | slow jobs → lower `HUEY_WORKERS` or per-tool `threads` |

Sizing `HUEY_WORKERS`, `TOOL_MAX_WORKERS`, per-tool `threads` and `DB_POOL_SIZE` against CPU and RAM is covered in [Scaling](../scaling.md).

## Day-2 cheatsheet

```bash
# What am I running?
./logstotal version
HEALTH_URL=https://logs.example.com ./logstotal health:remote

# Backups
./logstotal backup                  # dump + verify + receipt
```

Routine administration happens in the browser: `/admin` (dashboard), `/admin/workers` (fleet and stuck jobs), `/admin/tasks` (background and scheduled tasks), `/admin/storage` (disk and retention) and `/admin/settings`.

Version upgrades have their own page: [Upgrade and roll back](upgrading.md).

---

**Related:** [Troubleshooting](../troubleshooting.md) · [Upgrade and roll back](upgrading.md) · [Scaling](../scaling.md) · [Docs index](../README.md)
