# Scaling and capacity planning

How the three concurrency settings multiply into CPU pressure, and how to size a host.

Not sure how many workers to run? On each host, in the install directory, run
**`./logstotal recommend-scaling`**. It detects the host's CPU and RAM and prints recommended
values with the reasoning; the model below is what it applies. It needs only `python3`, so
it works on a Docker host.

## The mental model

LogsTotal has three nested layers of concurrency, and they multiply:

1. **Jobs per worker process — `HUEY_WORKERS`.** A worker runs this many threads, and
   **each thread processes one job at a time.** Analysis jobs *and* admin backfills share
   this pool. This is your throughput setting.
2. **Tools per job — `parallel_execution` + `TOOL_MAX_WORKERS`.** Within a single job, tools
   run **one after another by default**. If an admin turns on *Parallel tool execution*
   (`/admin/settings`), up to `TOOL_MAX_WORKERS` tools in that job run at once — never more
   than the workflow has. This is a per-job *latency* setting, not a throughput one.
3. **Threads per tool — `threads` (workflow YAML).** Hayabusa (`--threads`) and Chainsaw
   (`--num-threads`) can use several threads each; Zircolite ignores the setting. LogsTotal
   always passes an explicit value, so **omitting `threads` means 1** (never all cores).
   **The shipped workflows set `threads: 2`** for Hayabusa and Chainsaw. Workflows are
   stored in the database and shared by every worker, so size `threads` for your smallest
   worker host.

They multiply into CPU pressure:

```
peak CPU pressure  ≈  HUEY_WORKERS × (TOOL_MAX_WORKERS if parallel else 1) × per-tool threads
```

**Keep peak near your core count.** Above it, tools fight for CPU and *everything* gets
slower. The default (`parallel_execution` off) collapses the middle term to 1, so peak is
just `HUEY_WORKERS × threads`.

## Recommended defaults by host size

What `./logstotal recommend-scaling` prints for a **dedicated worker host** running the
shipped workflows (the largest runs three tools), with `parallel_execution` off — the
throughput-optimal default:

| Cores | RAM | `HUEY_WORKERS` | per-tool `threads` | `TOOL_MAX_WORKERS`² | `DB_POOL_SIZE`¹ | peak CPU |
|------:|----:|---------------:|-------------------:|--------------------:|----------------:|---------:|
| 2     | 2 GB  | 1 | 1 | 2 | 5 | 1 |
| 4     | 8 GB  | 2 | 2 | 2 | 5 | 4 |
| 8     | 16 GB | 4 | 2 | 3 | 5 | 8 |
| 16    | 32 GB | 8 | 2 | 3 | 8 | 16 |
| 32    | 64 GB | 16| 2 | 3 | 16| 32 |

¹ `DB_POOL_SIZE` applies to **PostgreSQL only** (SQLite ignores it). Size it at least
`HUEY_WORKERS` so each worker thread can hold a connection; the pool is per process (web
and each worker get their own).

² `TOOL_MAX_WORKERS` only takes effect when `parallel_execution` is **on**, so it does not
enter this table's peak-CPU column. It is sized to the largest workflow's tool count, but
capped so one job's parallel tools (`TOOL_MAX_WORKERS × threads`) stay within the core
budget.

Notes:

- **Everything on one host** (web + worker + Redis): drop `HUEY_WORKERS` by 1 to leave a
  core for the web and Redis processes.
- **Low RAM, many cores:** RAM caps concurrency first — the model budgets about 1.5 GB per
  concurrent job (a tool parsing a large EVTX is memory-hungry), and `recommend-scaling`
  takes the lower of the CPU and RAM limits.
- **`parallel_execution`** is worth turning *on* only on larger hosts where jobs usually
  arrive one at a time and you want each to finish faster. `recommend-scaling` already
  sizes `TOOL_MAX_WORKERS` for that; lower `HUEY_WORKERS` so peak stays near the core
  count. Under steady load, leave it off.
- **Fleets:** these recommendations are **per host** — run `./logstotal recommend-scaling`
  on each machine and set that host's own `.env`. Dedicated worker hosts started from
  `docker-compose.worker.yml` default to `HUEY_WORKERS=4`; the fleet deploy sets it from
  `DEPLOY_HUEY_WORKERS` (also 4).

## Storage growth

Each job stores its uploaded log plus each tool's raw output. Stored tool stdout/stderr is
capped by `MAX_LOG_OUTPUT_BYTES` (default 50 KB per task). Raw outputs are deleted after
`JOB_OUTPUT_RETENTION_DAYS` (default 90) by a daily sweep; uploaded files are kept unless
you set `UPLOAD_RETENTION_DAYS`. Watch usage on `/admin/storage` and the disk gauge on
`/admin`. The schedules and the manual reclaim actions are in
[Storage and retention](runbooks/storage.md).

## Apply a recommendation

On the host, in the install directory:

```bash
./logstotal recommend-scaling                      # print recommendation + reasoning for this host
./logstotal recommend-scaling -- --apply           # write HUEY_WORKERS / TOOL_MAX_WORKERS / DB_POOL_SIZE into .env
./logstotal recommend-scaling -- --apply-workflows # write per-tool threads: into workflows/*.yml
```

`--apply` only touches the `.env` settings (and skips `DB_POOL_SIZE` on SQLite, where it is
ignored); it asks before writing. Follow [Apply configuration changes](runbooks/configuration-changes.md)
afterwards — Docker containers must be recreated to see a new `.env`.

`--apply-workflows` writes the recommended `threads:` into every Hayabusa and Chainsaw task
in `workflows/*.yml` (Zircolite ignores threads and is left alone), editing only those
lines. Workflows live in the database, so load the edited files where the database is
initialised: on a Docker host — the control plane, in a fleet — run `./logstotal docker:up`,
which rebuilds the image and reloads the workflows as the web container starts; in a
development checkout, run `./logstotal sync-workflows`. The two flags work together or on
their own; the `parallel_execution` switch stays in `/admin/settings`.

The output shows both your **current** peak (from the `threads:` your workflows set now)
and the **recommended** peak, so you can see the gap.

---

**Related:** [Configuration](configuration.md) · [Worker operations](runbooks/workers.md) · [Fleet installation](install/fleet.md) · [Docs index](README.md)
