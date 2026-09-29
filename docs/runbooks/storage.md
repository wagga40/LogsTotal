# Storage and retention

What LogsTotal keeps on disk and in the database, how long it keeps it, and how to reclaim space.

`/admin/storage` shows current usage, the largest consumers, orphaned files and the retention windows in force, and holds the controls described below.

## Output cleanup + storage

Every analysis writes each tool's raw output to a per-job directory (`uploads/job_<id>/`, or the same prefix in the S3 bucket). These directories are the largest thing that grows with use, so they are swept by age:

- **`JOB_OUTPUT_RETENTION_DAYS`** (default `90`) sets the age. A worker sweeps outputs older than that every day at 04:45 UTC. `0` disables the sweep and keeps outputs forever.
- **`/admin/storage`** can override that value without editing `.env`, and **Run the output sweep now** runs the sweep at once. **Output Cleanup** on the `/admin` Maintenance tab (`POST /admin/cleanup-outputs`) does the same.

> [!IMPORTANT]
> With `JOB_OUTPUT_RETENTION_DAYS=0` raw outputs grow without limit. On SQLite, a full volume stops database writes, which takes the whole application down, not just new uploads.

The tool log shown on the job page is stored in the database, not in these directories, and is capped when it is written by `MAX_LOG_OUTPUT_BYTES` (default 50 KB per tool run).

### What survives output cleanup

Findings, analytics and entities are in the database and are not affected. Three views read the raw output again and stop working for a job once it has been swept:

| Surface | Source | Survives output cleanup? |
|---------|--------|--------------------------|
| Hourly MITRE histogram | raw output | no |
| Process tree | raw output | no |
| RAW ZIP export and **Recalculate analytics** | raw output | no |
| Zoomable events timeline | database | **yes** |
| Key events (case Timeline) | database | yes |

A case's **Timeline** tab says how many of its jobs still contribute to the histogram.

The events timeline is built during the analytics step and stored with the job. A job without one (a cancelled job, for example, skips analytics) shows "No event index for this data yet" until **Recalculate analytics** on the job page or the **Analytics** backfill builds it.

The events timeline shows every timestamp in UTC, while the hourly histogram keeps each tool's own time offset. On a job whose tools disagree about the time zone the two can sit an offset apart; the events timeline is the correct one.

### Orphaned files

A stored file or output directory that no database row refers to any more is an orphan. `/admin/storage` finds them on either storage backend (local or S3) and shows how much space they hold; **Purge** removes them as a background task. Nothing removes orphans on a schedule.

### Deleting every upload

`./logstotal uploads:clean` deletes everything under `uploads/`, whatever its age: every stored log file and every output directory. The jobs stay in the database without their files. It asks for confirmation, and it is not a substitute for the retention settings below.

## Automatic row retention

Workers run these tasks on a fixed schedule. They run only while at least one worker is up: the **Scheduled** tab on `/admin/tasks` shows when each last ran and when it runs next, which is how you notice that a stopped worker has stopped them all.

| Time (UTC) | Removes | After | Setting |
|-----------|---------|-------|---------|
| 03:00 | Revoked API tokens | 90 days | fixed |
| 03:30 | Enrichment results not fetched again | 30 days | fixed |
| 04:15 | Webhook delivery history | 30 days | `WEBHOOK_DELIVERY_RETENTION_DAYS` |
| 04:30 | Deleted comments | 180 days | fixed |
| 04:45 | Raw tool output directories | 90 days | `JOB_OUTPUT_RETENTION_DAYS`, or the override on `/admin/storage` |
| 05:00 | Activity log entries | 90 days | `ACTIVITY_RETENTION_DAYS` |
| 05:15 | Finished background task records | 30 days | `BACKGROUND_TASK_RETENTION_DAYS` |
| 05:30 | Uploaded log files **and their jobs** | never (off) | `UPLOAD_RETENTION_DAYS` |
| every hour at :20 | — refreshes rule lists that have a source URL | | per list |

For each setting, `0` turns that task off and keeps the data forever. `UPLOAD_RETENTION_DAYS` is `0` by default: the other tasks remove derived data, while this one deletes the logs users submitted, so it must be switched on deliberately. The windows marked *fixed* cannot be changed.

An upload's age counts from the newer of its upload and the most recent job that references it. Identical content is stored once, so a new job on it (a re-upload as a new job, or **Resubmit**) keeps the file and every job on it for another full window. Re-uploading content that returns an existing job does not start a new window.

Deleting a comment blanks its text at once and keeps a record of who deleted it and when; that record is what is removed after 180 days.

### Rule lists from a source URL

A list under **Rules → Lists** can name a source URL and a refresh interval. The hourly task fetches only the lists whose interval has passed. A list set to **Only when I press Refresh** (the default) is never fetched by the schedule; **Refresh now** on the list's form fetches it immediately and reports the result.

**A failed fetch keeps the values the list already has.** A feed that returns an error, times out or comes back empty must not empty a list your rules test: every rule naming it would silently stop matching. The failure is recorded on the list instead, shown in red on the Lists tab with the reason in its tooltip.

The feed is one value per line. Lines starting with `#`, `;` or `//` are ignored; values are lowercased, deduplicated and validated like a pasted list.

Fetches are restricted: `RULE_LIST_REQUIRE_PUBLIC_HOST` (default `true`) refuses private and internal addresses, redirects are not followed, and the response is capped at `RULE_LIST_FETCH_MAX_BYTES`. See [Configuration](../configuration.md).

---

**Related:** [Back up and restore](backup-and-restore.md) · [Admin UI reference](../reference/admin-ui.md) · [Known limitations](../limitations.md#storage-and-retention)
