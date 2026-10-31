# Explore and event indexes

A job's findings are what its rules matched. **Explore** is the rest of the log: every event
of the upload, searchable, charted and exportable, with the detected events marked. It runs
on an **event index** that LogsTotal builds itself from the upload, whichever detection
tools the workflow ran.

For the analyst's view (search syntax, the histogram, fields, the event panel, keys), see
**Explore every event** in the in-app documentation (`/docs#explore`). This page is for
operators.

## Who can use it

| | Admin | Member | User | Anonymous |
|---|---|---|---|---|
| Explore a job, export its events | yes | yes | their own jobs | no |
| Full process tree on the job page | yes | yes | their own jobs | no (hit-anchored tree) |

Explore always applies the job's own visibility first: a private job stays visible only to
its submitter and admins. Every refusal answers exactly like a job that does not exist.
Explore needs both `EVENTS_ENABLED` (environment) and **Explore** on `/admin/settings`.

## How an index is built

1. When a worker picks up a job, it asks for an index of the upload. One index serves every
   job on the same file and log type, so a re-run reuses it.
2. A worker thread builds it in a supervised subprocess, beside the detection tools:
   LogsTotal parses every event (EVTX, EVTX-JSON, winlogbeat, EVTX-XML, Sysmon for Linux,
   auditd, journald, syslog), flattens it, types each field from all of its values, and
   writes Parquet files. The subprocess is niced and killed past
   `EVENTS_BUILD_TIMEOUT_SECONDS` or `EVENTS_BUILD_MAX_RSS_MB`.
3. Once both the index and the job's analysis have finished, a second small task links the
   job's detections to the indexed events (the *overlay*). Windows events link on
   computer, channel and record id. Linux text logs link on the best available hint and
   only where it picks out exactly one event; the rest are counted, never guessed.

Jobs analysed before indexes existed show **Build event index** on their Explore tab
(**Build event index on request** on `/admin/settings`). A build that fails is retried
three times by the 10-minute sweep; the button retries again after that.

Measured: a 213 MB EVTX (184k events) builds in 6.5 s into an 11.5 MB index.

## Where indexes live

Indexes are stored with the uploads, through the same storage backend, under
`events/{sha256}/{generation}/`; each job's overlay sits beside its index under
`overlays/job_{id}/`. They are a **derived cache**: deleting one loses nothing, it is
rebuilt from the upload on request.

- Deleting an upload deletes its indexes; deleting a job deletes only its overlay.
- `EVENTS_RETENTION_DAYS` evicts an index nobody opened for that long, and
  `EVENTS_MAX_TOTAL_MB` caps their total size, least recently opened out first.
- The storage page counts indexes separately, and lists any that no database row owns as
  orphans.
- On S3, the web server keeps a local copy of recently opened indexes under
  `.events_cache/stores/`, up to `EVENTS_CACHE_MAX_MB`. The first open of an index shows a
  short "fetching" state.
- `.events_cache/matches/` keeps the answers to expensive searches (free text, column
  sorts, deep pages) and trims itself. Both are reported, never offered for deletion.

## Limits

| Setting | Default | What it bounds |
|---|---|---|
| `EVENTS_MAX_EVENTS` | 5,000,000 | Events stored per upload; past it the index says it is truncated |
| `EVENTS_MAX_COLUMNS` | 4,096 | Distinct fields stored as columns; the rest are kept in one JSON column and are searchable as text |
| `EVENTS_QUERY_TIMEOUT_SECONDS` | 10 | A search running longer is stopped and the page says so |
| `EVENTS_MAX_CONCURRENT_QUERIES` | 2 | Searches at once per web process; another waits, then retries |
| `EVENTS_EXPORT_RATE_LIMIT_PER_MINUTE` | 5 | Exports per user per minute |

Exports are capped at 500,000 rows (CSV, visible columns) and 100,000 (NDJSON, every
field), and each is recorded in the activity log as **Job events exported**, with the
search that produced it. Every setting is listed in [Configuration](../configuration.md).

## Turning it off

`EVENTS_ENABLED=false` stops new builds and hides Explore everywhere; existing indexes stay
on disk until retention or a delete removes them. **Explore** off on `/admin/settings` hides
the tab without stopping builds.
