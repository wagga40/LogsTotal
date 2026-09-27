# Known limitations

The caps, the deliberate omissions, and what is not built — so you find out what LogsTotal won't do without reading the source.

## Platform support

- **Tested on Ubuntu and Debian only.** macOS works for local development. Other Linux
  distributions probably work and are not exercised. The fleet deploy checks every host's
  OS, warns on anything outside the tested set, and continues.
- **Desktop browser, 1024px or wider, with JavaScript enabled.** The viewport is pinned at
  `width=1024` and the stylesheet has no `@media` rules, so a narrow screen scrolls the
  desktop layout instead of reflowing it. Submitting a file needs scripting — the file
  picker, the log-type preview and the workflow list are all script-driven, and the upload
  card says so with scripting off. There is no mobile layout and none is planned.
- **Zircolite runs as a Docker container**, so the default workflows need a reachable
  Docker daemon even on a "bare metal" install, and the worker mounts the host's Docker
  socket — see [Docker socket on workers](security.md#docker-socket-on-workers). Chainsaw,
  Hayabusa and ChopChopGo ship as binaries in the release and need nothing.
- **No macOS build of ChopChopGo**, so the Linux syslog workflow produces nothing when the
  worker runs directly on a Mac (local development). `./logstotal doctor` reports this as a
  **FAIL** rather than a warning: a workflow whose only task cannot run returns an empty
  report.
- **SQLite → PostgreSQL migration is scripted but one-way.** There is no reverse path and
  no live cutover — the app must be stopped while the data is copied. See
  [Move from SQLite to PostgreSQL](runbooks/sqlite-to-postgres.md).

## Deployment

- **`DOMAIN` cannot be an IPv6 literal.** The Caddy entrypoint validates it against
  letters, digits, `.` and `-` before interpolating it into the Caddyfile, which is what
  stops a value from `.env` injecting directives. An IPv4 literal passes; `[::1]` does not,
  because the brackets and colons are exactly what the guard exists to reject. Use a
  hostname — on an internal network a `/etc/hosts` entry is enough.
- **`DOMAIN` cannot carry a port either**, for the same reason. The bundled Caddy serves
  ports 80 and 443; for anything else, run your own proxy in front with `PROXY_TLS=off`.
- **`PROXY_TLS=internal` needs one manual step per client.** Caddy's own CA is not trusted
  by anything until you copy its root out and install it — see
  [Air-gapped and internal networks](install/https.md#air-gapped-and-internal-networks).
- **The bundled proxy terminates TLS for one name.** Multiple hostnames, SNI routing or a
  wildcard across several sites mean running your own proxy in front with `PROXY_TLS=off`.
- **API tokens do not work through HTTP basic auth.** A request carries one `Authorization`
  header, and the proxy (`BASIC_AUTH_USER` / `BASIC_AUTH_HASH`) takes it for its own
  password, so ingestion, the IOC feed and TAXII cannot authenticate through it. A token
  works only for a client that reaches the app without going through the proxy, and the
  proxy profile binds `WEB_PORT` to loopback, so that means a script on the same host
  calling `http://127.0.0.1:8000`. To use tokens from elsewhere, restrict the instance by
  network instead of basic auth (see [Restricting access](security.md#restricting-access)).
  `/admin/api-tokens` shows a notice when your own browser reached it through basic auth.

## Analysis

| Limit | Value | What happens at the edge |
|---|---|---|
| Events parsed per **job** for analytics | 250,000 (`MAX_PARSE_EVENTS`) | A job-wide budget shared across every tool's output, not a per-file one — four outputs do not get 250,000 each. Parsing stops there; findings are unaffected (they come from the tools), but analytics and the timeline describe a prefix of a very large job |
| Timeline markers held while parsing | 250,000 | The accumulator coarsens its time buckets in flight rather than dropping alerts |
| Markers returned per timeline request | 2,000 | The view coarsens to fit and reports `truncated`; zooming in restores detail |
| Process-tree nodes | 2,000 | Truncated during the parse, so a client-side filter cannot reach a process beyond it. Entity-anchored views prune server-side for this reason |
| Process-tree chain depth | 100 | A chain running deeper is split and the continuation re-rooted as a separate chain (nothing is dropped); the view says so. Depth is bounded separately from node count, because every consumer of the forest recurses once per level |
| Stored tool stdout/stderr per task | `MAX_LOG_OUTPUT_BYTES` (50 KB) | Truncated at write time |

Analytics, entity extraction and the timelines are all parsed from the raw tool output on
disk. **Once that output is cleaned up, they cannot be recomputed** — the stored results
survive, but "Recalculate analytics" declines rather than replacing them with an empty
result.

## Intel

| Limit | Value | Note |
|---|---|---|
| Entities labelled per built-in rule per job | 5,000 | A label must reach every match; the ones past a cap look unlabelled rather than truncated |
| Entity rules evaluated per job | 200 | Oldest-first; a busy instance should prune rules rather than rely on the tail |
| Job rules evaluated per job | 100 | Oldest-first; a separate budget so entity rules cannot starve them |
| Alerts raised per entity rule per job | 100 | Prevents one broad rule flooding the bell |
| Entities in a webhook payload | 50 | The true total is still reported in the payload |
| Webhook response body | not read | Only the status code is recorded; the connection closes after it, so the channel cannot be read back |
| Sample events kept per relationship per job | 3 | The per-job *count* is exact; only the examples are capped |
| Relationship rows on the entity tab | 1,000 | |
| Graph nodes / edges | 5,000 / 15,000 | Defaults are far lower (30 neighbours, 1 hop); these are the ceilings |
| Graph nodes when scoped to one job | 1,500 | |
| Graph export (GraphML) | 500 nodes / 25,000 edges | Budgeted separately, so raising the view caps does not silently widen exports |
| Case STIX / MISP / IOC-pack export | 200 entities, 200 jobs | The most recent members; the payload sets `truncated` |
| Comment body / thread page | 4,000 chars / newest 100 | The true total is always shown |
| Tags per `tag:` query | 10 | |

Two more:

- **The graph's `total_nodes` is unknown outside job scope.** A traversal never learns the
  true size of the graph it is walking, so the truncation banner can only say "top N" —
  except when scoped to a job, where the reachable set is known exactly.
- **The existence of a typed entity relationship is not visibility-filtered**, while
  everything derived from it — evidence, per-job counts, timespans — is.
  [Security trade-offs to understand](security.md#security-trade-offs-to-understand) states
  the boundary precisely.

## Storage and retention

- **Jobs, findings, entities and cases accumulate** until an admin removes them. Uploaded
  files are kept too, unless you set `UPLOAD_RETENTION_DAYS`. What *is* pruned
  automatically — raw tool outputs and a handful of log-like tables — and when, is in
  [Storage and retention](runbooks/storage.md).
- **Raw tool outputs are deleted** after `JOB_OUTPUT_RETENTION_DAYS` (default 90).
  Findings, analytics and the events timeline survive that; the activity histogram, the
  process tree and the raw-output ZIP export do not.
- **Orphans are found, not swept.** `/admin/storage` detects objects whose database rows
  have gone — on either backend — and offers to purge them, but nothing removes them on a
  schedule: reclaiming storage nothing claims is a decision, not a default.

## Scale

- **SQLite is the default and is single-writer.** It is fine for one host with a couple of
  workers; past that, use PostgreSQL. `./logstotal doctor` warns when the worker count and SQLite
  are a bad match.
- **Case aggregations are not paginated, deliberately** — the summary, timeline and pivot
  panes are aggregates, and capping them would make the numbers wrong. The Timeline tab
  re-reads every linked job's raw output; each finished job's result is cached in Redis for
  15 minutes, so repeat views are fast, but the first view of a case with very many jobs —
  and the first after the cache expires — is the slowest page in the application.
- **Analysis is per-file.** There is no cross-file correlation beyond fuzzy similarity and
  shared rule signatures.

## Not built

Called out because they are reasonable things to expect:

- No multi-tenancy. Roles are instance-wide; there are no organisations or per-team
  boundaries beyond a submission being private.
- No alerting transports other than webhooks — no email, no native Slack or Teams app.
- Ingestion supports multiple browser files and a scoped token API, but not persistent
  batch history, resumable transfers, folder traversal or archive extraction. See
  [Multiple log files and ingestion API](reference/ingestion-api.md). The IOC feed, STIX/MISP exports
  and TAXII server remain read-only.
- No LDAP, SAML or OIDC. Local accounts only.
- **The activity log is not tamper-proof.** It records what happened through the
  application, in the same database as everything else, so anyone with database access can
  alter it. Ship the JSON process logs elsewhere if you need an append-only copy.
- **Cancelling a background task takes effect at its next batch boundary** (100–500 rows,
  depending on the task), not immediately. Everything it had already finished is kept: the
  expensive backfills commit per item, so the boundary bounds when it *stops*, not how much
  is thrown away. A cancelled output cleanup does not restore the directories it removed.
- No scheduled or watched-directory ingestion — files are submitted, not collected.

---

**Related:** [Security](security.md) · [Storage and retention](runbooks/storage.md) · [Scaling](scaling.md) · [Docs index](README.md)
