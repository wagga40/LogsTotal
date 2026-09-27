# Multiple log files and ingestion API

How to submit several log files at once from the browser, and how to submit and track jobs from a script with an API token.

Each file is an independent analysis job. A case can group any number of jobs; it does
not become a combined analysis job. Existing compatible submissions can reuse a job
under the same ownership, filename, privacy, workflow and log-type rules as the browser.

## Browser

Drop or select files on the homepage, up to the limit shown there (50 by default).
Administrators can change **Settings → Submissions → Maximum files per submission**
to 1–500; reload the upload page to pick up the change. This controls one browser
selection, independently of the API's per-file requests, upload concurrency and rate
quotas. LogsTotal previews two files at a time,
then selects a compatible workflow for each. Change individual types/workflows, or
apply a workflow to all compatible files. Unknown types need a compatible workflow or
a manual type choice; oversized files remain visible with an error and can be removed.

The selection stays in a compact, scrollable list with aligned type/workflow controls.
Resolve any invalid files, then submit the whole selection with **Analyze**. Two files
transfer at a time; the next transfer starts while earlier requests are being confirmed,
up to four in-flight requests (or the configured server limit when lower). Analysis starts
as each file is accepted. Per-file bars show transfer progress; the overall bar counts
confirmed submissions. The page explicitly confirms when it is safe to close the tab,
without waiting for analysis. A failed file does not discard successful submissions.
Quota/capacity responses pause the queue and retry according to `Retry-After`: five
seconds for a busy upload slot, sixty seconds for the per-minute quota.
For selections above 50 jobs, status polling rotates through groups of 50 to keep the
request rate constant; all accepted jobs continue processing between polls.

Members and admins can choose no case, an existing visible case, or a new unshared
case. Jobs link immediately, including reused jobs. Entity import remains an explicit
case action after analysis. Sharing a case does not grant access to private jobs.

Keep the tab open until uploads finish. There is no persistent batch page: closing the
tab loses its unsubmitted files, but accepted jobs remain in Jobs and their case.
**Stop uploads** stops waiting transfers and aborts active browser requests; it does not
cancel accepted analyses. A lost/aborted response may have reached the server. Signed-in
uploads use a receipt to check that outcome before retrying. Anonymous users should
check Jobs before manually retrying an uncertain upload.

## Authentication and scopes

Create tokens at `/admin/api-tokens`. Tokens delegate their creator's access, including
job privacy and case visibility; they expire when revoked, expired, or their creator
loses access. Supply `Authorization: Bearer <token>`. A supplied invalid token is rejected,
even if a valid browser cookie is also present. Only the `Bearer` scheme counts as a token:
the `Authorization: Basic …` header a browser resends behind the proxy profile's basic auth is
the proxy's credential, and requests carrying it fall back to the browser session. The same
header is why a token client cannot get through that basic auth at all — see
[Known limitations](../limitations.md#deployment).

Ingestion uses the `job:submit`, `job:read`, `case:write` and `case:read` scopes; what each
one grants is in the [token scopes table](admin-ui.md#token-scopes). Attaching an uploaded
job to a case needs `case:write` as well as `job:submit`.

Browser cookies are also accepted. Ordinary signed-in users can submit jobs; case
operations require member-or-above access. Anonymous browser submissions use
`POST /upload`. Anonymous status requests return public jobs only.

## Endpoints

All versioned endpoints return JSON. The OpenAPI schema is served only with `DEBUG=true`,
at `/api/docs` and `/api/openapi.json`, so a production instance does not expose it.

### Submit one file

`POST /api/v1/jobs`, multipart form data, with a `Content-Length` header. From any machine
that can reach the instance:

| Field | Meaning |
|---|---|
| `file` | Exactly one file, required |
| `workflow_id` | Required workflow ID from `GET /api/v1/workflows` |
| `log_type_override` | `auto` by default, or a supported log type |
| `is_private` | `false` by default |
| `force_resubmit` | `false` by default; `true` requests a fresh analysis |
| `case_id` | Optional existing case ID; requires `case:write` as well as `job:submit` |

```bash
curl --fail-with-body "$LOGSTOTAL_URL/api/v1/jobs" \
  -H "Authorization: Bearer $LOGSTOTAL_TOKEN" \
  -H 'Idempotency-Key: collection-2026-09-host-a-security' \
  -F 'file=@Security.evtx' \
  -F 'workflow_id=1' \
  -F 'case_id=42' \
  -F 'is_private=true'
```

A new job returns `202`; reuse and idempotent replay return `200`:

```json
{"job_id":123,"status":"pending","reused":false,"job_url":"/jobs/123","case_id":42}
```

`202` means accepted for background analysis, not completed. Files are not concatenated.
To submit a collection, loop over files with at most two requests in flight; assign
one idempotency key per logical file submission. Keep keys in the client if recovery
across process restarts is needed. Mixed formats can use different workflow IDs.

### Retry receipts

`Idempotency-Key` is optional for authenticated clients and must be 1–128 printable
ASCII characters without spaces. The browser supplies it automatically when signed in.
Keys are scoped to the creator's user and operation (`job` or `case`).

Repeating the same file and options with the same key returns the same job, even with
`force_resubmit=true`. Changed content, filename or options with that key returns `409`.
Concurrent retries create one job and enqueue it once. Receipts are committed with the
job and its case link, before queueing. A queue failure marks that job failed and leaves
the receipt available; an intentional new attempt needs a new key.

`GET /api/v1/submissions/{key}` resolves a lost response without retransmitting the file.
A `404` means no committed receipt yet, so the original request may still be running;
retrying with the same key safely resolves that race. A `410` means its job was deleted.
Receipt tombstones remain after job/case deletion to prevent replay from recreating
resources. Receipts are deleted with their owning account.

### Workflows, statuses and cases

- `GET /api/v1/workflows` returns `{"workflows":[{"id":1,"name":"…","log_types":["evtx"],"is_default":true}]}`.
- `GET /api/v1/jobs?ids=123,124` accepts at most 50 IDs and returns `jobs` with `job_id`,
  `status`, `total_findings`, `error`, and `job_url`. `unavailable_ids` covers missing and
  inaccessible jobs identically. Poll about every three seconds while active, less
  often in background tabs, and stop at `completed`, `partial`, `failed`, or `cancelled`.
- `POST /api/v1/cases` accepts `{"name":"Investigation","is_shared":false}` and returns
  `201` with `case_id` and `case_url`. An optional idempotency key makes creation safe to
  retry (`200` on replay). Create once and pass the returned ID to each upload.
- `GET /intel/cases/list.json` discovers existing visible cases (`case:read`).

Errors use `{"detail":"…"}` (validation errors may contain a detail list). Handle
`400/422` per file, `401/403` as authentication/permission errors, `409` as a key conflict,
`411/413` as transfer format/size errors, `429` by waiting for `Retry-After`, and `507`
as insufficient temporary storage. After an uncertain network/server failure, look up
the receipt before retrying. Other successfully accepted jobs remain unaffected.

## Capacity

| Setting | Default | Applies to |
|---|---|---|
| `MAX_UPLOAD_SIZE_MB` | 500 | Each file |
| `UPLOAD_RATE_LIMIT_PER_MINUTE` | 30 | Anonymous submissions, per IP |
| `AUTHENTICATED_UPLOAD_RATE_LIMIT_PER_MINUTE` | 60 | Authenticated submissions, per creator across cookies and tokens |
| `PREVIEW_RATE_LIMIT_PER_MINUTE` | 120 | Preview requests, per IP |
| `UPLOAD_MAX_CONCURRENT` | 4 | Active upload requests across web processes sharing Redis |
| `API_TOKEN_RATE_LIMIT_PER_MINUTE` | 120 | API reads and case creation, the IOC feed, TAXII and the case read APIs, per token |

A zero rate disables that quota. The concurrency setting has a minimum effective value
of one. Upload admission uses Redis before multipart parsing; if coordination is
unavailable, uploads return `503`. It reserves room for both parser and storage spools,
retains 1 GiB of free headroom, and releases reservations on completion or failure.
Reservations are renewed while uploading and expire after a dead process disappears.
Local disk and S3 use the same admission rules because both need local temporary files.

Upload concurrency does not change worker or tool concurrency.

The default `HUEY_QUEUE_EXPIRY=1800` discards jobs not started within 30 minutes. Size
the workers and that setting for the longest wait a large batch can cause, with headroom,
and watch the queue on `/admin/tasks`. A faster uploader cannot make an overloaded worker
fleet process more logs. See [Scaling](../scaling.md).

---

**Related:** [Admin UI reference](admin-ui.md) · [Configuration](../configuration.md) · [Scaling](../scaling.md) · [Known limitations](../limitations.md)
