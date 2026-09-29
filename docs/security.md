# Security

How to harden a LogsTotal deployment: the production checklist, rate limits, the trust boundaries to decide on per deployment, and what each outbound feature can reach.

To report a vulnerability, see [SECURITY.md](https://github.com/wagga40/LogsTotal/blob/main/SECURITY.md). This page is about hardening a deployment.

## Production hardening checklist

Before exposing LogsTotal on the public internet, confirm each of the following. Startup logs print `PRODUCTION SAFETY` warnings for items you miss — treat them as blocking, not informational.

**Required**

- [ ] `SECRET_KEY` is a fresh 64-char hex string (`python3 -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] `DEBUG=false`
- [ ] `COOKIE_INSECURE=false` (and TLS is terminated in front of the app)
- [ ] `DISABLE_CSP=false` (and `I_ACCEPT_DISABLE_CSP_IN_PROD` is unset)
- [ ] `ENABLE_HSTS=true` when serving HTTPS with a publicly trusted certificate
- [ ] Every `*_RATE_LIMIT_PER_MINUTE` set to non-zero — `0` means unlimited. There are nine: `UPLOAD_`, `AUTHENTICATED_UPLOAD_`, `PREVIEW_`, `LOGIN_`, `RESUBMIT_`, `API_TOKEN_`, `AI_`, `ENRICHMENT_`, `WEBHOOK_`. `API_TOKEN_` guards the token APIs (ingestion reads, the IOC feed, TAXII, the case APIs); `WEBHOOK_` and `ENRICHMENT_` bound *outbound* traffic a member can cause
- [ ] `TRUST_PROXY_HEADERS=true` **only if** behind a trusted reverse proxy, with `TRUSTED_PROXY_CIDRS` pinned to the actual proxy CIDRs (never `*` unless ingress is fully trusted)
- [ ] `ADMIN_PASSWORD` is not a default, and the admin password has been changed after first login

**Operational**

- [ ] Backups scheduled via cron (see [Backup and restore](runbooks/backup-and-restore.md))
- [ ] `JOB_OUTPUT_RETENTION_DAYS` reviewed — it is `90` by default and a daily sweep enforces it (see [Storage and retention](runbooks/storage.md))
- [ ] The upload volume has room for many maximum-size uploads; the app refuses new ones below 1 GiB free, but that is a floor, not a plan
- [ ] `/admin/workers` shows every expected worker live, with fresh heartbeats
- [ ] Log rotation is configured for Caddy or your own proxy (`docker-compose.yml` caps container logs at 10 MB per file, three files)
- [ ] With the bundled Garage: `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `GARAGE_RPC_SECRET` and `GARAGE_ADMIN_TOKEN` set to generated values (`./logstotal gen-secrets -- --write`) — Compose falls back to fixed placeholders when they are unset
- [ ] You have decided what to do about the [Docker socket on workers](#docker-socket-on-workers)

**Minimal `.env` excerpt**

```bash
DEBUG=false
COOKIE_INSECURE=false
DISABLE_CSP=false
ENABLE_HSTS=true
SECRET_KEY=<64-char-hex>          # python3 -c "import secrets; print(secrets.token_hex(32))"
UPLOAD_RATE_LIMIT_PER_MINUTE=30
LOGIN_RATE_LIMIT_PER_MINUTE=20
RESUBMIT_RATE_LIMIT_PER_MINUTE=10
TRUST_PROXY_HEADERS=true          # only behind a trusted reverse proxy
TRUSTED_PROXY_CIDRS=172.18.0.0/16 # match your Docker/proxy network — never use *
```

> [!NOTE]
> **Why `172.18.0.0/16` and not the loopback default?** `TRUSTED_PROXY_CIDRS` defaults to `127.0.0.1/32,::1/128` (loopback only). When Caddy — or any reverse proxy — runs as a container in the same Compose network, the app sees requests arriving from the proxy's **container** IP, not loopback, so you must trust that network's subnet. On the deployment host, find the actual subnet with:
>
> ```bash
> docker network inspect logstotal_default --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
> ```
>
> (`logstotal_default` assumes the install directory is named `logstotal`; Compose names the network after it.) Use the CIDR it prints — commonly `172.18.0.0/16`, but it varies per host. Never widen it to `*` unless the app is reachable solely through fully trusted ingress.

> [!IMPORTANT]
> **List every proxy hop, not just the last one.** `X-Forwarded-For` is built by appending: each proxy adds the address it saw to the right of whatever arrived, so the leftmost entry is whatever the original caller chose to send. LogsTotal therefore reads the chain **from the right** and returns the first address that is *not* in `TRUSTED_PROXY_CIDRS`.
>
> With one reverse proxy that is simply the client's real address. With two or more — a load balancer in front of Caddy, say — you must list all of them, or the client IP resolves to your own inner proxy and every per-IP rate limit shares one bucket.
>
> Leave the default in place behind a proxy and any caller can pick their own IP: the login, upload and resubmit limits all bucket per IP, so rotating the header would give a fresh quota on every request.

The app logs `PRODUCTION SAFETY` warnings at startup for risky setting combinations (DEBUG enabled, CSP disabled, weak SECRET_KEY, rate limits disabled, wildcard proxy CIDRs). Review startup logs after deployment and resolve all warnings.

## Restricting access

**LogsTotal has no in-app switch that makes the instance private.** Anonymous visitors can
submit files and read every non-private job by design — that is the shared, multi-engine
model the product is built around, and no setting turns it off.

Two things that look like one and are not:

- **`demo_mode`** (a site setting, `/admin` → Settings) blocks *submissions*. It does not
  restrict reading: an anonymous visitor still sees the job list and every public report.
- **`is_private` on a submission** hides one job from everyone but its submitter and
  admins. It is per-job, chosen at upload, and unavailable to anonymous submitters. It
  hides the *job*, not the observables extracted from it: those join the entity list,
  which is [instance-wide](#the-entity-list-is-instance-wide).

If the instance must not be world-readable, put the boundary in front of the app:

1. **Network** — bind it to a private interface or a VPN (WireGuard or Tailscale, as in
   [Fleet installation](install/fleet.md)). This is the option that actually restricts reads.
2. **Reverse-proxy auth** — the bundled Caddy profile supports HTTP basic auth
   (`BASIC_AUTH_USER` / `BASIC_AUTH_HASH`, see
   [Generating secrets and keys](configuration.md#generating-secrets-and-keys)). Coarse, but
   it covers every route including the anonymous ones — and it shuts out the token APIs: a
   token client cannot authenticate through it
   ([Known limitations](limitations.md#deployment)). Set **both** or neither: the entrypoint
   refuses to start if only one is present, but with *neither* set it renders a Caddyfile
   with no `basic_auth` block and no complaint — which a typo in either variable name looks
   exactly like. Verify with an unauthenticated `curl -sI https://your-host/` and check for
   `401`.

Neither changes the role model inside the app: once past the boundary, anonymous access
behaves exactly as documented in the
[access model](https://github.com/wagga40/LogsTotal/blob/main/README.md#access-model).

## Security escape hatches

Avoid these unless you know why you need them.

- **`DISABLE_CSP=true`** — strips the Content-Security-Policy header. Intended for local testing over an IP where the default CSP breaks script loading. With `DEBUG=false`, the app **refuses to start** with CSP disabled unless you also set `I_ACCEPT_DISABLE_CSP_IN_PROD=true`. Do not ship this to production.
- **`I_ACCEPT_DISABLE_CSP_IN_PROD=true`** — bypasses the refuse-to-start guard above. Use only as a deliberate, time-boxed workaround.
- **`COOKIE_INSECURE=true`** — drops the Secure flag on auth cookies so login works over plain HTTP. Turn off as soon as TLS is in front (see [Cookies over plain HTTP](configuration.md#cookies-over-plain-http)).
- **`DEBUG=true`** — serves the generated API documentation at `/api/docs` (Swagger), `/api/redoc` and `/api/openapi.json`, and disables Secure cookies. The schema is a complete route inventory, `/admin` included; with `DEBUG=false` none of the three is served. Never enable on an internet-facing host.

## Rate limit semantics

Rate limits are enforced **per bucket per minute, in Redis** (`logstotal:ratelimit:*`), so the number you configure is the limit for the **whole deployment** — adding web processes or replicas does not multiply it. If Redis is unreachable the middleware falls back to per-process in-memory counters and logs a warning; only in that degraded state does a deployment with _N_ web processes effectively allow _N_ × the limit.

What each request is counted against:

- **Per client IP:** anonymous uploads (`/upload`), file-type previews (`/detect-preview`), login and resubmit.
- **Per account:** authenticated uploads — through `/upload` or `POST /api/v1/jobs` — count against `AUTHENTICATED_UPLOAD_RATE_LIMIT_PER_MINUTE`, shared by the account's browser sessions and tokens.
- **Per token:** requests under `/api/v1/` (status reads and case creation), `/intel/ioc-feed`, `/taxii2/` and `/intel/cases/` are counted per **Bearer token** when one is present, so two tokens from the same host do not share a quota. Without a token they fall back to the client IP — except `/intel/cases/`, which is limited only for token requests, because the same prefix serves the browser's case pages.

The window is anchored to its first request, not its last: the counter expires one minute after the request that opened it, regardless of how much traffic follows. `0` disables a limit entirely.

The client IP is resolved through `TRUST_PROXY_HEADERS` / `TRUSTED_PROXY_CIDRS` — misconfigure these and all traffic appears to come from your proxy, making the IP-bucketed limits useless. Behind a reverse proxy, set `TRUST_PROXY_HEADERS=true` and pin `TRUSTED_PROXY_CIDRS` to the actual proxy network (never `*` except for fully trusted ingress).

## Sizing and abuse

Uploads are anonymous. Request bodies and upload rates are bounded independently. Do the
arithmetic for your deployment before exposing it:

| Knob | Default | What it bounds |
|---|---|---|
| `MAX_UPLOAD_SIZE_MB` | 500 | File bytes; the multipart request allows an additional 1 MiB |
| `UPLOAD_RATE_LIMIT_PER_MINUTE` | 30 | Anonymous uploads per client IP per minute, deployment-wide |
| `UPLOAD_MAX_CONCURRENT` | 4 | Uploads being received at once, across all web processes |

At the defaults a single IP can offer 15 GB per minute, and **nothing caps the total
volume** — not per user, not per day, not across IPs. There is no quota system, and adding
one is not planned; a public instance should sit behind a proxy that enforces whatever
ceiling you need.

What the application does:

- **It refuses an upload with `507`** when accepting it would leave less than 1 GiB free,
  counting the uploads already in progress. This matters because the database, the tool
  outputs and the uploads share one volume on a single host — a full disk does not merely
  reject the next upload, it makes SQLite fail writes and takes the app down.
- **It deletes raw tool outputs** after `JOB_OUTPUT_RETENTION_DAYS` (default 90).
- **It keeps uploaded files** until you set `UPLOAD_RETENTION_DAYS` (off by default); a
  daily sweep then deletes older files together with their jobs. Deleting a job by hand
  removes its upload when no other job references it.
- **It finds orphaned files but does not sweep them on a schedule.** `/admin/storage` lists
  stored objects whose database rows are gone — on local disk or S3 — and **Purge orphans**
  removes them.

The schedules, and what survives each sweep, are in
[Storage and retention](runbooks/storage.md). Watch the disk gauge on `/admin`.

## Submission and input isolation

Every request body has a size limit enforced while it streams in, before any form or JSON
parsing: 1 MiB normally, 256 KiB for file-type previews, and `MAX_UPLOAD_SIZE_MB` plus
1 MiB of multipart overhead for uploads. The limits stay active with rate limiting
disabled. Exceeding one returns `413` and discards the partial upload. Uploads and previews
require a `Content-Length` header; other endpoints also accept bounded chunked bodies.

Imported rule documents are limited to 512 KiB. YAML aliases are rejected, nesting is
limited to 16 levels, and parsing stops after 100,000 events. Fields are type-checked
before conversion; validation reports contain at most 100 messages of 256 characters plus
a truncation notice.

Deduplication shares file bytes, not a submitter's filename or manual type override. Each
analysis stores its own filename and effective type, storage keys contain no submitted
filename, and auto-detection reads the content, duplicates included. A filename that
cannot be attributed to a submission is shown as `upload-<12-character SHA-256 prefix>`;
the shared original is shown only to administrators, on the job page. Search and exports
use the submission's own name or that neutral fallback.

Tag changes never put a tag name in the URL. Clients POST to `/intel/tags/rename`,
`/intel/tags/merge`, `/intel/tags/recolor` or `/intel/tags/delete` with a `tag` form
field, and remove a tag from a job or an entity with POST `/jobs/{id}/tags/remove` or
`/intel/entities/{id}/tags/remove`, also with `tag` in the form. Tag names may contain `/`.

## CSRF protection

State-changing requests (`POST`/`PUT`/`PATCH`/`DELETE`) that carry the `logstotal_auth` cookie must present an `Origin` or `Referer` header matching the request's `Host`; otherwise they are rejected with **403**. Anonymous requests — including `/upload` and login — are unaffected, as is `POST /auth/cookie/logout` (browsers strip `Origin` on some redirect flows, and logout is a no-op when not logged in).

The check needs no configuration, but it has one operational consequence: **your reverse proxy must not rewrite `Host` without also rewriting `Origin`.** If authenticated form posts start failing with `CSRF validation failed`, compare the two headers the app receives — a proxy setting `Host` to an internal name while the browser sends the public origin is the usual cause.

API clients using a Bearer token are unaffected: the check only engages when the auth cookie is present.

## Docker socket on workers

**What it is.** Every worker container bind-mounts the host's Docker socket,
`/var/run/docker.sock` (in both `docker-compose.yml` and `docker-compose.worker.yml`). It is
there for one reason: Zircolite runs as a container, so the worker asks the host's Docker
Engine to start it, with the job's files mounted in. Chainsaw, Hayabusa and ChopChopGo run
as binaries inside the worker and do not use it.

**Access to that socket is root on the host.** Anything that can talk to it can start a
privileged container with the host's filesystem mounted.

**When it matters.** Uploads come from untrusted users — anonymous visitors, by default —
and the worker parses every one of them, through the detection tools and through
LogsTotal's own analytics. A parser bug that gave an attacker code execution inside the
worker would reach the socket, and through it the host. Workflows are the other path: the
`docker_image`, `docker_options`, `tool_path`, `rules_path` and `extra_args` fields end up in
a command line or a container definition, so the admin accounts that can edit workflows
effectively have root on every worker host. Treat worker hosts like build servers —
dedicated to this job, not shared with other workloads — and keep workflow editing to
people you would give root.

There are two ways to reduce the exposure. Neither is tested by LogsTotal's CI, so check
the result on your own host as shown below.

### Without the Docker-run tool: drop the mount

Without the socket every Zircolite task fails: four of the six shipped workflows run
nothing else, and the full Windows workflow finishes with a failed task. Do this only if
you do not use those workflows, or have replaced them with your own (see
[Detection tools and workflows](runbooks/detection-tools.md)). Then, in the install
directory, create `docker-compose.override.yml`:

```yaml
services:
  worker:
    volumes: !override
      - ./data:/data
      - ./uploads:/app/uploads
```

`!override` replaces the worker's volume list instead of merging with it, which is what
removes the socket. It needs a recent Docker Compose (2.24 or later; `docker compose
version`), so confirm the result with the checks below. Apply it with
`./logstotal docker:up`.

### Behind a socket proxy

[tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) sits
between the worker and the socket and forwards only the parts of the Docker API you enable.
The worker needs to inspect and pull the tool image, and to create, start, wait for, read
the logs of, stop and remove containers. In the install directory, create
`docker-compose.override.yml`:

```yaml
services:
  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy:v0.5.0
    restart: unless-stopped
    environment:
      CONTAINERS: 1   # create, start, wait, logs, kill, remove
      IMAGES: 1       # inspect and pull the tool image
      POST: 1         # allow write calls; sections not enabled above stay refused
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  worker:
    environment:
      - DOCKER_HOST=tcp://docker-socket-proxy:2375
    volumes: !override
      - ./data:/data
      - ./uploads:/app/uploads
    depends_on:
      docker-socket-proxy:
        condition: service_started
```

Then run `./logstotal docker:up`. `v0.5.0` is the latest release of the proxy at the time
of writing; pin whichever release you have reviewed. Keep the proxy on the Compose network
only — never publish its port. The worker keeps `DOCKER_HOST_WORKDIR`: job files are still
mounted into the tool container by their host path, because the host's Docker Engine still
runs it. `:ro` on the socket stops the proxy container replacing the socket file; it does
not limit the API — the environment variables do that.

A proxy narrows the API; it does not make the socket safe. With `CONTAINERS` and `POST`
enabled, code running in the worker can still create a container with the host's
filesystem mounted. What the proxy refuses is the rest of the API — exec sessions,
networks, volumes, image builds, swarm, secrets and system-wide calls.

### Check the result, and keep it

On the host, in the install directory:

```bash
docker compose config | grep -E '^  [a-z-]+:$|docker\.sock'     # the socket appears under docker-socket-proxy only (or nowhere)
docker compose exec worker test -S /var/run/docker.sock && echo "socket still mounted" || echo "socket not mounted"
```

Then run a job with a workflow that uses Zircolite and confirm its task succeeds. A refused
API call shows up as a `403` in `docker compose logs docker-socket-proxy`.

Two things to know about the override file:

- **Compose reads `docker-compose.override.yml` only when no `-f` is given.**
  `./logstotal docker:up` qualifies, so this covers a single host and the control plane's
  own worker. A dedicated worker host runs `docker compose -f docker-compose.worker.yml` —
  in `./logstotal docker:worker-up` and in every fleet `deploy`, `deploy:start` and
  `upgrade` — which ignores the override. There, start the worker by hand with both files
  (`docker compose -f docker-compose.worker.yml -f docker-compose.override.yml up -d`), and
  do it again after every deploy or upgrade, which restarts the worker with the socket.
- **It is yours to keep.** Upgrades and deploys leave `docker-compose.override.yml` in
  place, like `.env`, and no release ever ships one. Re-run the checks above after an
  upgrade that changes the worker service.

## Security trade-offs to understand

These are intentional posture choices — not bugs — but they change the trust boundary and deserve a conscious decision per deployment. The largest one, the Docker socket on workers, has [its own section](#docker-socket-on-workers).

**Job discussion threads are visible to every logged-in user.** Cases and entities are member-and-above surfaces, but a job's comment thread is readable and writable by *any* account that can already view the job — including `role=user`. That is deliberate (triage notes belong with the report), but it means analyst commentary on a public job is visible to every account on the instance. Anonymous visitors never see the panel, and a private job's thread is invisible to everyone but its submitter and admins. If your `role=user` tier is untrusted, keep sensitive triage on private jobs or in cases.

<a id="the-entity-list-is-instance-wide"></a>**The entity list is instance-wide.** An entity is a shared observable, not a per-job record, so the Intel dashboard, the entity page, the IOC feed (`/intel/ioc-feed`) and TAXII (`/taxii2/`) all list every entity on the instance — including values that only a private job ever contained. Every member can read these surfaces, and so can an API token with `ioc_feed:read` or `taxii:read`. A token carries its creator's visibility, but that changes nothing here. The boundary:

- **Unfiltered:** the entity's value and type, and the counters kept on the entity row — `job_count`, `first_seen` and `last_seen`. They are totals across every job, private ones included, and the two timestamps are ingest times: for a value that only a private job saw, they record roughly when that job was analysed.
- **Filtered to the viewer's visible jobs:** everything read out of a job — the entity page's job list, events and findings, and the IOC feed's `threat_categories` and `max_severity` (with the STIX labels and MISP attributes built from them). A member never learns the private job's id, filename, events or threat context — only that the value exists here, how many jobs saw it, and when.

The **Allowlist** toggle is not an access control: it removes an entity from TAXII and from the default dashboard and IOC-feed output, but `include_allowlisted=1` brings it back for any member. If an observable must stay with its submitter, analyse it on an instance other members cannot reach.

**Typed entity relationships are global, not per-job.** Every other graph edge is filtered through the viewer's visible jobs: a "shared job" or "same Sigma finding" edge never reveals that two entities co-occurred inside a private job. Typed edges (`resolves_to`, `hashes_to`, …) are the exception — a typed relationship is an aggregate across jobs with no job of its own, and the entity **Relationships** tab lists them unfiltered by design, so filtering only the graph would hide the edge while leaving the same fact one click away.

The boundary is precise, and typed edges are where it matters — they are the only kind drawn with an arrow and a label, and the only kind a path traverses:

- **Unfiltered:** the *existence* of a typed edge, its type, and its total occurrence count. A member can learn that `evil.example` resolves to `1.2.3.4`.
- **Filtered to the viewer's visible jobs:** everything *derived* from that edge — the evidence rows and per-job counts on the **Evidence** expander, the sample events, and the observed-time window the graph's edge panel shows (`/intel/relationships/{id}/timespan.json`). A member never learns a job id, a filename, a timestamp, or an event body from a private job.

If the bare existence of a relation matters for your tenancy model, keep the affected observables out of shared instances — the per-entity **Allowlist** toggle also removes an entity from the IOC feed.

Scoping the graph to a job (`?job=`) does **not** change that boundary. Typed edges stay unfiltered under a job scope for the same reason they are unfiltered without one, and because the per-job record of a typed edge is captured only as jobs are analysed and keeps a capped sample — filtering through it would silently drop edges. The node set is already job-scoped, so a typed edge inside a scoped graph is a true statement about two entities that job saw — it is simply not a statement about that job, and the graph's in-canvas help says exactly that. Node *colour* (worst severity, dominant tactic, enrichment verdict, case membership) is likewise global: those are properties of the entity across everything the viewer can see, and case membership has no job dimension at all.

**A job id in a URL is a reference to someone else's submission.** Every filter that accepts one — `/intel?job=`, `/intel/entities/{id}?job=`, the entity tab panes, both graph endpoints, `/intel/cases/{id}/graph.json?job=`, and both process-tree routes — checks it against the jobs the viewer can see and, where applicable, against membership in the entity or case. All of them collapse "no such job", "private job" and "job unrelated to this entity/case" into **one indistinguishable response**, so the parameter cannot be used to enumerate job ids. The graph endpoints return an empty graph rather than dropping the filter (dropping would widen the view); everywhere else the filter is dropped with a single message.

**The Content-Security-Policy allows `unsafe-eval` and `unsafe-inline` for scripts.** Alpine.js evaluates every `x-data`/`x-show`/`@click` expression through the `Function` constructor, and the page templates carry inline `<script>` blocks and inline component definitions. Removing either directive would mean switching to Alpine's CSP build and rewriting every inline expression. What the policy does buy you:

- `default-src 'self'` plus `img-src 'self' data:` — no third-party origin can be contacted, and nothing loads from a CDN. Every third-party asset is served by the app itself.
- `base-uri 'none'` — an injected `<base>` cannot silently repoint every relative URL on the page, including the script tags.
- `form-action 'self'` — an injected form cannot post a cookie-authenticated write to an attacker's host.
- `object-src 'none'`, `frame-ancestors 'self'` — no plugins, no framing from another origin.

So the CSP is a useful exfiltration and redirection control, and **not** an XSS mitigation. The XSS defence is upstream of it: template autoescaping everywhere, and a Markdown renderer configured so dangerous output is never produced rather than scrubbed afterwards (raw HTML is escaped, bare URLs are not auto-linked, images are off).

**Bundled Garage secrets are readable inside its container.** `docker-compose.yml` sets `GARAGE_ALLOW_WORLD_READABLE_SECRETS: "true"` for the `garage` service, and the configuration Garage generates at start holds its secrets. That is fine on a single host where only Garage reads that file, but anyone with a shell in the container can read the S3 credentials. For multi-tenant or hardened fleets:

- Use managed S3 (AWS S3, Cloudflare R2, …) instead of the bundled Garage, and keep its credentials only in each host's `.env`. Workers write their outputs to S3, so they need read-write credentials.
- If you keep the bundled Garage, make sure `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `GARAGE_RPC_SECRET` and `GARAGE_ADMIN_TOKEN` are generated values, not the placeholders Compose falls back to (`./logstotal gen-secrets -- --write`).

## Live enrichment

Enrichment services are configured by an **admin**, not by members, and each one names a
third-party API that entity values are sent to on demand. Two consequences follow, and they
point in opposite directions from the webhook posture below.

**Outbound targets must be public by default** (`ENRICHMENT_REQUIRE_PUBLIC_HOST=true`).
This is the opposite default to `WEBHOOK_REQUIRE_PUBLIC_HOST` and `AI_REQUIRE_PUBLIC_HOST`,
and deliberately so: a threat-intel API lives on the public internet by definition, so a
loopback or RFC1918 address in an API template is either a mistake or an attempt to reach
something internal. A webhook receiver and a local model are the reverse — usually yours,
usually on your own network.

Set it to `false` when you genuinely have an internal service to reach: a self-hosted MISP
or OpenCTI, or a local stub while you are working a template out. What the switch does
**not** relax:

- cloud-metadata addresses (`169.254.169.254` and friends) are refused either way;
- the connection is still pinned to the address that was validated, so a DNS rebind cannot
  swap in a different host after the check;
- redirects are not followed, so a 302 cannot walk the request somewhere else;
- the response is capped at 64 KB while streaming, and a per-service rate limit applies.

**The decrypted API token is never logged and never stored with an error.** A failed
lookup records the exception *type*, not its text, because the URL that produced it carries
the token.

Note that the stored response *is* kept, unlike a webhook's: enrichment exists to show you
the answer. Treat stored enrichment results as third-party data of unknown sensitivity when
you plan retention.

## Rule webhooks

Members create their own rules and may point each one at a webhook URL they type
themselves. **Private and internal hosts are permitted by default** (`WEBHOOK_REQUIRE_PUBLIC_HOST=false`),
because a self-hosted deployment almost always posts to an internal Mattermost, n8n or SIEM
on RFC1918. This is a deliberate posture choice with two distinct consequences, and they
need separate decisions.

**1. Blind SSRF against your internal network.** Any member can make a worker issue a
signed POST to any address the worker can reach. The mitigations in place do not remove
that primitive; they bound what can be done with it:

- member-or-above only — `role=user` and anonymous visitors cannot create rules;
- redirects are not followed, so a 302 cannot walk the request somewhere else;
- the response body is **never read**, stored, logged or shown; the connection closes after
  receiving the status, so a slow body cannot hold a worker;
- a 5-second total HTTP deadline (DNS validation happens before it), and a per-rule rate
  limit (`WEBHOOK_RATE_LIMIT_PER_MINUTE`), with over-limit deliveries recorded and dropped
  rather than retried;
- `169.254.169.254` and the other cloud metadata addresses are refused regardless of
  setting — no legitimate receiver lives there and the payoff for an attacker is instance
  credentials;
- URLs may not embed credentials (they would end up in logs and error strings).

Set `WEBHOOK_REQUIRE_PUBLIC_HOST=true` on any deployment whose members you do not fully
trust. It restricts targets to publicly-routable addresses using the same check live
enrichment applies to admin-configured lookups. The cost is that internal receivers stop
working, which is why it is not the default.

**2. Cross-user data exposure — the larger risk, and unrelated to SSRF.** A rule's matches
carry entity values out of your instance to an endpoint its owner controls. If rules were
evaluated against jobs their owner cannot see, one broad rule would exfiltrate every
private job's observables, and no amount of URL filtering would help — the request is
perfectly well-formed. Rule evaluation therefore skips any job the rule's owner could not
open in the UI. That guards what a rule sends about a job; it does not narrow the entity
list itself, which is [instance-wide](#the-entity-list-is-instance-wide).

**Verifying a delivery.** Set a signing secret on the rule. Each POST carries
`X-LogsTotal-Signature: sha256=<hex>`, an HMAC-SHA256 over `f"{timestamp}.".encode() + body`
keyed by the secret, alongside `X-LogsTotal-Timestamp`. The timestamp is inside the signed
material so a receiver can reject stale replays. The secret is stored encrypted and is never
logged nor written to the delivery log.

## AI job analysis

The **AI Analysis** tab sends one job's findings to a language model and stores the written
assessment. It is off until an admin adds a provider on `/admin/ai` *and* enables the site
setting, and nothing is ever sent automatically — a member clicks a button, one job at a
time. There are two independent decisions here, and only one of them is about SSRF.

**1. Which outbound guard applies, and why it is the looser one.** LogsTotal has two
outbound-request postures. Live enrichment resolves admin-configured lookup URLs and
**refuses every non-public address**. Rule webhooks allow private addresses by default,
because self-hosted receivers live on RFC1918. AI providers follow the **webhook** posture,
not the enrichment one, for a concrete reason: the intended setup is a model such as Ollama
on `127.0.0.1`, and a public-only guard would reject it and every self-hosted install with
it. What that gives an attacker is narrower than the webhook case, because only a
**superuser** can configure a provider at all — an admin who can set a base URL can already
reach far more than one POST from the worker.

What stays unconditional, regardless of the setting:

- `169.254.169.254` and the other cloud metadata addresses are refused — no model lives
  there and the payoff is instance credentials;
- the connection is **pinned to the address that passed the check**, so a short-TTL DNS
  record cannot rebind between validation and request (TLS SNI keeps the real hostname, so
  the certificate is still verified against the name);
- redirects are not followed — a 302 cannot walk the request to an internal address;
- the response body is read to a 1 MB cap **while streaming**, not after the fact;
- the read is bounded by a **wall-clock** deadline, not merely a per-operation socket
  timeout: a host that dribbles keep-alive bytes resets a per-operation timeout forever, so
  without this an endpoint could hold a worker thread open indefinitely;
- URLs may not embed credentials.

Set `AI_REQUIRE_PUBLIC_HOST=true` on any deployment where an admin account is not fully
trusted. It restricts provider base URLs to publicly-routable addresses using the same
check `WEBHOOK_REQUIRE_PUBLIC_HOST` applies. The cost is that local models stop working,
which is why it is not the default.

**2. Data egress — the larger decision, and unrelated to SSRF.** A run ships a brief built
from the job: rule names and severities, MITRE tactics, extracted entities (users,
hostnames, IP addresses, hashes, command lines) and **up to three sample matched event
fields per finding**. If the configured provider is a hosted API, all of that leaves your
instance and reaches a third party under their retention and training terms. No URL
filtering helps here — the request is perfectly well-formed and exactly what was asked for.
Decide it deliberately:

- A **local** provider (Ollama, LM Studio, vLLM) keeps everything on your own hardware and
  is the configuration the defaults are tuned for.
- A **hosted** provider (OpenAI, Anthropic, OpenRouter, Groq, …) is a data-transfer
  decision that belongs to whoever owns the logs, not to whoever clicks the button. If your
  instance holds customer or regulated data, review the provider's terms before enabling it.
- The evidence brief is bounded by the provider's job or case prompt limit, falling back
  to `AI_MAX_PROMPT_CHARS`. System prompts are separate. These limits cap size; they do not
  redact evidence.

Running an analysis is member-or-above; *viewing* a stored one is open to anyone who can
view the job, the same as its findings. On a public job that means a public answer.
**Stopping and deleting** a run are narrower still: an admin, or the person who started it.
Stopping drops the connection to the provider rather than merely hiding the run, so a run
stopped for data-handling reasons stops transferring. Deletion is permanent — unlike a
comment, a run is a self-contained record with nothing pointing at it.

**The stored prompt is admin-only, and optional.** With `show_ai_prompt` on (the default)
each run keeps the brief it sent, so an administrator can read exactly what was transmitted
before deciding whether a hosted provider is acceptable — the data-egress question above is
unanswerable without it. It is the same content that was already sent, held on an instance
that already holds the job it was built from, so keeping it adds no new class of data; what
it adds is auditability. Turning the setting off stops it being written and hides what was
already stored, so "off" means off in both directions rather than merely hiding a column.

**The run log is admin-only.** Every run records a timestamped trace, and that trace names
the provider's base URL, its model and the exact request parameters. That is deployment
detail a member sees nowhere else, so only administrators see it — the same rule that shows
a tool's raw output on the job page to administrators only. It never contains the API
token, which only ever exists in a request header.

**Credentials and error text.** A provider's API token is stored encrypted at rest
(`ENRICHMENT_ENCRYPTION_KEY`, defaulting to `SECRET_KEY` — rotating either makes every
stored token unreadable) and is only ever placed in a request **header**: never in a URL,
never in a body. Error paths report an exception *type* plus LogsTotal's own wording, never
the raw exception text, which can carry the request URL — so no credential reaches a log
line or a stored error. The model's answer is rendered as Markdown through the same
renderer as analyst notes, which escapes raw HTML and never emits `javascript:`/`data:`
links — a prompt-injected response cannot become script on the page.

## Job tags and job watches

**Tagging is member-and-above**, including on a job. Applying a tag is not a per-job
annotation: it writes to the instance-wide vocabulary Intel curates, creating the name and
setting its colour everywhere it appears. Letting the one role with no Intel access do that
would be backwards.

Every tag write checks job visibility first. Without it the response would differ between
"tagged" and "no such job", which would make tagging an existence oracle for another
member's private submission. Bulk tagging skips ids the caller cannot see **silently**,
rather than returning a 404 that names one.

**Watching is open to any logged-in user**, mirroring commenting exactly: a job thread is
readable by whoever can view the job, and a watch is the notification half of the same act.
Anonymous visitors cannot watch — there is nowhere to notify them.

Two containment properties:

- **A watcher who loses access stops being told.** Job visibility is checked both when a
  notification is written and when the bell is read, so a job made private after the fact
  disappears from a watcher's notifications rather than linking them to a 404.
- **Acknowledgement is per person, admins included.** Admins see every *rule* — correct for
  a shared rule set — but only their own *watches*. Otherwise one admin's "Acknowledge all"
  would silently clear every colleague's notifications.

Job-watch webhooks add no new outbound surface: they reuse an existing rule's URL, secret,
SSRF guard and rate limit, and are therefore member-only for the same reason rules are. See
[Rule webhooks](#rule-webhooks) above for that posture.

## Activity log

Off by default (`activity_log_enabled` on `/admin/settings`), because turning it on means
storing two things you may not want stored: **actor email addresses and client IP
addresses**, for every recorded action. That is a data-handling decision, so it is opt-in
rather than a default someone inherits.

What is deliberately never written:

- **Comment text.** Discussion events record that a comment happened and on what, never
  the prose. The text lives only in the comment itself, where a delete removes it.
- **Passwords.** A failed sign-in records the account that was attempted and nothing else.
- **API tokens.** Issuing one records its scopes and 8-character prefix; the plaintext
  exists in no durable store, which is the entire point of showing it once.
- **Provider and enrichment secrets.** Updates record the *names* of the fields that
  changed, never their values.

Rows are readable by administrators only. Turning capture off stops new rows but keeps
existing ones — see [Activity log](reference/admin-ui.md#activity-log) for why, and for how to
remove them. Retention is `ACTIVITY_RETENTION_DAYS` (default 90 days; `0` keeps forever).

It is a record of what happened through the application, **not** a tamper-proof ledger. It
lives in the same database as everything else, so anyone with database access can alter it.
Where that matters, run with `LOG_FORMAT=json` and ship the process logs to a collector you
control — those carry the same `request_id` and cannot be edited from inside the app.

---

**Related:** [Configuration](configuration.md) · [Storage and retention](runbooks/storage.md) · [Health, logs and first-day checks](runbooks/health-and-logs.md) · [Fleet installation](install/fleet.md) · [Docs index](README.md)
