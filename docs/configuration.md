# Configuration

Every environment variable LogsTotal reads from `.env`, how to generate its secrets, and how the Docker Compose profiles work.

All application configuration lives in `.env` in the install directory.
[`.env.example`](https://github.com/wagga40/LogsTotal/blob/main/.env.example) is the
copy-paste template with safe defaults; this page is the annotated reference. The fleet
deploy tooling reads its own `DEPLOY_*` variables from `deploy.env` instead — see
[`DEPLOY_*` reference](#deploy_-reference). After editing `.env`, follow
[Apply configuration changes](runbooks/configuration-changes.md).

## Generating secrets and keys

Generate everything at once, on the deployment host, from the install directory:

```bash
./logstotal gen-secrets             # print a copy-paste block of all secrets
./logstotal gen-secrets -- --write  # fill them into .env (only empty/placeholder keys; never clobbers real values)
```

This covers `SECRET_KEY`, `ADMIN_PASSWORD` (printed once when newly generated),
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, the Garage-style `S3_ACCESS_KEY`/`S3_SECRET_KEY`,
and `GARAGE_RPC_SECRET`/`GARAGE_ADMIN_TOKEN`. `--write` only touches keys that are still
unset or a placeholder, so it is safe to re-run. To choose your own admin password, set
`ADMIN_PASSWORD` in `.env` before running it.

To generate a single value instead, run one of these anywhere `python3` or Docker is available:

| Key | Format | Command |
|-----|--------|---------|
| `SECRET_KEY` | 64 hex chars — signs JWTs and sessions | `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `S3_SECRET_KEY`, `GARAGE_RPC_SECRET` | 64 hex chars | `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `S3_ACCESS_KEY` | `GK` + 24 hex chars | `python3 -c "import secrets; print(f'GK{secrets.token_hex(12)}')"` |
| `GARAGE_ADMIN_TOKEN` | opaque bearer token, not hex | `python3 -c "import secrets; print(secrets.token_urlsafe(24))"` |
| `BASIC_AUTH_HASH` | bcrypt, with `COMPOSE_PROFILES=proxy` | `docker run --rm caddy:2-alpine caddy hash-password --plaintext 'yourpassword'` — or let `./logstotal proxy:enable` / `./logstotal deploy` do it (they pass the password over stdin, keeping it out of `ps`) |

Paste the basic-auth hash into `BASIC_AUTH_HASH` with **single quotes**, so Docker Compose does not treat `$` as variable expansion.

**Concurrency:** `HUEY_WORKERS`, `TOOL_MAX_WORKERS` and the per-tool `threads` multiply into CPU pressure — see [Scaling](scaling.md) for the model and `./logstotal recommend-scaling`.

## Docker Compose profiles

`COMPOSE_PROFILES` in `.env` selects which bundled services Docker Compose starts alongside web, worker and Redis. Combine them with commas:

| Profile | Adds | Used by |
|---------|------|---------|
| `postgres` | Bundled PostgreSQL (Docker volume `postgres_data`) | [With PostgreSQL](install/single-host.md#with-postgresql), fleets |
| `s3` | Bundled Garage S3-compatible object storage | Fleets |
| `proxy` | Caddy with automatic TLS (+ optional basic auth) | [HTTPS with Caddy](install/https.md) |
| `workers` | socat relays that publish Redis, PostgreSQL and Garage on the `REDIS_EXPOSE`, `POSTGRES_EXPOSE` and `GARAGE_EXPOSE` addresses, for remote workers. Each defaults to loopback (`127.0.0.1`) | [Fleet installation](install/fleet.md) |

Examples:

```bash
COMPOSE_PROFILES=postgres                  # single host, PostgreSQL instead of SQLite
COMPOSE_PROFILES=proxy                     # single host, HTTPS via Caddy
COMPOSE_PROFILES=postgres,s3,workers       # fleet control plane (bundled services)
COMPOSE_PROFILES=postgres,s3,proxy,workers # fleet control plane behind HTTPS
```

**`COMPOSE_PROFILES` decides whether the bundled PostgreSQL is used.** The image entrypoint switches from SQLite to PostgreSQL only when `POSTGRES_PASSWORD` is set **and** `postgres` is in `COMPOSE_PROFILES` (or an external `POSTGRES_HOST` is configured), then builds the database URLs itself — no manual URL editing. The rule cuts both ways:

- A `POSTGRES_PASSWORD` **without** the `postgres` profile keeps the app on SQLite and logs a warning, rather than waiting for a `postgres` host Compose never started.
- `COMPOSE_PROFILES=postgres` **without** a password also stays on SQLite.

An explicit `DATABASE_URL` always wins. `./logstotal backup` resolves the database the same way, so a leftover password never makes it dump the wrong engine. Avoid `#` `@` `%` `?` in the password, or URL-encode them.

## Cookies over plain HTTP

With `DEBUG=false`, auth cookies are marked `Secure`, and browsers silently drop them on `http://` — login appears to succeed but never sticks. Set `COOKIE_INSECURE=true` for any deployment served over plain HTTP (Docker without a proxy, local development on `:8000`). Once TLS is in front — the `proxy` profile or your own reverse proxy — set `COOKIE_INSECURE=false` (or remove it); [HTTPS with Caddy](install/https.md#choose-a-tls-mode) says which `ENABLE_HSTS` value goes with each TLS mode. `./logstotal quickstart` sets `COOKIE_INSECURE=true` for a plain-HTTP start, and `./logstotal proxy:enable` sets it to match the TLS mode it configures.

The browser's clipboard API also requires HTTPS, so every "Copy" button falls back to an older mechanism on plain HTTP. It works, and says so when a strict browser refuses it.

## AI provider base URLs

AI providers are configured on `/admin/ai`, not in `.env` — the base URL, model, API token, timeout and system prompt all live there. Two things about the base URL look like bugs the first time you meet them.

**A private or internal address is allowed by default.** The intended setup for this feature is a model running on the same machine, so `http://localhost:11434/v1` (Ollama) or `http://127.0.0.1:1234/v1` (LM Studio) is expected. `AI_REQUIRE_PUBLIC_HOST=true` restricts base URLs to publicly-routable addresses, which is the right setting when your admin accounts are not fully trusted — and it breaks every local model, so it is not the default. Cloud metadata addresses are refused either way. See [AI job analysis](security.md#ai-job-analysis) for the full boundary.

**In Docker, `localhost` is the container, not your machine.** The completion request is made by the **worker**, so the base URL is resolved inside the worker container. If Ollama runs on the Docker host, `http://localhost:11434/v1` reaches the worker container itself, and the run fails with "could not reach the provider". Use the host gateway instead:

```
http://host.docker.internal:11434/v1
```

That name resolves on Docker Desktop (macOS, Windows) and OrbStack. On Linux, `host.docker.internal` needs an explicit mapping — add `extra_hosts: ["host.docker.internal:host-gateway"]` to the worker service, or point the base URL at the host's LAN or WireGuard address. Also make sure the model listens on more than loopback: Ollama binds `127.0.0.1` by default and needs `OLLAMA_HOST=0.0.0.0` before anything outside the host can reach it.

The **Test** button on `/admin/ai` is the fastest way to tell these failures apart: it runs a real one-word completion and reports the error immediately. **Test runs in the web process; real runs happen in the worker.** On a single host both reach the same network, so a passing test means the feature works. In a fleet, a passing test only proves the *control plane* can reach the model — the base URL must also resolve and connect from every **worker** host.

## Environment variable reference

Every setting, grouped by concern. A default applies when the key is absent from `.env`.

### Required

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | JWT signing key (**must change** from the default — the app refuses to start with it) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | The first admin account, created when the database is initialised (the web container does this on start). Refused: `changeme123` and other common defaults, passwords under 8 characters, and passwords containing the email |
| `DATABASE_URL` | Async database URL (default: SQLite; `postgresql+asyncpg://...` for PostgreSQL) |
| `SYNC_DATABASE_URL` | Sync database URL for workers and migrations — derived from `DATABASE_URL` when unset |
| `AUTO_MIGRATE` | Run database migrations automatically when the web process starts (default: `true`; set `false` only while investigating a failed migration — see [Database migrations](runbooks/migrations.md)) |

### Redis and Huey

| Variable | Description |
|----------|-------------|
| `REDIS_HOST` / `REDIS_PORT` | Huey broker connection (default: `localhost:6379`) |
| `REDIS_PASSWORD` | Redis AUTH password; leave empty for no auth |
| `REDIS_URL` | Full Redis connection URL — overrides host, port and password (for remote Redis or TLS) |
| `REDIS_EXPOSE` | Address the `workers` profile publishes Redis on for remote workers (default `127.0.0.1:6379`; e.g. `10.0.0.1:6379`). A non-loopback address **requires** `REDIS_PASSWORD` or the app refuses to start |
| `HUEY_WORKERS` | Worker threads per worker process; each thread runs one job at a time. Default 2 in `docker-compose.yml` (and for `./logstotal worker`), 4 in `docker-compose.worker.yml` on dedicated worker hosts |

### PostgreSQL

Used with `COMPOSE_PROFILES=postgres` or an external PostgreSQL server.

| Variable | Description |
|----------|-------------|
| `POSTGRES_PASSWORD` | **Required** for PostgreSQL (see [Docker Compose profiles](#docker-compose-profiles) for when it takes effect) |
| `POSTGRES_USER` / `POSTGRES_DB` | Optional, both default to `logstotal` |
| `POSTGRES_HOST` / `POSTGRES_PORT` | Optional, default to `postgres` / `5432` (the Compose service) |
| `POSTGRES_EXPOSE` | Address the `workers` profile publishes PostgreSQL on for remote workers (default `127.0.0.1:5432`; e.g. `10.0.0.1:5432`) |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` / `DB_POOL_RECYCLE` | Connection pool tuning (defaults: 5 / 10 / 300; ignored for SQLite) |

### S3 storage

Used with `STORAGE_BACKEND=s3`.

| Variable | Description |
|----------|-------------|
| `STORAGE_BACKEND` | `local` (default) or `s3` — required for a fleet, where workers do not share a filesystem |
| `S3_ENDPOINT` / `S3_BUCKET` | S3-compatible endpoint URL and bucket name (bucket default: `logstotal`). With the `s3` profile and no `S3_ENDPOINT`, the bundled Garage (`http://garage:3900`) is used |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | S3 credentials (Garage: `GK`-prefixed key + 64-char hex secret). The bundled Garage creates this key and bucket on first start |
| `S3_REGION` | S3 region (default: `logstotal`) |
| `GARAGE_RPC_SECRET` | Secret for the bundled Garage node's internal RPC (`s3` profile), 64 hex chars. Unset, Garage starts with a built-in default and logs a warning — set it (`./logstotal gen-secrets` does) |
| `GARAGE_ADMIN_TOKEN` | Token for the bundled Garage's admin API (`s3` profile). Unset, Garage uses a built-in default and logs a warning — set it (`./logstotal gen-secrets` does) |
| `GARAGE_EXPOSE` | Address the `workers` profile publishes Garage's S3 API on for remote workers (default `127.0.0.1:3900`) |

### Reverse proxy and TLS

Used with `COMPOSE_PROFILES=proxy`. The four `PROXY_TLS` modes, what each needs, and the `COOKIE_INSECURE` / `ENABLE_HSTS` pair each one requires are in [HTTPS with Caddy](install/https.md#choose-a-tls-mode). `./logstotal proxy:enable -- --tls <mode>` — or `DOMAIN=... QUICKSTART_TLS=<mode> ./logstotal quickstart` on a first deploy — sets all of them together. They have to agree: when they do not, login fails silently.

| Variable | Description |
|----------|-------------|
| `DOMAIN` | The name Caddy serves. Letters, digits, `.` and `-` only — an IPv4 literal works, an IPv6 literal does not (see [Known limitations](limitations.md#deployment)) |
| `PROXY_TLS` | How TLS is terminated: `acme` (default), `internal`, `custom` or `off` |
| `ACME_EMAIL` | Contact address for the certificate authority, so it can warn about expiry. `PROXY_TLS=acme` only |
| `PROXY_TLS_CERT` / `PROXY_TLS_KEY` | In-container paths under `/etc/caddy/certs` (bind-mounted from `./certs`). `PROXY_TLS=custom` only; both are required together |
| `WEB_PORT` | *(also applies without the proxy — see below)* The web service's **port mapping**, not a port number |
| `BASIC_AUTH_USER` / `BASIC_AUTH_HASH` | Optional Caddy basic auth. Set both or neither. Generate the hash with the recipe in [Generating secrets and keys](#generating-secrets-and-keys) and paste it with **single quotes** |

> [!IMPORTANT]
> **`WEB_PORT` is a Docker Compose port *mapping* in `HOST:CONTAINER` form — not a port number.** `WEB_PORT=9000` publishes container port 9000, which nothing listens on, so the site becomes unreachable without any error.
>
> - Change the host port: `WEB_PORT=9000:8000`
> - Bind to loopback only (what the proxy profile sets): `WEB_PORT=127.0.0.1:8000:8000`
> - Default: `WEB_PORT=8000:8000`
>
> The container always listens on 8000; only the left-hand side is yours to choose.

### Docker Compose

| Variable | Description |
|----------|-------------|
| `COMPOSE_PROFILES` | Which bundled services start: `postgres`, `s3` (Garage), `proxy` (Caddy), `workers` (publish Redis, PostgreSQL and Garage to remote workers) — see [Docker Compose profiles](#docker-compose-profiles) |
| `LOGSTOTAL_IMAGE_TAG` | Tag of the `logstotal` and `logstotal-garage` images Compose builds and runs (default: `latest`). A bundle install sets it for you; you rarely need it otherwise |
| `DOCKER_HOST_WORKDIR` | Host path of the install directory, so the worker can mount job files into tool containers. Set by Compose to the directory you run it from — start the stack from the install directory |

### Application

| Variable | Description |
|----------|-------------|
| `DEBUG` | Debug mode (default: `false`). Never on an internet-facing host — see [Security escape hatches](security.md#security-escape-hatches) |
| `COOKIE_INSECURE` | When `true`, drops the Secure flag on auth cookies (plain-HTTP deployments only — see [Cookies over plain HTTP](#cookies-over-plain-http)) |
| `DISABLE_CSP` | Drop the Content-Security-Policy header — for local testing over an IP. With `DEBUG=false` the app refuses to start unless `I_ACCEPT_DISABLE_CSP_IN_PROD=true` is also set |
| `LOG_LEVEL` | Log verbosity for the web process, uvicorn **and** the Huey worker: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`) |
| `LOG_FORMAT` | `text` (human) or `json` (one object per line, for a log shipper). Both processes honour it (default: `text`) |
| `REQUEST_LOG_ENABLED` | Log one line per request with status and duration (default: `false`). `/static/` and `/health` are never logged; the request id is set either way |
| `ACTIVITY_RETENTION_DAYS` | How long activity-log rows are kept, in days; `0` keeps forever (default: `90`). Capture itself is the `activity_log_enabled` site setting, not an environment variable |
| `BACKGROUND_TASK_RETENTION_DAYS` | How long finished background-task rows are kept, in days; `0` keeps forever (default: `30`). Only finished rows are pruned |
| `UPLOAD_RETENTION_DAYS` | Age at which an uploaded log file **and its jobs** are deleted, in days (default: `0` = never). The age counts from the newer of the upload and the most recent job on that file, so re-uploading identical content as a new job or resubmitting it keeps the file. Off by default because this removes submitted evidence, not derived data. `/admin/storage` shows the effective value; the sweep schedule is in [Storage and retention](runbooks/storage.md) |
| `UPLOAD_DIR` | Local upload directory (default: `uploads`) |
| `MAX_UPLOAD_SIZE_MB` | Maximum upload file size in MB (default: `500`) |
| `UPLOAD_RATE_LIMIT_PER_MINUTE` | Anonymous uploads per client IP per minute (default: 30; `0` = unlimited) |
| `AUTHENTICATED_UPLOAD_RATE_LIMIT_PER_MINUTE` | Authenticated uploads per account per minute, shared by its cookies and tokens (default: 60; `0` = unlimited) |
| `PREVIEW_RATE_LIMIT_PER_MINUTE` | File-type previews per client IP per minute (default: 120; `0` = unlimited) |
| `UPLOAD_MAX_CONCURRENT` | Upload requests admitted at once across all web processes sharing Redis (default: 4; effective minimum: 1). See [Ingestion API](reference/ingestion-api.md#capacity) |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | `POST /auth/cookie/login` requests per client IP per minute (default: 20; `0` = unlimited) |
| `RESUBMIT_RATE_LIMIT_PER_MINUTE` | `POST /jobs/resubmit` requests per client IP per minute (default: 10; `0` = unlimited) |
| `ENABLE_HSTS` | Send the `Strict-Transport-Security` header (default: `false`; see [HTTPS with Caddy](install/https.md#choose-a-tls-mode) for which TLS modes want it) |
| `HSTS_MAX_AGE` | HSTS max-age in seconds (default: 63072000, two years) |
| `TRUST_PROXY_HEADERS` | Trust forwarded client-IP headers when the request comes from a trusted proxy (default: `false`) |
| `TRUSTED_PROXY_CIDRS` | Comma-separated CIDRs allowed to supply forwarded headers (default: `127.0.0.1/32,::1/128`; `*` only behind fully trusted ingress). List **every** hop — the `X-Forwarded-For` chain is read from the right, stopping at the first address not listed here. See [Production hardening checklist](security.md#production-hardening-checklist) |
| `ENRICHMENT_ENCRYPTION_KEY` | Separate key for encrypting stored secrets at rest — enrichment-service and AI-provider API tokens, rule webhook signing secrets (default: derived from `SECRET_KEY`; rotating either makes every stored secret unreadable) |
| `API_TOKEN_RATE_LIMIT_PER_MINUTE` | Requests per API token per minute under `/api/v1/*`, `/intel/ioc-feed`, `/taxii2/*` and `/intel/cases/*` (default: 120). Requests without a token are counted per client IP, except under `/intel/cases/*`, which is limited only for token requests because the same prefix serves the browser's case pages |
| `TAXII_ENABLED` | Enable the read-only TAXII 2.1 server at `/taxii2/` (default: `false`) |
| `ENRICHMENT_RATE_LIMIT_PER_MINUTE` | Outbound live-enrichment calls per service per minute (default: 30; `0` = unlimited; the cached result is served when limited) |
| `ENRICHMENT_REQUIRE_PUBLIC_HOST` | Restrict live-enrichment endpoints to publicly-routable addresses (default: `true`). The opposite default to the webhook and AI settings below, deliberately: a threat-intel API lives on the public internet, so a private address there is a mistake or an SSRF attempt. Set `false` to reach a self-hosted MISP or OpenCTI. Cloud metadata addresses are blocked either way — see [Live enrichment](security.md#live-enrichment) |
| `WEBHOOK_REQUIRE_PUBLIC_HOST` | Restrict rule webhook targets to publicly-routable addresses (default: `false`, so internal receivers work). Set `true` where members are not fully trusted — see [Rule webhooks](security.md#rule-webhooks) |
| `WEBHOOK_TIMEOUT_SECONDS` | Total HTTP deadline for one webhook delivery, in seconds (default: 5); DNS validation happens before it starts |
| `WEBHOOK_RATE_LIMIT_PER_MINUTE` | Webhook deliveries per rule per minute (default: 10; `0` = unlimited; deliveries over the limit are recorded and dropped, never retried) |
| `WEBHOOK_MAX_RETRIES` | Retries after a network error, timeout or 5xx, with 60s/120s/240s backoff. A 4xx other than 429 is final (default: 3) |
| `WEBHOOK_DELIVERY_RETENTION_DAYS` | Days to keep the webhook delivery log (default: 30; `0` = keep forever) |
| `WATCH_RULES_MAX_PER_USER` | Maximum rules one user may own (default: 50) |
| `RULE_LIST_REQUIRE_PUBLIC_HOST` | Restrict a rule list's source URL to publicly-routable addresses (default: `true`) — a feed is fetched on a schedule with nobody watching. Set `false` for an internal mirror of a public list. The cloud metadata endpoint is refused either way, and redirects are not followed |
| `RULE_LIST_FETCH_TIMEOUT_SECONDS` | Per-request timeout when fetching a list's source URL (default: 15) |
| `RULE_LIST_FETCH_MAX_BYTES` | Largest feed that will be read (default: 1048576). A list holds at most 2,000 values of 200 characters, so a real feed is far below this |
| `AI_REQUIRE_PUBLIC_HOST` | Restrict AI provider base URLs to publicly-routable addresses (default: `false`, so a local model works). Set `true` where an admin account is not fully trusted — see [AI provider base URLs](#ai-provider-base-urls) and [AI job analysis](security.md#ai-job-analysis) |
| `AI_RATE_LIMIT_PER_MINUTE` | Analysis runs one user may start per minute (default: 10; `0` = unlimited). Lower than the other limits because one click spends money or occupies a GPU |
| `AI_MAX_PROMPT_CHARS` | Default size of the evidence brief for job and case AI analysis, in characters (default: 60000). A provider can override the job and case limits on `/admin/ai`; blank fields inherit this value. System prompts are separate. An oversized brief omits evidence and says that the model's view is partial |

> [!NOTE]
> Every `*_RATE_LIMIT_PER_MINUTE` is counted in **Redis**, so the value is the limit for the whole deployment — running more web processes does not multiply it. See [Rate limit semantics](security.md#rate-limit-semantics).

### Workers

| Variable | Description |
|----------|-------------|
| `REGISTRY_PREFIX` | Pull images from this registry instead of Docker Hub — for a network with no route to Docker Hub that runs its own mirror. Applied to the Compose services and to the tool images named in `workflows/*.yml`; digests are kept, and an image that already names a registry is left alone. Empty by default. For a network with **no** registry, use `./logstotal bundle` instead ([Offline installation](install/offline.md)) |
| `TOOL_MAX_WORKERS` | Per-job cap on tools running at once, applied only when parallel execution is on (default: 2) |
| `MAX_LOG_OUTPUT_BYTES` | Cap on stored stdout/stderr per task result (default: 50 KB) |
| `HUEY_QUEUE_EXPIRY` | Seconds a queued task may wait before it is discarded unstarted (default: 1800). Not an execution timeout. `HUEY_TASK_TIMEOUT` is a deprecated alias |
| `WORKER_NAME` | Optional label shown on `/admin/workers` |
| `WORKER_IP` | Optional address shown on `/admin/workers` (use the WireGuard address for remote workers) |
| `WORKER_HEARTBEAT_TTL` | Seconds before a job's heartbeat expires in Redis (default: 60) |
| `WORKER_HEARTBEAT_INTERVAL` | Seconds between heartbeat refreshes (default: 30) |
| `WORKER_ALIVE_TTL` | Seconds before a silent worker disappears from `/admin/workers` (default: 180) |
| `MAX_PARSE_EVENTS` | Matched events read from one job's raw output per analytics pass; bounds worker CPU and process-tree memory (default: 250000) |
| `JOB_OUTPUT_RETENTION_DAYS` | Age at which a job's raw tool outputs are deleted, by the daily sweep and by the **Output cleanup** action; `0` keeps them forever (default: 90). See [Storage and retention](runbooks/storage.md) |

### Config paths

| Variable | Description |
|----------|-------------|
| `ANALYTICS_FIELDS_PATH` | Entity field-name YAML used by analytics (default: `config/analytics_fields.yaml`) |
| `THREAT_DETECTION_CONFIG_PATH` | Threat-detection heuristic patterns YAML (default: `config/threat_detection.yaml`) |

## `DEPLOY_*` reference

The fleet deploy tooling (`./logstotal deploy`, `upgrade` and the `deploy:*` commands) does
not read `.env`. It reads `DEPLOY_*` and `FLEET_*` variables from `deploy.env` or from the
environment of the command. Every one of them, with its default and where it is meant to be
set, is in the [Fleet reference](reference/fleet.md#deploy_-reference); `FLEET_FROM` and
the other `FLEET_*` variables are in
[Taking the record somewhere else](reference/fleet.md#taking-the-record-somewhere-else).

---

**Related:** [Security](security.md) · [Scaling](scaling.md) · [Prerequisites](install/prerequisites.md) · [Fleet reference](reference/fleet.md) · [Docs index](README.md)
