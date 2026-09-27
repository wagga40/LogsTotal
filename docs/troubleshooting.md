# Troubleshooting

Symptoms, their usual cause, and the fix, from installation to day-to-day operation.

Commands run on the deployment host, from the install directory, unless the fix says otherwise.

## Install and first boot

| Symptom | Cause | Fix |
|---------|-------|-----|
| **Every** command fails with `error reading env file`, even `./logstotal --list` | A malformed line in `.env`. It is read before any command runs, so the diagnostic commands fail too | Fix the line the message names: a bare word, a missing `=`, or an unquoted `#` inside a value. **The message prints the rest of your `.env`, secrets included — remove them before sharing it.** |
| `ConnectionRefusedError` when the application starts | Redis is not running | `docker compose ps redis` and `docker compose logs redis`; start it with `docker compose up -d redis` |
| Sign-in says **Invalid email or password.** | Wrong credentials | Use [lockout recovery](runbooks/account-recovery.md#lockout-recovery). Changing `ADMIN_PASSWORD` in `.env` does not reset an existing account |
| Sign-in says **Too many sign-in attempts** | More than `LOGIN_RATE_LIMIT_PER_MINUTE` attempts from one address | Wait a minute and try again |
| Sign-in appears to work, but every page shows you signed out | The session cookie is marked `Secure` and the site is served over plain HTTP | Serve it over HTTPS (see [Configure HTTPS](install/https.md)), or set `COOKIE_INSECURE=true` for an HTTP-only deployment. Safari refuses the cookie even on `http://localhost` |
| The upload form shows **No compatible workflow** | No workflow accepts the detected log type, or none is loaded | Check `/workflows`. The web service loads `workflows/*.yml` each time it starts: `docker compose restart web` |
| A Chainsaw, Hayabusa or ChopChopGo task fails with `No binary for architecture …` | The workflow has no binary for this host's architecture | The binaries ship under `tools/`; check the task's `tool_path` has an entry for your `{arch}-{os}`. There is no macOS build of ChopChopGo. `./logstotal doctor:docker` warns about such a task, and fails when it is the workflow's only task |
| Zircolite fails, or a job ends `partial` with only Zircolite failing | Zircolite runs as a container, so the worker needs a working Docker daemon and the image | On the worker host, run `docker info`, then `docker pull` the exact image named in `workflows/*.yml`. See [Detection tools](runbooks/detection-tools.md#detection-tools) |
| Port 8000 already in use | Another process has the port | Stop it, or publish another port: `WEB_PORT=8001:8000` in `.env` |
| `DISABLE_CSP=true with DEBUG=false refuses to start` | The Content-Security-Policy switch is off in a production configuration | Set `DISABLE_CSP=false`. Do not set `I_ACCEPT_DISABLE_CSP_IN_PROD` unless you understand what the policy protects |
| `403 CSRF validation failed` on every form | The browser's `Origin`/`Referer` does not match the `Host` the application sees — usually a reverse proxy that does not pass the original host | Forward `Host` or `X-Forwarded-Host`, and set `TRUST_PROXY_HEADERS=true` with `TRUSTED_PROXY_CIDRS` for your proxy — see [Security](security.md) |
| Copy buttons do nothing; the browser console shows `navigator.clipboard is undefined` | The browser's clipboard API works only over HTTPS or on `localhost` | Copying falls back automatically; if the browser refuses that too, a message says so. Serving over HTTPS restores the normal path |

## Fleet deploys

| Symptom | Cause | Fix |
|---------|-------|-----|
| The deploy hangs at the VPN step | A host is unreachable, or its key is rejected and ssh is waiting for a password | `./logstotal deploy:plan` checks every host in seconds. The deploy's own ssh calls never prompt and time out, so a hang means something outside them |
| The deploy stops with `the tunnel is not up: 0 of N peer(s) have completed a WireGuard handshake` | The VPN was built but carries no traffic — usually UDP 51820 to the hub is blocked, or the hub's address is not reachable from the other hosts | Open the path to the hub, then `wireconf status`. Continuing would point every worker at an address that does not answer |
| `wireconf verify` fails but the deploy continues | Every host has a WireGuard handshake, so the tunnel works; only ping (ICMP) is blocked | Nothing to do |
| The deploy stops with `Unknown DEPLOY_VPN=…` | A typo such as `wireguard`. Guessing `none` would put Redis, PostgreSQL and Garage on a routable network | Use `wireconf`, `tailscale` or `none` |
| `DEPLOY_VPN=tailscale` stops the deploy | Tailscale needs an interactive login, so the deploy does not set it up | Set it up on every host, then deploy again with `DEPLOY_CP_ADDRESS` set to the control plane's Tailscale (`100.x`) address |
| Wireconf reports a host as "not Debian/Ubuntu" when it is | Wireconf before 0.3.8 runs its remote commands on a terminal, so `/etc/os-release` comes back with Windows line endings and its check fails | The deploy updates Wireconf to 0.3.8 or later itself. By hand: `wireconf update` (a system-wide install may need `sudo`) |
| `Wireconf installed but the binary was not found` | Wireconf is not on the `PATH` the deploy searches | Set `WIRECONF_BIN` to the binary's path |
| `Cannot execute command-line and remote command.`, or preflight fails a host for `RemoteCommand` | A `Host` block in `~/.ssh/config` sets `RemoteCommand` for that host | Remove `RemoteCommand` from that block, or give the deploy a separate host alias |
| `./logstotal deploy:bootstrap` says there is no `apt-get` on the host | The host is not Ubuntu or Debian | Install `docker-ce`, `docker-compose-plugin`, `p7zip-full`, `rsync` and go-task by hand, then run `./logstotal deploy:preflight` to see what is still missing |
| `./logstotal deploy:bootstrap` says sudo needs a password | The SSH user has no passwordless sudo | Deploy as `root@host`, or allow the deploy user `sudo -n` |
| The deploy stops with `DEPLOY_BASIC_AUTH_USER is set but DEPLOY_DOMAIN is not` | Basic auth is enforced by Caddy, which runs only with a domain | Set `DEPLOY_DOMAIN`, or unset `DEPLOY_BASIC_AUTH_USER` |
| A second deploy stops with "no password or hash came with it" | `deploy.env` has the basic-auth user but neither the password nor its hash; the password was passed for one run only | Pass `DEPLOY_BASIC_AUTH_PASSWORD` again, put it in `deploy.env`, or store a `DEPLOY_BASIC_AUTH_HASH` you generated |
| `Could not write …/.env on <host>` | The SSH user cannot write to the install directory | Deploy as `root@host`, or give the SSH user passwordless sudo. The deploy stops rather than leave the host with no configuration or an old one |
| `./logstotal deploy:env` refuses a host | That host already has an `.env`, which may have been edited | Read the key names it lists and reconcile them, then `DEPLOY_ENV_PUSH_FORCE=yes ./logstotal deploy:env` |
| `./logstotal deploy:env` refuses because the control plane is `local` | Workers need a real address for the control plane | Set `DEPLOY_CP_ADDRESS` to the address workers will use, or run `./logstotal deploy:vpn` |
| A host is half-built: code but nothing running, or directories but no code | An earlier deploy stopped part way | `./logstotal deploy:plan` reports it as `PARTIAL`. Run `./logstotal deploy` again to finish it, or start over with `DEPLOY_REMOVE_CONFIRM=yes ./logstotal deploy:remove` |
| `./logstotal deploy:smoke` reports 401 on every check | The control plane is behind Caddy basic auth and the smoke test has no password. `deploy.env` keeps the user name, not the password | `DEPLOY_BASIC_AUTH_PASSWORD='...' ./logstotal deploy:smoke`, or put it in `deploy.env`. A 401 still shows that DNS, TLS, the port and the proxy work |
| The smoke test says "no workers registered" | The worker containers run but cannot reach the control plane's Redis, PostgreSQL or S3 — wrong address, wrong password, or a tunnel that carries no traffic | `./logstotal deploy:logs`, and check that each worker's `.env` points at an address it can reach |
| On a fleet, jobs stay `PENDING` | Workers cannot reach Redis, PostgreSQL or S3 over the private network | On a worker, `./logstotal docker:worker-logs`; check that `REDIS_URL`, `DATABASE_URL` and `S3_ENDPOINT` use the control plane's private address, not `localhost` |

## Upgrades

| Symptom | Cause | Fix |
|---------|-------|-----|
| The web container restarts in a loop after an upgrade | A database migration failed at startup | `docker compose logs web` shows the error — see [Database migrations](runbooks/migrations.md#if-a-migration-fails) |
| `migrations: unmanaged` in `/health` or System checks | The database has tables but no migration record, and they differ from what this release expects | See [`migrations: unmanaged`](runbooks/migrations.md#migrations-unmanaged) |
| The web service waits at startup, then stops with `Migration leader did not finish within 600s` | Another web service holds the startup migration lock, or one that crashed left it behind | Make sure only one web service is starting. The lock expires after 10 minutes; to clear it at once, delete the Redis key `logstotal:init_lock`, then start the web service again |
| `git pull` says "You are not currently on a branch" | An upgrade with `SOURCE=git` checks out the release tag, not a branch | Do not pull — upgrade with `./logstotal upgrade`. To follow a branch again: `git checkout main` |
| `git status` shows changes after an upgrade, and the next upgrade refuses | With the default `SOURCE=package`, the release archive is copied over your checkout | `git checkout -- .` resets it, or use `SOURCE=git` — see [Where the code comes from](runbooks/upgrading.md#where-the-code-comes-from) |

## Runtime and operations

| Symptom | Likely cause | First action |
|---------|--------------|--------------|
| `/health` returns 503 with `redis: error` | Redis is down or unreachable | `docker compose logs redis`; `docker compose exec redis redis-cli ping` (add `-a` with the password if `REDIS_PASSWORD` is set) |
| `/health` returns 503 with `database: error` | The database is down, or `DATABASE_URL` is wrong | `docker compose logs web`, and `docker compose logs postgres` for the bundled PostgreSQL; check the database settings in `.env` |
| `/health` returns 503 with `storage: error` | The S3 endpoint is unreachable, the bucket is missing or the keys are wrong — or the local `uploads/` directory is not writable | `./logstotal doctor:docker` shows the storage check with its detail; check `STORAGE_BACKEND` and the `S3_*` settings |
| New jobs are queued but never start | No live worker, every host paused, or the worker crashed | On `/admin/workers`, check that a worker is listed and not every host is at `-1`; restart the worker |
| A job stays `RUNNING` after its worker crashed or restarted | Its worker is gone and the heartbeat has expired | **Recover All** on `/admin/workers`, or restart the web service — see [Stuck job recovery](runbooks/workers.md#stuck-job-recovery) |
| A job page waits on `PENDING` and never starts | No worker claimed the job within `HUEY_QUEUE_EXPIRY`, so the queue dropped it | Start a worker, then **Recover All** on `/admin/workers` to mark the job failed, and resubmit it |
| A running or queued job needs stopping | — | **Cancel** on the job page keeps the findings of tools that already finished — see [Cancelling a job](runbooks/workers.md#cancelling-a-job) |
| A worker disappears from `/admin/workers` while its process is running | It cannot reach Redis, so its registration expired (after `WORKER_ALIVE_TTL`, 180 seconds by default) | Check the worker's connection to Redis and its log. Raising `WORKER_HEARTBEAT_INTERVAL` does not help: it makes refreshes rarer |
| Caddy cannot get a certificate | The domain does not resolve to this host, or ports 80/443 are blocked | `docker compose logs caddy`; check that `DOMAIN` resolves to the host and the firewall allows 80 and 443 |
| Caddy basic auth rejects every password | `BASIC_AUTH_HASH` is not a bcrypt hash, or lost its quoting in `.env` | Generate one with `docker run --rm -i caddy:2-alpine caddy hash-password`, put it in single quotes in `.env` — see [Configure HTTPS](install/https.md) |
| A setting changed in `.env` has no effect | The services were not recreated, or the key is misspelled (unknown keys are ignored silently) | `./logstotal env:diff` lists unknown keys; see [Apply configuration changes](runbooks/configuration-changes.md) |
| An upload fails near the end with a 500 | The uploads volume is full | `df -h` and `du -sh uploads/ data/`; free space, then see [Storage and retention](runbooks/storage.md) |
| Rate limits do not seem to apply | The application sees the proxy's address instead of the client's | See [Rate limit semantics](security.md#rate-limit-semantics): check `TRUST_PROXY_HEADERS` and that `TRUSTED_PROXY_CIDRS` matches your proxy |
| A user reports an error you cannot find | Nothing links their page to your logs | Every error page shows a **Reference** id, also sent as `X-Request-ID`. Search the logs for it; it is set even with `REQUEST_LOG_ENABLED=false` |
| Container logs are cut short | Docker keeps 3 files of 10 MB per service | Forward the logs to a log system, or raise `logging.options.max-size` in a Compose override file |

## S3 storage

With `STORAGE_BACKEND=s3`, each worker downloads the uploaded file from the bucket at the start of a job.

- **S3 unreachable during a job** — the job fails. Resubmit it once S3 is back.
- **S3 unreachable during an upload** — the upload returns a 500 before any job is created; the user can retry.
- **Wrong permissions on the bucket** — the job fails with a `botocore` error in the worker log. Check that the worker's `S3_ACCESS_KEY` can read `S3_BUCKET`.
- **Orphaned objects** — objects no database row refers to (for example, after restoring an older database). `/admin/storage` finds them and **Purge** removes them — see [Orphaned files](runbooks/storage.md#orphaned-files).
- **A worker's disk fills up** — workers keep the downloaded copy in `uploads/.s3_cache` for the length of the job. A worker killed during a job leaves its copy behind; deleting `uploads/.s3_cache` on that worker is safe while it runs no job.

With the bundled Garage, `no storage node connected` in `docker compose logs garage` means the storage layout has not been applied.

---

**Related:** [Health, logs and first-day checks](runbooks/health-and-logs.md) · [Upgrade and roll back](runbooks/upgrading.md) · [Security](security.md) · [Docs index](README.md)
