# Command reference

Every `./logstotal` command, grouped by purpose.

`./logstotal` is the command runner that ships with LogsTotal. It runs the version of
go-task pinned for this release — the copy a release archive carries, or a one-time,
checksum-verified download in a git checkout — so nothing has to be installed before the
first command. It always runs from its own directory, so `/opt/logstotal/logstotal backup`
works from anywhere, cron included.

```bash
./logstotal --list               # every command, one line each
./logstotal --summary <name>     # what one command does, and its options
```

If you already have Task 3.39 or newer, `task <name>` in the install directory does the same
as `./logstotal <name>`.

## Arguments and execution context

Run commands in the install directory (or in a checkout). Commands that manage the local
stack act on that host; `deploy:*`, `upgrade` and `fleet*` run on your workstation or the
control plane and reach other hosts over SSH.

A few commands need a development checkout with PDM — `doctor`, `init`, `sync-workflows`,
`sync-rules`, `db:*`, `dev`, `worker` and the test and lint commands. On a Docker host use
the container equivalents: `./logstotal doctor:docker` for the preflight, and the web
container initialises the database, workflows and rules every time it starts.

| Form | Meaning | Example |
|---|---|---|
| `NAME=value ./logstotal <name>` | Process environment, passed to the command's script | `BACKUP_CONTEXT=docker ./logstotal backup` |
| `./logstotal <name> NAME=value` | Task variable, used only by commands whose summary documents it | `./logstotal restore:sqlite BACKUP_FILE=backups/example.db` |
| `./logstotal <name> -- arguments` | Arguments passed to the command's script | `./logstotal deploy:init -- cp.example.com w1.example.com` |

Use the environment-prefix form for operational options unless the command's summary shows
another form. `.env` configures the application; `deploy.env` supplies fleet defaults, and
the environment of the command overrides it. Put application settings in `.env` rather than
on the command line.

Destructive commands prompt; `./logstotal -y <name>` answers that prompt for automation, but
does not replace an explicit confirmation variable such as `DEPLOY_REMOVE_CONFIRM=yes`.
Health, backup and restore failures exit non-zero. `deploy:plan` and `upgrade:plan` are
reports that exit zero even when they report blockers; use the preflight and health
commands as automation gates.

For SQLite, `BACKUP_CONTEXT=auto` uses the running Compose application or the configured
path; `host` and `docker` select how the path is interpreted. An ambiguous pair of
development and Docker databases is refused.

## Most-used commands

On a deployment host:

- `./logstotal quickstart` — guided first Docker deployment (one command)
- `./logstotal docker:up` / `./logstotal docker:down` — start / stop the Docker stack
- `./logstotal backup` — verified database backup
- `./logstotal upgrade` — upgrade to the latest release

In a development checkout:

- `./logstotal setup` — first-time local dev bootstrap
- `./logstotal dev` + `./logstotal worker:watch` + `./logstotal redis:docker` — the local development loop
- `./logstotal check` + `./logstotal test` — quality gate before a commit

## Setup

Development checkout only (needs PDM).

- `./logstotal setup` — dev bootstrap (dependencies + `.env` + database)
- `./logstotal install` — install all dependencies (runtime + dev)
- `./logstotal lock` — regenerate `pdm.lock` + `requirements.txt`
- `./logstotal init` — create the database tables, load workflows, create the admin account
- `./logstotal sync-workflows` — re-load workflow YAMLs from `workflows/` into the database
- `./logstotal sync-rules` — load the shared rules and lists from `rules/*.yml`; creates what is missing and updates what nobody edited (exit 1 on a file that does not parse)

## Preflight & secrets

- `./logstotal quickstart` — guided first Docker deploy: `.env` + secrets + preflight + up + health, idempotent. `QUICKSTART_PROFILE=postgres` starts on PostgreSQL instead of SQLite; `DOMAIN=... ACME_EMAIL=...` (or `DOMAIN=... QUICKSTART_TLS=internal`) brings the stack up behind Caddy so HTTPS needs no second step — see [HTTPS with Caddy](../install/https.md)
- `./logstotal doctor:docker` — full deployment preflight inside the web container (config, secrets, database, Redis, storage, migrations, workers, disk, hardware, tool binaries) with a fix for every failure; the check to use on a Docker host. Non-zero exit on failure
- `./logstotal doctor` — the same preflight run on the host itself, which can also check the Docker daemon and host ports; needs a development checkout with PDM
- `./logstotal show-admin-password` — print the admin login this deployment was created with, read back from `.env` (`ENV_FILE=deploy-envs/<host>.env` for a fleet). Prints a secret to the terminal, deliberately and only when asked
- `./logstotal gen-secrets` / `./logstotal gen-secrets -- --write` — generate all secrets, `ADMIN_PASSWORD` included (print, or fill empty/placeholder keys in `.env`)
- `./logstotal recommend-scaling` / `./logstotal recommend-scaling -- --apply` — recommend worker sizing for this host (print, or write the `.env` knobs); see [Scaling](../scaling.md)
- `./logstotal env:diff` / `./logstotal env:diff -- --strict` — diff `.env` against `.env.example`: new documented keys and unknown or misspelt keys (informational; `--strict` exits 1 if either report is non-empty)
- `DOMAIN=... ACME_EMAIL=... ./logstotal proxy:enable` — put Caddy in front: sets `COMPOSE_PROFILES`, `DOMAIN`, `PROXY_TLS`, `ACME_EMAIL`, `WEB_PORT`, `COOKIE_INSECURE` and `ENABLE_HSTS` in `.env`, runs a best-effort DNS check, idempotent. `-- --tls internal|custom|off` picks another TLS mode (see [HTTPS with Caddy](../install/https.md))

## Development

Development checkout only.

- `./logstotal validate-env` — quick `.env` sanity check (use `./logstotal doctor` for the full preflight)
- `./logstotal dev` — FastAPI dev server with live reload; prints the admin login from `.env` first, so the password `./logstotal setup` generated is at hand
- `./logstotal dev:check` — `validate-env`, then `dev`
- `./logstotal worker` / `./logstotal worker:watch` — Huey worker (`worker:watch` restarts on code changes)
- `./logstotal redis` / `./logstotal redis:bg` / `./logstotal redis:docker` — run Redis (foreground, background, or in Docker)
- `./logstotal health` — probe the app's `/health` at `http://localhost:8000` (works for local dev and a single Docker host)
- `./logstotal open` — open the app in a browser

## Code quality

- `./logstotal lint` — ruff check
- `./logstotal fmt` / `./logstotal fmt:check` — format, or check formatting
- `./logstotal lint:shell` — shellcheck every script under `scripts/`, the Docker entrypoints (`docker-entrypoint.sh`, `docker-caddy-entrypoint.sh`, `garage-entrypoint.sh`) and `./logstotal` itself
- `./logstotal check` — lint + fmt:check + lint:shell

## Testing

- `./logstotal test` — pytest, in parallel across every core (`-n auto --dist loadfile`). `./logstotal test -- -n0 tests/test_foo.py -k bar` runs serially with live output.
- `./logstotal test:js` — Node unit tests for the relationship-graph client (`node --test tests/js/`). No `package.json`; skips with a message when node is not installed.
- `./logstotal docs:build` — build this documentation website into `site/`, in strict mode: a broken link or anchor is an error. Needs `pdm install -G docs`.
- `./logstotal docs:serve` — preview the website at `http://localhost:8001`, rebuilding on save.
- `./logstotal test:pg` — the PostgreSQL-only SQL checks, against a throwaway `postgres:16-alpine` container it starts and removes (needs Docker; set `POSTGRES_TEST_URL` to use your own server instead). See [PostgreSQL SQL compatibility](../contribute/development.md#postgresql-sql-compatibility).
- `./logstotal test:cov` — pytest with coverage

## CI

One command per CI job. Both CI workflow files call exactly these, so every red CI job
reproduces locally with one command. See [Continuous integration](../contribute/development.md#continuous-integration).

- `./logstotal ci:test` — the whole suite in one pytest process, plus the graph JS tests. Set `POSTGRES_TEST_URL` to include the PostgreSQL-only checks.
- `./logstotal ci:artifacts` — the compose files parse, the image builds, the release archive builds, and neither ships a secret
- `./logstotal ci:deploy` — bring the Docker stack up for real, smoke it, and analyse a sample log end to end. `KEEP_STACK=yes` leaves it running.
- `./logstotal ci:dry-run` — shellcheck every script, then run the whole deploy chain against hosts that cannot resolve

## Database

Development checkout only (needs PDM); on Docker, migrations run automatically when the web container starts ([Database migrations](../runbooks/migrations.md)).

- `./logstotal db:reset` — DESTRUCTIVE: delete the SQLite database and re-initialise it
- `./logstotal db:shell` — SQLite shell on `logstotal.db`
- `./logstotal db:migrate` — run pending migrations (upgrade to head)
- `./logstotal db:revision -- "description"` — generate a new migration from model changes
- `./logstotal db:stamp -- head` — stamp the migration version table without running migrations
- `./logstotal db:to-postgres -- --postgres-url ...` — copy an existing SQLite database into PostgreSQL (see [Move from SQLite to PostgreSQL](../runbooks/sqlite-to-postgres.md)); refuses a populated target

## Backup / Restore

- `./logstotal backup` — **the canonical backup**: detects SQLite or PostgreSQL, dumps, verifies that exact file, and writes a non-secret receipt to `backups/last-verified.json`
- `./logstotal backup:sqlite` — timestamped SQLite backup in `backups/` (finds `./logstotal.db` or Docker's `./data/logstotal.db`)
- `./logstotal restore:sqlite` — restore from the most recent backup (or `BACKUP_FILE=...`)
- `./logstotal backup:postgres` — dump PostgreSQL to `backups/` (`pg_dump`, or the running postgres container)
- `./logstotal restore:postgres` — restore PostgreSQL from a dump (`psql`, or the running postgres container)
- `./logstotal backup:uploads` — archive the stored log files (`uploads/`) to `backups/`; also keep a copy of `.env` somewhere safe — see [Backup and restore](../runbooks/backup-and-restore.md)
- `./logstotal backup:verify` — check a backup file's integrity (`.db`, `.sql.gz` or `.tar.gz`; the newest in `backups/` by default, or `BACKUP_FILE=...`); exits non-zero on FAIL
- `./logstotal backup:prune` — DESTRUCTIVE: delete backups older than `BACKUP_RETENTION_DAYS` (default 14; a command option, not an app setting)

## Uploads

- `./logstotal uploads:clean` — DESTRUCTIVE: remove every file in `uploads/`, regardless of retention settings

## Clean

- `./logstotal clean` — remove the local database, uploads and caches (keeps `.env` and `.venv`)
- `./logstotal clean:all` — full wipe, `.env` and `.venv` included

## Docker

- `./logstotal docker:build` — build the images only
- `./logstotal docker:up` / `./logstotal docker:down` — build and start / stop all services
- `./logstotal docker:logs` / `./logstotal docker:logs:web` / `./logstotal docker:logs:worker` / `./logstotal docker:logs:proxy` — follow logs
- `./logstotal docker:restart` — restart without rebuilding
- `./logstotal docker:shell` — shell in the running web container
- `./logstotal docker:clean` — DESTRUCTIVE: remove containers, volumes, images and networks
- `./logstotal docker:worker-up` / `./logstotal docker:worker-down` / `./logstotal docker:worker-logs` — the standalone worker stack on a fleet's worker hosts

## Detection tools

- `./logstotal tools:check` — compare engine releases and rule snapshot commits with upstream, verifying installed checksums. Read-only; add `-- --strict` to fail on pending updates, unknown versions, changed files, or unreachable upstreams. Major version changes are flagged as BREAKING and need adapter validation.
- `./logstotal tools:update -- <tool>` — stage the latest binaries, matching mappings and configuration, and rules for each named tool, then install them under `tools/<tool>/` with a rollback copy in `backups/`. Requires every release asset and its SHA-256 checksum; refuses a major change without `--allow-major`. For Zircolite it refreshes the compiled rules only; its container digest in `workflows/*.yml` is changed separately. See [Detection tools and workflows](../runbooks/detection-tools.md).

## Vendor / Tailwind

Development checkout only.

- `./logstotal vendor:update` — download the JS/CSS bundles to `app/static/vendor/` (only when bumping a pinned version; the files are committed, so `./logstotal setup` does not run it and works offline)
- `./logstotal tailwind:install` — download the Tailwind CLI to `tools/tailwind/` (for `css:build`)
- `./logstotal css:build` — compile the production stylesheet (`tailwind-built.css`) and switch `base.html` to it
- `./logstotal css:prod` — switch `base.html` to the compiled stylesheet **without** recompiling it, for when the CLI is unavailable and the stylesheet in the tree is known to be current. It cannot tell current from stale — Tailwind emits only the classes it saw when it ran
- `./logstotal css:dev` — switch `base.html` back to the Tailwind play bundle (dev mode)

## Release (maintainer)

- `./logstotal release:prepare VERSION=X.Y.Z` — bump the three declared versions, move the CHANGELOG section and its links, sweep the docs (see [Cutting a release](../contribute/releasing.md#cutting-a-release))
- `./logstotal release:finish VERSION=X.Y.Z` — commit, tag, and run `./logstotal check && ./logstotal test`; never pushes

## Packaging

- `./logstotal package` — build the deployment archive (`logstotal-<version>.7z`)
- `./logstotal verify:artifacts` — run the release pipeline's artifact check locally: an archive (or built image) must ship no `.env`, database or uploads, and must ship what a deploy needs. CI runs the same script.
- `./logstotal bundle` — build a self-contained bundle for a closed network: the release archive plus every image it needs, for one CPU architecture. Run it on a machine with network access — see [Offline installation](../install/offline.md)
- `./logstotal bundle:verify -- <bundle>` — check a bundle before you carry it anywhere; needs no Docker

## Version & health

- `./logstotal version` — print the local version (the `VERSION` file, git commit and migration head)
- `HEALTH_URL=https://host ./logstotal health:remote` — probe a deployment's `/health` from a workstation (supports basic auth)

## Upgrade

- `./logstotal upgrade:plan` — read-only: what would an upgrade do? Resolves the release, names the source and the server it comes from, and checks the package can be fetched. Always exits 0
- `./logstotal upgrade` — upgrade to the latest release: this host, or the whole fleet when one is configured. `VERSION=X.Y.Z` pins a release; `ARCHIVE=` / `BUNDLE=` install from a file. Runs from a workstation or on the control plane, which reads its own fleet record (see [Upgrade and roll back](../runbooks/upgrading.md))
- `./logstotal upgrade:rollback` — undo the last upgrade: restore the previous release snapshot, rebuild, restart. Rolls back every host of the fleet when one is named (as arguments, in `deploy.env`, or in the control plane's fleet record), otherwise this host alone. Consumes the snapshot, so running it twice goes back two releases. Never touches the database

## Multi-server deploy

The usual order is **`deploy:init` → edit `deploy.env` → `deploy:plan` → `deploy`**; see
[Fleet installation](../install/fleet.md#automated-setup). Every option these commands
read is in the [`DEPLOY_*` reference](fleet.md#deploy_-reference).

- `./logstotal deploy` — **the one command**: bootstrap fresh hosts, optional WireGuard, generate and push one `.env` per host, deploy, smoke. Idempotent. Accepts a host list (`./logstotal deploy -- cp.example.com w1.example.com`), which it also records in `deploy.env`
- `./logstotal deploy:init` — write `deploy.env` from a host list, then stop, so you can edit it before anything is contacted (first host = control plane; refuses to overwrite, `FORCE=yes` overrides)
- `./logstotal deploy:plan` — report what a deploy would do to each host; changes nothing, always exits 0
- `./logstotal deploy:network` — print what must be reachable between the hosts and from where: the SSH, app, relay and WireGuard ports, each with the reason it exists, and which of them a host firewall actually governs (Docker-published ports bypass `ufw`). Connects to nothing. Run it *before* a first deploy
- `./logstotal deploy:bootstrap` — install Docker with the Compose plugin, 7z and rsync on every deploy host and create the install directory (idempotent; warns on an untested OS and continues)
- `./logstotal deploy:vpn` — build a WireGuard mesh across the deploy hosts with [Wireconf](https://github.com/wagga40/Wireconf) and record the addresses (`DEPLOY_VPN=wireconf`). A tunnel that was asked for and cannot be built **stops the deploy**; `DEPLOY_VPN_OPTIONAL=true` accepts falling back to public addresses
- `./logstotal deploy:env` — generate one ready-to-use `.env` per deploy host into `deploy-envs/` and install each on its host (shared secrets generated once and never rotated; hand-added keys kept; refuses to replace an `.env` edited on its host without `DEPLOY_ENV_PUSH_FORCE=yes`). `DEPLOY_ENV_PUSH=false` stops after generating
- `./logstotal deploy:env-scaffold` — generate template `.env` files for the control plane and workers into `deploy-envs/` (refuses if they already exist, since regenerating rotates the secrets in them; `FORCE=yes` overrides)
- `./logstotal deploy:env-scaffold:proxy` — the same scaffold, plus the Caddy/HTTPS block in `control-plane.env`
- `./logstotal deploy:preflight` — verify SSH, required tools and `.env` on every deploy host
- `./logstotal deploy:start` — start the stacks (first host control plane, others workers)
- `./logstotal deploy:stop` — stop the stacks without deploying (workers first, control plane last)
- `./logstotal deploy:status` — stack status and health on every host
- `./logstotal deploy:logs` — recent logs from every host
- `./logstotal deploy:shell` — SSH shell on one host (`DEPLOY_HOST`, default the first)
- `./logstotal deploy:exec` — run `DEPLOY_CMD` on every host
- `./logstotal deploy:smoke` — post-deploy health and smoke checks. The URL is `SMOKE_URL` if set, else `https://<DOMAIN>` behind the proxy, else `http://<first host>:8000`, else `http://localhost:8000`
- `./logstotal deploy:remove` — remove LogsTotal from every deploy host (needs `DEPLOY_REMOVE_CONFIRM=yes`)
- `./logstotal fleet` — on the control plane, show its record of the fleet: hosts, roles, versions, results (see [What the control plane knows](fleet.md#what-the-control-plane-knows))
- `./logstotal fleet:pull -- <control plane>` — fetch a control plane's fleet record and write a local `deploy.env` from it (refuses to overwrite one; `FORCE=yes` overrides)

---

**Related:** [Fleet reference](fleet.md) · [Configuration](../configuration.md) · [Health, logs and first-day checks](../runbooks/health-and-logs.md) · [Docs index](../README.md)
