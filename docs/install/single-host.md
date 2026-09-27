# Single-host installation

Run the whole application on one machine with Docker Compose: web, worker and Redis, with
SQLite by default.

Start from a release unpacked as described in
[Getting the software onto the machine](prerequisites.md#getting-the-software-onto-the-machine).
For a single host you can extract it straight to `/opt/logstotal` and install there. Every
command below runs on the host, from that directory.

## Guided install

```bash
cd /opt/logstotal
./logstotal quickstart
```

`./logstotal quickstart` does everything a first installation needs, in order:

1. Checks that Docker and Compose work.
2. Creates `.env` from `.env.example` if there is none.
3. Sets `COOKIE_INSECURE=true`, so login works over plain HTTP on port 8000.
4. Generates every secret, including a strong admin password, which it prints once. Save it.
5. Builds the image, runs the deployment checks inside a container, and stops if any fails.
6. Starts the stack and waits for `/health` to answer.

It is safe to re-run: it never overwrites a value already set in `.env`.

Open `http://<host>:8000` and log in with `ADMIN_EMAIL` from `.env` (`admin@example.com`
unless you changed it) and the printed password. `./logstotal show-admin-password` prints the
password again.

Two variants, chosen on the first run:

```bash
QUICKSTART_PROFILE=postgres ./logstotal quickstart                             # PostgreSQL instead of SQLite
DOMAIN=logs.example.com ACME_EMAIL=admin@example.com ./logstotal quickstart   # HTTPS with Caddy
```

The second, and its air-gapped variant, are explained in [HTTPS with Caddy](https.md).

## Manual install

The same result, one step at a time:

```bash
cd /opt/logstotal
cp .env.example .env
./logstotal gen-secrets -- --write
```

`./logstotal gen-secrets -- --write` fills `SECRET_KEY`, `ADMIN_PASSWORD` and the database,
Redis, S3 and Garage secrets, and prints the admin password once. It only fills keys that are
empty or still a placeholder.

Then edit `.env`:

- Set `ADMIN_EMAIL`.
- If users will reach the host over plain HTTP on port 8000, set `COOKIE_INSECURE=true`.
  Without it the browser drops the login cookie and login appears to fail — see
  [Cookies over plain HTTP](../configuration.md#cookies-over-plain-http).

Start the stack and check it:

```bash
./logstotal docker:up
./logstotal doctor:docker
```

The admin account is created from `ADMIN_EMAIL` and `ADMIN_PASSWORD` on first start. The
first start fails if `ADMIN_PASSWORD` is still `changeme123` or is otherwise weak, which is
why `gen-secrets` comes first. Database migrations also run on every start — see
[Database migrations](../runbooks/migrations.md). Follow the logs with `./logstotal docker:logs`.

## What runs

- **SQLite** keeps its database in `data/` in the install directory.
- **Redis** is started with `REDIS_PASSWORD` from `.env`, which `gen-secrets` fills; the app
  and worker use the same value. With the key left empty, Redis runs without a password. To
  use an external Redis instead, set `REDIS_HOST`, `REDIS_PORT` and `REDIS_PASSWORD` to
  point at it.
- **The worker** mounts the host's Docker socket so it can run Zircolite as a container.
  Read [Docker socket on workers](../security.md#docker-socket-on-workers) before exposing
  the host.

To run more worker containers, `docker compose up --scale worker=2 -d`. Each runs
`HUEY_WORKERS` threads, shared by analysis jobs and admin maintenance tasks. With SQLite,
raise one of the two at a time and watch CPU, memory and the queue — see
[Scaling and capacity planning](../scaling.md).

## Optional services (Compose profiles)

The default stack is web, worker and Redis. Everything else Compose can start is opt-in,
named in `COMPOSE_PROFILES` in `.env`:

| Profile | Adds | Use it when |
|---------|------|-------------|
| `postgres` | Bundled PostgreSQL | You have outgrown SQLite's single writer — see [With PostgreSQL](#with-postgresql) |
| `proxy` | Caddy, with automatic TLS and optional basic auth | You want HTTPS — see [HTTPS with Caddy](https.md) |
| `s3` | Bundled Garage S3-compatible object storage | Workers on other machines must read the uploads |
| `workers` | Relays that expose Redis, PostgreSQL and Garage to remote workers | Workers on other machines |

Combine them with commas: `COMPOSE_PROFILES=postgres,proxy`. Each profile also needs a
setting of its own (a password, a domain) — see
[Docker Compose profiles](../configuration.md#docker-compose-profiles). The last two are for
a [fleet](fleet.md).

## With PostgreSQL

Add two lines to `.env`:

```bash
COMPOSE_PROFILES=postgres
POSTGRES_PASSWORD=set-a-strong-password
```

Then run `./logstotal docker:up`. Both lines are required; with only the password, the stack
stays on SQLite and warns. `POSTGRES_USER` and `POSTGRES_DB` are optional and default to
`logstotal`. The data lives in the `postgres_data` Docker volume. See
[Docker Compose profiles](../configuration.md#docker-compose-profiles) for the password
characters to avoid.

On a new installation, `QUICKSTART_PROFILE=postgres ./logstotal quickstart` makes both edits
for you. To move an existing SQLite installation, follow
[Move from SQLite to PostgreSQL](../runbooks/sqlite-to-postgres.md).

## After installing

- Size the host before real traffic: `./logstotal recommend-scaling`.
- Go through the [first-day checklist](../runbooks/health-and-logs.md#first-day-after-deploy).
- Go through the [security checklist](../security.md#production-hardening-checklist) before
  anyone else can reach the instance.
