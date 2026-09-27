# Fleet reference

Options, variables and day-2 commands for a fleet deployed with `./logstotal deploy`; the install flow itself is in [Fleet installation](../install/fleet.md).

Unless a section says otherwise, commands on this page run in the directory that holds
`deploy.env` — on your workstation or on the control plane — and reach the other hosts over
SSH.

## Options

Set these in `deploy.env` (written by `./logstotal deploy:init` or `./logstotal deploy`) or in
the environment of the command — the environment always wins.
[`deploy.env.example`](https://github.com/wagga40/LogsTotal/blob/main/deploy.env.example)
is the annotated template; every variable, with its default, is in the
[`DEPLOY_*` reference](#deploy_-reference) at the end of this page.

### A private network

**On by default for a multi-host fleet.** Building it is what keeps Redis, PostgreSQL and
Garage off a routable interface, so `./logstotal deploy` does it unless you say
otherwise:

```bash
DEPLOY_VPN=none ./logstotal deploy      # deploy over the hosts' own addresses instead
```

Without one, the deploy works out where the control plane is — it asks a worker what
the control plane's name resolves to, then asks the control plane for its own address —
and the relays bind there. That works, but those three services then sit on a routable
interface protected only by their generated passwords.

**A host firewall does not fix that.** Docker publishes ports by writing NAT and FORWARD
rules, never INPUT, so `ufw` and `firewalld` never see the traffic: on a control plane with
ufw active and only SSH allowed, `http://host:8000` still answers. Restricting them means
DOCKER-USER rules, or binding them to an address that is not routable — which is what the
tunnel does. `./logstotal deploy:network` lists which ports are which.

Two fleets resolve to `none` on their own, because a hub-and-spoke mesh with no spokes
protects nothing: a single-host fleet, and one where every host is the `local` entry.
An explicit `DEPLOY_VPN=wireconf` is honoured either way.

**An existing fleet is asked rather than converted.** If `deploy.env` exists and says
nothing about `DEPLOY_VPN`, the deploy stops and offers both commands — building a tunnel
re-addresses every cross-host URL, which on a running fleet means a restart. Answer once,
`echo 'DEPLOY_VPN=wireconf' >> deploy.env`, and it never asks again.

Building the tunnel installs [Wireconf](https://github.com/wagga40/Wireconf) if it is
missing — and updates it if the copy it finds is older than `DEPLOY_VPN_MIN_VERSION` — then
builds a hub-and-spoke WireGuard mesh with the control plane as hub, and records every
host's VPN address in `deploy-envs/vpn.json`, which the env-file step then uses for all
cross-host URLs. The hub gets `10.200.0.1`, the first worker `10.200.0.2`, and so on;
change the range with `DEPLOY_VPN_NETWORK`.

If the tunnel cannot be built, **the deploy stops** — including when it comes up but
carries nothing: after a failed verify the deploy checks whether every peer has completed
a WireGuard handshake, and stops if they have not. (Handshakes present with the verify
pings failing means a firewall is dropping ICMP, which is reported and safe.) Continuing
past a dead tunnel would bind Redis, PostgreSQL and Garage to a routable address — the
opposite of what asking for a VPN meant — and leave every worker pointed at an address that
does not answer, with jobs sitting in `pending`. `DEPLOY_VPN_OPTIONAL=true` opts back into
best-effort. (A failed *verify* is only a warning: the addresses are already recorded by
then, so nothing is exposed.)

**Tailscale** is supported but not automated — `tailscale up` needs an interactive login.
Set it up on every host yourself
([Manual step 1](../install/fleet-manual.md#manual-step-1-private-network)), then deploy with
`DEPLOY_VPN=tailscale` and `DEPLOY_CP_ADDRESS` set to the control plane's `100.x` address.
Without `DEPLOY_CP_ADDRESS` the deploy stops rather than fall back to public addresses.

### HTTPS and HTTP basic auth

```bash
DEPLOY_DOMAIN=logs.example.com DEPLOY_ACME_EMAIL=admin@example.com \
  DEPLOY_BASIC_AUTH_USER=admin DEPLOY_BASIC_AUTH_PASSWORD='a long passphrase' \
  ./logstotal deploy
```

Setting `DEPLOY_DOMAIN` is what turns the proxy on: it adds `proxy` to the control plane's
`COMPOSE_PROFILES`, sets `DOMAIN`/`PROXY_TLS`/`ACME_EMAIL`/`WEB_PORT`/`ENABLE_HSTS`, and
sets `COOKIE_INSECURE` to match. With the default `acme`, Caddy fetches a public
certificate on first start, so point DNS at the control plane and open ports 80 and 443
first.

**`DEPLOY_PROXY_TLS` chooses how TLS is terminated.** For an internal fleet:

```bash
DEPLOY_DOMAIN=logs.internal DEPLOY_PROXY_TLS=internal ./logstotal deploy
```

`internal` uses Caddy's own certificate authority — no DNS, no port 80, no internet.
`custom` serves a certificate you supply from `./certs` on the control plane; `off` serves
plain HTTP, for a network where something in front already terminates TLS. The four modes,
what each needs and the manual step `internal` requires are in
[HTTPS with Caddy](../install/https.md).

The basic-auth password is hashed **on the control plane** — it always has Docker, your
workstation may not — and only the bcrypt hash is written to a host's `.env`. Pass the
password in the environment for one run, or set `DEPLOY_BASIC_AUTH_HASH` instead: stored
in `deploy.env`, it is plaintext on the machine you deploy from.

To add HTTPS to a fleet that is already up without re-staging it, add the settings to
`deploy.env` so later deploys keep them:

```bash
DEPLOY_DOMAIN=logs.example.com
DEPLOY_ACME_EMAIL=admin@example.com
```

Then regenerate and push each host's `.env`, and restart:

```bash
./logstotal deploy:env
./logstotal deploy:start
```

`deploy:env` replaces a host's `.env` only while it is unchanged since the tooling last
pushed it. If someone edited one by hand, the push refuses and names the keys that would be
lost; `DEPLOY_ENV_PUSH_FORCE=yes` replaces it anyway.

### Adding a worker later

Append the host to `DEPLOY_HOSTS`, then name it:

```bash
DEPLOY_ONLY=w3.example.com ./logstotal deploy
```

Only that host is bootstrapped, staged and started. The control plane and the existing
workers keep running — the control plane's health is still checked, so a new worker never
comes up against a failing control plane.

### Other operating systems

LogsTotal is tested on **Ubuntu and Debian only**. The deploy reads `/etc/os-release` on
every host, names anything else, and **continues**. On a host with no `apt-get`,
`./logstotal deploy:bootstrap` prints what to install by hand and moves on, and
`./logstotal deploy:preflight` then reports whatever is still missing.

## SSH deploy (`./logstotal deploy`)

`./logstotal deploy` copies one release archive to every host over SSH and installs it. The
first host in `DEPLOY_HOSTS` is the control plane; every other host runs a worker only. The
step-by-step flow is in [Fleet installation](../install/fleet.md#automated-setup); the
hand-typed equivalent is [Manual step 3](../install/fleet-manual.md#manual-step-3-distribute-and-deploy).

**Which archive it sends**, in order:

1. `BUNDLE=`, `ARCHIVE=` or `VERSION=` when you pass one — a bundle, a file or URL, or a
   published release downloaded once on the deploying machine.
2. `DEPLOY_PACKAGE`, an explicit archive path. Nothing is built.
3. Otherwise the newest `logstotal-*.7z` in the working directory: reused when its name
   matches this tree's `VERSION` and no source file is newer than it, rebuilt with
   `./logstotal package` when not, built when there is none. It never prompts;
   `DEPLOY_REBUILD=true` or `false` overrides the decision.

**Each host needs** Docker with the Compose plugin, 7z (p7zip) and rsync — rsync takes the
release snapshot the deploy refuses to proceed without, and restores it on rollback — plus
SSH key access as root, or as a user with passwordless sudo (`BatchMode` is always on, so
there is no password prompt). `./logstotal deploy:bootstrap`, the first step of every
deploy, installs the packages on Ubuntu and Debian. Hosts do not need Task: each release
runs its own `./logstotal`, on the copy of go-task its archive carries.

**Running stacks are stopped first.** Unless you set them, `./logstotal deploy` sets
`DEPLOY_STOP`, `DEPLOY_KEEPENV` and `DEPLOY_START` to `true`: it stops each stack, keeps
each host's `.env`, and starts the stack again afterwards. With `DEPLOY_STOP=false`, a host
with something running aborts the deploy instead of being deployed over. Version upgrades
of a running fleet go through `./logstotal upgrade` (see [Upgrades](#upgrades)).

Example `deploy.env`:

```bash
DEPLOY_HOSTS=cp.example.com,10.0.0.2
SSH_IDENTITY=~/.ssh/id_ed25519
```

## Remote worker details

`./logstotal deploy` starts every worker for you (it runs `./logstotal docker:worker-up` on
each worker host). To start one yourself — to add a machine outside the deploy tooling, or
to debug one — work on the worker host, in its install directory:

1. Put the release there: the same archive the control plane runs, extracted.
2. Write its `.env`. Every connection points at the control plane: database, Redis, S3, and
   the same `SECRET_KEY`. The complete worker example is in
   [Manual step 2](../install/fleet-manual.md#manual-step-2-control-plane-and-worker-env-files);
   `./logstotal deploy:env` generates it for you.
3. Start it **from the install directory** — `docker-compose.worker.yml` bind-mounts
   `data/` and `uploads/` from there, and takes `DOCKER_HOST_WORKDIR` from it:

   ```bash
   ./logstotal docker:worker-up
   ```

4. Check it: `./logstotal docker:worker-logs` shows the Huey consumer starting, and the host
   appears on `/admin/workers` on the control plane, labelled with `WORKER_NAME` and
   `WORKER_IP` when they are set.

Add capacity by adding more machines with the same `.env` and compose file. Each worker
registers itself through Redis and takes jobs from the shared queue.

The worker container mounts `/var/run/docker.sock`, because Zircolite runs as a sibling
container on the host's Docker Engine; install Docker on the host and keep the daemon
running. Read [Docker socket on workers](../security.md#docker-socket-on-workers) for what
that mount implies.

**Per-host concurrency.** In a fleet of unequal machines, set a **max concurrent jobs** cap
per host on the **Worker Fleet** admin page: a larger cap on a powerful host, `0` for
unlimited, `-1` to pause a worker. See
[Worker fleet management](../runbooks/workers.md#worker-fleet-management).

## Fleet recipes

Every deploy command reads `DEPLOY_HOSTS` and the other variables from the environment or
from `deploy.env` in the working directory; the environment wins. Host entries are `host`
(SSH as root), `user@host`, or `local` (this machine, no SSH).

**Status across the fleet:**

```bash
./logstotal deploy:status                             # compose ps + health on every host
DEPLOY_CMD="docker ps" ./logstotal deploy:exec        # raw docker ps everywhere
./logstotal deploy:logs                               # recent logs per host
```

**A shell on one host:**

```bash
DEPLOY_HOST=10.0.0.2 ./logstotal deploy:shell
```

**Start and stop without redeploying** (workers stop first, the control plane last):

```bash
./logstotal deploy:stop
./logstotal deploy:start
```

**Destructive rebuild** (deletes volumes, databases included, and images on every host):

```bash
DEPLOY_STOP=true DEPLOY_CLEAN=true DEPLOY_CLEAN_CONFIRM=yes DEPLOY_START=true ./logstotal deploy
```

Every deploy command, with its options, is listed in
[Multi-server deploy](commands.md#multi-server-deploy).

## What the control plane knows

Every deploy writes a record of the fleet to `<install>/fleet/manifest.json` **on the
control plane** — hosts and their roles, the install directory, the release, and the
settings the deploy was given. Read it on the control plane with:

```bash
./logstotal fleet
```

The record is what lets `./logstotal upgrade` run **on** the control plane and know which
hosts it is responsible for, without the `deploy.env` of whichever machine ran the deploy.

It separates what was **asked for** from what was **found**. `entry`, `role` and the
options are configuration; `version`, `result` and `containers` are measurements. That is
what lets `./logstotal deploy:status` say *"the record names three workers and I can see two"*
instead of trusting one of the two.

### It is a source, not just a report

On the control plane the record is the **last** place every `DEPLOY_*` variable is looked
for — after the environment, after `deploy.env`. So a machine that was deployed *to* rather
than *from* still knows its own VPN mode, control-plane address, domain and worker count,
and a bare command works there:

```bash
./logstotal upgrade ARCHIVE=/root/logstotal-<version>.7z   # no DEPLOY_* needed
```

Answering last is the safety property: the record can fill a gap, never override a choice.
Set something explicitly and yours wins, so a stale record cannot redirect a run you were
specific about.

It answers twelve settings: `DEPLOY_REMOTE_DIR`, `DEPLOY_VPN`, `DEPLOY_VPN_PORT`,
`DEPLOY_VPN_NETWORK`, `DEPLOY_VPN_HUB_ENDPOINT`, `DEPLOY_CP_ADDRESS`,
`DEPLOY_CP_BIND_ADDRESS`, `DEPLOY_DOMAIN`, `DEPLOY_PROXY_TLS`, `DEPLOY_BASIC_AUTH_USER`,
`DEPLOY_HUEY_WORKERS` and `DEPLOY_KEEP_RELEASES`. It also supplies the host list itself —
and there the control plane's own entry comes back as `local`, because the record names it
as it was typed on a workstation, and read back on the control plane that name would mean
"SSH to yourself".

A host's `result` is one of `ok`, `unverified`, `failed`, `skipped` or `not-attempted`.
**`unverified` means the deploy could not confirm that host — not that the host is
broken.** Check such a host with `./logstotal deploy:status`.

**It holds no secrets.** It is world-readable on purpose, so it is safe to paste into a
bug report. The generated per-host `.env` files and the fleet's secrets stay in
`deploy-envs/` (mode 0600) on the machine that generated them, and are never fetched.

### Taking the record somewhere else

A workstation that has never seen this fleet — or one that lost its `deploy.env` — can
fetch the record and drive every deploy command from it.

**For good:** write a `deploy.env` from the record, and every later command runs bare:

```bash
./logstotal fleet:pull -- cp.example.com
```

It refuses to overwrite an existing `deploy.env` (`FORCE=yes` overrides), because yours may
hold settings the record does not carry.

**For one command:** name the control plane with `FLEET_FROM` and act on the fleet it
records — no `deploy.env` written, nothing set up:

```bash
FLEET_FROM=cp.example.com ./logstotal upgrade:plan     # what would happen
FLEET_FROM=cp.example.com ./logstotal upgrade          # do it
FLEET_FROM=cp.example.com ./logstotal deploy:status
```

| Variable | Default | Effect |
|----------|---------|--------|
| `FLEET_FROM` | *(unset)* | Read the fleet record from this control plane and act on the fleet it names. One host, never a list. Environment only |
| `FLEET_REFRESH` | `no` | `yes` fetches the record again instead of using the cached copy |
| `FLEET_CACHE_TTL` | `900` | Seconds a fetched record is reused, under `${XDG_CACHE_HOME:-~/.cache}/logstotal/fleet/` — so a plan-then-upgrade session costs one SSH round trip |

`FLEET_FROM` is an explicit opt-in and never inferred: `./logstotal upgrade -- cp.example.com`
still means **that one host**, and `DEPLOY_ONLY` already spells "a subset of the fleet".
Guessing between them would be a coin flip on `./logstotal deploy:remove`, which deletes
install directories.

**What a fetched record can and cannot do.** Secrets are never fetched, which is what makes
the record safe to pass around:

| Works | Refused |
|-------|---------|
| `./logstotal upgrade`, `upgrade:plan`, `upgrade:rollback` | `./logstotal deploy` |
| `./logstotal deploy:plan`, `deploy:status`, `deploy:logs`, `deploy:smoke` | `./logstotal deploy:env` |
| `./logstotal deploy:stop`, `deploy:start`, `deploy:remove` | |

The refusal is not a limitation to work around. Without `deploy-envs/secrets.json` the env
generator **mints a fresh** `SECRET_KEY`, `POSTGRES_PASSWORD` and `REDIS_PASSWORD`, and the
push step would overwrite a working remote `.env` it recognises as its own. PostgreSQL sets
its password once, when its data directory is created, so the new one authenticates against
nothing: the deploy looks green and then the control plane fails its health check. To
deploy, run from the machine holding `deploy-envs/`, or copy that directory across.

A fleet deployed **from** its own control plane records that host as `local`, which means
"this machine" and is only true where it was written. A fetch substitutes the recorded
control-plane address — or, failing that, the host you fetched from. Without it a
workstation would read `DEPLOY_HOSTS=local,w1` and deploy the control plane **to itself**.

## Release traceability and rollback

Each release carries a `VERSION` file holding its release number. `./logstotal deploy:status`
shows it for each host, and `./logstotal deploy:plan` compares it with the release you are
about to deploy.

Every deploy and upgrade snapshots the installed release on each host before it stages
anything, keeping `DEPLOY_KEEP_RELEASES` of them. How to roll back — and when a database
restore has to come first — is in [Rollback](../runbooks/upgrading.md#rollback).

## Monitoring workers

The admin page `/admin/workers` shows:

- Live workers with their name, advertised IP, and heartbeat
- Queue depth (pending jobs)
- Stuck jobs (running with no heartbeat) with a one-click recovery button

## Scaling the web tier

On the control plane, run several web replicas behind Caddy (the `proxy` profile):

```bash
docker compose up -d --scale web=N
```

A host port can be bound only once, so the default `WEB_PORT` — which publishes the web
container on a fixed port — makes every replica after the first fail to start. Before
scaling, set `WEB_PORT=127.0.0.1::8000` in `.env`: each replica then gets its own loopback
port, and Caddy reaches them over the Compose network. Docker's DNS resolves `web` to every
replica, so Caddy spreads requests across them with no Caddy change. Replicas take turns
initialising and migrating the database: each waits for the one before it to finish.

With no fixed port, anything that probes `http://localhost:8000` needs the public URL
instead — `HEALTH_URL=https://<DOMAIN> ./logstotal health:remote`, and the same
`HEALTH_URL` for `./logstotal upgrade`'s health check.

## Upgrades

Version upgrades of a running fleet go through `./logstotal upgrade`. It wraps the deploy in
a verified control-plane backup, migrations on the control plane only, a doctor check
inside the container and a smoke check, with safe defaults — workers stop first, each
host's `.env` is kept, and workers restart behind the control plane's health check:

```bash
./logstotal upgrade -- cp worker1
```

The full procedure, migration ordering and rollback rules are in
[Upgrade and roll back](../runbooks/upgrading.md).

After an install:

- Before real load, size each worker host with `./logstotal recommend-scaling` (see [Scaling](../scaling.md)).
- Run the [first-day checklist](../runbooks/health-and-logs.md#first-day-after-deploy) before users arrive.

## `DEPLOY_*` reference

These configure the **deployment**, not the application. None of them belong in `.env`;
they live in `deploy.env` beside it, or in the environment of the command you run — and
the environment always wins. On a control plane the [fleet record](#it-is-a-source-not-just-a-report)
answers last, after both.

`deploy.env` is read with `grep` and `cut`, never by a shell: **no quotes, no inline
comments, no indentation, no `export` prefix**. Booleans are `true` / `false` (`1`, `yes`,
`on` also work; `True` and `Yes` count as **false**). `DEPLOY_ENV_FILE` names a different
file to read.

The **Set in** column says where a value is meant to come from:

| | Meaning |
|---|---|
| `deploy.env` | A setting. Put it in the file, or override it for one run from the environment |
| **env only** | Per-invocation, or a confirmation. Reading it from a file would be wrong — see each row |

Variables the scripts set for each other are listed in
[Development → Deploy tooling internals](../contribute/development.md#deploy-tooling-internals).

### The fleet

| Variable | Set in | Default | Effect |
|----------|--------|---------|--------|
| `DEPLOY_HOSTS` | `deploy.env` | — (required) | Comma-separated. **The first entry is the control plane**, which runs `./logstotal docker:up`; the others run `./logstotal docker:worker-up`. An entry is `host` (SSH as root), `user@host`, or `local` (this machine, no SSH; needs root or passwordless sudo). Positional arguments (`./logstotal deploy -- cp w1`) beat both |
| `DEPLOY_REMOTE_DIR` | `deploy.env` | `/opt/logstotal` | The install directory on every host |
| `SSH_IDENTITY` | `deploy.env` | agent / `~/.ssh/config` | SSH private key. A leading `~` is expanded; a path that does not exist is an error, not a silent fallback |
| `DEPLOY_ONLY` | `deploy.env` | — | Comma-separated subset of `DEPLOY_HOSTS` to act on, leaving every other host running and untouched. How a worker joins a live fleet: the control plane's health is still checked, but it is not restarted |
| `DEPLOY_ENV_FILE` | env only | `deploy.env` | Which defaults file to read. It cannot name itself |

### Which release to deploy

| Variable | Set in | Default | Effect |
|----------|--------|---------|--------|
| `VERSION` | env only | this tree | Deploy that **published** release (e.g. `VERSION=1.2.3`), downloaded once on the deploying machine and copied to every host. Same knob as `./logstotal upgrade` |
| `ARCHIVE` | env only | — | Deploy exactly this `.7z` (path or `https://` URL). No release lookup happens |
| `DEPLOY_PACKAGE` | `deploy.env` | newest `logstotal-*.7z` in the working directory | An explicit archive path. Nothing is built |
| `DEPLOY_REBUILD` | `deploy.env` | (decided) | `true` rebuilds the package, `false` reuses the existing one. Unset: reuse it when its name matches this tree's `VERSION` and no source file is newer, otherwise rebuild. There is no prompt |
| `DEPLOY_ALLOW_DOWNGRADE` | `deploy.env` | `false` | Deploy a tree older than the last release deployed from this machine |
| `RELEASE_REPO_URL` | `deploy.env` | derived | Where releases are published. Derived from `.release-origin`, then the git `origin`. Set it when `origin` is an SSH URL, which carries no web scheme or port |

### What runs, and when

| Variable | Set in | Default | Effect |
|----------|--------|---------|--------|
| `DEPLOY_BOOTSTRAP` | `deploy.env` | `true` | Install Docker with the Compose plugin, 7z and rsync (and wireguard-tools with `DEPLOY_VPN=wireconf`) on each host. `false` when hosts are already prepared |
| `DEPLOY_STOP` | `deploy.env` | `true` from `./logstotal deploy` | Stop stacks before staging (`./logstotal docker:down` on the control plane, the worker stack elsewhere). Without it, a host with something running aborts the deploy rather than deploying over it |
| `DEPLOY_START` | `deploy.env` | `true` from `./logstotal deploy` | Start stacks after staging. `false` leaves them stopped |
| `DEPLOY_KEEPENV` | `deploy.env` | `true` from `./logstotal deploy` | Copy each host's `.env` off before staging and restore it after |
| `DEPLOY_SKIP_SMOKE` | `deploy.env` | `false` | Skip the post-deploy check |
| `DEPLOY_STRICT` | `deploy.env` | `false` | A worker whose stack could not be **confirmed** running fails the deploy. Off by default: the poll giving up is a statement about the wait, not about the worker |
| `DEPLOY_PREFLIGHT_STAGE` | `deploy.env` | `all` | `pre` is the gate before bootstrap (reachability, remote shell, privilege, clock; missing tools are INFO). `post` is the fatal tool check. `./logstotal deploy` runs both, in that order |
| `DEPLOY_PLAN_FORMAT` | `deploy.env` | `text` | How `./logstotal deploy:plan` reports. `json` prints one document on stdout — settings, findings, per-host verdicts and counts — and moves the human check stream to stderr, so `./logstotal deploy:plan \| jq` works. Ignored outside a plan run |
| `DEPLOY_HEALTH_ATTEMPTS` / `DEPLOY_HEALTH_DELAY` | `deploy.env` | `30` / `2` | Control-plane `/health` polling, and the cadence the worker check reuses |
| `DEPLOY_KEEP_RELEASES` | `deploy.env` | `3` | Rollback snapshots kept per host |
| `DEPLOY_DRY_RUN` | `deploy.env` | `false` | Print every command; connect to nothing. Every step honours it, the smoke check included |

### Private network

| Variable | Set in | Default | Effect |
|----------|--------|---------|--------|
| `DEPLOY_VPN` | `deploy.env` | `wireconf` | `wireconf` builds a WireGuard mesh with the control plane as hub. `tailscale` uses a Tailscale network you set up yourself, and needs `DEPLOY_CP_ADDRESS`. `none` deploys over the hosts' own addresses |
| `DEPLOY_VPN_OPTIONAL` | `deploy.env` | `false` | `true` lets a VPN that cannot be built fall back to public addresses. Otherwise the deploy **stops** — falling back is the opposite of the request |
| `DEPLOY_VPN_NETWORK` | `deploy.env` | `10.200.0.0/24` | The mesh's address range; the hub takes `.1` |
| `DEPLOY_VPN_PORT` | `deploy.env` | `51820` | WireGuard listen port. Opened on the **hub only** — spokes dial out from ephemeral ports |
| `DEPLOY_VPN_HUB_ENDPOINT` | `deploy.env` | discovered | The address spokes dial. Required when the control plane is `local` |
| `DEPLOY_VPN_MIN_VERSION` | `deploy.env` | `0.3.8` | Oldest Wireconf the deploy will run; an older copy is updated for you. Set it only to run an older build deliberately |
| `DEPLOY_VPN_INSTALL` | `deploy.env` | `true` | Install Wireconf when it is missing |
| `DEPLOY_VPN_RETRIES` / `DEPLOY_VPN_DELAY` | `deploy.env` | `12` / `5` | How long to wait for the tunnel to come up |
| `DEPLOY_OPEN_WG_PORT` | `deploy.env` | `true` with wireconf | Add the hub's inbound `ufw` rule |
| `DEPLOY_CP_ADDRESS` | `deploy.env` | discovered | The address **workers use** for the control plane. With Tailscale, its `100.x` address |
| `DEPLOY_CP_BIND_ADDRESS` | `deploy.env` | the above, or `0.0.0.0` | The address the relays **bind to**. Must be an IP: Docker binds ports by address, never by name |

### Env files, HTTPS and basic auth

| Variable | Set in | Default | Effect |
|----------|--------|---------|--------|
| `DEPLOY_ENV_DIR` | `deploy.env` | `deploy-envs` | Where the generated per-host `.env` files and the fleet's secrets live (mode 0600) |
| `DEPLOY_ENV_FORCE` | `deploy.env` | `false` | Regenerate the shared secrets. **Rotates `SECRET_KEY` and the database password** |
| `DEPLOY_ENV_PUSH` | `deploy.env` | `true` | `false` generates the per-host files and stops, without installing any of them |
| `DEPLOY_ENV_PUSH_FORCE` | `deploy.env` | `false` | `yes` replaces an `.env` already on a host even if it was edited there (kept by default) |
| `DEPLOY_ADMIN_EMAIL` | `deploy.env` | `admin@example.com` | The admin account created on first start |
| `DEPLOY_HUEY_WORKERS` | `deploy.env` | `4` | Worker threads per host |
| `DEPLOY_DOMAIN` | `deploy.env` | — | **Setting it turns the Caddy proxy on** for the control plane |
| `DEPLOY_PROXY_TLS` | `deploy.env` | `acme` | `acme`, `internal`, `custom` or `off` — see [HTTPS with Caddy](../install/https.md#choose-a-tls-mode) |
| `DEPLOY_ACME_EMAIL` | `deploy.env` | `admin@$DOMAIN` | Let's Encrypt contact address |
| `DEPLOY_BASIC_AUTH_USER` | `deploy.env` | — | HTTP basic-auth username |
| `DEPLOY_BASIC_AUTH_PASSWORD` | `deploy.env` | — | Hashed **on the control plane**; only the hash reaches a host's `.env`. Better passed in the environment for one run: stored in `deploy.env` it is plaintext on the machine you deploy from, so keep that file at mode 600 or set `DEPLOY_BASIC_AUTH_HASH` instead |
| `DEPLOY_BASIC_AUTH_HASH` | `deploy.env` | derived | A bcrypt hash you produced yourself, instead of the password |

### Removal

| Variable | Set in | Default | Effect |
|----------|--------|---------|--------|
| `DEPLOY_REMOVE_CONFIRM` | env only | — | Must be exactly `yes` for `./logstotal deploy:remove`. **Not read from `deploy.env`**: it is the confirmation, and a confirmation you wrote down once is not one |
| `DEPLOY_REMOVE_KEEP_DATA` | `deploy.env` | `no` | Keep `data/`, `uploads/` and `backups/`; remove everything else |
| `DEPLOY_REMOVE_VPN` | `deploy.env` | `no` | Also bring `wg0` down, drop its config, and delete the local address map |
| `DEPLOY_CLEAN` | `deploy.env` | `false` | `docker compose down -v --rmi all` on both stacks, on every targeted host. **Deletes named volumes, databases included** |
| `DEPLOY_CLEAN_CONFIRM` | env only | — | Must be `yes` alongside `DEPLOY_CLEAN=true`, or the deploy refuses. A confirmation, for the reason above |

### Day-2 commands

| Variable | Set in | Default | Effect |
|----------|--------|---------|--------|
| `DEPLOY_HOST` | env only | first in `DEPLOY_HOSTS` | Which host `./logstotal deploy:shell` opens |
| `DEPLOY_CMD` | env only | — | The command `./logstotal deploy:exec` runs on every host |
| `DEPLOY_LOGS_LINES` | `deploy.env` | `120` | Lines per host for `./logstotal deploy:logs` |

`FLEET_FROM`, `FLEET_REFRESH` and `FLEET_CACHE_TTL` are in
[Taking the record somewhere else](#taking-the-record-somewhere-else).

---

**Related:** [Fleet installation](../install/fleet.md) · [Configuration](../configuration.md) · [Upgrade and roll back](../runbooks/upgrading.md) · [Security](../security.md) · [Docs index](../README.md)
