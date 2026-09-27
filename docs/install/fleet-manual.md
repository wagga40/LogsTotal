# Manual fleet installation

How to set up a fleet by hand, when the [automated fleet installation](fleet.md) does not fit.

Take this path for **external managed PostgreSQL, Redis or S3**, a private network you
already run, or hosts you want to configure yourself. The three steps below are what
`./logstotal deploy` otherwise does for you. Commands run on your workstation unless a step
says otherwise.

## Manual step 1: Private network

Every machine must reach PostgreSQL, Redis and S3. With managed services on public
endpoints you may not need a private network. With the bundled services, set one up
**first**, so every host has a stable private address before you write the `.env` files in
[step 2](#manual-step-2-control-plane-and-worker-env-files).

> [!WARNING]
> **A hub-and-spoke network is a single point of failure.** With Wireconf or a manual
> WireGuard hub, all worker traffic goes through the control plane's endpoint. If the hub
> goes down, workers cannot reach Redis, PostgreSQL or S3 and the fleet stops. Either run
> Tailscale (NAT traversal and redundant relays), put the control plane behind highly
> available ingress, or accept the risk and fail over quickly. Monitor `wg show` handshake
> times alongside the worker heartbeats.

| Option | Best for | Trade-offs |
|--------|----------|------------|
| **Wireconf** (WireGuard) | Full control, no third-party service | You manage the keys; the hub needs a public IP or port forwarding |
| **Tailscale** | Fast setup, NAT traversal, access control lists | Requires a Tailscale account |
| **Manual WireGuard** | Custom topologies, existing WireGuard infrastructure | Most configuration effort |

### Option A: Wireconf

[Wireconf](https://github.com/wagga40/Wireconf) sets up a WireGuard hub-and-spoke network
over SSH. The first host in its inventory becomes the hub (the control plane); the others
become peers (the workers).

```bash
git clone https://github.com/wagga40/Wireconf.git && cd Wireconf
chmod +x wireconf
./wireconf init          # creates inventory and wireconf.env
```

Edit `inventory` — the control plane on the first line, workers below:

```
root@cp.example.com no
root@worker-1.example.com no
root@worker-2.example.com no
```

If the control plane's public IP differs from its name in the inventory, set
`WG_HUB_ENDPOINT` in `wireconf.env`. Then:

```bash
./wireconf plan          # check SSH, OS and tools, show the address layout
./wireconf apply         # generate keys, upload configurations, bring the tunnels up
./wireconf verify        # confirm handshakes and hub-to-peer pings
```

The hub gets `10.200.0.1`, the first peer `10.200.0.2`, and so on. `./wireconf status`
shows tunnel health at any time.

### Option B: Tailscale

[Tailscale](https://tailscale.com/) is WireGuard with automatic NAT traversal and an admin
console for access control. On each machine (Ubuntu or Debian):

```bash
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up
```

Each machine gets a stable `100.x.y.z` address. Use
[Tailscale ACLs](https://tailscale.com/kb/1018/acls/) to limit which machines can reach the
database and Redis ports.

### Option C: Manual WireGuard

Follow [WireGuard's quick start](https://www.wireguard.com/quickstart/) to build a
hub-and-spoke `wg0`: the control plane as hub, each worker's `AllowedIPs` a `/32`, and
`PersistentKeepalive = 25` on the workers so NAT keeps the tunnel open. Check it with
`ping <hub-ip>` from a worker.

**You now have a private address for each host** — the control plane (for example
`10.200.0.1`) and each worker (`10.200.0.2`, `10.200.0.3`, …). Use them wherever step 2
shows an example address.

## Manual step 2: Control plane and worker env files

Generate both files instead of writing them by hand:

```bash
./logstotal deploy:env-scaffold        # writes deploy-envs/control-plane.env and deploy-envs/worker.env
```

The templates are for the bundled services (PostgreSQL, Garage S3 and Redis on the control
plane, exposed to the workers). They come with `SECRET_KEY`, `ADMIN_PASSWORD`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD` and the S3 keys already generated, and with example
addresses: `10.0.0.1` for the control plane, `10.0.0.2` for the first worker. The command
refuses to overwrite an existing scaffold, because a new one would rotate every secret.

For HTTPS in front of the control plane, run `./logstotal deploy:env-scaffold:proxy`
instead. It writes the same two files and adds the Caddy settings to `control-plane.env`
(`proxy` profile, `DOMAIN`, `PROXY_TLS`, `ACME_EMAIL`, `WEB_PORT`, `COOKIE_INSECURE=false`,
`ENABLE_HSTS=true`). See [HTTPS with Caddy](https.md) for the TLS modes.

Then edit both files:

- Replace the example addresses with the real ones from step 1.
- Set `ADMIN_EMAIL` on the control plane, and `DOMAIN` and `ACME_EMAIL` if you used `:proxy`.
- Give each worker its own `WORKER_NAME` and `WORKER_IP`.
- Add `GARAGE_RPC_SECRET` and `GARAGE_ADMIN_TOKEN` to `control-plane.env`:
  `./logstotal gen-secrets` prints a fresh pair. Left empty, Garage starts with built-in
  defaults and warns.

> [!IMPORTANT]
> Each worker's `DATABASE_URL`, `REDIS_URL` and `S3_ENDPOINT` must point at the **same
> addresses** the control plane publishes through `POSTGRES_EXPOSE`, `REDIS_EXPOSE` and
> `GARAGE_EXPOSE`. If they disagree, jobs stay `pending` or fail right after a worker picks
> them up.

On the control plane, `POSTGRES_PASSWORD` **together with** `postgres` in
`COMPOSE_PROFILES` is what switches it from SQLite to PostgreSQL; the scaffold sets both.
See [Docker Compose profiles](../configuration.md#docker-compose-profiles).

### Control-plane `.env`

To write the file by hand for the bundled services:

```bash
# Generate with: ./logstotal gen-secrets
SECRET_KEY=<64-char-hex>
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=<strong-password>

# postgres + s3 (Garage) + workers (exposes Redis, PostgreSQL and Garage to the workers)
COMPOSE_PROFILES=postgres,s3,workers
POSTGRES_PASSWORD=<strong-password>

# S3 storage — required for a fleet, because workers do not share a filesystem
STORAGE_BACKEND=s3
S3_BUCKET=logstotal
S3_ACCESS_KEY=<GK-prefixed-key>
S3_SECRET_KEY=<64-char-hex>
S3_REGION=logstotal
GARAGE_RPC_SECRET=<64-char-hex>
GARAGE_ADMIN_TOKEN=<token>

# The `workers` profile publishes Redis, PostgreSQL and Garage on these addresses.
# Use the control plane's private address, so only the private network reaches them.
REDIS_PASSWORD=<strong-password>
REDIS_EXPOSE=10.0.0.1:6379
POSTGRES_EXPOSE=10.0.0.1:5432
GARAGE_EXPOSE=10.0.0.1:3900

# Plain HTTP until Caddy is in front; set to false (or remove) once it is.
COOKIE_INSECURE=true
```

`./logstotal docker:up` on the control plane then starts PostgreSQL, Redis, Garage, the
relays for the three of them, the web service and a local worker.

### Worker `.env`

Every worker's `.env` points at the control plane. The values marked "same as the control
plane" must match it exactly:

```bash
SECRET_KEY=<same as the control plane>
WORKER_NAME=worker-eu-west-1      # the name shown on /admin/workers
WORKER_IP=10.0.0.2                # the address shown on /admin/workers

DATABASE_URL=postgresql+asyncpg://logstotal:<postgres-password>@10.0.0.1:5432/logstotal
SYNC_DATABASE_URL=postgresql+psycopg2://logstotal:<postgres-password>@10.0.0.1:5432/logstotal
REDIS_URL=redis://:<redis-password>@10.0.0.1:6379

STORAGE_BACKEND=s3
S3_ENDPOINT=http://10.0.0.1:3900
S3_BUCKET=logstotal
S3_ACCESS_KEY=<same as the control plane>
S3_SECRET_KEY=<same as the control plane>
S3_REGION=logstotal

# Worker threads — docker-compose.worker.yml defaults to 4
HUEY_WORKERS=4
```

A worker host runs `docker-compose.worker.yml`, started with `./logstotal docker:worker-up`
from the install directory. How workers register, and how to cap each one's concurrent
jobs, is in [Remote worker details](../reference/fleet.md#remote-worker-details).

### External managed services

With managed PostgreSQL, Redis and S3 (for example AWS RDS, ElastiCache, S3, Cloudflare R2
or Backblaze B2), point `DATABASE_URL`, `REDIS_URL` and the `S3_*` variables at them on
every host. The control plane then needs neither the `s3` nor the `workers` profile:

```bash
COMPOSE_PROFILES=proxy   # only if you want Caddy for HTTPS
DATABASE_URL=postgresql+asyncpg://user:pass@your-pg-host:5432/logstotal
REDIS_URL=redis://:password@your-redis-host:6379
STORAGE_BACKEND=s3
S3_ENDPOINT=https://s3.us-east-1.amazonaws.com
S3_BUCKET=logstotal
S3_ACCESS_KEY=AKIA...
S3_SECRET_KEY=...
S3_REGION=<provider-region>
```

## Manual step 3: Distribute and deploy

Copy each file to its host as `.env`. The scaffold prints these commands when it finishes:

```bash
ssh root@cp     mkdir -p /opt/logstotal
ssh root@worker mkdir -p /opt/logstotal
scp deploy-envs/control-plane.env root@cp:/opt/logstotal/.env
scp deploy-envs/worker.env root@worker:/opt/logstotal/.env
```

Then, in `deploy.env` on your workstation, list the hosts — **the control plane first**,
then the workers — and tell the deploy not to build a private network, because you built
one in step 1:

```bash
DEPLOY_HOSTS=cp.example.com,worker-1.example.com,worker-2.example.com
DEPLOY_VPN=none
```

With Tailscale, also set `DEPLOY_CP_ADDRESS` to the control plane's `100.x` address. Then:

```bash
./logstotal deploy:preflight      # SSH, tools and a .env on every host
./logstotal deploy
```

`./logstotal deploy` keeps the `.env` already on each host. It starts the control plane with
`./logstotal docker:up` and each worker with `./logstotal docker:worker-up`, and finishes by
checking `/health`; `./logstotal deploy:smoke` repeats that check at any time. Its settings
are described in [SSH deploy](../reference/fleet.md#ssh-deploy-logstotal-deploy) in the fleet
reference.
