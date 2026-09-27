# HTTPS with Caddy

How to put Caddy in front of a single-host installation so users reach LogsTotal over HTTPS.
A fleet sets the same thing up through `DEPLOY_DOMAIN` — see
[Fleet installation](fleet.md#before-you-start-three-decisions).

HTTPS is the `proxy` Compose profile: Caddy in front of the app, obtaining and renewing its
certificate by itself. Every command on this page runs on the host, from the install
directory.

## Choose a TLS mode

`PROXY_TLS` decides how Caddy gets its certificate, and the rest follows from it:

| `PROXY_TLS` | Use when | What Caddy does | Needs | `COOKIE_INSECURE` | `ENABLE_HSTS` |
|---|---|---|---|---|---|
| `acme` *(default)* | The instance is on the internet under a public name | Fetches a certificate from Let's Encrypt and renews it | A public DNS record for `DOMAIN` pointing at the host; ports **80 and 443** reachable from the internet; `ACME_EMAIL` | `false` | `true` |
| `internal` | An internal or air-gapped network | Issues a certificate from its own certificate authority | Nothing: no DNS, no port 80, no internet. Clients must trust Caddy's root — see [Air-gapped and internal networks](#air-gapped-and-internal-networks) | `false` | `false` |
| `custom` | Your organisation already issues certificates | Serves your certificate and key from `./certs` | The certificate and key files — see [Your own certificate](#your-own-certificate) | `false` | `true` |
| `off` | A load balancer or another proxy already terminates TLS in front of this one | Serves plain HTTP | Something in front that terminates TLS | `true` | `false` |

`COOKIE_INSECURE` and `ENABLE_HSTS` must match the mode. When they do not, login fails
without an error message. The commands below set all of them together.

`DOMAIN` must be a name or an IPv4 address; an IPv6 literal does not work (see
[Known limitations](../limitations.md#deployment)). For `internal`, any name works, including
one that only your DNS or an `/etc/hosts` entry resolves.

## Turn it on

On a new host, from the very first command:

```bash
DOMAIN=logs.example.com ACME_EMAIL=admin@example.com ./logstotal quickstart   # acme
DOMAIN=logs.internal QUICKSTART_TLS=internal ./logstotal quickstart           # internal
```

On an installation that is already running:

```bash
DOMAIN=logs.example.com ACME_EMAIL=admin@example.com ./logstotal proxy:enable   # acme
DOMAIN=logs.internal ./logstotal proxy:enable -- --tls internal                 # internal
DOMAIN=logs.example.com ./logstotal proxy:enable -- --tls custom                # custom
DOMAIN=logs.example.com ./logstotal proxy:enable -- --tls off                   # off
./logstotal docker:up
```

`QUICKSTART_TLS` accepts the same four modes as `--tls`. Both commands write the same seven
`.env` keys: `COMPOSE_PROFILES` (keeping any other profiles), `DOMAIN`, `PROXY_TLS`,
`ACME_EMAIL`, `WEB_PORT=127.0.0.1:8000:8000` so the app itself is no longer reachable from
outside, and the `COOKIE_INSECURE` and `ENABLE_HSTS` pair for the mode. `./logstotal proxy:enable`
is safe to re-run, and for `acme` it checks that `DOMAIN` resolves to this host (a warning,
never a failure).

For `acme`, Caddy gets its certificate on first start. Until it has one, the site does not
load over HTTPS; follow it with `./logstotal docker:logs:proxy`.

Behind Caddy, every request reaches the app from Caddy's address. For rate limits and the
activity log to see real client addresses, set `TRUST_PROXY_HEADERS` and
`TRUSTED_PROXY_CIDRS` — see [Rate limit semantics](../security.md#rate-limit-semantics).

## Your own certificate

With `PROXY_TLS=custom`:

1. Put the certificate (full chain) and the key in `certs/` in the install directory.
   That directory is mounted into Caddy at `/etc/caddy/certs` and is never included in a
   release archive.
2. Point `.env` at them by their path inside the container:

   ```bash
   PROXY_TLS_CERT=/etc/caddy/certs/fullchain.pem
   PROXY_TLS_KEY=/etc/caddy/certs/privkey.pem
   ```

3. `./logstotal docker:up`

Both keys are required, and both paths must be under `/etc/caddy/certs`. Caddy refuses to
start otherwise, and says which file is wrong.

## Air-gapped and internal networks

With `PROXY_TLS=internal`, Caddy runs its own certificate authority, so there is nothing to
validate and nothing to renew from outside. One manual step remains: the machines that use
LogsTotal must trust Caddy's root certificate. Copy it out:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./logstotal-root.crt
```

and install `logstotal-root.crt` as a trusted root on those machines. Until you do, every
browser shows a certificate warning. That is why `ENABLE_HSTS` stays `false` in this mode:
HSTS turns a warning you can click through into a page that cannot be opened at all.

## HTTP basic auth

Caddy can ask for a user name and password before anything reaches the app, in every mode,
including `off`. Generate the hash as described in
[Generating secrets and keys](../configuration.md#generating-secrets-and-keys), then either
set `BASIC_AUTH_USER` and `BASIC_AUTH_HASH` in `.env` (the hash in single quotes), or let
`proxy:enable` write them:

```bash
DOMAIN=logs.example.com ACME_EMAIL=admin@example.com \
  ./logstotal proxy:enable -- --basic-auth-user ops --basic-auth-hash '<bcrypt hash>'
```

API tokens cannot authenticate through basic auth — see
[Known limitations](../limitations.md#deployment).

## Turn HTTPS off

Plain HTTP is the default and needs nothing: leave `proxy` out of `COMPOSE_PROFILES`, keep
`COOKIE_INSECURE=true`, and the app serves on port 8000. That is the state
`./logstotal quickstart` leaves without `DOMAIN`.

To remove a proxy you enabled, change these four keys in `.env`:

```bash
COMPOSE_PROFILES=            # remove `proxy` (keep any other profiles)
WEB_PORT=8000:8000           # publish the app itself again
COOKIE_INSECURE=true         # plain HTTP drops a Secure cookie
ENABLE_HSTS=false
```

Then run `./logstotal docker:up`.

> [!IMPORTANT]
> **`PROXY_TLS=off` does not remove Caddy.** It keeps Caddy in front and serves plain HTTP
> through it, for when something else already terminates TLS. Removing the `proxy` profile
> is what takes Caddy away.
