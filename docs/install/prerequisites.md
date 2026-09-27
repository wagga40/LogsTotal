# Prerequisites

What a machine needs before LogsTotal is installed on it, and how to get a release onto it.

## Supported platforms

- **Ubuntu and Debian** are the tested targets, for every kind of host.
- **Other Linux distributions** may work but are untested. The fleet deploy reports each
  host's OS and warns, without stopping, when it is outside that set.
- **macOS** is supported for local development only.

Analysts need a desktop browser, 1024px or wider, with JavaScript enabled. The UI is
fixed-width and file submission is script-driven — see
[Known limitations](../limitations.md#platform-support).

## What each machine needs

| | Docker host | Fleet workstation | Fleet host | Local development |
|---|---|---|---|---|
| Bash and curl | yes | yes | yes | yes |
| Python 3.11 or later, standard library only | yes | yes | yes | yes |
| Docker Engine with the Compose plugin | yes | only to build an [offline bundle](offline.md) | yes | yes, for Zircolite |
| 7z (`p7zip-full`) | yes | yes | yes | to build a release archive |
| rsync | yes | no | yes | no |
| SSH client, with key access to every host | no | yes | no | no |
| PDM | no | no | no | yes |

- A **Docker host** runs a [single-host installation](single-host.md).
- A **fleet workstation** is the machine you run a [fleet deploy](fleet.md) from. It can be
  the control plane itself.
- **Fleet hosts** are the control plane and the workers. `./logstotal deploy` installs
  Docker, 7z, rsync and curl on them for you.
- **Local development** is for contributors — see
  [Local development](../contribute/local-development.md).

Python is used by the helper scripts that run on the host (secrets, backups, the deploy
tooling). They use the standard library only: no virtualenv, no `pip install`. The system
`python3` on Debian 12 and Ubuntu 24.04 is recent enough.

Redis, PostgreSQL and the S3 store run as Compose services; you do not install them.

## The `./logstotal` command

Every command in these docs is `./logstotal <name>`, run from the install directory.
`./logstotal` on its own lists the commands most sessions start with,
`./logstotal --list` lists them all, and `./logstotal --summary <name>` explains one.

`./logstotal` runs [Task](https://taskfile.dev) at a pinned version, so the commands need
nothing installed:

- **A release archive** carries the Linux Task binaries (x86_64 and arm64) under
  `tools/go-task/`. The first command verifies the one for this machine against its pinned
  checksum and caches it. No network is needed, so this works on a host with no internet
  access.
- **A git checkout** uses Task 3.39 or later if one is on your `PATH`. Otherwise it
  downloads the pinned version once, verifies its sha256, and caches it in `.bin/`.
- If you have Task installed, `task <name>` from the install directory is equivalent.

## Resources

- **Release archive** — about 60 MB to download and about 160 MB unpacked, most of it the
  detection tools and their rule sets.
- **Zircolite image** — about 530 MB, pulled once, by the first job that runs Zircolite
  (five of the six shipped workflows do). On a slow or metered link, pull the image named
  by `docker_image:` in `workflows/*.yml` ahead of time.
- **Evaluation host** — 2 CPU and 4 GB of RAM. Analysis is CPU- and memory-bound per
  concurrent job; run `./logstotal recommend-scaling` before real traffic, and see
  [Scaling and capacity planning](../scaling.md).

## Getting the software onto the machine

Every installation starts from a release unpacked on the machine you install from.

### 1. Install the prerequisites

On a fresh Ubuntu or Debian host, as root or with `sudo`:

```bash
apt update
apt install -y p7zip-full rsync curl python3
```

Then Docker, which is not in the distribution repositories:

```bash
curl -fsSL https://get.docker.com | sh      # or follow docs.docker.com/engine/install
```

> [!NOTE]
> `7z` is needed to unpack the release archive — the very next step — and no distribution
> installs it by default. `rsync` is needed to upgrade, because each release is laid over
> the install with it.

### 2. Download a release

Download `logstotal-<version>.7z` and `logstotal-<version>.7z.sha256` from the
[releases page](https://github.com/wagga40/LogsTotal/releases/latest), on the machine itself
or on your workstation.

Carrying them in on removable media works too: nothing about the install needs the release
server. See [Offline installation](offline.md).

### 3. Check the download

```bash
sha256sum -c logstotal-<version>.7z.sha256      # on macOS: shasum -a 256 -c
```

`./logstotal upgrade` and `./logstotal deploy` run this check themselves on anything they
download.

> [!NOTE]
> A checksum catches a truncated or corrupted transfer. It proves nothing about tampering
> when it comes from the same server as the archive — only a checksum that reached you by
> another path does. Releases are not signed.

### 4. Unpack it

```bash
7z x logstotal-<version>.7z -o~/logstotal-<version>
cd ~/logstotal-<version>
```

- **The archive has no top-level directory.** `-o<dir>` creates one; without it, the files
  land in your current directory.
- **This is the toolkit, not necessarily the install.** See
  [Where things live](#where-things-live).

### 5. Create system directories yourself

If you extract to, or install into, a system path, create it first and give it to your
user. Otherwise it is root-owned, and `./logstotal backup` and the application cannot write
`data/`, `uploads/` and `backups/`:

```bash
sudo mkdir -p /opt/logstotal
sudo chown "$USER" /opt/logstotal
```

## Where things live

Three directories:

| | What | Lifetime |
|---|---|---|
| **The toolkit** | Where you unpacked the release (or cloned the repository). You run the first install from here | **Deletable** once the install succeeds |
| **The stage** | `<install>/.stage` on each host, where a new release is unpacked before it is laid over the install | Deleted on every run |
| **The install** | `/opt/logstotal` by default. LogsTotal runs here, and `data/`, `uploads/`, `backups/` and `certs/` live here | Permanent |

The install is self-sufficient: each release carries its own `./logstotal`, `Taskfile.yml`
and `scripts/`, so every later command, upgrades included, runs from the install directory:

```bash
cd /opt/logstotal && ./logstotal upgrade
```

On a single host the toolkit and the install can be the same directory: extract straight to
`/opt/logstotal`. For a fleet they are always separate, because the deploy writes the install
on every host, including the one you run it from.
