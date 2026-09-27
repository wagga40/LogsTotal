# Offline installation

How to install and upgrade LogsTotal on a network with no internet access.

Build a **bundle** on a machine that has a network, carry it across, and install from it. A
bundle is a `.7z` file holding a release archive and every container image LogsTotal needs,
so nothing on the closed network has to build or pull anything.

## Build a bundle

On a machine with internet access and Docker, from a LogsTotal toolkit (an unpacked release
or a checkout):

```bash
./logstotal bundle
```

It writes `logstotal-bundle-<version>-<arch>.7z` and its `.sha256` file to the current
directory, packaging the toolkit's own release. `ARCHIVE=<file>` bundles a release archive
you already have instead, and `BUNDLE_OUT=<path>` chooses the output file.

A bundle contains:

- the release archive, which carries its own Task binaries, so `./logstotal` works on the
  closed network with nothing else installed;
- the LogsTotal application image and the Garage (S3 storage) image, built for the bundle;
- Redis, PostgreSQL, Caddy and socat, as the Compose files name them;
- **Zircolite**, as the shipped workflows name it.

Zircolite is the one that matters most. It is pulled by the first job that runs it, not at
install time, so a closed install without it passes every check and then fails the first
Windows or Linux job that needs it. Five of the six shipped workflows do.

Three things to know:

- **A bundle is single-architecture.** Build it on the same architecture as the target
  hosts; the file name says which one it is.
- **It is not published with releases.** It is several hundred megabytes, several times the
  size of the release archive, and most installations never need one.
- **Zircolite's digest pin is checked when the bundle is built.** The shipped workflows pin
  the Zircolite image by digest. `./logstotal bundle` pulls it by that digest, then saves it
  by tag, because an image loaded from a saved file can only be found by its tag. Hosts
  installed from the bundle run it by tag, and the bundle's `.sha256` covers it from there.
  To keep the digest checked on every run, use a [registry mirror](#with-a-registry-mirror)
  instead.

## Check it

Before the bundle goes through the airlock, and again after:

```bash
./logstotal bundle:verify -- logstotal-bundle-<version>-<arch>.7z
```

It needs 7z and Python but not Docker, so it runs on any machine. It reports whether the
checksum matches, whether the release archive and every image the manifest lists are inside,
whether the images were built from that archive, and whether the architecture matches the
machine it runs on.

## Install from it

On the closed network, take the release archive out of the bundle and unpack it as your
toolkit:

```bash
7z x logstotal-bundle-<version>-<arch>.7z logstotal-<version>.7z
7z x logstotal-<version>.7z -o~/logstotal-<version>
cd ~/logstotal-<version>
```

Then follow [Fleet installation](fleet.md), adding `BUNDLE=` to the deploy:

```bash
./logstotal deploy BUNDLE=/media/usb/logstotal-bundle-<version>-<arch>.7z
```

The deploy verifies the bundle, loads its images on every host, and starts them without
building or pulling. This works for a single machine too: name it `local`
(`./logstotal deploy:init -- local`) and it is deployed in place, without SSH.

For TLS on a closed network, use `DEPLOY_PROXY_TLS=internal`: Caddy's own certificate
authority, with no DNS, no port 80 and no internet. See
[Air-gapped and internal networks](https.md#air-gapped-and-internal-networks).

## Upgrade from a bundle

Build a bundle of the new release the same way, carry it across, and run, from the install
directory of a single host or the control plane of a fleet:

```bash
./logstotal upgrade BUNDLE=/media/usb/logstotal-bundle-<version>-<arch>.7z
```

It reads the release from the bundle, verifies the archive and the images, loads the images,
and starts them with building and pulling turned off. Later `./logstotal docker:up` runs and
fleet starts keep using the loaded images. An upgrade from an ordinary release archive goes
back to building images. See [Upgrade and rollback](../runbooks/upgrading.md) for the rest
of the upgrade procedure.

## Without a bundle

### Release archive only

The release archive alone installs without reaching the release server:

```bash
./logstotal deploy ARCHIVE=/media/usb/logstotal-<version>.7z
```

but every host then builds the application image itself, which needs Docker Hub, the Debian
package archive, PyPI and GitHub, and pulls the other images. Pre-loading all of that with
`docker save` and `docker load` is exactly what a bundle does for you.

### With a registry mirror

If your network runs a registry mirror, set `REGISTRY_PREFIX` in `.env`. Every image
LogsTotal does not build itself is then pulled from the mirror instead of Docker Hub: the
Compose services, and the tool images named in `workflows/*.yml`.

```bash
REGISTRY_PREFIX=registry.internal
```

Digests are kept, so a pull through the mirror is verified exactly like a pull from the
original registry. An image that already names a registry (`ghcr.io/…`,
`localhost:5000/…`) is left alone.

The mirror does not cover the **application image**, which is built rather than pulled, and
the build still needs the Debian package archive and PyPI. A bundle carries it ready-built.
