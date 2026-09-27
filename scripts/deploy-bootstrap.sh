#!/usr/bin/env bash
# Fleet host bootstrap for LogsTotal (developer / ops).
#
# Turns a fresh Ubuntu/Debian box into one the deploy can use: Docker + the compose
# plugin, 7z, rsync, and the install directory. Idempotent — every install is
# guarded by `command -v`, so a second run prints "already installed" and changes
# nothing. Run it on its own to add a machine to an existing fleet, or as the first
# step of bringing one up.
#
# What it deliberately does NOT do: fail on an untested OS. It reports the detected
# distro and keeps going (see docs/limitations.md#platform-support). On a host with no
# apt-get it names what to install by hand and moves on, leaving `task deploy:preflight`
# to report whatever is still missing.
#
# Usage:
#   bash scripts/deploy-bootstrap.sh
#
# Configuration (env vars from the caller always override deploy.env values):
#   DEPLOY_HOSTS      Comma-separated host list; entries are `host` (SSH as root),
#                     `user@host`, or `local` (this machine, no SSH). Required.
#   DEPLOY_REMOTE_DIR Install directory to create on each host (default /opt/logstotal).
#   DEPLOY_VPN        `wireconf` also installs wireguard-tools. DEFAULT for a multi-host
#                     fleet; resolved through lib/common.sh::vpn_mode so this script and
#                     deploy-vpn.sh cannot disagree about whether a tunnel is built.
#   DEPLOY_ENV_FILE   Path to defaults file (default: deploy.env in cwd).
#   DEPLOY_VPN_PORT       WireGuard UDP port for the hub's ufw rule (default 51820).
#   DEPLOY_OPEN_WG_PORT   truthy/falsy: add that ufw rule on the hub. Defaults to true
#                         when DEPLOY_VPN=wireconf, false otherwise.
#   DEPLOY_DRY_RUN    truthy: trace every command instead of running it. Package
#                     installs and the OS probe are skipped entirely.
#   SSH_IDENTITY      Path to SSH private key (optional).
#
# Test hook, not an operator knob:
#   DEPLOY_DRY_RUN_OS_RELEASE  under DEPLOY_DRY_RUN, an /etc/os-release body to run the
#                     tested-OS verdict against, so all four outcomes are exercised
#                     without needing four distros. Mirrors DEPLOY_DRY_RUN_HEALTH.
#
# `set -eu`, no pipefail — the `|| true` capture guards below rely on a non-zero
# upstream status not aborting the script. Assumes the repo root is the current
# working directory (same as every other scripts/*.sh).

set -eu

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"
deploy_env_load DEPLOY_HOSTS DEPLOY_REMOTE_DIR DEPLOY_VPN DEPLOY_DRY_RUN SSH_IDENTITY

DEPLOY_REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/logstotal}"
# Through the shared resolver, because this script runs BEFORE deploy-vpn.sh and decides
# from the answer whether to install WireGuard and open the hub's UDP port. Resolving it
# differently here is how a host gets a tunnel's prerequisites for a tunnel that is skipped.
vpn_mode
DEPLOY_VPN="$VPN_MODE"
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-false}"

[ -n "${DEPLOY_HOSTS:-}" ] || die "DEPLOY_HOSTS is required (comma-separated host list; set it or put it in ${DEPLOY_ENV_FILE})"

build_ssh_opts

WANT_WIREGUARD=no
WG_LABEL=""
if [ "$DEPLOY_VPN" = "wireconf" ]; then
  WANT_WIREGUARD=yes
  WG_LABEL=", wireguard-tools"
fi

# The one firewall rule this tooling will ever add, and only on the hub.
#
# In a hub-and-spoke mesh only the hub receives unsolicited packets: the spokes dial out
# from an ephemeral port and their return traffic rides conntrack: a working mesh has the
# hub on 51820 with a ufw allow and the spokes on ephemeral ports with no rule at all.
# Opening ports on the spokes would be cargo cult.
#
# Everything else about the firewall is reported by deploy-preflight.sh and left alone.
# Rewriting someone's firewall from a deploy script is not a trade worth making; this
# single rule earns its place because without it the VPN cannot come up at all, and the
# failure surfaces two steps later as an unexplained missing handshake.
DEPLOY_VPN_PORT="${DEPLOY_VPN_PORT:-51820}"
OPEN_WG_PORT="${DEPLOY_OPEN_WG_PORT:-}"
if [ -z "$OPEN_WG_PORT" ]; then
  OPEN_WG_PORT=$([ "$WANT_WIREGUARD" = "yes" ] && echo true || echo false)
fi

# ── Per-host bootstrap ───────────────────────────────────────────────────────
#
# Two parts are load-bearing and must not be dropped:
#
#   * rsync — scripts/deploy-multiserver.sh hard-exits at the snapshot step without it,
#     which is *after* the stacks are already stopped. Minimal base images do not ship it.
#   * the VERSION_CODENAME / UBUNTU_CODENAME fallback — Debian sets the first, Ubuntu
#     the second, and the Docker apt repo line needs whichever exists.
#
# The directories are chowned to the invoking user because Docker would otherwise create
# data/ root-owned on first `up`, and `task backup` could then not write into it.
#
# Values reach the host script as environment assignments on the command line, so the
# heredoc can stay single-quoted: nothing in it is expanded here, which is what keeps
# `$(id -u)` and `$SUDO` meaning what they say on the far side.

bootstrap_host() {
  local host=$1 idx=$2 role release dist_id codename open_wg
  role="worker"
  [ "$idx" -eq 0 ] && role="control-plane"
  # Only the hub (first host) gets the inbound WireGuard rule — see the note by
  # OPEN_WG_PORT above for why the spokes need nothing.
  open_wg=false
  [ "$idx" -eq 0 ] && [ "$OPEN_WG_PORT" = "true" ] && open_wg=true
  step "${host} (${role}): bootstrap"

  # Reachability first — everything below assumes commands run.
  host_exec "$host" "true" >/dev/null || die "Cannot reach ${host}. For an SSH host, check key access (BatchMode is always on, so there is no password fallback)."

  # The OS probe is skipped under dry-run rather than reported as unreadable: an empty
  # capture would emit the "could not read /etc/os-release" warning on every dry run,
  # which is a finding about the dry run, not about the host.
  release=""
  if truthy "$DEPLOY_DRY_RUN"; then
    release="${DEPLOY_DRY_RUN_OS_RELEASE:-}"
    if [ -n "$release" ]; then
      os_release_verdict "$host" "$release"
    else
      info "${host}: OS check skipped (dry-run)"
    fi
  else
    # Empty is a real answer here — os_release_verdict says "could not read
    # /etc/os-release" for it. Skipping the call on an empty capture would make an
    # unreadable os-release silently indistinguishable from a tested one.
    release=$(host_exec "$host" "cat /etc/os-release 2>/dev/null" || true)
    os_release_verdict "$host" "$release"
  fi

  dist_id=$(os_release_field ID "$release")
  codename=$(os_release_field VERSION_CODENAME "$release")
  [ -n "$codename" ] || codename=$(os_release_field UBUNTU_CODENAME "$release")
  case "$dist_id" in
    ubuntu | debian) ;;
    # download.docker.com serves ubuntu and debian only. A derivative usually still
    # resolves against debian; anything further out lands in the no-apt arm anyway.
    *) dist_id="debian" ;;
  esac
  if [ -z "$codename" ] && ! truthy "$DEPLOY_DRY_RUN"; then
    warn "${host}: no codename in /etc/os-release — cannot add the Docker apt repository. Install Docker by hand if it is missing."
  fi

  host_exec "$host" "LT_DIR='${DEPLOY_REMOTE_DIR}' LT_DIST_ID='${dist_id}' LT_CODENAME='${codename}' LT_WIREGUARD='${WANT_WIREGUARD}' LT_WG_LABEL='${WG_LABEL}' LT_OPEN_WG='${open_wg}' LT_WG_PORT='${DEPLOY_VPN_PORT}' bash -s" <<'BOOTSTRAP'
set -eu

have() { command -v "$1" >/dev/null 2>&1; }

# Probe for privilege rather than assuming it. `sudo -n` with no cached credentials
# fails at the first apt-get, halfway through, under set -e — so ask once, up front,
# and degrade to the same "install these by hand" arm a non-apt host gets.
SUDO=""
CAN_ELEVATE=yes
if [ "$(id -u)" -ne 0 ]; then
  if have sudo && sudo -n true 2>/dev/null; then
    SUDO="sudo -n"
  else
    CAN_ELEVATE=no
  fi
fi

if [ "$CAN_ELEVATE" = "no" ]; then
  echo "WARN: not root, and sudo needs a password here — skipping package installation."
  echo "WARN: install by hand: docker-ce, docker-compose-plugin, p7zip-full, rsync${LT_WG_LABEL}."
elif ! have apt-get; then
  echo "WARN: no apt-get on this host — skipping package installation."
  echo "WARN: install by hand: docker-ce, docker-compose-plugin, p7zip-full, rsync${LT_WG_LABEL}."
else
  export DEBIAN_FRONTEND=noninteractive

  # Wait for the dpkg lock rather than dying on it.
  #
  # A FRESHLY PROVISIONED Ubuntu box runs unattended-upgrades on boot, and a first deploy
  # is by definition aimed at a freshly provisioned box — so the two collide routinely.
  # apt's raw "Could not get lock /var/lib/dpkg/lock-frontend. It is held by process N"
  # would stop a deploy part way through several hosts, for something that is not a fault
  # and clears itself in seconds.
  #
  # apt's supported knob, and unknown -o keys are accepted by older versions rather than
  # rejected, so this is safe on anything the deploy claims to support.
  APT_WAIT="-o DPkg::Lock::Timeout=300"

  if have docker && docker compose version >/dev/null 2>&1; then
    echo "docker + compose plugin already installed"
  elif [ -z "$LT_CODENAME" ]; then
    echo "WARN: no distro codename — cannot add the Docker apt repository. Install Docker by hand."
  else
    echo "installing Docker from the official repository"
    $SUDO apt-get update ${APT_WAIT} -qq
    $SUDO apt-get install ${APT_WAIT} -y -qq ca-certificates curl gnupg
    $SUDO install -m 0755 -d /etc/apt/keyrings
    if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
      curl -fsSL "https://download.docker.com/linux/${LT_DIST_ID}/gpg" | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
    fi
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${LT_DIST_ID} ${LT_CODENAME} stable" \
      | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    $SUDO apt-get update ${APT_WAIT} -qq
    $SUDO apt-get install ${APT_WAIT} -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    [ "$(id -u)" -eq 0 ] || $SUDO usermod -aG docker "$(id -un)" || true
    # `systemctl enable --now` is right on systemd; the fallback is for images without it.
    $SUDO systemctl enable --now docker 2>/dev/null || $SUDO service docker start || true
  fi

  for PAIR in 7z:p7zip-full rsync:rsync curl:curl; do
    BIN=${PAIR%%:*}
    PKG=${PAIR##*:}
    if have "$BIN"; then
      echo "${BIN} already installed"
    else
      echo "installing ${PKG}"
      $SUDO apt-get install ${APT_WAIT} -y -qq "$PKG"
    fi
  done

  if [ "$LT_WIREGUARD" = "yes" ]; then
    if have wg; then
      echo "wireguard-tools already installed"
    else
      echo "installing wireguard-tools"
      $SUDO apt-get install ${APT_WAIT} -y -qq wireguard-tools
    fi

    # Hub only, ufw only, and only when the rule is absent. A stock Ubuntu cloud image
    # ships ufw enabled with just OpenSSH allowed, so wireguard-tools gets installed onto
    # a host that will silently drop every handshake packet.
    if [ "$LT_OPEN_WG" = "true" ] && have ufw; then
      if ! ufw status 2>/dev/null | grep -q "^Status: active"; then
        echo "ufw present but inactive — leaving it alone"
      elif ufw status 2>/dev/null | grep -qE "^${LT_WG_PORT}(/udp)?[[:space:]]+ALLOW"; then
        echo "ufw already allows ${LT_WG_PORT}/udp"
      else
        echo "opening ufw ${LT_WG_PORT}/udp (WireGuard hub)"
        $SUDO ufw allow "${LT_WG_PORT}/udp" >/dev/null 2>&1 ||
          echo "WARN: could not add the ufw rule — add it by hand: ufw allow ${LT_WG_PORT}/udp"
      fi
    fi
  fi
fi

# Plain mkdir first: the target is often already owned by the deploying user (a second
# run, or a home-directory DEPLOY_REMOTE_DIR), and asking for root to create a directory
# you can already write is how a working setup gets refused.
if mkdir -p "${LT_DIR}/data" "${LT_DIR}/uploads" "${LT_DIR}/backups" "${LT_DIR}/certs" 2>/dev/null; then
  :
elif [ "$CAN_ELEVATE" = "yes" ]; then
  $SUDO mkdir -p "${LT_DIR}/data" "${LT_DIR}/uploads" "${LT_DIR}/backups" "${LT_DIR}/certs"
  [ "$(id -u)" -eq 0 ] || $SUDO chown -R "$(id -un):$(id -gn)" "${LT_DIR}"
else
  echo "ERROR: cannot create ${LT_DIR} — not writable, and elevating needs a password."
  echo "       Fix: create it yourself and chown it to $(id -un), or set DEPLOY_REMOTE_DIR somewhere writable."
  exit 1
fi
echo "${LT_DIR} (+ data/ uploads/ backups/) ready"
BOOTSTRAP
}

# ── Main ─────────────────────────────────────────────────────────────────────

header "Bootstrap hosts"
IDX=0
for HOST in $(printf '%s' "${DEPLOY_HOSTS}" | tr ',' '\n'); do
  HOST=$(printf '%s' "$HOST" | xargs)
  [ -z "$HOST" ] && continue
  bootstrap_host "$HOST" "$IDX"
  IDX=$((IDX + 1))
done
info "Bootstrap complete on ${IDX} host(s). Next: ./logstotal deploy:preflight"
