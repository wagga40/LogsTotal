#!/usr/bin/env bash
# Optional private network for a LogsTotal fleet, via Wireconf (developer / ops).
#
# Builds a hub-and-spoke WireGuard mesh across DEPLOY_HOSTS — control plane as hub —
# and records each host's VPN address in deploy-envs/vpn.json, which
# task deploy:env then uses for every cross-host URL. Without it the workers
# reach the control plane at its public address, which works but puts Redis,
# PostgreSQL and Garage on a routable interface.
#
# When a tunnel is asked for — the default — a failure to build it STOPS the deploy:
# falling back to the public addresses is not a smaller version of the request, it is the
# opposite of it — Redis, PostgreSQL and Garage end up bound to a routable interface,
# which is precisely what a VPN is meant to prevent, and the only sign is one warning in
# a very long log. DEPLOY_VPN_OPTIONAL makes it best-effort for anyone who wants that.
#
# A failed *verify* is still only a warning: apply has already succeeded by then, the
# addresses are recorded, and nothing is exposed — the tunnels simply may not have
# finished coming up.
#
# Usage:
#   DEPLOY_VPN=wireconf bash scripts/deploy-vpn.sh
#
# Configuration (env vars from the caller always override deploy.env values):
#   DEPLOY_VPN               `wireconf` (default) to run, `none` to skip. `tailscale`
#                            is accepted and points at the manual instructions —
#                            Tailscale needs an interactive login, so it is documented
#                            rather than automated.
#   DEPLOY_HOSTS             Comma-separated host list; the first becomes the hub.
#   DEPLOY_VPN_NETWORK       WireGuard CIDR (default 10.200.0.0/24).
#   DEPLOY_VPN_HUB_ENDPOINT  Public address peers dial. Defaults to the first host.
#   DEPLOY_CP_ADDRESS        With DEPLOY_VPN=tailscale, the control plane's tailnet
#                            address — supplying it is what says Tailscale is actually up.
#   DEPLOY_VPN_INSTALL       falsy: never install Wireconf, just look for it.
#   DEPLOY_VPN_OPTIONAL      truthy: treat a VPN failure as a warning and deploy over
#                            the public addresses anyway. Off by default.
#   DEPLOY_VPN_MIN_VERSION   Oldest Wireconf this will run (default below). An escape
#                            hatch for running an older build deliberately, not a knob
#                            to reach for.
#   DEPLOY_ENV_DIR           Where vpn.json is written (default deploy-envs).
#   DEPLOY_VPN_RETRIES       Verify attempts (default 12).
#   DEPLOY_VPN_DELAY         Seconds between them (default 5).
#   DEPLOY_VPN_PORT          WireGuard listen port, written into wireconf.env as
#                            WG_PORT (default 51820).
#   DEPLOY_ENV_FILE          Path to defaults file (default: deploy.env in cwd).
#   DEPLOY_DRY_RUN           truthy: print what would happen, touch nothing.
#   SSH_IDENTITY             Path to SSH private key (optional).
#
# `set -eu`, no pipefail — the retry loop and the address probes must survive a
# non-zero status.

set -eu

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"
deploy_env_load \
  DEPLOY_VPN DEPLOY_HOSTS DEPLOY_VPN_NETWORK DEPLOY_VPN_HUB_ENDPOINT DEPLOY_VPN_INSTALL \
  DEPLOY_VPN_OPTIONAL DEPLOY_VPN_MIN_VERSION DEPLOY_ENV_DIR DEPLOY_VPN_RETRIES \
  DEPLOY_VPN_DELAY DEPLOY_VPN_PORT DEPLOY_DRY_RUN SSH_IDENTITY

vpn_mode
vpn_mode_require_decision
DEPLOY_VPN="$VPN_MODE"
DEPLOY_VPN_NETWORK="${DEPLOY_VPN_NETWORK:-10.200.0.0/24}"
DEPLOY_VPN_INSTALL="${DEPLOY_VPN_INSTALL:-true}"
DEPLOY_ENV_DIR="${DEPLOY_ENV_DIR:-deploy-envs}"
DEPLOY_VPN_RETRIES="${DEPLOY_VPN_RETRIES:-12}"
DEPLOY_VPN_DELAY="${DEPLOY_VPN_DELAY:-5}"
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-false}"
WG_IFACE="wg0"
# The WireGuard listen port, written into wireconf.env as WG_PORT (wireconf's own key:
# WC_PORT="${WG_PORT:-51820}") — the single source of truth shared with the bootstrap
# firewall rule and the "check UDP <port>" hint.
DEPLOY_VPN_PORT="${DEPLOY_VPN_PORT:-51820}"

# vpn_failed REASON — stop, unless the operator opted into best-effort. Never returns.
vpn_failed() {
  if truthy "${DEPLOY_VPN_OPTIONAL:-}"; then
    warn "$1"
    warn "DEPLOY_VPN_OPTIONAL is set — continuing over the public addresses. Redis, PostgreSQL and Garage will be reachable there."
    exit 0
  fi
  die "$1
Nothing has been deployed. Without the tunnel, Redis, PostgreSQL and Garage would be bound to a routable address — the opposite of what DEPLOY_VPN=wireconf asked for.
Fix it and re-run, or accept that trade explicitly with DEPLOY_VPN_OPTIONAL=true."
}

case "$DEPLOY_VPN" in
  none | "")
    if [ -n "${VPN_MODE_REASON:-}" ]; then
      info "VPN step skipped: ${VPN_MODE_REASON}."
    else
      info "VPN step skipped (DEPLOY_VPN=none). Workers will reach the control plane at its DEPLOY_HOSTS address."
    fi
    exit 0
    ;;
  tailscale)
    # Accepted as a value rather than rejected as a typo — Tailscale is supported, just
    # not automated, because `tailscale up` needs an interactive login or an auth key
    # this tooling has no business holding.
    #
    # But it must STOP: returning 0 would let the composer generate, push and deploy the
    # entire fleet over public addresses while the operator is being told to set up a
    # private network — the exposure they asked to avoid. Once Tailscale is up,
    # DEPLOY_CP_ADDRESS is what makes the
    # fleet use it, and at that point DEPLOY_VPN can go back to none.
    if [ -n "${DEPLOY_CP_ADDRESS:-}" ]; then
      info "DEPLOY_VPN=tailscale with DEPLOY_CP_ADDRESS=${DEPLOY_CP_ADDRESS} — using that address; Tailscale itself is managed by you."
      exit 0
    fi
    vpn_failed "DEPLOY_VPN=tailscale, but Tailscale is not automated here: 'tailscale up' needs an interactive login.
Set it up on every host (docs/install/fleet.md), then re-run with DEPLOY_CP_ADDRESS set to the control plane's 100.x address."
    ;;
  wireconf) ;;
  *)
    # A typo — `wireguard`, `Wireconf`, `zerotier` — must not warn and carry on, deploying
    # the whole fleet over public addresses. The operator asked for a private
    # network in terms the tooling did not understand; guessing that they meant "none"
    # is the one interpretation that cannot be right.
    vpn_failed "Unknown DEPLOY_VPN=${DEPLOY_VPN}. Expected: wireconf, tailscale, or none."
    ;;
esac

[ -n "${DEPLOY_HOSTS:-}" ] || die "DEPLOY_HOSTS is required (comma-separated host list; set it or put it in ${DEPLOY_ENV_FILE})"

# Like every ssh-using deploy script. An unset bash array expands to nothing SILENTLY even
# under `set -u`, so without this the whole VPN step would run with no BatchMode (a key that
# does not authenticate prompts for a password and blocks forever), no ConnectTimeout (a
# filtered host stalls at TCP connect, inside the 12-attempt retry loop below), no host-key
# auto-accept, and SSH_IDENTITY ignored.
build_ssh_opts

# ── Addresses ────────────────────────────────────────────────────────────────
#
# Computed, not parsed back out of Wireconf. Its allocation is a documented,
# deterministic rule — `wg_allocate_ips` in lib/common.sh sets `base = network + 1`
# and hands index i the address `base + i`, so the hub is .1 and peer N is .N+1 —
# and the alternative, `wireconf show`, regenerates the configs and prints every
# host's PrivateKey to stdout on the way past. Reading a private key we do not need
# is the wrong trade for output that is no more authoritative than the arithmetic.
#
# The awk below mirrors that function. The computed hub address is checked against
# what the interface actually holds once the tunnel is up.

vpn_addresses() {
  local cidr="$1" total="$2"
  awk -v cidr="$cidr" -v total="$total" '
  function ip2num(ip,   a, n) {
    n = split(ip, a, ".")
    if (n != 4) exit 2
    return a[1]*16777216 + a[2]*65536 + a[3]*256 + a[4] + 0
  }
  function num2ip(x,   o1,o2,o3,o4) {
    o4 = int(x % 256); x = int(x / 256)
    o3 = int(x % 256); x = int(x / 256)
    o2 = int(x % 256); o1 = int(x / 256)
    return o1 "." o2 "." o3 "." o4
  }
  BEGIN {
    split(cidr, p, "/")
    if (length(p) != 2) exit 3
    prefix = p[2] + 0
    if (prefix < 16 || prefix > 30) exit 4
    hostbits = 32 - prefix
    net = int(ip2num(p[1]) / (2^hostbits)) * (2^hostbits)
    if (total > (2^hostbits) - 2) exit 5
    for (i = 0; i < total; i++) print num2ip(net + 1 + i)
  }'
}

HOSTS=()
# `|| [ -n "$LINE" ]` is load-bearing: printf without a trailing newline leaves the
# last field unterminated, read returns non-zero on it, and the loop body never runs —
# so the final host would silently vanish from the inventory.
while read -r LINE || [ -n "$LINE" ]; do
  LINE=$(printf '%s' "$LINE" | xargs)
  [ -n "$LINE" ] && HOSTS+=("$LINE")
done < <(printf '%s' "${DEPLOY_HOSTS}" | tr ',' '\n')
((${#HOSTS[@]} > 0)) || die "No hosts in DEPLOY_HOSTS"

ADDRS=()
while read -r LINE || [ -n "$LINE" ]; do
  [ -n "$LINE" ] && ADDRS+=("$LINE")
done < <(vpn_addresses "$DEPLOY_VPN_NETWORK" "${#HOSTS[@]}" || true)
if [ "${#ADDRS[@]}" -ne "${#HOSTS[@]}" ]; then
  vpn_failed "DEPLOY_VPN_NETWORK=${DEPLOY_VPN_NETWORK} cannot address ${#HOSTS[@]} host(s) — it needs a /16-/30 with room for all of them."
fi

HUB="${HOSTS[0]}"
HUB_ADDR="${ADDRS[0]}"

# The endpoint is what every peer dials to raise the tunnel, so it has to resolve FROM
# A PEER. The bare DEPLOY_HOSTS entry frequently does not: it is an ~/.ssh/config alias
# or a name only the operator's laptop knows, and Wireconf will happily write it into
# each peer's config and leave the handshake to fail silently. Ask a peer, then ask the
# hub for its own address, and only fall back to the name.
HUB_ENDPOINT="${DEPLOY_VPN_HUB_ENDPOINT:-}"
# yes once a peer resolved it or the hub reported its own address; an operator-supplied
# DEPLOY_VPN_HUB_ENDPOINT counts too, since that is a deliberate answer.
ENDPOINT_RESOLVED=$([ -n "$HUB_ENDPOINT" ] && echo yes || echo no)
if [ -z "$HUB_ENDPOINT" ] && ! truthy "$DEPLOY_DRY_RUN"; then
  HUB_NAME="${HUB#*@}"
  for ((i = 1; i < ${#HOSTS[@]}; i++)); do
    CANDIDATE=$(resolve_from "${HOSTS[$i]}" "$HUB_NAME")
    if is_ipv4 "$CANDIDATE"; then
      HUB_ENDPOINT="$CANDIDATE"
      info "Hub endpoint ${HUB_NAME} resolves to ${HUB_ENDPOINT} from ${HOSTS[$i]}"
      ENDPOINT_RESOLVED=yes
      break
    fi
  done
  if [ -z "$HUB_ENDPOINT" ]; then
    CANDIDATE=$(host_primary_address "$HUB")
    if is_ipv4 "$CANDIDATE"; then
      HUB_ENDPOINT="$CANDIDATE"
      info "Hub reports its own address as ${HUB_ENDPOINT}"
      ENDPOINT_RESOLVED=yes
    fi
  fi
fi
HUB_ENDPOINT="${HUB_ENDPOINT:-${HUB#*@}}"

# Both discovery paths above can come back empty, and then HUB_ENDPOINT is just the
# DEPLOY_HOSTS entry — which is exactly the case the discovery exists to avoid. Two
# spellings are certainly wrong and must not be written into a peer config:
#
#   `local`  — the run-here sentinel. Nothing resolves it; every peer would dial a host
#              called "local", no handshake would ever complete, the retry loop would
#              burn, and the failure would blame UDP reachability.
#   an ssh alias — a name only this laptop knows, via ~/.ssh/config. Same outcome.
#
# We cannot tell an alias from a real DNS name here, so only refuse what is provably
# unusable: the sentinel, and any name no peer could resolve (which is what the loop
# above already tested). An IPv4 always passes.
#
# Both checks are skipped under DEPLOY_DRY_RUN for the same reason the discovery above
# is: a dry run makes no connections, so HUB_ENDPOINT is always the bare fallback there
# and neither check could be anything but a false alarm.
if ! truthy "$DEPLOY_DRY_RUN" && is_local_host "$HUB_ENDPOINT"; then
  vpn_failed "The hub endpoint resolved to the literal 'local', which no peer can dial.
That sentinel means \"run here\" and is not an address. Set the hub's reachable address explicitly:
  DEPLOY_VPN_HUB_ENDPOINT=<public ip of the hub>"
fi
if ! truthy "$DEPLOY_DRY_RUN" && ! is_ipv4 "$HUB_ENDPOINT" && [ "$ENDPOINT_RESOLVED" != "yes" ]; then
  # A warning, not a refusal. Falling back to the DEPLOY_HOSTS entry is deliberate and
  # specified (test_the_hub_endpoint_defaults_to_the_first_host_without_its_user), and a
  # perfectly good public DNS name lands here whenever the probe could not run — the
  # peer lacking getent is enough. Refusing would break working deployments to catch a
  # guess, which is the trade os_release_verdict already settled the other way.
  # The handshake gate after apply is what actually proves this, and it is fatal.
  warn "Hub endpoint '${HUB_ENDPOINT}' is not an IP and no peer confirmed it resolves."
  warn "If it is an ~/.ssh/config alias only this machine knows, no peer will complete a handshake."
  warn "Set it explicitly if the tunnel fails: DEPLOY_VPN_HUB_ENDPOINT=<public ip of the hub>"
fi

header "Private network (Wireconf)"
info "Hub: ${HUB} → ${HUB_ADDR}  (endpoint ${HUB_ENDPOINT}, network ${DEPLOY_VPN_NETWORK})"
for ((i = 1; i < ${#HOSTS[@]}; i++)); do
  info "Peer: ${HOSTS[$i]} → ${ADDRS[$i]}"
done

# ── Locate or install Wireconf ───────────────────────────────────────────────

# The oldest Wireconf this will run, and why that number: below 0.3.8, its wc_ssh_exec
# omits `-T`, so an operator whose ssh config requests a TTY gets CRLF back from every
# remote command — and Wireconf's own OS check is `grep -qE '^ID="?(debian|ubuntu)"?$'`,
# whose `$` anchor then fails on `ID=ubuntu\r`. The symptom is every Debian/Ubuntu host
# in the fleet reported as "is not Debian/Ubuntu", which reads like a Wireconf bug about
# the distro and is really about the terminal. This pin keeps a stale copy of the tool from
# reintroducing it.
WIRECONF_MIN_VERSION="${DEPLOY_VPN_MIN_VERSION:-0.3.8}"

# wireconf_version BIN — "0.3.8" from `wireconf -V` ("wireconf 0.3.8"), or nothing.
wireconf_version() {
  "$1" -V 2>/dev/null | tr -d '\r' | awk 'NF {v=$NF} END {print v}' | grep -oE '^[0-9]+(\.[0-9]+)*$' || true
}

# version_lt A B — 0 when A is strictly older than B, comparing numerically field by
# field. Written out rather than `sort -V`: that is a GNU extension BSD sort only
# carries recently, the operator's machine is as likely to be macOS as Linux, and a
# comparison that silently gets it wrong re-enables the exact bug this guards. A string
# compare is not an option either — it puts 0.3.10 before 0.3.9.
version_lt() {
  local a b i
  IFS=. read -r -a a <<< "$1"
  IFS=. read -r -a b <<< "$2"
  for ((i = 0; i < 4; i++)); do
    local x="${a[$i]:-0}" y="${b[$i]:-0}"
    ((10#$x < 10#$y)) && return 0
    ((10#$x > 10#$y)) && return 1
  done
  return 1
}

# abs_path PATH — absolute form, so run_wireconf can cd without losing the binary.
abs_path() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")" ;;
  esac
}

find_wireconf() {
  if [ -n "${WIRECONF_BIN:-}" ] && [ -x "$WIRECONF_BIN" ]; then
    abs_path "$WIRECONF_BIN"
    return 0
  fi
  if command -v wireconf >/dev/null 2>&1; then
    command -v wireconf
    return 0
  fi
  # The installer writes ${WIRECONF_PREFIX}/wireconf — the binary itself, not a
  # directory. Looking for `$HOME/.local/wireconf/wireconf` would report a successful
  # install into $HOME/.local as "installed but not found on PATH".
  local candidate
  for candidate in \
    "${WIRECONF_PREFIX:-}/wireconf" \
    /opt/wireconf/wireconf \
    "$HOME/.local/bin/wireconf" \
    "$HOME/.local/wireconf"; do
    [ "$candidate" = "/wireconf" ] && continue
    [ -x "$candidate" ] && {
      printf '%s' "$candidate"
      return 0
    }
  done
  return 1
}

# ensure_wireconf_current BIN — update in place when the located binary predates the
# pin. Prints the version it settled on. Never returns a binary below the minimum: it
# calls vpn_failed instead, because a version that cannot read /etc/os-release correctly
# cannot build the tunnel.
ensure_wireconf_current() {
  local bin="$1" version
  version=$(wireconf_version "$bin")
  if [ -z "$version" ]; then
    # A fork, a package build or a future --version wording. Refusing here would break
    # installs that are perfectly fine, so say what is unknown and carry on — but still
    # name the binary, because "which one ran" is the first question when this goes wrong.
    info "Using ${bin} (version unknown)"
    warn "Could not read a version from ${bin} — continuing, but ${WIRECONF_MIN_VERSION} or newer is expected."
    return 0
  fi
  info "Using ${bin} (wireconf ${version})"
  version_lt "$version" "$WIRECONF_MIN_VERSION" || return 0

  info "wireconf ${version} predates ${WIRECONF_MIN_VERSION} — updating"
  if "$bin" update >/dev/null 2>&1 || {
    [ -w "$(dirname "$bin")" ] && WIRECONF_PREFIX="$(dirname "$bin")" \
      bash -c 'curl -fsSL https://raw.githubusercontent.com/wagga40/Wireconf/main/scripts/install.sh | bash' >/dev/null 2>&1
  }; then
    version=$(wireconf_version "$bin")
    if [ -n "$version" ] && ! version_lt "$version" "$WIRECONF_MIN_VERSION"; then
      info "wireconf is now ${version}"
      return 0
    fi
  fi

  vpn_failed "wireconf ${version} is too old and could not be updated automatically (needs ${WIRECONF_MIN_VERSION} or newer).
Below ${WIRECONF_MIN_VERSION} its remote commands run on a terminal, so every host's /etc/os-release comes back with CRLF and Wireconf reports supported hosts as \"not Debian/Ubuntu\".
Update it by hand:  ${bin} update      (a system-wide install may need sudo)
…or set DEPLOY_VPN_MIN_VERSION to run the older build deliberately."
}

WIRECONF=""
if WIRECONF=$(find_wireconf); then
  ensure_wireconf_current "$WIRECONF"
elif truthy "$DEPLOY_DRY_RUN"; then
  info "(dry-run) would install Wireconf from its upstream installer"
  WIRECONF="wireconf"
elif ! truthy "$DEPLOY_VPN_INSTALL"; then
  vpn_failed "Wireconf not found and DEPLOY_VPN_INSTALL is off. Install it with:
  curl -fsSL https://raw.githubusercontent.com/wagga40/Wireconf/main/scripts/install.sh | bash
…or point WIRECONF_BIN at it."
else
  # Into the user prefix, so no step of this needs root on the operator's machine.
  WIRECONF_PREFIX="${WIRECONF_PREFIX:-$HOME/.local/bin}"
  export WIRECONF_PREFIX
  mkdir -p "$WIRECONF_PREFIX"
  info "Installing Wireconf into ${WIRECONF_PREFIX}"
  if ! bash -c 'curl -fsSL https://raw.githubusercontent.com/wagga40/Wireconf/main/scripts/install.sh | bash'; then
    vpn_failed "Could not install Wireconf."
  fi
  if ! WIRECONF=$(find_wireconf); then
    vpn_failed "Wireconf installed but the binary was not found. Set WIRECONF_BIN=/path/to/wireconf."
  fi
  ensure_wireconf_current "$WIRECONF"
fi

# ── Inventory + config ───────────────────────────────────────────────────────

WORK=$(mktemp -d "${TMPDIR:-/tmp}/logstotal-wireconf.XXXXXX")
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

{
  for HOST in "${HOSTS[@]}"; do
    # Wireconf treats localhost/127.0.0.1/::1 as "run here"; our sentinel is `local`.
    if is_local_host "$HOST"; then
      printf 'localhost no\n'
    else
      printf '%s no\n' "$HOST"
    fi
  done
} >"${WORK}/inventory"

{
  printf 'WG_INTERFACE=%s\n' "$WG_IFACE"
  printf 'WG_NETWORK=%s\n' "$DEPLOY_VPN_NETWORK"
  printf 'WG_HUB_ENDPOINT=%s\n' "$HUB_ENDPOINT"
  printf 'WG_PORT=%s\n' "$DEPLOY_VPN_PORT"
  printf 'SSH_ACCEPT_NEW=yes\n'
  printf 'AUTO_START=yes\n'
} >"${WORK}/wireconf.env"

if truthy "$DEPLOY_DRY_RUN"; then
  info "(dry-run) inventory:"
  sed 's/^/    /' "${WORK}/inventory"
  info "(dry-run) would run: ${WIRECONF} plan / -y apply / verify"
  info "(dry-run) not writing ${DEPLOY_ENV_DIR}/vpn.json — a map for tunnels that were never built would send every worker at an address that does not answer."
  exit 0
fi

# ── plan → apply → verify ────────────────────────────────────────────────────
#
# The three steps, not `wireconf up`. `up` verifies once, and a tunnel that has just
# come up has no handshake until traffic crosses it — so the first verify legitimately
# fails and the retry loop with a ping nudge below is what makes this reliable.

# Run from the workdir and let wireconf auto-load ./wireconf.env, rather than naming it
# with -e.
#
# Not a style choice: through 0.3.8, passing -e ONCE makes wireconf print
#   WARN: Multiple -e/--env-file flags; only the first was sourced (ignoring <path>)
# on every invocation. Its pre-scan finds the flag, loads the file and sets
# WC_ENV_FILE_EXPLICIT=1; its main parser then meets the same flag and counts it as a
# second one. The file *is* loaded and its values apply, but a warning saying your
# configuration was ignored, on every deploy, is not something to leave in front of an
# operator. The auto-load path prints "Auto-loaded …" instead and applies the same values.
#
# WIRECONF is absolute (find_wireconf resolves it) because this cds.
#
# SSH_OPTS is exported because wireconf reads it: `WC_SSH_OPTS="${SSH_OPTS:-}"`, injected
# into every ssh and scp it runs. It already passes -T, BatchMode and ConnectTimeout
# itself (that is what the 0.3.8 floor buys), but not RemoteCommand=none — so on a host
# whose ~/.ssh/config carries `RemoteCommand`, wireconf's own calls die with "Cannot
# execute command-line and remote command." while ours succeed. Passing it here is the
# only way to reach those calls. A scalar, not our array: wireconf word-splits it.
run_wireconf() {
  (cd "$WORK" && env SSH_OPTS="-o RemoteCommand=none" "$WIRECONF" --ssh-accept-new -I ./inventory "$@")
}

if ! run_wireconf plan; then
  vpn_failed "wireconf plan failed."
fi
if ! run_wireconf -y apply; then
  vpn_failed "wireconf apply failed."
fi

# count_handshakes — sets PEERS_TOTAL and PEERS_SHOOK from the hub's peer table.
# `wg show <iface> latest-handshakes` prints "<pubkey> <unix-ts>" per peer; 0 = never.
# PEERS_TOTAL stays 0 when the hub could not be asked at all, which the callers must
# treat as "unknown", never as "no peers".
count_handshakes() {
  PEERS_TOTAL=0
  PEERS_SHOOK=0
  while read -r _key stamp; do
    [ -n "${stamp:-}" ] || continue
    PEERS_TOTAL=$((PEERS_TOTAL + 1))
    [ "$stamp" -gt 0 ] 2>/dev/null && PEERS_SHOOK=$((PEERS_SHOOK + 1))
  done <<< "$(host_exec "$HUB" "wg show ${WG_IFACE} latest-handshakes 2>/dev/null" 2>/dev/null | tr -d '\r' || true)"
  # Load-bearing under `set -e`. The loop body ends in `[ "$stamp" -gt 0 ] && ...`, which
  # is false for a peer that has never shaken hands — so without this the function
  # returns non-zero and a bare call kills the script exactly when there IS something to
  # report.
  return 0
}

# all_peers_shook — every peer has a handshake AND there was at least one to ask about.
all_peers_shook() {
  count_handshakes
  [ "$PEERS_TOTAL" -gt 0 ] && [ "$PEERS_SHOOK" -eq "$PEERS_TOTAL" ]
}

VERIFIED=no
sleep "$DEPLOY_VPN_DELAY"
for ((attempt = 1; attempt <= DEPLOY_VPN_RETRIES; attempt++)); do
  # Nudge traffic across the tunnel in both directions first: WireGuard is lazy, and
  # `wg show` reports no handshake until something has actually been sent.
  for ((i = 1; i < ${#HOSTS[@]}; i++)); do
    host_exec "$HUB" "ping -c 1 -W 1 ${ADDRS[$i]} >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    host_exec "${HOSTS[$i]}" "ping -c 1 -W 1 ${HUB_ADDR} >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  done
  if run_wireconf verify; then
    VERIFIED=yes
    break
  fi
  # verify pings, and a host that drops ICMP (ufw's default deny) fails it while carrying
  # traffic perfectly well. Asking the question the fleet
  # actually depends on lets a working tunnel leave on attempt 1 instead of always
  # paying the full RETRIES x DELAY.
  if all_peers_shook; then
    # Same finding as the post-loop gate, so it uses the same words deliberately: one
    # condition should not have two vocabularies depending on which attempt noticed it.
    warn "wireconf verify failed, but all ${PEERS_TOTAL} peer(s) have completed a WireGuard handshake, so the tunnel is carrying traffic."
    warn "The verify pings are most likely being dropped by a firewall. Continuing."
    VERIFIED=yes
    break
  fi
  info "verify attempt ${attempt}/${DEPLOY_VPN_RETRIES} — retrying in ${DEPLOY_VPN_DELAY}s"
  sleep "$DEPLOY_VPN_DELAY"
done

# Recording a failed verify and continuing would produce the worst outcome available here:
# every worker's DATABASE_URL, REDIS_URL and S3_ENDPOINT pointed at a VPN address that does
# not answer, the deploy reporting success, and the fleet sitting with jobs in `pending`
# and nothing in any log explaining why.
#
# But failing on the verify alone would be wrong too. Wireconf verifies by PINGING each
# peer's VPN address from the hub, and plenty of hardened hosts drop ICMP while carrying
# traffic perfectly well — refusing there would block a working deployment.
#
# So ask the question the fleet actually depends on: has WireGuard completed a handshake
# with every peer? `wg show <iface> latest-handshakes` prints one line per peer with a
# unix timestamp, and 0 means "never". Handshakes present and ping failing is a filtered
# ICMP, which is fine and worth saying out loud. No handshake is a tunnel that is not
# carrying anything, and that is fatal.
if [ "$VERIFIED" != "yes" ]; then
  warn "wireconf verify never succeeded after ${DEPLOY_VPN_RETRIES} attempts."
  count_handshakes

  if [ "$PEERS_TOTAL" -gt 0 ] && [ "$PEERS_SHOOK" -eq "$PEERS_TOTAL" ]; then
    warn "…but all ${PEERS_TOTAL} peer(s) have completed a WireGuard handshake, so the tunnel is carrying traffic."
    warn "The verify pings are most likely being dropped by a firewall. Continuing."
  elif [ "$PEERS_TOTAL" -eq 0 ]; then
    # Not "no peers have shaken hands" — we could not ask. Reporting that as
    # "0 of 0 peer(s)" reads like a parse bug and sends the operator to the firewall,
    # when the hub itself is what did not answer.
    vpn_failed "Could not read the peer table from the hub ${HUB}: 'wg show ${WG_IFACE}' returned nothing.
That is the hub being unreachable, wireguard-tools missing, or ${WG_IFACE} never coming up — not a peer problem.
Check in this order: ssh ${HUB} true, then on the hub: wg show ${WG_IFACE}"
  else
    vpn_failed "The tunnel is not up: ${PEERS_SHOOK} of ${PEERS_TOTAL} peer(s) have completed a WireGuard handshake (wireconf verify also failed ${DEPLOY_VPN_RETRIES} times).
Continuing would point every worker's DATABASE_URL, REDIS_URL and S3_ENDPOINT at a VPN address that does not answer — the deploy would report success and every job would sit in pending.
Check UDP ${DEPLOY_VPN_PORT} reachability to the hub, then: wireconf status"
  fi
fi

# The arithmetic above is a mirror of Wireconf's allocation, so confirm it against what
# the interface actually holds rather than trusting two implementations to agree.
ACTUAL=$(host_exec "$HUB" "ip -4 -o addr show ${WG_IFACE} 2>/dev/null | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null || true)
ACTUAL=$(printf '%s' "$ACTUAL" | tr -d '[:space:]')
if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$HUB_ADDR" ]; then
  warn "Wireconf gave the hub ${ACTUAL}, not the ${HUB_ADDR} this computed. Using ${ACTUAL}."
  OFFSET_OK=no
  HUB_ADDR="$ACTUAL"
else
  OFFSET_OK=yes
fi

# ── Record the map ───────────────────────────────────────────────────────────

mkdir -p "$DEPLOY_ENV_DIR"
{
  printf '{\n'
  printf '  "network": "%s",\n' "$DEPLOY_VPN_NETWORK"
  printf '  "interface": "%s",\n' "$WG_IFACE"
  printf '  "hub": "%s",\n' "$HUB"
  printf '  "verified": "%s",\n' "$VERIFIED"
  printf '  "addresses": {\n'
  for ((i = 0; i < ${#HOSTS[@]}; i++)); do
    ADDR="${ADDRS[$i]}"
    [ "$i" -eq 0 ] && ADDR="$HUB_ADDR"
    printf '    "%s": "%s"' "${HOSTS[$i]}" "$ADDR"
    [ "$i" -lt $((${#HOSTS[@]} - 1)) ] && printf ','
    printf '\n'
  done
  printf '  }\n'
  printf '}\n'
} >"${DEPLOY_ENV_DIR}/vpn.json"
chmod 600 "${DEPLOY_ENV_DIR}/vpn.json"

if [ "$OFFSET_OK" != "yes" ]; then
  warn "Only the hub address was corrected — if the peers disagree too, set DEPLOY_CP_ADDRESS and re-run ./logstotal deploy:env."
fi
info "Wrote ${DEPLOY_ENV_DIR}/vpn.json — ./logstotal deploy:env will use these addresses."
