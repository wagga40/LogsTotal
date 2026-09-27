#!/usr/bin/env bash
# Multi-server deploy helper for LogsTotal (developer / ops).
#
# Prerequisites on this machine: ssh, scp, bash 4+.
# Prerequisites on each remote: SSH with key (BatchMode) as root or the DEPLOY_HOSTS user,
#   docker + compose plugin, 7z (p7zip), rsync (release snapshot + rollback). No go-task:
#   each release runs through its own ./logstotal, on the go-task tarball its archive
#   carries. The deploy action uploads and extracts the archive itself; the other actions
#   (status, logs, start-only, rollback, ...) need an existing install under
#   DEPLOY_REMOTE_DIR.
#
# Configuration:
#   Variables can be set via environment or a deploy.env file in the working directory.
#   Env vars from the caller always override deploy.env values.
#   Set DEPLOY_ENV_FILE to load a different file (default: deploy.env).
#
# Positional arguments:
#   Host entries, which beat both the environment and deploy.env:
#     bash scripts/deploy-multiserver.sh cp.example.com w1.example.com
#   This is how `task deploy:status -- cp w1` reaches the script — go-task never exports
#   a CLI variable to the shell, so a DEPLOY_HOSTS= suffix does not.
#
# Required env:
#   DEPLOY_HOSTS   Comma-separated hostnames or IPs (first = control plane, rest = workers).
#                  Entries may be `host` (SSH as root), `user@host` — never both prefixed —
#                  or the literal `local`, meaning THIS machine: commands run directly with
#                  no SSH, which is how the whole deploy can run from the control plane
#                  itself. A `local` entry needs root, or sudo without a password prompt.
#
# Deploy phases (action=deploy):
#   1. validate    SSH probe + running-stack guard on every host
#   2. stop        workers first, control plane last (requires DEPLOY_STOP=true if stacks run)
#   3. stage       snapshot + upload + extract on every host (stacks down)
#   4. start CP    start the control plane, poll /health — an unhealthy CP FAILS the
#                  deploy and leaves the workers stopped
#   5. start workers  start + verify each worker stack
#
# Optional env:
#   DEPLOY_DRY_RUN      true: print every ssh/scp command instead of executing it —
#                       no connections are made. Used by tests to pin phase ordering.
#   DEPLOY_HEALTH_ATTEMPTS / DEPLOY_HEALTH_DELAY
#                       Control-plane health polling (default 30 attempts x 2 s).
#   SSH_IDENTITY        Path to private key. When unset, SSH uses its default key resolution
#                       (agent, ~/.ssh/config, default key files). BatchMode is always on —
#                       if no key works, SSH fails cleanly (no password fallback).
#   DEPLOY_REMOTE_DIR   Default /opt/logstotal
#   DEPLOY_PACKAGE      Path to logstotal-*.7z (default: newest logstotal-*.7z in cwd)
#   DEPLOY_ACTION       deploy | status | logs | stop-only | start-only | exec | shell | rollback
#                       (default: deploy)
#   DEPLOY_ONLY         Comma-separated subset of DEPLOY_HOSTS to act on. Everything else
#                       is left running and untouched — this is how a worker joins an
#                       existing fleet without restarting the control plane. When the
#                       control plane is not in the subset, phase 4 checks its health
#                       instead of restarting it.
#   DEPLOY_STOP         true: before deploy, stop running stacks; if false and a stack is up,
#                       deploy aborts — set DEPLOY_STOP=true to confirm the stop.
#   DEPLOY_CLEAN        true: destructive docker compose down -v --rmi all (main + worker file)
#                       on EVERY host in DEPLOY_HOSTS — deletes named volumes (databases!) and
#                       images. Also requires DEPLOY_CLEAN_CONFIRM=yes or the script refuses.
#   DEPLOY_CLEAN_CONFIRM  yes: required alongside DEPLOY_CLEAN=true to actually run the clean.
#   DEPLOY_REMOVE_CONFIRM  yes: required by DEPLOY_ACTION=remove. Without it, nothing.
#   DEPLOY_REMOVE_KEEP_DATA  yes: remove keeps data/ uploads/ backups/, drops the rest.
#   DEPLOY_REMOVE_VPN   truthy: remove also brings wg0 down, deletes /etc/wireguard/wg0.conf
#                       and drops the local deploy-envs/vpn.json address map.
#   DEPLOY_ENV_DIR      Where vpn.json lives (default deploy-envs); only read by remove.
#   DEPLOY_KEEPENV      true: backup .env before extract, restore after (per host)
#   DEPLOY_START        true: after extract, task docker:up on first host, task docker:worker-up on others
#   DEPLOY_LOGS_LINES   For logs action, tail this many lines per host (default 120)
#   DEPLOY_KEEP_RELEASES  Rollback snapshots kept per host (default 3)
#   DEPLOY_VPN / DEPLOY_VPN_PORT
#                       Read by the remove action only, and only to REPORT: a fleet built
#                       with a tunnel leaves wireguard-tools and a ufw rule behind, and
#                       naming them is the difference between a teardown and one you can
#                       trust. Nothing here acts on them — that is deploy-vpn.sh's job.
#   LOGSTOTAL_IMAGE_TAG Set by this script from the bundle manifest, so compose asks for the
#                     tag the images were LOADED under. Defaults to `latest` everywhere else.
#   LOGSTOTAL_NO_BUILD  Set by this script when a bundle supplied the images: the hosts
#                       start what was loaded instead of building, because there is nothing
#                       to build from on a closed network.
#   DEPLOY_STRICT       true: a worker whose stack could not be CONFIRMED running fails the
#                       deploy. Default false — the poll giving up is a statement about the
#                       wait, not about the worker, and the control plane has already
#                       passed its own health gate by then. For CI.
#   DEPLOY_HOST         For the shell action, target a single host (default: first in DEPLOY_HOSTS)
#   DEPLOY_CMD          For exec action, the command string to run on each host
#   DEPLOY_ENV_FILE     Path to defaults file (default: deploy.env in cwd)
#
# Examples:
#   # Save defaults to deploy.env so you don't retype them:
#   #   DEPLOY_HOSTS=cp.example.com,10.0.0.2
#   #   DEPLOY_KEEPENV=true
#
#   # Full deploy cycle (SSH_IDENTITY omitted — uses ssh-agent / ~/.ssh/config)
#   DEPLOY_STOP=true DEPLOY_START=true bash scripts/deploy-multiserver.sh
#
#   # Full deploy cycle with explicit key
#   DEPLOY_HOSTS=cp.example.com,10.0.0.2 SSH_IDENTITY=~/.ssh/id_ed25519 \
#     DEPLOY_STOP=true DEPLOY_KEEPENV=true DEPLOY_START=true ./scripts/deploy-multiserver.sh
#
#   # Check status
#   task deploy:status
#
#   # Run arbitrary command on all hosts
#   DEPLOY_CMD="docker ps" task deploy:exec

set -euo pipefail

# Resolved from BASH_SOURCE, not from cwd: this script is run from wherever the
# operator keeps their package, and the dry-run tests run it from a temp dir.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# ── Load deploy.env defaults (env vars from caller take precedence) ─────────

# Defaulted here, like the sibling scripts do. Under `set -u` a bare reference is fatal, and
# both uses are on paths easy to miss in a test: the "DEPLOY_HOSTS is required" hint — the
# very first error a new operator meets — and the leftovers checklist a remove prints.
DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"

# An explicit key list rather than exporting every line in the file: a stray PATH= or
# LD_PRELOAD= in deploy.env would silently reconfigure the deploy, and an indented key would
# make bash abort on `invalid variable name` before anything was printed. Every key below
# is documented in the header block above —
# tests/test_docs_in_sync.py::test_deploy_script_env_vars_are_self_documented
# enforces that, so a new knob must be added in both places.
# Adopt a remote fleet record when FLEET_FROM names a control plane. ABOVE the first
# deploy.env read, always: _fleet_options memoises the record's options on first read, so a
# later adoption is silently half-applied — hosts from the remote record, settings from this
# machine. See lib/fleet_record.sh::fleet_adopt.
fleet_adopt
deploy_env_load \
  DEPLOY_HOSTS DEPLOY_ONLY DEPLOY_REMOTE_DIR DEPLOY_ACTION DEPLOY_STOP DEPLOY_CLEAN \
  DEPLOY_CLEAN_CONFIRM DEPLOY_KEEPENV DEPLOY_START DEPLOY_LOGS_LINES \
  DEPLOY_KEEP_RELEASES DEPLOY_DRY_RUN DEPLOY_HEALTH_ATTEMPTS DEPLOY_HEALTH_DELAY \
  DEPLOY_PACKAGE DEPLOY_HOST DEPLOY_CMD DEPLOY_STRICT SSH_IDENTITY \
  DEPLOY_REMOVE_KEEP_DATA DEPLOY_REMOVE_VPN DEPLOY_ENV_DIR DEPLOY_VPN DEPLOY_VPN_PORT

# ── Host list ────────────────────────────────────────────────────────────────
#
# Positional arguments beat both the environment and deploy.env, the same precedence
# upgrade.sh uses and for the same reason: go-task never exports a CLI variable to the
# shell, so `task deploy:status DEPLOY_HOSTS=cp,w1` never reaches this script — and with
# a deploy.env present it does not abort either, it acts on THE FLEET NAMED IN THAT FILE.
_hosts_from_args=$(hosts_from_args "$@")
[[ -n "$_hosts_from_args" ]] && DEPLOY_HOSTS="$_hosts_from_args"

# ── Configuration ────────────────────────────────────────────────────────────

DEPLOY_REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/logstotal}"
DEPLOY_ACTION="${DEPLOY_ACTION:-deploy}"
DEPLOY_STOP="${DEPLOY_STOP:-false}"
DEPLOY_CLEAN="${DEPLOY_CLEAN:-false}"
DEPLOY_CLEAN_CONFIRM="${DEPLOY_CLEAN_CONFIRM:-false}"
DEPLOY_KEEPENV="${DEPLOY_KEEPENV:-false}"
DEPLOY_START="${DEPLOY_START:-false}"
DEPLOY_LOGS_LINES="${DEPLOY_LOGS_LINES:-120}"
DEPLOY_KEEP_RELEASES="${DEPLOY_KEEP_RELEASES:-3}"
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-false}"
DEPLOY_HEALTH_ATTEMPTS="${DEPLOY_HEALTH_ATTEMPTS:-30}"
DEPLOY_HEALTH_DELAY="${DEPLOY_HEALTH_DELAY:-2}"
DEPLOY_STRICT="${DEPLOY_STRICT:-false}"
UNVERIFIED_WORKERS=''

# ── Helpers ──────────────────────────────────────────────────────────────────

# die/info/warn/header/step, truthy, to_target and build_ssh_opts come from
# lib/common.sh.

flag_label() {
  truthy "${1:-}" && echo "YES" || echo "no"
}

# ── Validation ───────────────────────────────────────────────────────────────

# LAST in the chain, after positionals, the environment and deploy.env: this host's own
# record of the fleet it belongs to. It is what lets every deploy action run bare ON a
# control plane, where deploy.env does not exist — it belongs to whoever ran the deploy,
# and package.sh keeps it out of the archive on purpose.
if [[ -z "${DEPLOY_HOSTS:-}" ]]; then
  DEPLOY_HOSTS=$(fleet_hosts "$DEPLOY_REMOTE_DIR")
  [[ -n "${DEPLOY_HOSTS:-}" ]] && info "Fleet from this host's own record: ${DEPLOY_HOSTS}"
fi

[[ -n "${DEPLOY_HOSTS:-}" ]] || die "DEPLOY_HOSTS is required (comma-separated host list).
Name them: ./logstotal deploy:status -- cp.example.com w1.example.com
Or put DEPLOY_HOSTS in ${DEPLOY_ENV_FILE}.
On a control plane this is normally answered by its own fleet record; there is none at
$(fleet_manifest_path "$DEPLOY_REMOTE_DIR")."

if [[ "$DEPLOY_ACTION" == "deploy" ]] && truthy "$DEPLOY_CLEAN" && ! truthy "$DEPLOY_CLEAN_CONFIRM"; then
  die "DEPLOY_CLEAN=true would run 'docker compose down -v --rmi all' on BOTH the main and worker stacks on EVERY host in DEPLOY_HOSTS (${DEPLOY_HOSTS}) — this destroys all containers, named volumes (including databases), and images. Set DEPLOY_CLEAN_CONFIRM=yes to confirm and proceed."
fi

build_ssh_opts

# ── Host wrappers ────────────────────────────────────────────────────────────
#
# Thin names over lib/common.sh's host_exec/host_copy_to/host_copy_from, which carry
# the ssh-or-local branch and the dry-run tracing. Kept as local aliases because
# `remote` reads correctly at ~40 call sites.

remote()    { host_exec "$@"; }
scp_to()    { host_copy_to "$@"; }
scp_from()  { host_copy_from "$@"; }

# ── Parse hosts ──────────────────────────────────────────────────────────────

HOSTS=()
IFS=',' read -r -a _raw <<< "${DEPLOY_HOSTS// /}"
for h in "${_raw[@]}"; do
  h="${h#"${h%%[![:space:]]*}"}"
  h="${h%"${h##*[![:space:]]}"}"
  [[ -n "$h" ]] && HOSTS+=("$h")
done
((${#HOSTS[@]} > 0)) || die "No hosts in DEPLOY_HOSTS"

host_role() {
  [[ "$1" -eq 0 ]] && echo "control-plane" || echo "worker"
}

# ── Targeting ────────────────────────────────────────────────────────────────
#
# DEPLOY_ONLY narrows every loop below to a subset of DEPLOY_HOSTS, so adding a worker to a
# live fleet does not mean re-staging every host including a perfectly healthy control
# plane — a full outage to gain one machine. Roles stay positional in DEPLOY_HOSTS, so
# the subset never changes which host is the control plane.

TARGETS=()
if [[ -n "${DEPLOY_ONLY:-}" ]]; then
  IFS=',' read -r -a _only <<< "${DEPLOY_ONLY// /}"
  for t in "${_only[@]}"; do
    [[ -n "$t" ]] || continue
    _found=false
    for h in "${HOSTS[@]}"; do
      [[ "$h" == "$t" ]] && _found=true && break
    done
    # Silently ignoring an unknown name would deploy to nothing and report success,
    # which is the worst possible outcome for a typo.
    [[ "$_found" == "true" ]] || die "DEPLOY_ONLY names ${t}, which is not in DEPLOY_HOSTS (${DEPLOY_HOSTS}). Spell it exactly as it appears there."
    TARGETS+=("$t")
  done
  ((${#TARGETS[@]} > 0)) || die "DEPLOY_ONLY is set but empty"
fi

# targeted HOST — 0 when HOST should be acted on. Always true without DEPLOY_ONLY.
targeted() {
  ((${#TARGETS[@]} == 0)) && return 0
  local t
  for t in "${TARGETS[@]}"; do
    [[ "$t" == "$1" ]] && return 0
  done
  return 1
}

# Any host that is not the `local` sentinel needs the OpenSSH client. Checked after
# parsing rather than before, so a fleet that is entirely local (a single-machine
# rehearsal, or a control plane deploying only to itself) does not demand ssh it
# never uses. Without the check the first missing binary surfaces as
# `ssh: command not found` partway through phase 1, some hosts already validated.
if ! truthy "$DEPLOY_DRY_RUN"; then
  for h in "${HOSTS[@]}"; do
    if ! is_local_host "$h"; then
      require_cmd ssh "Install the OpenSSH client."
      require_cmd scp "Install the OpenSSH client."
      break
    fi
  done
fi

# Running from inside DEPLOY_REMOTE_DIR is allowed: phase 3 stages beside the install and
# rsyncs across, and rsync renames rather than truncates, so the script bash is reading is
# never rewritten in place (see lib/install.sh). The install can deploy and upgrade itself,
# which is the whole point of running upgrades from the control plane.
#
# Sibling scripts are a different question — the overlay replaces them mid-run — so this
# run's scripts are pinned to a copy taken now, and every dispatch below resolves there.
if hosts_have_local "$DEPLOY_HOSTS"; then
  pin_run_dir
fi

# ONE EXIT trap for the whole script, because bash keeps only the last one registered: a
# second one (say, in do_deploy for STAGE_TMPDIR) would silently replace this, and a
# `trap - EXIT` before an early return would disarm both. Everything that needs removing
# on the way out is named here.
_lt_cleanup() {
  [ -n "${STAGE_TMPDIR:-}" ] && rm -rf "$STAGE_TMPDIR"
  [ -n "${FLEET_WORK:-}" ] && rm -rf "$FLEET_WORK"
  unpin_run_dir
  return 0
}
trap _lt_cleanup EXIT

# ── Banner ───────────────────────────────────────────────────────────────────

print_banner() {
  printf '\n%s  LogsTotal Multi-Server Deploy%s\n' "$C_BOLD" "$C_OFF"
  printf '  Action:     %s\n' "$DEPLOY_ACTION"
  printf '  Hosts:      %s\n' "${HOSTS[*]}"
  printf '  Remote dir: %s\n' "$DEPLOY_REMOTE_DIR"
  if [[ "$DEPLOY_ACTION" == "deploy" ]]; then
    printf '  STOP:       %s\n' "$(flag_label "$DEPLOY_STOP")"
    printf '  CLEAN:      %s\n' "$(flag_label "$DEPLOY_CLEAN")"
    printf '  KEEPENV:    %s\n' "$(flag_label "$DEPLOY_KEEPENV")"
    printf '  START:      %s\n' "$(flag_label "$DEPLOY_START")"
  fi
  if truthy "$DEPLOY_DRY_RUN"; then
    printf '  DRY-RUN:    YES (no ssh/scp commands will be executed)\n'
  fi
  printf '\n'
}

# ── Package resolution ───────────────────────────────────────────────────────

resolve_package() {
  if [[ -n "${DEPLOY_PACKAGE:-}" ]]; then
    if [[ ! -f "$DEPLOY_PACKAGE" ]] && ! truthy "$DEPLOY_DRY_RUN"; then
      die "DEPLOY_PACKAGE not found: $DEPLOY_PACKAGE"
    fi
    echo "$DEPLOY_PACKAGE"
    return
  fi
  local newest
  # shellcheck disable=SC2012  # newest-first by mtime; the names are generated
  # (logstotal-<version>.7z) so there is nothing for `find -print0` to protect against.
  # A bundle opened by the package gate leaves its archive here. Preferred over anything
  # else in the working directory, because an operator who named a bundle meant it.
  if [ -d .bundle ]; then
    local from_bundle
    # shellcheck disable=SC2012  # generated names
    from_bundle=$(ls -t .bundle/logstotal-*.7z 2>/dev/null | head -1 || true)
    if [[ -n "$from_bundle" ]]; then
      echo "$from_bundle"
      return
    fi
  fi
  # shellcheck disable=SC2012  # generated names; newest-first by mtime is the intent
  newest=$(ls -t logstotal-*.7z 2>/dev/null | head -1 || true)
  if [[ -z "$newest" ]]; then
    truthy "$DEPLOY_DRY_RUN" && { echo "logstotal-dryrun.7z"; return; }
    die "No logstotal-*.7z in cwd; set DEPLOY_PACKAGE or run: ./logstotal package"
  fi
  echo "$newest"
}

# ── Remote helpers ───────────────────────────────────────────────────────────

# Returns 0 if any LogsTotal compose stack is running on the host, 1 otherwise.
# Prints a short description of what is running to stdout.
check_running() {
  local host=$1
  # Dry-run makes no connections — treat every host as idle.
  truthy "$DEPLOY_DRY_RUN" && return 1
  remote "$host" bash -s <<EOS
DIR="${DEPLOY_REMOTE_DIR}"
cd "\$DIR" 2>/dev/null || exit 1

main_running=false
worker_running=false

if docker compose ps --status running -q 2>/dev/null | grep -q .; then
  main_running=true
fi
if docker compose -f docker-compose.worker.yml ps --status running -q 2>/dev/null | grep -q .; then
  worker_running=true
fi

if \$main_running && \$worker_running; then
  echo "main + worker stacks running"
  exit 0
elif \$main_running; then
  echo "main stack running"
  exit 0
elif \$worker_running; then
  echo "worker stack running"
  exit 0
fi
exit 1
EOS
}

remote_stop() {
  local host=$1 idx=${2:-0}
  local role
  role=$(host_role "$idx")
  step "${host} (${role}): stopping stacks"
  # No `|| true` on this heredoc. Every command inside it already ends in `|| true` and
  # a missing directory exits 0, so the outer mask could only ever hide the one thing
  # worth seeing: ssh itself failing. With it remote_stop could never fail, and phase 3
  # would stage a new release over a still-running install.
  remote "$host" bash -s <<EOS
set -euo pipefail
cd "${DEPLOY_REMOTE_DIR}" 2>/dev/null || exit 0
ROLE="${role}"
# The install's own ./logstotal, else a go-task from before the wrapper, else compose itself.
if [ -x ./logstotal ]; then
  LT=./logstotal
elif command -v task >/dev/null 2>&1; then
  LT=task
else
  LT=""
fi
if [ "\$ROLE" = "control-plane" ]; then
  if [ -n "\$LT" ]; then
    "\$LT" docker:down 2>/dev/null || true
  else
    docker compose down 2>/dev/null || true
  fi
else
  if [ -n "\$LT" ]; then
    "\$LT" docker:worker-down 2>/dev/null || true
  else
    docker compose -f docker-compose.worker.yml down 2>/dev/null || true
  fi
fi
EOS
}

remote_clean() {
  local host=$1
  step "${host}: CLEAN (destructive: volumes + images)"
  remote "$host" bash -s <<EOS
set -euo pipefail
cd "${DEPLOY_REMOTE_DIR}" 2>/dev/null || { echo "Skip clean: directory missing"; exit 0; }
docker compose down -v --rmi all 2>/dev/null || true
docker compose -f docker-compose.worker.yml down -v --rmi all 2>/dev/null || true
EOS
}

remote_start() {
  local host=$1 idx=${2:-0}
  local role
  role=$(host_role "$idx")
  step "${host} (${role}): starting stack"
  remote "$host" bash -s <<EOS
set -euo pipefail
cd "${DEPLOY_REMOTE_DIR}" 2>/dev/null || { echo "ERROR: ${DEPLOY_REMOTE_DIR} not found"; exit 1; }
# The staged release's own ./logstotal, which runs on the go-task tarball its archive carries;
# a release from before the wrapper needs the go-task the host was bootstrapped with.
if [ -x ./logstotal ]; then
  LT=./logstotal
elif command -v task >/dev/null 2>&1; then
  LT=task
else
  echo "ERROR: ${DEPLOY_REMOTE_DIR}/logstotal not found, and no go-task to start an older release with"
  exit 1
fi
ROLE="${role}"
# Exported into the remote environment so the start task uses what was loaded rather than
# building it — there is nothing to build from on a host with no network.
export LOGSTOTAL_NO_BUILD="${LOGSTOTAL_NO_BUILD:-false}"
export LOGSTOTAL_IMAGE_TAG="${LOGSTOTAL_IMAGE_TAG:-latest}"
# Read on the HOST, so a plain start — which knows nothing about a bundle — starts what is
# there instead of trying to build it. Written by the image-load step above.
# No backticks in this comment: it rides inside the heredoc, where they would RUN.
if [ -f "${DEPLOY_REMOTE_DIR}/data/.bundle-images" ]; then
  if [ "\$LOGSTOTAL_NO_BUILD" != "true" ]; then
    export LOGSTOTAL_NO_BUILD=true
    . "${DEPLOY_REMOTE_DIR}/data/.bundle-images"
    [ -n "\${tag:-}" ] && export LOGSTOTAL_IMAGE_TAG="\$tag"
  fi
  # The worker CONTAINER is the thing that needs this — the tool adapter runs inside it and
  # env_file is the only way it is told anything. Written here because every other place is
  # upstream of something that replaces .env. Idempotent, so a regenerated .env heals on the
  # next start rather than needing a redeploy.
  touch .env
  sed -i.bak '/^LOGSTOTAL_BUNDLED_IMAGES=/d' .env && rm -f .env.bak
  printf 'LOGSTOTAL_BUNDLED_IMAGES=true\n' >> .env
fi
if [ "\$ROLE" = "control-plane" ]; then
  "\$LT" docker:up
else
  "\$LT" docker:worker-up
fi
EOS
}

# Poll the control plane's /health until it returns 200 or attempts run out.
wait_for_health() {
  local host=$1
  local attempts="${DEPLOY_HEALTH_ATTEMPTS}" delay="${DEPLOY_HEALTH_DELAY}"
  if truthy "$DEPLOY_DRY_RUN"; then
    local dry_code="${DEPLOY_DRY_RUN_HEALTH:-200}"
    if [[ "$dry_code" == "200" ]]; then
      info "${host}: /health returned 200 — OK (dry-run)"
      return 0
    fi
    warn "${host}: /health returned ${dry_code} (dry-run)"
    return 1
  fi
  step "${host}: waiting for /health (up to $((attempts * delay))s)"
  local i code
  # The probe below uses -s, never -sf, and has no `|| echo "000"` fallback. With -f, curl
  # still writes the code through -w AND exits non-zero, so the guard would append a second
  # value — "/health still 503000 after 60s", a code nothing can grep for, from the gate
  # that decides whether a deploy succeeded. Without -f, a 503 is reported as 503.
  for ((i = 1; i <= attempts; i++)); do
    code=$(remote "$host" bash -s <<EOS 2>/dev/null || true
cd "${DEPLOY_REMOTE_DIR}" 2>/dev/null || exit 1
# no -f, and no 000 fallback -- see the note above this heredoc
if docker compose ps --status running -q web 2>/dev/null | grep -q .; then
  docker compose exec -T web curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://127.0.0.1:8000/health 2>/dev/null || true
else
  curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://127.0.0.1:8000/health 2>/dev/null || true
fi
EOS
)
    code=$(printf '%s' "$code" | tail -1 | tr -d '[:space:]')
    if [[ "$code" == "200" ]]; then
      info "${host}: /health returned 200 — OK"
      return 0
    fi
    sleep "$delay"
  done
  warn "${host}: /health still ${code:-unreachable} after $((attempts * delay))s"
  return 1
}

# A dry run contacts nothing, so any terminal claim it prints is an assertion about remote
# state nobody observed, and a transcript is readily taken as evidence that a deploy or a
# rollback happened.
dry_suffix() {
  if truthy "$DEPLOY_DRY_RUN"; then printf ' (DRY RUN — nothing was contacted)'; fi
}

# ── The fleet record ─────────────────────────────────────────────────────────
#
# Built HERE, on the deploying machine, and pushed to the control plane — rather than
# running the manifest tool over SSH. Two reasons, and the first is decisive: at phase 1 a
# fresh host has no tree yet, so it has no scripts/fleet_manifest.py to run and no python3
# guaranteed either. Building locally also means one implementation runs whatever the fleet
# is made of.
#
# It round-trips: the existing record is pulled first, so per-host results accumulate
# across runs and a DEPLOY_ONLY deploy does not erase what the other hosts were last seen
# doing. Everything here is best-effort — `|| true` throughout — because a fleet record is
# a convenience, and a deploy that fails because its own bookkeeping failed is worse than
# one with a stale record.
FLEET_WORK=""
_fleet_local_copy() {
  [ -n "$FLEET_WORK" ] && return 0
  FLEET_WORK=$(mktemp -d "${TMPDIR:-/tmp}/logstotal-fleet.XXXXXX")
  host_copy_from "${HOSTS[0]}" "$(fleet_remote_manifest_path "$DEPLOY_REMOTE_DIR")" \
    "${FLEET_WORK}/manifest.json" >/dev/null 2>&1 || true
}

_fleet_push() {
  truthy "$DEPLOY_DRY_RUN" && return 0
  [ -f "${FLEET_WORK}/manifest.json" ] || return 0
  remote "${HOSTS[0]}" "mkdir -p ${DEPLOY_REMOTE_DIR}/fleet" >/dev/null 2>&1 || true
  host_copy_to "${FLEET_WORK}/manifest.json" "${HOSTS[0]}" \
    "$(fleet_remote_manifest_path "$DEPLOY_REMOTE_DIR")" >/dev/null 2>&1 || true
}

fleet_write_intent() {
  _fleet_local_copy
  FLEET_MANIFEST="${FLEET_WORK}/manifest.json" \
    fleet_record_intent "$(IFS=,; printf '%s' "${HOSTS[*]}")" "$DEPLOY_REMOTE_DIR" || true
  _fleet_push
}

fleet_write_result() {
  # Self-initialising, so an action that never called fleet_write_intent — `deploy:start`,
  # which brings a stopped fleet up and verifies it — still updates the record rather than
  # quietly doing nothing. A no-op that looks like it works is worse than an absent one.
  _fleet_local_copy

  # The version and container count are MEASURED here, not assumed from the fact that the
  # deploy reached this line. "Which release is each host on" is the first question anyone
  # asks of a fleet record, and a record that says a host is fine without saying what it is
  # running is barely a record.
  #
  # One extra probe per host, at the end of a deploy that has already made dozens.
  local measured version containers
  measured=$(host_installed_release "$1" "$DEPLOY_REMOTE_DIR" 2>/dev/null || true)
  version="${measured%%|*}"
  containers="${measured##*|}"
  case "$containers" in *[!0-9]* | "") containers="" ;; esac

  FLEET_MANIFEST="${FLEET_WORK}/manifest.json" \
    fleet_record_result "$1" "$2" "$version" "$containers" || true
  _fleet_push
}

# Verify the worker stack has running containers (retries — compose start is async).
#
# 15 attempts at the fleet's own polling cadence, DEPLOY_HEALTH_DELAY, rather than a
# hardcoded `sleep 2`: it is the same question the control-plane health gate asks — how
# often do we ask a host whether it is ready yet — and one answer for the fleet beats two.
# It also means the whole wait can be collapsed for a test, which a hardcoded 30 seconds
# per host cannot.
verify_worker_running() {
  local host=$1
  truthy "$DEPLOY_DRY_RUN" && return 0
  local i
  for ((i = 1; i <= 15; i++)); do
    if remote "$host" bash -s <<EOS 2>/dev/null
cd "${DEPLOY_REMOTE_DIR}" 2>/dev/null || exit 1
docker compose -f docker-compose.worker.yml ps --status running -q 2>/dev/null | grep -q .
EOS
    then
      return 0
    fi
    sleep "${DEPLOY_HEALTH_DELAY}"
  done
  return 1
}

remote_status() {
  local host=$1 idx=$2
  header "${host} ($(host_role "$idx"))"
  remote "$host" bash -s <<EOS
set -euo pipefail
DIR="${DEPLOY_REMOTE_DIR}"
if [[ ! -d "\$DIR" ]]; then
  echo "LogsTotal not installed at \$DIR"
  exit 0
fi
cd "\$DIR"

if [[ -f VERSION ]]; then
  echo "Release:"
  cat VERSION | sed 's/^/  /'
fi

if [[ -d ${SNAPSHOT_ROOT} ]]; then
  SNAP_COUNT=\$(ls -d ${SNAPSHOT_ROOT}/*/ 2>/dev/null | wc -l || echo 0)
  echo "Rollback snapshots: \$SNAP_COUNT"
fi

echo ""
echo "Main stack:"
docker compose ps 2>/dev/null || echo "  (not running or no compose file)"
echo ""
echo "Worker stack:"
docker compose -f docker-compose.worker.yml ps 2>/dev/null || echo "  (not running)"

echo ""
echo "Health:"
if docker compose ps --status running -q web 2>/dev/null | grep -q .; then
  docker compose exec -T web curl -sf --max-time 5 http://127.0.0.1:8000/health && echo " OK" || echo " FAIL"
else
  curl -sf --max-time 3 http://127.0.0.1:8000/health && echo " OK (host-level)" || echo " not reachable on :8000"
fi
EOS
}

remote_logs() {
  local host=$1 idx=$2
  header "logs: ${host} ($(host_role "$idx"))"
  remote "$host" bash -s <<EOS
set -euo pipefail
cd "${DEPLOY_REMOTE_DIR}" 2>/dev/null || { echo "directory missing"; exit 0; }
if [[ "$idx" -eq 0 ]]; then
  echo "Main stack (last ${DEPLOY_LOGS_LINES} lines, all services):"
  docker compose logs --tail "${DEPLOY_LOGS_LINES}" 2>/dev/null || echo "(no logs)"
else
  echo "Worker stack (last ${DEPLOY_LOGS_LINES} lines):"
  docker compose -f docker-compose.worker.yml logs --tail "${DEPLOY_LOGS_LINES}" 2>/dev/null || echo "(no logs)"
fi
EOS
}

# ── Actions ──────────────────────────────────────────────────────────────────

# do_remove — take LogsTotal off every targeted host: stacks down, volumes and images
# gone, ${DEPLOY_REMOTE_DIR} deleted.
#
# DEPLOY_CLEAN does not remove the directory, so without this "start from scratch" is not
# available: a half-finished deploy leaves code and a .env behind, and the next run
# inherits them.
#
# Guarded twice, matching the two precedents already in this file: a confirm variable
# (DEPLOY_CLEAN_CONFIRM's shape) and a Taskfile prompt (deploy:rollback's).
do_remove() {
  [[ "${DEPLOY_REMOVE_CONFIRM:-}" == "yes" ]] ||
    die "Refusing to remove: set DEPLOY_REMOVE_CONFIRM=yes.
This deletes ${DEPLOY_REMOTE_DIR}, every container, volume and image on: ${DEPLOY_HOSTS}"

  # A path that is empty, /, or a single segment would take the host with it. There is
  # no legitimate DEPLOY_REMOTE_DIR of that shape, so refuse rather than interpret.
  #
  # One test: the `/*/*` glob below rejects "", "/" and "/opt" on its own. It must stay
  # unquoted — a quoted case pattern is matched literally.
  [[ "${DEPLOY_REMOTE_DIR}" == /*/* ]] ||
    die "Refusing to remove an unsafe DEPLOY_REMOTE_DIR: '${DEPLOY_REMOTE_DIR}' — expected an absolute path of at least two segments (e.g. /opt/logstotal)."

  local keep_data="${DEPLOY_REMOVE_KEEP_DATA:-no}"
  local removed=0

  # Workers first, control plane last — the do_stop_only ordering, for the same reason:
  # a worker whose database vanished first spends its last moments erroring.
  local order=()
  for i in "${!HOSTS[@]}"; do [[ "$i" -eq 0 ]] || order+=("$i"); done
  order+=(0)

  for i in "${order[@]}"; do
    local host="${HOSTS[$i]}"
    targeted "$host" || continue
    step "${host}: REMOVE (containers, volumes, images, ${DEPLOY_REMOTE_DIR})"
    remote "$host" bash -s <<EOS
set -uo pipefail
DIR="${DEPLOY_REMOTE_DIR}"
KEEP="${keep_data}"
if [ -d "\$DIR" ]; then
  cd "\$DIR" || exit 0
  docker compose down -v --rmi all 2>/dev/null || true
  docker compose -f docker-compose.worker.yml down -v --rmi all 2>/dev/null || true
  cd / || exit 0
  if [ "\$KEEP" = "yes" ]; then
    # Keep the three state directories, remove everything else including dotfiles.
    find "\$DIR" -mindepth 1 -maxdepth 1 \
      ! -name data ! -name uploads ! -name backups -exec rm -rf {} + 2>/dev/null || true
    echo "removed code, kept data/ uploads/ backups/"
  else
    rm -rf "\$DIR"
    echo "removed \$DIR"
  fi
else
  echo "nothing at \$DIR"
fi

# Outside the directory check on purpose. "docker compose down -v" can only reach volumes
# it still has a compose file for, and a deploy that died before staging the code leaves
# the directory without one — so the named volumes outlive both, and the next install
# would silently adopt a stale database after a remove that reported success.
#
# Matched on the compose project prefix (the install directory's basename), and a volume
# still attached to a container is left alone, so this cannot reach anything else.
PROJECT=\$(basename "\$DIR")
for v in \$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -E "^\${PROJECT}_" || true); do
  if docker volume rm "\$v" >/dev/null 2>&1; then
    echo "removed volume \$v"
  else
    echo "volume \$v is still in use — left alone"
  fi
done
EOS
    removed=$((removed + 1))
  done

  if truthy "${DEPLOY_REMOVE_VPN:-}"; then
    for i in "${order[@]}"; do
      local host="${HOSTS[$i]}"
      targeted "$host" || continue
      step "${host}: REMOVE VPN (wg0)"
      remote "$host" bash -s <<'EOS' || true
wg-quick down wg0 2>/dev/null || true
rm -f /etc/wireguard/wg0.conf 2>/dev/null || true
EOS
    done
    # The address map describes tunnels that no longer exist; leaving it would have the
    # next env-fleet point every worker at an address nothing answers on.
    #
    # Dry-run guarded explicitly, unlike every other write in this function: the wg-quick
    # calls above go through `remote`, which traces instead of connecting, but this one is
    # a LOCAL rm — of the one file here that cannot be rebuilt by re-running anything,
    # because it records addresses Wireconf allocated.
    if truthy "$DEPLOY_DRY_RUN"; then
      info "DRY-RUN remove ${DEPLOY_ENV_DIR:-deploy-envs}/vpn.json"
    else
      rm -f "${DEPLOY_ENV_DIR:-deploy-envs}/vpn.json" 2>/dev/null || true
      info "removed ${DEPLOY_ENV_DIR:-deploy-envs}/vpn.json"
    fi
  fi

  info "Removed from ${removed} host(s)."

  # ── What is left, and who has to do it ──────────────────────────────────────
  #
  # A remove that reports success while leaving the operator's machines changed is the
  # shape of "start from scratch" that does not. Everything below is deliberately NOT
  # removed — each would be wrong to undo automatically — so the only honest thing is to
  # name it. This is the difference between a teardown and a teardown you can trust.
  echo ""
  header "Left behind — deliberately"
  echo "  On each host, installed by ./logstotal deploy:bootstrap and shared with everything else"
  echo "  on the machine, so removing them is not ours to decide:"
  echo "    docker, docker compose, p7zip, rsync, curl (and go-task, on hosts bootstrapped before 1.0)"
  if [[ "${DEPLOY_VPN:-}" == "wireconf" ]] && ! truthy "${DEPLOY_REMOVE_VPN:-}"; then
    echo "    wireguard-tools, /etc/wireguard/wg0.conf, and the wg0 interface"
    echo "      (DEPLOY_REMOVE_VPN=yes would have taken these too)"
  fi
  echo "    the ufw allow rule for ${DEPLOY_VPN_PORT:-51820}/udp on the hub, if one was added"
  if truthy "$keep_data"; then
    echo "    ${DEPLOY_REMOTE_DIR}/{data,uploads,backups} — kept by DEPLOY_REMOVE_KEEP_DATA=yes"
  fi
  echo ""
  echo "  On THIS machine:"
  # Named only when they are actually here. A control plane that was deployed TO rather
  # than FROM has neither — `task package` keeps deploy.env out of the archive and secrets
  # never leave the machine that generated them — so listing them there sends the operator
  # looking for files that do not exist, and says nothing about the machine that does hold
  # them, which is the one with the leftover work.
  if [ -f "$DEPLOY_ENV_FILE" ] || [ -d "${DEPLOY_ENV_DIR:-deploy-envs}" ]; then
    echo "    ${DEPLOY_ENV_FILE} and ${DEPLOY_ENV_DIR:-deploy-envs}/ — the fleet's secrets. They are the"
    echo "      only surviving copy of SECRET_KEY and the database password, so they are"
    echo "      never deleted for you. Remove them yourself once you are sure."
  else
    echo "    Nothing — this machine holds no ${DEPLOY_ENV_FILE} and no ${DEPLOY_ENV_DIR:-deploy-envs}/."
    echo "      They are on whichever machine ran the deploy, and they are the only"
    echo "      surviving copy of SECRET_KEY and the database password. Finish there."
  fi
  # The control plane cannot delete the ground it is standing on. rsync's rename keeps the
  # running script readable, but `rm -rf` on the current directory leaves the process with
  # no cwd, and nothing can finish a teardown from there.
  if hosts_have_local "$DEPLOY_HOSTS"; then
    case "$(pwd)" in
      "${DEPLOY_REMOTE_DIR}" | "${DEPLOY_REMOTE_DIR}"/*)
        echo ""
        echo "  YOU ARE STANDING IN THE DIRECTORY THAT WAS REMOVED."
        echo "    Its contents are gone; the directory itself, and this shell's idea of"
        echo "    where it is, are not. Finish with:"
        echo "      cd ~ && sudo rm -rf ${DEPLOY_REMOTE_DIR}"
        ;;
    esac
  fi
  echo ""
  info "Next: ./logstotal deploy:plan   (every host should read FRESH INSTALL)"
}

do_stop_only() {
  # Workers first, control plane last — workers drain against a still-running
  # control plane instead of erroring into a vanished database/broker.
  for i in "${!HOSTS[@]}"; do
    [[ "$i" -eq 0 ]] && continue
    targeted "${HOSTS[$i]}" || continue
    remote_stop "${HOSTS[$i]}" "$i"
  done
  if targeted "${HOSTS[0]}"; then remote_stop "${HOSTS[0]}" 0; fi
}

# Mirrors phases 4-5 of do_deploy: the control plane comes up first and must pass its
# health check before any worker starts. This is the documented resume path after
# DEPLOY_START=false, so it must not bring workers up against a control plane that might
# be failing — the exact ordering the deploy path exists to prevent.
do_start_only() {
  header "start control plane + health gate"
  if targeted "${HOSTS[0]}"; then remote_start "${HOSTS[0]}" 0; fi
  if ! wait_for_health "${HOSTS[0]}"; then
    fleet_write_result "${HOSTS[0]}" failed
    die "Control plane ${HOSTS[0]} failed its health check — workers were NOT started. Inspect: ./logstotal deploy:logs"
  fi

  if ((${#HOSTS[@]} > 1)); then
    header "start workers"
    local worker_failed="" worker_start_failed=""
    for i in "${!HOSTS[@]}"; do
      [[ "$i" -eq 0 ]] && continue
      targeted "${HOSTS[$i]}" || continue
      if ! remote_start "${HOSTS[$i]}" "$i"; then
        # A MEASURED failure, unlike the poll below: `docker compose up` ran on the host and
        # returned non-zero. Unguarded, `set -e` would kill the entire run right here —
        # before this host's result is recorded, before the workers after it are attempted,
        # and with go-task's bare `exit status 201` as the only explanation.
        warn "${HOSTS[$i]}: could not start the worker stack"
        worker_start_failed="${worker_start_failed} ${HOSTS[$i]}"
        fleet_write_result "${HOSTS[$i]}" failed
        continue
      fi
      if verify_worker_running "${HOSTS[$i]}"; then
        if truthy "$DEPLOY_DRY_RUN"; then
          info "${HOSTS[$i]}: worker stack not verified (DRY RUN — nothing was contacted)"
        else
          info "${HOSTS[$i]}: worker stack running"
        fi
        fleet_write_result "${HOSTS[$i]}" ok
      else
        warn "${HOSTS[$i]}: worker stack NOT running after start"
        worker_failed="${worker_failed} ${HOSTS[$i]}"
        # `unverified`, not `failed`: the poll gave up, which is a statement about the
        # wait. See the note where worker_failed is acted on.
        fleet_write_result "${HOSTS[$i]}" unverified
      fi
    done
    [[ -n "$worker_failed" ]] && warn "Workers not running:${worker_failed}"
    if [[ -n "$worker_start_failed" ]]; then
      die "Worker stack could not be started on:${worker_start_failed}
Every other host was still attempted and its result recorded — read them with: ./logstotal fleet
Inspect the failure with: ./logstotal deploy:logs"
    fi
  fi
  info "Start complete."
}

do_status() {
  for i in "${!HOSTS[@]}"; do
    targeted "${HOSTS[$i]}" || continue
    remote_status "${HOSTS[$i]}" "$i"
  done
}

do_logs() {
  for i in "${!HOSTS[@]}"; do
    targeted "${HOSTS[$i]}" || continue
    remote_logs "${HOSTS[$i]}" "$i"
  done
}

do_exec() {
  [[ -n "${DEPLOY_CMD:-}" ]] || die "DEPLOY_CMD is required for exec action"
  for i in "${!HOSTS[@]}"; do
    local h="${HOSTS[$i]}"
    targeted "$h" || continue
    header "${h} ($(host_role "$i"))"
    # One joined string, not `bash -c <string>`: remote() hands its arguments to a
    # shell already (that is ssh's contract), so an explicit `bash -c` would be a second
    # round of quoting that survives ssh re-joining argv but not a local exec.
    remote "$h" "cd ${DEPLOY_REMOTE_DIR} 2>/dev/null; ${DEPLOY_CMD}" || warn "command failed on ${h}"
  done
}

do_shell() {
  local target="${DEPLOY_HOST:-${HOSTS[0]}}"
  info "Opening interactive shell on ${target} (cd ${DEPLOY_REMOTE_DIR})"
  # Not remote(): an interactive shell needs a TTY, so this is the one call that
  # cannot go through the shared wrapper.
  if is_local_host "$target"; then
    cd "${DEPLOY_REMOTE_DIR}" 2>/dev/null || true
    exec bash -l
  fi
  ssh "${SSH_OPTS[@]}" -t "$(to_target "$target")" "cd ${DEPLOY_REMOTE_DIR} 2>/dev/null || true; exec bash -l"
}

# One snapshot layout, shared with the single-host upgrade: <install>/backups/releases/
# <timestamp>-<version>. See common.sh::SNAPSHOT_ROOT.
remote_snapshot() {
  local host=$1
  local SNAP_EXCLUDES
  SNAP_EXCLUDES=$(snapshot_exclude_args)
  step "${host}: snapshot current release"
  remote "$host" bash -s <<EOS
set -euo pipefail
DIR="${DEPLOY_REMOTE_DIR}"
RELEASES_DIR="\${DIR}/${SNAPSHOT_ROOT}"
mkdir -p "\$RELEASES_DIR"

if [ -f "\${DIR}/VERSION" ]; then
  # A snapshot that silently degrades is worse than none: the operator is told they
  # can roll back, and only finds out otherwise while already recovering.
  command -v rsync >/dev/null 2>&1 || { echo "ERROR: rsync is required to snapshot the release for rollback. Install it (apt install rsync)."; exit 1; }
  STAMP=\$(date +%Y%m%d-%H%M%S)
  # Timestamp first, then the release it holds. A stamp alone cannot answer the first
  # question anyone asks of a rollback point, and a VERSION-first name is not an ordering:
  # "1.10.0" sorts before "1.9.0".
  INSTALLED=\$(sed -n 's/^version: *//p' "\${DIR}/VERSION" | head -1 | tr -d '[:space:]')
  SNAPSHOT="\${RELEASES_DIR}/\${STAMP}-\${INSTALLED:-unknown}"
  mkdir -p "\$SNAPSHOT"
  # Copy key files to snapshot (not uploads/data — just the release).
  # The exclude list is common.sh::snapshot_excludes, expanded here.
  if ! rsync -a ${SNAP_EXCLUDES} \
    "\${DIR}/" "\$SNAPSHOT/"; then
    rm -rf "\$SNAPSHOT"
    echo "ERROR: snapshot failed — refusing to continue with no rollback point."
    exit 1
  fi
  echo "Snapshot saved: \$SNAPSHOT"

  # Prune old releases, keep N most recent
  KEEP=${DEPLOY_KEEP_RELEASES}
  cd "\$RELEASES_DIR"
  TOTAL=\$(ls -d */ 2>/dev/null | wc -l)
  if [ "\$TOTAL" -gt "\$KEEP" ]; then
    ls -d */ | head -n \$(( TOTAL - KEEP )) | xargs rm -rf
    echo "Pruned to \$KEEP releases."
  fi
else
  echo "No VERSION file — skipping snapshot."
fi
EOS
}

do_rollback() {
  for i in "${!HOSTS[@]}"; do
    local h="${HOSTS[$i]}"
    targeted "$h" || continue
    header "${h} ($(host_role "$i")): rollback"

    local SNAP_EXCLUDES
    SNAP_EXCLUDES=$(snapshot_exclude_args)

    if truthy "$DEPLOY_STOP"; then
      remote_stop "$h" "$i"
    fi

    remote "$h" bash -s <<EOS
set -euo pipefail
DIR="${DEPLOY_REMOTE_DIR}"
RELEASES="\${DIR}/${SNAPSHOT_ROOT}"

if [ ! -d "\$RELEASES" ]; then
  echo "ERROR: No releases directory. Nothing to roll back to."
  exit 1
fi

LATEST=\$(ls -d "\${RELEASES}/"*/ 2>/dev/null | tail -1 || true)
if [ -z "\$LATEST" ]; then
  echo "ERROR: No previous release snapshots found."
  exit 1
fi

echo "Rolling back to: \$LATEST"
command -v rsync >/dev/null 2>&1 || { echo "ERROR: rsync is required to restore a snapshot. Install it (apt install rsync)."; exit 1; }

# Restore snapshot over current release (preserving .env, uploads, data, backups).
# Errors are fatal: a rollback that restored nothing must not print "Rollback complete"
# and then delete the snapshot it failed to restore from, leaving no way to retry.
#
# --checksum, for the reason written out in upgrade.sh's _restore_snapshot: rsync's
# default quick check skips a file whose size AND whole-second mtime both match, and a
# snapshot preserves the original mtimes while the deploy replaced them moments later.
# A VERSION manifest is one short line, so consecutive releases collide on size by
# construction — it is the likeliest file in the tree to be silently left alone, and it
# is the one the rollback is judged by.
#
# --delete, because a snapshot is the whole release: without it a file the newer release
# ADDED survives the rollback, and the tree is neither version.
if ! rsync -a --checksum --delete ${SNAP_EXCLUDES} \
  "\$LATEST/" "\${DIR}/"; then
  echo "ERROR: restore failed — snapshot kept at \$LATEST so you can retry."
  exit 1
fi

# Remove the used snapshot so re-rollback uses the one before it. Only after a
# verified restore.
rm -rf "\$LATEST"
echo "Rollback complete on ${h}."
EOS

    if truthy "$DEPLOY_START"; then
      remote_start "$h" "$i"
    fi
  done
  info "Rollback complete.$(dry_suffix)"
}

do_deploy() {
  local pkg
  pkg=$(resolve_package)
  local pkg_size="dry-run"
  [[ -f "$pkg" ]] && pkg_size=$(du -h "$pkg" | cut -f1)
  info "Package: $pkg (${pkg_size})"

  # ── Phase 1/5 — validate: SSH probe + running-stack guard on EVERY host ──
  header "Phase 1/5: validate hosts"
  if ((${#TARGETS[@]} > 0)); then
    info "Targeting ${TARGETS[*]} — every other host is left running and untouched."
  fi
  local blocked=false
  for i in "${!HOSTS[@]}"; do
    local h="${HOSTS[$i]}"
    # The control plane is always probed: phase 4 gates the workers on its health
    # whether or not it is being deployed to.
    if ! targeted "$h" && [[ "$i" -ne 0 ]]; then
      continue
    fi
    remote "$h" "true" >/dev/null || die "SSH probe failed for ${h}"
    # Create the deploy root here, not in the stage phase: a clean host has no
    # ${DEPLOY_REMOTE_DIR}, and docs/install/fleet.md Step 3 has operators scp their .env
    # into it before the first deploy.
    remote "$h" "mkdir -p ${DEPLOY_REMOTE_DIR}" >/dev/null || die "Cannot create ${DEPLOY_REMOTE_DIR} on ${h}"
    local status_line
    if status_line=$(check_running "$h" 2>/dev/null); then
      if ! targeted "$h"; then
        info "${h}: ${status_line} — left alone (not in DEPLOY_ONLY)"
      elif truthy "$DEPLOY_STOP"; then
        info "${h}: ${status_line} — will be stopped (DEPLOY_STOP=true)"
      else
        warn "${h}: ${status_line}"
        blocked=true
      fi
    else
      info "${h}: no running stacks detected"
    fi
  done

  if [[ "$blocked" == "true" ]]; then
    die "Aborting: one or more hosts have running stacks. Set DEPLOY_STOP=true to stop them first, or run: ./logstotal deploy:stop"
  fi

  # The fleet record, written HERE — after validation, before a single host is mutated.
  # A run that dies in phase 5 is exactly when someone needs to know which machines were
  # in scope, so the intended half cannot wait for a successful ending. Each host's
  # observed result is merged in as that host finishes.
  #
  # Only on the control plane: it is the machine that has to answer "which fleet am I
  # part of" when the operator's laptop is not around. Written locally when the control
  # plane is `local`, pushed over SSH otherwise.
  fleet_write_intent

  # ── Phase 2/5 — stop: workers first, control plane last ──
  # Workers drain against a still-running control plane; stopping the CP first
  # would leave workers mid-job with no database/broker to write to.
  if truthy "$DEPLOY_STOP"; then
    header "Phase 2/5: stop stacks (workers first, control plane last)"
    for i in "${!HOSTS[@]}"; do
      [[ "$i" -eq 0 ]] && continue
      targeted "${HOSTS[$i]}" || continue
      remote_stop "${HOSTS[$i]}" "$i"
    done
    if targeted "${HOSTS[0]}"; then
      remote_stop "${HOSTS[0]}" 0
    fi
  else
    info "Phase 2/5: stop skipped (DEPLOY_STOP=false — nothing was stopped; whether anything was running here was not checked)"
  fi

  # ── Phase 3/5 — stage: snapshot + upload + extract on every host (stacks down) ──
  header "Phase 3/5: snapshot + upload + extract"
  # STAGE_TMPDIR is script-scope, not `local`, and that is the whole point: the EXIT
  # trap (_lt_cleanup, registered at the top of the script) fires *after* do_deploy has
  # returned, so a function-local would be out of scope by then and the cleanup would die
  # on an unbound variable under set -u — a shell error on top of whatever actually went
  # wrong in phase 4 or 5, exactly when the real message matters most.
  local OVERLAY_EXCLUDES
  OVERLAY_EXCLUDES=$(overlay_exclude_args)

  STAGE_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/logstotal-deploy-env.XXXXXX")

  for i in "${!HOSTS[@]}"; do
    local h="${HOSTS[$i]}"
    targeted "$h" || continue
    step "${h} ($(host_role "$i")): stage new release"

    if truthy "$DEPLOY_CLEAN"; then
      remote_clean "$h"
    fi

    remote_snapshot "$h"

    local env_backup="${STAGE_TMPDIR}/env.${h//[^a-zA-Z0-9._-]/_}"
    if truthy "$DEPLOY_KEEPENV"; then
      if remote "$h" "test -f ${DEPLOY_REMOTE_DIR}/.env" >/dev/null; then
        step "backup .env from ${h}"
        scp_from "$h" "${DEPLOY_REMOTE_DIR}/.env" "$env_backup"
      else
        info "(no remote .env to backup on ${h})"
      fi
    fi

    local remote_pkg
    remote_pkg="/tmp/logstotal-deploy-$(basename "$pkg")"
    step "upload package to ${h}"
    scp_to "$pkg" "$h" "$remote_pkg"

    # Stage beside the install, then rsync across — never extract over the live tree.
    #
    # `7z x -aoa` rewrites each target IN PLACE, under whatever file descriptor is open on
    # it. On a `local` host that is the very script bash is executing.
    #
    # rsync renames its temporary into place instead, so the running script keeps reading
    # the inode it started on. lib/install.sh carries the full reasoning and the three
    # rules that keep it true. The upshot here: one mechanism for every host, `local`
    # included, and no refusal.
    #
    # --delete, because the release is the whole tree: without it a file dropped between
    # versions lingers, and a stale alembic revision is the case that hurts — it makes
    # get_head_revision() resolve to a migration the installed code does not contain.
    local stage
    stage=$(stage_dir "$DEPLOY_REMOTE_DIR")
    step "stage and overlay ${DEPLOY_REMOTE_DIR}"
    remote "$h" bash -s <<EOS
set -euo pipefail
command -v 7z >/dev/null 2>&1 || { echo "ERROR: 7z (p7zip) not installed on this server"; exit 1; }
command -v rsync >/dev/null 2>&1 || { echo "ERROR: rsync not installed on this server (apt install rsync)"; exit 1; }
mkdir -p "${DEPLOY_REMOTE_DIR}"
rm -rf "${stage}"
mkdir -p "${stage}"
7z x -y "${remote_pkg}" -o"${stage}" >/dev/null
rm -f "${remote_pkg}"
[ -f "${stage}/VERSION" ] || { echo "ERROR: the staged archive has no VERSION at its root — is it a LogsTotal release?"; rm -rf "${stage}"; exit 1; }
rsync -a --delete ${OVERLAY_EXCLUDES} "${stage}/" "${DEPLOY_REMOTE_DIR}/"
rm -rf "${stage}"
cd "${DEPLOY_REMOTE_DIR}"
mkdir -p data uploads
EOS

    # The bundle's images, if there is one — copied and `docker load`ed here rather than
    # pulled. This is the whole difference between an install that needs a network and one
    # that does not, and it happens per host because each has its own Docker daemon.
    if [[ -n "${BUNDLE:-}" && -d .bundle/images ]]; then
      step "${h}: load images from the bundle"
      local img
      for img in .bundle/images/*.tar; do
        [[ -f "$img" ]] || continue
        scp_to "$img" "$h" "/tmp/$(basename "$img")"
        remote "$h" "docker load -i /tmp/$(basename "$img") && rm -f /tmp/$(basename "$img")" >/dev/null
      done
      export LOGSTOTAL_NO_BUILD=true
      # And SAY which tag was loaded. The bundle tags its images with the release —
      # `logstotal:1.0.0` — so that a host can hold two and a rollback has something to go
      # back to. compose asks for `${LOGSTOTAL_IMAGE_TAG:-latest}`, so without it a bundle
      # deploy looks for `:latest`, finds nothing under `--pull never`, and dies at its last
      # step with the right images on the host, unreferenced.
      local bundle_tag
      bundle_tag=$(run_py -c \
        "import json,sys;print(json.load(open(sys.argv[1])).get('image_tag',''))" \
        .bundle/bundle-manifest.json 2>/dev/null || true)
      if [[ -n "$bundle_tag" ]]; then
        export LOGSTOTAL_IMAGE_TAG="$bundle_tag"
      fi

      # Leave the host knowing how it got its images, because THIS deploy is not the only
      # thing that will ever start it. `task deploy:start` and every restart go through
      # remote_start with no bundle in sight, default to building, and on a closed network
      # would die pulling the base image — day 2 broken on a fleet day 1 installed fine.
      #
      # Under data/, which the overlay never deletes and every host has. It carries the tag
      # as well, so a restart asks for the images that are actually there.
      #
      # The marker only. The .env line that goes with it is written at START time, not here:
      # both the KEEPENV restore and the env push land AFTER this step in the same phase, and
      # either one puts a file back without it — and the .env line is the half the worker
      # container actually reads.
      remote "$h" "set -eu
        mkdir -p '${DEPLOY_REMOTE_DIR}/data'
        printf 'tag=%s\n' '${bundle_tag}' > '${DEPLOY_REMOTE_DIR}/data/.bundle-images'" >/dev/null
    fi

    if truthy "$DEPLOY_KEEPENV" && [[ -f "$env_backup" ]]; then
      step "restore .env to ${h}"
      scp_to "$env_backup" "$h" "${DEPLOY_REMOTE_DIR}/.env"
    fi
    if [[ -z "${BUNDLE:-}" ]]; then
      remote "$h" "if [ -f '${DEPLOY_REMOTE_DIR}/data/.bundle-images' ]; then
        rm -f '${DEPLOY_REMOTE_DIR}/data/.bundle-images'
        sed -i.bak '/^LOGSTOTAL_BUNDLED_IMAGES=/d; /^LOGSTOTAL_IMAGE_TAG=/d' '${DEPLOY_REMOTE_DIR}/.env'
        rm -f '${DEPLOY_REMOTE_DIR}/.env.bak'
      fi" >/dev/null
    fi
  done

  if ! truthy "$DEPLOY_START"; then
    info "Phases 4-5/5 skipped: DEPLOY_START=false — stacks left stopped."
    info "Start when ready: ./logstotal deploy:start   (control plane first, then workers)"
    info "Deploy complete (not started).$(dry_suffix)"
    return 0
  fi

  # ── Phase 4/5 — start the control plane and gate on its health ──
  header "Phase 4/5: start control plane + health gate"
  if targeted "${HOSTS[0]}"; then
    remote_start "${HOSTS[0]}" 0
  else
    # Not restarting it is the entire point of DEPLOY_ONLY. Its health is still the
    # gate: a worker started against a failing control plane is the ordering this
    # phase exists to prevent, and that is true however the worker got here.
    info "${HOSTS[0]} (control-plane): not in DEPLOY_ONLY — checking its health without restarting it"
  fi
  if ! wait_for_health "${HOSTS[0]}"; then
    die "Control plane ${HOSTS[0]} failed its health check — workers were NOT started. Inspect: ./logstotal deploy:logs — previous release is snapshotted; roll back with: ./logstotal upgrade:rollback"
  fi

  fleet_write_result "${HOSTS[0]}" ok

  # ── Phase 5/5 — start workers and verify each ──
  if ((${#HOSTS[@]} > 1)); then
    header "Phase 5/5: start workers"
    local worker_failed="" worker_start_failed=""
    for i in "${!HOSTS[@]}"; do
      [[ "$i" -eq 0 ]] && continue
      targeted "${HOSTS[$i]}" || continue
      if ! remote_start "${HOSTS[$i]}" "$i"; then
        # A MEASURED failure, unlike the poll below: `docker compose up` ran on the host and
        # returned non-zero. Unguarded, `set -e` would kill the entire run right here —
        # before this host's result is recorded, before the workers after it are attempted,
        # and with go-task's bare `exit status 201` as the only explanation.
        warn "${HOSTS[$i]}: could not start the worker stack"
        worker_start_failed="${worker_start_failed} ${HOSTS[$i]}"
        fleet_write_result "${HOSTS[$i]}" failed
        continue
      fi
      if verify_worker_running "${HOSTS[$i]}"; then
        if truthy "$DEPLOY_DRY_RUN"; then
          info "${HOSTS[$i]}: worker stack not verified (DRY RUN — nothing was contacted)"
        else
          info "${HOSTS[$i]}: worker stack running"
        fi
        fleet_write_result "${HOSTS[$i]}" ok
      else
        warn "${HOSTS[$i]}: worker stack NOT running after start"
        worker_failed="${worker_failed} ${HOSTS[$i]}"
        # `unverified`, not `failed`: the poll gave up, which is a statement about the
        # wait. See the note below where worker_failed is acted on.
        fleet_write_result "${HOSTS[$i]}" unverified
      fi
    done
    # NOT a die, and the distinction is the whole point of the verdict vocabulary.
    #
    # verify_worker_running polls for 30s and then gives up. What it reports is "I did not
    # see running containers in the time I waited" — which on a slow host, a cold image
    # pull or a machine under load is a statement about the wait, not about the worker.
    # The control plane is healthy (phase 4 gated on that), the code is staged, and
    # `docker compose up -d` has already returned successfully. Killing the deploy here
    # would throw away a run that has done everything asked of it.
    #
    # It is still said loudly, named per host, and repeated in the closing line, because an
    # unverified worker that nobody looks at is the failure mode this leniency could
    # otherwise create. DEPLOY_STRICT=true restores the hard stop for CI.
    if [[ -n "$worker_failed" ]]; then
      if truthy "${DEPLOY_STRICT:-false}"; then
        die "Worker start not confirmed on:${worker_failed} (DEPLOY_STRICT=true) — the control plane is healthy; inspect with: ./logstotal deploy:logs"
      fi
      warn "worker stack NOT confirmed running on:${worker_failed}"
      warn "The control plane is healthy and the code is staged there. Check with:"
      warn "  ./logstotal deploy:status"
      warn "  ./logstotal deploy:logs"
      UNVERIFIED_WORKERS="$worker_failed"
    fi
    if [[ -n "$worker_start_failed" ]]; then
      die "Worker stack could not be started on:${worker_start_failed}
Every other host was still attempted and its result recorded — read them with: ./logstotal fleet
Inspect the failure with: ./logstotal deploy:logs"
    fi
  else
    info "Phase 5/5: no worker hosts."
  fi

  if [[ -n "${UNVERIFIED_WORKERS:-}" ]]; then
    info "Deploy complete —${UNVERIFIED_WORKERS} not confirmed running.$(dry_suffix)"
  else
    info "Deploy complete.$(dry_suffix)"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

print_banner

case "$DEPLOY_ACTION" in
  deploy)    do_deploy ;;
  status)    do_status ;;
  logs)      do_logs ;;
  stop-only) do_stop_only ;;
  start-only) do_start_only ;;
  exec)      do_exec ;;
  shell)     do_shell ;;
  rollback)  do_rollback ;;
  remove)    do_remove ;;
  *) die "Unknown DEPLOY_ACTION=$DEPLOY_ACTION (use: deploy | status | logs | stop-only | start-only | exec | shell | rollback | remove)" ;;
esac
