#!/usr/bin/env bash
# Multi-server deploy preflight for LogsTotal (developer / ops).
#
# Remote readiness check — run before a deploy. For each host in
# DEPLOY_HOSTS it verifies SSH connectivity, required tools (docker, compose
# plugin, task, 7z), the target directory + .env, and disk/memory headroom.
#
# Usage:
#   bash scripts/deploy-preflight.sh
#
# Configuration (env vars from the caller always override deploy.env values):
#   DEPLOY_HOSTS      Comma-separated host list; entries are `host` (SSH as root),
#                     `user@host`, or `local` (this machine, no SSH). Required.
#   SSH_IDENTITY      Path to SSH private key (optional).
#   DEPLOY_REMOTE_DIR Target dir on each server (default /opt/logstotal).
#   DEPLOY_PACKAGE    Read for the PLAN's comparison target only, never deployed from
#                     here: a plan has to report against the archive a deploy would
#                     actually push, not against whatever tree it happens to run in.
#   DEPLOY_ENV_FILE   Path to defaults file (default: deploy.env in cwd).
#   DEPLOY_DRY_RUN    truthy: trace every ssh command to STDERR instead of
#                     connecting (used by tests to pin behaviour without SSH).
#   DEPLOY_PREFLIGHT_STAGE  pre | post | all (default all).
#                     `pre` is the gate that runs BEFORE bootstrap: it checks the things
#                     bootstrap cannot fix (can we reach it, will our commands parse,
#                     can we elevate, is the clock sane) and reports missing tools as
#                     INFO, since installing them is bootstrap's job. `post` is the
#                     fatal check. Run only at step 6 of 8 — after packages are
#                     installed, the VPN built and .env pushed — it would not be a
#                     gate, which is why the split exists.
#   DEPLOY_PLAN_ONLY  truthy: report only, change nothing, always exit 0. Adds a verdict
#                     per host (FRESH INSTALL / UPDATE / ALREADY CURRENT / PARTIAL /
#                     BLOCKED), the fleet's own settings and a fleet summary. This is
#                     `task deploy:plan`.
#   DEPLOY_PLAN_FORMAT  text (default) | json, for a plan run only. `json` prints one
#                     document on stdout — settings, findings, per-host verdicts and the
#                     counts — and moves the human check stream to stderr so a caller can
#                     pipe it. Ignored without DEPLOY_PLAN_ONLY: there would be nothing
#                     to serialise, and a preflight that fell silent would look broken.
#   DEPLOY_VPN        when `wireconf`, the firewall and WireGuard checks are included
#                     and a hub with no UDP allow rule for DEPLOY_VPN_PORT is an error.
#   DEPLOY_VPN_PORT   WireGuard UDP port to expect on the hub (default 51820).
#   DEPLOY_DOMAIN     Setting it means Caddy is in front, so the plan expects 80/443
#                     rather than 8000.
#   DEPLOY_PROXY_TLS  acme | internal | custom | off — decides whether a certificate
#                     authority has to reach port 80.
#   DEPLOY_OPEN_WG_PORT  deploy-bootstrap.sh's knob for adding the hub's ufw rule, and
#                     ON by default under wireconf. Read here so a missing rule on a fresh
#                     fleet is reported as "bootstrap will add it" rather than as a blocker
#                     — the next phase fixes it.
#
# `set -eu`, no pipefail — the numeric-capture pipelines below must survive a
# non-zero upstream status. Assumes the repo root is the current working
# directory.

set -eu

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# _ssh HOST CMD — run CMD on HOST, or (DEPLOY_DRY_RUN) trace it to STDERR.
#
# The trace goes to STDERR and nothing reaches stdout, so the numeric captures
# below see an empty string, which host_number turns into `?` — never OK. The
# normal branch suppresses the ssh client's own stderr per call, so
# operator-visible output carries no client noise.
#
# Not lib/common.sh::host_exec, deliberately: that one traces to STDOUT, which is
# exactly what the numeric captures above cannot tolerate. Only the local-vs-remote
# branch is shared in spirit.
# shellcheck disable=SC2029  # remote command is intentionally assembled client-side (as in deploy-multiserver.sh::remote)
_ssh() {
  local host=$1 cmd=$2
  if truthy "${DEPLOY_DRY_RUN:-}"; then
    if is_local_host "$host"; then
      printf 'DRY-RUN local: %s\n' "$cmd" >&2
    else
      printf 'DRY-RUN ssh %s: %s\n' "$(to_target "$host")" "$cmd" >&2
    fi
    return 0
  fi
  if is_local_host "$host"; then
    bash -c "$cmd" 2>/dev/null
  else
    # bash -c, for the reason common.sh::shquote documents: ssh hands the command to the
    # remote LOGIN shell, and a fleet whose root shell is fish rejects ordinary POSIX
    # constructs outright. The local branch above forces bash too.
    ssh "${SSH_OPTS[@]}" "$(to_target "$host")" bash -c "$(shquote "$cmd")" 2>/dev/null
  fi
}

# The tallies live in lib/verdict.sh (V_FAIL, V_WARN,
# V_UNKNOWN, V_PASS) so the preflight and the smoke test cannot count differently.

# ── Telling "the host answered no" from "the host never answered" ────────────
#
# _ssh returns non-zero for two unrelated reasons: the remote command genuinely failed, or
# the SSH session did. ssh reserves exit 255 for its own errors, which is what makes the
# distinction reliable.
#
# Conflating them would turn a dropped session into "docker not found" with an apt-get
# command attached, "a POSIX command did not survive this host's login shell", and — worst
# — "VERDICT: FRESH INSTALL" for a fully deployed control plane, which invites a
# first-time deploy over a live installation, with the real fault named nowhere.
#
# A `local` host runs through `bash -c`, where 255 is an ordinary command status rather
# than a session error. That is acceptable: a local session cannot drop, so the only way
# to see 255 there is a command that genuinely returned it.
SSH_RC=0
_ssh_rc() {
  SSH_RC=0
  _ssh "$1" "$2" || SSH_RC=$?
}

# session_lost — true (and reports, once per host) when the last _ssh_rc lost the session.
# Callers use it to stop making claims about a host they can no longer reach.
HOST_SESSION_LOST=""
session_lost() {
  [ "$SSH_RC" -eq 255 ] || return 1
  if [ -z "$HOST_SESSION_LOST" ]; then
    HOST_SESSION_LOST=yes
    note_fail "lost the SSH session to ${HOST} partway through its checks." \
      "Everything after this point on this host was NOT measured — the findings below" \
      "are absent measurements, not faults." \
      "The first checks passed, so this is intermittent: check the network and the key."
  fi
  return 0
}

# deploy.env provides defaults for values not already set — same precedence as
# scripts/deploy-multiserver.sh (caller env wins).
DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"
# Adopt a remote fleet record when FLEET_FROM names a control plane. ABOVE the first
# deploy.env read, always: _fleet_options memoises the record's options on first read, so a
# later adoption is silently half-applied — hosts from the remote record, settings from this
# machine. See lib/fleet_record.sh::fleet_adopt.
fleet_adopt

# Positional hosts, the same rung and the same validator every other deploy verb uses.
# `task deploy:plan -- cp w1 w2` is the natural thing to type before `task deploy -- cp w1
# w2`. Without positionals the plan would silently report on whatever deploy.env or the
# fleet record names — and a report about a different fleet still looks like a report.
#
# A CLI variable is no workaround: go-task never exports one to the shell, so
# `task deploy:plan DEPLOY_HOSTS=cp,w1` is ignored outright.
_from_args=$(hosts_from_args "$@")
if [ -n "$_from_args" ]; then
  DEPLOY_HOSTS="$_from_args"
  deploy_env_note_source DEPLOY_HOSTS "the command line"
fi

# The settings the plan REPORTS, as opposed to the ones it acts on, resolved through the
# shared loader so each one's provenance is recorded as it is found.
#
# It has to run before the `${X:-$(deploy_env_default X)}` cascade below, not after: that
# form resolves a value without telling anyone where it came from, so a later load sees
# the key already set and would report deploy.env's own values as having come from the
# caller's environment. Ordering is the whole mechanism. The cascade below is then a
# no-op for anything this already answered, and is left in place because it is what the
# checks themselves read.
# shellcheck disable=SC2086  # a space-separated key list, deliberately split
deploy_env_load $_CONFIG_REVIEW_KEYS

DEPLOY_HOSTS="${DEPLOY_HOSTS:-$(deploy_env_default DEPLOY_HOSTS)}"
SSH_IDENTITY="${SSH_IDENTITY:-$(deploy_env_default SSH_IDENTITY)}"
DEPLOY_REMOTE_DIR="${DEPLOY_REMOTE_DIR:-$(deploy_env_default DEPLOY_REMOTE_DIR)}"
# Read for the plan's comparison target only, so `deploy:plan DEPLOY_PACKAGE=…` reports
# against the archive a deploy would actually push rather than against this tree.
DEPLOY_PACKAGE="${DEPLOY_PACKAGE:-$(deploy_env_default DEPLOY_PACKAGE)}"

# ── Remote host checks ──
#
# LAST: this host's own fleet record, so `deploy:plan` runs bare on a control plane the
# same way every other deploy action does. See lib/fleet_record.sh.
if [ -z "${DEPLOY_HOSTS:-}" ]; then
  DEPLOY_HOSTS=$(fleet_hosts "${DEPLOY_REMOTE_DIR:-}")
fi
if [ -z "${DEPLOY_HOSTS:-}" ]; then
  printf '%sFAIL:%s %s\n' "$C_RED" "$C_OFF" "DEPLOY_HOSTS is required (comma-separated host list)."
  exit 1
fi

REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/logstotal}"
build_ssh_opts

DEPLOY_PREFLIGHT_STAGE="${DEPLOY_PREFLIGHT_STAGE:-$(deploy_env_default DEPLOY_PREFLIGHT_STAGE)}"
DEPLOY_PREFLIGHT_STAGE="${DEPLOY_PREFLIGHT_STAGE:-all}"
DEPLOY_PLAN_ONLY="${DEPLOY_PLAN_ONLY:-$(deploy_env_default DEPLOY_PLAN_ONLY)}"
DEPLOY_VPN="${DEPLOY_VPN:-$(deploy_env_default DEPLOY_VPN)}"
# Resolved through vpn_mode, never left "": an empty value would silently skip the firewall
# and WireGuard checks below — on exactly the fleets that did not ask for a tunnel and
# need the firewall report most.
vpn_mode
DEPLOY_VPN="$VPN_MODE"
DEPLOY_VPN_PORT="${DEPLOY_VPN_PORT:-$(deploy_env_default DEPLOY_VPN_PORT)}"
DEPLOY_VPN_PORT="${DEPLOY_VPN_PORT:-51820}"
# Read only to build the network plan below — which ports the deploy will need depends on
# whether Caddy is in front, and on how it terminates TLS.
DEPLOY_DOMAIN="${DEPLOY_DOMAIN:-$(deploy_env_default DEPLOY_DOMAIN)}"
DEPLOY_PROXY_TLS="${DEPLOY_PROXY_TLS:-$(deploy_env_default DEPLOY_PROXY_TLS)}"
DEPLOY_OPEN_WG_PORT="${DEPLOY_OPEN_WG_PORT:-$(deploy_env_default DEPLOY_OPEN_WG_PORT)}"

case "$DEPLOY_PREFLIGHT_STAGE" in
  pre | post | all) ;;
  *) printf '%sFAIL:%s %s\n' "$C_RED" "$C_OFF" "DEPLOY_PREFLIGHT_STAGE must be pre, post or all (got '${DEPLOY_PREFLIGHT_STAGE}')."; exit 1 ;;
esac

# text | json, for `task deploy:plan` only. The text form is unaffected by the
# machine-readable one.
PLAN_FORMAT="${DEPLOY_PLAN_FORMAT:-$(deploy_env_default DEPLOY_PLAN_FORMAT)}"
PLAN_FORMAT="${PLAN_FORMAT:-text}"
case "$PLAN_FORMAT" in
  text | json) ;;
  *) printf '%sFAIL:%s %s\n' "$C_RED" "$C_OFF" "DEPLOY_PLAN_FORMAT must be text or json (got '${PLAN_FORMAT}')."; exit 1 ;;
esac
#: One `--plan-host` argument per host, accumulated as the loop runs and serialised by
#: deploy_config_review.py at the end. The quoting lives in Python on purpose: a verdict
#: carries a free-text reason, and hand-rolling JSON in shell is how a stray quote in a
#: host name turns a machine-readable report into a parse error.
PLAN_RECORDS=()

# plan_record VERDICT [DETAIL] — the machine-readable twin of the VERDICT line beside it.
#
# A separate call rather than a helper that prints AND records, because the printed form
# is load-bearing: seven literals from these lines are asserted verbatim by
# tests/test_deploy_check_scripts.py and cross-checked against docs/install/fleet.md by
# tests/test_docs_in_sync.py. Routing them through a formatter is how they drift.
#
# Guarded on the format, so a text run does no work for output it will not produce.
plan_record() {
  [ "$PLAN_FORMAT" = "json" ] || return 0
  PLAN_RECORDS+=(--plan-host "$(printf '%s\t%s\t%s\t%s\t%s\t%s' "$HOST" "$ROLE" "$1" "${REMOTE_VER:-}" "${RUNNING:-0}" "${2:-}")")
}

# In plan mode nothing is fatal — the verdict IS the output, and an operator asking
# "what would happen" must get an answer for every host rather than an exit code from
# the first bad one.
PLAN=false
truthy "${DEPLOY_PLAN_ONLY:-false}" && PLAN=true

# JSON is a plan-only form, so a `task deploy:preflight` that inherits the variable keeps
# printing its checks rather than falling silent with nothing to emit at the end.
[ "$PLAN" = true ] || PLAN_FORMAT=text

# In JSON mode stdout carries ONE document and nothing else, so the human check stream
# moves to stderr and the document is written to a saved copy of the real stdout.
#
# Suppressing the checks instead would be worse: they are how an
# operator sees which host is being contacted and why one is slow, and a machine caller
# gets a clean `| jq` either way. This is the DRY-RUN trace's arrangement — that one goes
# to stderr for the same reason, and a test already pins it.
# Left to right in one exec: fd 3 takes a copy of the real stdout, then stdout becomes
# stderr. Only in JSON mode — an unconditional `exec 3>&1` would hand every ssh and
# python child an extra inherited descriptor for a form they will never write to.
if [ "$PLAN_FORMAT" = "json" ]; then
  exec 3>&1 1>&2
fi

# The verdicts come from lib/verdict.sh: v_pass, v_fail, v_warn, v_unknown and
# v_unknown_blocking, with V_PASS/V_FAIL/V_WARN/V_UNKNOWN as the tallies. What is local
# to a preflight is the per-host label the plan-mode footer prints, which is the first
# thing that stopped this host — v_fail and v_unknown_blocking both record it in V_REASON,
# and HOST_BLOCKED tracks it across the loop.
HOST_BLOCKED=""

# note_fail REASON DETAIL... — measured, and bad. The host is blocked.
note_fail() {
  v_fail "$@"
  [ -n "$HOST_BLOCKED" ] || HOST_BLOCKED="$V_REASON"
}

# note_warn REASON DETAIL... — measured, worth saying, not a fault.
note_warn() { v_warn "$@"; }

# note_unknown REASON DETAIL... — NOT measured. Never OK, and never a failure.
#
# `host_number` returns `?` for an unreachable host, a missing command, an empty reply or a
# non-numeric one. Treating that as note_fail would fail a whole deploy on a box with no
# /proc/meminfo, or whose df did not answer, having found nothing wrong. The `?` still means
# an unmeasured host never prints OK; it just is not fatal.
note_unknown() {
  v_unknown "$@"
  [ -n "$HOST_UNKNOWN" ] || HOST_UNKNOWN="$1"
}
HOST_UNKNOWN=""

# network_plan_for_host HOST — the `proto port scope why` lines this host must accept.
# Empty (and silent) when the plan cannot be built, so a preflight never fails over its
# own reporting.
network_plan_for_host() {
  local module
  module="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/deploy_network_plan.py"
  [ -f "$module" ] || return 0
  run_py "$module" \
    --hosts "$DEPLOY_HOSTS" \
    --vpn "${VPN_MODE:-${DEPLOY_VPN:-none}}" \
    --vpn-port "${DEPLOY_VPN_PORT:-51820}" \
    --domain "${DEPLOY_DOMAIN:-}" \
    --proxy-tls "${DEPLOY_PROXY_TLS:-acme}" \
    --format host --for-host "$1" 2>/dev/null || true
}

# What a deploy from HERE would actually install, and where that answer came from.
#
# `read_version_file` on the current directory alone — "what this checkout would deploy" —
# is right on a workstation and WRONG on a control plane, where upgrades run: there the
# current directory IS the install, its VERSION is the version already deployed, and every
# host would read ALREADY CURRENT forever.
#
# So resolve what a deploy would really push, in the order deploy-multiserver.sh's
# resolve_package does — an explicit package, else the newest archive here — and fall back
# to the tree only when there is none. And SAY which, because "ALREADY CURRENT" is only
# meaningful next to what it is current WITH.
LOCAL_VERSION=""
LOCAL_VERSION_SOURCE=""
LOCAL_UNRELEASED=false
if [ -n "${DEPLOY_PACKAGE:-}" ]; then
  LOCAL_VERSION=$(package_version "$DEPLOY_PACKAGE")
  LOCAL_VERSION_SOURCE="DEPLOY_PACKAGE=$(basename "$DEPLOY_PACKAGE")"
fi
if [ -z "$LOCAL_VERSION" ]; then
  # shellcheck disable=SC2012  # generated names; newest-first by mtime is the intent
  _newest_pkg=$(ls -t logstotal-*.7z 2>/dev/null | head -1 || true)
  if [ -n "$_newest_pkg" ]; then
    LOCAL_VERSION=$(package_version "$_newest_pkg")
    LOCAL_VERSION_SOURCE="$_newest_pkg"
  fi
fi
if [ -z "$LOCAL_VERSION" ] && [ -f VERSION ]; then
  LOCAL_VERSION=$(read_version_file)
  LOCAL_VERSION_SOURCE="this tree"
  # The mirror case. When the tree being compared is itself one of the
  # hosts' installs, "ALREADY CURRENT" is a tautology, not news.
  case "$(pwd)" in
    "${REMOTE_DIR}" | "${REMOTE_DIR}"/*) LOCAL_VERSION_SOURCE="this tree — which IS the install" ;;
  esac
fi
# The version string is a sufficient code identity ONLY because upgrades are restricted to
# published releases: one tag, one commit, one CI-built archive, one version. An
# ALLOW_UNRELEASED build breaks that — two different commits both report the same number,
# so "ALREADY CURRENT" would be a lie. Say so rather than reporting a verdict that cannot
# be true. A tree with no .git came from a release archive and needs no note.
if [ -d .git ] && command -v git >/dev/null 2>&1; then
  git describe --tags --exact-match >/dev/null 2>&1 || LOCAL_UNRELEASED=true
fi

PLAN_FRESH=0
PLAN_UPDATE=0
PLAN_CURRENT=0
PLAN_PARTIAL=0
PLAN_BLOCKED=0

# What this fleet is, before what state its hosts are in.
#
# The question a plan is asked most often is *which site is this about*, and the network
# plan reads DEPLOY_DOMAIN only as a boolean — so the settings block names it.
#
# Plan only: `task deploy:preflight` is a host readiness check, and the settings block
# would push its first result off a short terminal.
if [ "$PLAN" = true ] && [ "$PLAN_FORMAT" = "text" ]; then
  config_review text --settings-only
  echo ""
fi

HOST_COUNT=0
IDX=0
for HOST in $(printf "%s" "${DEPLOY_HOSTS}" | tr ',' '\n'); do
  HOST=$(echo "$HOST" | xargs)
  [ -z "$HOST" ] && continue
  HOST_COUNT=$((HOST_COUNT + 1))
  ROLE="worker"
  [ "$IDX" -eq 0 ] && ROLE="control-plane"
  # Whole line bold-cyan on a terminal, so it reads as a section break the eye can find
  # in a wall of check output. Plain off a terminal (C_* are empty), so the pinned literal
  # `=== HOST (role) ===` is byte-identical — tests pin it, several by index.
  printf '%s=== %s (%s) ===%s\n' "${C_BOLD}${C_CYAN}" "$HOST" "$ROLE" "$C_OFF"
  HOST_BLOCKED=""
  HOST_UNKNOWN=""
  v_reset

  # Reachability. The `local` sentinel is this machine, so there is no SSH to check —
  # but the command still has to run, since everything below assumes it can.
  if ! _ssh "$HOST" "true"; then
    if is_local_host "$HOST"; then
      printf '  %sFAIL:%s cannot run commands locally.\n' "$C_RED" "$C_OFF"
    else
      printf '  %sFAIL:%s SSH connection failed.\n' "$C_RED" "$C_OFF"
      echo "        Fix: ensure root SSH key access (BatchMode) is configured."
    fi
    V_FAIL=$((V_FAIL + 1))
    IDX=$((IDX + 1))
    echo ""
    continue
  fi
  if is_local_host "$HOST"; then
    v_pass "local (this machine, no SSH)"
  else
    v_pass "SSH"
  fi

  # ── Checks bootstrap cannot fix, so they belong before it ──────────────────
  if [ "$DEPLOY_PREFLIGHT_STAGE" != "post" ] && ! is_local_host "$HOST"; then
    # ssh -G asks the local client what it WOULD do for this host. No connection, and it
    # is the only way to see an ~/.ssh/config the deploy never reads. RemoteCommand is
    # fatal because our own calls pass RemoteCommand=none but wireconf's do not, and
    # a VPN step failing with "Cannot execute command-line and remote command" names
    # neither the file nor the line responsible.
    SSH_G=$(ssh -G "$(to_target "$HOST")" 2>/dev/null || true)
    RC_LINE=$(printf '%s\n' "$SSH_G" | awk '$1=="remotecommand"{ $1=""; sub(/^ /,""); print; exit }')
    if [ -n "$RC_LINE" ] && [ "$RC_LINE" != "none" ]; then
      # shellcheck disable=SC2088  # "~/.ssh/config" is prose naming a file, not a path to expand
      note_fail "~/.ssh/config sets RemoteCommand for ${HOST} (${RC_LINE})." \
        "Our own ssh calls override it, but wireconf's do not — DEPLOY_VPN would fail here." \
        "Fix: remove RemoteCommand from that Host block, or give the deploy its own alias."
    fi
    if printf '%s\n' "$SSH_G" | grep -qx 'requesttty yes\|requesttty force'; then
      printf '  %sINFO:%s ~/.ssh/config requests a TTY for %s (neutralised by RequestTTY=no).\n' "$C_CYAN" "$C_OFF" "$HOST"
    fi
  fi

  # Does an ordinary POSIX command survive this host's login shell? This is the on-fleet
  # detector for the fish problem: `rc=$?` is rejected outright by fish, and the .env install
  # would then report it as a permission error. It also proves the
  # bash -c wrapper is in place end to end.
  SHELL_RC=0
  # shellcheck disable=SC2016  # $? and $rc must expand on the REMOTE host, not here
  SHELL_PROBE=$(_ssh "$HOST" 'rc=$?; printf "shell-ok-%s\n" "$rc"') || SHELL_RC=$?
  SSH_RC="$SHELL_RC"
  if truthy "${DEPLOY_DRY_RUN:-}"; then
    # The disk/memory idiom below. A dry run connects to nothing, so the probe cannot have
    # been answered — and reporting FAIL for it would contradict this run's own closing
    # line, "measured nothing, connected to nothing".
    printf '  %sINFO:%s login shell not measured (dry run).\n' "$C_CYAN" "$C_OFF"
  elif session_lost; then
    : # the session went away; the login shell was never asked anything
  elif [ "$(printf '%s' "$SHELL_PROBE" | tr -d '[:space:]')" != "shell-ok-0" ]; then
    # shellcheck disable=SC2016  # expands remotely
    LOGIN_SHELL=$(_ssh "$HOST" 'getent passwd "$(id -un)" | cut -d: -f7' || true)
    note_fail "a POSIX command did not survive ${HOST}'s login shell (${LOGIN_SHELL:-unknown})." \
      "Got: ${SHELL_PROBE:-<nothing>}, expected shell-ok-0." \
      "Every remote command should be wrapped in bash -c — see lib/common.sh::shquote."
  elif [ "$SHELL_PROBE" != "${SHELL_PROBE%$'\r'}" ]; then
    # CRLF surviving the strip means a PTY was allocated despite RequestTTY=no, which is
    # what makes ID=ubuntu stop matching ubuntu.
    note_fail "${HOST} returned CRLF — a PTY is being allocated despite RequestTTY=no."
  fi

  # Can we write where the deploy writes? The failure otherwise surfaces three steps
  # later as env-push's "Usually this is write permission", which is a guess.
  # shellcheck disable=SC2016  # expands remotely
  _ssh_rc "$HOST" '[ "$(id -u)" = 0 ] || sudo -n true' >/dev/null
  if session_lost; then
    : # a dropped session is not a privilege problem, and saying so sends the operator
      # to edit sudoers on a host that never answered
  elif [ "$SSH_RC" -ne 0 ]; then
    note_fail "no root and no passwordless sudo on ${HOST}." \
      "Fix: deploy as root@${HOST#*@}, or give the SSH user NOPASSWD sudo."
  fi

  # Clock skew breaks ACME issuance, WireGuard's handshake window and JWT validation,
  # and every one of those failures points somewhere else.
  REMOTE_EPOCH=$(host_number "$HOST" "date +%s")
  if [ "$REMOTE_EPOCH" != "?" ]; then
    SKEW=$((REMOTE_EPOCH - $(date +%s)))
    [ "$SKEW" -lt 0 ] && SKEW=$((-SKEW))
    if [ "$SKEW" -gt 120 ]; then
      note_fail "clock on ${HOST} is ${SKEW}s away from this machine." \
        "Fix: enable NTP (timedatectl set-ntp true). This breaks TLS issuance and WireGuard."
    fi
  fi

  # Once the session is gone, every remaining check reports an absent measurement as a
  # fault: "compose plugin not found", "docker daemon not reachable", a disk it could not
  # read. One honest line about the session beats a dozen invented ones about the host.
  if [ -n "$HOST_SESSION_LOST" ]; then
    printf '  %sSKIP%s remaining checks for %s — no session to ask.\n' "$C_CYAN" "$C_OFF" "$HOST"
    if [ "$PLAN" = true ]; then
      printf '  %sVERDICT: BLOCKED%s — %s\n' "${C_BOLD}${C_RED}" "$C_OFF" "$HOST_BLOCKED"
      plan_record BLOCKED "$HOST_BLOCKED"
      PLAN_BLOCKED=$((PLAN_BLOCKED + 1))
    fi
    IDX=$((IDX + 1))
    echo ""
    continue
  fi

  # Required tools. rsync is checked here rather than discovered during a rollback:
  # it is what takes the release snapshot and what restores it.
  #
  # In the `pre` stage a missing tool is INFO, not an error: bootstrap installs all three,
  # and failing the gate for something the very next step fixes would make the gate
  # useless on a fresh box — which is the only place it matters most. No go-task: a host
  # runs each release through its own ./logstotal, on the tarball the archive carries.
  for TOOL in docker 7z rsync; do
    _ssh_rc "$HOST" "command -v ${TOOL}" >/dev/null
    if [ "$SSH_RC" -eq 0 ]; then
      v_pass "${TOOL}"
    elif session_lost; then
      # Four "not found" lines with four apt-get commands, for a host that stopped
      # answering, is four wrong instructions and no mention of the real fault.
      break
    elif [ "$DEPLOY_PREFLIGHT_STAGE" = "pre" ]; then
      printf '  %sINFO:%s %s not installed yet (./logstotal deploy:bootstrap installs it).\n' "$C_CYAN" "$C_OFF" "$TOOL"
    else
      printf '  %sFAIL:%s %s not found.\n' "$C_RED" "$C_OFF" "$TOOL"
      case "$TOOL" in
        docker) echo "        Fix: install Docker — https://docs.docker.com/engine/install/" ;;
        7z)     echo "        Fix: install p7zip — apt install p7zip-full" ;;
        rsync)  echo "        Fix: install rsync — apt install rsync (needed for release snapshots and rollback)" ;;
      esac
      V_FAIL=$((V_FAIL + 1))
      [ -n "$HOST_BLOCKED" ] || HOST_BLOCKED="${TOOL} missing"
    fi
  done

  # Once the session is gone, every remaining check reports an absent measurement as a
  # fault: "compose plugin not found", "docker daemon not reachable", a disk it could not
  # read. One honest line about the session beats a dozen invented ones about the host.
  if [ -n "$HOST_SESSION_LOST" ]; then
    printf '  %sSKIP%s remaining checks for %s — no session to ask.\n' "$C_CYAN" "$C_OFF" "$HOST"
    if [ "$PLAN" = true ]; then
      printf '  %sVERDICT: BLOCKED%s — %s\n' "${C_BOLD}${C_RED}" "$C_OFF" "$HOST_BLOCKED"
      plan_record BLOCKED "$HOST_BLOCKED"
      PLAN_BLOCKED=$((PLAN_BLOCKED + 1))
    fi
    IDX=$((IDX + 1))
    echo ""
    continue
  fi

  # Docker Compose plugin
  if _ssh "$HOST" "docker compose version" >/dev/null; then
    v_pass "docker compose"
  elif [ "$DEPLOY_PREFLIGHT_STAGE" = "pre" ]; then
    printf '  %sINFO:%s docker compose not installed yet (./logstotal deploy:bootstrap installs it).\n' "$C_CYAN" "$C_OFF"
  else
    note_fail "docker compose plugin not found." \
      "Fix: install compose plugin — https://docs.docker.com/compose/install/"
  fi

  # Target directory
  if _ssh "$HOST" "test -d ${REMOTE_DIR}"; then
    v_pass "${REMOTE_DIR} exists"
    # .env presence
    if _ssh "$HOST" "test -f ${REMOTE_DIR}/.env"; then
      v_pass ".env present"
    else
      printf '  %sWARN:%s no .env at %s/ — first deploy or DEPLOY_KEEPENV needed.\n' "$C_YELLOW" "$C_OFF" "$REMOTE_DIR"
      V_WARN=$((V_WARN + 1))
    fi
  else
    printf '  %sINFO:%s %s does not exist yet (will be created on deploy).\n' "$C_CYAN" "$C_OFF" "$REMOTE_DIR"
  fi

  # Disk space (warn under 5 GiB — Docker images + backups eat space)
  #
  # host_number returns `?` when it could not measure. That distinction is the whole
  # point: a `[ -n "$FREE_KB" ]` guard would skip the comparison on an empty capture and
  # fall straight to `OK   disk space` about a host it never successfully asked.
  FREE_KB=$(host_number "$HOST" "df -k ${REMOTE_DIR%/*} 2>/dev/null | tail -1 | awk '{print \$4}'")
  if [ "$FREE_KB" = "?" ]; then
    if truthy "${DEPLOY_DRY_RUN:-}"; then
      printf '  %sINFO:%s disk space not measured (dry run).\n' "$C_CYAN" "$C_OFF"
    else
      note_unknown "could not measure free disk on ${HOST}:${REMOTE_DIR%/*}." \
        "A deploy is not blocked by this — but nothing here checked that there is room for it."
    fi
  elif [ "$FREE_KB" -lt 5242880 ]; then
    printf '  %sWARN:%s only %s MB free on %s (recommend ≥ 5 GiB).\n' "$C_YELLOW" "$C_OFF" "$((FREE_KB / 1024))" "${REMOTE_DIR%/*}"
    V_WARN=$((V_WARN + 1))
  else
    v_pass "disk space"
  fi

  # Free memory (warn under 1 GiB — workers + Postgres + Redis baseline)
  # Same `?` treatment as disk. Printing nothing on an empty capture would be worse than a
  # wrong OK: the check would silently vanish from the report.
  FREE_MEM_KB=$(host_number "$HOST" "awk '/MemAvailable:/ {print \$2}' /proc/meminfo")
  if [ "$FREE_MEM_KB" = "?" ]; then
    if truthy "${DEPLOY_DRY_RUN:-}"; then
      printf '  %sINFO:%s memory not measured (dry run).\n' "$C_CYAN" "$C_OFF"
    else
      note_unknown "could not measure available memory on ${HOST}." \
        "/proc/meminfo is Linux-only; a host without it is unmeasured, not unhealthy."
    fi
  elif [ "$FREE_MEM_KB" -lt 1048576 ]; then
    printf '  %sWARN:%s only %s MB available memory.\n' "$C_YELLOW" "$C_OFF" "$((FREE_MEM_KB / 1024))"
    V_WARN=$((V_WARN + 1))
  else
    v_pass "memory"
  fi

  # Docker daemon reachable (distinct from `command -v docker`)
  if _ssh "$HOST" "docker info" >/dev/null; then
    v_pass "docker daemon"
  elif [ "$DEPLOY_PREFLIGHT_STAGE" = "pre" ]; then
    printf '  %sINFO:%s docker daemon not up yet (./logstotal deploy:bootstrap starts it).\n' "$C_CYAN" "$C_OFF"
  else
    note_fail "docker daemon not reachable (try: systemctl start docker)."
  fi

  # ── Firewall ───────────────────────────────────────────────────────────────
  #
  # Detection, not mutation. The one rule this fleet needs is opened by
  # deploy-bootstrap.sh on the hub; everything else here reports and moves on, because
  # rewriting someone's firewall from a deploy script is not a trade worth making.
  #
  # It runs whatever DEPLOY_VPN says: without a tunnel the control plane has Redis,
  # PostgreSQL and Garage on a routable interface, and that is
  # precisely the fleet whose firewall matters most. The port list comes from
  # scripts/deploy_network_plan.py, so this checks what the deploy will actually need
  # rather than one hard-coded port.
  #
  # A dry run measures nothing, and `_ssh` returns 0 with empty stdout there — which would
  # make `ip link show wg0` "succeed" and print `wg0 already present` about a host nobody
  # contacted. Never report OK for something you could not measure: the same rule that
  # made host_number return `?`.
  if ! truthy "${DEPLOY_DRY_RUN:-}"; then
    FW_RC=0
    # shellcheck disable=SC2016  # expands remotely
    FW=$(_ssh "$HOST" 'if command -v ufw >/dev/null 2>&1; then ufw status 2>/dev/null | head -1; elif command -v firewall-cmd >/dev/null 2>&1; then printf "firewalld: %s\n" "$(firewall-cmd --state 2>/dev/null)"; else echo "none"; fi') || FW_RC=$?
    # An empty capture is NOT "no firewall". The remote snippet always echoes something, so
    # nothing coming back means the question was never answered — an unreachable host, a
    # refused key, a probe that died. Folding that into `none` would print "nothing here is
    # filtering" as a fact about a machine we could not reach, AND silently skip the whole
    # per-port audit below, including the WireGuard hub check. Never report OK for something
    # you could not measure — this file's own rule, applied to itself.
    case "$FW" in
      *"Status: active"*) FW_KIND=ufw ;;
      *"firewalld: running"*) FW_KIND=firewalld ;;
      none) FW_KIND=none ;;
      "") FW_KIND=unknown ;;
      *) FW_KIND=other ;;
    esac

    [ "$FW_RC" -eq 0 ] || FW_KIND=unknown

    if [ "$FW_KIND" = "unknown" ]; then
      printf '  %sWARN:%s could not determine the firewall here — the probe did not answer.\n' "$C_YELLOW" "$C_OFF"
      echo "        Port reachability was NOT checked on this host. This is not evidence"
      echo "        that nothing is filtering; it means nobody asked."
    elif [ "$FW_KIND" = "none" ]; then
      printf '  %sINFO:%s no firewall manager detected — nothing here is filtering.\n' "$C_CYAN" "$C_OFF"
    elif [ "$FW_KIND" = "other" ]; then
      printf '  %sINFO:%s firewall: %s (not ufw or firewalld — checking rules is up to you).\n' "$C_CYAN" "$C_OFF" "$FW"
    else
      printf '  %sINFO:%s firewall: %s, active.\n' "$C_CYAN" "$C_OFF" "$FW_KIND"
      # What this host has to accept, from the same plan the operator was shown.
      #
      # Read into an array FIRST. Piping the plan into `while read` and then calling _ssh
      # in the loop body lets ssh consume the remaining lines — it reads stdin, and the
      # loop's stdin is the list — so only the first port on each host would be checked,
      # with the run looking completely normal.
      PLAN_LINES=()
      while IFS= read -r _line; do
        [ -n "$_line" ] && PLAN_LINES+=("$_line")
      done < <(network_plan_for_host "$HOST")

      DOCKER_PORTS=0
      for _line in ${PLAN_LINES[@]+"${PLAN_LINES[@]}"}; do
        read -r PROTO PORT SCOPE ENFORCED_BY WHY <<<"$_line"
        [ -n "${PORT:-}" ] || continue
        # A tunnelled port needs no rule on the public interface — that is the whole point
        # of the VPN, and demanding one would teach people to open exactly what the tunnel
        # exists to keep closed.
        [ "$SCOPE" = "tunnel" ] && continue
        # SSH is answering right now, by construction: this check arrived over it.
        [ "$SCOPE" = "admin" ] && continue
        # Docker publishes its ports through nat and FORWARD, never INPUT, so ufw does not
        # see that traffic at all: a host whose ufw allows only 22 and 51820 still answers
        # 200 on http://cp:8000. Reporting those as "no matching allow rule" reads as
        # "your app is unreachable" — which is false — and sends the operator to run a
        # command that changes nothing. Counted and explained once instead.
        if [ "$ENFORCED_BY" != "host" ]; then
          DOCKER_PORTS=$((DOCKER_PORTS + 1))
          continue
        fi

        if [ "$FW_KIND" = "ufw" ]; then
          ALLOWED=$(_ssh "$HOST" "ufw status | grep -cE '^${PORT}(/${PROTO})?[[:space:]]+ALLOW' || true")
        else
          ALLOWED=$(_ssh "$HOST" "firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | grep -cx '${PORT}/${PROTO}' || true")
        fi
        ALLOWED=$(printf '%s' "${ALLOWED:-0}" | tr -dc '0-9')

        if [ "${ALLOWED:-0}" -gt 0 ]; then
          v_pass "${PORT}/${PROTO} allowed — ${WHY}"
        elif [ "$IDX" -eq 0 ] && [ "$PROTO" = "udp" ] && [ "$DEPLOY_VPN" = "wireconf" ]; then
          # The hub's WireGuard port. deploy-bootstrap.sh opens it itself when
          # DEPLOY_OPEN_WG_PORT is on — which is the DEFAULT under wireconf — so on a fresh
          # fleet this is a step that has not run yet, not a blocker. Reporting BLOCKED for
          # something the very next phase fixes is the mirror of claiming OK for something
          # unmeasured: it stops an operator who had nothing to do.
          if truthy "${DEPLOY_OPEN_WG_PORT:-$([ "$DEPLOY_VPN" = "wireconf" ] && echo true || echo false)}"; then
            printf '  %sINFO:%s %s/udp not open yet — deploy:bootstrap adds it on the hub.\n' "$C_CYAN" "$C_OFF" "$PORT"
          else
            # With DEPLOY_OPEN_WG_PORT off, nothing will: no handshake, no tunnel, and the
            # VPN step fails two phases later blaming reachability.
            note_fail "${FW_KIND} is active on the hub and does not allow ${PORT}/udp." \
              "DEPLOY_OPEN_WG_PORT is off, so nothing will open it, and no peer can complete a handshake." \
              "Fix: ssh ${HOST#*@} ufw allow ${PORT}/udp   (or unset DEPLOY_OPEN_WG_PORT)"
          fi
        else
          # A warning, not a failure: a rule scoped to a source address
          # (`ufw allow from 10.0.0.2 to any port 5432`) is correct and does not match the
          # check above, so failing here would block deploys that are configured properly.
          note_warn "${PORT}/${PROTO} has no matching allow rule — ${WHY}." \
            "A source-scoped rule would not be detected here, so check before acting." \
            "Open it: ssh ${HOST#*@} ufw allow ${PORT}/${PROTO}"
        fi
      done
      if [ "$DOCKER_PORTS" -gt 0 ]; then
        printf '  %sINFO:%s %s published port(s) here bypass %s (Docker writes nat/FORWARD, not INPUT).\n' "$C_CYAN" "$C_OFF" "$DOCKER_PORTS" "$FW_KIND"
        echo "        A ufw rule neither opens nor closes them — see ./logstotal deploy:network."
      fi
    fi

    # Reported, never asserted: a UDP probe cannot distinguish "open" from "black hole",
    # so claiming reachability here would be a guess wearing a checkmark. The handshake
    # count after apply is the real evidence, and deploy-vpn.sh gates on it.
    if [ "$DEPLOY_VPN" = "wireconf" ] && _ssh "$HOST" "ip link show wg0" >/dev/null; then
      printf '  %sINFO:%s wg0 already present on this host.\n' "$C_CYAN" "$C_OFF"
    fi
  fi

  # ── Verdict: what would a deploy do to this host? ──────────────────────────
  if [ "$PLAN" = true ]; then
    REMOTE_VER=""
    # A lost session makes every test below answer "absent", and absent would make a fully
    # deployed control plane come out as FRESH INSTALL — the verdict that invites a
    # first-time deploy over a live installation. Classify nothing we could not read.
    _ssh_rc "$HOST" "test -f ${REMOTE_DIR}/VERSION"
    if session_lost; then
      : # HOST_BLOCKED is now set, so the BLOCKED branch below reports it
    elif [ "$SSH_RC" -eq 0 ]; then
      REMOTE_VER=$(_ssh "$HOST" "sed -n 's/^version: *//p' ${REMOTE_DIR}/VERSION | head -1" | tr -d '[:space:]')
    fi
    # Both compose files, deduped — common.sh::compose_running_count_cmd, which explains
    # why probing both is necessary and why `sort -u` is not cosmetic. Reading only
    # docker-compose.yml, a worker-only host — every host but the control plane — would
    # report zero containers however healthy, and the plan would call it "PARTIAL: code
    # current but nothing running". deploy-multiserver.sh::check_running probes both too.
    RUNNING=$(host_number "$HOST" "cd ${REMOTE_DIR} 2>/dev/null && $(compose_running_count_cmd) || echo 0")
    [ "$RUNNING" = "?" ] && RUNNING=0

    # A dry run contacted nothing, so every input to the verdict below is an empty capture
    # read as an answer: `test -d …/data` "succeeds", the version comes back blank, the
    # container count is zero. It would report PARTIAL for every host in the fleet — a claim
    # about machines nobody asked. The summary says so instead.
    if truthy "${DEPLOY_DRY_RUN:-}"; then
      IDX=$((IDX + 1))
      echo ""
      continue
    fi

    # An UNKNOWN is reported on its own line and does NOT change the verdict. A host
    # whose free disk could not be read is still FRESH INSTALL or UPDATE — the plan says
    # what a deploy would do, and it would do exactly that. Folding it into BLOCKED would
    # make `deploy:plan` unusable on any host the checks could not fully reach.
    # Colour the whole "verdict + token" prefix inline rather than the token alone:
    # tests/test_docs_in_sync.py greps this source for the verdict word after each
    # V.E.R.D.I.C.T. label to verify every one is documented, so that word must stay
    # LITERAL in the format string (a `%s` arg would hide it). Plain-text output is
    # unchanged (C_* are empty when tests run without a TTY), so every substring
    # assertion still matches byte-for-byte.
    [ -n "$HOST_UNKNOWN" ] && printf '  %sNOT MEASURED:%s %s\n' "$C_CYAN" "$C_OFF" "$HOST_UNKNOWN"

    if [ -n "$HOST_BLOCKED" ]; then
      printf '  %sVERDICT: BLOCKED%s — %s\n' "${C_BOLD}${C_RED}" "$C_OFF" "$HOST_BLOCKED"
      plan_record BLOCKED "$HOST_BLOCKED"
      PLAN_BLOCKED=$((PLAN_BLOCKED + 1))
    elif [ -z "$REMOTE_VER" ]; then
      if _ssh "$HOST" "test -d ${REMOTE_DIR}/data -o -d ${REMOTE_DIR}/uploads -o -d ${REMOTE_DIR}/backups"; then
        # Bootstrap made the directories and the code never landed — the shape a deploy
        # that died partway leaves behind, and it is not a fresh box.
        printf '  %sVERDICT: PARTIAL%s — data directories present, no code\n' "${C_BOLD}${C_YELLOW}" "$C_OFF"
        plan_record PARTIAL "data directories present, no code"
        PLAN_PARTIAL=$((PLAN_PARTIAL + 1))
      else
        printf '  %sVERDICT: FRESH INSTALL%s\n' "${C_BOLD}${C_GREEN}" "$C_OFF"
        plan_record "FRESH INSTALL"
        PLAN_FRESH=$((PLAN_FRESH + 1))
      fi
    elif [ "$REMOTE_VER" = "$LOCAL_VERSION" ]; then
      if [ "$RUNNING" -gt 0 ]; then
        printf '  %sVERDICT: ALREADY CURRENT%s %s (%s container(s) up)\n' "${C_BOLD}${C_CYAN}" "$C_OFF" "$(value "$REMOTE_VER")" "$RUNNING"
        plan_record "ALREADY CURRENT"
        truthy "$LOCAL_UNRELEASED" && echo "           NOTE: this checkout is not at a release tag — a version match cannot"
        truthy "$LOCAL_UNRELEASED" && echo "                 tell two builds of ${LOCAL_VERSION} apart."
        PLAN_CURRENT=$((PLAN_CURRENT + 1))
      else
        printf '  %sVERDICT: PARTIAL%s — code %s is current but nothing is running\n' "${C_BOLD}${C_YELLOW}" "$C_OFF" "$(value "$REMOTE_VER")"
        plan_record PARTIAL "code is current but nothing is running"
        PLAN_PARTIAL=$((PLAN_PARTIAL + 1))
      fi
    else
      printf '  %sVERDICT: UPDATE%s %s → %s\n' "${C_BOLD}${C_GREEN}" "$C_OFF" "$(value "${REMOTE_VER:-?}")" "$(value "${LOCAL_VERSION:-?}")"
      plan_record UPDATE "${REMOTE_VER:-?} → ${LOCAL_VERSION:-?}"
      [ "$RUNNING" -eq 0 ] && echo "           (nothing running there now)"
      PLAN_UPDATE=$((PLAN_UPDATE + 1))
    fi
  fi

  IDX=$((IDX + 1))
  echo ""
done

# ── Summary ──
#
# A dry run connects to nothing, so it measured nothing, so it cannot pass. Printing
# "PREFLIGHT PASSED: all 3 host(s) ready" after making no connection is the most
# dangerous line this script could produce.
# The machine-readable form, emitted instead of the banner rather than beside it: one
# document per run is what a caller can parse. Every judgement in it comes from the same
# counters the text form prints, so the two cannot disagree.
if [ "$PLAN" = true ] && [ "$PLAN_FORMAT" = "json" ]; then
  config_review json \
    --plan-version "${LOCAL_VERSION:-}" \
    --plan-version-source "${LOCAL_VERSION_SOURCE:-}" \
    --plan-count "fresh=${PLAN_FRESH}" \
    --plan-count "update=${PLAN_UPDATE}" \
    --plan-count "current=${PLAN_CURRENT}" \
    --plan-count "partial=${PLAN_PARTIAL}" \
    --plan-count "blocked=${PLAN_BLOCKED}" \
    --plan-count "unmeasured=${V_UNKNOWN}" \
    --plan-dry-run "$(truthy "${DEPLOY_DRY_RUN:-}" && echo true || echo false)" \
    "${PLAN_RECORDS[@]+"${PLAN_RECORDS[@]}"}" >&3
  exit 0
fi

if truthy "${DEPLOY_DRY_RUN:-}"; then
  printf '%sPREFLIGHT NOT RUN (dry run):%s traced %s host(s), measured nothing, connected to nothing.\n' \
    "${C_BOLD}${C_YELLOW}" "$C_OFF" "$(value "$HOST_COUNT")"
  # In plan mode the report is the whole output, and a dry run still owes the operator the
  # half it CAN answer without connecting: what a deploy would install, and which ports the
  # topology needs. The per-host verdicts are the half it cannot — they are computed from
  # replies that never arrived — so they are suppressed above rather than printed here and
  # contradicted by this line.
  if [ "$PLAN" = true ]; then
    echo ""
    printf 'Would install %s (%s)\n' "$(value "${LOCAL_VERSION:-?}")" "${LOCAL_VERSION_SOURCE:-nothing to compare}"
    echo "No host was contacted, so there is no per-host verdict. Drop DEPLOY_DRY_RUN for one."
    # The findings are read off deploy.env, not off a host, so a dry run can answer them
    # in full. Withholding them here would make the rehearsal weaker than the thing it
    # rehearses for no reason.
    _FINDINGS=$(config_review text --findings-only)
    [ -n "$_FINDINGS" ] && { echo ""; printf '%s\n' "$_FINDINGS"; }
    header "Network plan"
    network_plan text
  fi
  exit 0
fi

if [ "$PLAN" = true ]; then
  header "Deploy plan"
  printf 'Compared against %s (%s)\n' "$(value "${LOCAL_VERSION:-?}")" "${LOCAL_VERSION_SOURCE:-nothing to compare}"
  case "$LOCAL_VERSION_SOURCE" in
    *"IS the install"*)
      echo "  So every host that is up to date with THIS machine reads ALREADY CURRENT,"
      echo "  which is a tautology rather than news. To see what a NEW release would do:"
      echo "    ./logstotal upgrade:plan"
      ;;
  esac
  # Counts as bold values on a plain-cyan label so the fleet shape reads at a glance;
  # phrased on one line still so the pinned "Fleet: " prefix survives.
  printf 'Fleet: %s fresh, %s to update, %s current, %s partial, %s blocked\n' \
    "$(value "$PLAN_FRESH")" "$(value "$PLAN_UPDATE")" "$(value "$PLAN_CURRENT")" \
    "$(value "$PLAN_PARTIAL")" "$(value "$PLAN_BLOCKED")"
  [ "$V_UNKNOWN" -gt 0 ] && printf '       %s check(s) could not be measured — listed above, none of them blocking.\n' "$(value "$V_UNKNOWN")"
  # Settings that disagree with each other. Deliberately below the per-host results and
  # above the network plan: it is a statement about the configuration, like the block at
  # the top, and none of it changes a verdict or the exit code.
  _FINDINGS=$(config_review text --findings-only)
  [ -n "$_FINDINGS" ] && { echo ""; printf '%s\n' "$_FINDINGS"; }
  # What must be reachable, and from where. `deploy:plan` is where an operator asks "what
  # would this do to my fleet", and the answer includes the ports it needs.
  header "Network plan"
  network_plan text
  echo ""
  if [ "$PLAN_BLOCKED" -gt 0 ]; then
    echo "Resolve the BLOCKED host(s) above first — a deploy would stop there."
  elif [ "$PLAN_FRESH" -eq 0 ] && [ "$PLAN_UPDATE" -eq 0 ] && [ "$PLAN_PARTIAL" -eq 0 ]; then
    printf 'Nothing to do — every host already runs %s.\n' "$(value "${LOCAL_VERSION:-this build}")"
  else
    step "Recommended"
    echo "  ./logstotal deploy                                             # converge the fleet"
    echo "Start from scratch instead:"
    echo "  DEPLOY_REMOVE_CONFIRM=yes ./logstotal deploy:remove            # then ./logstotal deploy"
  fi
  # Always 0: this is a report. An operator asking what would happen gets an answer,
  # not an exit code.
  exit 0
fi

header "Network plan"
network_plan text
echo ""

# The tally is printed on EVERY outcome, including a clean one. An operator who only
# ever sees "not measured" when something is wrong learns to read its absence as "fine".
#
# Verdict token stays LITERAL in the printf format (never a %s arg): tests grep for
# "PREFLIGHT PASSED" / "PREFLIGHT FAILED" / "PREFLIGHT BLOCKED" in stdout, and
# tests/test_docs_in_sync.py mirrors what deploy:plan emits back into docs.
if [ "$V_FAIL" -gt 0 ]; then
  printf '%sPREFLIGHT FAILED:%s %s. Fix the failures above before deploying.\n' "${C_BOLD}${C_RED}" "$C_OFF" "$(v_tally)"
elif [ "$V_BLOCKING" -gt 0 ]; then
  printf '%sPREFLIGHT BLOCKED:%s %s.\n' "${C_BOLD}${C_RED}" "$C_OFF" "$(v_tally)"
  echo "A security control could not be verified — see the UNKNOWN (blocking) line above."
elif [ "$V_UNKNOWN" -gt 0 ]; then
  printf '%sPREFLIGHT PASSED:%s %s.\n' "${C_BOLD}${C_GREEN}" "$C_OFF" "$(v_tally)"
  echo "Nothing measured is wrong. Read the UNKNOWN line(s) above and decide whether you"
  echo "need those answers before deploying — the deploy is not blocked by them."
elif [ "$V_WARN" -gt 0 ]; then
  printf '%sPREFLIGHT PASSED:%s %s. Review the warnings above.\n' "${C_BOLD}${C_GREEN}" "$C_OFF" "$(v_tally)"
else
  printf '%sPREFLIGHT PASSED:%s all %s host(s) ready for deployment (%s).\n' "${C_BOLD}${C_GREEN}" "$C_OFF" "$(value "$HOST_COUNT")" "$(v_tally)"
fi
exit "$(v_status)"
