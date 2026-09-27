#!/usr/bin/env bash
# shellcheck shell=bash
#
# The control plane's record of its own fleet (developer / ops).
#
# A thin shell face over scripts/fleet_manifest.py, which holds the reasoning and the
# schema. What lives here is only the two questions bash needs answered: where does the
# record live, and how do I read one field out of it without a JSON parser on the host.
#
# Everything here is SAFE WHEN THE RECORD IS ABSENT. That is deliberate and not defensive
# habit: the manifest is the LAST source consulted for a host list (positionals, then the
# environment, then deploy.env, then this), so a missing or damaged one must degrade to
# "I know nothing" rather than to an error. A cosmetic file may not become a hard
# dependency of the tool that writes it.

# fleet_manifest_path [INSTALL_DIR] — where the record lives.
#
# Inside the install directory, because the install is the thing it describes and the two
# should travel together — a host that is moved or restored from a snapshot carries its own
# architecture with it. `fleet` is in lib/install.sh's overlay excludes and in
# snapshot_excludes, so an upgrade cannot delete it and a snapshot cannot carry it into
# another host's tree.
# FLEET_MANIFEST overrides it outright. That is what lets a deploy BUILD the record on the
# machine running it — where the tool and a python3 certainly exist — and then push the
# finished file to a control plane that may be a bare box with no tree yet.
fleet_manifest_path() {
  [ -n "${FLEET_MANIFEST:-}" ] && { printf '%s' "$FLEET_MANIFEST"; return 0; }
  local dir="${1:-${DEPLOY_REMOTE_DIR:-/opt/logstotal}}"
  printf '%s/fleet/manifest.json' "${dir%/}"
}

# fleet_remote_manifest_path [INSTALL_DIR] — where the record lives ON A HOST.
#
# The same path, with the FLEET_MANIFEST override deliberately NOT applied. The two answer
# different questions and only look alike: fleet_manifest_path says "the record this process
# should read", which an override is entitled to redirect; this one says "the file at
# <install>/fleet/ on the machine at the other end of an scp", which nothing local may move.
#
# Without the split, exporting FLEET_MANIFEST — which is exactly how a workstation adopts a
# remote fleet — would make a deploy copy the control plane's record TO and FROM the
# workstation's own cache path on the remote host. Silently: every call site here is
# `|| true`, because a fleet record is bookkeeping and a deploy must not fail over it.
fleet_remote_manifest_path() {
  local dir="${1:-${DEPLOY_REMOTE_DIR:-/opt/logstotal}}"
  printf '%s/fleet/manifest.json' "${dir%/}"
}

# _fleet_py ARGS... — run the manifest tool, quietly. Never fails the caller.
_fleet_py() {
  local module
  module="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/fleet_manifest.py"
  [ -f "$module" ] || return 0
  run_py "$module" "$@" 2>/dev/null || true
}

# fleet_record_intent HOSTS INSTALL_DIR — write what the operator asked for.
#
# Called BEFORE anything is mutated, so a run that dies partway still leaves a record of
# the fleet it was working on. Options are read from the environment the deploy has already
# resolved, which is the only place they are all correct at once.
fleet_record_intent() {
  local hosts="$1" install_dir="$2" path
  path=$(fleet_manifest_path "$install_dir")
  _fleet_py --file "$path" intent \
    --hosts "$hosts" \
    --install-dir "$install_dir" \
    --written-by "$(read_version_file)" \
    --written-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --option "remote_dir=${install_dir}" \
    --option "vpn=${DEPLOY_VPN:-}" \
    --option "vpn_port=${DEPLOY_VPN_PORT:-}" \
    --option "vpn_network=${DEPLOY_VPN_NETWORK:-}" \
    --option "vpn_hub_endpoint=${DEPLOY_VPN_HUB_ENDPOINT:-}" \
    --option "cp_address=${DEPLOY_CP_ADDRESS:-}" \
    --option "cp_bind_address=${DEPLOY_CP_BIND_ADDRESS:-}" \
    --option "domain=${DEPLOY_DOMAIN:-}" \
    --option "proxy_tls=${DEPLOY_PROXY_TLS:-}" \
    --option "basic_auth_user=${DEPLOY_BASIC_AUTH_USER:-}" \
    --option "huey_workers=${DEPLOY_HUEY_WORKERS:-}" \
    --option "keep_releases=${DEPLOY_KEEP_RELEASES:-}" \
    --release "server=$(release_repo_url 2>/dev/null || true)"
}

# fleet_record_result HOST RESULT [VERSION] [CONTAINERS] — merge one host's outcome.
#
# One of ok / unverified / failed / skipped / not-attempted. `unverified` is how the
# deploy's UNKNOWN verdict outlives the console: a worker whose containers were never
# confirmed is neither claimed healthy nor reported broken.
fleet_record_result() {
  local host="$1" result="$2" version="${3:-}" containers="${4:-}" path args
  path=$(fleet_manifest_path)
  args=(--file "$path" result --entry "$host" --result "$result"
        --when "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
  [ -n "$version" ] && args+=(--version "$version")
  [ -n "$containers" ] && args+=(--containers "$containers")
  _fleet_py "${args[@]}"
}

# fleet_adopt — when FLEET_FROM names a control plane, drive this run against ITS fleet.
#
# The answer to "I am on my laptop and the fleet is over there". `task fleet:pull` already
# fetched a record and wrote a deploy.env from it; this is the same fetch without the file,
# for the case where you want to run one command rather than adopt a fleet permanently.
#
# ONE explicit opt-in, never inference. `task upgrade -- cp.example.com` still means that one
# host: a positional means exactly what it says, and
# DEPLOY_ONLY already spells "a subset of the fleet". Guessing which was meant would be a
# coin flip on `task deploy:remove`, which deletes install directories.
#
# Three things here are load-bearing:
#
#   It exports FLEET_MANIFEST, so nothing else has to change — deploy_env_load, fleet_hosts
#   and fleet_env_default all read through fleet_manifest_path, which the override redirects.
#   That is also why fleet_remote_manifest_path exists: the two scp sites in
#   deploy-multiserver.sh name a path ON the control plane and must not follow it.
#
#   It rewrites the cached copy rather than filtering on read. A record made by deploying
#   FROM the control plane stores `local`, and fleet_hosts returns stored entries verbatim
#   under an override — so a workstation would read DEPLOY_HOSTS=local,w1 and deploy the
#   control plane to itself. Normalising the file once means every later reader is right.
#
#   It must be called ABOVE a script's first deploy_env_load. _fleet_options memoises the
#   record's options on first read, so adopting afterwards is silently ignored: the hosts
#   would come from the remote record and the settings from this machine.
fleet_adopt() {
  [ -n "${FLEET_FROM:-}" ] || return 0
  [ -n "${FLEET_ADOPTED:-}" ] && return 0

  # hosts_from_args, not a second validator: it accepts one entry, REFUSES a comma — so
  # FLEET_FROM can never smuggle a host list past the "one control plane" contract — and
  # rejects shell metacharacters before the value reaches to_target and ssh.
  local from
  from=$(hosts_from_args "$FLEET_FROM") || return 1
  [ -n "$from" ] || die "FLEET_FROM is empty. Name one control plane: FLEET_FROM=cp.example.com"

  local remote_dir slug cache age ttl
  remote_dir="${DEPLOY_REMOTE_DIR:-$(deploy_env_default DEPLOY_REMOTE_DIR)}"
  remote_dir="${remote_dir:-/opt/logstotal}"
  # Per control plane, under $HOME rather than the working directory, so one admin can hold
  # several fleets and a command works from wherever it is run.
  slug=$(printf '%s' "${from#*@}" | tr -c 'A-Za-z0-9._-' '_')
  cache="${XDG_CACHE_HOME:-${HOME}/.cache}/logstotal/fleet/${slug}.json"
  ttl="${FLEET_CACHE_TTL:-900}"

  age=$(_fleet_cache_age "$cache")
  if [ "${FLEET_REFRESH:-}" = "yes" ] || [ "$age" -ge "$ttl" ]; then
    _fleet_fetch "$from" "$remote_dir" "$cache" || {
      [ -f "$cache" ] || die "could not fetch the fleet record from ${from}:${remote_dir}/fleet/manifest.json
       A control plane writes one on every deploy. Check the host is reachable, or name the
       fleet directly with DEPLOY_HOSTS=..."
      warn "could not refresh the fleet record from ${from} — using the cached copy."
    }
  fi

  FLEET_MANIFEST="$cache"
  FLEET_ADOPTED=yes
  export FLEET_MANIFEST FLEET_ADOPTED

  # The companion to the note on fleet_hosts above.
  # shellcheck disable=SC2119
  info "fleet: $(fleet_hosts) (from the fleet record on ${from})"
  info "  secrets were NOT fetched — they never leave the machine that generated them."
  info "  So: upgrade, plan, status, logs, smoke, stop/start and remove. Not deploy or"
  info "  deploy:env, which mint and push per-host env files."
}

# _fleet_cache_age PATH — seconds since PATH was written, or a number larger than any TTL.
_fleet_cache_age() {
  [ -f "$1" ] || { printf '%s' 99999999; return 0; }
  local now mtime
  now=$(date +%s)
  # BSD and GNU stat disagree about everything except being present on their own platform.
  mtime=$(stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || printf '0')
  printf '%s' "$((now - mtime))"
}

# _fleet_fetch HOST DIR CACHE — copy HOST's record to CACHE and make it portable.
_fleet_fetch() {
  local host="$1" dir="$2" cache="$3" tmp
  mkdir -p "$(dirname "$cache")"
  chmod 700 "$(dirname "$cache")" 2>/dev/null || true
  tmp="${cache}.$$"
  build_ssh_opts
  host_copy_from "$host" "$(fleet_remote_manifest_path "$dir")" "$tmp" >/dev/null 2>&1 || {
    rm -f "$tmp"
    return 1
  }
  # `local` is only meaningful where it was written. Substituted here, once, against the
  # address the record holds or the host we just reached — which is reachable by
  # construction, since the file came off it.
  _fleet_py --file "$tmp" portable --fallback "$host" >/dev/null || {
    rm -f "$tmp"
    die "the record on ${host} names its control plane as \`local\` and carries no address.
       Deploy once from a machine that names it, or set DEPLOY_HOSTS explicitly."
  }
  mv -f "$tmp" "$cache"
}

# fleet_hosts [INSTALL_DIR] — the recorded host list, or "".
#
# The control plane's own entry comes back as `local` — see fleet_manifest.py::hosts_line for
# why, and why the substitution is exact rather than a hostname guess. Only when the record is
# the one in THIS machine's install directory: FLEET_MANIFEST points elsewhere by definition
# (a deploy builds the record on the machine running it, before pushing it), and a workstation
# reading a pulled copy has to keep the control plane's name or it starts deploying to itself.
# The INSTALL_DIR argument is optional and always has been; fleet_adopt calls it with none.
# Version 0.10.0 of the linter — which scripts/ci-provision.sh pins, and which is OLDER than
# a current local install — reports SC2120/SC2119 for an optional-argument function whose
# only in-file caller passes nothing. 0.11.0 stopped emitting it. So a local run is clean
# while CI fails, and the directive below is what closes that gap. Reproduce CI's exact
# verdict with:  docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:v0.10.0 -x <file>
#
# Note no line of this comment may begin with the linter's own name: it would be parsed as a
# malformed directive and fail the file outright.
# shellcheck disable=SC2120
fleet_hosts() {
  local path
  path=$(fleet_manifest_path "${1:-}")
  if [ -n "${FLEET_MANIFEST:-}" ]; then
    _fleet_py --file "$path" hosts
  else
    _fleet_py --file "$path" hosts --as-control-plane
  fi
}

# fleet_env_default NAME — the record's answer for the DEPLOY_* variable NAME, or "".
#
# The manifest's twin of deploy_env_default, and it sits AFTER it in every precedence chain:
# positionals, then the environment, then deploy.env, then this. Explicit configuration always
# wins — a stale record must never redirect a run the operator has been specific about.
#
# The mapping is mechanical (DEPLOY_VPN_HUB_ENDPOINT → vpn_hub_endpoint) and holds for every
# key in fleet_manifest.py::OPTION_KEYS, so there is no table here to fall out of step.
#
# This is what makes the record more than a report: a control plane with cp_address, vpn
# and domain recorded does not have to be told all three on the command line.
fleet_env_default() {
  local key
  key=$(printf '%s' "${1#DEPLOY_}" | tr '[:upper:]' '[:lower:]')
  _fleet_options | grep "^${key}=" | head -1 | cut -d= -f2-
}

# _fleet_options — the record's options as key=value lines, read AT MOST ONCE per process.
#
# deploy_env_load asks about a dozen keys and several scripts call it, so a python invocation
# per key would be ~40 of them per run. The cache is a plain string rather than an associative
# array: bash 3.2 is still what /bin/bash is on macOS.
_fleet_options() {
  if [ -z "${_FLEET_OPTIONS_READ:-}" ]; then
    _FLEET_OPTIONS_READ=1
    _FLEET_OPTIONS_BLOB=$(_fleet_py --file "$(fleet_manifest_path)" options)
  fi
  printf '%s\n' "${_FLEET_OPTIONS_BLOB:-}"
}

# fleet_release KEY [INSTALL_DIR] — one recorded release field, or "".
#
# `server` is the only field, and it is what lets release_repo_url answer on a control
# plane. It needs its own reader because fleet_manifest.py's `get` reads options{} and
# this lives beside it.
fleet_release() {
  _fleet_py --file "$(fleet_manifest_path "${2:-}")" release "$1"
}

# fleet_option KEY [INSTALL_DIR] — one recorded option, or "".
#
# The manifest's twin of deploy_env_default, and it sits at the same place in every
# precedence chain: after it. Explicit configuration always wins; this is what answers when
# there is none, which is the situation on a control plane that was deployed TO rather than
# FROM.
fleet_option() {
  _fleet_py --file "$(fleet_manifest_path "${2:-}")" get "$1"
}
