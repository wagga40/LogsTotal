#!/usr/bin/env bash
# One command from fresh boxes to a working LogsTotal fleet (developer / ops).
#
# The multi-host counterpart of scripts/quickstart.sh, and the same shape: numbered,
# self-announcing steps, every write conditional, safe to re-run. It composes the
# pieces rather than reimplementing them — bootstrap, VPN, env generation, env push,
# preflight, the unchanged five-phase deploy, and smoke — so each remains usable on
# its own for a fleet that is already up.
#
# Usage:
#   bash scripts/deploy-fleet.sh                        # hosts from deploy.env
#   bash scripts/deploy-fleet.sh cp.example w1 w2       # …and write them to deploy.env
#   bash scripts/deploy-fleet.sh init cp.example w1 w2  # write deploy.env and stop
#
# Host entries are `host` (SSH as root), `user@host`, or `local` (this machine, no
# SSH) — the last is what lets the whole thing run from the control plane itself.
# The FIRST host is the control plane.
#
# Configuration (env vars from the caller always override deploy.env values):
#   DEPLOY_HOSTS               Comma-separated host list. Positional arguments win.
#   DEPLOY_REMOTE_DIR          Install dir on each host (default /opt/logstotal).
#   DEPLOY_BOOTSTRAP           falsy: skip package installation (hosts already prepared).
#   DEPLOY_VPN                 `wireconf` builds a WireGuard mesh first. DEFAULT. `none`
#                              deploys over the hosts' own addresses instead.
#   DEPLOY_ONLY                Act on this subset only — how one worker joins a live fleet.
#   DEPLOY_DOMAIN              Setting it puts Caddy in front of the control plane.
#   DEPLOY_ENV_DIR             Where the generated .env files live (default deploy-envs).
#                              Read here only to name the control plane's file in the
#                              closing banner — a hardcoded default would point at a file
#                              that does not exist whenever this is set.
#   DEPLOY_PROXY_TLS           How Caddy terminates TLS: acme (default, public domain),
#                              internal (its own CA — no DNS, no port 80, no internet),
#                              custom (your certificate), off (plain HTTP).
#   DEPLOY_ACME_EMAIL          Let's Encrypt contact address.
#   DEPLOY_BASIC_AUTH_USER     Caddy basic-auth username.
#   DEPLOY_BASIC_AUTH_PASSWORD Hashed ON THE CONTROL PLANE; only the hash is stored.
#   DEPLOY_BASIC_AUTH_HASH     A bcrypt hash you produced yourself, instead of the above.
#   DEPLOY_PREFLIGHT_STAGE     Set by this script, not by the caller: `pre` for the step-2
#                              gate (what bootstrap cannot fix, reported before it runs),
#                              `post` for the step-7 one (the fatal tool check, after
#                              bootstrap has installed them).
#   VERSION / ARCHIVE          Deploy a PUBLISHED release rather than a repackaging of
#                              this tree: VERSION=1.0.0 resolves and downloads it once
#                              here, ARCHIVE=<path or URL> names one exactly. The same two
#                              knobs `task upgrade` answers, deliberately — "which release"
#                              is the same question on the first install as on the fifth.
#   DEPLOY_SKIP_SMOKE          truthy: do not run the post-deploy smoke check.
#   DEPLOY_ACTION              set to `deploy` by this script for the deploy step. Not for
#                              callers — every other action has its own task.
#   DEPLOY_SMOKE_STRICT        set to true by this script when it runs the smoke check, so
#                              it can tell verified from merely-answered. Not for callers.
#   DEPLOY_HEALTH_CONFIRMED    set to true by this script, because step 8 already gated on
#                              the control plane's own /health from inside the network.
#                              Not for callers.
#   DEPLOY_STOP / DEPLOY_KEEPENV / DEPLOY_START
#                              Passed through to the deploy phase; all default to true
#                              here, because a bring-up that leaves the stacks stopped
#                              is not a bring-up. Set any of them to override.
#   DEPLOY_ENV_FILE            Path to defaults file (default: deploy.env in cwd).
#   DEPLOY_DRY_RUN             truthy: trace everything, connect to nothing.
#   FORCE                      `yes`: let `init` overwrite an existing deploy.env.
#   SSH_IDENTITY               Path to SSH private key (optional).
#
# `init` also WRITES, commented and at their documented defaults, the settings most often
# tuned on a first deploy. This script does not read them — they are there so the file it
# hands you is one you can edit without first reading deploy.env.example:
#   DEPLOY_VPN_NETWORK         WireGuard CIDR for the mesh.
#   DEPLOY_VPN_PORT            UDP port the hub listens on.
#   DEPLOY_CP_ADDRESS          The address workers dial for Redis, PostgreSQL and S3.
#   DEPLOY_HUEY_WORKERS        Analysis workers per host.
#   DEPLOY_KEEP_RELEASES       Rollback snapshots kept per host.
#   DEPLOY_ADMIN_EMAIL         The first admin account.
#   RELEASE_REPO_URL           Where task upgrade looks for published releases.
#
# `set -eu`, no pipefail — deploy_env_default's grep must be allowed to miss, and the
# hash capture below must survive a non-zero producer.

set -eu

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

DEPLOY_ENV_FILE="${DEPLOY_ENV_FILE:-deploy.env}"

# ── Host list ────────────────────────────────────────────────────────────────
#
# Positional, never a go-task `env:` bridge. That bridge exports the key even when the
# template resolves empty, and deploy_env_load skips a key that is merely *set* — so a
# bare `task deploy` would export DEPLOY_HOSTS="" and silently defeat the
# documented deploy.env workflow. Arguments never become environment variables at all.

# Adopt a remote fleet record when FLEET_FROM names a control plane — above the host block
# below and above the first deploy_env_load, which _fleet_options memoises.
fleet_adopt

# `task deploy` generates and installs per-host env files, so it needs the fleet's secrets.
# Refused here rather than at step 5 of 8, after three hosts have been bootstrapped.
if [ "${FLEET_ADOPTED:-}" = "yes" ] && [ ! -f "${DEPLOY_ENV_DIR:-deploy-envs}/secrets.json" ] && [ "${1:-}" != "init" ]; then
  die "this fleet was adopted from ${FLEET_FROM}, and a deploy needs its secrets.
       They never leave the machine that generated them, so fresh ones would be minted here
       and pushed over the running fleet — PostgreSQL sets its password once, when its data
       directory is created, so the new one would authenticate against nothing.

       From here you can: ./logstotal upgrade, ./logstotal deploy:plan, ./logstotal deploy:status,
       ./logstotal deploy:smoke, ./logstotal deploy:remove.
       To deploy, run from the machine holding deploy-envs/, or copy that directory here."
fi

ACTION="deploy"
if [ "${1:-}" = "init" ]; then
  ACTION="init"
  shift
fi

# The task the operator actually typed, for every hint printed below. `init` and the
# positional-deploy path share write_deploy_env, so its refusal must name whichever was run:
# `task deploy:init` run twice must not suggest deploying the whole fleet to rewrite one
# file. A hint that names a more destructive command than the one you ran is worse than none.
THIS_TASK="deploy"
[ "$ACTION" = "init" ] && THIS_TASK="deploy:init"

if [ "$#" -gt 0 ]; then
  for arg in "$@"; do
    case "$arg" in
      *[!A-Za-z0-9._@-]*) die "Not a host: '${arg}'. Entries are host, user@host, or local." ;;
    esac
  done
  DEPLOY_HOSTS=$(
    IFS=,
    printf '%s' "$*"
  )
  export DEPLOY_HOSTS
else
  deploy_env_load DEPLOY_HOSTS
fi

# Last, the fleet record — this host's own, or an adopted one. The same rung every other
# deploy verb ends on.
if [ -z "${DEPLOY_HOSTS:-}" ]; then
  DEPLOY_HOSTS=$(fleet_hosts "${DEPLOY_REMOTE_DIR:-}")
  [ -n "${DEPLOY_HOSTS:-}" ] && export DEPLOY_HOSTS
fi

if [ -z "${DEPLOY_HOSTS:-}" ]; then
  die "No hosts. Name them once — task ${THIS_TASK} -- cp.example.com w1.example.com — or put DEPLOY_HOSTS in ${DEPLOY_ENV_FILE}.
       For a single machine with no fleet, use: ./logstotal quickstart"
fi

CP="${DEPLOY_HOSTS%%,*}"

# DEPLOY_VPN comes from deploy.env HERE, not with the rest of the knobs further down.
#
# vpn_mode's own contract says to load it first. Otherwise, with `DEPLOY_VPN=none` in
# deploy.env, the mode resolves as unset, defaults to wireconf, and the deploy BUILDS A
# WIREGUARD MESH THE OPERATOR DECLINED — re-addressing every cross-host URL from the public
# address to 10.200.0.x, an outage on a running fleet — while the later deploy_env_load
# picks the value up and warns about the very tunnel being built. Anything vpn_mode or the
# banner reads must be loaded above this line.
deploy_env_load DEPLOY_VPN

# Resolved here, before write_deploy_env can be called: the file records what will actually
# happen, and the banner further down reports the same answer.
vpn_mode

# _knob KEY DEFAULT COMMENT — one commented setting, unless it was written for real above.
#
# Commented keys are inert: deploy_env_default greps ^KEY=, so nothing here changes what a
# deploy does. What it changes is whether the operator knows the knob exists.
_knob() {
  local key="$1" default="$2"
  shift 2
  case " ${WRITTEN_KEYS} " in *" ${key} "*) return 0 ;; esac
  # Wrapped at the width of the rest of the file. `fold -s` breaks on spaces; without it a
  # one-sentence explanation becomes a 140-column line and the file stops being readable in
  # the terminal it is edited in.
  printf '%s\n' "$*" | fold -s -w 74 | sed 's/^/# /' | sed 's/ *$//'
  printf '#%s=%s\n' "$key" "$default"
}

# _knob_section TITLE — a heading, matching deploy.env.example's own sections.
_knob_section() {
  printf '\n# ── %s ' "$1"
  printf '─%.0s' $(seq 1 $((72 - ${#1})))
  printf '\n'
}

# write_deploy_env — the file `task deploy:init` exists to give you.
#
# Two halves. Values that were actually supplied are written for real at the top; everything
# else an operator commonly tunes on a first deploy is emitted COMMENTED, at its documented
# default, with the one line of explanation deploy.env.example gives it.
#
# The second half is the point of the command. The Taskfile calls deploy:init "the step that
# gives you something to EDIT": an operator who never opens deploy.env.example still learns
# that DEPLOY_DOMAIN, DEPLOY_HUEY_WORKERS and RELEASE_REPO_URL exist.
#
# Curated, not complete: deploy.env.example documents dozens of keys and most are switches
# for one situation. A template nobody reads to the end is the same as no template.
# tests/test_deploy_fleet.py pins that every key here still exists there, so the two cannot
# drift apart.
write_deploy_env() {
  if [ -f "$DEPLOY_ENV_FILE" ] && [ "${FORCE:-}" != "yes" ]; then
    info "${DEPLOY_ENV_FILE} already exists — keeping it (it may hold settings this does not know about)."
    info "Overwrite it with: FORCE=yes task ${THIS_TASK} -- ${DEPLOY_HOSTS//,/ }"
    return 0
  fi

  # Which keys got a real value, so the template below does not offer them twice.
  WRITTEN_KEYS="DEPLOY_HOSTS DEPLOY_VPN"
  [ -n "${DEPLOY_REMOTE_DIR:-}" ] && WRITTEN_KEYS="${WRITTEN_KEYS} DEPLOY_REMOTE_DIR"
  [ -n "${SSH_IDENTITY:-}" ] && WRITTEN_KEYS="${WRITTEN_KEYS} SSH_IDENTITY"
  [ -n "${DEPLOY_DOMAIN:-}" ] && WRITTEN_KEYS="${WRITTEN_KEYS} DEPLOY_DOMAIN"
  [ -n "${DEPLOY_ACME_EMAIL:-}" ] && WRITTEN_KEYS="${WRITTEN_KEYS} DEPLOY_ACME_EMAIL"
  [ -n "${DEPLOY_BASIC_AUTH_USER:-}" ] && WRITTEN_KEYS="${WRITTEN_KEYS} DEPLOY_BASIC_AUTH_USER"

  {
    printf '# LogsTotal fleet configuration.\n'
    printf '#\n'
    printf '# Uncommented below: what this fleet was created with. Commented: the settings\n'
    printf '# most often tuned on a first deploy, at their defaults. deploy.env.example\n'
    printf '# documents every knob; docs/reference/fleet.md is the full reference.\n'
    printf '#\n'
    printf '# No quotes, no inline comments, no indentation — this file is read with grep,\n'
    printf '# never sourced, so a quoted value arrives with its quotes.\n'
    printf '\n# First host = control plane, the rest = workers.\n'
    printf 'DEPLOY_HOSTS=%s\n' "$DEPLOY_HOSTS"
    # The RESOLVED VPN mode, never the raw default: writing `wireconf` for a single-host
    # fleet records a mesh that cannot be built and, worse, reads back as an explicit
    # request, which is what stops vpn_mode()'s degenerate-fleet rules applying next time.
    printf 'DEPLOY_VPN=%s\n' "${DEPLOY_VPN:-$VPN_MODE}"
    [ -n "${DEPLOY_REMOTE_DIR:-}" ] && printf 'DEPLOY_REMOTE_DIR=%s\n' "$DEPLOY_REMOTE_DIR"
    [ -n "${SSH_IDENTITY:-}" ] && printf 'SSH_IDENTITY=%s\n' "$SSH_IDENTITY"
    # DOMAIN as well as DEPLOY_DOMAIN: deploy-smoke.sh resolves its target from DOMAIN,
    # and once Caddy binds WEB_PORT to loopback the http://host:8000 fallback is gone.
    if [ -n "${DEPLOY_DOMAIN:-}" ]; then
      printf 'DEPLOY_DOMAIN=%s\n' "$DEPLOY_DOMAIN"
      printf 'DOMAIN=%s\n' "$DEPLOY_DOMAIN"
    fi
    [ -n "${DEPLOY_ACME_EMAIL:-}" ] && printf 'DEPLOY_ACME_EMAIL=%s\n' "$DEPLOY_ACME_EMAIL"
    [ -n "${DEPLOY_BASIC_AUTH_USER:-}" ] && printf 'DEPLOY_BASIC_AUTH_USER=%s\n' "$DEPLOY_BASIC_AUTH_USER"

    _knob_section "Where it installs"
    _knob DEPLOY_REMOTE_DIR /opt/logstotal \
      "Everything LogsTotal owns on a host: code, data/, uploads/, backups/, and the fleet record. ./logstotal deploy:remove deletes it; nothing else does."
    # shellcheck disable=SC2088  # a literal written INTO a config file, not a path used
    # here — and build_ssh_opts expands a leading ~ when it reads the key back.
    _knob SSH_IDENTITY "~/.ssh/id_ed25519" "SSH key for every host. Omit to use your agent and ssh config."

    _knob_section "Private network"
    _knob DEPLOY_VPN_NETWORK 10.200.0.0/24 "WireGuard CIDR for the mesh."
    _knob DEPLOY_VPN_PORT 51820 "UDP port the hub listens on. Only the hub needs it open."
    _knob DEPLOY_CP_ADDRESS 10.200.0.1 "The address workers dial for Redis, PostgreSQL and S3. Probed when the mesh is built; set it to override."

    _knob_section "HTTPS and HTTP basic auth"
    _knob DEPLOY_DOMAIN logs.example.com "Put Caddy in front and serve this name. Without it the app is http://<control-plane>:8000."
    _knob DEPLOY_PROXY_TLS acme "acme (Let's Encrypt) | internal (self-signed) | custom | off."
    _knob DEPLOY_ACME_EMAIL admin@example.com "Expiry notices from the CA. Required for acme."
    _knob DEPLOY_BASIC_AUTH_USER admin "Username for HTTP basic auth."
    _knob DEPLOY_BASIC_AUTH_PASSWORD "" \
      "Its password. Hashed on the control plane (it always has Docker); only the bcrypt hash reaches a host's .env. The environment wins over this line, so it can also be passed per run. Set here it is plaintext on this machine — keep this file at mode 600, or set the hash below instead."
    # A bcrypt hash is literal $ sigils; single quotes keep the shell out of it.
    # shellcheck disable=SC2016
    _knob DEPLOY_BASIC_AUTH_HASH '$2a$14$...' \
      "The hash itself, if you would rather produce it: docker run --rm -i caddy:2-alpine caddy hash-password. Set, it skips the hashing step and no plaintext is stored anywhere."

    _knob_section "Sizing and retention"
    _knob DEPLOY_HUEY_WORKERS 4 "Analysis workers per host. ./logstotal recommend-scaling sizes it from CPU and RAM."
    _knob DEPLOY_KEEP_RELEASES 3 "Rollback snapshots kept under backups/releases/ on each host."
    _knob DEPLOY_ADMIN_EMAIL admin@example.com "The first admin account. Its password is generated; read it with ./logstotal show-admin-password."

    _knob_section "Where releases come from"
    printf '# Only a release ARCHIVE can name this, so an install that was deployed rather\n'
    printf '# than cloned has nothing to derive it from — and an ssh origin carries no web\n'
    printf '# scheme or port, so git@host:o/r.git becomes https://host/o/r, wrong for any\n'
    printf '# self-hosted forge not on 443. Set it once here and every host inherits it\n'
    printf '# through the fleet record.\n'
    _knob RELEASE_REPO_URL "https://github.com/wagga40/LogsTotal" "Where ./logstotal upgrade looks for published releases."
  } >"$DEPLOY_ENV_FILE"

  info "Wrote ${DEPLOY_ENV_FILE}"
  info "  control plane : ${CP}"
  if [ "$DEPLOY_HOSTS" != "$CP" ]; then
    info "  workers       : ${DEPLOY_HOSTS#*,}"
  else
    info "  workers       : (none yet — add them to DEPLOY_HOSTS and re-run)"
  fi
}

if [ "$ACTION" = "init" ]; then
  write_deploy_env
  info "Next: edit ${DEPLOY_ENV_FILE}, then './logstotal deploy:plan', then './logstotal deploy'"
  exit 0
fi

# Positional hosts are also a decision to remember them, so every later deploy task
# runs bare. An existing file is never clobbered.
[ "$#" -gt 0 ] && write_deploy_env

deploy_env_load \
  DEPLOY_REMOTE_DIR DEPLOY_BOOTSTRAP DEPLOY_VPN DEPLOY_ONLY DEPLOY_DOMAIN DEPLOY_PROXY_TLS DEPLOY_ACME_EMAIL \
  DEPLOY_BASIC_AUTH_USER DEPLOY_BASIC_AUTH_PASSWORD DEPLOY_BASIC_AUTH_HASH DEPLOY_SKIP_SMOKE \
  DEPLOY_DRY_RUN SSH_IDENTITY

# The rest of what the settings block reports. Most are already loaded above because this
# script acts on them; these it only shows — and a value it did not load reads as unset,
# so the block would report `a default` for a line sitting in deploy.env.
# shellcheck disable=SC2086  # a space-separated key list, deliberately split
deploy_env_load $_CONFIG_REVIEW_KEYS

DEPLOY_BOOTSTRAP="${DEPLOY_BOOTSTRAP:-true}"
# Before step 1 of 8: bootstrap installs WireGuard and opens the hub's port, so an
# undecided fleet has to stop here rather than after that has already happened.
vpn_mode_require_decision
DEPLOY_VPN="$VPN_MODE"
export DEPLOY_VPN
# Say so when a rule softened the request. The child step receives the resolved value and
# cannot tell that anything was decided for it.
[ -n "${VPN_MODE_REASON:-}" ] && info "Private network: not building one — ${VPN_MODE_REASON}."
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-false}"
export DEPLOY_HOSTS DEPLOY_ENV_FILE

printf '\n%s  LogsTotal Fleet Quickstart%s\n\n' "$C_BOLD" "$C_OFF"
# The same block `task deploy:plan` opens with, rather than a second summary of the same
# settings in a different shape. It says where each value came from, which is the half an
# operator needs when the domain in front of them is not the one they edited.
config_review text --settings-only
# Settings that disagree with each other. Never fatal — see deploy_config_review.py — so
# this adds no way for a deploy to stop, only a reason to look before it does not.
_FINDINGS=$(config_review text --findings-only)
[ -n "$_FINDINGS" ] && { printf '\n'; printf '%s\n' "$_FINDINGS"; }
truthy "$DEPLOY_DRY_RUN" && printf '\n  DRY-RUN: nothing will be connected to or written to a host\n'
printf '\n'

# Before anything is installed or rewritten, say what will have to be reachable. This is
# the one moment an operator can still open a port without a failed deploy in between.
network_plan text
printf '\n'

build_ssh_opts

# ── Step 1/8 — local tools ───────────────────────────────────────────────────
#
# Checked here rather than discovered three steps in, when hosts have already been
# stopped. 7z is only needed if a package has to be built.

header "Step 1/8: local tools"
if ! truthy "$DEPLOY_DRY_RUN"; then
  if ! hosts_have_local "$DEPLOY_HOSTS"; then
    require_cmd ssh "Install the OpenSSH client."
    require_cmd scp "Install the OpenSSH client."
  fi
fi
require_task
info "ok"

# ── Step 2/8 — can we even reach these hosts? ────────────────────────────────
#
# DEPLOY_PREFLIGHT_STAGE=pre exists precisely for this position: the fatal preflight alone,
# at step 6 of 8, would run after packages are installed, a WireGuard mesh is built and an
# .env is written to every host — a report filed after the fact, not a gate.
#
# `pre` checks what bootstrap cannot fix — can we reach it, will our commands survive its
# login shell, can we elevate, is its clock sane — and reports a missing docker/task/7z/
# rsync as INFO, because installing those is the very next step's job.
header "Step 2/8: reachability and privilege"
DEPLOY_PREFLIGHT_STAGE=pre bash "$SCRIPT_DIR/deploy-preflight.sh"

# ── Step 3/8 — bootstrap ─────────────────────────────────────────────────────

header "Step 3/8: bootstrap hosts"
if truthy "$DEPLOY_BOOTSTRAP"; then
  bash "$SCRIPT_DIR/deploy-bootstrap.sh"
else
  info "skipped (DEPLOY_BOOTSTRAP is off)"
fi

# ── Step 4/8 — private network ───────────────────────────────────────────────

header "Step 4/8: private network"
bash "$SCRIPT_DIR/deploy-vpn.sh"

# ── Step 5/8 — env files ─────────────────────────────────────────────────────
#
# The bcrypt hash is produced ON THE CONTROL PLANE, over stdin. It always has Docker;
# the operator's laptop may not. Over stdin rather than the documented
# `--plaintext <password>` form because that puts the password in the control plane's
# argv, where every user on the box can read it out of ps.

header "Step 5/8: generate and install env files"
if [ -n "${DEPLOY_BASIC_AUTH_PASSWORD:-}" ] && [ -z "${DEPLOY_BASIC_AUTH_HASH:-}" ]; then
  if truthy "$DEPLOY_DRY_RUN"; then
    info "(dry-run) would hash the basic-auth password on ${CP}"
    # shellcheck disable=SC2016  # a bcrypt hash is literal $ sigils, not expansions
    DEPLOY_BASIC_AUTH_HASH='$2a$14$dry-run-placeholder'
  else
    step "hashing the basic-auth password on ${CP}"
    # printf '%s\n', not '%s': `caddy hash-password` reads a LINE from stdin, so a
    # payload with no trailing newline makes it hit EOF mid-read and exit 1 with
    # "Error: EOF" — which, with stderr discarded, arrives here as an empty capture and
    # reads like "Docker is not running there".
    # Caddy strips the newline before hashing: the result verifies against the password
    # itself, not the password plus a newline (checked with bcrypt.checkpw).
    HASHED=$(printf '%s\n' "$DEPLOY_BASIC_AUTH_PASSWORD" | host_exec "$CP" "docker run --rm -i caddy:2-alpine caddy hash-password" 2>/dev/null | tr -d '\r' | tail -1 | tr -d '[:space:]' || true)
    # A failure here is FATAL. Carrying on without it would deploy a control plane the
    # operator believes is behind HTTP auth and which is not — the deploy would report
    # success, the smoke check would pass, and the only sign would be one warning in a
    # thousand lines of output. An explicitly requested access control that cannot be
    # established stops the deploy; it never silently downgrades.
    # shellcheck disable=SC2016  # bcrypt prefixes are literal $ sigils, not expansions
    case "$HASHED" in
      '$2a$'* | '$2b$'* | '$2y$'*) ;;
      '')
        die "Could not hash the basic-auth password on ${CP}. Nothing was deployed.\nSee the reason by running it there by hand:  ssh ${CP} \"printf '%s\\n' <password> | docker run --rm -i caddy:2-alpine caddy hash-password\"\nOr supply DEPLOY_BASIC_AUTH_HASH yourself." ;;
      *)
        # Do not print $HASHED: whatever it is, it came from a command fed the password.
        die "The basic-auth hash returned by ${CP} is not bcrypt. Nothing was deployed. Run it by hand to see what happened:  docker run --rm -i caddy:2-alpine caddy hash-password" ;;
    esac
    DEPLOY_BASIC_AUTH_HASH="$HASHED"
    info "hashed (the plaintext is never written anywhere)"
  fi
fi
export DEPLOY_BASIC_AUTH_HASH="${DEPLOY_BASIC_AUTH_HASH:-}"
export DEPLOY_BASIC_AUTH_USER="${DEPLOY_BASIC_AUTH_USER:-}"
# Generating the files and installing them where they are read is ONE job: split, nothing
# would push them, and a fleet would get as far as `env_file: .env` and stop.
bash "$SCRIPT_DIR/deploy-env-fleet.sh"
bash "$SCRIPT_DIR/deploy-env-push.sh"

# ── Step 6/8 — preflight ─────────────────────────────────────────────────────

# The fatal one. Step 2 asked whether these hosts can be worked with at all; this asks
# whether they are now ready, with the tools bootstrap was supposed to install.
header "Step 6/8: preflight"
DEPLOY_PREFLIGHT_STAGE=post bash "$SCRIPT_DIR/deploy-preflight.sh"

# ── Step 7/8 — package and deploy ────────────────────────────────────────────
#
# The unchanged five-phase deploy: stop workers first, stage, start the control plane
# behind its health gate, then the workers.
#
# The two scripts are called DIRECTLY rather than through a `task` re-entry: re-entering
# go-task to sequence two scripts this one already has in hand buys nothing and costs a
# dependency on the Taskfile of whatever tree is installed, which during an upgrade is not
# necessarily this one.

header "Step 7/8: package and deploy"
# VERSION= / ARCHIVE= reach the package gate through the environment, so
# `task deploy VERSION=1.0.0` installs the PUBLISHED release rather than a repackaging of
# whatever tree this happens to be. Exported rather than passed, because the gate runs as
# its own process between here and the deploy.
[ -n "${VERSION:-}" ] && export VERSION
[ -n "${ARCHIVE:-}" ] && export ARCHIVE
export DEPLOY_STOP="${DEPLOY_STOP:-true}"
export DEPLOY_KEEPENV="${DEPLOY_KEEPENV:-true}"
export DEPLOY_START="${DEPLOY_START:-true}"
bash "$SCRIPT_DIR/deploy-package-gate.sh"
DEPLOY_ACTION=deploy bash "$SCRIPT_DIR/deploy-multiserver.sh"

# ── Step 8/8 — smoke ─────────────────────────────────────────────────────────

header "Step 8/8: smoke"
# Whether anything actually confirmed the fleet answers. The closing banner says "is up",
# which is a claim, and must not be made when this step was skipped or could not measure.
FLEET_VERIFIED=no
if truthy "${DEPLOY_SKIP_SMOKE:-false}"; then
  info "skipped (DEPLOY_SKIP_SMOKE)"
else
  # Caddy binds WEB_PORT to loopback, so http://host:8000 stops answering the moment
  # HTTPS is on and the smoke check has to be told the domain. Basic auth turns every
  # probe into a 401 unless it can authenticate — a healthy fleet would report
  # SMOKE FAILED. The plaintext is exported for this process only, never written down.
  # Step 8 gated on the control plane's own /health, probed from the host itself. So an
  # unreachable endpoint HERE is a fact about the route from this machine, not an outage —
  # see the note at deploy-smoke.sh's /health probe.
  export DEPLOY_HEALTH_CONFIRMED=true
  [ -n "${DEPLOY_DOMAIN:-}" ] && export DOMAIN="$DEPLOY_DOMAIN"
  if [ -n "${DEPLOY_BASIC_AUTH_USER:-}" ] && [ -n "${DEPLOY_BASIC_AUTH_PASSWORD:-}" ]; then
    export BASIC_AUTH_USER="$DEPLOY_BASIC_AUTH_USER"
    export BASIC_AUTH_PASS="$DEPLOY_BASIC_AUTH_PASSWORD"
  fi
  # Exit 2 is "could not measure" (basic auth, no credentials), not "the fleet is broken";
  # under `set -e` it would abort step 8/8 on a fleet just deployed correctly. Exit 1 still
  # stops everything, because that one was measured.
  # DEPLOY_SMOKE_STRICT so this can tell verified from unverified. Without it an auth-walled
  # fleet exits 0 — correct for a human running the task, and here it would make the closing
  # banner claim "fleet is up" about a URL nothing ever fetched.
  SMOKE_RC=0
  DEPLOY_SMOKE_STRICT=true bash "$SCRIPT_DIR/deploy-smoke.sh" || SMOKE_RC=$?
  if [ "$SMOKE_RC" -eq 0 ]; then
    FLEET_VERIFIED=yes
  elif [ "$SMOKE_RC" -ne 2 ]; then
    exit "$SMOKE_RC"
  fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────

URL="http://${CP#*@}:8000"
is_local_host "${CP#*@}" && URL="http://localhost:8000"
# The scheme follows how the proxy actually terminates TLS. Printing https:// for a
# PROXY_TLS=off deployment hands the operator a URL that refuses the connection, at the one
# moment they are most likely to believe the deploy failed.
if [ -n "${DEPLOY_DOMAIN:-}" ]; then
  if [ "${DEPLOY_PROXY_TLS:-acme}" = "off" ]; then
    URL="http://${DEPLOY_DOMAIN}"
  else
    URL="https://${DEPLOY_DOMAIN}"
  fi
fi
CP_ENV_FILE="${DEPLOY_ENV_DIR:-deploy-envs}/$(printf '%s' "${CP#*@}" | sed 's/[^A-Za-z0-9._-]/_/g').env"
ADMIN_EMAIL_LINE=$(grep -E "^ADMIN_EMAIL=" "$CP_ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true)

printf '\n'
printf '════════════════════════════════════════════════════════════\n'
if [ "$FLEET_VERIFIED" = "yes" ]; then
  printf '  LogsTotal fleet is up:  %s\n' "$URL"
else
  # Everything above succeeded, but nothing fetched this URL. Saying "is up" would be an
  # assertion about a server nobody asked — and it is printed at the exact moment an
  # operator stops checking.
  printf '  LogsTotal fleet is deployed:  %s\n' "$URL"
  printf '  (not verified — the smoke step did not confirm this URL answers)\n'
fi
[ -n "$ADMIN_EMAIL_LINE" ] && printf '  Admin login:            %s\n' "$ADMIN_EMAIL_LINE"
printf '  Password:               ENV_FILE=%s ./logstotal show-admin-password\n' "$CP_ENV_FILE"
printf '\n'
printf '  Next steps:\n'
printf '    ./logstotal deploy:status                # compose ps + /health on every host\n'
printf '    %s/admin/workers   # confirm every worker registered\n' "$URL"
printf '    ./logstotal recommend-scaling            # size each worker host\n'
printf '\n'
printf '  Going further:\n'
printf '    HTTPS:        DEPLOY_DOMAIN=logs.example.com DEPLOY_ACME_EMAIL=you@example.com ./logstotal deploy\n'
printf '    Internal TLS: DEPLOY_DOMAIN=logs.internal DEPLOY_PROXY_TLS=internal ./logstotal deploy   # no DNS, no internet\n'
if [ "$DEPLOY_VPN" = "wireconf" ]; then
  printf '    Ports needed: ./logstotal deploy:network\n'
else
  printf '    Private net:  DEPLOY_VPN=wireconf ./logstotal deploy   # relays move onto a tunnel\n'
fi
printf '    Add a worker: append it to DEPLOY_HOSTS, then DEPLOY_ONLY=<host> ./logstotal deploy\n'
printf '    Upgrades:     ./logstotal upgrade\n'
printf '════════════════════════════════════════════════════════════\n'
