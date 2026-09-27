# shellcheck shell=bash
#
# Shared shell helper library for LogsTotal's scripts/*.sh.
#
# Sourced by scripts/*.sh; do not execute directly. Assumes the caller's cwd
# is the repo root (matches how Taskfile.yml invokes every script).
#
# No `set -euo pipefail` here — a sourced file must never mutate the caller's
# shell options; each script that sources this sets its own.

[ -n "${_LT_COMMON_SH:-}" ] && return 0
_LT_COMMON_SH=1

# ── The libraries that travel with this one ──────────────────────────────────
#
# _LT_LIB_DIR, not `dirname "${BASH_SOURCE[0]}"` inline, and the fallback is the whole
# point: BASH_SOURCE is a bashism, and go-task runs every `cmds:` line under mvdan/sh,
# which does not provide it. Several tasks do `. scripts/lib/common.sh` directly — there
# `${BASH_SOURCE[0]}` expands to nothing, `dirname ""` gives `.`, and the three files below
# would be looked for in the REPO ROOT. A failed `source` does not stop the shell, so that
# fails silently: three "no such file" lines, then no verdict, install or fleet helpers.
#
# The fallback is this file's own documented contract, stated in the header above: every
# caller runs from the repo root.
_LT_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-scripts/lib/common.sh}")" && pwd)

# ── Colour ───────────────────────────────────────────────────────────────────
#
# Resolved once, at source time, and every escape in every script goes through these: a
# TTY, no NO_COLOR, TERM not dumb. The Python half reads the answer rather than re-deriving
# it — LT_COLOR below is what scripts/cli_color.py consults first — because only the shell
# sees whether the operator redirected anything; sys.stdout.isatty() in a subprocess is the
# wrong question.
#
# The gate is not cosmetic: ungated, escape codes go into pipes, redirected log files and
# CI transcripts, and `deploy:plan > plan.txt` produces a file no one can read. It is also
# what keeps the test suite honest: the ~500 stdout assertions across tests/test_deploy_*.py
# run under `capture_output=True`, which is not a TTY, so every one of them matches plain text.
#
# Empty strings rather than an `echo -e` wrapper, so a format string reads the same in
# both modes and a caller cannot forget to reset.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
  C_BOLD=$'\033[1m'
  C_OFF=$'\033[0m'
  LT_COLOR=always
else
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_BLUE=''
  C_CYAN=''
  C_BOLD=''
  C_OFF=''
  LT_COLOR=never
fi
# LT_COLOR is passed to the Python helpers so ONE decision covers the whole run: a shell
# gate and an isatty() inside a subprocess can disagree, and the subprocess is the one
# that cannot see the caller's redirection.
export LT_COLOR

# The verdict vocabulary (PASS / FAIL / UNKNOWN / UNKNOWN-blocking) lives in its own file
# because it is a contract several scripts share — see its header.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=verdict.sh
. "${_LT_LIB_DIR}/verdict.sh"

# How a release lands on a host — staging, the overlay exclude list, and the run-dir pin.
# Its own file because the rule it enforces (never write over a tree something is reading)
# needs its reasoning kept next to it.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=install.sh
. "${_LT_LIB_DIR}/install.sh"

# The control plane's record of its own fleet. Sourced LAST of the three, because
# fleet_record_intent calls read_version_file and release_repo_url from this file.
#
# NOT lib/fleet.sh: scripts/fleet.sh is the dispatcher, and a shared basename makes the
# `source=` directive below resolve back to whichever file the check started from — which
# it then follows forever — `task lint:shell` hangs rather than failing.
#
# (A comment line here may not BEGIN with the linter's own name either: it reads that as a
# directive and fails to parse it.)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=fleet_record.sh
. "${_LT_LIB_DIR}/fleet_record.sh"

# ── Logging ──────────────────────────────────────────────────────────────────
# ERROR/WARN/>>>/header are bold, and every colour goes through the gate above.

die() { printf '%sERROR:%s %s\n' "${C_BOLD}${C_RED}" "$C_OFF" "$*" >&2; exit 1; }
info() { printf '%s>>>%s %s\n' "${C_BOLD}${C_BLUE}" "$C_OFF" "$*"; }
warn() { printf '%sWARN:%s %s\n' "${C_BOLD}${C_YELLOW}" "$C_OFF" "$*" >&2; }
header() { printf '\n%s========== %s ==========%s\n' "${C_BOLD}${C_CYAN}" "$*" "$C_OFF"; }
step() { printf '%s--- %s ---%s\n' "$C_CYAN" "$*" "$C_OFF"; }

# value VAL — one operator-facing value (a host, a domain, a version, a port), emphasised
# where it is introduced, so a plan naming three domains and two versions does not bury
# them in grey prose.
value() { printf '%s%s%s' "$C_BOLD" "$1" "$C_OFF"; }

# ok MSG — a step that FINISHED. `info` says what is being attempted; this says it worked.
#
# The distinction is load-bearing in a script that prints a dozen lines before it can fail:
# `>>> docker compose build` and `✓ docker compose build` are the difference between "this
# is where it hung" and "this is where it got to".
#
# A symbol here, where the verdict labels deliberately have none: `OK   ` in verdict.sh is a
# COLUMN, and a glyph ahead of it would widen every line in the block. This is prose, not a
# column, so the mark is free.
ok() { printf '%s✓%s %s\n' "${C_BOLD}${C_GREEN}" "$C_OFF" "$*"; }

# note MSG [DETAIL...] — an advisory. Not a warning: nothing is wrong.
#
# The separation matters because `warn` goes to stderr and is the thing an operator is
# trained to act on. "This archive ships the Play CDN bundle" is neither — it is a fact
# about what you just built, and printing it as WARN teaches people to ignore WARN.
# Continuation lines are indented under the label.
note() {
  printf '%sNOTE:%s %s\n' "$C_CYAN" "$C_OFF" "$1"
  shift
  local line
  for line in "$@"; do printf '      %s\n' "$line"; done
}

# ── The closing banner ───────────────────────────────────────────────────────
#
# The "you are done, here is your URL" block, shared by deploy fleet, quickstart and upgrade.
# The URL, the admin account and the password hint are the only reason the block exists, so
# they must not read in the same grey as the prose around them.
#
# Open/close rather than one `banner LINES...` call: the bodies are conditional (a fleet
# that was not verified says so; a rollback says the database was not touched), and a dozen
# conditionally-built lines passed through "$@" is unreadable at the call site.
_LT_RULE='════════════════════════════════════════════════════════════'
banner_open() { printf '\n%s%s%s\n' "$C_CYAN" "$_LT_RULE" "$C_OFF"; }
banner_close() { printf '%s%s%s\n' "$C_CYAN" "$_LT_RULE" "$C_OFF"; }

# kv LABEL VALUE — one aligned `Label:   value` line inside a banner.
#
# The pad is 22 columns, which is the widest label any of the three banners uses
# ("LogsTotal fleet is deployed"'s siblings), so no call site has to know the width. The
# value goes through `value` — an operator scanning a wall of text for a URL should not
# have to read the prose to find it.
kv() {
  local label="$1"
  shift
  printf '  %-22s %s\n' "${label}:" "$(value "$*")"
}

# truthy VAL — returns 0 for exactly 1/true/TRUE/yes/YES/on/ON; mixed case (`True`,
# `Yes`) does NOT match. Byte-identical to the copy in scripts/deploy-multiserver.sh.
truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

# ── SSH ──────────────────────────────────────────────────────────────────────

# build_ssh_opts — fills the global SSH_OPTS array, prepending -i "$SSH_IDENTITY"
# when SSH_IDENTITY is set and non-empty.
#
# A leading ~ is expanded here because SSH_IDENTITY usually arrives from deploy.env,
# which is read with grep/cut and never sees a shell — so `SSH_IDENTITY=~/.ssh/id_ed25519`
# (the form the docs show) would stay literal, ssh could not open it, and the connection
# would silently fall back to agent/default keys and fail further along. A set-but-missing
# identity is a config error, so say so here rather than three steps later. Mirrors the
# same handling in the self-contained scripts/deploy-multiserver.sh.
build_ssh_opts() {
  # shellcheck disable=SC2034  # consumed by sourcing scripts
  # RequestTTY=no is not cosmetic. An operator whose ~/.ssh/config sets `RequestTTY yes`
  # gets a PTY on every one of these calls, and a PTY does two things that break this
  # tooling silently: it turns the remote command's output into CRLF, so every value
  # captured back arrives with a trailing \r (so `ID=ubuntu` stops matching `ubuntu` and a
  # supported OS reports itself as unknown), and it makes the remote stdin a terminal, so
  # piping a password into a command that reads stdin does not reach it.
  #
  # RemoteCommand=none is the same class of defence. An ~/.ssh/config entry carrying
  # `RemoteCommand fish` (a normal thing to write for a host you also log into by hand)
  # makes ssh refuse outright — "Cannot execute command-line and remote command." —
  # because we always pass a command. scp accepts the option too.
  #
  # ServerAlive* bounds a session that CONNECTS AND THEN STALLS, which ConnectTimeout
  # cannot: that one only covers the TCP handshake. A stateful firewall dropping the
  # return path leaves an established channel that never speaks again, and without these
  # the deploy waits forever. 15s × 4
  # gives up after ~60s.
  #
  # Connection multiplexing, because this tooling is chatty by design: the preflight
  # alone makes about fifteen round trips per host, and a fresh handshake to a distant host
  # measured 1.29s against 0.42s over an existing master — 68s of a three-host
  # `task deploy:plan` spent on TCP and key exchange. ControlMaster=auto starts one master
  # per host and reuses it; if the master dies the next call simply opens its own, so this
  # never costs more than not multiplexing.
  #
  # %C is a hash of (host, port, user, local host): unique per destination, and short.
  # ControlPersist keeps the master briefly after the last call so the consecutive
  # scripts in one deploy share it, without leaving sockets around indefinitely.
  #
  # /tmp, deliberately NOT $TMPDIR: a unix socket path is capped at 104 bytes, and on
  # macOS $TMPDIR is a ~50-character /var/folders/... path which the 40-char %C hash
  # pushes straight past it. ssh then fails every connection with "ControlPath too long".
  # The length is re-checked below anyway, because being wrong about this breaks everything
  # rather than slowing
  # it down: over budget, we simply go without multiplexing.
  local cm_dir cm_path cm_uid
  cm_uid=$(id -u 2>/dev/null || echo 0)
  cm_dir="/tmp/.lt-ssh-${cm_uid}"
  cm_path="${cm_dir}/%C"
  if [ "${#cm_path}" -gt 90 ] || ! mkdir -p "$cm_dir" 2>/dev/null; then
    cm_path=""
  else
    chmod 700 "$cm_dir" 2>/dev/null || true
  fi

  SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o RequestTTY=no
    -o RemoteCommand=none -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
  if [ -n "$cm_path" ]; then
    SSH_OPTS+=(-o ControlMaster=auto -o "ControlPath=${cm_path}" -o ControlPersist=60s)
  fi
  if [ -n "${SSH_IDENTITY:-}" ]; then
    # The pattern must stay quoted: tilde expansion applies to an unquoted case
    # pattern, so `~/*` would become `$HOME/*` and never match a literal `~/...`.
    # shellcheck disable=SC2088  # literal tilde is the intent — this matches, not expands
    case "${SSH_IDENTITY}" in
      "~/"*) SSH_IDENTITY="${HOME}/${SSH_IDENTITY#\~/}" ;;
    esac
    [ -f "$SSH_IDENTITY" ] || die "SSH_IDENTITY is not a file: $SSH_IDENTITY"
    # shellcheck disable=SC2034  # consumed by sourcing scripts
    SSH_OPTS=(-i "$SSH_IDENTITY" "${SSH_OPTS[@]}")
  fi
}

# to_target HOST — root@HOST for a bare host; passthrough when HOST already
# contains an `@` (never double-prefixed to root@user@host).
to_target() {
  case "$1" in
    *@*) echo "$1" ;;
    *)   echo "root@$1" ;;
  esac
}

# first_host — the control-plane host: the first entry in DEPLOY_HOSTS.
first_host() {
  printf '%s' "$DEPLOY_HOSTS" | cut -d',' -f1 | xargs
}

# ── Local vs remote execution ────────────────────────────────────────────────
#
# A DEPLOY_HOSTS entry may be the literal `local`, meaning "this machine" — which is
# what lets the whole deploy run from the control plane itself instead of a laptop.
#
# The alternative was to require SSH-to-self. That asks a fresh box for a keypair, a
# self-entry in authorized_keys, a PermitRootLogin compatible with BatchMode, and a
# listening sshd — four independent ways for step one to fail, all to avoid the
# branching below. It also breaks the common shape where the operator is a non-root
# user with sudo -n and no root SSH at all.
#
# `local` and not `localhost`: localhost is a legitimate SSH target someone may really
# mean, and every mDNS name (`cp.local`) carries a dot, so the bare token cannot collide.

# is_local_host HOST — 0 iff HOST is the `local` sentinel.
is_local_host() {
  [ "${1:-}" = "local" ]
}

# hosts_from_args ARG... — a comma-separated host list built from positional arguments,
# or "" when there are none.
#
# Every entry is validated character by character before it is joined. These strings end
# up inside `ssh <target> bash -c ...`, and `task deploy:status -- 'cp; rm -rf /'` must be
# a refusal that names the offender rather than a command someone runs.
#
# Positionals exist because a go-task `env:` bridge cannot carry a host list: go-task
# never exports a CLI variable to the shell, so `task deploy:status DEPLOY_HOSTS=cp,w1`
# does not reach the script — and with a deploy.env present it does not abort either, it
# acts on THE FLEET NAMED IN THAT FILE.
hosts_from_args() {
  [ "$#" -gt 0 ] || { printf ''; return 0; }
  local arg
  for arg in "$@"; do
    case "$arg" in
      *[!A-Za-z0-9._@-]*) die "Not a host: '${arg}'. Entries are host, user@host, or local." ;;
    esac
  done
  ( IFS=,; printf '%s' "$*" )
}

# hosts_have_local LIST — 0 iff a comma-separated host LIST contains the `local` entry.
#
# Entry-wise, never a substring: `case "$LIST" in *local*)` would match
# `mylocalbox.example.com` and silently skip deploy-fleet.sh's ssh/scp requirement for a
# fleet that needs both. Commas are added on each side so the first and last entries
# match the same pattern as the middle ones, and surrounding spaces are stripped because
# `deploy.env` is read by grep+cut and a hand-edited list may carry them.
hosts_have_local() {
  local list
  list=$(printf '%s' "${1:-}" | tr -d '[:space:]')
  case ",${list}," in
    *,local,*) return 0 ;;
  esac
  return 1
}

# shquote STR — STR wrapped in single quotes, safe to paste into a command line.
#
# This exists because `ssh host CMD` runs CMD through the REMOTE LOGIN SHELL, which is
# not necessarily a POSIX one — fish, for instance, rejects a bare `rc=$?` outright
# ("Unsupported use of '='").
#
# Single-quote escaping is the one form that survives both: POSIX closes-escapes-reopens
# with '\'' and fish reads the same bytes as quote, literal-quote, quote. Verified
# against real fish, including a payload containing an apostrophe.
shquote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# host_exec HOST CMD... — run CMD on HOST: over SSH, or directly for the `local`
# sentinel. DEPLOY_DRY_RUN traces instead of executing, making no connections.
#
# The local branch is `bash -c "$*"` rather than `"$@"` because that is exactly ssh's
# own semantics: ssh joins its argv with spaces and hands the result to the remote
# login shell. Uniform joining is what lets all three existing call shapes work with
# no per-call-site branching — `host_exec h true`, `host_exec h "mkdir -p /opt/x"`
# (which `"$@"` would try to exec as a binary named `mkdir -p /opt/x`), and
# `host_exec h bash -s <<EOS`, where the inner `bash -s` inherits the heredoc.
#
# The remote branch wraps that joined string in `bash -c` for the reason shquote
# documents: ssh hands it to the remote LOGIN shell, which may be fish. Both branches force
# bash, so a bash-only construct behaves the same on a `local` host as on a real one,
# whatever shell the account happens to have.
#
# Deliberately NOT adding -n or </dev/null here: `host_exec h bash -s <<EOS` (12 call
# sites) and the password pipe in deploy-fleet.sh both need the caller's stdin to reach
# the remote command, and closing it would make them fail silently by returning 0 over
# an empty read. No stdin-consumption bug exists to justify it — every host loop in this
# tree iterates a $(...) word list, not a stream.
#
# shellcheck disable=SC2029  # remote-side expansion is the intent, as in ssh's own contract
host_exec() {
  local host=$1
  shift
  if truthy "${DEPLOY_DRY_RUN:-}"; then
    if is_local_host "$host"; then
      printf 'DRY-RUN local: %s\n' "$*"
    else
      printf 'DRY-RUN ssh %s: %s\n' "$(to_target "$host")" "$*"
    fi
    return 0
  fi
  if is_local_host "$host"; then
    bash -c "$*"
  else
    ssh "${SSH_OPTS[@]}" "$(to_target "$host")" bash -c "$(shquote "$*")"
  fi
}

# host_copy_to SRC HOST DEST — copy a local file to HOST.
host_copy_to() {
  local src=$1 host=$2 dest=$3
  if truthy "${DEPLOY_DRY_RUN:-}"; then
    if is_local_host "$host"; then
      printf 'DRY-RUN copy %s -> local:%s\n' "$src" "$dest"
    else
      printf 'DRY-RUN scp %s -> %s:%s\n' "$src" "$(to_target "$host")" "$dest"
    fi
    return 0
  fi
  if is_local_host "$host"; then
    cp "$src" "$dest"
  else
    scp "${SSH_OPTS[@]}" "$src" "$(to_target "$host"):${dest}"
  fi
}

# host_copy_from HOST SRC DEST — copy a file off HOST to a local path.
host_copy_from() {
  local host=$1 src=$2 dest=$3
  if truthy "${DEPLOY_DRY_RUN:-}"; then
    if is_local_host "$host"; then
      printf 'DRY-RUN copy local:%s -> %s\n' "$src" "$dest"
    else
      printf 'DRY-RUN scp %s:%s -> %s\n' "$(to_target "$host")" "$src" "$dest"
    fi
    return 0
  fi
  if is_local_host "$host"; then
    cp "$src" "$dest"
  else
    scp "${SSH_OPTS[@]}" "$(to_target "$host"):${src}" "$dest"
  fi
}

# host_capture HOST CMD — run CMD on HOST and return its output as one clean line.
# Strips CR (a forced PTY yields CRLF) and surrounding whitespace, and never fails:
# every caller treats an empty answer as "could not determine".
host_capture() {
  local host=$1 cmd=$2 out=""
  out=$(host_exec "$host" "$cmd" 2>/dev/null | tr -d '\r' | head -1 || true)
  printf '%s' "$out" | xargs 2>/dev/null || printf '%s' "$out"
}

# host_number HOST CMD — CMD's output as a bare integer, or the literal `?` when it
# could not be measured (host unreachable, command missing, empty or non-numeric reply).
#
# The `?` is the whole point. Testing an empty capture with `[ -n "$v" ] && [ "$v" -lt
# LIMIT ]` skips the comparison, so a probe that returned nothing prints OK for a host it
# never measured — "OK disk space" about a box it could not reach. A distinct sentinel forces
# every caller to decide, and "could not measure" is a FAIL, not a pass.
host_number() {
  local out
  out=$(host_capture "$1" "$2")
  case "$out" in
    '' | *[!0-9]*) printf '?' ;;
    *) printf '%s' "$out" ;;
  esac
}

# ── Artifact integrity ───────────────────────────────────────────────────────
#
# Without it, a release archive is fetched with `curl -fL` and extracted, and the only thing
# standing between a host and someone else's bytes is TLS to the release server — which an
# operator carrying a file on a USB stick does not have at all.
#
# What a checksum does and does not prove is worth being precise about, because overstating
# it is worse than having none: it detects a TRUNCATED OR CORRUPTED transfer, and it detects
# tampering ONLY if the checksum reached you by a path the tamperer did not control. A
# `.sha256` sitting beside the archive on the same server proves the download completed; it
# proves nothing about the server. Signing is the answer to that, and this is not it.

# file_sha256 PATH — the digest, using whichever tool this platform has.
file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# verify_sha256 FILE EXPECTED — 0 if it matches, 1 if not. Prints its verdict.
verify_sha256() {
  local file="$1" expected="$2" got
  got=$(file_sha256 "$file")
  if [ "$got" = "$expected" ]; then
    ok "sha256 OK: $(basename "$file")"
    return 0
  fi
  warn "sha256 MISMATCH for $(basename "$file")"
  echo "       expected ${expected}"
  echo "       got      ${got}"
  return 1
}

# verify_downloaded_artifact FILE URL — check FILE against <URL>.sha256, when one exists.
#
# A missing checksum is NOT a failure. Older releases have none, and refusing those would
# break every older pin. It says so
# instead — the deploy vocabulary's UNKNOWN, in prose.
verify_downloaded_artifact() {
  local file="$1" url="$2" expected
  command -v curl >/dev/null 2>&1 || return 0
  expected=$(curl -fsSL --max-time 20 "${url}.sha256" 2>/dev/null | cut -d' ' -f1 || true)
  if [ -z "$expected" ]; then
    note "no ${url##*/}.sha256 published — the download was not checked."
    return 0
  fi
  verify_sha256 "$file" "$expected" || die "the downloaded archive does not match its published
       checksum. That is a corrupted or truncated transfer, or a file that is not the one
       published. Do not deploy it. Re-run to download again."
}

# ── Release snapshots ────────────────────────────────────────────────────────
#
# SNAPSHOT_ROOT — where a rollback point lives, relative to an install directory.
#
# ONE layout, everywhere. On a control plane the single-host and fleet flows run on the same
# machine, and upgrades run FROM the control plane, so two layouts would send
# `task upgrade:rollback` and the fleet rollback looking in two directories for one thing.
#
# backups/ is the right parent: it is
# already in .gitignore, .dockerignore, package.sh's excludes, verify-artifacts.sh and
# every rsync exclude, so a snapshot cannot be committed, imaged or shipped. And
# `backup:prune` cannot eat these — it deletes `find backups -maxdepth 1 -type f`, i.e.
# depth-1 FILES, while these are directories one level deeper.
#
# The name carries the version because <stamp> alone cannot say which release it holds,
# which is the first thing anyone asks of a rollback point.
# shellcheck disable=SC2034  # read by the scripts that source this file, not by it.
SNAPSHOT_ROOT="backups/releases"

# snapshot_excludes — everything that is not "the code of this release", one list.
#
# A code snapshot has no business carrying `certs/` or `deploy-envs/`: on a control plane
# every rollback point would otherwise be a copy of the TLS private key and the fleet's
# generated env files — DEPLOY_KEEP_RELEASES of them, indefinitely.
#
# `releases` is in the list because the fleet keeps its snapshots inside the install
# directory; on a single host they live under backups/, which is excluded anyway.
snapshot_excludes() {
  printf '%s\n' \
    --exclude=.env --exclude=.env.deploy.sha256 --exclude=data --exclude=uploads --exclude=backups \
    --exclude=.bundle --exclude=certs --exclude=deploy-envs --exclude=deploy.env \
    --exclude=releases --exclude=fleet \
    --exclude=.git --exclude=.venv --exclude=.bin --exclude=docker-compose.override.yml --exclude=node_modules \
    --exclude=logs --exclude=testkit --exclude=tools/tailwind \
    --exclude='*.db' --exclude='logstotal-*.7z' \
    --exclude=__pycache__ --exclude='*.pyc' --exclude=.pytest_cache --exclude=.ruff_cache
}

# snapshot_exclude_args — the same list as one shell-quoted string, for pasting into a
# remote command. Each item is quoted individually so `--exclude=*.db` reaches the remote
# rsync as a pattern rather than being globbed by either shell on the way.
snapshot_exclude_args() {
  local out="" e
  while IFS= read -r e; do
    out="${out} $(shquote "$e")"
  done <<EOF
$(snapshot_excludes)
EOF
  printf '%s' "${out# }"
}

# is_ipv4 VALUE — a bare dotted-quad, which is what Docker needs for a port binding
# and what a worker needs in a connection URL.
is_ipv4() {
  case "${1:-}" in
    "" | *[!0-9.]*) return 1 ;;
  esac
  local IFS=. parts
  read -r -a parts <<< "$1"
  [ "${#parts[@]}" -eq 4 ] || return 1
  local octet
  for octet in "${parts[@]}"; do
    [ -n "$octet" ] || return 1
    [ "$octet" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

# host_primary_address HOST — the IPv4 address HOST would use to reach the internet,
# i.e. the one on its default route. The best single answer to "where is this host".
host_primary_address() {
  host_capture "$1" "ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \\([0-9.]*\\).*/\\1/p'"
}

# host_addresses HOST — every global IPv4 address HOST holds, one per line.
host_addresses() {
  host_exec "$1" "ip -4 -o addr show scope global 2>/dev/null | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null | tr -d '\r' || true
}

# resolve_from HOST NAME — what NAME resolves to as seen FROM HOST. That is the
# question that matters for a worker reaching the control plane: the operator's laptop
# may resolve a name its workers cannot, or resolve it to a different address.
resolve_from() {
  host_capture "$1" "getent ahostsv4 $2 2>/dev/null | awk 'NR==1{print \$1}'"
}

# ── Host OS ──────────────────────────────────────────────────────────────────

# os_release_field KEY TEXT — one value out of an /etc/os-release body, unquoted.
os_release_field() {
  printf '%s\n' "$2" | tr -d '\r' | sed -n "s/^$1=//p" | head -1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//"
}

# os_release_verdict LABEL TEXT — say whether LABEL's OS is one LogsTotal is tested on,
# given that host's /etc/os-release body. Prints exactly one line and always exits 0.
#
# It warns and continues, deliberately, matching app/system_checks.py::check_host_os.
# Refusing an untested distro turns a probably-fine deployment into a support ticket;
# saying nothing is how "it worked on my Fedora box until it didn't" happens with no
# clue anywhere in the output.
os_release_verdict() {
  local label="$1" release="$2" id like pretty
  if [ -z "$release" ]; then
    warn "${label}: could not read /etc/os-release — cannot confirm a tested OS (Ubuntu/Debian). Continuing."
    return 0
  fi
  id=$(os_release_field ID "$release" | tr '[:upper:]' '[:lower:]')
  like=$(os_release_field ID_LIKE "$release" | tr '[:upper:]' '[:lower:]')
  pretty=$(os_release_field PRETTY_NAME "$release")
  [ -n "$pretty" ] || pretty=$(os_release_field NAME "$release")
  [ -n "$pretty" ] || pretty="unknown Linux"
  case "$id" in
    ubuntu | debian)
      info "${label}: OS ${pretty} (tested)"
      return 0
      ;;
  esac
  case " ${like} " in
    *" debian "*)
      info "${label}: OS ${pretty} (Debian-like — close to the tested set, not exercised)"
      return 0
      ;;
  esac
  warn "${label}: OS ${pretty} — LogsTotal is tested on Ubuntu and Debian only. Continuing; if something breaks, report it naming this OS."
}

# ── Config ───────────────────────────────────────────────────────────────────

# deploy_env_default KEY — value of KEY from $DEPLOY_ENV_FILE (default deploy.env),
# or nothing if the file is missing. Callers do VAR="${VAR:-$(deploy_env_default VAR)}"
# so caller env always wins over the file.
#
# The trailing `|| true` is load-bearing: an absent key makes grep exit 1, and under
# `set -o pipefail` that becomes the pipeline's status, so `v=$(deploy_env_default X)`
# kills the calling script before it prints anything.
deploy_env_default() {
  local key="$1" file="${DEPLOY_ENV_FILE:-deploy.env}"
  [ -f "$file" ] || return 0
  grep -E "^${key}=" "$file" | head -1 | cut -d'=' -f2- || true
}

# deploy_env_load KEY... — export each KEY from $DEPLOY_ENV_FILE unless it is already
# set in the caller's environment. Set-but-empty counts as set, so caller env always
# wins (the `${!key+x}` test).
#
# An explicit key list rather than exporting every line in the file: exporting whatever it
# holds would let a stray PATH= or LD_PRELOAD= in deploy.env silently reconfigure the
# deploy, and an indented key abort the script with a raw `invalid variable name` from
# bash. Keys that are absent or empty are left
# unset — every consumer reads them as ${VAR:-default}, where the two are the same thing.
deploy_env_load() {
  local key val
  : "${DEPLOY_ENV_FILE:=deploy.env}"
  for key in "$@"; do
    if [ -n "${!key+x}" ]; then
      _deploy_env_record_source "$key" "the environment"
      continue
    fi
    val=$(deploy_env_default "$key")
    if [ -n "$val" ]; then
      # The basename: provenance answers "which source", and DEPLOY_ENV_FILE is an
      # absolute path in every test and on any machine driving more than one fleet, which
      # would put a 60-character temp path in the middle of every settings row.
      _deploy_env_record_source "$key" "${DEPLOY_ENV_FILE##*/}"
    else
      # Then the fleet record — last, so explicit configuration always wins. This is what lets
      # a bare `task upgrade` work on a control plane that was deployed TO rather than FROM,
      # where there is no deploy.env because it belongs to whoever ran the deploy.
      val=$(fleet_env_default "$key" 2>/dev/null || true)
      [ -n "$val" ] && _deploy_env_record_source "$key" "the fleet record"
    fi
    [ -n "$val" ] || continue
    export "${key}=${val}"
  done
}

# Where each loaded key's value came from, recorded as it is resolved rather than
# re-derived afterwards.
#
# Re-deriving is not possible: deploy_env_load EXPORTS what it finds, so a second pass
# sees every key as "already in the environment" and reports the file's own values as
# having come from the caller. The provenance column on the settings block is most of its
# worth — a domain you cannot explain is a domain you cannot fix — so it has to be
# captured at the one moment the answer is still knowable.
#
# First write wins, matching the resolution order: a key loaded twice was already settled
# by the first call.
_DEPLOY_ENV_SOURCES=$'\n'
_deploy_env_record_source() {
  # Both the haystack and the needle carry the leading newline, so KEY cannot match a
  # longer key that ends with it (DEPLOY_VPN against DEPLOY_VPN_PORT).
  case "$_DEPLOY_ENV_SOURCES" in *$'\n'"$1="*) return 0 ;; esac
  _DEPLOY_ENV_SOURCES="${_DEPLOY_ENV_SOURCES}$1=$2"$'\n'
}

# deploy_env_note_source KEY WHERE — record a provenance the loader could not have seen,
# for a value a script resolved on its own: positional arguments, a host list recovered
# from the fleet record. Without it those read as "the environment", which is where they
# ended up rather than where they came from.
deploy_env_note_source() { _deploy_env_record_source "$1" "$2"; }

# deploy_env_source KEY — that record, or `a default` for a key nothing supplied.
deploy_env_source() {
  local line
  while IFS= read -r line; do
    case "$line" in "$1="*) printf '%s' "${line#*=}"; return 0 ;; esac
  done <<<"$_DEPLOY_ENV_SOURCES"
  printf 'a default'
}

# resolve_deploy_hosts — set DEPLOY_HOSTS from the first rung that can answer.
#
# Settings and the host list take different routes, and that is not an accident of
# implementation — the record stores them in different places. deploy_env_load's record rung
# is fleet_env_default, which reads options{}; the hosts live in hosts[]. So
# `deploy_env_load DEPLOY_HOSTS` returns NOTHING even with a record right there, and no
# amount of adding DEPLOY_HOSTS to a key list can change that.
#
# Called explicitly rather than folded into deploy_env_load, because ordering decides
# correctness. deploy-multiserver.sh loads its settings at the top and applies POSITIONAL
# hosts afterwards; a rung hidden inside the settings load would announce "fleet from this
# host's own record: local,w1" and then run against the hosts named on the command line. An
# announcement that can be wrong is worse than none.
#
# Sets FLEET_HOSTS_SOURCE so a caller can say where the answer came from, and never fails:
# no host list is a question for the caller, not an error here.
# shellcheck disable=SC2034  # FLEET_HOSTS_SOURCE is consumed by sourcing scripts
resolve_deploy_hosts() {
  FLEET_HOSTS_SOURCE=""
  if [ -n "${DEPLOY_HOSTS:-}" ]; then
    FLEET_HOSTS_SOURCE="the environment"
    return 0
  fi
  DEPLOY_HOSTS=$(deploy_env_default DEPLOY_HOSTS)
  if [ -n "$DEPLOY_HOSTS" ]; then
    FLEET_HOSTS_SOURCE="${DEPLOY_ENV_FILE:-deploy.env}"
    export DEPLOY_HOSTS
    return 0
  fi
  DEPLOY_HOSTS=$(fleet_hosts "${DEPLOY_REMOTE_DIR:-}")
  if [ -n "$DEPLOY_HOSTS" ]; then
    FLEET_HOSTS_SOURCE="this host's fleet record"
    export DEPLOY_HOSTS
  fi
  return 0
}

# resolve_pg_conn — sets PG_HOST/PG_PORT/PG_USER/PG_DB from POSTGRES_HOST/PORT/USER/DB
# (defaults localhost/5432/logstotal/logstotal) and PG_URL from DATABASE_URL with the
# SQLAlchemy +asyncpg/+psycopg2 driver suffixes stripped (libpq tools don't understand them).
resolve_pg_conn() {
  # shellcheck disable=SC2034  # consumed by sourcing scripts
  PG_HOST="${POSTGRES_HOST:-localhost}"
  # shellcheck disable=SC2034  # consumed by sourcing scripts
  PG_PORT="${POSTGRES_PORT:-5432}"
  # shellcheck disable=SC2034  # consumed by sourcing scripts
  PG_USER="${POSTGRES_USER:-logstotal}"
  # shellcheck disable=SC2034  # consumed by sourcing scripts
  PG_DB="${POSTGRES_DB:-logstotal}"
  # shellcheck disable=SC2034  # consumed by sourcing scripts
  PG_URL=""
  if [ -n "${DATABASE_URL:-}" ] && echo "$DATABASE_URL" | grep -q "postgres"; then
    # shellcheck disable=SC2034  # consumed by sourcing scripts
    PG_URL=$(printf '%s' "$DATABASE_URL" | sed -e 's/+asyncpg//' -e 's/+psycopg2//')
  fi
}

# compose_postgres_running — 0 iff docker-compose.yml exists AND the compose
# postgres service has a running container.
compose_postgres_running() {
  [ -f docker-compose.yml ] && docker compose ps --status running postgres 2>/dev/null | grep -q postgres
}

# A running bundled database is a transport only when it is the configured target.
configured_postgres_container() {
  local host="${POSTGRES_HOST:-postgres}"
  if [ -n "$PG_URL" ]; then
    host=$(python3 -c 'import sys; from urllib.parse import urlsplit; print(urlsplit(sys.argv[1]).hostname or "")' "$PG_URL")
  fi
  [ "$host" = postgres ] && compose_postgres_running
}

# Resolve the same SQLite target for backup, restore and rollback inspection.
resolve_sqlite_target() {
  local context="${BACKUP_CONTEXT:-auto}"
  if [ "$context" = auto ] && [ -f docker-compose.yml ] && command -v docker >/dev/null 2>&1; then
    if docker compose ps --services --status running 2>/dev/null | grep -qE '^(web|worker)$'; then
      context=docker
    fi
  fi
  run_py "${SCRIPT_DIR}/db_target.py" sqlite-path --context "$context"
}

# refuse_if_app_running TASK_HINT [ACTION] — refuse to proceed while the app/worker is
# running (local uvicorn/huey processes, or compose web/worker services),
# unless FORCE=yes. TASK_HINT is interpolated into the override hint
# (FORCE=yes task TASK_HINT).
refuse_if_app_running() {
  local task_hint="$1"
  # Verb for the message; defaults to "restore", the backup callers' wording (pinned by
  # tests/test_backup_scripts.py).
  local action="${2:-restore}"
  local running=""
  if command -v pgrep >/dev/null 2>&1; then
    if pgrep -f "uvicorn app.main" >/dev/null 2>&1 || pgrep -f huey_consumer >/dev/null 2>&1; then
      running="local app processes (uvicorn/huey)"
    fi
  fi
  if [ -z "$running" ] && [ -f docker-compose.yml ] && command -v docker >/dev/null 2>&1; then
    local up
    up=$(docker compose ps --services --status running 2>/dev/null | grep -E '^(web|worker)$' | tr '\n' ' ' || true)
    if [ -n "$up" ]; then running="running compose services: $up"; fi
  fi
  if [ -n "$running" ] && [ "${FORCE:-}" != "yes" ]; then
    # Two lines — the refusal and the way out are separate sentences, and die() takes an
    # embedded newline for exactly this (deploy-fleet.sh's adopted-record refusal is the
    # other one). On stderr, because a refusal on stdout is lost by an operator redirecting
    # the run to a log.
    die "refusing to ${action} while the app is running ($running).
Stop it first (./logstotal docker:down, or stop ./logstotal dev and ./logstotal worker), or override with: FORCE=yes ./logstotal ${task_hint}"
  fi
}

# ── Private network ──────────────────────────────────────────────────────────
#
# The one place the default lives. Kept as its own variable rather than inlined into the
# `${DEPLOY_VPN:-...}` below so that changing it is a one-line, greppable change rather
# than four scripts that have to agree.
#
# It defaults to building a tunnel. Without one, `deploy_fleet_env.py` binds Redis,
# PostgreSQL and Garage to a routable interface and prints a warning saying so — and a
# warning in a long log is not a default. The three ways this softens or stops rather than
# surprising anyone are in vpn_mode() below.
DEPLOY_VPN_DEFAULT="${DEPLOY_VPN_DEFAULT:-wireconf}"
#
# vpn_mode — the fleet's VPN choice, resolved once and identically by every script.
#
# One resolution for every script, because a copy is not merely untidy:
# **deploy-bootstrap.sh runs before deploy-vpn.sh** and decides whether to install
# wireguard-tools and open the hub's UDP port.
# A rule applied in one place and not the other installs a tunnel's prerequisites, and
# rewrites a firewall, for a tunnel that is then skipped.
#
# Sets, rather than prints. `mode=$(vpn_mode)` would run the whole thing in a subshell and
# throw away everything below it — so it has no stdout at all and every caller reads
# VPN_MODE.
#
#   VPN_MODE            the effective mode: wireconf | tailscale | none — or the operator's
#                       value verbatim when it is none of those, because refusing a typo
#                       belongs to deploy-vpn.sh, the only script that can honour
#                       DEPLOY_VPN_OPTIONAL while doing it.
#   VPN_MODE_REQUESTED  what was asked for, before any rule below applied
#   VPN_MODE_EXPLICIT   yes when the operator chose it (environment or deploy.env), no when
#                       it was defaulted. The difference decides whether a skip is a quiet
#                       fact or a warning about an unmet request.
#   VPN_MODE_REASON     why the effective mode differs from the requested one, else empty
#
# Reads DEPLOY_VPN and DEPLOY_HOSTS. Call deploy_env_load for both first — this deliberately
# does not, so it stays a pure function of the environment and a test can drive it directly.
#
# shellcheck disable=SC2034  # every VPN_MODE_* below is read by the sourcing script
vpn_mode() {
  local requested hosts host count non_local _ifs_saved
  requested="${DEPLOY_VPN:-}"
  if [ -n "$requested" ]; then
    VPN_MODE_EXPLICIT=yes
  else
    VPN_MODE_EXPLICIT=no
    requested="$DEPLOY_VPN_DEFAULT"
  fi
  VPN_MODE_REQUESTED="$requested"
  VPN_MODE_REASON=""
  VPN_MODE="$requested"
  VPN_MODE_UNDECIDED=no

  # A fleet configured before wireconf became the default must not be converted behind the
  # operator's back. Building a tunnel rewrites every cross-host URL from the public
  # address to 10.200.0.x, which on a running fleet is not an improvement applied quietly
  # — it is an outage.
  #
  # The signal is `deploy.env` exists and says nothing about DEPLOY_VPN, which identifies
  # exactly that case and nothing else. deploy-envs/ was the obvious candidate and is
  # wrong: it is local, disposable, written by dry runs, and absent entirely when the
  # deploy is driven from a second machine.
  if [ "$VPN_MODE_EXPLICIT" = "no" ] && [ -f "${DEPLOY_ENV_FILE:-deploy.env}" ] &&
    ! grep -qE '^[[:space:]]*DEPLOY_VPN=' "${DEPLOY_ENV_FILE:-deploy.env}"; then
    VPN_MODE_UNDECIDED=yes
  fi

  # Only wireconf builds anything, so only wireconf can be skipped for having nothing to
  # build. `tailscale` is managed by the operator and `none` is already the answer.
  [ "$requested" = "wireconf" ] || return 0

  # The rules below only ever soften a DEFAULT. An operator who wrote DEPLOY_VPN=wireconf
  # gets a tunnel, even a degenerate one — quietly overruling what someone asked for is
  # worse than building something pointless, and it is the difference between a default
  # that behaves well and a setting that does not work.
  [ "$VPN_MODE_EXPLICIT" = "no" ] || return 0

  # A hub-and-spoke mesh needs a spoke. One host — or a fleet that is entirely this
  # machine — has no traffic crossing a network for a tunnel to protect, and building one
  # would still install WireGuard, rewrite the firewall and re-address every service URL.
  hosts="${DEPLOY_HOSTS:-}"
  count=0
  non_local=0
  _ifs_saved="$IFS"
  IFS=','
  for host in $hosts; do
    host="$(printf '%s' "$host" | tr -d '[:space:]')"
    [ -n "$host" ] || continue
    count=$((count + 1))
    case "${host#*@}" in
      local | localhost | 127.0.0.1 | ::1) ;;
      *) non_local=$((non_local + 1)) ;;
    esac
  done
  IFS="$_ifs_saved"

  if [ "$count" -le 1 ]; then
    VPN_MODE_REASON="only one host — a hub-and-spoke mesh with no spokes protects nothing"
    VPN_MODE=none
  elif [ "$non_local" -eq 0 ]; then
    VPN_MODE_REASON="every host is this machine — nothing crosses a network"
    VPN_MODE=none
  fi
}

# vpn_mode_require_decision — stop when the fleet predates the wireconf default.
#
# Called before anything is installed or rewritten. Putting it after bootstrap would mean
# WireGuard packages and a firewall rule land for a tunnel the operator has not agreed to.
vpn_mode_require_decision() {
  [ "${VPN_MODE_UNDECIDED:-no}" = "yes" ] || return 0
  die "this fleet was set up before private networking became the default, and ${DEPLOY_ENV_FILE:-deploy.env} does not say which you want.

Nothing has been changed. Pick one:

  DEPLOY_VPN=wireconf ./logstotal deploy    # build the tunnel. Redis, PostgreSQL and Garage move onto it,
                                                # which re-addresses every worker: expect a restart, not an outage.
  DEPLOY_VPN=none ./logstotal deploy        # keep today's addresses. Those three stay on a routable
                                                # interface, protected only by their passwords.

To stop being asked, write the answer down:

  echo 'DEPLOY_VPN=wireconf' >> ${DEPLOY_ENV_FILE:-deploy.env}

'./logstotal deploy:network' shows exactly which ports each choice needs open."
}

# network_plan FORMAT — print the fleet's reachability matrix.
#
# One assembly of the arguments, because three callers want the same plan from the same
# facts and a fourth (deploy:network) is the plan on its own. Reads DEPLOY_HOSTS, VPN_MODE
# (call vpn_mode first), DEPLOY_VPN_PORT, DEPLOY_DOMAIN and DEPLOY_PROXY_TLS.
# ── The fleet's own settings ─────────────────────────────────────────────────
#
# config_review FORMAT [--settings-only|--findings-only] — what this fleet is configured
# to be, and where its settings disagree with each other.
#
# The shim half of scripts/deploy_config_review.py, the network_plan arrangement below:
# every judgement lives in a pure, stdlib-only module that is testable as data, and this
# only collects values and provenance, which is the part only the shell knows.
#
# The key list is duplicated here rather than read back from the module because the
# alternative is a second python3 start-up per render just to ask what to pass.
# tests/test_deploy_config_review.py pins it against REVIEWED_KEYS, so it cannot drift.
_CONFIG_REVIEW_KEYS="DEPLOY_HOSTS DEPLOY_DOMAIN DOMAIN DEPLOY_PROXY_TLS DEPLOY_ACME_EMAIL \
DEPLOY_BASIC_AUTH_USER DEPLOY_BASIC_AUTH_PASSWORD DEPLOY_BASIC_AUTH_HASH DEPLOY_ADMIN_EMAIL \
DEPLOY_VPN DEPLOY_VPN_NETWORK DEPLOY_VPN_PORT DEPLOY_CP_ADDRESS DEPLOY_REMOTE_DIR \
DEPLOY_HUEY_WORKERS DEPLOY_KEEP_RELEASES DEPLOY_HEALTH_ATTEMPTS DEPLOY_HEALTH_DELAY DEPLOY_ONLY"

config_review() {
  local format="${1:-text}" module key args=()
  shift || true
  # Resolved from this file's own location, not the cwd — the fleet script is driven from
  # a temp directory by its tests, and a relative path there aborts the run under `set -e`.
  module="$(cd "${_LT_LIB_DIR}/.." && pwd)/deploy_config_review.py"
  [ -f "$module" ] || return 0
  for key in $_CONFIG_REVIEW_KEYS; do
    # The RESOLVED mode, not the raw setting: vpn_mode's degenerate-fleet rules turn a
    # defaulted `wireconf` into `none` for a single-host fleet, and a review that reports
    # the unresolved value describes a tunnel that will not be built.
    if [ "$key" = "DEPLOY_VPN" ] && [ -n "${VPN_MODE:-}" ]; then
      args+=(--set "DEPLOY_VPN=${VPN_MODE}")
    elif [ -n "${!key:-}" ]; then
      args+=(--set "${key}=${!key}")
    fi
    args+=(--source "${key}=$(deploy_env_source "$key")")
  done
  run_py "$module" --format "$format" "$@" "${args[@]}"
}

network_plan() {
  local format="${1:-text}" module
  [ -n "${DEPLOY_HOSTS:-}" ] || return 0
  # Resolved from this file's own location, not the cwd. Every other run_py caller happens
  # to run from the repo root; the fleet script is driven from a temp directory by its
  # tests, and a relative path there aborts the whole run under `set -e`.
  module="$(cd "${_LT_LIB_DIR}/.." && pwd)/deploy_network_plan.py"
  [ -f "$module" ] || return 0
  run_py "$module" \
    --hosts "$DEPLOY_HOSTS" \
    --vpn "${VPN_MODE:-${DEPLOY_VPN:-none}}" \
    --vpn-port "${DEPLOY_VPN_PORT:-51820}" \
    --domain "${DEPLOY_DOMAIN:-}" \
    --proxy-tls "${DEPLOY_PROXY_TLS:-acme}" \
    --format "$format"
}

# ── Backups ──────────────────────────────────────────────────────────────────

# record_backup_artifact DEST — remember the artifact path for task backup's
# verify step (backups/.last-backup-path).
record_backup_artifact() {
  mkdir -p backups
  printf '%s\n' "$1" > backups/.last-backup-path
}

# artifact_size DEST — human-readable size (du -h).
artifact_size() {
  du -h "$1" | cut -f1
}

# backup_stamp — a YYYYMMDD-HHMMSS timestamp for backup filenames.
backup_stamp() {
  date +%Y%m%d-%H%M%S
}

# assert_sqlite_artifact_populated ARTIFACT SOURCE — post-condition for a SQLite
# snapshot. `task backup:verify` only runs PRAGMA integrity_check, and an *empty*
# database passes that, so a snapshot that silently copied nothing would still earn
# a green last-verified.json receipt. Compare schema-object counts against the live
# DB instead, and refuse to record an artifact that lost objects.
assert_sqlite_artifact_populated() {
  local artifact source_db counts got want
  artifact="$1"
  source_db="$2"
  [ -s "$artifact" ] || die "Backup ${artifact} is missing or empty — refusing to record it."
  counts=$(run_py -c '
import sqlite3, sys


def objects(path):
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return con.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
    finally:
        con.close()


print(objects(sys.argv[1]), objects(sys.argv[2]))
' "$artifact" "$source_db" 2>/dev/null) || die "Could not read ${artifact} as a SQLite database — refusing to record it."
  got=${counts%% *}
  want=${counts##* }
  # (locals declared at the top, so nothing leaks into scripts/backup.sh.)
  [ "$got" -ge "$want" ] || die "Backup ${artifact} holds ${got} schema objects but ${source_db} has ${want} — the snapshot is incomplete; not recording it."
}

# ── Bounded execution ────────────────────────────────────────────────────────

# run_bounded SECONDS CMD [ARG...] — run CMD, killing it after SECONDS. Returns 124 on
# timeout, otherwise CMD's own status. stdout and stderr pass straight through.
#
# `timeout(1)` when there is one, and there is on every Linux host. The fallback exists
# for macOS, where /bin/bash is 3.2 and coreutils is not installed.
#
# The fallback puts the child in its own process group (`set -m`) and signals the GROUP,
# the same discipline as ToolAdapter._exec: `git ls-remote` forks git-remote-https, and
# TERMing only the parent leaves that helper connecting for another two minutes. Measured
# on bash 3.2: with the group kill, nothing survives; without it, the helper does.
#
# `set -m` is restored only if the caller did not already have it, so this cannot turn
# monitor mode off underneath a caller that wanted it.
#
# Two properties every caller depends on, both verified on bash 3.2 and 5.3: a timed-out
# child leaves NO job-control text on stderr (a stray "Terminated" inside a command
# substitution is indistinguishable from real output), and a non-zero exit is passed
# through rather than flattened to 124.
#
# Callers run under `set -e`, so this must be invoked as `out=$(run_bounded ...) || rc=$?`.
run_bounded() {
  local secs="$1"
  shift

  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
    return $?
  fi
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@"
    return $?
  fi

  local pid rc waited=0 monitor=""
  case "$-" in *m*) monitor=on ;; esac
  set -m
  "$@" &
  pid=$!
  [ -n "$monitor" ] || set +m

  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      kill -TERM "-${pid}" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
      sleep 1
      kill -KILL "-${pid}" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done

  rc=0
  wait "$pid" || rc=$?
  return "$rc"
}

# CURL_DOWNLOAD_OPTS — how a release archive is fetched, everywhere it is fetched.
#
# Deliberately NOT `--max-time`. Every other curl in this library is a probe answering a
# yes/no question in under a second, and a total ceiling is right for those. These three
# are a 400 MB download, whose honest duration on a slow link is minutes — a total timeout
# there would abort a transfer that is working.
#
# What is bounded is the two ways it can hang instead of progress: the connect (10s, the
# ConnectTimeout the fleet already uses everywhere else) and a stall (`--speed-limit` /
# `--speed-time`: under 1 KB/s for a solid minute is a dead connection, not a slow one).
# `--retry` covers the transient case without re-running the whole upgrade.
#
# shellcheck disable=SC2034  # consumed by sourcing scripts
CURL_DOWNLOAD_OPTS=(--connect-timeout 10 --speed-limit 1024 --speed-time 60 --retry 2 --retry-connrefused)

# ── Release resolution ───────────────────────────────────────────────────────
#
# Upgrades run from published releases, never a branch, so what you install is something
# that was actually released.
#
# The knobs, in precedence order:
#   ARCHIVE           an explicit archive path or URL. Wins outright; no resolution happens.
#   VERSION           pin a published release (1.0.0 or v1.0.0).
#   REF               an arbitrary git ref. Refused unless it is vX.Y.Z or ALLOW_UNRELEASED=true.
#   (nothing)         resolve the latest published release.
#   RELEASE_REPO_URL  where releases live. Resolved by release_repo_url() below, which tries
#                     its sources in turn so a GitHub clone, a Forgejo clone and a release
#                     archive each need zero configuration.

#: The file a release archive carries to name the server it was published from.
#: Written by scripts/package.sh only when CI passes RELEASE_REPO_URL, so a locally built
#: package never stamps a guess. Gitignored, so overlaying an archive onto a checkout does
#: not leave an untracked file behind for `task release:finish` to trip over.
RELEASE_ORIGIN_FILE=".release-origin"

# compose_running_count_cmd — the ONE pipeline that counts a deployment's running
# containers, emitted as text so all three call sites share a single definition: two embed
# it in a remote command (host_installed_release, deploy-preflight.sh) and one runs it here
# (upgrade.sh::_local_running_containers).
#
# It probes BOTH compose files. `docker compose ps -q` alone reads docker-compose.yml, so a
# worker-only host reports zero containers however healthy it is.
#
# `sort -u` is what makes probing both safe, and it is not cosmetic: `docker compose ps` is
# scoped to the PROJECT, not to the file it was handed. Both invocations run in the same
# directory, so both resolve the same project name and both list the SAME containers —
# the second file narrows nothing. Without the dedupe every host counts twice (18 containers
# for a nine-container control plane). Measured against Compose v5.1.2: a project with two
# running services answers `2`
# to `ps -q` through a compose file that declares neither of them.
#
# Callers add their own `|| true` (or `|| echo 0`): grep -c prints 0 AND exits 1 when
# nothing matches, so a fallback that prints its own zero appends a SECOND one and the
# field arrives as "0\n0".
compose_running_count_cmd() {
  printf '%s' '{ docker compose ps -q 2>/dev/null; docker compose -f docker-compose.worker.yml ps -q 2>/dev/null; } | sort -u | grep -c .'
}

# host_installed_release HOST DIR — "<version>|<running-containers>" for HOST, or "|".
#
# The read scripts/deploy-preflight.sh does per host, shared so the upgrade can
# ask the same question without running a whole preflight first. Empty fields mean "could
# not measure", and every caller must treat that as not-current rather than as absent —
# never report OK for something you could not measure.
#
# CR-stripped: an operator whose ~/.ssh/config sets RequestTTY gets a pty on every call, and
# a pty rewrites remote output as CRLF — `ID=ubuntu` becomes `ubuntu\r` and every host
# reports itself as an unknown distro.
host_installed_release() {
  local host="$1" dir="$2" out
  out=$(host_exec "$host" "v=\$(sed -n 's/^version: *//p' ${dir}/VERSION 2>/dev/null | head -1 | tr -d '[:space:]'); r=\$(cd ${dir} 2>/dev/null && $(compose_running_count_cmd) || true); printf '%s|%s' \"\$v\" \"\$r\"" 2>/dev/null || true)
  printf '%s' "$out" | tr -d '\r'
}

# read_version_file [DIR] — the release number from a VERSION manifest, or "".
#
# One reader, so every consumer agrees on what a missing or malformed file means. The
# manifest is one line — `version: X.Y.Z` — and every consumer wants the same thing out of it.
# shellcheck disable=SC2120  # DIR is optional; shellcheck 0.10 (which CI pins) otherwise
# reports SC2119 at every no-argument call site, and 0.11 does not — so a tree that lints
# clean locally fails on the runner.
read_version_file() {
  local dir="${1:-.}"
  sed -n 's/^version: *//p' "${dir%/}/VERSION" 2>/dev/null | head -1 | tr -d '[:space:]' || true
}

# package_basename VERSION — the release archive's filename for VERSION (with or without a
# leading `v`). The name is a contract: it is
# both the published asset and what deploy-package-gate.sh compares against to decide
# whether the local archive is current.
package_basename() {
  printf 'logstotal-%s.7z' "${1#v}"
}

# package_version PATH — the release a `logstotal-<version>.7z` carries, or "".
#
# The inverse of package_basename, and the same contract read the other way: the filename
# IS the version, because package.sh derives both it and the app's reported version from
# the same `version:` line. Anything not matching the pattern yields "" rather than a
# guess — a plan that names the wrong release is worse than one that admits it cannot.
package_version() {
  local base
  base=$(basename "${1:-}")
  case "$base" in
    logstotal-*.7z)
      base="${base#logstotal-}"
      base="${base%.7z}"
      case "$base" in
        *[!0-9.]* | "") printf '' ;;
        *) printf '%s' "$base" ;;
      esac
      ;;
    *) printf '' ;;
  esac
}

# release_repo_url_source — which arm answered, for diagnostics. Kept beside
# release_repo_url so the two cannot describe different arms. "Where will this download
# from, and why" is the question behind most upgrade failures.
release_repo_url_source() {
  if [ -n "${RELEASE_REPO_URL:-}" ]; then printf 'RELEASE_REPO_URL'; return 0; fi
  if [ -s "$RELEASE_ORIGIN_FILE" ]; then printf '%s' "$RELEASE_ORIGIN_FILE"; return 0; fi
  if [ -n "$(deploy_env_default RELEASE_REPO_URL 2>/dev/null || true)" ]; then
    printf '%s' "${DEPLOY_ENV_FILE:-deploy.env}"; return 0
  fi
  if [ -n "$(fleet_release server 2>/dev/null || true)" ]; then printf 'this fleet record'; return 0; fi
  if [ -n "$(git remote get-url origin 2>/dev/null || true)" ]; then printf 'git origin'; return 0; fi
  printf 'built-in default'
}

# release_repo_url — the https base URL releases are published under.
#
# Six sources, most explicit first. The three in the middle exist because deriving this is
# not always possible: scripts/package.sh excludes .git, so an archive install has no origin
# at all, and an SSH origin carries no web scheme or port — `ssh://git@host/o/r.git` becomes
# `https://host/o/r`, which is wrong for any self-hosted instance not on 443. When the asset
# lives on a non-standard port, nothing can compute the right URL; it has to be recorded.
#
# deploy.env is read with `$(deploy_env_default …)`, never deploy_env_load: the go-task
# `env:` bridge exports a key set-but-empty and deploy_env_load skips a key that is merely
# set. .env is deliberately NOT a source —
# Taskfile.yml declares `dotenv: ['.env']` and a value there would silently beat a caller's
# `RELEASE_REPO_URL=… task upgrade`.
#
# Normalising ssh→https is still right for the origins it can handle: `origin` on a
# developer clone is typically git@github.com:owner/repo.git, and `git ls-remote` against
# that needs an SSH key a production server does not have.
release_repo_url() {
  local url="${RELEASE_REPO_URL:-}"
  if [ -z "$url" ] && [ -s "$RELEASE_ORIGIN_FILE" ]; then
    url=$(sed -n 's/^url: *//p' "$RELEASE_ORIGIN_FILE" 2>/dev/null | head -1 | tr -d '[:space:]')
  fi
  if [ -z "$url" ]; then
    url=$(deploy_env_default RELEASE_REPO_URL 2>/dev/null || true)
  fi
  # Then this host's own fleet record — after deploy.env, before the derived origin.
  #
  # It is recorded configuration, so it outranks anything computed; it is not something the
  # operator typed here, so it yields to anything that is. That places it exactly where
  # deploy_env_load puts the record for every other setting.
  #
  # This is the arm that makes an archive install answerable at all. A control plane has no
  # .git and no deploy.env — deploy.env belongs to whoever ran the deploy, and package.sh
  # keeps it out of the archive — so without it, every upgrade there would fall through to
  # the built-in github.com default, which for a self-hosted forge is the wrong server.
  if [ -z "$url" ]; then
    url=$(fleet_release server 2>/dev/null || true)
  fi
  if [ -z "$url" ]; then
    url=$(git remote get-url origin 2>/dev/null || true)
  fi
  [ -n "$url" ] || url="https://github.com/wagga40/LogsTotal"
  case "$url" in
    # scp-style: strip git@ and .git FIRST, then split host from path on the single
    # remaining colon. Substituting on the whole string rewrites the one in "https://".
    git@*:*)      url="${url#git@}"; url="${url%.git}"; url="https://${url%%:*}/${url#*:}" ;;
    ssh://git@*)  url="https://${url#ssh://git@}"; url="${url%.git}" ;;
    *)            url="${url%.git}" ;;
  esac
  printf '%s' "${url%/}"
}

# release_api_url — the releases API for whichever server release_repo_url names.
# GitHub and Gitea/Forgejo differ here (and only here); the release-asset and source-archive
# URL shapes are identical between them, which is why one template serves both below.
release_api_url() {
  if [ -n "${RELEASE_API_URL:-}" ]; then printf '%s' "$RELEASE_API_URL"; return 0; fi
  local repo scheme host path
  repo=$(release_repo_url)
  # Carry the repo URL's OWN scheme: a stamp or deploy.env can name an http instance, and a
  # hardcoded https:// would send every API call to a plaintext port over TLS and fail with
  # `tlsv1 alert protocol version`, an error that names nothing an operator can act on.
  scheme=$(printf '%s' "$repo" | sed -E 's#^(https?)://.*#\1#')
  [ "$scheme" = "http" ] || scheme="https"
  host=$(printf '%s' "$repo" | sed -E 's#^https?://([^/]+)/.*#\1#')
  path=$(printf '%s' "$repo" | sed -E 's#^https?://[^/]+/##')
  if [ "$host" = "github.com" ]; then
    printf 'https://api.github.com/repos/%s/releases/latest' "$path"
  else
    printf '%s://%s/api/v1/repos/%s/releases/latest' "$scheme" "$host" "$path"
  fi
}

# is_release_tag REF — 0 iff REF is exactly vX.Y.Z.
is_release_tag() {
  printf '%s' "${1:-}" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

# RELEASE_NET_TIMEOUT — the ceiling on one release-server round trip, seconds.
# 10 matches SSH_OPTS' ConnectTimeout, which answers the same question for the fleet.
RELEASE_NET_TIMEOUT="${RELEASE_NET_TIMEOUT:-10}"

# git_ls_remote_tags URL — the vX.Y.Z tags URL publishes, or "". Never blocks indefinitely.
#
# Bounded like every other network call in this file, and on the path of EVERY upgrade
# entry point.
#
# Two independent failure modes, and each needs its own guard:
#
#   Waiting forever for a human. A private repo makes git ask for a username on the
#   terminal, and a GUI credential helper or askpass can block with no output at all.
#   GIT_TERMINAL_PROMPT=0 refuses the terminal prompt, the askpass pair supplies an empty
#   credential so a 401 comes back immediately instead of a dialog, and an empty
#   credential.helper neutralises whatever the host has configured. No timeout fixes this
#   one — the call is not slow, it is waiting.
#
#   Waiting out the kernel. A firewall that DROPS rather than refuses leaves git in a TCP
#   connect that ends when SYN retries do, which is minutes. Git has no connect-timeout
#   knob: measured here, `http.lowSpeedLimit`/`lowSpeedTime` do NOT bound the connect
#   phase — a blackholed address ran past 25s with them set exactly as it did without.
#   So the bound has to come from outside, hence run_bounded.
#
# GIT_SSH_COMMAND covers the third transport: an ssh:// origin with a key that fails would
# otherwise prompt for a password and wait.
#
# A checkout rarely reaches this — it falls through to the local-tags arm below and answers
# from `git tag --list` — but a control plane is an extracted archive with no .git, so it has
# no fallback and would simply stop.
git_ls_remote_tags() {
  local url="$1" out rc=0
  out=$(
    GIT_TERMINAL_PROMPT=0 \
      GIT_ASKPASS=/bin/echo \
      SSH_ASKPASS=/bin/echo \
      GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=${RELEASE_NET_TIMEOUT} -o StrictHostKeyChecking=accept-new" \
      run_bounded "$RELEASE_NET_TIMEOUT" \
      git -c credential.helper= ls-remote --tags --refs "$url" 2>/dev/null
  ) || rc=$?
  # 124 is run_bounded's timeout; anything else non-zero is git saying no. Neither is an
  # error here — release_tags has two more sources — but a timeout is worth one line,
  # because the alternative is an operator watching a silent command and guessing.
  if [ "$rc" -eq 124 ]; then
    warn "release server did not answer within ${RELEASE_NET_TIMEOUT}s: ${url}" >&2
    return 0
  fi
  printf '%s' "$out" | sed -n 's#.*refs/tags/\(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$#\1#p' || true
}

# release_tags — every published vX.Y.Z, newline separated. Empty when nothing can be reached.
#
# Three sources, cheapest and most authoritative first. The local-tags arm is what lets an
# air-gapped host with a mirrored checkout still resolve; the API arm is for a host with no
# git at all, which is exactly the archive-install case.
release_tags() {
  local url tags
  url=$(release_repo_url)

  if command -v git >/dev/null 2>&1; then
    tags=$(git_ls_remote_tags "$url")
    [ -n "$tags" ] && { printf '%s\n' "$tags"; return 0; }

    tags=$(git tag --list 'v*' 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)
    [ -n "$tags" ] && { printf '%s\n' "$tags"; return 0; }
  fi

  if command -v curl >/dev/null 2>&1; then
    tags=$(release_tags_api)
    [ -n "$tags" ] && { printf '%s\n' "$tags"; return 0; }
  fi

  printf ''
}

# release_tags_list_url PAGE — the releases LIST endpoint, one page of it.
#
# A sibling of release_api_url rather than a rewrite of it: that one names
# `/releases/latest`, which several callers and tests depend on, and the two answer
# different questions.
#
# One URL carries BOTH `per_page` (GitHub) and `limit` (Gitea/Forgejo) because neither
# server reads the other's key and both ignore an unknown one — cheaper and less brittle
# than branching a second time on the host.
release_tags_list_url() {
  local page="${1:-1}" base
  base=$(release_api_url)
  base="${base%/latest}"
  printf '%s?per_page=100&limit=100&page=%s' "$base" "$page"
}

# release_tags_api — every published release tag the server will admit to, newline separated.
#
# Every tag, not just `/releases/latest`: scripts/deploy-bootstrap.sh installs docker, 7z,
# rsync and curl but NOT git, so on a deployed host this arm is the only one there
# is — and with a single tag in hand, release_resolve_ref would refuse every pin except the
# newest, making the documented rollback impossible on exactly the hosts that run in
# production.
#
# It stops at RELEASE_API_MAX_PAGES x 100 releases, and deliberately does NOT report that
# it did. A flag would be unreadable: every caller reads this through `tags=$(release_tags)`,
# and a variable set inside a command substitution dies with the subshell. So the authority
# on "can this release be fetched" is release_artifact_exists below, which asks the artifact
# rather than a list — a capped list can never turn "I did not see it" into "it does not
# exist", because the list is not what decides. The refusal names the cap all the same.
release_tags_api() {
  local page=1 max="${RELEASE_API_MAX_PAGES:-3}" body count all=""
  while [ "$page" -le "$max" ]; do
    body=$(curl -fsSL --max-time 20 "$(release_tags_list_url "$page")" 2>/dev/null || true)
    [ -n "$body" ] || break
    # Count RAW releases, not matching tags: the page-size test has to see a page that was
    # full of prereleases just as clearly as one full of releases.
    count=$(printf '%s' "$body" | grep -oE '"tag_name" *: *"' | grep -c . || true)
    [ "${count:-0}" -gt 0 ] || break
    all="${all}$(printf '%s' "$body" | grep -oE '"tag_name" *: *"[^"]+"' | cut -d'"' -f4)
"
    [ "$count" -lt 100 ] && break
    page=$((page + 1))
  done
  printf '%s' "$all" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true
}

# release_artifact_exists TAG — is there actually a downloadable package for TAG?
#
# Three outcomes, because two of them are not the same thing:
#   0  the asset answered
#   1  the server answered and there is no such asset
#   2  nothing could be measured (no curl, no network) — the caller must not refuse on this
#
# A TAG IS NOT A RELEASE. `release_latest_tag` reads tags, and a tag whose release job
# failed still resolves, with no published asset. Under a git
# checkout that merely checks out the tag; under package mode it 404s at download, after
# the backup. Measured at ~0.1s against ~3s for the full list, and immune to pagination,
# truncation and prerelease semantics — so this, not the list, is the authority on whether
# a package can be fetched.
release_artifact_exists() {
  local tag="${1:-}"
  [ -n "$tag" ] || return 2
  command -v curl >/dev/null 2>&1 || return 2
  # -L: a GitHub release asset redirects to objects.githubusercontent.com.
  if curl -fsIL --max-time 15 "$(release_package_url "$tag")" >/dev/null 2>&1; then
    return 0
  fi
  # Tell "no such asset" from "could not reach the server at all": without the second
  # probe, an offline host reports every release as missing.
  if curl -fsI --max-time 10 "$(release_repo_url)" >/dev/null 2>&1; then
    return 1
  fi
  return 2
}

# release_latest_tag — the newest published vX.Y.Z, or "".
#
# Field sort, not `sort -V`: it needs no GNU/BSD feature detection and is exactly right for
# X.Y.Z. A plain lexical sort puts v1.0.10 before v1.0.2, which is the whole trap.
release_latest_tag() {
  local newest
  newest=$(release_tags | sed 's/^v//' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -t. -k1,1n -k2,2n -k3,3n | tail -1 || true)
  [ -n "$newest" ] || { printf ''; return 0; }
  printf 'v%s' "$newest"
}

# release_package_url TAG — the .7z release asset, always.
#
# Always the .7z, never a source zip: the multi-server deploy uploads ONE archive and every
# host opens it with `7z x`, and the zip does not carry the production stylesheet.
release_package_url() {
  printf '%s/releases/download/%s/%s' "$(release_repo_url)" "$1" "$(package_basename "$1")"
}

# release_resolve_ref — the policy. Prints the ref to stage on stdout, diagnostics on stderr.
# Prints nothing and returns 0 when ARCHIVE is set: archive mode owns the decision.
release_resolve_ref() {
  local tag tags rc

  if [ -n "${BUNDLE:-}" ]; then
    local bundle_version
    bundle_version=$(run_py "${SCRIPT_DIR:-scripts}/bundle_manifest.py" version "$BUNDLE") || return 1
    [ -z "${VERSION:-}" ] || [ "${VERSION#v}" = "$bundle_version" ] || die "VERSION differs from the selected bundle release."
    printf 'v%s' "$bundle_version"
    return 0
  fi
  if [ -n "${ARCHIVE:-}" ]; then printf ''; return 0; fi

  if [ -n "${VERSION:-}" ]; then
    tag="v${VERSION#v}"
    is_release_tag "$tag" || die "VERSION=${VERSION} is not X.Y.Z."
    tags=$(release_tags)
    if [ -n "$tags" ] && ! printf '%s\n' "$tags" | grep -qx "$tag"; then
      # Not in the list is not the same as not published. Three things put a tag there: a
      # list capped by the page limit, a server that lists releases differently, or a
      # genuinely absent release. Ask the artifact itself — the only one of the three that
      # answers the question the caller actually has.
      # `|| rc=$?`, never a bare call: under `set -e` — which every caller of this
      # library sets — a function returning non-zero aborts before `case $?` runs, leaving
      # both non-zero arms below unreachable and an unpublished VERSION= exiting 1 with
      # nothing said.
      rc=0
      release_artifact_exists "$tag" || rc=$?
      case $rc in
        0) : ;;  # the package is right there; the list was simply incomplete
        2) warn "could not reach $(release_repo_url) to verify ${tag} — continuing." ;;
        *)
          # Absent from the list AND no package to fetch. Distinguishing "no such release"
          # from "could not reach the server" is the whole value of this branch — a warning
          # for the second (rc 2 above), a refusal for the first.
          die "no release ${tag} at $(release_repo_url)
       Published: $(printf '%s\n' "$tags" | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -5 | sed 's/^/v/' | tr '\n' ' ')
       (that list is capped at RELEASE_API_MAX_PAGES x 100 releases; raise it if your
       forge publishes more than the default 300.)"
          ;;
      esac
    fi
    [ -n "$tags" ] || warn "could not reach $(release_repo_url) to verify ${tag} — continuing."
    printf '%s' "$tag"
    return 0
  fi

  if [ -n "${REF:-}" ]; then
    if is_release_tag "$REF"; then printf '%s' "$REF"; return 0; fi
    if truthy "${ALLOW_UNRELEASED:-}"; then
      warn "staging an UNRELEASED ref (REF=${REF}). Not a published release: /health will report
      the version of whatever commit you land on, and nothing records which commit that was.
      Unsupported — use it on your own boxes, not on a fleet."
      printf '%s' "$REF"
      return 0
    fi
    die "REF=${REF} is not a published release (expected vX.Y.Z).
       Upgrades run from versioned releases only.

         ./logstotal upgrade                                    # latest release
         ./logstotal upgrade VERSION=X.Y.Z                      # a specific release
         ALLOW_UNRELEASED=true REF=${REF} ./logstotal upgrade   # escape hatch, unsupported"
  fi

  tag=$(release_latest_tag)
  # Never fall back to a branch. Defaulting to origin/main is what this replaces.
  [ -n "$tag" ] || die "could not resolve the latest release from $(release_repo_url)
       No network, or no releases published there.
         Pin one:           ./logstotal upgrade VERSION=X.Y.Z
         Or use an archive: ./logstotal upgrade ARCHIVE=/path/to/logstotal-X.Y.Z.7z"
  printf '%s' "$tag"
}

# ── Python / misc ────────────────────────────────────────────────────────────

# run_py ARGS... — venv-aware python3 runner: uses `pdm run --` when a .venv
# and pdm are present, otherwise falls back to plain python3. Always python3,
# never python.
run_py() {
  if [ -d .venv ] && command -v pdm >/dev/null 2>&1; then
    pdm run -- python3 "$@"
  else
    python3 "$@"
  fi
}

# require_cmd CMD HINT — die with an install hint if CMD is not on PATH.
require_cmd() {
  local cmd="$1" hint="$2"
  command -v "$cmd" >/dev/null 2>&1 || die "${cmd} not found. ${hint}"
}

# lt_task ARGS... — run another task from a script, with the go-task running this one.
#
#   1. LOGSTOTAL_TASK_BIN: Taskfile.yml exports it as {{.TASK_EXE}}. Under ./logstotal that
#      is a pinned copy that is not on PATH, so a bare `task` would find nothing, or a
#      different go-task.
#   2. ./logstotal, for a script run directly from the installation (a release workflow's
#      `bash scripts/package.sh`, an operator's `bash scripts/backup.sh auto`). Ahead of PATH
#      because on Debian and Ubuntu the `task` there may well be Taskwarrior.
#   3. `task` on PATH — a script run anywhere else, including by a test with a stub there.
lt_task() {
  if [ -n "${LOGSTOTAL_TASK_BIN:-}" ]; then
    "$LOGSTOTAL_TASK_BIN" "$@"
  elif [ -x ./logstotal ]; then
    ./logstotal "$@"
  elif command -v task >/dev/null 2>&1; then
    task "$@"
  else
    die "go-task not found. Run this from the LogsTotal directory through ./logstotal, which provides it."
  fi
}

# require_task — die unless lt_task has something to run.
require_task() {
  if [ -n "${LOGSTOTAL_TASK_BIN:-}" ]; then
    command -v "$LOGSTOTAL_TASK_BIN" >/dev/null 2>&1 || die "LOGSTOTAL_TASK_BIN=${LOGSTOTAL_TASK_BIN} is not runnable."
  elif [ ! -x ./logstotal ] && ! command -v task >/dev/null 2>&1; then
    die "go-task not found. Run this from the LogsTotal directory through ./logstotal, which provides it."
  fi
}

# ── CI: borrowing the .env slot ──────────────────────────────────────────────
#
# Both compose files declare `env_file: .env` **relative to themselves**, so there is no
# --env-file that redirects them: anything that runs the stack has to write the real path.
# In CI the checkout has no .env and this is free; on a developer's machine that file is
# their working configuration, and `cp .env.example .env` followed by `rm -f .env`
# destroys it.
#
# Always paired, always through a trap:
#     ci_env_borrow            # .env -> .env.ci-backup, then .env.example -> .env
#     trap ci_env_return EXIT  # .env.ci-backup -> .env  (no-op when there was none)

CI_ENV_BACKUP=".env.ci-backup"

ci_env_borrow() {
  # Refuse rather than clobber: a leftover backup means a previous run died between the two
  # halves, and overwriting it now loses the original for good.
  [ -e "$CI_ENV_BACKUP" ] && die "${CI_ENV_BACKUP} exists — a previous run left it behind. Move it back to .env, or delete it, then re-run."
  [ -f .env ] && mv .env "$CI_ENV_BACKUP"
  cp .env.example .env

  # Shed the OLD .env's values from this process's environment. Taskfile.yml declares
  # `dotenv: ['.env']`, so go-task loaded the developer's .env at startup and exported it —
  # and in compose interpolation the shell environment BEATS the .env file. Without this,
  # `docker compose up` starts Redis with the developer's password from the environment
  # while the containers read the freshly generated one from the file, and the app reports
  # `invalid username-password pair` and 503s for as long as you are willing to wait.
  #
  # Same list as scripts/quickstart.sh, plus WEB_PORT — the CI scripts
  # write that one, and a developer with WEB_PORT in their .env would otherwise have compose
  # publish on their port while the smoke test polls the one it chose.
  # shellcheck disable=SC2086  # deliberately one unset over a fixed list of names
  unset SECRET_KEY ADMIN_PASSWORD POSTGRES_PASSWORD REDIS_PASSWORD S3_ACCESS_KEY S3_SECRET_KEY \
    GARAGE_RPC_SECRET GARAGE_ADMIN_TOKEN COOKIE_INSECURE COMPOSE_PROFILES WEB_PORT
}

ci_env_return() {
  rm -f .env
  if [ -f "$CI_ENV_BACKUP" ]; then
    mv -f "$CI_ENV_BACKUP" .env
    info "restored your .env"
  fi
}
