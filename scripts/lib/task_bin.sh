# shellcheck shell=bash
#
# Which go-task binary runs this installation's Taskfile (developer / ops).
#
# Sourced by ./logstotal and scripts/package.sh. It must not source scripts/lib/common.sh or
# need anything beyond bash, tar, gzip and a sha256 tool: the wrapper runs before any task,
# on a host that may have nothing else yet.
#
# ── The pin ──────────────────────────────────────────────────────────────────
#
# One go-task release, and the sha256 of each upstream tarball exactly as published in that
# release's task_checksums.txt, so a pin can be checked against upstream by eye. To move it:
# change LT_TASK_VERSION, copy the four matching lines from
#   https://github.com/go-task/task/releases/download/v<version>/task_checksums.txt
# into lt_task_sha256_pin, and run tests/test_logstotal_wrapper.py.
#
# ── Resolution order (lt_task_resolve) ───────────────────────────────────────
#
#   1. $LOGSTOTAL_TASK, an explicit path. Still has to be go-task >= the floor.
#   2. The cached pinned copy (.bin/task), if it reports the pinned version.
#   3. The tarball a release archive carries under tools/go-task/. This is how a host with
#      no network gets its go-task: an offline bundle carries the release archive whole.
#      A checksum mismatch here is fatal, never a reason to try something else.
#   4. `task` or `go-task` on PATH, if it is go-task and at least LT_TASK_MIN_VERSION.
#   5. Download the pinned tarball, verify it, cache it.
#
# The archive is checked before PATH on purpose: an installed release runs the go-task it
# was tested with, whatever else the host has. A git checkout carries no tarball, so a
# developer's own `task` wins there.

LT_TASK_VERSION=3.53.1
# The oldest go-task that loads this Taskfile: `flatten:` includes arrived in 3.39.0.
LT_TASK_MIN_VERSION=3.39.0
LT_TASK_URL_BASE=https://github.com/go-task/task/releases/download
LT_TASK_BUNDLE_DIR=tools/go-task
# What package.sh puts in every release archive. Hosts are Linux; macOS is a development
# platform, where the download or a Homebrew `task` serves.
LT_TASK_BUNDLED_PLATFORMS="linux_amd64 linux_arm64"

lt_task_sha256_pin() {
  case "$1" in
    linux_amd64) echo a54a408f6861ff921f6e87774180db31bacd8c1e7c944ca696db9fea49a82fc7 ;;
    linux_arm64) echo e3ad19101493a0112e1f22ae8ccc54bf03e533b1076a0ca1e6c782a09ad2e588 ;;
    darwin_amd64) echo 7f1a702d54a789cb818a636039a83df071f4179893133afafa4eba351a7e19ef ;;
    darwin_arm64) echo 85d2d96c2380b33d7855b07b3f7a20dc7ca0eda999a26efa0fb5f6f32b366cd7 ;;
    *) return 1 ;;
  esac
}

_lt_task_err() {
  printf 'logstotal: %s\n' "$*" >&2
}

# lt_task_platform — go-task's own asset naming: linux_amd64, darwin_arm64, …
lt_task_platform() {
  local os arch
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) return 1 ;;
  esac
  printf '%s_%s\n' "$os" "$arch"
}

# _lt_task_version_string BIN — the X.Y.Z a go-task binary reports, or nothing. Current
# releases print a bare `3.53.1`, older ones `Task version: v3.39.0 (h1:…)`.
#
# No pipes in this or the next function: the wrapper runs under `pipefail`, and a `| grep -q`
# that exits on its first match hands the writer a SIGPIPE that fails the whole check.
_lt_task_version_string() {
  local out
  out=$("$1" --version 2>/dev/null) || return 1
  [[ $out =~ ([0-9]+\.[0-9]+\.[0-9]+) ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

# lt_task_version_of BIN — as above, but only for go-task. On Debian and Ubuntu a `task` on
# PATH is as likely to be Taskwarrior, whose 3.x versions would pass a bare version check.
lt_task_version_of() {
  local help
  help=$("$1" --help 2>&1) || return 1
  case "$help" in *--taskfile*) ;; *) return 1 ;; esac
  _lt_task_version_string "$1"
}

# lt_version_ge A B — dotted numeric comparison, A >= B.
lt_version_ge() {
  local IFS=. i
  local -a a b
  read -r -a a <<<"$1"
  read -r -a b <<<"$2"
  for i in 0 1 2; do
    [ "${a[i]:-0}" -gt "${b[i]:-0}" ] && return 0
    [ "${a[i]:-0}" -lt "${b[i]:-0}" ] && return 1
  done
  return 0
}

lt_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    return 1
  fi
}

# lt_task_cache_dir ROOT — .bin/ inside the installation, or a per-user cache when the
# installation is not writable by whoever is running it.
lt_task_cache_dir() {
  if mkdir -p "$1/.bin" 2>/dev/null && [ -w "$1/.bin" ]; then
    printf '%s/.bin\n' "$1"
  else
    printf '%s/logstotal/go-task\n' "${XDG_CACHE_HOME:-$HOME/.cache}"
  fi
}

# lt_task_install_tarball TARBALL PLATFORM DIR — verify TARBALL against the pin for PLATFORM
# and put its `task` at DIR/task. Extracted beside the target and renamed into place, so two
# first runs at once cannot leave a half-written binary.
lt_task_install_tarball() {
  local tarball=$1 platform=$2 dir=$3 want got tmp
  want=$(lt_task_sha256_pin "$platform") || {
    _lt_task_err "no pinned go-task checksum for ${platform}."
    return 1
  }
  got=$(lt_sha256 "$tarball") || {
    _lt_task_err "cannot verify ${tarball}: install sha256sum (coreutils) or shasum."
    return 1
  }
  if [ "$got" != "$want" ]; then
    _lt_task_err "${tarball} does not match the pinned checksum for go-task ${LT_TASK_VERSION} (${platform})."
    _lt_task_err "expected ${want}, got ${got}. Refusing to run it."
    return 1
  fi
  mkdir -p "$dir" || return 1
  tmp=$(mktemp -d "${dir}/.task.XXXXXX") || return 1
  if ! tar -xzf "$tarball" -C "$tmp" task; then
    rm -rf "$tmp"
    _lt_task_err "could not extract task from ${tarball}."
    return 1
  fi
  chmod 755 "$tmp/task" && mv -f "$tmp/task" "$dir/task"
  rm -rf "$tmp"
  printf '%s/task\n' "$dir"
}

# lt_task_download PLATFORM DEST — fetch the pinned upstream tarball. Returns 2 when there is
# no download tool at all, so the caller can say that rather than "download failed".
lt_task_download() {
  local url="${LT_TASK_URL_BASE}/v${LT_TASK_VERSION}/task_${1}.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 15 -O "$2" "$url"
  else
    return 2
  fi
}

# lt_task_resolve ROOT — print the go-task binary to run ROOT's Taskfile with.
lt_task_resolve() {
  local root=$1 platform cache bin version name tarball tmp rc
  if [ -n "${LOGSTOTAL_TASK:-}" ]; then
    if [ ! -x "$LOGSTOTAL_TASK" ]; then
      _lt_task_err "LOGSTOTAL_TASK=${LOGSTOTAL_TASK} is not an executable file."
      return 1
    fi
    version=$(lt_task_version_of "$LOGSTOTAL_TASK" || true)
    if [ -z "$version" ] || ! lt_version_ge "$version" "$LT_TASK_MIN_VERSION"; then
      _lt_task_err "LOGSTOTAL_TASK=${LOGSTOTAL_TASK} is not go-task ${LT_TASK_MIN_VERSION} or later."
      return 1
    fi
    printf '%s\n' "$LOGSTOTAL_TASK"
    return 0
  fi

  platform=$(lt_task_platform || true)
  cache=$(lt_task_cache_dir "$root")

  if [ -x "${cache}/task" ] && [ "$(_lt_task_version_string "${cache}/task")" = "$LT_TASK_VERSION" ]; then
    printf '%s/task\n' "$cache"
    return 0
  fi

  tarball="${root}/${LT_TASK_BUNDLE_DIR}/task_${platform}.tar.gz"
  if [ -n "$platform" ] && [ -f "$tarball" ]; then
    lt_task_install_tarball "$tarball" "$platform" "$cache"
    return
  fi

  for name in task go-task; do
    bin=$(command -v "$name" 2>/dev/null) || continue
    version=$(lt_task_version_of "$bin" || true)
    if [ -n "$version" ] && lt_version_ge "$version" "$LT_TASK_MIN_VERSION"; then
      printf '%s\n' "$bin"
      return 0
    fi
  done

  if [ -z "$platform" ]; then
    _lt_task_err "no go-task for $(uname -s) $(uname -m). Install go-task ${LT_TASK_MIN_VERSION}+ (https://taskfile.dev/installation/)"
    _lt_task_err "and re-run, or point LOGSTOTAL_TASK at it."
    return 1
  fi
  tmp=$(mktemp "${TMPDIR:-/tmp}/logstotal-task.XXXXXX") || return 1
  printf 'logstotal: fetching go-task %s (%s), once…\n' "$LT_TASK_VERSION" "$platform" >&2
  rc=0
  lt_task_download "$platform" "$tmp" || rc=$?
  if [ "$rc" -eq 0 ]; then
    lt_task_install_tarball "$tmp" "$platform" "$cache"
    rc=$?
    rm -f "$tmp"
    return "$rc"
  fi
  rm -f "$tmp"
  if [ "$rc" -eq 2 ]; then
    _lt_task_err "go-task is needed and there is no curl or wget to fetch it."
  else
    _lt_task_err "could not download go-task ${LT_TASK_VERSION}."
  fi
  _lt_task_err "On a host without internet access, install from a release archive or an offline bundle:"
  _lt_task_err "both carry ${LT_TASK_BUNDLE_DIR}/task_${platform}.tar.gz. Or copy that file there,"
  _lt_task_err "or install go-task ${LT_TASK_MIN_VERSION}+ yourself, or set LOGSTOTAL_TASK."
  return 1
}

# lt_task_stage_bundled ROOT — put the verified Linux tarballs under ROOT/tools/go-task for
# a release archive, downloading only what is missing or does not match the pin.
lt_task_stage_bundled() {
  local root=$1 dir platform file want rc
  dir="${root}/${LT_TASK_BUNDLE_DIR}"
  mkdir -p "$dir" || return 1
  for platform in $LT_TASK_BUNDLED_PLATFORMS; do
    file="${dir}/task_${platform}.tar.gz"
    want=$(lt_task_sha256_pin "$platform")
    if [ -f "$file" ] && [ "$(lt_sha256 "$file")" = "$want" ]; then
      continue
    fi
    rc=0
    lt_task_download "$platform" "${file}.part" || rc=$?
    if [ "$rc" -ne 0 ] || [ "$(lt_sha256 "${file}.part")" != "$want" ]; then
      rm -f "${file}.part"
      _lt_task_err "could not fetch a verified go-task ${LT_TASK_VERSION} for ${platform}."
      return 1
    fi
    mv -f "${file}.part" "$file"
  done
}
