#!/usr/bin/env bash
# Put the tools CI needs on the PATH, on a runner that has no sudo.
#
# One installer for every workflow, rather than a pasted "Provide <tool>" block per tool,
# each with its own uname switch, `$HOME/.local/bin` guard and failure message — copies
# that drift where nobody can see them.
#
# Every tool here is a dependency GitHub's ubuntu-latest happens to satisfy by luck, so
# the dependency is undeclared upstream and only shows up on a runner that does not ship
# it. Installing is a download, never a package manager: the Forgejo runner is PEP 668
# externally-managed with no sudo, so `apt` and `pip install --user` are both unavailable.
#
# Everything lands in $HOME/.local/bin (or $HOME/.ci-pdm for pdm), which **persists
# between runs on a host executor** — so the first run downloads and every run after it
# is a no-op. That is the whole caching strategy, and it needs no cache key: a tool is
# "cached" only while it reports the version pinned below, so a bump reinstalls it once.
# (Keyed on presence alone, the runner kept the first version it ever downloaded.)
#
# Usage:
#   bash scripts/ci-provision.sh shellcheck sqlite3 7z jq pdm tailwind
#   bash scripts/ci-provision.sh --report        # print what CI is running on
#
# Appends $HOME/.local/bin to $GITHUB_PATH when that file exists, so later steps see it.
# Safe to run locally: with GITHUB_PATH unset it just installs and says where.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

BIN_DIR="${HOME}/.local/bin"
PDM_VENV="${HOME}/.ci-pdm"

SHELLCHECK_VERSION="v0.11.0"
# sqlite.org's own encoding: 3540100 is 3.54.1, published under /2026/.
SQLITE_VERSION="3540100"
SQLITE_YEAR="2026"
SEVENZIP_VERSION="26.06"
JQ_VERSION="1.8.2"
PDM_VERSION="2.29.7"
# Kept in step with Taskfile.yml's TAILWIND_VERSION and the Dockerfile ARG — this one
# compiles the CSS shipped in every release archive. tests/test_version_pins.py holds the
# three copies together (they had drifted: 3.4.17 here, 3.4.19 elsewhere).
TAILWIND_VERSION="4.3.5"

fail() { echo "::error::$1" >&2; exit 1; }

# `uname -m` spellings vary; normalise once so no caller repeats the switch.
arch_key() {
  case "$(uname -m)" in
    x86_64 | amd64) echo x86_64 ;;
    aarch64 | arm64) echo aarch64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
}

fetch() { curl -fsSL --max-time 180 "$1" -o "$2" || fail "download failed: $1"; }

# True when the tool is already usable, either on the PATH or from a previous run's cache.
have() { command -v "$1" >/dev/null 2>&1 || [ -x "${BIN_DIR}/$1" ]; }

sqlite_dotted() {
  local v=$SQLITE_VERSION
  echo "$((v / 1000000)).$((v / 10000 % 100)).$((v / 100 % 100))"
}

# pinned TOOL — true when the copy this run would use reports the pinned version. main()
# puts $BIN_DIR first on PATH, so that is the cached copy when there is one.
#
# Each banner is captured and then matched, never piped into `grep -q`: under pipefail,
# grep exiting on its first match can leave the writer a SIGPIPE that fails the pipeline,
# and the check would then miss every time.
pinned() {
  local out nl=$'\n'
  case "$1" in
    shellcheck)
      out=$(shellcheck --version 2>/dev/null || true)
      [[ "${nl}${out}${nl}" == *"${nl}version: ${SHELLCHECK_VERSION#v}${nl}"* ]] ;;
    sqlite3)
      # Upstream publishes x86_64 only, so elsewhere any sqlite3 will do.
      [ "$(arch_key)" = x86_64 ] || { have sqlite3; return; }
      out=$(sqlite3 --version 2>/dev/null || true)
      [[ "$out" == "$(sqlite_dotted) "* ]] ;;
    7z)
      # 7zz's banner: "7-Zip (z) 26.06 (x64) : Copyright …". p7zip's says "7-Zip [64] 16.02",
      # so a runner's own p7zip is replaced too, and every archive is built by one 7-Zip.
      out=$(7z 2>/dev/null || true)
      [[ "$out" == *"7-Zip (z) ${SEVENZIP_VERSION} "* ]] ;;
    jq)
      out=$(jq --version 2>/dev/null || true)
      [ "$out" = "jq-${JQ_VERSION}" ] ;;
    pdm)
      out=$("${PDM_VENV}/bin/pdm" --version 2>/dev/null || true)
      [ "$out" = "PDM, version ${PDM_VERSION}" ] ;;
    tailwind)
      tailwind_is_pinned tools/tailwind/tailwindcss ;;
    *) return 1 ;;
  esac
}

tailwind_is_pinned() {
  local out nl=$'\n'
  out=$("$1" --help 2>&1 || true)
  [[ "${nl}${out}${nl}" == *"tailwindcss v${TAILWIND_VERSION}${nl}"* ]]
}

install_shellcheck() {
  local arch tarball
  arch=$(arch_key)
  tarball=/tmp/shellcheck.tar.xz
  fetch "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.${arch}.tar.xz" "$tarball"
  tar -xJf "$tarball" -C /tmp
  install -m 0755 "/tmp/shellcheck-${SHELLCHECK_VERSION}/shellcheck" "${BIN_DIR}/shellcheck"
}

install_sqlite3() {
  # Upstream publishes an x86_64 build only. A warning rather than an error: on aarch64
  # the backup tests fail with a message naming sqlite3, which is more useful than this
  # step failing before anything has run.
  [ "$(arch_key)" = "x86_64" ] || { echo "::warning::no static sqlite3 for $(uname -m); scripts/backup.sh tests will fail"; return 0; }
  fetch "https://www.sqlite.org/${SQLITE_YEAR}/sqlite-tools-linux-x64-${SQLITE_VERSION}.zip" /tmp/sqlite.zip
  # python3 rather than unzip: the runner is guaranteed to have one and not the other.
  python3 -m zipfile -e /tmp/sqlite.zip /tmp/sqlite-tools/
  find /tmp/sqlite-tools -name sqlite3 -type f -exec install -m 0755 {} "${BIN_DIR}/sqlite3" \;
}

install_7z() {
  local arch key
  arch=$(arch_key)
  case "$arch" in x86_64) key=x64 ;; aarch64) key=arm64 ;; esac
  # 7-zip.org now links its Linux builds from the project's GitHub releases.
  fetch "https://github.com/ip7z/7zip/releases/download/${SEVENZIP_VERSION}/7z${SEVENZIP_VERSION//./}-linux-${key}.tar.xz" /tmp/7z.tar.xz
  tar -xJf /tmp/7z.tar.xz -C /tmp 7zz
  # Installed as `7z`: scripts/package.sh gates on `command -v 7z`, and 7zz is
  # command-line compatible for the `a` and `l` verbs it and verify-artifacts.sh use.
  install -m 0755 /tmp/7zz "${BIN_DIR}/7z"
}

install_jq() {
  local arch key
  arch=$(arch_key)
  case "$arch" in x86_64) key=amd64 ;; aarch64) key=arm64 ;; esac
  fetch "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${key}" /tmp/jq
  install -m 0755 /tmp/jq "${BIN_DIR}/jq"
}

# pdm goes in its own venv, not $BIN_DIR: the runner's interpreter is PEP 668
# externally-managed, so `pip install --user` fails outright and --break-system-packages
# would mutate the runner's own Python for every repo it serves.
install_pdm() {
  python3 -m venv "$PDM_VENV"
  "${PDM_VENV}/bin/pip" install --quiet --upgrade pip
  # Pinned: it reads and writes pdm.lock, and an unpinned install was whatever PyPI had
  # on the day the runner's cache was filled.
  "${PDM_VENV}/bin/pip" install --quiet "pdm==${PDM_VERSION}"
}

# The Tailwind CLI is what makes scripts/package.sh build production CSS. Without it
# package.sh warns and ships development CSS, so the archive CI verifies would not be the
# archive a release publishes. It is ~46 MB, so the cache matters.
install_tailwind() {
  local arch key dest
  arch=$(arch_key)
  case "$arch" in x86_64) key=linux-x64 ;; aarch64) key=linux-arm64 ;; esac
  dest="${PWD}/tools/tailwind/tailwindcss"
  mkdir -p "${PWD}/tools/tailwind"
  # The checkout's copy is gone every run, but ~/.local/bin keeps one between runs.
  if ! tailwind_is_pinned "${BIN_DIR}/tailwindcss"; then
    fetch "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-${key}" /tmp/tailwindcss
    install -m 0755 /tmp/tailwindcss "${BIN_DIR}/tailwindcss"
  fi
  # package.sh looks for it at tools/tailwind/tailwindcss inside the checkout, which is
  # wiped every run — so the cached copy is linked into place rather than re-downloaded.
  cp "${BIN_DIR}/tailwindcss" "$dest"
  chmod +x "$dest"
}

report() {
  # Printed once per run so the right `-n` for pytest and the right runner `capacity`
  # stop being guesses. Costs nothing and answers the question the logs never could.
  # `|| true` on each: pipefail makes a missing `free` fail the whole assignment, and a
  # report step must never be the thing that fails a build.
  local mem cpus
  mem=$(free -m 2>/dev/null | awk '/^Mem:/{print $2 "MB"}' || true)
  cpus=$(nproc 2>/dev/null || true)
  info "runner: $(uname -s) $(uname -m) | cpus: ${cpus:-?} | mem: ${mem:-?}"
  info "python: $(python3 --version 2>&1) | docker: $(docker --version 2>/dev/null || echo 'absent')"
}

main() {
  [ $# -gt 0 ] || fail "usage: ci-provision.sh <tool>... | --report"

  mkdir -p "$BIN_DIR"
  # GITHUB_PATH is how a step exports PATH to the ones after it. Absent when run locally.
  [ -n "${GITHUB_PATH:-}" ] && echo "$BIN_DIR" >>"$GITHUB_PATH"
  export PATH="${BIN_DIR}:${PDM_VENV}/bin:${PATH}"

  for tool in "$@"; do
    [ "$tool" = --report ] && { report; continue; }
    pinned "$tool" && { info "${tool}: cached"; continue; }
    info "${tool}: installing"
    case "$tool" in
      shellcheck) install_shellcheck ;;
      sqlite3) install_sqlite3 ;;
      7z) install_7z ;;
      jq) install_jq ;;
      pdm) install_pdm ;;
      tailwind) install_tailwind ;;
      *) fail "unknown tool: ${tool}" ;;
    esac
    # A download that installs something other than the pin would otherwise be redone on
    # every run, silently. sqlite3 off x86_64 has nothing to install (see install_sqlite3).
    if ! pinned "$tool" && ! { [ "$tool" = sqlite3 ] && [ "$(arch_key)" != x86_64 ]; }; then
      fail "${tool}: installed, but it does not report the pinned version"
    fi
  done

  # Appended once, after any install, so a cached run does not duplicate the entry.
  if [ -n "${GITHUB_PATH:-}" ] && [ -d "${PDM_VENV}/bin" ]; then
    echo "${PDM_VENV}/bin" >>"$GITHUB_PATH"
  fi
}

main "$@"
