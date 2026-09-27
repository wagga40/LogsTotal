#!/usr/bin/env bash
# Run the whole 8-step deploy chain against hosts that cannot exist, and prove it never
# reached the network.
#
# The dry-run seam in lib/common.sh makes the chain runnable with no fleet, and this is
# what keeps that true: a step that ignores DEPLOY_DRY_RUN would fire real requests at the
# first DEPLOY_HOSTS entry, and nothing else would notice.
#
# What this proves: the chain completes, in order, touching nothing. What it cannot: any
# behaviour of a real remote shell. Fish and other non-POSIX shells are not tested in CI.
#
# Usage:  bash scripts/ci-deploy-dry-run.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

cd "$REPO_ROOT"

LOG_DIR=$(mktemp -d)

# The generated env files go to a temp directory, never the repo's own deploy-envs/.
# Step 5/8 writes one .env per host plus the fleet's secrets; in the repo's deploy-envs/
# they would sit beside a developer's real fleet files — gitignored, so never surfaced —
# and mislead anything that reads that directory to decide what state a fleet is in.
DEPLOY_ENV_DIR=$(mktemp -d)
export DEPLOY_ENV_DIR
trap 'rm -rf "$LOG_DIR" "$DEPLOY_ENV_DIR"; rm -f "${REPO_ROOT}"/logstotal-*.7z' EXIT

# .invalid is reserved by RFC 2606 and can never resolve, so any resolution error in the
# output is proof that something tried to connect for real.
export DEPLOY_DRY_RUN=true
export DEPLOY_VPN=wireconf

step "The whole chain, connecting to nothing"
# stdin closed on purpose: a step that waits on a terminal must fail here rather than hang
# a runner for its whole timeout.
DEPLOY_HOSTS="cp.invalid,w1.invalid,w2.invalid" \
  lt_task deploy </dev/null | tee "${LOG_DIR}/dry.log"

for n in 1 2 3 4 5 6 7 8; do
  grep -q "Step ${n}/8" "${LOG_DIR}/dry.log" || die "step ${n}/8 never ran — the chain stopped early"
done
info "all 8 steps ran"

if grep -qiE 'could not resolve|connection refused|SMOKE FAILED' "${LOG_DIR}/dry.log"; then
  warn "a dry run attempted real network I/O:"
  grep -iE 'could not resolve|connection refused|SMOKE FAILED' "${LOG_DIR}/dry.log" >&2
  die "DEPLOY_DRY_RUN must not connect to anything"
fi
info "no network I/O"

step "A dry-run preflight must not claim hosts are ready"
DEPLOY_HOSTS="cp.invalid,w1.invalid" \
  lt_task deploy:preflight </dev/null | tee "${LOG_DIR}/pre.log"

grep -q "PREFLIGHT NOT RUN" "${LOG_DIR}/pre.log" || die "a dry-run preflight must say it measured nothing"
# It measured nothing, so "all N host(s) ready for deployment" would be a lie — and that is
# the shape of claim this whole file exists to catch.
! grep -q "PASSED" "${LOG_DIR}/pre.log" || die "a dry-run preflight reported PASSED without measuring anything"
info "reported honestly"

header "DEPLOY DRY RUN PASSED"
