#!/usr/bin/env bash
# Bring the Docker stack up for real, prove it is healthy, and run one analysis through it.
#
# Everything else in CI reasons *about* the deployment: `docker compose config -q` parses
# the files, `docker build` builds the image, `verify-artifacts.sh` inspects its
# filesystem. None of it starts the application, so `docker-entrypoint.sh`'s real
# (non-DRYRUN) path, `init_db.py`, migrations inside a container, the worker↔Redis
# registration and every field of `/health` are exercised here and nowhere else.
#
# Environment-shaped bugs — bind-mount ownership, which container answers a question,
# what else writes to stdout — pass code review and unit tests alike. Reading cannot find
# those. Starting the thing can.
#
# What this proves, in order of how much it is worth:
#   1. the image boots with a generated .env, and /health answers 200
#   2. `task doctor:docker` — the preflight `task quickstart` runs — passes in-container
#   3. deploy-smoke.sh's six probes, including "a worker actually registered"
#   4. a real log goes in and real findings come out
#   5. `task upgrade` upgrades that USED deployment — snapshot, overlay, rebuild,
#      migrate, health, doctor — and /health reports the new version afterwards
#   6. `task upgrade:rollback` puts it back, and /health agrees
#
# Step 4 uses the Linux syslog workflow, which runs ChopChopGo — a vendored binary already
# in the image, for both x86_64 and aarch64. No Docker-in-Docker, no image pull, ~2s.
#
# Usage:  bash scripts/ci-deploy-smoke.sh
# Env:    KEEP_STACK=yes   leave the stack running for inspection (skips teardown)
#
# Run locally it behaves exactly like `task docker:up`, which means it writes to the
# bind-mounted ./data and ./uploads and adds one job there. Your .env is moved aside and
# put back — see cleanup() — but those two directories are the stack's own state and are
# left as compose leaves them.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
. "${SCRIPT_DIR}/lib/common.sh"

cd "$REPO_ROOT"

# A run-unique project name isolates containers, networks and volumes, so two CI jobs on
# one runner cannot collide. Exported rather than passed as `-p` so that every
# `docker compose` in this script *and* in `task doctor:docker` inherits it.
COMPOSE_PROJECT_NAME="ltci-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
export COMPOSE_PROJECT_NAME

HEALTH_BUDGET_SECONDS=120
JOB_BUDGET_SECONDS=180
SAMPLE="samples/linux/syslog_intrusion.log"
BASE_URL=""

require_cmd docker "Install Docker Engine + the compose plugin."
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not available"

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    warn "the stack failed; dumping container logs"
    docker compose logs --no-color --tail 120 2>&1 | sed 's/^/    /' || true
    docker compose ps 2>&1 | sed 's/^/    /' || true
  fi
  if truthy "${KEEP_STACK:-}"; then
    info "KEEP_STACK set — leaving ${COMPOSE_PROJECT_NAME} running"
  else
    # -v so the named volumes go too: a stale redis_data or postgres_data would make the
    # next run's "fresh install" not one.
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  # The upgrade step below rsyncs a staged tree over this checkout, and VERSION is tracked.
  # A rollback restores it, but a failure part way through would leave the working copy
  # carrying a version nobody released. Cheap to put back, and it matters most when the run
  # is being done locally.
  if [ -n "${UPGRADE_VERSION_BACKUP:-}" ] && [ -f "$UPGRADE_VERSION_BACKUP" ]; then
    cp "$UPGRADE_VERSION_BACKUP" VERSION 2>/dev/null || true
    rm -f "$UPGRADE_VERSION_BACKUP"
  fi
  ci_env_return
  return $rc
}
trap cleanup EXIT

# ── 1. Configuration ─────────────────────────────────────────────────────────
header "Prepare a first-run configuration"

# .env.example ships SECRET_KEY=change-me-…, which docker-entrypoint.sh refuses outright,
# so a bare copy boots nothing. This is the documented first-run sequence — the same one
# scripts/quickstart.sh performs — which is the point: CI should fail if it stops working.
ci_env_borrow
run_py scripts/gen_secrets.py --write >/dev/null
# Plain HTTP, so the auth cookie must not be Secure or /auth/login is untestable.
grep -q '^COOKIE_INSECURE=' .env || echo 'COOKIE_INSECURE=true' >>.env
# A free port, chosen here and then FIXED. Compose's ephemeral form (`127.0.0.1::8000`)
# is subtly wrong: the published port is read once, and Docker assigns a new
# one if the container is ever recreated — so the poll below silently starts talking to a
# port nothing is listening on, and the run fails as a timeout rather than as whatever the
# container's actual problem was. A fixed port survives a restart and fails loudly if it is
# taken.
web_port=$(run_py -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
grep -q '^WEB_PORT=' .env || echo "WEB_PORT=127.0.0.1:${web_port}:8000" >>.env
mkdir -p data uploads backups
info "configuration written (project ${COMPOSE_PROJECT_NAME})"

# ── 2. Start ─────────────────────────────────────────────────────────────────
header "Start the stack"
# Down first, not only on the way out: a previous run that was killed, or left up with
# KEEP_STACK, otherwise hands this one its containers and its volumes.
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build
BASE_URL="http://127.0.0.1:${web_port}"
info "web is published at ${BASE_URL}"

# ── 3. /health ───────────────────────────────────────────────────────────────
header "Wait for /health"
# Polled rather than read from `docker compose ps --status healthy`: the image's own
# HEALTHCHECK has a 30s interval and no start_period, so the container reports healthy no
# sooner than 30s after it already was.
deadline=$((SECONDS + HEALTH_BUDGET_SECONDS))
until curl -fsS --max-time 5 "${BASE_URL}/health" >/dev/null 2>&1; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    # The body is the diagnosis and the container logs usually are not: /health answers 503
    # with a per-subsystem verdict, so "database": "error" and "storage": "error" are
    # different bugs that look identical from the outside. Printing it turns a timeout from
    # something to re-run into something to read.
    warn "last /health response:"
    curl -s --max-time 5 -w '\n  (HTTP %{http_code})\n' "${BASE_URL}/health" | sed 's/^/    /' || true
    die "/health did not become healthy within ${HEALTH_BUDGET_SECONDS}s"
  fi
  sleep 2
done
curl -fsS "${BASE_URL}/health"
echo ""

# ── 4. The preflight quickstart runs ─────────────────────────────────────────
header "In-container preflight"
# `task quickstart` gates on exactly this. It runs inside the web container, which
# deliberately has no Docker socket, so a check that assumes one fails every clean host.
lt_task doctor:docker

# ── 5. The deployment smoke probes ───────────────────────────────────────────
header "Smoke probes"
# The same script a real multi-server deploy finishes with — /health, database, redis,
# storage, a registered worker, / and /auth/login.
SMOKE_URL="$BASE_URL" bash scripts/deploy-smoke.sh

# ── 6. A real log, a real finding ────────────────────────────────────────────
header "Analyse a sample log end to end"
[ -f "$SAMPLE" ] || die "missing sample: ${SAMPLE}"

# The upload form's workflow list is server-rendered as JSON, which makes it the stable
# way to learn the id — ids are assigned by init_db.py and are not fixed.
workflow_id=$(curl -fsS --max-time 15 "${BASE_URL}/" | run_py scripts/ci_smoke_probe.py workflow-id --log-type syslog)
info "using workflow ${workflow_id} (Linux Syslog / ChopChopGo)"

# Anonymous upload: CsrfMiddleware only gates *cookie-authed* writes, so no login needed.
#
# force_resubmit is what makes this repeatable. `data/` and `uploads/` are bind mounts, so
# `docker compose down -v` — which removes named volumes — leaves them exactly as they
# were: a second run uploads a file whose sha256 is already known, and /upload redirects to
# the *previous* job with `?dup=1` rather than analysing anything, so the run would "pass"
# by reading yesterday's findings. Forcing a resubmit means every run analyses for real.
job_url=$(
  curl -fsS --max-time 60 -o /dev/null -w '%{redirect_url}' \
    -F "file=@${SAMPLE}" \
    -F "workflow_id=${workflow_id}" \
    -F "log_type_override=auto" \
    -F "force_resubmit=true" \
    "${BASE_URL}/upload"
)
# Strip any query string before the id: the redirect carries one on some branches.
job_id="${job_url##*/}"
job_id="${job_id%%\?*}"
case "$job_id" in
  '' | *[!0-9]*) die "POST /upload did not redirect to a job (got '${job_url}')" ;;
esac
info "job ${job_id} submitted"

# Status comes from the same partial the job page polls — `/jobs/{id}/findings.json` is a
# bare list of findings and says nothing about whether the run is over.
deadline=$((SECONDS + JOB_BUDGET_SECONDS))
while :; do
  partial=$(curl -fsS --max-time 10 "${BASE_URL}/jobs/${job_id}/status-partial" 2>/dev/null || true)
  # An empty body means the request failed outright; treat it as not-yet and keep waiting
  # rather than feeding the probe something it will rightly refuse to interpret.
  if [ -n "$partial" ]; then
    status=$(printf '%s' "$partial" | run_py scripts/ci_smoke_probe.py job-status)
    [ "$status" = "pending" ] || break
  fi
  [ "$SECONDS" -lt "$deadline" ] || die "job ${job_id} was still running after ${JOB_BUDGET_SECONDS}s"
  sleep 3
done

[ "$status" = "completed" ] || die "job ${job_id} finished as '${status}', not 'completed'"

findings=$(curl -fsS --max-time 15 "${BASE_URL}/jobs/${job_id}/findings.json" | run_py scripts/ci_smoke_probe.py findings-count)
# The assertion that matters. A stack that boots, reports healthy and then finds nothing
# is the shape of a storage or database misconfiguration: no error anywhere, just an empty
# result. `samples/linux/syslog_intrusion.log` exists to trip the Sigma rules.
[ "$findings" -gt 0 ] || die "job ${job_id} completed with ZERO findings — the detection path is broken, not the boot path"

info "job ${job_id} completed with ${findings} finding(s)"

# ── 6. Upgrade, for real ─────────────────────────────────────────────────────
#
# tests/test_upgrade_script.py drives real bash but stubs `task`, `docker` and `git`, so the
# rsync overlay, the image rebuild from an overlaid tree, `python3 -m app.migrations` against
# a live database, and the snapshot are executed for real only here.
#
# The stack is already up with a database that has real rows in it, which is what makes this
# worth doing here rather than in a unit test: this is an upgrade of a USED deployment.
header "Upgrade the running stack"

before_version=$(run_py scripts/ci_smoke_probe.py health-version <<<"$(curl -fsS --max-time 10 "${BASE_URL}/health")" 2>/dev/null || true)
[ -n "$before_version" ] || before_version=$(read_version_file)
info "running ${before_version}"

# Stage FROM this checkout, with a version nobody has released, so the assertion afterwards
# is that the upgrade actually landed — not that two identical trees are identical. A tar
# archive rather than a .7z keeps this independent of which 7-Zip the runner has.
UPGRADE_VERSION_BACKUP=$(mktemp)
export UPGRADE_VERSION_BACKUP
cp VERSION "$UPGRADE_VERSION_BACKUP"

staged=$(mktemp -d)
tar -cf - --exclude=./.git --exclude=./data --exclude=./uploads --exclude=./backups \
    --exclude=./.venv --exclude=./node_modules . | (cd "$staged" && tar -xf -)
# Assembled from parts, not written as a literal: scripts/*.sh are swept by
# `task release:prepare`, and tests/test_docs_in_sync.py fails on any version-shaped token
# that is not the current release. This one is deliberately a version nobody will ever cut.
synthetic=$(printf '%d.%d.%d' 99 0 0)
printf 'version: %s\n' "$synthetic" >"${staged}/VERSION"
archive="${staged}.tar.gz"
tar -czf "$archive" -C "$staged" .
rm -rf "$staged"

# The real task, with its real steps: backup, snapshot, overlay, build, stop, migrate, up,
# health, doctor. SKIP_BACKUP is NOT set — the backup is one of the things being tested.
HEALTH_URL="$BASE_URL" ARCHIVE="$archive" lt_task upgrade
rm -f "$archive"

after_version=$(run_py scripts/ci_smoke_probe.py health-version <<<"$(curl -fsS --max-time 10 "${BASE_URL}/health")" 2>/dev/null || true)
[ "$after_version" = "$synthetic" ] || die "the upgrade reported success but /health still says '${after_version}' — the overlay or the rebuild did not take"
info "upgraded: /health reports ${after_version}"

# The job from step 5 must survive an upgrade. A migration that dropped the data, or a
# rebuild that pointed at a fresh volume, looks like a clean upgrade from every other angle.
surviving=$(curl -fsS --max-time 15 "${BASE_URL}/jobs/${job_id}/findings.json" | run_py scripts/ci_smoke_probe.py findings-count)
[ "$surviving" -eq "$findings" ] || die "job ${job_id} had ${findings} finding(s) before the upgrade and ${surviving} after"
info "the pre-upgrade job still has its ${surviving} finding(s)"

# ── 7. Roll it back ──────────────────────────────────────────────────────────
header "Roll the upgrade back"
# Restores the snapshot the upgrade took, rebuilds and restarts. A tree restore alone would
# leave the containers on the newer image, which is precisely what this asserts against.
HEALTH_URL="$BASE_URL" task -y upgrade:rollback

rolled_version=$(run_py scripts/ci_smoke_probe.py health-version <<<"$(curl -fsS --max-time 10 "${BASE_URL}/health")" 2>/dev/null || true)
[ "$rolled_version" = "$before_version" ] || die "rollback left /health reporting '${rolled_version}', expected '${before_version}'"
info "rolled back: /health reports ${rolled_version}"

header "DEPLOYMENT SMOKE PASSED"
