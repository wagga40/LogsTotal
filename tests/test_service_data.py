"""scripts/lib/service_data.sh — rolling back across one-way changes to service data.

Each crossing was reached by rehearsal, not by reading: a PostgreSQL 16 → 19 move, a
Redis 7 → 8 RDB, a Garage 2.2 → 2.6 metadata migration. What these tests pin is what the
older release would meet if a rollback restored the code and nothing else:

- PostgreSQL: postgres_data again, which is right — but postgres19_data would then be
  taken as current by the NEXT upgrade, reviving rows the rollback abandoned. Marked
  superseded instead, so the next upgrade moves postgres_data across afresh;
- Redis 7 crash-looping on Redis 8's dump.rdb;
- Garage 2.2 refusing metadata 2.5 migrated.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
LIB = REPO_ROOT / "scripts" / "lib" / "service_data.sh"

NEW_COMPOSE = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
NEW_GARAGE = (REPO_ROOT / "Dockerfile.garage").read_text(encoding="utf-8")
OLD_COMPOSE = """services:
  redis:
    image: ${REGISTRY_PREFIX:-}redis:7-alpine
  postgres:
    image: ${REGISTRY_PREFIX:-}postgres:16-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
"""
OLD_GARAGE = "FROM alpine:3.21\nCOPY --from=dxflrs/garage:v2.2.0 /garage /garage\n"


def _tree(root: Path, compose: str, garage: str) -> Path:
    root.mkdir(parents=True)
    (root / "docker-compose.yml").write_text(compose)
    (root / "Dockerfile.garage").write_text(garage)
    return root


def _docker_stub(tmp_path: Path, services: str) -> Path:
    """`docker compose config --services` answers *services*; every call is logged."""
    shim = tmp_path / "shim"
    shim.mkdir()
    log = tmp_path / "docker.log"
    (shim / "docker").write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" | tr '\\n' ' ' >> \"{log}\"; echo >> \"{log}\"\n"
        'case "$*" in "compose config --services") printf \'%s\\n\' ' + " ".join(services.split()) + " ;; esac\n"
        "exit 0\n"
    )
    (shim / "docker").chmod(0o755)
    return shim


def _bash(script: str, cwd: Path, shim: Path) -> subprocess.CompletedProcess[str]:
    env = {"PATH": f"{shim}:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(cwd)}
    return subprocess.run(["bash", "-c", f'set -euo pipefail; . "{LIB}"; {script}'], cwd=cwd, env=env, capture_output=True, text=True, check=False)


@pytest.fixture
def trees(tmp_path):
    current = _tree(tmp_path / "current", NEW_COMPOSE, NEW_GARAGE)
    snapshot = _tree(tmp_path / "snap", OLD_COMPOSE, OLD_GARAGE)
    return current, snapshot


def test_every_crossing_is_found_on_a_host_running_all_three(tmp_path, trees):
    current, snapshot = trees
    shim = _docker_stub(tmp_path, "redis postgres postgres-migrate garage web worker")
    result = _bash(f'service_data_crossings "{snapshot}" .', current, shim)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["postgres", "redis", "garage"]


def test_an_install_without_the_bundled_database_or_garage_hears_only_about_redis(tmp_path, trees):
    """SQLite and local storage: postgres-migrate and garage are not this host's concern,
    and touching them would create their volumes and pull their images."""
    current, snapshot = trees
    shim = _docker_stub(tmp_path, "redis web worker")
    assert _bash(f'service_data_crossings "{snapshot}" .', current, shim).stdout.split() == ["redis"]


def test_rolling_back_between_two_releases_on_the_same_side_crosses_nothing(tmp_path):
    current = _tree(tmp_path / "current", NEW_COMPOSE, NEW_GARAGE)
    snapshot = _tree(tmp_path / "snap", NEW_COMPOSE, NEW_GARAGE)
    shim = _docker_stub(tmp_path, "redis postgres garage")
    assert _bash(f'service_data_crossings "{snapshot}" .', current, shim).stdout.strip() == ""


def test_every_crossing_is_explained(tmp_path):
    shim = _docker_stub(tmp_path, "")
    out = _bash("service_data_explain postgres redis garage", tmp_path, shim).stdout
    assert "postgres19_data" in out and "dump.rdb.from-redis-8" in out and "pre-2.5" in out.replace("before Garage 2.5", "pre-2.5")


def test_the_revert_stops_writers_before_it_touches_any_data(tmp_path):
    shim = _docker_stub(tmp_path, "")
    result = _bash("service_data_revert postgres redis garage", tmp_path, shim)
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "docker.log").read_text().splitlines()
    assert calls[0].strip() == "compose stop web worker"
    # Each service is stopped before its data is changed — Redis in particular rewrites its
    # RDB on shutdown, which would put a Redis 8 file straight back.
    for service, runner in (("postgres", "postgres-migrate"), ("redis", "redis"), ("garage", "garage")):
        stop = [c.strip() for c in calls].index(f"compose stop {service}")
        run = next(i for i, c in enumerate(calls) if c.startswith("compose run") and f" {runner} -c " in c)
        assert stop < run, f"{service}: {calls}"


def test_the_postgres_revert_marks_the_19_cluster_superseded_and_deletes_nothing(tmp_path):
    shim = _docker_stub(tmp_path, "")
    _bash("service_data_revert postgres", tmp_path, shim)
    run = next(c for c in (tmp_path / "docker.log").read_text().splitlines() if c.startswith("compose run"))
    payload = run.split(" -c ", 1)[1]
    assert "touch /new/.logstotal-restore-pending" in payload
    assert "rm " not in payload
    # The marker is the one postgres-migrate.sh reads, and that script discards a 19 cluster
    # carrying it before moving postgres_data across again.
    script = (REPO_ROOT / "postgres-migrate.sh").read_text(encoding="utf-8")
    assert "PENDING=/new/.logstotal-restore-pending" in script and 'rm -rf "$NEW_PGDATA"' in script


def test_the_garage_revert_keeps_the_newer_metadata(tmp_path):
    shim = _docker_stub(tmp_path, "")
    _bash("service_data_revert garage", tmp_path, shim)
    run = next(c for c in (tmp_path / "docker.log").read_text().splitlines() if c.startswith("compose run"))
    assert ".from-garage-2.5" in run and "cp -a .pre-garage-2.5/. ." in run
    # The marker and the copy go, so the next upgrade takes a fresh pre-2.5 copy.
    assert "rm -rf .pre-garage-2.5 .logstotal-garage-version" in run
    # The names agree with what garage-entrypoint.sh writes.
    entry = (REPO_ROOT / "garage-entrypoint.sh").read_text(encoding="utf-8")
    assert 'PRE_MIGRATION="$META/.pre-garage-2.5"' in entry and 'VERSION_MARKER="$META/.logstotal-garage-version"' in entry


# ── wired into the rollbacks ─────────────────────────────────────────────────

from tests.test_deploy_multiserver import _run_deploy  # noqa: E402
from tests.test_upgrade_script import _PINNED, _assert_ordered, _install, _make_stub_dir, _run, _snapshots  # noqa: E402

OLD_REDIS_COMPOSE = "services:\n  redis:\n    image: ${REGISTRY_PREFIX:-}redis:7-alpine\n"
NEW_REDIS_COMPOSE = "services:\n  redis:\n    image: ${REGISTRY_PREFIX:-}redis:8-alpine\n"


def _upgraded_across_redis_8(tmp_path: Path) -> Path:
    """An install whose snapshot ran Redis 7 and whose current tree runs Redis 8."""
    _install(tmp_path, "0.9.14")
    (tmp_path / "docker-compose.yml").write_text(OLD_REDIS_COMPOSE)
    shim = _make_stub_dir(tmp_path)
    assert _run(["docker"], tmp_path, _PINNED, path_prefix=shim).returncode == 0
    (tmp_path / "VERSION").write_text("version: 0.9.15\n")
    (tmp_path / "docker-compose.yml").write_text(NEW_REDIS_COMPOSE)
    return shim


def test_a_single_host_rollback_across_redis_8_is_refused_without_consent(tmp_path):
    shim = _upgraded_across_redis_8(tmp_path)
    result = _run(["rollback"], tmp_path, path_prefix=shim)
    assert result.returncode != 0
    assert "one-way changes to service data" in result.stderr and "Redis" in result.stderr
    assert "ROLLBACK_DATA=previous" in result.stderr
    # Refused before anything was touched.
    assert (tmp_path / "VERSION").read_text() == "version: 0.9.15\n"
    assert _snapshots(tmp_path), "the snapshot is kept for the retry"
    assert "compose run" not in result.stdout


def test_with_consent_the_data_is_set_back_before_the_older_release_starts(tmp_path):
    shim = _upgraded_across_redis_8(tmp_path)
    result = _run(["rollback"], tmp_path, {"ROLLBACK_DATA": "previous"}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    _assert_ordered(
        result.stdout,
        [
            "service data: setting Redis 8's data file aside",
            # (the stop before it is silenced; test_the_revert_stops_writers… covers it)
            "STUB docker compose run --rm --no-deps -T --entrypoint sh redis",
            "(consumed)",
            "STUB docker compose build",
            "STUB docker compose up -d",
        ],
    )
    assert (tmp_path / "VERSION").read_text() == "version: 0.9.14\n"


def test_the_fleet_checks_service_data_before_stopping_anything(tmp_path):
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example.com,w1.example.com", "DEPLOY_ACTION": "rollback", "DEPLOY_STOP": "true"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert out.index("checking the database") < out.index("check cp.example.com's bundled service data") < out.index("stopping stacks")
