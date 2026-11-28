"""The one-time move of the bundled database from PostgreSQL 16 to 19.

The behaviour was rehearsed against real containers — a seeded PostgreSQL 16 stack upgraded
the way `./logstotal upgrade` does it, a second `up` afterwards, a restore that never
finished. These tests pin the wiring each of those runs depended on, because every one of
them fails as data that is silently absent rather than as an error:

- the dump must not carry an extension the postgres image runs by itself. Named
  `*.sql.gz`, it was restored twice — once by the loader, once by the image — and the
  second run failed on "type already exists" and crashed the first start;
- `postgres` must wait for `postgres-migrate` to COMPLETE, or it initialises an empty
  cluster before there is anything to load into it, and serves that;
- while the restore-pending marker is present, `postgres` must refuse to start, or a
  failed restore restarts into an empty database the app then migrates a fresh schema into;
- the healthcheck must use TCP: the image's first-start server listens on its socket
  only, so a socket check reports healthy while the restore is still running.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from app import system_checks

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (REPO_ROOT / "postgres-migrate.sh").read_text(encoding="utf-8")


def _services() -> dict:
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]


def _assigned(name: str) -> str:
    m = re.search(rf'^{name}="?([^"\n]+)"?$', SCRIPT, re.M)
    assert m, f"postgres-migrate.sh no longer assigns {name}"
    return m.group(1)


# The extensions docker-entrypoint.sh in the postgres image executes on first start.
_IMAGE_RUNS = (".sh", ".sql", ".sql.gz", ".sql.xz", ".sql.zst")


def test_the_dump_is_named_so_the_image_ignores_it():
    dump = _assigned("DUMP")
    assert not dump.endswith(_IMAGE_RUNS), f"{dump} would be run by the postgres image itself, a second time"
    loader = _assigned("LOADER")
    assert loader.endswith(".sh"), "the loader is the one file the image must run"
    # And the loader the script writes reads the same file it published.
    assert f"DUMP=/docker-entrypoint-initdb.d/{Path(dump).name}" in SCRIPT


def test_postgres_waits_for_the_migration_to_complete():
    postgres = _services()["postgres"]
    assert postgres["depends_on"]["postgres-migrate"]["condition"] == "service_completed_successfully"
    assert "postgres_migration:/docker-entrypoint-initdb.d:ro" in postgres["volumes"]


def test_postgres_refuses_to_start_while_a_restore_is_pending():
    postgres = _services()["postgres"]
    wrapper = " ".join(postgres["entrypoint"])
    assert ".logstotal-restore-pending" in wrapper and "PG_VERSION" in wrapper and "exit 1" in wrapper
    assert "exec docker-entrypoint.sh" in wrapper
    # The marker the wrapper tests is the one the script writes and the loader removes.
    assert _assigned("PENDING") == "/new/.logstotal-restore-pending"
    assert "PENDING=/var/lib/postgresql/.logstotal-restore-pending" in SCRIPT


def test_the_healthcheck_cannot_pass_during_the_first_start_restore():
    test = " ".join(_services()["postgres"]["healthcheck"]["test"])
    assert "-h 127.0.0.1" in test, "a socket healthcheck reports healthy while the restore still runs"


def test_the_migration_reads_the_old_volume_and_writes_the_new_one():
    migrate = _services()["postgres-migrate"]
    assert migrate["image"].endswith("postgres:16-alpine"), "only a PostgreSQL 16 server can read a 16 data directory"
    assert migrate["profiles"] == ["postgres"]
    assert {"postgres_data:/old", "postgres19_data:/new", "postgres_migration:/out"} <= set(migrate["volumes"])
    assert "./postgres-migrate.sh:/postgres-migrate.sh:ro" in migrate["volumes"]
    # The 19 service mounts the volume root, where 18+ images keep PGDATA/<major>/docker.
    assert "postgres19_data:/var/lib/postgresql" in _services()["postgres"]["volumes"]
    assert _assigned("NEW_PGDATA") == "/new/19/docker"


def test_a_dump_is_published_only_once_it_is_complete():
    # Written to a partial name, checked for pg_dump's closing line, then renamed.
    assert "-- PostgreSQL database dump complete" in SCRIPT
    assert SCRIPT.index("dump complete") < SCRIPT.index('mv "$tmp" "$DUMP"')
    assert SCRIPT.index('mv "$tmp" "$DUMP"') < SCRIPT.index('touch "$PENDING"')


def test_a_second_server_is_never_started_on_a_directory_another_container_serves():
    # The live old server is dumped over the network; a private one is started only when
    # the old one does not answer, and only after its postmaster.pid is given time to go.
    network = SCRIPT.index("pg_isready -q -h postgres")
    private = SCRIPT.index("pg_ctl -D")
    assert network < private
    assert SCRIPT.index('[ -e "$OLD/postmaster.pid" ] || break') < private


# ── the system check ─────────────────────────────────────────────────────────


@pytest.fixture
def host(monkeypatch):
    monkeypatch.setattr(system_checks, "_running_in_container", lambda: False)

    def volumes(names):
        monkeypatch.setattr(system_checks, "_docker_volume_names", lambda: names)

    return volumes


def test_the_leftover_postgres_16_volume_is_reported_once_the_move_happened(host):
    host(["logstotal_postgres_data", "logstotal_postgres19_data", "logstotal_redis_data"])
    result = system_checks.check_postgres_legacy_volume()
    assert result is not None and result.level == system_checks.INFO
    assert "docker volume rm logstotal_postgres_data" in result.fix


@pytest.mark.parametrize(
    "names",
    [
        ["logstotal_postgres_data"],  # not moved yet: that volume is the live database
        ["logstotal_postgres19_data"],  # a fresh 19 install
        ["other_postgres_data", "logstotal_postgres19_data"],  # a different compose project
        [],
        None,  # no Docker CLI
    ],
)
def test_nothing_is_reported_unless_both_volumes_belong_to_one_project(host, names):
    host(names)
    assert system_checks.check_postgres_legacy_volume() is None


def test_the_check_stays_silent_inside_a_container(monkeypatch):
    monkeypatch.setattr(system_checks, "_docker_volume_names", lambda: ["x_postgres_data", "x_postgres19_data"])
    assert system_checks.check_postgres_legacy_volume(in_container=True) is None
