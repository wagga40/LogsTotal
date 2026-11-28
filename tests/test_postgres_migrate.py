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


def test_a_superseded_19_cluster_is_discarded_only_when_there_is_a_16_cluster_to_move_again():
    """Discarding it with an empty postgres_data would leave nothing: the 19 cluster is then
    the only copy, and an empty 16 one would be "migrated" over it."""
    branch = SCRIPT[SCRIPT.index('if [ -s "$NEW_PGDATA/PG_VERSION" ] && [ -e "$PENDING" ]; then') :]
    branch = branch[: branch.index("\nfi\n")]
    assert branch.index('[ -s "$OLD/PG_VERSION" ] || die') < branch.index('rm -rf "$NEW_PGDATA"')


# ── the system check ─────────────────────────────────────────────────────────


def test_the_leftover_cluster_is_reported_by_the_name_the_host_hands_in(monkeypatch):
    monkeypatch.setenv(system_checks.HOST_PG16_VOLUME_ENV, "logstotal_postgres_data")
    result = system_checks.check_postgres_legacy_volume()
    assert result is not None and result.level == system_checks.INFO
    assert "logstotal_postgres_data still holds the PostgreSQL 16 cluster" in result.message


def test_the_removal_command_clears_the_container_that_holds_the_volume_first(monkeypatch):
    """`docker volume rm` alone is refused: the stopped postgres-migrate container still
    references the volume (measured on the fleet's control plane)."""
    monkeypatch.setenv(system_checks.HOST_PG16_VOLUME_ENV, "lt_postgres_data")
    fix = system_checks.check_postgres_legacy_volume().fix
    assert "docker compose rm -f postgres-migrate && docker volume rm lt_postgres_data" in fix


@pytest.mark.parametrize("handed_in", [None, "", "   ", "x; rm -rf /", "$(id)"])
def test_nothing_is_reported_without_a_usable_answer_from_the_host(monkeypatch, handed_in):
    """Silent on the System tab and a host doctor (no answer), and for an empty answer: the
    volume exists but holds nothing — every fresh 1.4 install, and every install whose old
    volume was removed and then recreated empty by the next start."""
    if handed_in is None:
        monkeypatch.delenv(system_checks.HOST_PG16_VOLUME_ENV, raising=False)
    else:
        monkeypatch.setenv(system_checks.HOST_PG16_VOLUME_ENV, handed_in)
    assert system_checks.check_postgres_legacy_volume() is None


def test_the_check_never_lists_volumes_by_name_again():
    """Names cannot tell a held cluster from the empty volume Compose recreates."""
    source = (REPO_ROOT / "app" / "system_checks.py").read_text(encoding="utf-8")
    assert "docker volume ls" not in source and "_postgres19_data" not in source


def test_doctor_docker_asks_the_volume_itself_and_hands_the_answer_in_on_both_paths():
    from _taskfile import all_tasks

    script = next(c for c in all_tasks()["doctor:docker"]["cmds"] if isinstance(c, str) and "doctor.py" in c)
    assert ". scripts/lib/service_data.sh" in script and "pg16=$(service_data_pg16_volume)" in script
    invocations = [line for line in script.splitlines() if "scripts/doctor.py" in line]
    assert len(invocations) == 2, invocations
    for line in invocations:
        assert f'-e {system_checks.HOST_PG16_VOLUME_ENV}="$pg16"' in line, line
