"""Operator outcomes missing from the original command-shape tests."""

from __future__ import annotations

import gzip
import hashlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from db_target import check_rollback, sqlite_path

ROOT = Path(__file__).resolve().parents[1]


def database(path: Path, value: str = "saved"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as con:
        con.execute("CREATE TABLE marker(value TEXT)")
        con.execute("INSERT INTO marker VALUES (?)", (value,))


def shim(path: Path, name: str, body: str):
    path.mkdir(exist_ok=True)
    file = path / name
    file.write_text("#!/bin/sh\n" + body + "\n")
    file.chmod(0o755)


def invoke(tmp_path, script, args=(), **overrides):
    bins = tmp_path / "bin"
    bins.mkdir(exist_ok=True)
    env = {"PATH": f"{bins}:{os.environ['PATH']}", "HOME": str(tmp_path), "NO_COLOR": "1", "DEPLOY_ENV_FILE": str(tmp_path / "absent.env")}
    env.update(overrides)
    return subprocess.run(["bash", str(ROOT / "scripts" / script), *args], cwd=tmp_path, env=env, text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)


def test_backup_uses_the_configured_docker_database_not_the_dev_copy(tmp_path):
    database(tmp_path / "logstotal.db", "development")
    database(tmp_path / "data/logstotal.db", "production")
    result = invoke(tmp_path, "backup.sh", ["sqlite"], BACKUP_CONTEXT="docker")
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(next((tmp_path / "backups").glob("*.db"))) as con:
        assert con.execute("SELECT value FROM marker").fetchone()[0] == "production"


def test_ambiguous_sqlite_target_is_refused(tmp_path):
    database(tmp_path / "logstotal.db")
    database(tmp_path / "data/logstotal.db")
    with pytest.raises(ValueError, match="Both host and Docker"):
        sqlite_path(tmp_path, {})
    assert sqlite_path(tmp_path, {"DATABASE_URL": "sqlite:///custom.db"}) == tmp_path / "custom.db"


@pytest.mark.parametrize("empty", [False, True])
def test_restore_missing_docker_database_and_reject_empty_backup(tmp_path, empty):
    backup = tmp_path / "input.db"
    if empty:
        backup.touch()
    else:
        database(backup)
    shim(tmp_path / "bin", "pgrep", "exit 1")
    shim(tmp_path / "bin", "task", f'exec bash "{ROOT}/scripts/backup.sh" verify')
    result = invoke(tmp_path, "backup.sh", ["restore-sqlite"], BACKUP_CONTEXT="docker", BACKUP_FILE=str(backup))
    assert (result.returncode != 0) == empty, result.stdout + result.stderr
    assert (tmp_path / "data/logstotal.db").exists() != empty
    assert not (tmp_path / "logstotal.db").exists()


def test_external_postgres_is_not_replaced_by_a_running_bundled_server(tmp_path):
    (tmp_path / "docker-compose.yml").touch()
    shim(tmp_path / "bin", "docker", "echo postgres; exit 0")
    shim(tmp_path / "bin", "pg_dump", 'echo "-- PostgreSQL database dump"; echo "$*"')
    url = "postgresql+asyncpg://example:dummy@external.invalid/production"
    result = invoke(tmp_path, "backup.sh", ["postgres"], DATABASE_URL=url)
    assert result.returncode == 0, result.stderr
    contents = gzip.decompress(next((tmp_path / "backups").glob("*.sql.gz")).read_bytes()).decode()
    assert "external.invalid/production" in contents


def test_rollback_checks_restored_database_revision_instead_of_newer_code(tmp_path):
    snapshot = tmp_path / "snapshot"
    revisions = snapshot / "alembic/versions"
    revisions.mkdir(parents=True)
    (revisions / "a.py").write_text('revision: str = "a"\ndown_revision = None\n')
    db = tmp_path / "db.sqlite"
    with sqlite3.connect(db) as con:
        con.execute("CREATE TABLE alembic_version(version_num TEXT)")
        con.execute('INSERT INTO alembic_version VALUES ("b")')
    env = {"DATABASE_URL": f"sqlite:///{db}"}
    with pytest.raises(ValueError, match="Restore the pre-upgrade"):
        check_rollback(snapshot, tmp_path, env, "host")
    with sqlite3.connect(db) as con:
        con.execute('UPDATE alembic_version SET version_num="a"')
    check_rollback(snapshot, tmp_path, env, "host")


@pytest.mark.parametrize("action", ["rollback", "stop-only", "exec", "start-only"])
def test_fleet_mutations_respect_subset(tmp_path, action):
    result = invoke(
        tmp_path,
        "deploy-multiserver.sh",
        DEPLOY_HOSTS="cp.invalid,w1.invalid,w2.invalid",
        DEPLOY_ONLY="w1.invalid",
        DEPLOY_ACTION=action,
        DEPLOY_DRY_RUN="true",
        DEPLOY_CMD="echo selected",
        DEPLOY_STOP="true",
    )
    assert result.returncode == 0, result.stderr
    # The control plane can be health-probed, but no mutation may target it or w2.
    mutations = [line for line in result.stdout.splitlines() if any(term in line for term in (": rollback", ": stopping", ": starting", "echo selected"))]
    assert any("w1.invalid" in line for line in mutations), result.stdout
    assert not any(host in line for line in mutations for host in ("cp.invalid", "w2.invalid")), result.stdout


@pytest.mark.parametrize("fingerprint", [True, False])
def test_editing_an_existing_generated_value_requires_force(tmp_path, fingerprint):
    remote = tmp_path / "install"
    remote.mkdir()
    envs = tmp_path / "envs"
    envs.mkdir()
    before = "# generated by task deploy:env\nHUEY_WORKERS=4\n"
    (remote / ".env").write_text(before.replace("=4", "=12"))
    if fingerprint:
        (remote / ".env.deploy.sha256").write_text(hashlib.sha256(before.encode()).hexdigest())
    (envs / "local.env").write_text(before)
    result = invoke(tmp_path, "deploy-env-push.sh", DEPLOY_HOSTS="local", DEPLOY_REMOTE_DIR=str(remote), DEPLOY_ENV_DIR=str(envs))
    assert "not overwriting" in result.stderr
    assert "HUEY_WORKERS=12" in (remote / ".env").read_text()


@pytest.mark.parametrize("status", ["200", "503", "302"])
def test_health_requires_successful_http_status(tmp_path, status):
    shim(tmp_path / "bin", "curl", """printf '%s\\n' '{"app":"ok","database":"ok","redis":"ok","storage":"ok","workers":1}' """ + status)
    result = invoke(tmp_path, "health-remote.sh", HEALTH_URL="http://unused.invalid")
    assert (result.returncode == 0) == (status == "200"), result.stdout
