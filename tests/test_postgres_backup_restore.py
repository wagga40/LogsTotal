"""A disposable PostgreSQL proves dump integrity is also a usable restore.

Run with LOGSTOTAL_TEST_DOCKER=1; no existing database is used.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.environ.get("LOGSTOTAL_TEST_DOCKER") != "1", reason="requires disposable Docker services (task test:pg)")


def test_postgres_backup_restores_rows_into_empty_database(tmp_path):
    docker = shutil.which("docker")
    assert docker
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  postgres:\n    image: postgres:16-alpine\n    environment:\n      POSTGRES_PASSWORD: test-only\n      POSTGRES_USER: logstotal\n      POSTGRES_DB: logstotal\n"
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith(("POSTGRES", "DATABASE", "SYNC_DATABASE", "COMPOSE", "BACKUP", "DEPLOY", "FORCE"))}
    env.update(POSTGRES_PASSWORD="test-only", POSTGRES_USER="logstotal", POSTGRES_DB="logstotal", POSTGRES_HOST="postgres")
    bins = tmp_path / "bin"
    bins.mkdir()
    for name, body in {"task": f'exec bash "{ROOT}/scripts/backup.sh" verify', "pgrep": "exit 1"}.items():
        file = bins / name
        file.write_text("#!/bin/sh\n" + body + "\n")
        file.chmod(0o755)
    env["PATH"] = str(bins) + os.pathsep + env["PATH"]

    def run(*args, **kwargs):
        return subprocess.run(args, cwd=tmp_path, env=env, text=True, capture_output=True, check=True, **kwargs)

    def sql(statement, db="logstotal"):
        return run(docker, "compose", "exec", "-T", "postgres", "psql", "-U", "logstotal", "-d", db, "-At", "-v", "ON_ERROR_STOP=1", "-c", statement).stdout.strip()

    try:
        run(docker, "compose", "up", "-d", "--wait")
        run(docker, "compose", "exec", "-T", "postgres", "sh", "-c", "until pg_isready -U logstotal -q; do sleep 1; done", timeout=45)
        sql("CREATE TABLE recovery_marker(value text); INSERT INTO recovery_marker VALUES ('recovered')")
        run("bash", str(ROOT / "scripts/backup.sh"), "postgres")
        artifact = next((tmp_path / "backups").glob("*.sql.gz"))
        sql("CREATE DATABASE recovered")
        env.update(BACKUP_FILE=str(artifact), DATABASE_URL="postgresql://logstotal:test-only@postgres/recovered")
        run("bash", str(ROOT / "scripts/backup.sh"), "restore-postgres")
        assert sql("SELECT value FROM recovery_marker", "recovered") == "recovered"
        assert sql("SELECT value FROM recovery_marker") == "recovered"
        # A nonempty target must fail transactionally, preserving its existing data.
        failed = subprocess.run(["bash", str(ROOT / "scripts/backup.sh"), "restore-postgres"], cwd=tmp_path, env=env, text=True, capture_output=True)
        assert failed.returncode != 0
        assert sql("SELECT value FROM recovery_marker", "recovered") == "recovered"
    finally:
        run(docker, "compose", "down", "--volumes")
