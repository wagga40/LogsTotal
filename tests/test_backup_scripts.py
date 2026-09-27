"""Behavior tests for scripts/backup.sh (the extracted backup/restore task family).

Mirrors tests/test_deploy_multiserver.py: real bash, an isolated tmp_path cwd,
a scrubbed environment, and assertions on stdout/stderr text + return codes.
The script resolves scripts/lib/common.sh relative to its own location, so
invoking the repo's script from a tmp_path cwd works while keeping all of its
cwd-relative state (backups/, logstotal.db, …) inside the throwaway directory.
"""

from __future__ import annotations

import gzip
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "backup.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _run(
    action: str,
    tmp_path: Path,
    env_overrides: dict[str, str] | None = None,
    path_prefix: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run `bash scripts/backup.sh <action>` from an isolated cwd."""
    env = {**os.environ}
    for var in ("BACKUP_FILE", "FORCE", "BACKUP_RETENTION_DAYS", "DATABASE_URL", "SYNC_DATABASE_URL", "POSTGRES_PASSWORD", "POSTGRES_HOST", "COMPOSE_PROFILES", "BACKUP_CONTEXT"):
        env.pop(var, None)
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env.get('PATH', '')}"
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["bash", str(SCRIPT), action],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _make_stub_dir(tmp_path: Path, stubs: dict[str, int]) -> Path:
    """Create a dir of `#!/bin/sh; exit N` executables to shim onto PATH."""
    d = tmp_path / "shim"
    d.mkdir(exist_ok=True)
    for name, code in stubs.items():
        p = d / name
        p.write_text(f"#!/bin/sh\nexit {code}\n")
        p.chmod(0o755)
    return d


# ── verify ────────────────────────────────────────────────────────────────────


def test_verify_valid_sqlite_passes(tmp_path: Path):
    db = tmp_path / "good.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE t (x INTEGER)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()
    result = _run("verify", tmp_path, {"BACKUP_FILE": str(db)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "  OK   " in result.stdout
    assert "passed PRAGMA integrity_check (ok)." in result.stdout


def test_verify_corrupted_db_fails(tmp_path: Path):
    db = tmp_path / "bad.db"
    db.write_bytes(b"this is definitely not a sqlite database" * 64)
    result = _run("verify", tmp_path, {"BACKUP_FILE": str(db)})
    assert result.returncode == 1
    assert "  FAIL: " in result.stdout
    assert "failed integrity check" in result.stdout


def test_verify_postgres_dump_passes(tmp_path: Path):
    dump = tmp_path / "dump.sql.gz"
    body = b"--\n-- PostgreSQL database dump\n--\nCREATE TABLE t (x int);\n"
    dump.write_bytes(gzip.compress(body))
    result = _run("verify", tmp_path, {"BACKUP_FILE": str(dump)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "  OK   " in result.stdout
    assert "is a valid, non-empty PostgreSQL dump." in result.stdout


def test_verify_bad_postgres_dump_fails(tmp_path: Path):
    dump = tmp_path / "notpg.sql.gz"
    dump.write_bytes(gzip.compress(b"just some gzipped text without the header\n"))
    result = _run("verify", tmp_path, {"BACKUP_FILE": str(dump)})
    assert result.returncode == 1
    assert "does not contain the expected 'PostgreSQL database dump' header" in result.stdout


def test_verify_uploads_tar_passes(tmp_path: Path):
    payload = tmp_path / "payload.txt"
    payload.write_text("hello\n")
    archive = tmp_path / "uploads.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(payload, arcname="uploads/payload.txt")
    result = _run("verify", tmp_path, {"BACKUP_FILE": str(archive)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "  OK   " in result.stdout
    assert "is a listable tar.gz archive." in result.stdout


def test_verify_unknown_suffix_fails(tmp_path: Path):
    """Pinned to the pre-extraction Taskfile behavior: the `*)` case arm."""
    blob = tmp_path / "mystery.zip"
    blob.write_bytes(b"whatever")
    result = _run("verify", tmp_path, {"BACKUP_FILE": str(blob)})
    assert result.returncode == 1
    assert "cannot determine backup type for" in result.stdout
    assert "(expected a .db, .sql.gz, or .tar.gz file)." in result.stdout


def test_verify_no_backups_errors(tmp_path: Path):
    result = _run("verify", tmp_path)
    assert result.returncode == 1
    assert "no backup files found in backups/" in result.stderr


# ── prune ─────────────────────────────────────────────────────────────────────


def test_prune_non_integer_retention_errors(tmp_path: Path):
    result = _run("prune", tmp_path, {"BACKUP_RETENTION_DAYS": "abc"})
    assert result.returncode == 1
    assert "ERROR: BACKUP_RETENTION_DAYS must be a non-negative integer (got 'abc')." in result.stderr


def test_prune_zero_retention_deletes_all(tmp_path: Path):
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / "a.db").write_text("a")
    (backups / "b.tar.gz").write_text("b")
    result = _run("prune", tmp_path, {"BACKUP_RETENTION_DAYS": "0"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Found 2 file(s) older than 0 day(s) in backups/:" in result.stdout
    assert "Pruned 2 file(s)." in result.stdout
    assert not (backups / "a.db").exists()
    assert not (backups / "b.tar.gz").exists()


def test_prune_missing_backups_dir_is_noop(tmp_path: Path):
    result = _run("prune", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "backups/ is empty or missing — nothing to prune." in result.stdout


def test_prune_removes_aged_keeps_fresh(tmp_path: Path):
    backups = tmp_path / "backups"
    backups.mkdir()
    old = backups / "old.db"
    old.write_text("old")
    fresh = backups / "fresh.db"
    fresh.write_text("fresh")
    thirty_days_ago = time.time() - 30 * 86400
    os.utime(old, (thirty_days_ago, thirty_days_ago))
    # Default retention (14 days); no BACKUP_RETENTION_DAYS in env.
    result = _run("prune", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Pruned 1 file(s)." in result.stdout
    assert not old.exists()
    assert fresh.exists()


# ── restore guards ────────────────────────────────────────────────────────────


def test_restore_sqlite_refuses_while_app_running(tmp_path: Path):
    """Stub pgrep (exit 0 → app running) → refusal, rc 1, no destructive command."""
    dummy = tmp_path / "backup.db"
    dummy.write_text("dummy backup contents")
    shim = _make_stub_dir(tmp_path, {"pgrep": 0})
    result = _run("restore-sqlite", tmp_path, {"BACKUP_FILE": str(dummy)}, path_prefix=shim)
    assert result.returncode == 1
    assert "refusing to restore while the app is running" in result.stderr
    assert "FORCE=yes ./logstotal restore:sqlite" in result.stderr
    # The guard exits before verify / cp — nothing destructive ran.
    combined = result.stdout + result.stderr
    assert "→ verifying backup before restore" not in combined
    assert not (tmp_path / "logstotal.db").exists()


def test_restore_postgres_refuses_while_app_running(tmp_path: Path):
    """The task_hint is parameterized — postgres refusal names its own task."""
    dump = tmp_path / "dump.sql.gz"
    dump.write_bytes(gzip.compress(b"-- PostgreSQL database dump\n"))
    shim = _make_stub_dir(tmp_path, {"pgrep": 0})
    result = _run("restore-postgres", tmp_path, {"BACKUP_FILE": str(dump)}, path_prefix=shim)
    assert result.returncode == 1
    assert "refusing to restore while the app is running" in result.stderr
    assert "FORCE=yes ./logstotal restore:postgres" in result.stderr


def test_restore_sqlite_force_proceeds_past_guard(tmp_path: Path):
    """FORCE=yes + stubbed pgrep/task → gets past the guard to the verify shell-out."""
    dummy = tmp_path / "backup.db"
    dummy.write_text("dummy backup contents")
    shim = _make_stub_dir(tmp_path, {"pgrep": 0, "task": 0})
    result = _run(
        "restore-sqlite",
        tmp_path,
        {"BACKUP_FILE": str(dummy), "FORCE": "yes"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "refusing to restore" not in result.stdout + result.stderr
    assert ">>> verifying backup before restore" in result.stdout
    # It reached the restore itself (cp of the backup over the live DB).
    assert f"Restored {tmp_path / 'logstotal.db'} from:" in result.stdout
    assert (tmp_path / "logstotal.db").exists()


# ── dispatch ──────────────────────────────────────────────────────────────────


def test_unknown_action_prints_usage(tmp_path: Path):
    result = _run("bogus", tmp_path)
    assert result.returncode == 1
    assert "Usage: bash scripts/backup.sh" in result.stderr


def test_missing_action_prints_usage(tmp_path: Path):
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=tmp_path,
        env={
            k: v
            for k, v in os.environ.items()
            if k
            not in (
                "BACKUP_FILE",
                "FORCE",
                "BACKUP_RETENTION_DAYS",
                "DATABASE_URL",
                "SYNC_DATABASE_URL",
                "POSTGRES_PASSWORD",
                "POSTGRES_HOST",
                "COMPOSE_PROFILES",
                "BACKUP_CONTEXT",
            )
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "Usage: bash scripts/backup.sh" in result.stderr


# ── sqlite snapshot: the copy must go source → artifact ──────────────────────


def _seed_live_db(tmp_path: Path, rows: int = 3) -> Path:
    db = tmp_path / "logstotal.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE job (id INTEGER PRIMARY KEY, name TEXT)")
    con.executemany("INSERT INTO job (name) VALUES (?)", [(f"job-{i}",) for i in range(rows)])
    con.commit()
    con.close()
    return db


def _row_count(db: Path) -> int:
    con = sqlite3.connect(db)
    try:
        return con.execute("SELECT count(*) FROM job").fetchone()[0]
    finally:
        con.close()


def test_container_snapshot_copies_source_into_artifact(tmp_path: Path):
    """The exact code the container fallback runs.

    The call is easy to reverse. Python's contract is `source.backup(target)`, so
    `sqlite3.connect(dst).backup(sqlite3.connect(src))` copies the freshly created, empty
    destination *into the live database*: it destroys the data it was asked to protect
    and leaves an empty artifact. `PRAGMA integrity_check` calls an empty database "ok", so
    `task backup:verify` would stamp a green receipt over the loss.

    A test that only exercises `backup.sh` on a machine with the `sqlite3` CLI installed
    never reaches this path.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    try:
        from sqlite_snapshot import snapshot
    finally:
        sys.path.pop(0)

    db = _seed_live_db(tmp_path)
    artifact = tmp_path / "snap.db"

    objects = snapshot(str(db), str(artifact))

    assert _row_count(db) == 3, "the snapshot overwrote the live database"
    assert _row_count(artifact) == 3, "the artifact did not receive the live rows"
    assert objects >= 1


def test_sqlite_backup_preserves_the_live_database_and_copies_its_rows(tmp_path: Path):
    """End-to-end through backup.sh (host-`sqlite3` branch on machines that have it)."""
    db = _seed_live_db(tmp_path)
    result = _run("sqlite", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr

    assert _row_count(db) == 3, "the backup overwrote the live database"

    artifacts = list((tmp_path / "backups").glob("logstotal-*.db"))
    assert len(artifacts) == 1, artifacts
    assert _row_count(artifacts[0]) == 3, "the artifact did not receive the live rows"


def test_sqlite_backup_records_the_artifact_for_the_verify_step(tmp_path: Path):
    _seed_live_db(tmp_path)
    assert _run("sqlite", tmp_path).returncode == 0
    recorded = (tmp_path / "backups" / ".last-backup-path").read_text().strip()
    assert (tmp_path / recorded).is_file()


def test_sqlite_backup_rejects_an_artifact_that_lost_schema_objects(tmp_path: Path):
    """`assert_sqlite_artifact_populated` is the belt to the fixed copy's braces.

    Simulated by shimming `sqlite3` to a no-op that exits 0 without writing anything —
    the same observable outcome as any future snapshot bug that silently produces nothing.
    """
    db = _seed_live_db(tmp_path)
    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    stub = shim / "sqlite3"
    stub.write_text('#!/bin/sh\n: > "$(printf \'%s\' "$2" | sed "s/^\\.backup \'//;s/\'$//")"\nexit 0\n')
    stub.chmod(0o755)

    result = _run("sqlite", tmp_path, path_prefix=shim)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    # Either guard branch is a pass: empty file, or present-but-missing-schema.
    assert "refusing to record it" in output or "not recording it" in output, output
    assert not (tmp_path / "backups" / ".last-backup-path").exists()
    assert _row_count(db) == 3
