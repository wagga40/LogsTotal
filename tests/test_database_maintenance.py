"""SQLite maintenance: connection pragmas, the daily optimise task, and the storage DB card.

Deleting rows frees pages inside a SQLite file and never shrinks it (the dev database was
24.7% free pages, never vacuumed). The daily task reclaims them; these tests pin each branch
of what it decides, on real files.
"""

from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy import create_engine, event, text

pytestmark = pytest.mark.anyio


def _db_with_free_pages(path, *, incremental: bool = False) -> None:
    """A WAL file with whole pages on the freelist: rows deleted in one contiguous block."""
    conn = sqlite3.connect(path, isolation_level=None)
    if incremental:
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t(x TEXT)")
    conn.execute("BEGIN")
    conn.executemany("INSERT INTO t VALUES (?)", [("x" * 1000,)] * 4000)
    conn.execute("COMMIT")
    conn.execute("DELETE FROM t WHERE rowid > 1000")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()


def _pragma(path, name):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(f"PRAGMA {name}").fetchone()[0]
    finally:
        conn.close()


@pytest.fixture()
def sqlite_engine(tmp_path, monkeypatch):
    import app.database as database_mod

    path = tmp_path / "maint.db"
    engines = []

    def use(*, incremental: bool = False):
        _db_with_free_pages(path, incremental=incremental)
        engine = create_engine(f"sqlite:///{path}")
        engines.append(engine)
        monkeypatch.setattr(database_mod, "sync_engine", engine)
        return path

    yield use
    for engine in engines:
        engine.dispose()


def _run():
    from app.workers import tasks

    return tasks._optimize_database_periodic_body()


def test_below_the_threshold_only_statistics_are_refreshed(sqlite_engine, monkeypatch):
    from app.config import settings

    path = sqlite_engine()
    monkeypatch.setattr(settings, "db_vacuum_freelist_percent", 99)
    free_before = _pragma(path, "freelist_count")
    detail = _run()
    assert detail.startswith("statistics refreshed;") and "free pages" in detail
    assert _pragma(path, "freelist_count") == free_before > 0


def test_zero_disables_the_reclaim(sqlite_engine, monkeypatch):
    from app.config import settings

    path = sqlite_engine()
    monkeypatch.setattr(settings, "db_vacuum_freelist_percent", 0)
    _run()
    assert _pragma(path, "freelist_count") > 0
    assert _pragma(path, "auto_vacuum") == 0


def test_a_small_file_is_vacuumed_once_and_switched_to_incremental(sqlite_engine, monkeypatch):
    from app.config import settings

    path = sqlite_engine()
    monkeypatch.setattr(settings, "db_vacuum_freelist_percent", 25)
    size_before = path.stat().st_size
    detail = _run()
    assert "vacuumed" in detail and "incremental" in detail
    assert _pragma(path, "auto_vacuum") == 2  # incremental
    assert _pragma(path, "freelist_count") == 0
    assert path.stat().st_size < size_before


def test_an_incremental_file_reclaims_without_a_rewrite(sqlite_engine, monkeypatch):
    from app.config import settings

    path = sqlite_engine(incremental=True)
    monkeypatch.setattr(settings, "db_vacuum_freelist_percent", 25)
    assert _pragma(path, "auto_vacuum") == 2
    detail = _run()
    assert "returned" in detail
    assert _pragma(path, "freelist_count") == 0


def test_a_large_file_is_flagged_not_vacuumed(sqlite_engine, monkeypatch):
    """A full VACUUM locks the database while it rewrites the file; past the cap a web write
    would wait out SQLITE_BUSY_TIMEOUT_MS and 500, so the task leaves it to an admin."""
    from app.config import settings
    from app.workers import tasks

    path = sqlite_engine()
    monkeypatch.setattr(settings, "db_vacuum_freelist_percent", 25)
    monkeypatch.setattr(tasks, "_AUTO_VACUUM_MAX_BYTES", 1024)
    detail = _run()
    assert "run Vacuum from Storage" in detail
    assert _pragma(path, "freelist_count") > 0
    assert _pragma(path, "auto_vacuum") == 0


def test_postgresql_is_left_to_autovacuum(monkeypatch):
    import app.database as database_mod

    class _PgUrl:
        def get_backend_name(self):
            return "postgresql"

    class _PgEngine:
        url = _PgUrl()

    monkeypatch.setattr(database_mod, "sync_engine", _PgEngine())
    assert "autovacuum" in _run()


def test_a_failing_run_is_recorded_as_failed(monkeypatch, fake_redis):
    import app.database as database_mod
    from app.redis_client import TASK_LAST_RUN_PREFIX
    from app.workers import tasks

    class _Url:
        def get_backend_name(self):
            return "sqlite"

    class _Broken:
        url = _Url()

        def connect(self):
            raise RuntimeError("database unavailable")

    monkeypatch.setattr(database_mod, "sync_engine", _Broken())
    with pytest.raises(RuntimeError):
        tasks.optimize_database_periodic.call_local()
    assert fake_redis.hgetall(f"{TASK_LAST_RUN_PREFIX}optimize_database_periodic").get("outcome") == "error"


def test_new_connections_get_the_tuned_pragmas(tmp_path):
    from app.database import SQLITE_JOURNAL_SIZE_LIMIT_BYTES, SQLITE_MMAP_BYTES, _set_sqlite_pragmas

    engine = create_engine(f"sqlite:///{tmp_path / 'p.db'}")
    event.listen(engine, "connect", _set_sqlite_pragmas)
    try:
        with engine.connect() as conn:
            assert conn.execute(text("PRAGMA mmap_size")).scalar() == SQLITE_MMAP_BYTES
            assert conn.execute(text("PRAGMA temp_store")).scalar() == 2  # MEMORY
            assert conn.execute(text("PRAGMA journal_size_limit")).scalar() == SQLITE_JOURNAL_SIZE_LIMIT_BYTES
            assert conn.execute(text("PRAGMA journal_mode")).scalar() == "wal"
    finally:
        engine.dispose()


async def test_the_storage_db_card_shows_free_pages_wal_and_mode(admin_client):
    resp = await admin_client.get("/admin/storage/db-footprint-partial")
    assert resp.status_code == 200
    for label in ("Free pages", "WAL", "Auto-vacuum", "Last vacuum", "a floor on what Vacuum reclaims"):
        assert label in resp.text, label
