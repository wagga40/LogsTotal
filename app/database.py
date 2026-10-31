"""Database engines and session factories — async for FastAPI, sync for Huey."""

from datetime import UTC, datetime

from sqlalchemy import create_engine, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

_is_sqlite = "sqlite" in settings.database_url

# How long a writer waits for the lock before giving up with "database is locked".
#
# WAL lets readers and one writer coexist, but only *one* writer — so this is the window a
# route's commit has while a worker is mid-transaction; too short, and queueing a backfill
# while another runs returns a 500 instead of the status chip.
#
# The real protection is that no transaction is held that long (the backfills commit per
# item), so this is the margin for the ordinary case: a big job's own commit, a VACUUM, a
# checkpoint. Deliberately a module constant and not a Settings field, on the
# CHECK_CACHE_TTL_SECONDS argument — a knob here would owe .env.example a line and
# docs/configuration.md a row for something no operator should ever need to tune.
SQLITE_BUSY_TIMEOUT_MS = 15000
# Module constants, not settings, on the same argument: tuning values no operator should touch.
SQLITE_MMAP_BYTES = 256 * 1024 * 1024
SQLITE_JOURNAL_SIZE_LIMIT_BYTES = 64 * 1024 * 1024


def _set_sqlite_pragmas(dbapi_conn, connection_record):
    """Enable WAL mode, enforce foreign keys, and tune SQLite for concurrent performance."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=-64000")  # 64 MB cache
    cursor.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    # Reads through the OS page cache instead of copying pages into SQLite's own buffers.
    # Safe with WAL; a virtual-address reservation, not resident memory.
    cursor.execute(f"PRAGMA mmap_size={SQLITE_MMAP_BYTES}")
    # Sorts and temp indexes in memory, not in a temp file next to the database.
    cursor.execute("PRAGMA temp_store=MEMORY")
    # After a checkpoint the WAL is truncated back to this size, so one large write (a
    # backfill, a VACUUM) does not leave a WAL as large as the database behind for good.
    cursor.execute(f"PRAGMA journal_size_limit={SQLITE_JOURNAL_SIZE_LIMIT_BYTES}")
    # Off by default in SQLite, so without this the default backend would not enforce the
    # constraints its own schema declares: a delete that missed a child table would leave
    # dangling rows here — a nav-bell count over an empty dropdown, links to jobs that no
    # longer exist — while raising ForeignKeyViolation on PostgreSQL. The test suite
    # enables it too, which is what makes that class of bug findable before it ships.
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# ── Pool kwargs for PostgreSQL ─────────────────────────────────────────────────
_pg_pool_kwargs = (
    {}
    if _is_sqlite
    else {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_recycle": settings.db_pool_recycle,
        "pool_pre_ping": True,
    }
)

# ── Async engine (FastAPI routes) ──────────────────────────────────────────────
async_engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    **_pg_pool_kwargs,
)

if _is_sqlite:
    event.listens_for(async_engine.sync_engine, "connect")(_set_sqlite_pragmas)

async_session_maker = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)


async def get_async_session():
    """FastAPI dependency — yields an async DB session."""
    async with async_session_maker() as session:
        yield session


def utc_now_naive() -> datetime:
    """UTC wall time without ``tzinfo``.

    Models use :class:`sqlalchemy.DateTime` without ``timezone=True``, which maps to
    ``TIMESTAMP WITHOUT TIME ZONE`` on PostgreSQL. asyncpg cannot bind timezone-aware
    ``datetime`` values to those columns.
    """
    return datetime.now(UTC).replace(tzinfo=None)


# Every primary key is PostgreSQL `integer`. A larger value there is a bind error rather than
# a missing row, and SQLite's own ceiling (int8) is an OverflowError — both a 500.
INT4_MAX = 2_147_483_647


def parse_row_id(text) -> int | None:
    """A row id from user-typed text, or None when no row could have it.

    ASCII digits only: `str.isdigit()` is also True for '²' and '①', which `int()` then
    refuses. And at most `INT4_MAX`, so both backends answer "no such row" the same way.
    """
    s = str(text or "").strip()
    if not (s.isascii() and s.isdigit()):
        return None
    # Bound before int(): Python refuses strings with thousands of digits. Leading
    # zeroes do not change the value and must not make a small id overflow the guard.
    s = s.lstrip("0") or "0"
    if len(s) > len(str(INT4_MAX)):
        return None
    n = int(s)
    return n if n <= INT4_MAX else None


# ── Sync engine (Huey workers) ─────────────────────────────────────────────────
_is_sqlite_sync = "sqlite" in settings.sync_database_url
_pg_pool_kwargs_sync = (
    {}
    if _is_sqlite_sync
    else {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_recycle": settings.db_pool_recycle,
        "pool_pre_ping": True,
    }
)

sync_engine = create_engine(
    settings.sync_database_url,
    echo=settings.debug,
    connect_args={"check_same_thread": False} if _is_sqlite_sync else {},
    **_pg_pool_kwargs_sync,
)

if _is_sqlite_sync:
    event.listens_for(sync_engine, "connect")(_set_sqlite_pragmas)

SyncSession = sessionmaker(sync_engine, expire_on_commit=False)


def get_sync_session() -> Session:
    """Return a sync DB session for Huey workers. Caller must close."""
    return SyncSession()


# ── Base class ─────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


def _migrate_analysis_confidence(conn):
    from sqlalchemy import inspect, text

    inspector = inspect(conn)
    for table, columns in (("taskresult", ("diagnostics_json", "execution_snapshot")), ("analysisjob", ("execution_snapshot",))):
        existing = {column["name"] for column in inspector.get_columns(table)}
        for column in columns:
            if column not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} TEXT"))
    if conn.dialect.name == "postgresql":
        conn.execute(text("ALTER TYPE taskstatus ADD VALUE IF NOT EXISTS 'PARTIAL'"))


def _move_rule_content_to_rule_text(conn) -> None:
    """The legacy-path twin of migration f3a91c2e7d40: dedupe `finding.rule_content` into
    `rule_text` by SHA-256, point each finding at its row, then drop the old column.

    A copy rather than a shared function because migrations never import app code here.
    `tests/test_migrations_auto.py` runs both paths on the same data.
    """
    import hashlib
    import logging
    import sqlite3

    from sqlalchemy import bindparam, text
    from sqlalchemy import column as sa_column
    from sqlalchemy import table as sa_table
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    logger = logging.getLogger(__name__)

    rule_text = sa_table("rule_text", sa_column("id"), sa_column("sha256"), sa_column("content"))
    insert = pg_insert if conn.dialect.name == "postgresql" else sqlite_insert
    last = 0
    while True:
        rows = conn.execute(
            text("SELECT id, rule_content FROM finding WHERE id > :last AND rule_content IS NOT NULL AND rule_content != '' ORDER BY id LIMIT 2000"), {"last": last}
        ).all()
        if not rows:
            break
        last = rows[-1][0]
        shas = {fid: hashlib.sha256(content.encode("utf-8")).hexdigest() for fid, content in rows}
        contents = {shas[fid]: content for fid, content in rows}
        conn.execute(insert(rule_text).values([{"sha256": s, "content": c} for s, c in contents.items()]).on_conflict_do_nothing(index_elements=["sha256"]))
        ids = dict(conn.execute(text("SELECT sha256, id FROM rule_text WHERE sha256 IN :shas").bindparams(bindparam("shas", expanding=True)), {"shas": list(contents)}).all())
        conn.execute(text("UPDATE finding SET rule_text_id = :rid WHERE id = :fid"), [{"fid": fid, "rid": ids[sha]} for fid, sha in shas.items()])
    if conn.dialect.name != "sqlite" or sqlite3.sqlite_version_info >= (3, 35, 0):
        conn.execute(text("ALTER TABLE finding DROP COLUMN rule_content"))
    else:
        logger.warning("SQLite %s cannot DROP COLUMN; finding.rule_content is left in place, unread", sqlite3.sqlite_version)


def _migrate_add_missing_columns(conn):
    """Add post-bootstrap columns plus a hand-listed set of indexes (idempotent).

    Model-declared indexes are `migrations._create_missing_indexes`' job, not this one.
    """
    from sqlalchemy import inspect, text

    is_pg = conn.dialect.name == "postgresql"
    _true = "TRUE" if is_pg else "1"
    _false = "FALSE" if is_pg else "0"

    _migrate_analysis_confidence(conn)
    inspector = inspect(conn)
    existing = {c["name"] for c in inspector.get_columns("taskresult")}
    if "log_output" not in existing:
        conn.execute(text("ALTER TABLE taskresult ADD COLUMN log_output TEXT"))

    existing_logfile = {c["name"] for c in inspector.get_columns("logfile")}
    if "tlsh_hash" not in existing_logfile:
        conn.execute(text("ALTER TABLE logfile ADD COLUMN tlsh_hash VARCHAR(72)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_logfile_tlsh_hash ON logfile (tlsh_hash)"))

    existing_finding = {c["name"] for c in inspector.get_columns("finding")}
    if "rule_signature" not in existing_finding:
        conn.execute(text("ALTER TABLE finding ADD COLUMN rule_signature VARCHAR(200)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_finding_rule_signature ON finding (rule_signature)"))

    # The ORM selects rule_text_id on every Finding load, so it belongs here too (the
    # _migrate_analysis_confidence precedent). create_all has already made rule_text. The old
    # rule_content column is not read any more; only migration f3a91c2e7d40 moves its text.
    if "rule_text_id" not in existing_finding:
        conn.execute(text("ALTER TABLE finding ADD COLUMN rule_text_id INTEGER REFERENCES rule_text (id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_finding_rule_text_id ON finding (rule_text_id)"))
    if "rule_content" in existing_finding:
        # A legacy database is stamped at head after this pass and never runs f3a91c2e7d40,
        # so the move happens here too: compare_metadata would otherwise report the column
        # as drift and refuse to stamp.
        _move_rule_content_to_rule_text(conn)

    existing_job = {c["name"] for c in inspector.get_columns("analysisjob")}
    if "submitted_filename" not in existing_job:
        conn.execute(text("ALTER TABLE analysisjob ADD COLUMN submitted_filename VARCHAR(512)"))
    if "effective_log_type" not in existing_job:
        type_sql = "logtype" if is_pg else "VARCHAR(32)"
        conn.execute(text(f"ALTER TABLE analysisjob ADD COLUMN effective_log_type {type_sql} NOT NULL DEFAULT 'UNKNOWN'"))
        conn.execute(text("UPDATE analysisjob SET effective_log_type = (SELECT log_type FROM logfile WHERE logfile.id = analysisjob.file_id)"))
    if "analytics_json" not in existing_job:
        conn.execute(text("ALTER TABLE analysisjob ADD COLUMN analytics_json TEXT"))
    if "submitted_by_user_id" not in existing_job:
        conn.execute(text("ALTER TABLE analysisjob ADD COLUMN submitted_by_user_id CHAR(36)"))
    if "submitter_ip" not in existing_job:
        conn.execute(text("ALTER TABLE analysisjob ADD COLUMN submitter_ip VARCHAR(45)"))
    if "is_private" not in existing_job:
        conn.execute(text(f"ALTER TABLE analysisjob ADD COLUMN is_private BOOLEAN NOT NULL DEFAULT {_false}"))

    existing_site = {c["name"] for c in inspector.get_columns("sitesettings")}
    for column, definition in {
        "show_threat_detection": f"BOOLEAN NOT NULL DEFAULT {_true}",
        "max_finding_details": "INTEGER NOT NULL DEFAULT 10",
        "demo_mode": f"BOOLEAN NOT NULL DEFAULT {_false}",
        "max_upload_files": "INTEGER NOT NULL DEFAULT 50",
    }.items():
        if column not in existing_site:
            conn.execute(text(f"ALTER TABLE sitesettings ADD COLUMN {column} {definition}"))

    # Create indexes on FK columns and common query paths if missing (idempotent)
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS ix_analysisjob_file_id ON analysisjob (file_id)",
        "CREATE INDEX IF NOT EXISTS ix_analysisjob_workflow_id ON analysisjob (workflow_id)",
        "CREATE INDEX IF NOT EXISTS ix_analysisjob_created_at ON analysisjob (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_taskresult_job_id ON taskresult (job_id)",
        # The composite, not a task_result_id index of its own: it covers that column too
        # (migration e064602640a4 dropped the redundant single-column one).
        "CREATE INDEX IF NOT EXISTS ix_finding_task_severity ON finding (task_result_id, severity)",
        "CREATE INDEX IF NOT EXISTS ix_analysisjob_status ON analysisjob (status)",
        "CREATE INDEX IF NOT EXISTS ix_analysisjob_finished_at ON analysisjob (finished_at)",
        "CREATE INDEX IF NOT EXISTS ix_analysisjob_file_wf_created ON analysisjob (file_id, workflow_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS ix_analysisjob_submitted_by_user_id ON analysisjob (submitted_by_user_id)",
        "CREATE INDEX IF NOT EXISTS ix_finding_rule_sig_id ON finding (rule_signature, id)",
        "CREATE INDEX IF NOT EXISTS ix_analysisjob_status_finished ON analysisjob (status, finished_at)",
        "CREATE INDEX IF NOT EXISTS ix_logfile_sha256 ON logfile (sha256)",
    ]:
        conn.execute(text(idx_sql))

    # BackgroundTask indexes (table may not exist on fresh installs before models are created)
    try:
        inspector.get_columns("backgroundtask")
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS ix_backgroundtask_status ON backgroundtask (status)",
            "CREATE INDEX IF NOT EXISTS ix_backgroundtask_created_at ON backgroundtask (created_at)",
            "CREATE INDEX IF NOT EXISTS ix_backgroundtask_finished_at ON backgroundtask (finished_at)",
        ]:
            conn.execute(text(idx_sql))
    except Exception:
        pass

    # Entity + EntityJobLink indexes. The tables come from create_all in
    # migrations._legacy_bootstrap; these indexes were added later, so existing DBs that
    # already had the tables need them patched in here.
    all_tables = set(inspector.get_table_names())
    if "ai_provider" in all_tables:
        provider_columns = {c["name"] for c in inspector.get_columns("ai_provider")}
        if "case_system_prompt" not in provider_columns:
            conn.execute(text("ALTER TABLE ai_provider ADD COLUMN case_system_prompt TEXT"))
        for column in ("job_max_prompt_chars", "case_max_prompt_chars"):
            if column not in provider_columns:
                conn.execute(text(f"ALTER TABLE ai_provider ADD COLUMN {column} INTEGER"))
    if "entity" in all_tables:
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS ix_entity_type ON entity (entity_type)",
            "CREATE INDEX IF NOT EXISTS ix_entity_value ON entity (value)",
        ]:
            conn.execute(text(idx_sql))
    if "entity_job_link" in all_tables:
        for idx_sql in [
            # entity_id is covered by the table's own uq_entity_job (entity_id, job_id).
            "CREATE INDEX IF NOT EXISTS ix_entity_job_link_job_entity ON entity_job_link (job_id, entity_id)",
        ]:
            conn.execute(text(idx_sql))
