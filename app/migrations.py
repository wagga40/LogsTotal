"""Automatic schema migrations — Alembic-backed, safe on every deployment path.

Runs at startup (init_db.py and the FastAPI lifespan) and from the upgrade
tasks (``python3 -m app.migrations``). Handles three database states:

- **fresh** — no tables yet: create the schema from the models, then stamp
  Alembic head (the schema produced by ``create_all`` matches head by
  construction; a parity test in ``tests/test_migrations_auto.py`` pins this).
- **legacy unstamped** — tables exist but ``alembic_version`` was never
  written (a database bootstrapped by ``init_db.py`` without auto-migrate).
  The create_all + column-patch pass runs first, then the live schema is
  compared against the models; only a provably
  matching schema is adopted (stamped head). A drifted schema is left
  untouched with a loud warning — never blindly stamped.
- **stamped** — normal Alembic-managed database: upgrade to head when behind.

Workers never import this module — schema changes are the web/init role only.
Set ``AUTO_MIGRATE=false`` to fall back to the legacy create_all-only path
(escape hatch while investigating a failed migration).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.pool import NullPool

from app.config import settings

logger = logging.getLogger("logstotal.migrations")

# The key init_db.py takes too, so replicas on either entry point serialize together.
LOCK_KEY = "logstotal:init_lock"
LOCK_TTL = 600  # seconds; no renewal — comfortably above any migration at this schema size.
# Exceeding it is not silent: _unlock() warns when the lock is no longer ours.
WAIT_TIMEOUT = 600  # how long a non-leader replica waits for the leader to finish
POLL_INTERVAL = 2.0

# Diff kinds from alembic.autogenerate.compare_metadata that do NOT block adopting a
# legacy database: index/constraint presence varies with bootstrap history, and
# modify_* entries (nullability, defaults, types) are dialect-noise on SQLite.
# What must match: the set of tables and columns.
_IGNORED_DIFF_KINDS = {
    "add_index",
    "remove_index",
    "add_constraint",
    "remove_constraint",
    "add_fk",
    "remove_fk",
    "add_table_comment",
    "remove_table_comment",
}


@dataclass
class MigrationStatus:
    current: str | None
    head: str | None
    state: str  # "at_head" | "behind" | "unmanaged" | "fresh" | "unknown"
    pending_count: int

    @property
    def summary(self) -> str:
        cur = self.current or "-"
        head = self.head or "-"
        return f"{cur} → {head} ({self.state})"


def _engine() -> Engine:
    """Short-lived engine on the sync URL — created per call so tests and the
    ``__main__`` entrypoint always see the current settings value."""
    is_sqlite = "sqlite" in (settings.sync_database_url or "")
    return create_engine(
        settings.sync_database_url,
        poolclass=NullPool,
        connect_args={"check_same_thread": False} if is_sqlite else {},
    )


def _alembic_config():
    from alembic.config import Config

    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.sync_database_url)
    # The app already configured logging — env.py must not reconfigure it.
    cfg.attributes["configure_logger"] = False
    return cfg


def get_head_revision() -> str | None:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(_alembic_config()).get_current_head()


def get_current_revision(conn: Connection) -> str | None:
    inspector = inspect(conn)
    if "alembic_version" not in inspector.get_table_names():
        return None
    return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def classify_db(conn: Connection) -> str:
    """Return "fresh" (no app tables), "legacy_unstamped" or "stamped"."""
    inspector = inspect(conn)
    tables = set(inspector.get_table_names())
    if "user" not in tables:
        return "fresh"
    if get_current_revision(conn):
        return "stamped"
    return "legacy_unstamped"


def schema_matches_models(conn: Connection) -> list:
    """Compare the live schema against the ORM models.

    Returns the significant diffs (missing/extra tables or columns) — an empty
    list means the schema can safely be stamped as Alembic head.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    import app.models  # noqa: F401  # populate Base.metadata
    from app.database import Base

    def _include_name(name, type_, parent_names):
        return not (type_ == "table" and name == "alembic_version")

    ctx = MigrationContext.configure(
        conn,
        opts={
            "compare_type": False,
            "compare_server_default": False,
            "include_name": _include_name,
        },
    )
    diffs = compare_metadata(ctx, Base.metadata)

    significant = []
    for diff in diffs:
        kind = diff[0][0] if isinstance(diff, list) else diff[0]
        if kind in _IGNORED_DIFF_KINDS or kind.startswith("modify_"):
            continue
        significant.append(diff)
    return significant


def migration_status() -> MigrationStatus:
    """Current vs head revision — for doctor and the admin System Status card."""
    try:
        head = get_head_revision()
        engine = _engine()
        try:
            with engine.connect() as conn:
                state = classify_db(conn)
                current = get_current_revision(conn)
        finally:
            engine.dispose()
        if state == "fresh":
            return MigrationStatus(None, head, "fresh", 0)
        if state == "legacy_unstamped":
            return MigrationStatus(None, head, "unmanaged", 0)
        if current == head:
            return MigrationStatus(current, head, "at_head", 0)
        pending = _count_pending(current, head)
        return MigrationStatus(current, head, "behind", pending)
    except Exception as exc:
        logger.warning("Could not determine migration status: %s", exc)
        return MigrationStatus(None, None, "unknown", 0)


def _count_pending(current: str | None, head: str | None) -> int:
    from alembic.script import ScriptDirectory

    if head is None:
        return 0
    script = ScriptDirectory.from_config(_alembic_config())
    try:
        return sum(1 for _ in script.iterate_revisions(head, current))
    except Exception:
        return 0


def _create_missing_indexes(conn: Connection) -> int:
    """Create every model-declared index the database does not already have.

    ``create_all(checkfirst=True)`` skips an *existing table* wholesale — including any
    index declared on it since it was created. So on a legacy database every table already
    exists, and every index added in a later release is silently never built.
    ``_migrate_add_missing_columns`` builds only a hand-written list of indexes, never the
    model-declared ones, and ``add_index`` is in ``_IGNORED_DIFF_KINDS`` so the adoption
    verify does not notice either. The database is then stamped at head, which means
    ``alembic upgrade head`` will never run those revisions: the indexes are absent
    permanently — on exactly the long-lived instances that need them most.

    Returns the number created. Failures warn rather than raise: an index that will not
    build is a performance problem, and refusing to boot an existing deployment over one
    is worse than running it unindexed and saying so.
    """
    from app.database import Base

    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())

    created = 0
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables or not table.indexes:
            continue
        have = {ix.get("name") for ix in inspector.get_indexes(table.name)}
        for index in table.indexes:
            if index.name in have:
                continue
            try:
                index.create(bind=conn, checkfirst=True)
                created += 1
                logger.info("Created missing index %s on %s.", index.name, table.name)
            except Exception as exc:
                logger.warning("Could not create index %s on %s: %s", index.name, table.name, exc)
    return created


def _legacy_bootstrap(engine: Engine) -> None:
    """create_all + idempotent column patch + index patch — the historical bootstrap pass."""
    import app.models  # noqa: F401
    from app.database import Base, _migrate_add_missing_columns

    with engine.begin() as conn:
        Base.metadata.create_all(conn)
        _migrate_add_missing_columns(conn)
        _create_missing_indexes(conn)


def _migrate(engine: Engine) -> None:
    from alembic import command

    cfg = _alembic_config()
    head = get_head_revision()

    with engine.connect() as conn:
        state = classify_db(conn)

    if state == "fresh":
        _legacy_bootstrap(engine)
        command.stamp(cfg, "head")
        logger.info("Fresh database created and stamped at Alembic head %s.", head)
        return

    if state == "legacy_unstamped":
        _legacy_bootstrap(engine)
        with engine.connect() as conn:
            diffs = schema_matches_models(conn)
        if not diffs:
            command.stamp(cfg, "head")
            logger.info("Adopted legacy database into Alembic management (stamped head %s).", head)
        else:
            logger.warning(
                "Legacy database schema differs from the models (%d diff(s): %s). "
                "NOT stamping Alembic head — automatic migrations stay disabled for this database. "
                "Reconcile the schema manually, then stamp it: ./logstotal db:stamp -- head "
                "(Docker: docker compose run --rm web python3 -m alembic stamp head)",
                len(diffs),
                "; ".join(str(d[0][0] if isinstance(d, list) else d[0]) for d in diffs[:10]),
            )
        return

    # stamped
    with engine.connect() as conn:
        current = get_current_revision(conn)
    if current == head:
        logger.info("Database schema is at Alembic head (%s).", head)
        return
    logger.info("Upgrading database schema: %s → %s ...", current, head)
    command.upgrade(cfg, "head")
    logger.info("Database schema upgraded to head (%s).", head)


#: Token proving *this* process owns the lock, so the release can tell "still mine"
#: from "expired and re-acquired by someone else". None when we hold no Redis lock
#: (either not acquired, or Redis was unavailable and we proceeded regardless).
_lock_token: str | None = None


def _try_lock() -> bool:
    """Acquire the init lock. Returns True when acquired OR when Redis is
    unavailable, so a single node without Redis still boots."""
    global _lock_token
    try:
        import uuid

        from app.redis_client import get_redis

        token = uuid.uuid4().hex
        if get_redis().set(LOCK_KEY, token, nx=True, ex=LOCK_TTL):
            _lock_token = token
            return True
        _lock_token = None
        return False
    except Exception as exc:
        logger.warning("Redis unavailable for init lock (%s) — proceeding without it.", exc)
        _lock_token = None
        return True


def _unlock() -> None:
    """Release the lock only if we still hold it.

    An unconditional DELETE is unsafe: a migration outliving ``LOCK_TTL`` lets a second
    replica acquire the lock, and this process would then delete *that* replica's lock on
    the way out — admitting a third to run ``alembic upgrade head`` concurrently with the
    second. Checking first also gives us somewhere to say the TTL was exceeded, which is
    the condition an operator needs to know about.

    The check and the delete are two round trips rather than a Lua CAS, so a lock that
    expires in the microseconds between them can still be deleted by us. That residual
    window is a single round trip wide instead of ``LOCK_TTL`` seconds, and keeping it
    scriptless means this exact code runs in tests as well as in production.
    """
    global _lock_token
    token, _lock_token = _lock_token, None
    if token is None:
        return
    try:
        from app.redis_client import get_redis

        r = get_redis()
        if r.get(LOCK_KEY) == token:
            r.delete(LOCK_KEY)
        else:
            logger.warning(
                "Init lock was no longer ours at release — this migration ran longer than LOCK_TTL (%ss) "
                "and another replica may have migrated concurrently. Verify the schema (./logstotal doctor:docker, or ./logstotal doctor on a source checkout).",
                LOCK_TTL,
            )
    except Exception:
        pass


def run_auto_migrate() -> None:
    """Bring the schema to Alembic head, serialized across replicas.

    Raises on migration failure — the caller must NOT serve traffic on a
    half-migrated schema (a visible crash loop beats silent corruption).
    """
    if not settings.auto_migrate:
        logger.warning("AUTO_MIGRATE=false — running legacy create_all bootstrap only (no Alembic).")
        _legacy_bootstrap(_engine())
        return

    deadline = time.monotonic() + WAIT_TIMEOUT
    waited = False
    while True:
        if _try_lock():
            try:
                engine = _engine()
                try:
                    _migrate(engine)
                finally:
                    engine.dispose()
            finally:
                _unlock()
            return
        # Another replica holds the lock — wait for it to finish.
        if not waited:
            logger.info("Another replica is migrating the schema — waiting...")
            waited = True
        time.sleep(POLL_INTERVAL)
        try:
            head = get_head_revision()
            engine = _engine()
            try:
                with engine.connect() as conn:
                    if head is not None and get_current_revision(conn) == head:
                        logger.info("Schema migrated by another replica (head %s).", head)
                        return
            finally:
                engine.dispose()
        except Exception:
            pass
        if time.monotonic() > deadline:
            raise RuntimeError(f"Migration leader did not finish within {WAIT_TIMEOUT}s — refusing to start on an unverified schema.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    run_auto_migrate()
    status = migration_status()
    print(f"Migration status: {status.summary}")
