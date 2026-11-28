"""The whole Alembic chain, on PostgreSQL, from an empty database to head.

Every other migration test runs on SQLite. That left the migration path PostgreSQL
deployments actually take untested end to end, and it is the path most exposed to a
SQLAlchemy upgrade: 2.1 changed how named types (the enums: jobstatus, severity,
aianalysisstatus, …) are created and dropped on PostgreSQL, and several revisions branch on
`dialect.name == "postgresql"` to ALTER TYPE by hand.

Two checks, one database each:

- `upgrade head` from nothing completes, and the result matches the ORM models
  (`schema_matches_models` — the same comparison the SQLite parity test makes);
- the production boot path, `run_auto_migrate()`, brings an empty database to head.

Runs under `./logstotal test:pg` and in CI, where POSTGRES_TEST_URL is set; skipped (failed,
under CI) otherwise — the same contract as tests/test_postgres_sql_compat.py.
"""

from __future__ import annotations

import os
import secrets

import pytest
from sqlalchemy import create_engine, text

POSTGRES_TEST_URL = os.environ.get("POSTGRES_TEST_URL", "")
IN_CI = bool(os.environ.get("CI"))

pytestmark = pytest.mark.skipif(
    not POSTGRES_TEST_URL and not IN_CI,
    reason="set POSTGRES_TEST_URL (or run `./logstotal test:pg`) to run the migration chain on PostgreSQL",
)


def _url(database: str | None = None) -> str:
    head, _, tail = POSTGRES_TEST_URL.partition("://")
    url = f"{head.split('+')[0]}+psycopg2://{tail}"
    if database:
        url = url.rsplit("/", 1)[0] + "/" + database
    return url


@pytest.fixture
def scratch_database(monkeypatch):
    """A fresh, empty database on the test server, dropped afterwards whatever happens."""
    if not POSTGRES_TEST_URL:
        pytest.fail("POSTGRES_TEST_URL is not set — CI must run the PostgreSQL checks, not skip them")
    name = f"lt_migrate_{secrets.token_hex(4)}"
    admin = create_engine(_url(), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    from app.config import settings

    monkeypatch.setattr(settings, "sync_database_url", _url(name))
    try:
        yield _url(name)
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def test_the_migration_chain_reaches_head_and_matches_the_models(scratch_database):
    from alembic import command
    from app.migrations import _alembic_config, get_head_revision, schema_matches_models

    command.upgrade(_alembic_config(), "head")

    engine = create_engine(scratch_database)
    try:
        with engine.connect() as conn:
            assert conn.scalar(text("SELECT version_num FROM alembic_version")) == get_head_revision()
            diffs = schema_matches_models(conn)
            enum_types = set(conn.scalars(text("SELECT typname FROM pg_type WHERE typtype = 'e'")))
    finally:
        engine.dispose()
    assert diffs == [], f"on PostgreSQL, Alembic head and the ORM models have diverged: {diffs}"
    # The ALTER TYPE revisions only run on a real enum; if these were VARCHARs the
    # comparison above could pass while every enum-specific branch went unexercised.
    assert {"jobstatus", "aianalysisstatus"} <= enum_types, enum_types


def test_the_boot_path_brings_an_empty_postgres_database_to_head(scratch_database, monkeypatch):
    """`run_auto_migrate()` — what the web tier runs at start — rather than `command.upgrade`.

    On an empty database that is create_all + stamp, a different code path from the chain
    above, and the one every fresh PostgreSQL install takes. The Redis leader lock is
    stubbed: serialising replicas is not what is under test.
    """
    from app import migrations
    from app.config import settings
    from app.migrations import get_head_revision, run_auto_migrate

    monkeypatch.setattr(settings, "auto_migrate", True)
    monkeypatch.setattr(migrations, "_try_lock", lambda: True)
    monkeypatch.setattr(migrations, "_unlock", lambda: None)
    run_auto_migrate()

    engine = create_engine(scratch_database)
    try:
        with engine.connect() as conn:
            assert conn.scalar(text("SELECT version_num FROM alembic_version")) == get_head_revision()
    finally:
        engine.dispose()
