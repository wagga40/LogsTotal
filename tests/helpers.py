"""Shared test helpers: the cached schema, and the auth boilerplate.

**Schema creation** was the duplication that cost real time. `Base.metadata.create_all` is
32.6 ms per call — DDL compilation plus a reflection round-trip per table — and roughly
1,050 tests want a fresh database, plus nine modules that had each written out the same
synchronous fixture. Compiling the DDL once and replaying it as a single `executescript`
is 3.3 ms and produces a byte-identical schema (136 `sqlite_master` rows, compared
directly against `create_all`).

**Auth boilerplate** is here for readability rather than speed: `_login` had been written
out 23 times and `_create_user` 16 times, near-identically. Since
`conftest._fast_password_hashing` those cost almost nothing to run — they just cost to
read.

A third candidate was measured and rejected: caching the template/AST scans that fifteen
modules repeat. It is ~9.6 s of CPU, but `pytest -n auto` already spreads those modules
across workers, so the wall-clock saving was nil and it would have touched fifteen files.

Everything here is import-safe: `app.*` imports happen inside functions, so importing
this module cannot run before `tests/conftest.py` has set the bootstrap env vars.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_PASSWORD = "testpass123"


# ── Schema ───────────────────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def schema_ddl() -> str:
    """Every CREATE TABLE / CREATE INDEX for the ORM metadata, as one SQLite script.

    Compiled once per process. `Base.metadata.sorted_tables` is FK-safe order, which is
    what lets this run as a single script rather than statement by statement.
    """
    from sqlalchemy.dialects import sqlite
    from sqlalchemy.schema import CreateIndex, CreateTable

    import app.models  # noqa: F401  # populate the metadata
    from app.database import Base

    dialect = sqlite.dialect()
    parts: list[str] = []
    for table in Base.metadata.sorted_tables:
        parts.append(str(CreateTable(table).compile(dialect=dialect)).strip())
        parts.extend(str(CreateIndex(index).compile(dialect=dialect)).strip() for index in table.indexes)
    return ";\n".join(parts) + ";"


def make_async_engine():
    """A fresh in-memory async engine with foreign keys ON.

    SQLite disables FKs by default, which made a whole class of bug invisible here and
    fatal on PostgreSQL: a delete that forgets a child table leaves dangling rows silently
    in tests and raises `ForeignKeyViolation` the first time an admin removes a job or a
    user. Two such bugs shipped exactly that way. `app/database.py` sets the same pragma
    for the running app.
    """
    from sqlalchemy import event
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False})

    @event.listens_for(engine.sync_engine, "connect")
    def _enforce_foreign_keys(dbapi_conn, _record):  # pragma: no cover - one statement
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    return engine


async def create_schema(engine) -> None:
    """Replay the cached DDL onto *engine*.

    `executescript` rather than 117 round-trips: 3.3 ms against 16.8 ms. It commits before
    it runs, so it is issued on a bare connection rather than inside `engine.begin()`.
    """
    async with engine.connect() as conn:
        raw = await conn.get_raw_connection()
        await raw.driver_connection.executescript(schema_ddl())


def make_sync_engine():
    """The synchronous twin, for worker-side tests, with the schema already on it.

    Deliberately *not* a copy of `make_async_engine`: no `PRAGMA foreign_keys=ON` and the
    default pool. The worker-side tests it serves do not expect foreign keys, so turning
    them on here would change what they test. `async_db` is where FK enforcement is asserted.
    """
    from sqlalchemy import create_engine

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    with engine.begin() as conn:
        conn.connection.driver_connection.executescript(schema_ddl())
    return engine


# ── Auth ─────────────────────────────────────────────────────────────────────


async def create_user(db, email: str, *, role: str = "user", is_superuser: bool = False, password: str = DEFAULT_PASSWORD, **extra):
    """Create a user through the real `UserManager`, the way registration does.

    Goes through the manager rather than `User(hashed_password=...)` so the row is exactly
    what production writes. `conftest._fast_password_hashing` is what keeps that cheap.
    """
    from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

    from app.auth.schemas import UserCreate
    from app.auth.users import UserManager
    from app.models import User

    manager = UserManager(SQLAlchemyUserDatabase(db, User))
    return await manager.create(UserCreate(email=email, password=password, is_superuser=is_superuser, is_active=True, role=role, **extra))


async def login(client, email: str, password: str = DEFAULT_PASSWORD):
    """Cookie-login *client* as *email*, asserting it worked."""
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": password})
    assert resp.status_code in (200, 204, 303), f"login as {email} failed: {resp.status_code}"
    return client
