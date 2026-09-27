"""Shared test fixtures and env-var bootstrap.

Environment variables are set BEFORE any `app.*` imports so that
pydantic-settings reads test-safe values.
"""

from __future__ import annotations

import os
from pathlib import Path

# ── Bootstrap env vars before app imports ────────────────────────────────────
# Force test-safe values even when Taskfile loads production-like .env values.
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["DEBUG"] = "true"  # cookies must not be Secure over http://test
os.environ["UPLOAD_RATE_LIMIT_PER_MINUTE"] = "0"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"
os.environ["SYNC_DATABASE_URL"] = "sqlite://"
# `./logstotal test` runs pytest under go-task, which exports its own path as
# LOGSTOTAL_TASK_BIN (Taskfile.yml). Every script a test launches would inherit it, and
# `lt_task` would run the real go-task instead of the `task` stub the test put on PATH.
os.environ.pop("LOGSTOTAL_TASK_BIN", None)

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def tmp_file(tmp_path: Path):
    """Factory fixture: write *content* (str or bytes) to a temp file, return its Path."""

    def _make(content: str | bytes, name: str = "sample.log") -> Path:
        p = tmp_path / name
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        return p

    return _make


# ── Password hashing ─────────────────────────────────────────────────────────


@pytest.fixture(scope="session", autouse=True)
def _fast_password_hashing():
    """Swap fastapi-users' Argon2 parameters for cheap ones, suite-wide.

    Measured without it: **1813 hashes + 823 verifies = 84.4 s of a 252 s run**,
    a third of the whole suite, spent proving that Argon2 is slow. `PasswordHelper()`
    defaults to pwdlib's `Argon2Hasher()`, which is RFC 9106 low-memory — time_cost=3,
    memory_cost=64 MiB, parallelism=4 — so every fixture user and every login costs ~34 ms
    *and a 64 MiB allocation*, and the `admin_client`/`member_client`/`user_client` chain
    pays it twice per test.

    Patching `PasswordHelper.__init__` rather than a manager attribute is what makes this
    total: `BaseUserManager.__init__` does `self.password_helper = PasswordHelper()`, and
    `routers/admin.py` + `system_checks.py` construct their own for the default-password
    banner. All three reach the same class object.

    Bcrypt is dropped from the chain deliberately — nothing in the suite verifies a
    bcrypt-format hash, and keeping it would leave the slow path one `hash()` call away.

    `tests/test_password_hashing.py` pins that production still gets the real parameters.
    """
    from fastapi_users import password as fu_password
    from pwdlib import PasswordHash
    from pwdlib.hashers.argon2 import Argon2Hasher

    # memory_cost=8 KiB is argon2's floor for parallelism=1.
    cheap = PasswordHash((Argon2Hasher(time_cost=1, memory_cost=8, parallelism=1),))
    original_init = fu_password.PasswordHelper.__init__

    def _init(self, password_hash=None):
        self.password_hash = password_hash or cheap

    fu_password.PasswordHelper.__init__ = _init
    try:
        yield
    finally:
        fu_password.PasswordHelper.__init__ = original_init


# ── Integration test fixtures ────────────────────────────────────────────────


@pytest.fixture()
async def async_db():
    """In-memory async SQLite session. Fresh schema per test, torn down after.

    The schema is replayed from `helpers.schema_ddl()` rather than built with
    `Base.metadata.create_all`. Measured: **3.3 ms against 44.2 ms**, over ~1,049 tests
    that ask for this fixture, and the resulting schema is byte-identical (136
    `sqlite_master` rows, compared directly). `create_all` pays DDL compilation plus a
    reflection round-trip per table on every single call; none of that changes between
    tests.

    There is deliberately no `drop_all`. The database is in-memory and the engine is about
    to be disposed, so dropping 33 tables first was 10.6 ms of pure ceremony per test.
    """
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from tests.helpers import create_schema, make_async_engine

    engine = make_async_engine()
    await create_schema(engine)

    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # `app.activity.record()` deliberately opens its OWN session rather than the request's
    # — see that module's docstring. It reaches it through `app.database`, so without this
    # rebind an audit write from a route under test would land in the developer's real
    # database instead of this in-memory one, and every assertion about it would fail
    # silently (record() swallows everything by design).
    import app.database as _database

    _saved_maker = _database.async_session_maker
    _database.async_session_maker = session_maker
    try:
        async with session_maker() as session:
            yield session
    finally:
        _database.async_session_maker = _saved_maker
        await engine.dispose()


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Patch app.redis_client to use fakeredis. Returns the FakeRedis instance.

    Autouse deliberately. `get_redis()` builds a real client lazily and caches it in the
    module global, so any test that reached it without this fixture would talk to whatever
    Redis happens to be running on the developer's machine — reading and writing real
    keys, and behaving differently in CI than locally. Depend on it by name when you need
    the instance to assert against.
    """
    import fakeredis

    fake = fakeredis.FakeRedis(decode_responses=True)
    import app.redis_client as rc

    monkeypatch.setattr(rc, "_client", fake)
    return fake


@pytest.fixture()
def sync_db():
    """In-memory **synchronous** session — the shape Huey tasks and other worker code use.

    Nine modules had written this out identically (`test_comment_prune`,
    `test_events_timeline_index`, `test_failed_job_finalization`, `test_integration_worker`,
    `test_intel_attr_filter`, `test_intel_job_filter`, `test_intel_relationships_persist`,
    `test_tag_multi_write`, `test_watch_rules`). One of them even carried an unused
    `tmp_path` parameter, which is the sort of thing nine copies get you.

    Same engine settings as those copies — no foreign-key pragma, default pool — so this is
    a de-duplication and not a behaviour change riding along with one. `async_db` is where
    FK enforcement is asserted.
    """
    from sqlalchemy.orm import sessionmaker

    from tests.helpers import make_sync_engine

    engine = make_sync_engine()
    session = sessionmaker(engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def huey_memory_storage():
    """Point Huey's queue at memory, so nothing in the suite needs a live Redis.

    `fake_redis` covers `app.redis_client`, but Huey holds its **own** connection
    (`app/workers/huey_app.py` builds a `RedisHuey`). Most enqueue sites are stubbed by
    the test that reaches them, but not all: the `POST /jobs/resubmit` tests
    (`app/routers/jobs.py` imports `run_analysis` lazily, so `test_client`'s patch of
    `app.routers.upload.run_analysis` never covers it) and the rule `test` delivery, which
    reaches `deliver_webhook`, would fail whenever Redis is stopped.

    Swapping `huey.storage` rather than the task objects is what keeps
    `tasks_mod.run_analysis.call_local(...)` working — the worker integration tests call
    exactly that, and replacing the module attribute with a stub would take `call_local`
    with it. Enqueueing still does everything it did, into a dict.

    Function-scoped so each test starts with an empty queue. That also keeps the "polling
    stops when the queue is idle" assertions from reading whatever a previous run left in a
    developer's Redis.
    """
    from huey.storage import MemoryStorage

    from app.workers.huey_app import huey

    saved = huey.storage
    huey.storage = MemoryStorage(name=huey.name)
    try:
        yield huey.storage
    finally:
        huey.storage = saved


@pytest.fixture(autouse=True)
def fresh_storage_singleton(monkeypatch):
    """Every test starts with no storage backend built, and none survives it.

    `app.storage.get_storage()` is a lazy singleton, and `LocalStorage` captures
    `settings.upload_dir` when it is built. A test that patched `upload_dir` but not the
    singleton read whatever an earlier test had left: under `pytest -n auto --dist loadfile`
    the files sharing a worker change from run to run, and when one of them had built the
    backend and left a `job_1/` (job ids restart at 1 in every test database) holding no tool
    output, `job_outputs_dir` resolved to that stale folder and
    `test_backfill_analytics_fills_the_index` saw "no raw output" — once, in the 0.17.1
    release gate, after passing in every run before it. `test_client` already reset it; this
    makes it true for every test.
    """
    monkeypatch.setattr("app.storage._storage", None)


@pytest.fixture()
async def test_client(async_db, fake_redis, monkeypatch, tmp_path):
    """httpx.AsyncClient wired to the FastAPI app with test DB and fake Redis.

    - Overrides get_async_session to use the test DB
    - Patches run_analysis to a no-op (no Huey needed)
    - Patches storage to use tmp_path
    """
    from httpx import ASGITransport, AsyncClient

    from app.database import get_async_session
    from app.main import app

    async def _override_session():
        yield async_db

    app.dependency_overrides[get_async_session] = _override_session

    # Patch Huey task to no-op
    monkeypatch.setattr("app.routers.upload.run_analysis", lambda job_id: None)

    # Patch storage to use local tmp dir
    from app import storage as storage_mod

    monkeypatch.setattr(storage_mod, "_storage", None)  # reset singleton
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path / "uploads")

    # CsrfMiddleware requires a same-origin Origin/Referer on authenticated
    # state-changing requests. httpx doesn't set Origin by default, so pin it
    # to the test base URL for all requests.
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Origin": "http://test"},
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture()
async def admin_user(async_db):
    """Create an admin (superuser) in the test DB and return (User, auth_cookie_value)."""
    from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

    from app.auth.schemas import UserCreate
    from app.auth.users import UserManager
    from app.models import User

    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    user = await manager.create(UserCreate(email="admin@test.example.com", password="testpass123", is_superuser=True, is_active=True, role="admin"))
    return user


@pytest.fixture()
async def admin_client(test_client, admin_user):
    """test_client that is authenticated as admin via cookie login."""
    resp = await test_client.post(
        "/auth/cookie/login",
        data={"username": "admin@test.example.com", "password": "testpass123"},
    )
    assert resp.status_code in (200, 204, 303), f"Admin login failed: {resp.status_code}"
    return test_client


@pytest.fixture()
async def member_user(async_db):
    """Create a member-role user in the test DB."""
    from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

    from app.auth.schemas import UserCreate
    from app.auth.users import UserManager
    from app.models import User

    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    user = await manager.create(UserCreate(email="member@test.example.com", password="testpass123", is_superuser=False, is_active=True, role="member"))
    return user


@pytest.fixture()
async def member_client(test_client, member_user):
    """test_client authenticated as a member via cookie login."""
    resp = await test_client.post(
        "/auth/cookie/login",
        data={"username": "member@test.example.com", "password": "testpass123"},
    )
    assert resp.status_code in (200, 204, 303), f"Member login failed: {resp.status_code}"
    return test_client


@pytest.fixture()
async def regular_user(async_db):
    """Create a basic user (role='user') in the test DB."""
    from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

    from app.auth.schemas import UserCreate
    from app.auth.users import UserManager
    from app.models import User

    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    user = await manager.create(UserCreate(email="user@test.example.com", password="testpass123", is_superuser=False, is_active=True, role="user"))
    return user


@pytest.fixture()
async def user_client(test_client, regular_user):
    """test_client authenticated as a basic user (no member/admin) via cookie login."""
    resp = await test_client.post(
        "/auth/cookie/login",
        data={"username": "user@test.example.com", "password": "testpass123"},
    )
    assert resp.status_code in (200, 204, 303), f"User login failed: {resp.status_code}"
    return test_client


def path_without(*tools: str) -> str:
    """`os.environ["PATH"]` with every directory that holds one of `tools` removed.

    A test that asserts what a script does when a tool is ABSENT cannot express that by
    omitting a shim: PATH ordering can shadow a binary but never unpublish one, so the real
    /usr/sbin/ufw, ~/.local/bin/wireconf or /opt/homebrew/bin/7z answers instead and the
    assertion silently becomes a test of the other branch. That turns a Linux CI runner red
    while macOS stays green, and it points both ways: a developer who has once run
    `task deploy:vpn` has wireconf in a directory on their own PATH.

    Dropping whole directories rather than the single binary is deliberate — there is no
    way to hide one name from `command -v` — and it is safe in practice because these tools
    live in /usr/sbin, /opt/... or a user-local bin, never beside `sh`. If one ever did, the
    script under test would fail loudly for want of a shell rather than quietly take the
    wrong branch, which is the right direction to fail in.
    """
    keep = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d and not any(os.access(os.path.join(d, t), os.X_OK) for t in tools)]
    return os.pathsep.join(keep)


def decode_graph(payload: dict) -> dict:
    """Expand a columnar graph payload back into `{"nodes": [...], "edges": [...]}` dicts.

    The wire format is parallel arrays of indices into `graph_payload.client_schema()`
    (see that module for why). Assertions read far better against dicts, and roughly twenty
    Tier-2 assertions — including the private-job isolation suite — are written against
    them. This is the one shim; the format itself is pinned by `test_intel_graph_payload.py`.

    Nodes come back as `{"data": {...}}` with the flags decoded to booleans; edges as
    `{"data": {"source": "e1", "target": "e2", "kind": ..., "weight": ..., "rel_type": ...}}`
    where `kind` is `"job"`, `"finding"` or `"typed"`.
    """
    from app.intel.graph_payload import EDGE_CODE_FINDING, EDGE_KIND_TYPED_BASE, NODE_FLAGS, SUBTYPES, client_schema

    schema = client_schema()
    n = payload.get("n") or {}
    e = payload.get("e") or {}
    ids = n.get("id") or []
    words = (payload.get("dict") or {}).get("tags") or []
    tags_by_index = {row[0]: [words[i] for i in row[1:]] for row in (n.get("tg") or [])}
    cases_by_index = {row[0]: list(row[1:]) for row in (n.get("ca") or [])}
    matched = set(n.get("mt") or [])

    nodes = []
    for i, eid in enumerate(ids):
        flags = (n.get("fl") or [0])[i]
        data = {
            "id": f"e{eid}",
            "entity_id": eid,
            "label": (n.get("lb") or [""])[i],
            "entity_type": schema["types"][(n.get("ty") or [0])[i]],
            "subtype": SUBTYPES[n["sub"][i] - 1] if n.get("sub") and n["sub"][i] else None,
            "job_count": (n.get("jc") or [0])[i],
            "tags": tags_by_index.get(i, []),
            "cases": cases_by_index.get(i, []),
            "matched": i in matched,
        }
        for name, bit in NODE_FLAGS.items():
            data[name] = bool(flags & bit)
        if "sv" in n:
            data["severity"] = schema["severities"][n["sv"][i] - 1] if n["sv"][i] else None
        if "tc" in n:
            data["tactic"] = schema["tactics"][n["tc"][i] - 1] if n["tc"][i] else None
        if "en" in n:
            data["verdict"] = schema["verdicts"][n["en"][i]]
        nodes.append({"data": data})

    edges = []
    for i, s in enumerate(e.get("s") or []):
        code = e["k"][i]
        rel = schema["rels"][code - EDGE_KIND_TYPED_BASE] if code >= EDGE_KIND_TYPED_BASE else None
        edges.append(
            {
                "data": {
                    "source": f"e{ids[s]}",
                    "target": f"e{ids[e['t'][i]]}",
                    "source_id": ids[s],
                    "target_id": ids[e["t"][i]],
                    "kind": "typed" if rel else ("finding" if code == EDGE_CODE_FINDING else "job"),
                    "rel_type": rel,
                    "weight": e["w"][i],
                }
            }
        )
    return {"nodes": nodes, "edges": edges, "stats": payload.get("stats") or {}, "mt_partial": bool(n.get("mt_partial"))}
