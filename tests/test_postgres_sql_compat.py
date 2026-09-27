"""SQL this app emits, executed against a real PostgreSQL through the real driver.

Every other test in this suite runs on SQLite, which is the right default — it is the
default backend and needs no service. But PostgreSQL is a first-class backend here and
SQLite is permissive in exactly the places PostgreSQL is strict, so a whole class of bug is
structurally invisible to the rest of the suite.

For example, ``CASE finding.severity WHEN 'CRITICAL' THEN 0 …`` built from plain Python
strings: on PostgreSQL that column is a real enum *type* and the WHEN values carry no type
information, so the driver binds them as ``$1::VARCHAR`` and the server answers
``operator does not exist: severity = character varying`` — a 500 on the entity Findings
tab, the entity graph and the case roll-up. On SQLite the column is a VARCHAR and it simply
works.

**Two things have to be right for a test here to catch anything.**

*It must execute.* Both dialects render the offending statement to byte-identical SQL
*text* — the difference is the bind parameter's type, which `literal_binds` erases. A
compile-only assertion passes with the bug present.

*It must use asyncpg.* Through psycopg2 the test passes with the bug in place: psycopg2
interpolates an untyped literal, which PostgreSQL happily coerces to the enum by context;
asyncpg sends a genuine parameter and SQLAlchemy stamps it ``::VARCHAR``, which is the thing
with no operator. The web tier — where these 500s happen — is asyncpg. So the async engine is not
an incidental choice here, it is the whole point, and a "simplification" to the sync engine
would silently disarm this file.

Skipped unless a server is reachable::

    task test:pg                                        # throwaway container, torn down after
    POSTGRES_TEST_URL=postgresql://u:pw@host/db pytest tests/test_postgres_sql_compat.py

Add a case whenever you write SQL that leans on a column's *type* rather than its text:
enum comparisons, JSON operators, casts, a CASE over a non-text column.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import create_async_engine

#: Driver-less, e.g. ``postgresql://user:pw@host:5432/db`` — both URLs are derived from it.
POSTGRES_TEST_URL = os.environ.get("POSTGRES_TEST_URL", "")

#: CI must never *silently* skip these, and a skip inside a large run is invisible. So under
#: CI a missing or unreachable server is a failure, and everywhere else it stays the
#: ordinary skip that lets a laptop with no PostgreSQL run the suite.
IN_CI = bool(os.environ.get("CI"))


def _unavailable(reason: str):
    """Skip locally, fail in CI. The blind spot these tests exist to remove is this one."""
    if IN_CI:
        pytest.fail(f"{reason} — CI must run the PostgreSQL checks, not skip them")
    pytest.skip(reason)


pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        not POSTGRES_TEST_URL and not IN_CI,
        reason="set POSTGRES_TEST_URL (or run `task test:pg`) to exercise the PostgreSQL-only SQL paths",
    ),
]


def _url(driver: str) -> str:
    """`postgresql://…` → `postgresql+<driver>://…`, accepting a URL that already names one."""
    head, _, tail = POSTGRES_TEST_URL.partition("://")
    return f"{head.split('+')[0]}+{driver}://{tail}"


@pytest.fixture(scope="module")
def pg_schema():
    """This app's schema on the server, created once for the module — **synchronously**.

    Through psycopg2 rather than asyncpg deliberately: schema setup is not what is under
    test, and an async engine held at module scope is bound to the loop that made it, while
    the tests each get their own. That mismatch surfaces as asyncpg's
    ``got Future attached to a different loop``, which looks like a driver fault and is
    really a fixture-scope one. Keeping the setup off the event loop removes the question.

    `create_all` rather than Alembic: what matters here is the shape the ORM declares — the
    enum types above all. `test_migrations_auto.py` owns the migration path.
    """
    from sqlalchemy import create_engine

    if not POSTGRES_TEST_URL:  # only reachable under CI — the skipif covers every other case
        _unavailable("POSTGRES_TEST_URL is not set")

    engine = create_engine(_url("psycopg2"), future=True)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - a bad URL should say so plainly
        engine.dispose()
        _unavailable(f"POSTGRES_TEST_URL is not reachable: {exc}")

    from app import models  # noqa: F401 — importing is what registers every table
    from app.database import Base

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    try:
        yield
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
async def pg_engine(pg_schema):
    """An **asyncpg** engine, per test — see the module docstring for why the driver matters."""
    engine = create_async_engine(_url("asyncpg"), future=True)
    try:
        yield engine
    finally:
        await engine.dispose()


async def test_severity_is_a_real_enum_type_here(pg_engine):
    """The precondition for everything below. If this column stops being an enum, the rest
    of this module tests nothing and would pass while the bug it guards came back."""
    async with pg_engine.connect() as conn:
        rows = await conn.execute(text("SELECT e.enumlabel FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid WHERE t.typname = 'severity' ORDER BY e.enumsortorder"))
    assert list(rows.scalars()) == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


async def test_severity_rank_executes(pg_engine):
    """`operator does not exist: severity = character varying` — the shipped 500."""
    from app.models import Finding, severity_rank_sql

    async with pg_engine.connect() as conn:
        await conn.execute(select(func.min(severity_rank_sql())).select_from(Finding))


async def test_severity_rank_in_the_shape_the_entity_page_uses(pg_engine):
    """The statement behind the entity Findings tab and the graph's threat columns: ranked,
    grouped and ordered — three places the expression is re-evaluated."""
    from app.models import Finding, FindingEntityLink, severity_rank_sql

    rank = severity_rank_sql()
    stmt = (
        select(FindingEntityLink.entity_id, func.min(rank).label("rank"), func.count().label("n"))
        .join(Finding, FindingEntityLink.finding_id == Finding.id)
        .where(FindingEntityLink.entity_id.in_([1, 2, 3]))
        .group_by(FindingEntityLink.entity_id)
        .order_by(func.min(rank))
        .limit(10)
    )
    async with pg_engine.connect() as conn:
        await conn.execute(stmt)


async def test_severity_rank_orders_correctly_on_real_rows(pg_engine):
    """Executing is not enough — the cast must still rank most-severe first.

    A cast that compared against the wrong strings would run cleanly and sort
    alphabetically, which is the bug `severity_rank_sql` exists to prevent in the first
    place. Rows are inserted worst-last so insertion order cannot make this pass by luck.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models import AnalysisJob, Finding, LogFile, TaskResult, WorkflowDef, severity_rank_sql

    async with async_sessionmaker(pg_engine, expire_on_commit=False)() as s:
        wf = WorkflowDef(name="wf-sev", log_types="[]", tasks_yaml="tasks: []")
        lf = LogFile(original_filename="f.evtx", stored_filename="s.evtx", sha256="a" * 64, size_bytes=1)
        s.add_all([wf, lf])
        await s.flush()
        job = AnalysisJob(file_id=lf.id, workflow_id=wf.id)
        s.add(job)
        await s.flush()
        tr = TaskResult(job_id=job.id, tool_name="t")
        s.add(tr)
        await s.flush()
        for sev in ("informational", "low", "medium", "high", "critical"):
            s.add(Finding(task_result_id=tr.id, rule_id=sev, rule_name=sev, severity=sev, count=1))
        await s.commit()

        rows = await s.execute(select(Finding.rule_name).order_by(severity_rank_sql(), Finding.id))
        ordered = list(rows.scalars())

    assert ordered == ["critical", "high", "medium", "low", "informational"]


async def test_the_jobs_query_status_filter_executes(pg_engine):
    """`AnalysisJob.status.in_(["pending", "running"])` in `jobs_query.py` hands raw
    lowercase strings to an enum column whose labels are uppercase.

    That one is *correct* — SQLAlchemy's `Enum` maps value to label and binds with the enum
    type — and it is asserted here precisely because at the call site it looks identical to
    the bug above. Without a test saying so, the obvious "fix" is to change it and break it.
    """
    from app.jobs_query import apply_jobs_query, parse_jobs_query
    from app.models import AnalysisJob

    stmt = apply_jobs_query(select(AnalysisJob.id), parse_jobs_query("is:running"))
    async with pg_engine.connect() as conn:
        await conn.execute(stmt)


# ── Routes whose SQL changed in the v1.0 review, run through asyncpg ─────────────────────────


@pytest.fixture
async def pg_app(pg_engine, monkeypatch, fake_redis):
    """A bare app on the PostgreSQL engine, `activity.record`'s own session included — or an
    audit write from a route under test would land in the developer's real database."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    import app.database as database
    from app.database import get_async_session

    maker = async_sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(database, "async_session_maker", maker)
    app = FastAPI()

    async def _session():
        async with maker() as s:
            yield s

    app.dependency_overrides[get_async_session] = _session

    def client(**headers):
        return AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test", headers=headers)

    return app, maker, client


async def _token(maker, scope: str, suffix: str) -> str:
    from app.auth.api_tokens import generate_token
    from app.json_utils import dumps as json_dumps
    from app.models import ApiToken, User

    plaintext, digest, prefix = generate_token()
    async with maker() as s:
        creator = User(email=f"pg-{suffix}@example.com", hashed_password="x", is_active=True, is_superuser=True, role="admin")
        s.add(creator)
        await s.flush()
        s.add(ApiToken(name=suffix, token_hash=digest, prefix=prefix, scopes_json=json_dumps([scope]), created_by_user_id=creator.id))
        await s.commit()
    return plaintext


async def test_taxii_paging_executes_and_refuses_a_crafted_cursor(pg_app):
    """The keyset cursor compares `coalesce(last_seen_at, epoch)` with a bound datetime.
    asyncpg refuses a timezone-aware bind for a `timestamp without time zone` column, and
    an out-of-range id bind, so a crafted `next` must be a 400 rather than a 500."""
    import base64
    from datetime import datetime

    from app.intel.taxii import COLLECTIONS
    from app.models import Entity
    from app.routers import taxii as taxii_router

    app, maker, client = pg_app
    app.include_router(taxii_router.router)
    token = await _token(maker, "taxii:read", "taxii")
    async with maker() as s:
        for i in range(5):
            seen = datetime(2026, 2, 1 + min(i, 3), 12, 0)
            s.add(Entity(value=f"10.9.0.{i}", entity_type="ip_address", job_count=1, last_seen_at=seen, first_seen_at=seen))
        await s.commit()
    url = f"/taxii2/logstotal/collections/{COLLECTIONS[0]['id']}/objects/"

    async with client(Authorization=f"Bearer {token}") as c:
        names: list[str] = []
        params = {"limit": 2, "added_after": "2026-01-31T00:00:00Z"}
        for _ in range(5):
            resp = await c.get(url, params=params)
            assert resp.status_code == 200, resp.text
            env = resp.json()
            names += [o["name"] for o in env["objects"] if o["type"] == "indicator"]
            if not env.get("more"):
                break
            params = {"limit": 2, "added_after": "2026-01-31T00:00:00Z", "next": env["next"]}
        assert sorted(n for n in names if "10.9.0." in n) == sorted(f"10.9.0.{i}" for i in range(5))

        def crafted(raw: str) -> str:
            return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

        for raw in ("2026-02-02T12:00:00+02:00|3", "2026-02-02T12:00:00|99999999999"):
            assert (await c.get(url, params={"next": crafted(raw)})).status_code in (200, 400), raw


async def test_the_ioc_feed_since_filter_executes(pg_app):
    """`since` with a UTC offset was bound as an aware datetime: a 500 on PostgreSQL."""
    from app.routers import intel as intel_router

    app, maker, client = pg_app
    app.include_router(intel_router.router)
    token = await _token(maker, "ioc_feed:read", "feed")
    async with client(Authorization=f"Bearer {token}") as c:
        for since in ("2026-01-01T02:00:00+02:00", "2026-01-01T01:30:00Z", "2026-01-01"):
            resp = await c.get("/intel/ioc-feed", params={"format": "json", "since": since})
            assert resp.status_code == 200, (since, resp.text[:300])


async def test_the_cases_list_counts_execute(pg_app):
    """The list's job count became a visibility-filtered subquery; run it for a member,
    whose filter is not the admin shortcut."""
    from app.auth.users import current_member_or_above
    from app.models import AnalysisJob, CaseJobLink, InvestigationCase, LogFile, User, WorkflowDef
    from app.routers import cases as cases_router

    app, maker, client = pg_app
    app.include_router(cases_router.router)
    async with maker() as s:
        member = User(email="pg-member@example.com", hashed_password="x", is_active=True, is_superuser=False, role="member")
        wf = WorkflowDef(name="wf-cases-pg", log_types="[]", tasks_yaml="tasks: []")
        lf = LogFile(original_filename="c.evtx", stored_filename="c.evtx", sha256="c" * 64, size_bytes=1)
        s.add_all([member, wf, lf])
        await s.flush()
        case = InvestigationCase(name="pg case", created_by_user_id=member.id, is_shared=True)
        job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, is_private=True)
        s.add_all([case, job])
        await s.flush()
        s.add(CaseJobLink(case_id=case.id, job_id=job.id))
        await s.commit()
    app.dependency_overrides[current_member_or_above] = lambda: member
    async with client() as c:
        resp = await c.get("/intel/cases")
    assert resp.status_code == 200, resp.text[:500]


async def test_submission_filename_and_type_filters_are_isolated(pg_engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.jobs_query import apply_jobs_query, parse_jobs_query
    from app.models import AnalysisJob, LogFile, LogType, WorkflowDef

    async with async_sessionmaker(pg_engine, expire_on_commit=False)() as session:
        file = LogFile(original_filename="secret-first.evtx", stored_filename="submission-test", sha256="d" * 64, size_bytes=1, log_type=LogType.EVTX)
        workflow = WorkflowDef(name="submission metadata")
        session.add_all([file, workflow])
        await session.flush()
        submitted = AnalysisJob(file_id=file.id, workflow_id=workflow.id, submitted_filename="own.evtx", effective_log_type=LogType.SYSLOG)
        legacy = AnalysisJob(file_id=file.id, workflow_id=workflow.id, effective_log_type=LogType.EVTX)
        session.add_all([submitted, legacy])
        await session.flush()
        await session.refresh(legacy)
        assert legacy.filename == "upload-" + "d" * 12
        stmt = apply_jobs_query(select(AnalysisJob.id), parse_jobs_query("own.evtx type:syslog"))
        assert list((await session.scalars(stmt)).all()) == [submitted.id]
        stmt = apply_jobs_query(select(AnalysisJob.id), parse_jobs_query("secret-first"))
        assert list((await session.scalars(stmt)).all()) == []


async def test_case_ai_evidence_queries_execute_through_asyncpg(pg_engine):
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.ai.case_evidence import evidence_exists, invalidate_case_sources, prepare_case_evidence, readable_runs
    from app.json_utils import loads
    from tests.test_case_ai import saved_run, seed_case

    async with pg_engine.connect() as conn:
        transaction = await conn.begin()
        async with AsyncSession(conn, expire_on_commit=False, join_transaction_mode="create_savepoint") as db:
            data = await db.run_sync(seed_case)
            assert await db.scalar(evidence_exists(data.case.id, data.owner))
            prompt, meta, sources = await db.run_sync(lambda sync: prepare_case_evidence(sync, data.case, data.owner))
            assert "secret-2" not in prompt
            assert meta["findings_rendered"] == 40
            run = saved_run(data, source_jobs_json=sources)
            db.add(run)
            await db.commit()
            assert len(loads(sources)) == 2
            assert await readable_runs(db, [run], data.owner) == [run]
            await db.execute(invalidate_case_sources(data.jobs[0].id))
            await db.commit()
            await db.refresh(run)
            assert await readable_runs(db, [run], data.owner) == []
        await transaction.rollback()


async def test_case_ai_migration_reuses_existing_postgres_enum(pg_engine):
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import inspect

    path = Path(__file__).resolve().parents[1] / "alembic/versions/b92a7e13c640_case_ai_analysis.py"
    spec = importlib.util.spec_from_file_location("case_ai_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    def round_trip(conn):
        with Operations.context(MigrationContext.configure(conn)):
            migration.downgrade()
            assert conn.scalar(text("SELECT COUNT(*) FROM pg_type WHERE typname = 'aianalysisstatus'")) == 1
            migration.upgrade()
            assert "case_ai_analysis" in inspect(conn).get_table_names()
            assert "case_system_prompt" in {c["name"] for c in inspect(conn).get_columns("ai_provider")}
            conn.execute(text("SELECT id FROM case_ai_analysis WHERE status = 'CANCELLED'"))

    async with pg_engine.connect() as conn:
        transaction = await conn.begin()
        await conn.run_sync(round_trip)
        await transaction.rollback()


@pytest.mark.parametrize("missing_column", [False, True])
async def test_case_ai_followup_repairs_early_postgres_schema(pg_engine, missing_column):
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    from app.models import CaseAiAnalysis

    path = Path(__file__).resolve().parents[1] / "alembic/versions/c63d1e4a902b_repair_early_case_ai_schema.py"
    spec = importlib.util.spec_from_file_location("case_ai_followup", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    def repair(conn):
        case_id = conn.scalar(text("INSERT INTO investigation_case (name) VALUES ('Repair regression') RETURNING id"))
        run_id = conn.scalar(
            text(
                "INSERT INTO case_ai_analysis (case_id, provider_name, model, status, content, source_deleted_at) "
                "VALUES (:case_id, 'Saved provider', 'saved-model', 'COMPLETED', 'Saved report', '2026-09-20 11:00:00') RETURNING id"
            ),
            {"case_id": case_id},
        )
        with Operations.context(MigrationContext.configure(conn)):
            if missing_column:
                conn.execute(text("ALTER TABLE case_ai_analysis DROP COLUMN source_deleted_at"))
            migration.upgrade()
            migration.upgrade()  # Already-finalized schemas must also work.
        run = conn.execute(select(CaseAiAnalysis).where(CaseAiAnalysis.id == run_id)).mappings().one()
        assert run["content"] == "Saved report"
        assert (run["source_deleted_at"] is None) == missing_column

    async with pg_engine.connect() as conn:
        transaction = await conn.begin()
        await conn.run_sync(repair)
        await transaction.rollback()
