"""A case's Entities and Jobs tabs are paged, and every link is reachable.

Both lists are server-paged, so row 201 is as reachable as row 1.

The two tests worth reading are the pagination invariants, because both failure modes look
completely healthy in a browser:

* `test_walking_every_page_yields_each_link_exactly_once` — the visibility rule and the
  dead-entity filter run in SQL. **In Python after the LIMIT**, a page of 50 could render
  47 rows and the three it dropped would appear on no page at all.
* `test_links_sharing_a_timestamp_appear_on_exactly_one_page` — `added_at` is not unique.
  `POST /{case_id}/jobs/{id}/add-entities` links hundreds of entities with one timestamp,
  and SQL may order tied rows differently per query, so without the `id` tiebreaker paging
  shows one row twice and skips another. This has to be constructed deliberately; it will
  never happen by accident in a fixture.

`_CASE_LINK_CAP` is the API/export bound, and `detail.json` is capped, because it is
Bearer-token reachable.
"""

from __future__ import annotations

import re

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import text

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
    CaseEntityLink,
    CaseJobLink,
    Entity,
    InvestigationCase,
    JobStatus,
    LogFile,
    LogType,
    User,
    WorkflowDef,
)
from app.routers.cases import _CASE_LINK_CAP, _CASE_PAGE_SIZE

OVER_CAP = _CASE_LINK_CAP + 5


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    manager = UserManager(SQLAlchemyUserDatabase(async_db, User))
    return await manager.create(UserCreate(email=email, password="pass123456", is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


def _entity_row_ids(html: str, _case_id: int | None = None) -> list[str]:
    """The **link** ids of the rendered rows.

    Read off `id="case-entity-row-N"`, which every row carries, rather than the `/remove`
    form — that one is owner-gated, so counting it would report zero rows for a member
    viewing someone else's shared case.
    """
    return re.findall(r'id="case-entity-row-(\d+)"', html)


def _job_row_ids(html: str, _case_id: int | None = None) -> list[str]:
    return re.findall(r'id="case-job-row-(\d+)"', html)


@pytest.fixture()
async def big_case(async_db):
    """A case holding more entity and job links than one page."""
    owner = await _create_user(async_db, email="owner@caps.example.com")
    wf = WorkflowDef(name="Caps WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()

    case = InvestigationCase(name="Big case", status="open", created_by_user_id=owner.id, is_shared=True)
    async_db.add(case)
    await async_db.flush()

    for i in range(OVER_CAP):
        entity = Entity(value=f"10.0.{i // 256}.{i % 256}", entity_type="ip_address", job_count=1)
        async_db.add(entity)
        await async_db.flush()
        async_db.add(CaseEntityLink(case_id=case.id, entity_id=entity.id, added_by_user_id=owner.id))

        lf = LogFile(
            original_filename=f"caps-{i}.evtx",
            stored_filename=f"caps_{i}.evtx",
            sha256=f"{i:064d}",
            size_bytes=1024,
            log_type=LogType.EVTX,
            detected_type=LogType.EVTX,
        )
        async_db.add(lf)
        await async_db.flush()
        job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=owner.id, is_private=False)
        async_db.add(job)
        await async_db.flush()
        async_db.add(CaseJobLink(case_id=case.id, job_id=job.id, added_by_user_id=owner.id))

    await async_db.commit()
    return {"case_id": case.id, "owner": owner}


# ─── The page itself stays cheap ─────────────────────────────────────────────────


async def test_the_detail_page_renders_no_rows_at_all(test_client, big_case):
    """Both tabs are lazy: `case_detail` issues two COUNTs and nothing else."""
    await _login(test_client, "owner@caps.example.com")
    case_id = big_case["case_id"]
    resp = await test_client.get(f"/intel/cases/{case_id}")
    assert resp.status_code == 200
    assert _entity_row_ids(resp.text, case_id) == []
    assert _job_row_ids(resp.text, case_id) == []
    # …but the regions that will fetch them are wired up.
    assert f'hx-get="/intel/cases/{case_id}/entities-partial"' in resp.text
    assert f'hx-get="/intel/cases/{case_id}/jobs-partial"' in resp.text


async def test_the_badges_still_show_the_true_totals(test_client, big_case):
    """The counts come from two cheap COUNTs, so they are unaffected by paging."""
    await _login(test_client, "owner@caps.example.com")
    resp = await test_client.get(f"/intel/cases/{big_case['case_id']}")
    assert f"({OVER_CAP})" in resp.text
    # No truncation banner — there is nothing to truncate.
    assert "most recently added of" not in resp.text


# ─── Pagination invariants ───────────────────────────────────────────────────────


async def test_a_page_holds_exactly_the_page_size(test_client, big_case):
    await _login(test_client, "owner@caps.example.com")
    case_id = big_case["case_id"]
    for kind, extract in (("entities", _entity_row_ids), ("jobs", _job_row_ids)):
        resp = await test_client.get(f"/intel/cases/{case_id}/{kind}-partial")
        assert resp.status_code == 200
        assert len(extract(resp.text, case_id)) == _CASE_PAGE_SIZE, f"{kind} page 1"


@pytest.mark.parametrize(("kind", "extract"), [("entities", _entity_row_ids), ("jobs", _job_row_ids)])
async def test_walking_every_page_yields_each_link_exactly_once(test_client, big_case, kind, extract):
    """No row appears twice, and no row is skipped — no ragged pages."""
    await _login(test_client, "owner@caps.example.com")
    case_id = big_case["case_id"]

    seen: list[str] = []
    pages = -(-OVER_CAP // _CASE_PAGE_SIZE)
    for page in range(1, pages + 1):
        resp = await test_client.get(f"/intel/cases/{case_id}/{kind}-partial?page={page}")
        assert resp.status_code == 200
        seen.extend(extract(resp.text, case_id))

    assert len(seen) == OVER_CAP, f"walked {len(seen)} {kind}, expected {OVER_CAP}"
    assert len(set(seen)) == OVER_CAP, f"{kind} pages repeat a row"


async def test_links_sharing_a_timestamp_appear_on_exactly_one_page(test_client, async_db):
    """`added_at` is not unique, so `id` has to be the tiebreaker.

    Bulk-linking stamps one timestamp across hundreds of rows. Without a deterministic
    second sort key SQL may order tied rows differently per query, and paging then shows
    one row twice while skipping another — silently, and only on a case big enough to page.
    """
    from datetime import datetime

    owner = await _create_user(async_db, email="tie@caps.example.com")
    case = InvestigationCase(name="Tied", status="open", created_by_user_id=owner.id, is_shared=True)
    async_db.add(case)
    await async_db.flush()

    stamp = datetime(2026, 1, 1, 12, 0, 0)  # naive, matching the column
    n = _CASE_PAGE_SIZE * 2 + 3
    for i in range(n):
        entity = Entity(value=f"192.168.{i // 256}.{i % 256}", entity_type="ip_address", job_count=1)
        async_db.add(entity)
        await async_db.flush()
        # Every link shares one `added_at`, exactly as a bulk link would.
        async_db.add(CaseEntityLink(case_id=case.id, entity_id=entity.id, added_by_user_id=owner.id, added_at=stamp))
    await async_db.commit()

    await _login(test_client, "tie@caps.example.com")
    seen: list[str] = []
    for page in (1, 2, 3):
        resp = await test_client.get(f"/intel/cases/{case.id}/entities-partial?page={page}")
        seen.extend(_entity_row_ids(resp.text, case.id))

    assert len(seen) == n
    assert len(set(seen)) == n, "a tied `added_at` made a row appear on two pages"


async def test_an_out_of_range_page_is_clamped(test_client, big_case):
    await _login(test_client, "owner@caps.example.com")
    case_id = big_case["case_id"]
    resp = await test_client.get(f"/intel/cases/{case_id}/entities-partial?page=9999")
    assert resp.status_code == 200
    assert _entity_row_ids(resp.text, case_id), "clamping to the last page must still render rows"


# ─── Filters that must run before the LIMIT ──────────────────────────────────────


async def test_a_link_whose_entity_is_gone_never_renders_and_is_not_counted(test_client, async_db):
    """A legacy DB can hold `CaseEntityLink` rows whose `Entity` was deleted.

    Dropping them in Python after the LIMIT makes pages ragged; an INNER JOIN removes them
    before the window instead.

    The suite runs with `PRAGMA foreign_keys=ON`, so this state cannot be created the
    ordinary way — which is the point of enforcing it. It remains reachable in
    a database that predates enforcement, so the pragma is dropped for this insert only:
    the resilience being tested is about *legacy data*, not about a state the current code
    can still produce.
    """
    owner = await _create_user(async_db, email="orphan@caps.example.com")
    case = InvestigationCase(name="Orphans", status="open", created_by_user_id=owner.id, is_shared=True)
    async_db.add(case)
    await async_db.flush()

    keeper = Entity(value="10.9.9.9", entity_type="ip_address", job_count=1)
    async_db.add(keeper)
    await async_db.flush()
    async_db.add(CaseEntityLink(case_id=case.id, entity_id=keeper.id, added_by_user_id=owner.id))
    await async_db.commit()

    # A link pointing at an entity id that does not exist — see the docstring.
    await async_db.execute(text("PRAGMA foreign_keys=OFF"))
    await async_db.execute(text("INSERT INTO case_entity_link (case_id, entity_id, added_by_user_id) VALUES (:c, 999999, :u)"), {"c": case.id, "u": str(owner.id)})
    await async_db.commit()
    await async_db.execute(text("PRAGMA foreign_keys=ON"))

    await _login(test_client, "orphan@caps.example.com")
    page = await test_client.get(f"/intel/cases/{case.id}")
    assert "(1)" in page.text, "the badge must count only rows that can render"

    rows = await test_client.get(f"/intel/cases/{case.id}/entities-partial")
    assert len(_entity_row_ids(rows.text, case.id)) == 1


async def test_a_private_job_never_appears_on_another_members_page(test_client, async_db):
    """Visibility is applied in SQL, so it cannot shorten a page after the LIMIT."""
    owner = await _create_user(async_db, email="jobowner@caps.example.com")
    await _create_user(async_db, email="jobother@caps.example.com")
    wf = WorkflowDef(name="Vis WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()

    case = InvestigationCase(name="Mixed", status="open", created_by_user_id=owner.id, is_shared=True)
    async_db.add(case)
    await async_db.flush()

    for i, private in enumerate((False, True)):
        lf = LogFile(original_filename=f"vis-{i}.evtx", stored_filename=f"vis_{i}.evtx", sha256=f"{i + 500:064d}", size_bytes=1)
        async_db.add(lf)
        await async_db.flush()
        job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=owner.id, is_private=private)
        async_db.add(job)
        await async_db.flush()
        async_db.add(CaseJobLink(case_id=case.id, job_id=job.id, added_by_user_id=owner.id))
    await async_db.commit()

    await _login(test_client, "jobother@caps.example.com")
    page = await test_client.get(f"/intel/cases/{case.id}")
    assert "vis-1.evtx" not in page.text
    rows = await test_client.get(f"/intel/cases/{case.id}/jobs-partial")
    assert len(_job_row_ids(rows.text, case.id)) == 1
    assert "vis-1.evtx" not in rows.text


async def test_partials_refuse_a_case_the_viewer_cannot_see(test_client, async_db):
    owner = await _create_user(async_db, email="hidden@caps.example.com")
    await _create_user(async_db, email="nosy@caps.example.com")
    case = InvestigationCase(name="Private case", status="open", created_by_user_id=owner.id, is_shared=False)
    async_db.add(case)
    await async_db.commit()

    await _login(test_client, "nosy@caps.example.com")
    for kind in ("entities", "jobs"):
        assert (await test_client.get(f"/intel/cases/{case.id}/{kind}-partial")).status_code == 404


# ─── The cap survives where it still means something ─────────────────────────────


async def test_the_json_api_is_still_capped(test_client, big_case):
    """`detail.json` is Bearer-token reachable; an uncapped 50k-entity dump is a DoS."""
    await _login(test_client, "owner@caps.example.com")
    data = (await test_client.get(f"/intel/cases/{big_case['case_id']}/detail.json")).json()
    assert len(data["entities"]) == _CASE_LINK_CAP
    assert len(data["jobs"]) == _CASE_LINK_CAP
    assert data["truncated"] is True


async def test_small_case_renders_without_a_pager(test_client, async_db):
    owner = await _create_user(async_db, email="small@caps.example.com")
    case = InvestigationCase(name="Small case", status="open", created_by_user_id=owner.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()

    await _login(test_client, "small@caps.example.com")
    rows = await test_client.get(f"/intel/cases/{case.id}/entities-partial")
    assert rows.status_code == 200
    assert "No entities" in rows.text
    assert "entities-partial?page=" not in rows.text


async def test_the_graph_tab_is_gated_on_the_count_not_on_a_loaded_row_list(test_client, async_db):
    """The graph must not say "no entities" on a case whose Entities tab is lazy.

    The tab is lazy and paged, so `case_detail` passes no row list. Jinja renders an
    undefined name as falsy, so a gate on one raises no error anywhere — the page would
    quietly claim the case is empty while graph.json returns hundreds of nodes. The count
    is correct, and it is what the badge already needs.
    """
    owner = await _create_user(async_db, email="graphgate@caps.example.com")
    empty = InvestigationCase(name="Empty", status="open", created_by_user_id=owner.id, is_shared=True)
    filled = InvestigationCase(name="Filled", status="open", created_by_user_id=owner.id, is_shared=True)
    async_db.add_all([empty, filled])
    await async_db.flush()

    entity = Entity(value="8.8.8.8", entity_type="ip_address", job_count=1)
    async_db.add(entity)
    await async_db.flush()
    async_db.add(CaseEntityLink(case_id=filled.id, entity_id=entity.id, added_by_user_id=owner.id))
    await async_db.commit()

    await _login(test_client, "graphgate@caps.example.com")

    body = (await test_client.get(f"/intel/cases/{filled.id}")).text
    assert "case-graph-region" in body, "a case with entities must wire up the graph"
    assert "No entities to graph" not in body

    body = (await test_client.get(f"/intel/cases/{empty.id}")).text
    assert "No entities to graph" in body
    assert "case-graph-region" not in body
