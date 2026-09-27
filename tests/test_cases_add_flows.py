"""Tests for the case add-flows: browsable pickers, multi-select bulk endpoints,
bulk-add from the jobs list, and the include-entities default."""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
    CaseEntityLink,
    CaseJobLink,
    Entity,
    EntityJobLink,
    InvestigationCase,
    JobStatus,
    LogFile,
    User,
    WorkflowDef,
)

pytestmark = pytest.mark.anyio


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


@pytest.fixture()
async def data(async_db):
    async_db.add(WorkflowDef(id=1, name="wf"))
    for i in (1, 2, 3):
        async_db.add(LogFile(id=i, original_filename=f"capture{i}.evtx", stored_filename=f"f{i}.evtx", sha256=str(i) * 64, size_bytes=10))
    await async_db.commit()

    owner = await _create_user(async_db, email="owner@add.example.com")
    other = await _create_user(async_db, email="other@add.example.com")

    public_a = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED)
    public_b = AnalysisJob(file_id=2, workflow_id=1, status=JobStatus.COMPLETED)
    others_private = AnalysisJob(file_id=3, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=other.id)
    async_db.add_all([public_a, public_b, others_private])

    e1 = Entity(value="10.0.0.1", entity_type="ip_address", job_count=9)
    e2 = Entity(value="evil.example", entity_type="domain", job_count=4)
    muted = Entity(value="8.8.8.8", entity_type="ip_address", job_count=99, allowlisted=True)
    async_db.add_all([e1, e2, muted])
    await async_db.commit()

    # public_a carries two entities, so include_entities has something to import.
    async_db.add_all([EntityJobLink(entity_id=e1.id, job_id=public_a.id), EntityJobLink(entity_id=e2.id, job_id=public_a.id)])
    case = InvestigationCase(name="Add Case", created_by_user_id=owner.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()

    for obj in (public_a, public_b, others_private, e1, e2, muted, case, owner, other):
        await async_db.refresh(obj)
    return {"a": public_a, "b": public_b, "private": others_private, "e1": e1, "e2": e2, "muted": muted, "case": case}


# ── Browsable pickers ────────────────────────────────────────────────────────


async def test_entity_picker_browses_on_empty_query(member_client, data):
    rows = (await member_client.get("/intel/cases/pickers/entities.json?q=")).json()
    values = [r["value"] for r in rows]
    assert values, "empty q must browse, not return nothing"
    assert values[0] == "10.0.0.1", "browse is ranked by job_count desc"
    assert "8.8.8.8" not in values, "allowlisted entities are noise in a browse list"


async def test_entity_picker_waits_at_one_char(member_client, data):
    assert (await member_client.get("/intel/cases/pickers/entities.json?q=e")).json() == []
    assert (await member_client.get("/intel/cases/pickers/entities.json?q=ev")).json()


async def test_job_picker_browses_recent_visible_jobs(member_client, data):
    rows = (await member_client.get("/intel/cases/pickers/jobs.json?q=")).json()
    assert rows, "empty q must browse"
    assert {r["id"] for r in rows} == {data["a"].id, data["b"].id}


async def test_job_picker_browse_excludes_other_users_private_jobs(member_client, data):
    """The browse default is a new surface for the private-job boundary."""
    rows = (await member_client.get("/intel/cases/pickers/jobs.json?q=")).json()
    assert data["private"].id not in {r["id"] for r in rows}


async def test_job_picker_numeric_id_still_works(member_client, data):
    rows = (await member_client.get(f"/intel/cases/pickers/jobs.json?q={data['a'].id}")).json()
    assert [r["id"] for r in rows] == [data["a"].id]


@pytest.mark.parametrize("q", ["%C2%B2", "%E2%91%A0"])
async def test_job_picker_treats_a_non_ascii_digit_as_text(member_client, data, q):
    """`'²'.isdigit()` is True and `int('²')` raises, so the id branch 500'd on one keystroke."""
    resp = await member_client.get(f"/intel/cases/pickers/jobs.json?q={q}")
    assert resp.status_code == 200
    assert resp.json() == []


# ── Bulk entity linking ──────────────────────────────────────────────────────


async def test_bulk_add_entities_links_all_and_is_idempotent(member_client, async_db, data):
    case, e1, e2 = data["case"], data["e1"], data["e2"]
    payload = {"entity_ids": [str(e1.id), str(e2.id)], "note": "from the picker"}

    assert (await member_client.post(f"/intel/cases/{case.id}/entities/bulk", data=payload, follow_redirects=False)).status_code == 303
    links = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all()
    assert {link.entity_id for link in links} == {e1.id, e2.id}
    assert all(link.note == "from the picker" for link in links)

    await member_client.post(f"/intel/cases/{case.id}/entities/bulk", data=payload, follow_redirects=False)
    again = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all()
    assert len(again) == 2, "re-submitting must not duplicate links"


async def test_re_adding_with_a_note_updates_it_rather_than_dropping_it(member_client, async_db, data):
    """A duplicate add is not an error, but the note it carries is the one thing new about
    it — and it must not be swallowed with the IntegrityError."""
    case, e1 = data["case"], data["e1"]

    await member_client.post(f"/intel/cases/{case.id}/entities/bulk", data={"entity_ids": [str(e1.id)]}, follow_redirects=False)
    await member_client.post(f"/intel/cases/{case.id}/entities/bulk", data={"entity_ids": [str(e1.id)], "note": "seen again in job 12"}, follow_redirects=False)

    links = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all()
    assert len(links) == 1, "still no duplicate row"
    assert links[0].note == "seen again in job 12"


async def test_re_adding_without_a_note_leaves_the_existing_one_alone(member_client, async_db, data):
    """Blank is the default state of every one of these fields, so treating it as "erase"
    would delete a colleague's note on any re-add."""
    case, e1 = data["case"], data["e1"]

    await member_client.post(f"/intel/cases/{case.id}/entities/bulk", data={"entity_ids": [str(e1.id)], "note": "the original reason"}, follow_redirects=False)
    await member_client.post(f"/intel/cases/{case.id}/entities/bulk", data={"entity_ids": [str(e1.id)]}, follow_redirects=False)

    links = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all()
    assert links[0].note == "the original reason"


async def test_single_add_also_lands_a_note_on_an_existing_link(member_client, async_db, data):
    """The single-add route swallows its own IntegrityError, so it needed the same fix."""
    # Plain ints, captured before the request: this route rolls back on the duplicate, and
    # a rollback expires every ORM object in the shared session — reading `case.id`
    # afterwards is the MissingGreenlet the route's own comment warns about.
    case_id, entity_id = data["case"].id, data["e1"].id

    await member_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(entity_id)}, follow_redirects=False)
    await member_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(entity_id), "note": "second thoughts"}, follow_redirects=False)

    links = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id))).scalars().all()
    assert len(links) == 1
    assert links[0].note == "second thoughts"


async def test_the_jobs_list_bulk_bar_offers_a_note(member_client, async_db, data):
    """The one add-to-case surface that had no note field, though its endpoint took one."""
    body = (await member_client.get("/jobs")).text
    assert 'name="note"' in body, "the jobs-list bulk bar must offer the link note"


async def test_the_dialog_note_is_separated_from_the_new_case_field(member_client, async_db, data):
    """It applies to both paths, and the submit handler has always sent it on both — but
    sitting flush under "Create a new case" made it read as a field of that block."""
    body = (await member_client.get(f"/jobs/{data['a'].id}")).text
    assert "whichever case you pick" in body
    # And it really is sent down the existing-case branch, not only quick-create.
    assert body.count("setHiddenField('note', noteValue)") == 2


async def test_bulk_add_entities_rejects_unknown_id(member_client, async_db, data):
    case = data["case"]
    resp = await member_client.post(
        f"/intel/cases/{case.id}/entities/bulk",
        data={"entity_ids": [str(data["e1"].id), "999999"]},
        follow_redirects=False,
    )
    assert resp.status_code == 404
    assert (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all() == []


async def test_bulk_add_entities_over_cap_rejected(member_client, data):
    case = data["case"]
    payload = {"entity_ids": [str(i) for i in range(1, 60)]}
    assert (await member_client.post(f"/intel/cases/{case.id}/entities/bulk", data=payload, follow_redirects=False)).status_code == 400


# ── Bulk job linking ─────────────────────────────────────────────────────────


async def test_bulk_add_jobs_includes_entities_by_default(member_client, async_db, data):
    case, a, b = data["case"], data["a"], data["b"]
    resp = await member_client.post(
        f"/intel/cases/{case.id}/jobs/bulk",
        data={"job_ids": [str(a.id), str(b.id)]},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    job_links = (await async_db.execute(select(CaseJobLink).where(CaseJobLink.case_id == case.id))).scalars().all()
    assert {link.job_id for link in job_links} == {a.id, b.id}

    entity_links = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all()
    assert {link.entity_id for link in entity_links} == {data["e1"].id, data["e2"].id}


async def test_bulk_add_jobs_can_opt_out_of_entities(member_client, async_db, data):
    case, a = data["case"], data["a"]
    await member_client.post(
        f"/intel/cases/{case.id}/jobs/bulk",
        data={"job_ids": [str(a.id)], "include_entities": "0"},
        follow_redirects=False,
    )
    assert (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all() == []


async def test_bulk_add_jobs_404s_and_writes_nothing_when_any_id_unviewable(member_client, async_db, data):
    """A partial success would be an existence oracle for another member's private job."""
    case = data["case"]
    resp = await member_client.post(
        f"/intel/cases/{case.id}/jobs/bulk",
        data={"job_ids": [str(data["a"].id), str(data["private"].id)]},
        follow_redirects=False,
    )
    assert resp.status_code == 404
    assert (await async_db.execute(select(CaseJobLink).where(CaseJobLink.case_id == case.id))).scalars().all() == []


# ── include_entities defaults ────────────────────────────────────────────────


async def test_single_job_route_server_default_does_not_add_entities(member_client, async_db, data):
    """The single-job form contract defaults to `include_entities=0` server-side, so
    scripted callers that never opt in get no entities; only the templates send 1."""
    case, a = data["case"], data["a"]
    await member_client.post(f"/intel/cases/{case.id}/jobs", data={"job_id": str(a.id)}, follow_redirects=False)
    assert (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all() == []


async def test_add_to_case_dialog_checks_include_entities(member_client, data):
    """The job page's shared dialog must pre-tick 'also add this job's entities'."""
    body = (await member_client.get(f"/jobs/{data['a'].id}")).text
    marker = 'type="checkbox" checked class="add-to-case-include-entities'
    assert marker in body


async def test_case_detail_add_job_dialog_checks_include_entities(member_client, data):
    body = (await member_client.get(f"/intel/cases/{data['case'].id}")).text
    assert 'name="include_entities" value="1" checked' in body


# ── Jobs-list bulk controls ──────────────────────────────────────────────────


async def test_jobs_list_bulk_controls_are_member_gated(test_client, async_db, data):
    """The store itself is declared globally in base.html; what must be gated are the
    row checkboxes and the action bar."""
    await _create_user(async_db, email="basic@add.example.com", role="user")

    anon = (await test_client.get("/jobs")).text
    assert "$store.jobSelection.toggle(" not in anon
    assert "Add to case" not in anon

    await _login(test_client, "basic@add.example.com")
    basic = (await test_client.get("/jobs")).text
    assert "$store.jobSelection.toggle(" not in basic
    assert "Add to case" not in basic

    await _login(test_client, "owner@add.example.com")
    body = (await test_client.get("/jobs")).text
    assert "$store.jobSelection.toggle(" in body
    assert "Add to case" in body


async def test_jobs_table_checkboxes_bind_to_the_alpine_store(member_client, data):
    """Guards the poll-survival mechanism: DOM state would be wiped every 5s."""
    body = (await member_client.get("/jobs/table-partial")).text
    assert "$store.jobSelection.has(" in body
    assert "$store.jobSelection.toggle(" in body


# ── Jobs-list bulk delete ────────────────────────────────────────────────────


async def test_bulk_delete_removes_selected_jobs(admin_client, async_db, data):
    a, b, keep = data["a"], data["b"], data["private"]
    resp = await admin_client.post("/jobs/bulk-delete", data={"job_ids": [str(a.id), str(b.id)]}, follow_redirects=False)
    assert resp.status_code == 303

    remaining = {j.id for j in (await async_db.execute(select(AnalysisJob))).scalars().all()}
    assert a.id not in remaining and b.id not in remaining
    assert keep.id in remaining, "unselected jobs must survive"

    # Entity links for the deleted jobs are cleaned up too.
    links = (await async_db.execute(select(EntityJobLink).where(EntityJobLink.job_id == a.id))).scalars().all()
    assert links == []


async def test_bulk_delete_skips_unknown_ids_instead_of_failing(admin_client, async_db, data):
    """The selection can go stale against the 5s poll; a half-completed 404 is worse."""
    a = data["a"]
    resp = await admin_client.post("/jobs/bulk-delete", data={"job_ids": [str(a.id), "999999"]}, follow_redirects=False)
    assert resp.status_code == 303
    assert await async_db.get(AnalysisJob, a.id) is None


async def test_bulk_delete_over_cap_rejected(admin_client, data):
    payload = {"job_ids": [str(i) for i in range(1, 120)]}
    assert (await admin_client.post("/jobs/bulk-delete", data=payload, follow_redirects=False)).status_code == 400


async def test_bulk_delete_is_admin_only(test_client, async_db, data):
    await _create_user(async_db, email="plainmember@add.example.com")
    await _login(test_client, "plainmember@add.example.com")
    resp = await test_client.post("/jobs/bulk-delete", data={"job_ids": [str(data["a"].id)]}, follow_redirects=False)
    assert resp.status_code in (401, 403)
    assert await async_db.get(AnalysisJob, data["a"].id) is not None


async def test_bulk_delete_button_only_renders_for_admin(admin_client, async_db, data):
    """A member sees 'Add to case' but no Delete; an admin sees both.

    `admin_client` and `test_client` are the same httpx client in conftest, so the admin
    assertions run first and the member login deliberately replaces that session.
    """
    admin_body = (await admin_client.get("/jobs")).text
    assert "/jobs/bulk-delete" in admin_body
    assert 'data-confirm-title="Delete jobs"' in admin_body

    await _login(admin_client, "owner@add.example.com")
    member_body = (await admin_client.get("/jobs")).text
    assert "Add to case" in member_body
    assert "/jobs/bulk-delete" not in member_body


async def test_jobs_list_explains_what_the_checkboxes_do(member_client, data):
    """The checkbox column must not be an unexplained control."""
    body = (await member_client.get("/jobs")).text
    assert "Tick jobs to add them to a case" in body
    assert "$store.jobSelection.setAllVisible(" in body, "select-all affordance missing"


async def test_the_cases_list_counts_only_jobs_the_viewer_can_see(test_client, async_db, data):
    """Another member's private job linked into a shared case showed as "1 job" on the list,
    while the case's own Jobs tab said (0) — a mismatch that reads as data loss and says a
    private job is there. The list's other aggregates already filtered; this count did not."""
    from app.models import CaseJobLink

    async_db.add(CaseJobLink(case_id=data["case"].id, job_id=data["private"].id))
    await async_db.commit()

    await _login(test_client, "owner@add.example.com")
    body = (await test_client.get("/intel/cases")).text
    assert "0 jobs" in body
    assert ">1 job<" not in body
