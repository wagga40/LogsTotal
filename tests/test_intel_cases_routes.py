"""Route tests for the case-building shortcuts.

Covers quick-create (case + entity/job in one step), the entity/job search pickers,
the bulk add-job-entities helper/endpoint, and owner-only case editing.
"""

from __future__ import annotations

import json

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
    Finding,
    InvestigationCase,
    JobStatus,
    LogFile,
    LogType,
    Severity,
    TaskResult,
    TaskStatus,
    User,
    WorkflowDef,
)

PUBLIC_FILENAME = "public_case_target.evtx"
PRIVATE_FILENAME = "private_case_target.evtx"


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


def _case_id_from_redirect(resp) -> int:
    return int(resp.headers["location"].rstrip("/").split("/")[-1])


async def _seed_finding(async_db, job_id: int, *, severity, rule_name: str, count: int = 1, tags: list[str] | None = None) -> Finding:
    """Create a TaskResult + Finding on *job_id* — for summary-partial roll-up tests."""
    tr = TaskResult(job_id=job_id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=1)
    async_db.add(tr)
    await async_db.flush()
    finding = Finding(
        task_result_id=tr.id,
        rule_id=rule_name.lower().replace(" ", "-"),
        rule_name=rule_name,
        severity=severity,
        count=count,
        tags=json.dumps(tags or []),
    )
    async_db.add(finding)
    await async_db.commit()
    await async_db.refresh(finding)
    return finding


@pytest.fixture()
async def cases_data(async_db):
    """owner + other members, a public and a private job (both owner's), and two
    entities linked to the public job — enough surface for pickers, quick-create,
    and bulk add-entities."""
    wf = WorkflowDef(name="Cases WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()

    owner = await _create_user(async_db, email="owner@cases.example.com")
    other = await _create_user(async_db, email="other@cases.example.com")

    lf_pub = LogFile(original_filename=PUBLIC_FILENAME, stored_filename="pub_case.evtx", sha256="d" * 64, size_bytes=1024, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    lf_priv = LogFile(original_filename=PRIVATE_FILENAME, stored_filename="priv_case.evtx", sha256="e" * 64, size_bytes=1024, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([lf_pub, lf_priv])
    await async_db.flush()

    job_pub = AnalysisJob(
        submitted_filename=lf_pub.original_filename,
        effective_log_type=lf_pub.log_type,
        file_id=lf_pub.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
        is_private=False,
    )
    job_priv = AnalysisJob(
        submitted_filename=lf_priv.original_filename,
        effective_log_type=lf_priv.log_type,
        file_id=lf_priv.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
        is_private=True,
    )
    async_db.add_all([job_pub, job_priv])
    await async_db.flush()

    entity_a = Entity(value="10.10.10.10", entity_type="ip_address", job_count=1)
    entity_b = Entity(value="20.20.20.20", entity_type="ip_address", job_count=1)
    async_db.add_all([entity_a, entity_b])
    await async_db.flush()
    async_db.add_all(
        [
            EntityJobLink(entity_id=entity_a.id, job_id=job_pub.id, occurrence_count=1),
            EntityJobLink(entity_id=entity_b.id, job_id=job_pub.id, occurrence_count=1),
        ]
    )

    await async_db.commit()
    for obj in (owner, other, job_pub, job_priv, entity_a, entity_b, wf):
        await async_db.refresh(obj)
    return {"owner": owner, "other": other, "job_pub": job_pub, "job_priv": job_priv, "entity_a": entity_a, "entity_b": entity_b, "wf": wf}


# ── quick-create ──────────────────────────────────────────────────────────────


async def test_quick_create_with_entity_links_and_redirects(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]

    resp = await test_client.post("/intel/cases/quick-create", data={"name": "New Case", "entity_id": str(entity.id)}, follow_redirects=False)
    assert resp.status_code == 303
    case_id = _case_id_from_redirect(resp)
    assert resp.headers["location"] == f"/intel/cases/{case_id}"

    case = await async_db.get(InvestigationCase, case_id)
    assert case is not None
    assert case.name == "New Case"
    assert case.created_by_user_id == cases_data["owner"].id

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link is not None


async def test_quick_create_with_job_and_include_entities_links_both(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]

    resp = await test_client.post(
        "/intel/cases/quick-create",
        data={"name": "Job Case", "job_id": str(job.id), "include_job_entities": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    case_id = _case_id_from_redirect(resp)

    job_link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job.id))
    assert job_link is not None

    entity_links = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id))).scalars().all()
    linked_entity_ids = {el.entity_id for el in entity_links}
    assert linked_entity_ids == {cases_data["entity_a"].id, cases_data["entity_b"].id}


async def test_quick_create_rejects_unviewable_private_job_and_creates_no_case(test_client, async_db, cases_data):
    await _login(test_client, "other@cases.example.com")

    before = len((await async_db.execute(select(InvestigationCase))).scalars().all())

    resp = await test_client.post(
        "/intel/cases/quick-create",
        data={"name": "Should Not Exist", "job_id": str(cases_data["job_priv"].id)},
        follow_redirects=False,
    )
    assert resp.status_code == 404

    after = len((await async_db.execute(select(InvestigationCase))).scalars().all())
    assert after == before

    orphan = await async_db.scalar(select(InvestigationCase).where(InvestigationCase.name == "Should Not Exist"))
    assert orphan is None


async def test_quick_create_rejects_unknown_entity_and_creates_no_case(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    before = len((await async_db.execute(select(InvestigationCase))).scalars().all())

    resp = await test_client.post("/intel/cases/quick-create", data={"name": "Ghost Entity Case", "entity_id": "999999"}, follow_redirects=False)
    assert resp.status_code == 404

    after = len((await async_db.execute(select(InvestigationCase))).scalars().all())
    assert after == before


async def test_quick_create_with_entity_and_note_stores_it_on_link(test_client, async_db, cases_data):
    """The dialog's "Note (optional)" field must not be silently dropped on the
    quick-create path — it should land on the freshly-created CaseEntityLink."""
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]

    resp = await test_client.post(
        "/intel/cases/quick-create",
        data={"name": "Quick Create Note Case", "entity_id": str(entity.id), "note": "Seen beaconing"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    case_id = _case_id_from_redirect(resp)

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link.note == "Seen beaconing"


async def test_quick_create_with_job_and_note_stores_it_on_link(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]

    resp = await test_client.post(
        "/intel/cases/quick-create",
        data={"name": "Quick Create Job Note Case", "job_id": str(job.id), "note": "First observed intrusion"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    case_id = _case_id_from_redirect(resp)

    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job.id))
    assert link.note == "First observed intrusion"


async def test_quick_create_with_overlong_note_rejected_and_creates_no_case(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    before = len((await async_db.execute(select(InvestigationCase))).scalars().all())

    resp = await test_client.post(
        "/intel/cases/quick-create",
        data={"name": "Quick Create Overlong Note Case", "entity_id": str(entity.id), "note": "x" * 501},
        follow_redirects=False,
    )
    assert resp.status_code == 400

    after = len((await async_db.execute(select(InvestigationCase))).scalars().all())
    assert after == before


# ── pickers ───────────────────────────────────────────────────────────────────


async def test_pickers_jobs_hides_other_users_private_job(test_client, cases_data):
    await _login(test_client, "other@cases.example.com")

    resp = await test_client.get("/intel/cases/pickers/jobs.json", params={"q": str(cases_data["job_priv"].id)})
    assert resp.status_code == 200
    assert resp.json() == []


async def test_pickers_jobs_numeric_query_matches_by_id(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]

    resp = await test_client.get("/intel/cases/pickers/jobs.json", params={"q": str(job.id)})
    assert resp.status_code == 200
    data = resp.json()
    assert [row["id"] for row in data] == [job.id]
    assert data[0]["filename"] == PUBLIC_FILENAME
    assert data[0]["status"] == "completed"


async def test_pickers_jobs_owner_can_see_own_private_job(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_priv"]

    resp = await test_client.get("/intel/cases/pickers/jobs.json", params={"q": str(job.id)})
    assert resp.status_code == 200
    assert [row["id"] for row in resp.json()] == [job.id]


async def test_pickers_jobs_numeric_query_beyond_int4_range_returns_empty(test_client, cases_data):
    """A 30-digit numeric `q` is still `str.isdigit()`, but `int(q)` overflows int4 —
    on PostgreSQL that 500s at bind time. Must degrade to "no match" instead."""
    await _login(test_client, "owner@cases.example.com")

    resp = await test_client.get("/intel/cases/pickers/jobs.json", params={"q": "9" * 30})
    assert resp.status_code == 200
    assert resp.json() == []


async def test_pickers_entities_requires_two_chars(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")

    resp = await test_client.get("/intel/cases/pickers/entities.json", params={"q": "a"})
    assert resp.status_code == 200
    assert resp.json() == []

    resp = await test_client.get("/intel/cases/pickers/entities.json", params={"q": " a "})
    assert resp.json() == []


async def test_pickers_entities_escapes_like_wildcards(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    e_percent = Entity(value="5%off-deal", entity_type="domain", job_count=1)
    e_plain = Entity(value="5xyz-other", entity_type="domain", job_count=1)
    async_db.add_all([e_percent, e_plain])
    await async_db.commit()

    resp = await test_client.get("/intel/cases/pickers/entities.json", params={"q": "5%"})
    assert resp.status_code == 200
    values = [row["value"] for row in resp.json()]
    assert "5%off-deal" in values
    assert "5xyz-other" not in values


async def test_case_detail_picker_forms_guard_against_empty_selection(test_client, cases_data):
    """Submitting the Add Entity/Add Job forms without picking anything must not POST an
    empty id list — a client-side guard should block the submit instead. (The pickers are
    multi-select, so the guard checks `selected.length` rather than a single hidden input.)"""
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Guard Check Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.get(f"/intel/cases/{case_id}")
    assert resp.status_code == 200
    assert '@submit="onSubmit($event)"' in resp.text
    assert "if (!this.selected.length) event.preventDefault()" in resp.text


# ── bulk add-entities ─────────────────────────────────────────────────────────


async def test_bulk_add_job_entities_helper_dedupes_and_second_call_links_zero(async_db, cases_data):
    from app.routers.cases import _bulk_add_job_entities

    owner = cases_data["owner"]
    case = InvestigationCase(name="Helper Case", created_by_user_id=owner.id)
    async_db.add(case)
    await async_db.flush()
    # Pre-link one of the two entities to prove the helper dedupes.
    async_db.add(CaseEntityLink(case_id=case.id, entity_id=cases_data["entity_a"].id))
    await async_db.commit()
    await async_db.refresh(case)

    linked = await _bulk_add_job_entities(async_db, case.id, cases_data["job_pub"].id, owner.id)
    assert linked == 1  # only entity_b was missing

    links = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case.id))).scalars().all()
    entity_ids = {link.entity_id for link in links}
    assert entity_ids == {cases_data["entity_a"].id, cases_data["entity_b"].id}
    # The newly-linked row must record who/what triggered the bulk add.
    new_link = next(link for link in links if link.entity_id == cases_data["entity_b"].id)
    assert new_link.added_by_user_id == owner.id

    linked_again = await _bulk_add_job_entities(async_db, case.id, cases_data["job_pub"].id, owner.id)
    assert linked_again == 0


async def test_case_add_job_include_entities_links_entities_on_fresh_link(test_client, async_db, cases_data):
    """include_entities=1 on a job that isn't linked yet — the common case."""
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]
    create = await test_client.post("/intel/cases", data={"name": "Fresh Link Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/jobs",
        data={"job_id": str(job.id), "include_entities": "1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    entity_ids = set((await async_db.execute(select(CaseEntityLink.entity_id).where(CaseEntityLink.case_id == case_id))).scalars().all())
    assert entity_ids == {cases_data["entity_a"].id, cases_data["entity_b"].id}


async def test_case_add_job_include_entities_on_already_linked_job_does_not_500(test_client, async_db, cases_data):
    """Re-adding an already-linked job with the checkbox checked must not 500.

    The IntegrityError/rollback path expires the ORM `case`/`job` objects; touching their
    .id attributes afterwards in _bulk_add_job_entities would crash with MissingGreenlet
    under the async engine.
    """
    await _login(test_client, "owner@cases.example.com")
    job_id = cases_data["job_pub"].id
    # Capture plain ids up front: the request that follows shares `async_db` with the
    # test (dependency override), so the rollback the app performs internally expires
    # every ORM object in the session's identity map, including these fixture objects.
    entity_a_id = cases_data["entity_a"].id
    entity_b_id = cases_data["entity_b"].id
    create = await test_client.post("/intel/cases", data={"name": "Already Linked Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    first = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job_id)}, follow_redirects=False)
    assert first.status_code == 303

    second = await test_client.post(
        f"/intel/cases/{case_id}/jobs",
        data={"job_id": str(job_id), "include_entities": "1"},
        follow_redirects=False,
    )
    assert second.status_code == 303

    job_links = (await async_db.execute(select(CaseJobLink).where(CaseJobLink.case_id == case_id))).scalars().all()
    assert len(job_links) == 1  # no duplicate job link from the second POST

    entity_ids = set((await async_db.execute(select(CaseEntityLink.entity_id).where(CaseEntityLink.case_id == case_id))).scalars().all())
    assert entity_ids == {entity_a_id, entity_b_id}


async def test_add_entities_endpoint_requires_job_to_be_case_member(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "No Job Yet"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{cases_data['job_pub'].id}/add-entities", follow_redirects=False)
    assert resp.status_code == 404


async def test_add_entities_endpoint_links_all_job_entities(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]
    create = await test_client.post("/intel/cases", data={"name": "Add Entities Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    add_job = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)
    assert add_job.status_code == 303

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{job.id}/add-entities", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/intel/cases/{case_id}"

    entity_ids = set((await async_db.execute(select(CaseEntityLink.entity_id).where(CaseEntityLink.case_id == case_id))).scalars().all())
    assert entity_ids == {cases_data["entity_a"].id, cases_data["entity_b"].id}


async def test_add_entities_endpoint_owner_cannot_bulk_add_entities_of_link_whose_job_they_cannot_view(test_client, async_db, cases_data):
    """A member adds their own PRIVATE job to a shared case; the case owner (who did not
    submit that job and isn't an admin) must get 404 — not a silent bulk-import of that
    job's entity roster — mirroring case_job_note_save's visibility gate.

    Also asserts that 404 is byte-identical to the "job was never linked to this case at
    all" 404 (no existence oracle), and that zero CaseEntityLink rows are created.
    """
    other_private_job = await _add_other_private_job(async_db, cases_data, "bulk_owner_cannot_view.evtx")
    # Give the private job its own entity so a successful (buggy) bulk-add would be observable.
    hidden_entity = Entity(value="99.99.99.99", entity_type="ip_address", job_count=1)
    async_db.add(hidden_entity)
    await async_db.flush()
    async_db.add(EntityJobLink(entity_id=hidden_entity.id, job_id=other_private_job.id, occurrence_count=1))
    await async_db.commit()

    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Bulk Cross-Visibility Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    # Scenario A: the job was never linked to this case at all.
    never_linked = await test_client.post(f"/intel/cases/{case_id}/jobs/{other_private_job.id}/add-entities", follow_redirects=False)
    assert never_linked.status_code == 404

    await _login(test_client, "other@cases.example.com")
    add = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(other_private_job.id)}, follow_redirects=False)
    assert add.status_code == 303

    # Scenario B: the job IS linked (by `other`), but is private and invisible to `owner`.
    await _login(test_client, "owner@cases.example.com")
    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{other_private_job.id}/add-entities", follow_redirects=False)
    assert resp.status_code == 404
    assert "bulk_owner_cannot_view.evtx" not in resp.text
    assert resp.json()["detail"] == never_linked.json()["detail"]

    links = (await async_db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id))).scalars().all()
    assert links == []


async def test_add_entities_endpoint_adder_can_bulk_add_their_own_private_job_link(test_client, async_db, cases_data):
    """The adder of a private job can still bulk-add its own job's entities, even though
    other case members (e.g. the case owner) cannot view that job at all."""
    other_private_job = await _add_other_private_job(async_db, cases_data, "bulk_adder_can_view.evtx")
    hidden_entity = Entity(value="88.88.88.88", entity_type="ip_address", job_count=1)
    async_db.add(hidden_entity)
    await async_db.flush()
    async_db.add(EntityJobLink(entity_id=hidden_entity.id, job_id=other_private_job.id, occurrence_count=1))
    await async_db.commit()

    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Bulk Adder Can Edit Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    await _login(test_client, "other@cases.example.com")
    add = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(other_private_job.id)}, follow_redirects=False)
    assert add.status_code == 303

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{other_private_job.id}/add-entities", follow_redirects=False)
    assert resp.status_code == 303

    entity_ids = set((await async_db.execute(select(CaseEntityLink.entity_id).where(CaseEntityLink.case_id == case_id))).scalars().all())
    assert entity_ids == {hidden_entity.id}


# ── /edit ─────────────────────────────────────────────────────────────────────


async def test_case_edit_owner_updates_name_summary_severity(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Edit Me"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/edit",
        data={"name": "Edited Name", "summary": "New summary", "severity": "high"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    case = await async_db.get(InvestigationCase, case_id)
    await async_db.refresh(case)
    assert case.name == "Edited Name"
    assert case.summary == "New summary"
    assert case.severity == "high"


async def test_case_edit_invalid_severity_coerced_to_none(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Bad Severity Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/edit",
        data={"name": "Bad Severity Case", "summary": "", "severity": "not-a-real-severity"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    case = await async_db.get(InvestigationCase, case_id)
    await async_db.refresh(case)
    assert case.severity is None


async def test_case_edit_non_owner_member_forbidden(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    # Shared so the other member can see the case (and thus reach the owner check).
    create = await test_client.post("/intel/cases", data={"name": "Shared Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    await _login(test_client, "other@cases.example.com")
    resp = await test_client.post(
        f"/intel/cases/{case_id}/edit",
        data={"name": "Hijacked", "summary": "", "severity": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 403


# ── case notes ──────────────────────────────────────────────────────────────────


async def test_case_notes_owner_saves_and_renders(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Notes Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(f"/intel/cases/{case_id}/notes", data={"body": "Suspicious lateral movement, escalating."})
    assert resp.status_code == 200
    assert "Suspicious lateral movement, escalating." in resp.text

    case = await async_db.get(InvestigationCase, case_id)
    await async_db.refresh(case)
    assert case.notes == "Suspicious lateral movement, escalating."


async def test_case_notes_non_owner_member_forbidden(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Shared Notes Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    await _login(test_client, "other@cases.example.com")
    resp = await test_client.post(f"/intel/cases/{case_id}/notes", data={"body": "Sneaky edit"})
    assert resp.status_code == 403


async def test_case_notes_too_long_rejected(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Long Notes Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(f"/intel/cases/{case_id}/notes", data={"body": "x" * 8001})
    assert resp.status_code == 400

    case = await async_db.get(InvestigationCase, case_id)
    await async_db.refresh(case)
    assert case.notes is None


async def test_case_notes_empty_body_clears(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Clear Notes Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    saved = await test_client.post(f"/intel/cases/{case_id}/notes", data={"body": "Something to clear later"})
    assert saved.status_code == 200

    resp = await test_client.post(f"/intel/cases/{case_id}/notes", data={"body": "   "})
    assert resp.status_code == 200

    case = await async_db.get(InvestigationCase, case_id)
    await async_db.refresh(case)
    assert case.notes is None


async def test_case_notes_exactly_at_cap_accepted(test_client, async_db, cases_data):
    """8000 chars exactly is within the cap (`> cap` rejects) — must be accepted, not
    rejected off-by-one."""
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Boundary Notes Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    body = "x" * 8000
    resp = await test_client.post(f"/intel/cases/{case_id}/notes", data={"body": body})
    assert resp.status_code == 200

    case = await async_db.get(InvestigationCase, case_id)
    await async_db.refresh(case)
    assert case.notes == body


# ── entity link notes ────────────────────────────────────────────────────────────


async def test_add_entity_with_note_stores_it_on_link(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    create = await test_client.post("/intel/cases", data={"name": "Add With Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/entities",
        data={"entity_id": str(entity.id), "note": "Beaconing host"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link.note == "Beaconing host"


async def test_add_job_with_note_stores_it_on_link(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]
    create = await test_client.post("/intel/cases", data={"name": "Add Job With Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/jobs",
        data={"job_id": str(job.id), "note": "First observed intrusion"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job.id))
    assert link.note == "First observed intrusion"


async def test_add_job_with_overlong_note_rejected(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]
    create = await test_client.post("/intel/cases", data={"name": "Add Job Overlong Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/jobs",
        data={"job_id": str(job.id), "note": "x" * 501},
        follow_redirects=False,
    )
    assert resp.status_code == 400

    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job.id))
    assert link is None


async def test_add_entity_with_overlong_note_rejected(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    create = await test_client.post("/intel/cases", data={"name": "Add Overlong Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/entities",
        data={"entity_id": str(entity.id), "note": "x" * 501},
        follow_redirects=False,
    )
    assert resp.status_code == 400

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link is None


async def test_add_entity_with_note_exactly_at_cap_accepted(test_client, async_db, cases_data):
    """500 chars exactly is within the cap (`> cap` rejects) — must be accepted, not
    rejected off-by-one."""
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    create = await test_client.post("/intel/cases", data={"name": "Boundary Link Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    note = "x" * 500
    resp = await test_client.post(
        f"/intel/cases/{case_id}/entities",
        data={"entity_id": str(entity.id), "note": note},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link.note == note


async def test_entity_link_note_adder_can_edit_own(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    create = await test_client.post("/intel/cases", data={"name": "Entity Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(entity.id)}, follow_redirects=False)

    resp = await test_client.post(f"/intel/cases/{case_id}/entities/{entity.id}/note", data={"note": "Command-and-control IP"})
    assert resp.status_code == 200
    assert "Command-and-control IP" in resp.text

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link.note == "Command-and-control IP"


async def test_entity_link_note_different_non_owner_member_forbidden(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    create = await test_client.post("/intel/cases", data={"name": "Shared Entity Note Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(entity.id)}, follow_redirects=False)

    await _login(test_client, "other@cases.example.com")
    resp = await test_client.post(f"/intel/cases/{case_id}/entities/{entity.id}/note", data={"note": "Hijacked note"})
    assert resp.status_code == 403


async def test_entity_link_note_owner_can_edit_someone_elses_link(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Owner Overrides Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    await _login(test_client, "other@cases.example.com")
    entity = cases_data["entity_a"]
    add = await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(entity.id)}, follow_redirects=False)
    assert add.status_code == 303  # `other` can add to a shared case even though they don't own it

    await _login(test_client, "owner@cases.example.com")
    resp = await test_client.post(f"/intel/cases/{case_id}/entities/{entity.id}/note", data={"note": "Owner's annotation"})
    assert resp.status_code == 200

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link.note == "Owner's annotation"
    assert link.added_by_user_id == cases_data["other"].id  # adder is untouched, only the note changed


async def test_entity_link_note_too_long_rejected(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    create = await test_client.post("/intel/cases", data={"name": "Long Link Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(entity.id)}, follow_redirects=False)

    resp = await test_client.post(f"/intel/cases/{case_id}/entities/{entity.id}/note", data={"note": "x" * 501})
    assert resp.status_code == 400

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link.note is None


async def test_entity_link_note_empty_clears_existing_note(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    create = await test_client.post("/intel/cases", data={"name": "Clear Link Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(entity.id), "note": "Initial note"}, follow_redirects=False)

    resp = await test_client.post(f"/intel/cases/{case_id}/entities/{entity.id}/note", data={"note": "   "})
    assert resp.status_code == 200

    link = await async_db.scalar(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity.id))
    assert link.note is None


# ── job link notes ───────────────────────────────────────────────────────────────


async def test_job_link_note_adder_can_edit_own(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]
    create = await test_client.post("/intel/cases", data={"name": "Job Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{job.id}/note", data={"note": "Patient zero"})
    assert resp.status_code == 200
    assert "Patient zero" in resp.text

    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job.id))
    assert link.note == "Patient zero"


async def test_job_link_note_owner_can_edit_someone_elses_link(test_client, async_db, cases_data):
    """Owner overrides another member's note on a job link they CAN view (public job) —
    the visibility gate must not block the owner from a job they're allowed to see."""
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Owner Overrides Job Note Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    await _login(test_client, "other@cases.example.com")
    job = cases_data["job_pub"]
    add = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)
    assert add.status_code == 303  # `other` can add to a shared case even though they don't own it

    await _login(test_client, "owner@cases.example.com")
    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{job.id}/note", data={"note": "Owner's annotation"})
    assert resp.status_code == 200

    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job.id))
    assert link.note == "Owner's annotation"
    assert link.added_by_user_id == cases_data["other"].id  # adder is untouched, only the note changed


async def test_job_link_note_different_non_owner_member_forbidden(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]
    create = await test_client.post("/intel/cases", data={"name": "Shared Job Note Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)

    await _login(test_client, "other@cases.example.com")
    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{job.id}/note", data={"note": "Hijacked note"})
    assert resp.status_code == 403


async def test_job_link_note_too_long_rejected(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]
    create = await test_client.post("/intel/cases", data={"name": "Long Job Note Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{job.id}/note", data={"note": "x" * 501})
    assert resp.status_code == 400


async def _add_other_private_job(async_db, cases_data, filename: str) -> AnalysisJob:
    """A private job submitted by `other` — used to test the job-note endpoint's
    can_view_job gate against a case member who isn't the job's submitter."""
    other = cases_data["other"]
    lf = LogFile(original_filename=filename, stored_filename=filename, sha256="f" * 64, size_bytes=1024, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add(lf)
    await async_db.flush()
    job = AnalysisJob(
        submitted_filename=lf.original_filename,
        effective_log_type=lf.log_type,
        file_id=lf.id,
        workflow_id=cases_data["wf"].id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=other.id,
        is_private=True,
    )
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)
    return job


async def test_job_link_note_owner_cannot_edit_link_whose_job_they_cannot_view(test_client, async_db, cases_data):
    """A member adds their own PRIVATE job to a shared case; the case owner (who did
    not submit that job and isn't an admin) must get 404 — not a rendered row with
    the job's filename — mirroring case_add_job's private-job treatment.

    Also asserts that 404 is byte-identical to the "job was never linked to this
    case at all" 404: a distinct message for "linked but invisible" would be an
    existence oracle, letting any case member learn a given job_id is (privately)
    linked to the case just from which 404 text comes back.
    """
    other_private_job = await _add_other_private_job(async_db, cases_data, "owner_cannot_view.evtx")

    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Cross-Visibility Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    # Scenario A: the job was never linked to this case at all.
    never_linked = await test_client.post(f"/intel/cases/{case_id}/jobs/{other_private_job.id}/note", data={"note": "Should not work"})
    assert never_linked.status_code == 404

    await _login(test_client, "other@cases.example.com")
    add = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(other_private_job.id)}, follow_redirects=False)
    assert add.status_code == 303

    # Scenario B: the job IS linked (by `other`), but is private and invisible to `owner`.
    await _login(test_client, "owner@cases.example.com")
    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{other_private_job.id}/note", data={"note": "Should not work"})
    assert resp.status_code == 404
    assert "owner_cannot_view.evtx" not in resp.text
    assert resp.json()["detail"] == never_linked.json()["detail"]

    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == other_private_job.id))
    assert link.note is None


async def test_job_link_note_adder_can_edit_their_own_private_job_link(test_client, async_db, cases_data):
    """The adder of a private job can still edit its own link note, even though other
    case members (e.g. the case owner) cannot view that job at all."""
    other_private_job = await _add_other_private_job(async_db, cases_data, "adder_can_view.evtx")

    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Adder Can Edit Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    await _login(test_client, "other@cases.example.com")
    add = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(other_private_job.id)}, follow_redirects=False)
    assert add.status_code == 303

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs/{other_private_job.id}/note", data={"note": "Patient zero, my own job"})
    assert resp.status_code == 200
    assert "Patient zero, my own job" in resp.text

    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == other_private_job.id))
    assert link.note == "Patient zero, my own job"


# ── case detail rendering ─────────────────────────────────────────────────────────


async def test_case_detail_renders_added_by_and_note_for_linked_entity(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    entity = cases_data["entity_a"]
    create = await test_client.post("/intel/cases", data={"name": "Render Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(
        f"/intel/cases/{case_id}/entities",
        data={"entity_id": str(entity.id), "note": "Pivot point"},
        follow_redirects=False,
    )

    # The rows are lazy — the detail page carries the region, the partial the rows.
    resp = await test_client.get(f"/intel/cases/{case_id}/entities-partial")
    assert resp.status_code == 200
    assert "added" in resp.text
    assert "owner@cases.example.com" in resp.text
    assert "Pivot point" in resp.text


async def test_case_detail_renders_added_by_and_note_for_linked_job(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]
    create = await test_client.post("/intel/cases", data={"name": "Render Job Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(
        f"/intel/cases/{case_id}/jobs",
        data={"job_id": str(job.id), "note": "Beacon source"},
        follow_redirects=False,
    )

    resp = await test_client.get(f"/intel/cases/{case_id}/jobs-partial")
    assert resp.status_code == 200
    assert "added" in resp.text
    assert "owner@cases.example.com" in resp.text
    assert "Beacon source" in resp.text


# ── tabbed workspace ─────────────────────────────────────────────────────────────


def test_build_case_tabs_shape():
    from app.routers.cases import _build_case_tabs

    tabs = _build_case_tabs(entity_count=3, job_count=5)
    # timeline sits second (after overview); Discussions is last, as on the entity page.
    assert [t["key"] for t in tabs] == ["overview", "timeline", "entities", "jobs", "processes", "graph", "discussion"]
    by_key = {t["key"]: t for t in tabs}
    assert by_key["overview"]["badge"] is None
    assert by_key["timeline"]["badge"] is None and by_key["timeline"]["lazy_event"] == "loadTimeline"
    # Entities and Jobs are lazy and paged; the badges stay the true totals.
    assert by_key["entities"]["badge"] == 3 and by_key["entities"]["lazy_event"] == "loadEntities"
    assert by_key["jobs"]["badge"] == 5 and by_key["jobs"]["lazy_event"] == "loadJobs"
    assert by_key["processes"]["badge"] is None and by_key["processes"]["lazy_event"] == "loadProcesses"
    # The narrative lives on Overview; this tab is the comment thread alone.
    assert by_key["discussion"]["badge"] is None and by_key["discussion"]["lazy_event"] == "loadComments"
    assert by_key["graph"]["badge"] is None and by_key["graph"]["lazy_event"] == "loadGraph"


async def test_case_detail_renders_tab_strip_with_six_keys_and_badges(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Tabbed Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(cases_data["entity_a"].id)}, follow_redirects=False)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(cases_data["job_pub"].id)}, follow_redirects=False)

    resp = await test_client.get(f"/intel/cases/{case_id}")
    assert resp.status_code == 200
    for key in ("overview", "timeline", "entities", "jobs", "discussion", "graph"):
        assert f'"{key}"' in resp.text
    assert '"badge": 1' in resp.text  # entities and jobs both have exactly one member


async def test_case_detail_timeline_trigger_fires_once_not_on_every_tab_switch(test_client, cases_data):
    """The timeline tab's HTMX lazy-load must only fire on first activation — otherwise
    switching back to the tab re-fetches and discards the analyst's filter selections."""
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Timeline Trigger Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.get(f"/intel/cases/{case_id}")
    assert resp.status_code == 200
    assert 'hx-trigger="loadTimeline from:body once"' in resp.text


def test_tactic_counts_from_tag_rows_skips_non_list_tags():
    """A corrupt Finding.tags value that decodes to something other than a JSON array
    (e.g. an object) must be skipped, not raise and 500 the Overview roll-up."""
    from app.routers.cases import _tactic_counts_from_tag_rows

    rows = [
        ('{"not": "a list"}', 3),  # corrupt: valid JSON, but not an array
        ('["attack.initial_access"]', 2),
    ]
    counts = _tactic_counts_from_tag_rows(rows)
    assert counts == {"initial_access": 2}


# ── findings roll-up (Overview tab) ──────────────────────────────────────────────


async def test_summary_partial_totals_findings_across_case_jobs(test_client, async_db, cases_data):
    await _login(test_client, "owner@cases.example.com")
    job_pub = cases_data["job_pub"]
    job_priv = cases_data["job_priv"]  # owner's own private job — owner can see both

    await _seed_finding(async_db, job_pub.id, severity=Severity.HIGH, rule_name="Suspicious Logon", count=2, tags=["attack.initial_access"])
    await _seed_finding(async_db, job_priv.id, severity=Severity.CRITICAL, rule_name="Ransomware Behavior", count=1, tags=["attack.impact"])

    create = await test_client.post("/intel/cases", data={"name": "Rollup Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job_pub.id)}, follow_redirects=False)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job_priv.id)}, follow_redirects=False)

    resp = await test_client.get(f"/intel/cases/{case_id}/summary-partial")
    assert resp.status_code == 200
    assert "Suspicious Logon" in resp.text
    assert "Ransomware Behavior" in resp.text
    # Worst severity present (critical, from Ransomware Behavior) drives the suggestion.
    assert "Suggested" in resp.text
    assert "critical" in resp.text.lower()


async def test_summary_partial_empty_case_shows_muted_empty_state(test_client, cases_data):
    await _login(test_client, "owner@cases.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Empty Rollup Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)

    resp = await test_client.get(f"/intel/cases/{case_id}/summary-partial")
    assert resp.status_code == 200
    assert "No findings" in resp.text


async def test_summary_partial_linked_job_with_zero_findings_shows_empty_state(test_client, cases_data):
    """Distinct from the no-jobs-at-all case above: a case WITH a linked job whose task
    results produced no findings must still render the same muted empty state, not error
    out or render a roll-up with nothing in it."""
    await _login(test_client, "owner@cases.example.com")
    job = cases_data["job_pub"]  # no TaskResult/Finding rows seeded for this job
    create = await test_client.post("/intel/cases", data={"name": "Zero Findings Rollup Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)

    resp = await test_client.get(f"/intel/cases/{case_id}/summary-partial")
    assert resp.status_code == 200
    assert "No findings" in resp.text


async def test_summary_partial_excludes_private_job_findings_from_non_owner(test_client, async_db, cases_data):
    """Member A's private job in a shared case: member B's roll-up must not count its
    findings (severity totals or the top-rules table), even though the owner's does."""
    await _login(test_client, "owner@cases.example.com")
    job_pub = cases_data["job_pub"]
    job_priv = cases_data["job_priv"]  # private, owned by "owner"

    await _seed_finding(async_db, job_pub.id, severity=Severity.LOW, rule_name="Public Finding", count=1, tags=[])
    await _seed_finding(async_db, job_priv.id, severity=Severity.CRITICAL, rule_name="Private Finding", count=5, tags=[])

    create = await test_client.post("/intel/cases", data={"name": "Cross Visibility Rollup", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job_pub.id)}, follow_redirects=False)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job_priv.id)}, follow_redirects=False)

    # Owner sees both jobs' findings.
    owner_resp = await test_client.get(f"/intel/cases/{case_id}/summary-partial")
    assert owner_resp.status_code == 200
    assert "Private Finding" in owner_resp.text
    assert "Public Finding" in owner_resp.text
    assert "critical" in owner_resp.text.lower()

    # `other` is a case member (case is shared) but did not submit the private job and
    # is not an admin — its findings must not leak into their roll-up at all.
    await _login(test_client, "other@cases.example.com")
    other_resp = await test_client.get(f"/intel/cases/{case_id}/summary-partial")
    assert other_resp.status_code == 200
    assert "Private Finding" not in other_resp.text
    assert "Public Finding" in other_resp.text
    assert "critical" not in other_resp.text.lower()
