"""Route tests for the cases-list triage aggregates and sorting.

Covers: `app/routers/cases.py::cases_list`'s derived-severity/findings-count aggregates
(and their privacy filtering via `visible_job_filter`), the `sort` query param's five
branches, and that sorting preserves the existing `status`/`q` filter state. Pure-function
sort/aggregate coverage (incl. None-handling) lives in
`tests/test_intel_cases.py::TestBuildCaseListRows`.
"""

from __future__ import annotations

import re
from datetime import datetime

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
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


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


def _case_id_from_redirect(resp) -> int:
    return int(resp.headers["location"].rstrip("/").split("/")[-1])


async def _seed_finding(async_db, job_id: int, *, severity, rule_name: str, count: int = 1) -> Finding:
    tr = TaskResult(job_id=job_id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=1)
    async_db.add(tr)
    await async_db.flush()
    finding = Finding(task_result_id=tr.id, rule_id=rule_name.lower().replace(" ", "-"), rule_name=rule_name, severity=severity, count=count, tags="[]")
    async_db.add(finding)
    await async_db.commit()
    await async_db.refresh(finding)
    return finding


@pytest.fixture()
async def list_data(async_db):
    """owner + other members, a public job and owner's private job — base fixture for the
    cases-list triage/privacy tests."""
    wf = WorkflowDef(name="List WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()

    owner = await _create_user(async_db, email="owner@caselist.example.com")
    other = await _create_user(async_db, email="other@caselist.example.com")

    lf_pub = LogFile(original_filename="pub.evtx", stored_filename="pub_list.evtx", sha256="1" * 64, size_bytes=10, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    lf_priv = LogFile(original_filename="priv.evtx", stored_filename="priv_list.evtx", sha256="2" * 64, size_bytes=10, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([lf_pub, lf_priv])
    await async_db.flush()

    job_pub = AnalysisJob(file_id=lf_pub.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=owner.id, is_private=False)
    job_priv = AnalysisJob(file_id=lf_priv.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=owner.id, is_private=True)
    async_db.add_all([job_pub, job_priv])
    await async_db.commit()
    for obj in (owner, other, job_pub, job_priv, wf):
        await async_db.refresh(obj)
    return {"owner": owner, "other": other, "job_pub": job_pub, "job_priv": job_priv, "wf": wf}


# ── derived severity chip / findings count ──────────────────────────────────────


async def test_derived_chip_and_findings_count_shown_for_case_with_findings(test_client, async_db, list_data):
    await _login(test_client, "owner@caselist.example.com")
    job = list_data["job_pub"]
    await _seed_finding(async_db, job.id, severity=Severity.HIGH, rule_name="Suspicious Logon", count=3)

    create = await test_client.post("/intel/cases", data={"name": "Chip Case"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)

    resp = await test_client.get("/intel/cases")
    assert resp.status_code == 200
    assert "1 finding" in resp.text
    # Precise check of the derived-severity chip's own content — a bare "high" substring
    # check would false-positive against base.html's `--severity-high-*` CSS var names.
    assert re.search(r"title=\"Derived from findings across this case's jobs\">\s*high\s*</span>", resp.text)


async def test_no_chip_or_findings_count_for_empty_case(test_client, list_data):
    await _login(test_client, "owner@caselist.example.com")
    await test_client.post("/intel/cases", data={"name": "Empty Case"}, follow_redirects=False)

    resp = await test_client.get("/intel/cases")
    assert resp.status_code == 200
    assert "Derived from findings across this case" not in resp.text
    # The "N finding(s)" count span never renders for an empty case (the sort dropdown's
    # "Sort: Findings" option/value would false-positive on a plain substring check).
    assert not re.search(r">\d+ findings?<", resp.text)


# ── privacy: private-job findings excluded from non-owner aggregates ────────────


async def test_private_job_findings_excluded_from_non_owner_list_aggregates(test_client, async_db, list_data):
    """owner's private job (with a critical finding) linked into a SHARED case: `other`
    (a case member who did not submit that job) must see no derived severity/findings
    count contributed by it; the owner sees them."""
    await _login(test_client, "owner@caselist.example.com")
    job_priv = list_data["job_priv"]
    await _seed_finding(async_db, job_priv.id, severity=Severity.CRITICAL, rule_name="Ransomware Behavior", count=1)

    create = await test_client.post("/intel/cases", data={"name": "Cross Vis List Case", "is_shared": "1"}, follow_redirects=False)
    case_id = _case_id_from_redirect(create)
    await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job_priv.id)}, follow_redirects=False)

    owner_resp = await test_client.get("/intel/cases")
    assert owner_resp.status_code == 200
    assert "1 finding" in owner_resp.text
    # The derived-severity chip title only renders inside `{% if row.derived_severity %}` —
    # a much more precise marker than the word "critical", which also appears unconditionally
    # in the "New case" dialog's severity <select>.
    assert "Derived from findings across this case's jobs" in owner_resp.text

    await _login(test_client, "other@caselist.example.com")
    other_resp = await test_client.get("/intel/cases")
    assert other_resp.status_code == 200
    assert not re.search(r">\d+ findings?<", other_resp.text)
    assert "Derived from findings across this case's jobs" not in other_resp.text


# ── sorting ──────────────────────────────────────────────────────────────────────


async def test_sort_findings_orders_by_count_desc(test_client, async_db, list_data):
    await _login(test_client, "owner@caselist.example.com")
    job = list_data["job_pub"]
    await _seed_finding(async_db, job.id, severity=Severity.LOW, rule_name="Rule One")
    await _seed_finding(async_db, job.id, severity=Severity.LOW, rule_name="Rule Two")
    await _seed_finding(async_db, job.id, severity=Severity.LOW, rule_name="Rule Three")

    high_create = await test_client.post("/intel/cases", data={"name": "High Count Case"}, follow_redirects=False)
    high_id = _case_id_from_redirect(high_create)
    await test_client.post(f"/intel/cases/{high_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)

    await test_client.post("/intel/cases", data={"name": "Low Count Case"}, follow_redirects=False)

    resp = await test_client.get("/intel/cases", params={"sort": "findings"})
    assert resp.status_code == 200
    body = resp.text
    assert body.index("High Count Case") < body.index("Low Count Case")


async def test_sort_name_case_insensitive(test_client, list_data):
    await _login(test_client, "owner@caselist.example.com")
    await test_client.post("/intel/cases", data={"name": "banana"}, follow_redirects=False)
    await test_client.post("/intel/cases", data={"name": "Apple"}, follow_redirects=False)
    await test_client.post("/intel/cases", data={"name": "cherry"}, follow_redirects=False)

    resp = await test_client.get("/intel/cases", params={"sort": "name"})
    assert resp.status_code == 200
    body = resp.text
    assert body.index("Apple") < body.index("banana") < body.index("cherry")


async def test_sort_severity_worst_first_no_severity_last(test_client, async_db, list_data):
    await _login(test_client, "owner@caselist.example.com")
    job = list_data["job_pub"]
    await _seed_finding(async_db, job.id, severity=Severity.CRITICAL, rule_name="Critical Rule")

    critical_create = await test_client.post("/intel/cases", data={"name": "Critical Derived Case"}, follow_redirects=False)
    critical_id = _case_id_from_redirect(critical_create)
    await test_client.post(f"/intel/cases/{critical_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)

    await test_client.post("/intel/cases", data={"name": "No Findings Case"}, follow_redirects=False)

    resp = await test_client.get("/intel/cases", params={"sort": "severity"})
    assert resp.status_code == 200
    body = resp.text
    assert body.index("Critical Derived Case") < body.index("No Findings Case")


async def test_sort_activity_respects_fresh_link_added_at_over_older_updated_at(test_client, async_db, list_data):
    """A case whose own `updated_at` is stale but which just had a job linked (fresh
    `CaseJobLink.added_at`) must rank above a case with a more recent `updated_at` but no
    recent link activity, when sorting by `activity`."""
    await _login(test_client, "owner@caselist.example.com")
    job = list_data["job_pub"]

    stale_create = await test_client.post("/intel/cases", data={"name": "Stale Case Fresh Link"}, follow_redirects=False)
    stale_id = _case_id_from_redirect(stale_create)
    add_job = await test_client.post(f"/intel/cases/{stale_id}/jobs", data={"job_id": str(job.id)}, follow_redirects=False)
    assert add_job.status_code == 303

    fresher_create = await test_client.post("/intel/cases", data={"name": "Fresher Updated No Link"}, follow_redirects=False)
    fresher_id = _case_id_from_redirect(fresher_create)

    # Push the stale case's own updated_at far into the past (its job link's added_at,
    # set by the POST above, stays "now") and the other case's updated_at to a point that
    # is more recent than the stale case's updated_at but older than the link's added_at.
    stale_case = await async_db.get(InvestigationCase, stale_id)
    stale_case.updated_at = datetime(2020, 1, 1)
    fresher_case = await async_db.get(InvestigationCase, fresher_id)
    fresher_case.updated_at = datetime(2024, 1, 1)
    await async_db.commit()

    resp = await test_client.get("/intel/cases", params={"sort": "activity"})
    assert resp.status_code == 200
    body = resp.text
    assert body.index("Stale Case Fresh Link") < body.index("Fresher Updated No Link")

    # Sanity: the naive query-only ordering (by updated_at alone) would have put the
    # "fresher" case first — confirms the fresh link's added_at is really driving this.
    rows = (await async_db.execute(select(InvestigationCase.name).order_by(InvestigationCase.updated_at.desc()))).scalars().all()
    assert rows[0] == "Fresher Updated No Link"


async def test_invalid_sort_value_falls_back_to_default_order(test_client, list_data):
    await _login(test_client, "owner@caselist.example.com")
    await test_client.post("/intel/cases", data={"name": "First Created"}, follow_redirects=False)
    await test_client.post("/intel/cases", data={"name": "Second Created"}, follow_redirects=False)

    default_resp = await test_client.get("/intel/cases")
    bogus_resp = await test_client.get("/intel/cases", params={"sort": "not-a-real-sort"})
    assert default_resp.status_code == bogus_resp.status_code == 200
    assert default_resp.text == bogus_resp.text


# ── filter state preserved across sorting ───────────────────────────────────────


async def test_filter_state_preserved_when_sorting(test_client, list_data):
    await _login(test_client, "owner@caselist.example.com")
    await test_client.post("/intel/cases", data={"name": "Foo Target"}, follow_redirects=False)
    closed_create = await test_client.post("/intel/cases", data={"name": "Foo Closed"}, follow_redirects=False)
    closed_id = _case_id_from_redirect(closed_create)
    await test_client.post(f"/intel/cases/{closed_id}/status", data={"status": "closed"}, follow_redirects=False)

    resp = await test_client.get("/intel/cases", params={"status": "open", "q": "foo", "sort": "name"})
    assert resp.status_code == 200
    body = resp.text
    assert "Foo Target" in body
    assert "Foo Closed" not in body
    assert 'value="foo"' in body  # q preserved in the text input
    assert '<input type="hidden" name="status" value="open">' in body  # status preserved
    assert '<option value="name" selected' in body  # sort selection preserved
