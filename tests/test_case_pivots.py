"""Route tests for the case Overview "Pivot suggestions" panel.

Covers the three bounded sections (co-occurring entities, similar files, correlated
findings), the private-job exclusion discipline (a private job of another user
contributes NO suggestions AND is never used as a suggestion source for a non-owner
member), the one-click add contract (`pivot=1` + HX-Request returns the refreshed
partial; a plain POST still 303s), and the co-occurring-entities row cap.

Helper style mirrors tests/test_case_timeline.py (own workflow/user/job fixtures, no
shared conftest fixtures beyond test_client/async_db).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    Finding,
    JobStatus,
    LogFile,
    LogType,
    Severity,
    TaskResult,
    TaskStatus,
    User,
    WorkflowDef,
)

# ── helpers (mirrors tests/test_case_timeline.py) ─────────────────────────────────


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


def _case_id_from_redirect(resp) -> int:
    return int(resp.headers["location"].rstrip("/").split("/")[-1])


_SHA_SEQ = iter(range(100000))


async def _add_job(async_db, wf, submitter, *, filename: str, private: bool = False, created_at: datetime | None = None) -> AnalysisJob:
    n = next(_SHA_SEQ)
    lf = LogFile(
        original_filename=filename,
        stored_filename=f"stored_{n}_{filename}",
        sha256=f"{n:064d}",
        size_bytes=1024,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()
    job_kwargs = {
        "submitted_filename": filename,
        "effective_log_type": lf.log_type,
        "file_id": lf.id,
        "workflow_id": wf.id,
        "status": JobStatus.COMPLETED,
        "submitted_by_user_id": submitter.id,
        "is_private": private,
    }
    if created_at is not None:
        # Explicit value overrides the created_at server_default so recency-ordering
        # tests don't depend on real wall-clock timing / same-second insert ties.
        job_kwargs["created_at"] = created_at
    job = AnalysisJob(**job_kwargs)
    async_db.add(job)
    await async_db.flush()
    return job


async def _seed_finding_with_sig(async_db, job_id: int, sig: str, *, severity, rule_name: str) -> Finding:
    tr = TaskResult(job_id=job_id, tool_name="hayabusa", status=TaskStatus.COMPLETED, findings_count=1)
    async_db.add(tr)
    await async_db.flush()
    f = Finding(task_result_id=tr.id, rule_id=rule_name.lower().replace(" ", "-"), rule_name=rule_name, severity=severity, count=1, rule_signature=sig)
    async_db.add(f)
    await async_db.flush()
    return f


@pytest.fixture()
async def piv_base(async_db):
    """Workflow + owner + a second member; commit and refresh."""
    wf = WorkflowDef(name="Pivot WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()
    owner = await _create_user(async_db, email="owner@piv.example.com")
    other = await _create_user(async_db, email="other@piv.example.com")
    await async_db.commit()
    for obj in (wf, owner, other):
        await async_db.refresh(obj)
    return {"wf": wf, "owner": owner, "other": other}


async def _new_case(client, name: str, *, shared: bool = False) -> int:
    data = {"name": name}
    if shared:
        data["is_shared"] = "1"
    resp = await client.post("/intel/cases", data=data, follow_redirects=False)
    return _case_id_from_redirect(resp)


async def _link_job(client, case_id: int, job_id: int) -> None:
    resp = await client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job_id)}, follow_redirects=False)
    assert resp.status_code == 303, resp.text


# ── Co-occurring entities ─────────────────────────────────────────────────────────


async def test_cooccurring_entity_suggested_excludes_members_and_allowlisted(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job = await _add_job(async_db, piv_base["wf"], owner, filename="member.evtx")
    await async_db.commit()

    e_new = Entity(value="10.1.1.1", entity_type="ip_address")
    e_member = Entity(value="10.1.1.2", entity_type="ip_address")
    e_allow = Entity(value="10.1.1.3", entity_type="ip_address", allowlisted=True)
    async_db.add_all([e_new, e_member, e_allow])
    await async_db.flush()
    async_db.add_all(
        [
            EntityJobLink(entity_id=e_new.id, job_id=job.id, occurrence_count=5),
            EntityJobLink(entity_id=e_member.id, job_id=job.id, occurrence_count=1),
            EntityJobLink(entity_id=e_allow.id, job_id=job.id, occurrence_count=9),
        ]
    )
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Cooccur Case")
    await _link_job(test_client, case_id, job.id)
    await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(e_member.id)}, follow_redirects=False)

    resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert resp.status_code == 200
    assert "10.1.1.1" in resp.text
    assert "10.1.1.2" not in resp.text
    assert "10.1.1.3" not in resp.text


async def test_cooccurring_entities_ordered_by_count_desc(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job = await _add_job(async_db, piv_base["wf"], owner, filename="order.evtx")
    await async_db.commit()
    e_low = Entity(value="20.0.0.1", entity_type="ip_address")
    e_high = Entity(value="20.0.0.2", entity_type="ip_address")
    async_db.add_all([e_low, e_high])
    await async_db.flush()
    async_db.add_all(
        [
            EntityJobLink(entity_id=e_low.id, job_id=job.id, occurrence_count=1),
            EntityJobLink(entity_id=e_high.id, job_id=job.id, occurrence_count=50),
        ]
    )
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Order Case")
    await _link_job(test_client, case_id, job.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert resp.status_code == 200
    assert resp.text.index("20.0.0.2") < resp.text.index("20.0.0.1")


async def test_cooccurring_entities_capped_at_ten(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job = await _add_job(async_db, piv_base["wf"], owner, filename="cap.evtx")
    await async_db.commit()
    entities = []
    for i in range(11):
        e = Entity(value=f"30.0.0.{i}", entity_type="ip_address")
        async_db.add(e)
        entities.append(e)
    await async_db.flush()
    for i, e in enumerate(entities):
        async_db.add(EntityJobLink(entity_id=e.id, job_id=job.id, occurrence_count=11 - i))
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Cap Case")
    await _link_job(test_client, case_id, job.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert resp.status_code == 200
    for i in range(10):
        assert f"30.0.0.{i}" in resp.text
    assert "30.0.0.10" not in resp.text  # lowest occurrence count (1) dropped by the cap


# ── Similar files ──────────────────────────────────────────────────────────────────


async def test_similar_files_probes_hash_bearing_job_even_if_not_among_ten_newest(test_client, async_db, piv_base):
    """The case has 11 visible jobs. The 10 NEWEST all lack a tlsh_hash (compute_tlsh is
    best-effort and can return None); an older, 11th job DOES have one, with a real TLSH
    neighbor outside the case. The similar-files section must still probe that older job
    — filtering to hash-bearing jobs happens BEFORE the recency slice, not after (else the
    10-newest cut would exclude it entirely and this section would render empty)."""
    tlsh = pytest.importorskip("tlsh")
    digest = tlsh.hash(os.urandom(4096))
    if not digest or digest == "TNULL":
        pytest.skip("tlsh backend produced no digest for random data")

    owner = piv_base["owner"]
    base_time = datetime(2026, 1, 1, 0, 0, 0)

    # Oldest job (earliest created_at) — the only one with a tlsh_hash.
    old_job = await _add_job(async_db, piv_base["wf"], owner, filename="old_with_hash.evtx", created_at=base_time)
    await async_db.commit()
    old_lf = await async_db.get(LogFile, old_job.file_id)
    old_lf.tlsh_hash = digest
    await async_db.commit()

    # 10 strictly newer jobs, all WITHOUT a hash — these are "the 10 most recent".
    newer_jobs = []
    for i in range(10):
        j = await _add_job(async_db, piv_base["wf"], owner, filename=f"newer_{i}.evtx", created_at=base_time + timedelta(days=i + 1))
        newer_jobs.append(j)
    await async_db.commit()

    # An outside (non-member) file sharing the digest — the neighbor we expect to surface.
    outside_lf = LogFile(
        original_filename="older_job_neighbor.evtx",
        stored_filename="stored_older_job_neighbor.evtx",
        sha256="e" * 64,
        size_bytes=2048,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
        tlsh_hash=digest,
    )
    async_db.add(outside_lf)
    await async_db.flush()
    outside_job = AnalysisJob(
        submitted_filename=outside_lf.original_filename,
        effective_log_type=outside_lf.log_type,
        file_id=outside_lf.id,
        workflow_id=piv_base["wf"].id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
        is_private=False,
    )
    async_db.add(outside_job)
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Old Hash Case")
    await _link_job(test_client, case_id, old_job.id)
    for j in newer_jobs:
        await _link_job(test_client, case_id, j.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert resp.status_code == 200
    assert "older_job_neighbor.evtx" in resp.text


# ── Correlated findings ────────────────────────────────────────────────────────────


async def test_correlated_outside_job_suggested_member_jobs_excluded(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job_member = await _add_job(async_db, piv_base["wf"], owner, filename="member_correlated.evtx")
    job_member2 = await _add_job(async_db, piv_base["wf"], owner, filename="member_correlated2.evtx")
    job_outside = await _add_job(async_db, piv_base["wf"], owner, filename="outside_correlated.evtx")
    await async_db.commit()
    sig = "sig-corr-1:high"
    await _seed_finding_with_sig(async_db, job_member.id, sig, severity=Severity.HIGH, rule_name="Corr Rule")
    await _seed_finding_with_sig(async_db, job_member2.id, sig, severity=Severity.HIGH, rule_name="Corr Rule")
    await _seed_finding_with_sig(async_db, job_outside.id, sig, severity=Severity.HIGH, rule_name="Corr Rule")
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Correlated Case")
    await _link_job(test_client, case_id, job_member.id)
    await _link_job(test_client, case_id, job_member2.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert resp.status_code == 200
    assert "outside_correlated.evtx" in resp.text
    assert "member_correlated.evtx" not in resp.text
    assert "member_correlated2.evtx" not in resp.text


# ── Privacy: private job never a suggestion or a suggestion source ────────────────


async def test_private_job_entities_hidden_from_non_owner_shown_to_owner(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job_pub = await _add_job(async_db, piv_base["wf"], owner, filename="pub_priv_ent.evtx", private=False)
    job_priv = await _add_job(async_db, piv_base["wf"], owner, filename="priv_priv_ent.evtx", private=True)
    await async_db.commit()
    e_priv_only = Entity(value="60.0.0.1", entity_type="ip_address")
    async_db.add(e_priv_only)
    await async_db.flush()
    async_db.add(EntityJobLink(entity_id=e_priv_only.id, job_id=job_priv.id, occurrence_count=5))
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Private Ent Case", shared=True)
    await _link_job(test_client, case_id, job_pub.id)
    await _link_job(test_client, case_id, job_priv.id)

    owner_resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert owner_resp.status_code == 200
    assert "60.0.0.1" in owner_resp.text

    await _login(test_client, "other@piv.example.com")
    other_resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert other_resp.status_code == 200
    assert "60.0.0.1" not in other_resp.text


async def test_private_job_not_used_as_correlation_source(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job_pub = await _add_job(async_db, piv_base["wf"], owner, filename="pub_priv_corr.evtx", private=False)
    job_priv = await _add_job(async_db, piv_base["wf"], owner, filename="priv_priv_corr.evtx", private=True)
    job_outside = await _add_job(async_db, piv_base["wf"], owner, filename="outside_priv_corr.evtx", private=False)
    await async_db.commit()
    sig = "sig-priv-corr:critical"
    await _seed_finding_with_sig(async_db, job_priv.id, sig, severity=Severity.CRITICAL, rule_name="Priv Corr Rule")
    await _seed_finding_with_sig(async_db, job_outside.id, sig, severity=Severity.CRITICAL, rule_name="Priv Corr Rule")
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Private Corr Case", shared=True)
    await _link_job(test_client, case_id, job_pub.id)
    await _link_job(test_client, case_id, job_priv.id)

    owner_resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert owner_resp.status_code == 200
    assert "outside_priv_corr.evtx" in owner_resp.text

    await _login(test_client, "other@piv.example.com")
    other_resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert other_resp.status_code == 200
    assert "outside_priv_corr.evtx" not in other_resp.text


async def test_private_job_not_used_as_similarity_source(test_client, async_db, piv_base):
    tlsh = pytest.importorskip("tlsh")
    digest = tlsh.hash(os.urandom(4096))
    if not digest or digest == "TNULL":
        pytest.skip("tlsh backend produced no digest for random data")

    owner = piv_base["owner"]
    job_pub = await _add_job(async_db, piv_base["wf"], owner, filename="pub_tlsh_member.evtx", private=False)
    job_priv = await _add_job(async_db, piv_base["wf"], owner, filename="priv_tlsh.evtx", private=True)
    await async_db.commit()

    # An outside (non-member) file with the SAME digest — a TLSH neighbor of job_priv's file.
    outside_lf = LogFile(
        original_filename="outside_tlsh_neighbor.evtx",
        stored_filename="stored_outside_tlsh_neighbor.evtx",
        sha256="f" * 64,
        size_bytes=2048,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
        tlsh_hash=digest,
    )
    async_db.add(outside_lf)
    await async_db.flush()
    outside_job = AnalysisJob(
        submitted_filename=outside_lf.original_filename,
        effective_log_type=outside_lf.log_type,
        file_id=outside_lf.id,
        workflow_id=piv_base["wf"].id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
        is_private=False,
    )
    async_db.add(outside_job)
    await async_db.flush()

    priv_lf = await async_db.get(LogFile, job_priv.file_id)
    priv_lf.tlsh_hash = digest
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Private TLSH Case", shared=True)
    await _link_job(test_client, case_id, job_pub.id)
    await _link_job(test_client, case_id, job_priv.id)

    owner_resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert owner_resp.status_code == 200
    assert "outside_tlsh_neighbor.evtx" in owner_resp.text

    await _login(test_client, "other@piv.example.com")
    other_resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert other_resp.status_code == 200
    assert "outside_tlsh_neighbor.evtx" not in other_resp.text


# ── One-click add ───────────────────────────────────────────────────────────────────


async def test_pivot_add_entity_returns_partial_with_row_gone(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job = await _add_job(async_db, piv_base["wf"], owner, filename="pivotadd.evtx")
    await async_db.commit()
    e = Entity(value="40.0.0.1", entity_type="ip_address")
    async_db.add(e)
    await async_db.flush()
    async_db.add(EntityJobLink(entity_id=e.id, job_id=job.id, occurrence_count=3))
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Pivot Add Case")
    await _link_job(test_client, case_id, job.id)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/entities",
        data={"entity_id": str(e.id), "pivot": "1"},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert 'id="case-pivots"' in resp.text
    assert "40.0.0.1" not in resp.text


async def test_plain_add_entity_without_pivot_still_redirects(test_client, async_db, piv_base):
    e = Entity(value="50.0.0.1", entity_type="ip_address")
    async_db.add(e)
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Plain Add Case")

    resp = await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(e.id)}, follow_redirects=False)
    assert resp.status_code == 303


async def test_pivot_add_job_returns_partial(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job_member = await _add_job(async_db, piv_base["wf"], owner, filename="member_j.evtx")
    job_new = await _add_job(async_db, piv_base["wf"], owner, filename="new_j.evtx")
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Pivot Add Job Case")
    await _link_job(test_client, case_id, job_member.id)

    resp = await test_client.post(
        f"/intel/cases/{case_id}/jobs",
        data={"job_id": str(job_new.id), "pivot": "1"},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert 'id="case-pivots"' in resp.text


async def test_plain_add_job_without_pivot_still_redirects(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job_new = await _add_job(async_db, piv_base["wf"], owner, filename="plain_new_j.evtx")
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Plain Add Job Case")

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(job_new.id)}, follow_redirects=False)
    assert resp.status_code == 303


async def test_pivot_add_with_htmx_header_but_no_pivot_flag_still_redirects(test_client, async_db, piv_base):
    """`pivot` must be explicitly set — an HTMX request without it keeps the normal redirect."""
    e = Entity(value="70.0.0.1", entity_type="ip_address")
    async_db.add(e)
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "HTMX No Pivot Case")

    resp = await test_client.post(
        f"/intel/cases/{case_id}/entities",
        data={"entity_id": str(e.id)},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


# ── Empty state ──────────────────────────────────────────────────────────────────────


async def test_no_suggestions_empty_state(test_client, async_db, piv_base):
    owner = piv_base["owner"]
    job = await _add_job(async_db, piv_base["wf"], owner, filename="empty.evtx")
    await async_db.commit()

    await _login(test_client, "owner@piv.example.com")
    case_id = await _new_case(test_client, "Empty Case")
    await _link_job(test_client, case_id, job.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/pivots-partial")
    assert resp.status_code == 200
    assert "No suggestions" in resp.text
