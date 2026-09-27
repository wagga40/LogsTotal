"""Route tests for the case attack-timeline tab.

Covers the merged MITRE histogram (per-job Redis bucket cache), the durable key-events
list from ``Finding.details``, the coverage notice math, private-job exclusion, the
job/severity/entity filters, and the recalculate cache-busting.

Raw tool outputs are written under the patched upload dir as ``job_{id}/*_hayabusa.json``
(same approach as tests/test_raw_output_parsing.py). ``tmp_path`` is shared with the
``test_client`` fixture, whose ``upload_dir`` is patched to ``tmp_path / "uploads"``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
    Entity,
    Finding,
    FindingEntityLink,
    JobStatus,
    LogFile,
    LogType,
    Severity,
    TaskResult,
    TaskStatus,
    User,
    WorkflowDef,
)

# ── helpers ──────────────────────────────────────────────────────────────────────


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


def _case_id_from_redirect(resp) -> int:
    return int(resp.headers["location"].rstrip("/").split("/")[-1])


def _uploads_dir(tmp_path: Path) -> Path:
    return Path(tmp_path) / "uploads"


def _write_hayabusa(tmp_path: Path, job_id: int, events: list[dict], filename: str = "out_hayabusa.json") -> Path:
    d = _uploads_dir(tmp_path) / f"job_{job_id}"
    d.mkdir(parents=True, exist_ok=True)
    path = d / filename
    path.write_text("\n".join(json.dumps(e) for e in events))
    return path


def _hb_event(hour: int, rule: str = "Rule A", day: str = "2024-01-05") -> dict:
    return {"Timestamp": f"{day}T{hour:02d}:15:00Z", "RuleTitle": rule}


_SHA_SEQ = iter(range(1000))


async def _add_job(async_db, wf, submitter, *, filename: str, private: bool = False) -> AnalysisJob:
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
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=submitter.id, is_private=private)
    async_db.add(job)
    await async_db.flush()
    return job


async def _seed_finding(async_db, job_id: int, *, severity, rule_name: str, details: list[dict], tags: list[str] | None = None) -> Finding:
    tr = TaskResult(job_id=job_id, tool_name="hayabusa", status=TaskStatus.COMPLETED, findings_count=1)
    async_db.add(tr)
    await async_db.flush()
    f = Finding(
        task_result_id=tr.id,
        rule_id=rule_name.lower().replace(" ", "-"),
        rule_name=rule_name,
        severity=severity,
        count=len(details),
        tags=json.dumps(tags or []),
        details=json.dumps(details),
    )
    async_db.add(f)
    await async_db.flush()
    return f


@pytest.fixture()
async def tl_base(async_db):
    """Workflow + owner + a second member; commit and refresh."""
    wf = WorkflowDef(name="TL WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()
    owner = await _create_user(async_db, email="owner@tl.example.com")
    other = await _create_user(async_db, email="other@tl.example.com")
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


# ── histogram merge across jobs ──────────────────────────────────────────────────


async def test_histogram_merges_buckets_across_two_jobs(test_client, async_db, tmp_path, tl_base):
    owner = tl_base["owner"]
    job_a = await _add_job(async_db, tl_base["wf"], owner, filename="a.evtx")
    job_b = await _add_job(async_db, tl_base["wf"], owner, filename="b.evtx")
    await async_db.commit()
    _write_hayabusa(tmp_path, job_a.id, [_hb_event(10)])
    _write_hayabusa(tmp_path, job_b.id, [_hb_event(20)])

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Merge Case")
    await _link_job(test_client, case_id, job_a.id)
    await _link_job(test_client, case_id, job_b.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial")
    assert resp.status_code == 200
    # Distinct hours from BOTH jobs appear in the merged chart.
    assert "10:00" in resp.text
    assert "20:00" in resp.text
    # Both jobs have raw output → no coverage notice.
    assert "Histogram covers" not in resp.text


# ── cache behaviour ──────────────────────────────────────────────────────────────


async def test_bucket_cache_hit_survives_raw_dir_deletion(test_client, async_db, tmp_path, tl_base, fake_redis):
    owner = tl_base["owner"]
    job = await _add_job(async_db, tl_base["wf"], owner, filename="cache.evtx")
    await async_db.commit()
    _write_hayabusa(tmp_path, job.id, [_hb_event(10)])

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Cache Case")
    await _link_job(test_client, case_id, job.id)

    first = await test_client.get(f"/intel/cases/{case_id}/timeline-partial")
    assert first.status_code == 200
    assert "10:00" in first.text
    # The per-job bucket cache was written.
    cache_key = f"logstotal:jobtlbuckets:{job.id}"
    assert fake_redis.get(cache_key) is not None

    # Delete the raw output dir; the cache (has_raw=True) must keep the chart intact.
    shutil.rmtree(_uploads_dir(tmp_path) / f"job_{job.id}")

    second = await test_client.get(f"/intel/cases/{case_id}/timeline-partial")
    assert second.status_code == 200
    assert "10:00" in second.text  # served from cache, not re-parsed
    assert "Histogram covers" not in second.text  # cached has_raw=True → no coverage notice


# ── retention / coverage notice ──────────────────────────────────────────────────


async def test_partial_coverage_shows_amber_notice(test_client, async_db, tmp_path, tl_base):
    owner = tl_base["owner"]
    job_a = await _add_job(async_db, tl_base["wf"], owner, filename="has_raw.evtx")
    job_b = await _add_job(async_db, tl_base["wf"], owner, filename="no_raw.evtx")
    # Only job_a gets raw output; job_b's raw dir never exists.
    await _seed_finding(async_db, job_b.id, severity=Severity.HIGH, rule_name="Durable Rule", details=[{"Timestamp": "2024-01-05T05:00:00Z", "Computer": "PC1"}])
    await async_db.commit()
    _write_hayabusa(tmp_path, job_a.id, [_hb_event(10)])

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Partial Coverage Case")
    await _link_job(test_client, case_id, job_a.id)
    await _link_job(test_client, case_id, job_b.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial")
    assert resp.status_code == 200
    assert "Histogram covers 1 of 2 job" in resp.text
    assert "10:00" in resp.text  # the covered job's chart still renders
    assert "Durable Rule" in resp.text  # DB-backed key events survive


async def test_all_jobs_missing_raw_still_renders_key_events(test_client, async_db, tmp_path, tl_base):
    owner = tl_base["owner"]
    job = await _add_job(async_db, tl_base["wf"], owner, filename="no_raw_only.evtx")
    await _seed_finding(async_db, job.id, severity=Severity.CRITICAL, rule_name="Ghost Rule", details=[{"Timestamp": "2024-01-05T07:00:00Z", "Computer": "PC2"}])
    await async_db.commit()

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "No Raw Case")
    await _link_job(test_client, case_id, job.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial")
    assert resp.status_code == 200
    assert "Histogram covers 0 of 1 job" in resp.text
    assert "Event Timeline" not in resp.text  # no chart at all
    assert "Ghost Rule" in resp.text  # key events still render
    assert "PC2" in resp.text


# ── private-job exclusion ────────────────────────────────────────────────────────


async def test_private_job_buckets_and_events_hidden_from_non_owner(test_client, async_db, tmp_path, tl_base):
    owner = tl_base["owner"]
    job_pub = await _add_job(async_db, tl_base["wf"], owner, filename="pub.evtx", private=False)
    job_priv = await _add_job(async_db, tl_base["wf"], owner, filename="priv.evtx", private=True)
    await _seed_finding(async_db, job_pub.id, severity=Severity.LOW, rule_name="Public Rule", details=[{"Timestamp": "2024-01-05T10:00:00Z"}])
    await _seed_finding(async_db, job_priv.id, severity=Severity.CRITICAL, rule_name="Private Rule", details=[{"Timestamp": "2024-01-05T20:00:00Z"}])
    await async_db.commit()
    _write_hayabusa(tmp_path, job_pub.id, [_hb_event(10)])
    _write_hayabusa(tmp_path, job_priv.id, [_hb_event(20)])

    # Owner creates a SHARED case containing both jobs.
    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Cross-Visibility TL", shared=True)
    await _link_job(test_client, case_id, job_pub.id)
    await _link_job(test_client, case_id, job_priv.id)

    # Owner sees both jobs' buckets AND both findings' key events.
    owner_resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial")
    assert owner_resp.status_code == 200
    assert "10:00" in owner_resp.text and "20:00" in owner_resp.text
    assert "Public Rule" in owner_resp.text and "Private Rule" in owner_resp.text

    # A non-owner member: the private job's bucket (20:00) AND its key events are absent.
    await _login(test_client, "other@tl.example.com")
    other_resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial")
    assert other_resp.status_code == 200
    assert "10:00" in other_resp.text
    assert "20:00" not in other_resp.text
    assert "Public Rule" in other_resp.text
    assert "Private Rule" not in other_resp.text


# ── filters ──────────────────────────────────────────────────────────────────────


async def test_job_filter_narrows_chart_and_events(test_client, async_db, tmp_path, tl_base):
    owner = tl_base["owner"]
    job_a = await _add_job(async_db, tl_base["wf"], owner, filename="ja.evtx")
    job_b = await _add_job(async_db, tl_base["wf"], owner, filename="jb.evtx")
    await _seed_finding(async_db, job_a.id, severity=Severity.HIGH, rule_name="Rule From A", details=[{"Timestamp": "2024-01-05T10:00:00Z"}])
    await _seed_finding(async_db, job_b.id, severity=Severity.HIGH, rule_name="Rule From B", details=[{"Timestamp": "2024-01-05T20:00:00Z"}])
    await async_db.commit()
    _write_hayabusa(tmp_path, job_a.id, [_hb_event(10)])
    _write_hayabusa(tmp_path, job_b.id, [_hb_event(20)])

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Job Filter Case")
    await _link_job(test_client, case_id, job_a.id)
    await _link_job(test_client, case_id, job_b.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial", params={"job_id": job_a.id})
    assert resp.status_code == 200
    assert "10:00" in resp.text and "20:00" not in resp.text  # chart narrowed
    assert "Rule From A" in resp.text and "Rule From B" not in resp.text  # events narrowed


async def test_job_filter_unknown_or_non_member_404(test_client, async_db, tmp_path, tl_base):
    owner = tl_base["owner"]
    job_a = await _add_job(async_db, tl_base["wf"], owner, filename="member.evtx")
    job_off = await _add_job(async_db, tl_base["wf"], owner, filename="offcase.evtx")  # never linked
    await async_db.commit()

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Job 404 Case")
    await _link_job(test_client, case_id, job_a.id)

    # A job not linked to this case is indistinguishable from a non-existent one.
    resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial", params={"job_id": job_off.id})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Job not found"

    ghost = await test_client.get(f"/intel/cases/{case_id}/timeline-partial", params={"job_id": 999999})
    assert ghost.status_code == 404
    assert ghost.json()["detail"] == "Job not found"


async def test_severity_filter_narrows_events(test_client, async_db, tmp_path, tl_base):
    owner = tl_base["owner"]
    job = await _add_job(async_db, tl_base["wf"], owner, filename="sev.evtx")
    await _seed_finding(async_db, job.id, severity=Severity.CRITICAL, rule_name="Crit Rule", details=[{"Timestamp": "2024-01-05T10:00:00Z"}])
    await _seed_finding(async_db, job.id, severity=Severity.LOW, rule_name="Low Rule", details=[{"Timestamp": "2024-01-05T11:00:00Z"}])
    await async_db.commit()

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Severity Filter Case")
    await _link_job(test_client, case_id, job.id)

    resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial", params={"severity": "critical"})
    assert resp.status_code == 200
    assert "Crit Rule" in resp.text
    assert "Low Rule" not in resp.text

    # An invalid severity is ignored (all events shown).
    both = await test_client.get(f"/intel/cases/{case_id}/timeline-partial", params={"severity": "not-real"})
    assert both.status_code == 200
    assert "Crit Rule" in both.text and "Low Rule" in both.text


async def test_entity_filter_narrows_events_and_non_member_404(test_client, async_db, tmp_path, tl_base):
    owner = tl_base["owner"]
    job = await _add_job(async_db, tl_base["wf"], owner, filename="ent.evtx")
    f_hit = await _seed_finding(async_db, job.id, severity=Severity.HIGH, rule_name="Linked Rule", details=[{"Timestamp": "2024-01-05T10:00:00Z"}])
    await _seed_finding(async_db, job.id, severity=Severity.HIGH, rule_name="Unlinked Rule", details=[{"Timestamp": "2024-01-05T11:00:00Z"}])

    linked_entity = Entity(value="10.1.1.1", entity_type="ip_address", job_count=1)
    off_entity = Entity(value="9.9.9.9", entity_type="ip_address", job_count=1)  # not linked to the case
    async_db.add_all([linked_entity, off_entity])
    await async_db.flush()
    async_db.add(FindingEntityLink(finding_id=f_hit.id, entity_id=linked_entity.id))
    await async_db.commit()

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Entity Filter Case")
    await _link_job(test_client, case_id, job.id)
    # Link the entity to the case so it's an allowed filter target.
    await test_client.post(f"/intel/cases/{case_id}/entities", data={"entity_id": str(linked_entity.id)}, follow_redirects=False)

    resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial", params={"entity_id": linked_entity.id})
    assert resp.status_code == 200
    assert "Linked Rule" in resp.text
    assert "Unlinked Rule" not in resp.text

    # An entity not linked to this case → single 404 message.
    off = await test_client.get(f"/intel/cases/{case_id}/timeline-partial", params={"entity_id": off_entity.id})
    assert off.status_code == 404
    assert off.json()["detail"] == "Entity not found"


async def test_entity_membership_404_short_circuits_before_histogram_work(test_client, async_db, monkeypatch, tl_base):
    """The entity-membership 404 must fire BEFORE the raw-output histogram build — an
    invalid request should never pay for the full parse. Monkeypatch the histogram-path
    entry point to raise if it's ever called, then send a request with an entity_id that
    isn't linked to the case; it must 404 without touching the histogram at all."""
    owner = tl_base["owner"]
    job = await _add_job(async_db, tl_base["wf"], owner, filename="hoist.evtx")
    off_entity = Entity(value="8.8.8.8", entity_type="ip_address", job_count=1)
    async_db.add(off_entity)
    await async_db.flush()
    await async_db.commit()

    await _login(test_client, "owner@tl.example.com")
    case_id = await _new_case(test_client, "Hoist Case")
    await _link_job(test_client, case_id, job.id)

    def _boom(*args, **kwargs):
        raise AssertionError("histogram work must not run before request validation 404s")

    monkeypatch.setattr("app.routers.cases.extract_all_from_raw_output", _boom)

    resp = await test_client.get(f"/intel/cases/{case_id}/timeline-partial", params={"entity_id": off_entity.id})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Entity not found"


# ── recalculate cache invalidation ───────────────────────────────────────────────


async def test_recalculate_deletes_timeline_bucket_cache(admin_client, async_db, fake_redis, monkeypatch, tl_base):
    # Avoid a real Huey enqueue — we only assert the pre-enqueue Redis DEL side-effect.
    monkeypatch.setattr("app.workers.tasks.recalculate_single_analytics", lambda job_id, bg_task_id=None: None)
    job = await _add_job(async_db, tl_base["wf"], tl_base["owner"], filename="recalc.evtx")
    await async_db.commit()

    cache_key = f"logstotal:jobtlbuckets:{job.id}"
    fake_redis.set(cache_key, json.dumps({"buckets": {}, "has_raw": True}))
    assert fake_redis.get(cache_key) is not None

    resp = await admin_client.post(f"/jobs/{job.id}/recalculate-analytics", follow_redirects=False)
    assert resp.status_code == 303
    assert fake_redis.get(cache_key) is None
