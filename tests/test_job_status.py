"""Integration tests for job listing and detail routes."""

from __future__ import annotations

import pytest

from app.models import AnalysisJob, JobStatus, LogFile, LogType, TaskResult, TaskStatus, WorkflowDef


@pytest.fixture()
async def sample_job(async_db):
    """Create a LogFile + WorkflowDef + AnalysisJob for testing."""
    wf = WorkflowDef(
        name="Test WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks: []",
        is_default=True,
    )
    async_db.add(wf)
    await async_db.flush()

    lf = LogFile(
        original_filename="sample.evtx",
        stored_filename="abc123_sample.evtx",
        sha256="a" * 64,
        size_bytes=1024,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()

    job = AnalysisJob(submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)
    return job


@pytest.fixture()
async def failed_job_with_error_details(async_db):
    """Terminal failed job with job- and task-level error strings (for visibility tests)."""
    wf = WorkflowDef(
        name="Err WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks: []",
        is_default=False,
    )
    async_db.add(wf)
    await async_db.flush()

    lf = LogFile(
        original_filename="bad.evtx",
        stored_filename="xyz_bad.evtx",
        sha256="b" * 64,
        size_bytes=512,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()

    job = AnalysisJob(
        submitted_filename=lf.original_filename,
        effective_log_type=lf.log_type,
        file_id=lf.id,
        workflow_id=wf.id,
        status=JobStatus.FAILED,
        error_message="SECRET_JOB_ERR_XYZ",
    )
    async_db.add(job)
    await async_db.flush()

    tr = TaskResult(
        job_id=job.id,
        tool_name="zircolite",
        status=TaskStatus.FAILED,
        findings_count=0,
        error_message="SECRET_TOOL_ERR_XYZ",
        log_output="LEAK_STDERR_XYZ",
    )
    async_db.add(tr)
    await async_db.commit()
    await async_db.refresh(job)
    return job


async def test_jobs_list_renders(test_client, sample_job):
    """GET /jobs should return 200 with the job in the list."""
    resp = await test_client.get("/jobs")
    assert resp.status_code == 200
    assert "sample.evtx" in resp.text


async def test_job_detail_renders(test_client, sample_job):
    """GET /jobs/{id} should return 200 with job details."""
    resp = await test_client.get(f"/jobs/{sample_job.id}")
    assert resp.status_code == 200
    assert "sample.evtx" in resp.text


async def test_job_404_nonexistent(test_client):
    """GET /jobs/999999 should return 404."""
    resp = await test_client.get("/jobs/999999")
    assert resp.status_code == 404


async def test_job_status_partial_htmx(test_client, sample_job):
    """GET /jobs/{id}/status-partial with HX-Request header returns partial HTML."""
    resp = await test_client.get(
        f"/jobs/{sample_job.id}/status-partial",
        headers={"HX-Request": "true"},
    )
    # 200 = still polling, 286 = HTMX stop-polling (terminal job)
    assert resp.status_code in (200, 286)
    assert "job-status-region" in resp.text
    # OOB fragment updates header actions (Analytics / Recalculate) without full page reload
    assert "hx-swap-oob" in resp.text
    assert "job-header-terminal-actions" in resp.text


async def test_job_delete_requires_admin(test_client, sample_job):
    """POST /jobs/{id}/delete without admin auth should fail."""
    resp = await test_client.post(
        f"/jobs/{sample_job.id}/delete",
        follow_redirects=False,
    )
    # Should be 401 (not logged in) or 403 (not admin)
    assert resp.status_code in (401, 403)


async def test_job_status_partial_hides_error_details_for_anonymous(test_client, failed_job_with_error_details):
    """Anonymous users must not see job/task error text or tool log output."""
    jid = failed_job_with_error_details.id
    resp = await test_client.get(f"/jobs/{jid}/status-partial", headers={"HX-Request": "true"})
    assert resp.status_code in (200, 286)
    text = resp.text
    assert "SECRET_JOB_ERR_XYZ" not in text
    assert "SECRET_TOOL_ERR_XYZ" not in text
    assert "LEAK_STDERR_XYZ" not in text
    assert "The analysis did not complete successfully." in text


async def test_job_status_partial_shows_error_details_for_admin(admin_client, failed_job_with_error_details):
    """Admins see full job and task error messages in the status partial."""
    jid = failed_job_with_error_details.id
    resp = await admin_client.get(f"/jobs/{jid}/status-partial", headers={"HX-Request": "true"})
    assert resp.status_code in (200, 286)
    text = resp.text
    assert "SECRET_JOB_ERR_XYZ" in text
    assert "SECRET_TOOL_ERR_XYZ" in text
    assert "LEAK_STDERR_XYZ" in text


# ── Pagination bounds ────────────────────────────────────────────────────────
#
# `?page=0` must not produce `OFFSET -20`. PostgreSQL rejects a negative OFFSET outright
# ("OFFSET must not be negative") — an unauthenticated 500 — while SQLite silently
# treats it as 0, so the failure is invisible in dev and test and only bites in production.


@pytest.mark.parametrize("page", ["0", "-5"])
async def test_jobs_list_clamps_non_positive_page(test_client, sample_job, page):
    resp = await test_client.get("/jobs", params={"page": page})
    assert resp.status_code == 200


@pytest.mark.parametrize("page", ["0", "-5"])
async def test_jobs_table_partial_clamps_non_positive_page(test_client, sample_job, page):
    resp = await test_client.get("/jobs/table-partial", params={"page": page})
    assert resp.status_code == 200


async def test_admin_users_clamps_non_positive_page(admin_client):
    resp = await admin_client.get("/admin/users", params={"page": "0"})
    assert resp.status_code == 200


def test_paginated_routes_clamp_before_computing_offset():
    """A direct check on the arithmetic, since SQLite masks the symptom end-to-end."""
    import inspect

    from app.routers import admin, jobs

    for module, names in ((jobs, ("job_list", "jobs_table_partial")), (admin, ("user_list",))):
        for name in names:
            fn = getattr(module, name)  # not getattr(..., None): a renamed route must fail here
            src = inspect.getsource(fn)
            assert "page = max(1, page)" in src, f"{name} computes an offset from an unclamped page"
