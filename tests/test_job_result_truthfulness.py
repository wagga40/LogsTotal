"""The job page must not present an incomplete or stalled analysis as a finished one.

Three ways it can mislead:

* a failed tool that shows its reason to admins only, so everyone else sees a red glyph
  and "0 rules matched" — indistinguishable from a clean run;
* an ETA that never renders (an aware-minus-naive ``TypeError`` swallowed by a bare
  ``except``), so a queued job gives no progress signal;
* a workflow that declares limited detection coverage saying so in the upload dropdown
  but nowhere on the results page, where the low finding count actually appears.
"""

from __future__ import annotations

import pytest

from app.models import AnalysisJob, JobStatus, LogFile, LogType, TaskResult, TaskStatus, WorkflowDef
from app.redis_client import AVG_DURATION_PREFIX

TOOL_ERROR = "zircolite exited 1: rules file unreadable"
WORKFLOW_CAVEAT = "LIMITED coverage — most rules do not fire on this format"


@pytest.fixture()
async def failing_job(async_db):
    wf = WorkflowDef(name="Truth WF", description=WORKFLOW_CAVEAT, log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()
    lf = LogFile(
        original_filename="truth.evtx",
        stored_filename="truth_abc.evtx",
        sha256="1" * 64,
        size_bytes=1024,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PARTIAL)
    async_db.add(job)
    await async_db.flush()
    async_db.add(TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.FAILED, findings_count=0, error_message=TOOL_ERROR))
    await async_db.commit()
    return job


# ── A failed tool must be legible to the people who submitted the file ───────


async def test_anonymous_viewer_is_told_results_are_incomplete(test_client, failing_job):
    resp = await test_client.get(f"/jobs/{failing_job.id}/status-partial")
    assert resp.status_code == 286  # terminal — HTMX stops polling
    assert "findings below are incomplete" in resp.text


async def test_anonymous_viewer_still_does_not_see_tool_internals(test_client, failing_job):
    """The reason can carry paths and command lines — that stays admin-only."""
    resp = await test_client.get(f"/jobs/{failing_job.id}/status-partial")
    assert TOOL_ERROR not in resp.text


async def test_admin_sees_the_actual_error_not_the_generic_line(admin_client, failing_job):
    resp = await admin_client.get(f"/jobs/{failing_job.id}/status-partial")
    assert TOOL_ERROR in resp.text
    assert "findings below are incomplete" not in resp.text


# ── ETA ──────────────────────────────────────────────────────────────────────


async def test_eta_renders_for_a_running_job(test_client, async_db, fake_redis, failing_job):
    """A broken ETA fails silently and renders nothing, so it needs its own assertion."""
    failing_job.status = JobStatus.RUNNING
    await async_db.commit()
    fake_redis.set(f"{AVG_DURATION_PREFIX}{failing_job.workflow_id}", "600")

    resp = await test_client.get(f"/jobs/{failing_job.id}/status-partial")
    assert resp.status_code == 200
    assert "Estimated:" in resp.text


async def test_no_eta_without_a_recorded_average(test_client, async_db, failing_job):
    failing_job.status = JobStatus.RUNNING
    await async_db.commit()
    resp = await test_client.get(f"/jobs/{failing_job.id}/status-partial")
    assert "Estimated:" not in resp.text


# ── Workflow coverage caveat ─────────────────────────────────────────────────


async def test_job_page_shows_the_workflow_description(test_client, failing_job):
    """A workflow's declared coverage limits belong beside its results, not only on upload."""
    resp = await test_client.get(f"/jobs/{failing_job.id}")
    assert resp.status_code == 200
    assert WORKFLOW_CAVEAT in resp.text


# ── Zero findings is only "clean" when every tool actually ran ───────────────


@pytest.mark.parametrize("status", [JobStatus.FAILED, JobStatus.PARTIAL])
async def test_a_run_whose_tools_failed_is_not_reported_as_clean(test_client, async_db, failing_job, status):
    """The green "No threats detected — All tools completed with 0 rules matched" is the one
    verdict an analyst acts on without reading further. A job whose tools never ran (binary
    missing, timeout, Docker down) must not wear it."""
    failing_job.status = status
    failing_job.score_ratio = "0/1"
    failing_job.total_findings = 0
    await async_db.commit()

    body = (await test_client.get(f"/jobs/{failing_job.id}/status-partial")).text
    assert "No threats detected" not in body
    assert "All tools completed" not in body
    assert "border-l-green-500" not in body


async def test_a_completed_run_with_no_findings_is_still_reported_as_clean(test_client, async_db, failing_job):
    failing_job.status = JobStatus.COMPLETED
    failing_job.score_ratio = "0/1"
    failing_job.total_findings = 0
    await async_db.commit()
    body = (await test_client.get(f"/jobs/{failing_job.id}/status-partial")).text
    assert "No threats detected" in body


@pytest.mark.parametrize("view", ["compact", "roomy"])
async def test_the_jobs_list_does_not_colour_a_failed_zero_green(test_client, async_db, failing_job, view):
    failing_job.status = JobStatus.FAILED
    failing_job.score_ratio = "0/1"
    failing_job.total_findings = 0
    await async_db.commit()
    body = (await test_client.get(f"/jobs?view={view}")).text
    import re

    cell = re.search(r'class="([^"]*)"[^>]*>\s*0/1\s*<', body)
    assert cell, "the score cell renders"
    assert "text-green-400" not in cell.group(1)
