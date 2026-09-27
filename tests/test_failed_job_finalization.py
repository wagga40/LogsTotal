"""A job that dies part-way must still tell the truth about what it found.

Findings are persisted per tool as each one completes (the progressive-results pattern),
so a job killed in step 3 or 4 has real, committed findings. A `_fail_job` that wrote
`status=FAILED` and nothing else would leave two lies on the page:

* the score card would read `0/0` and `0 findings` directly above a list of real
  detections — in a detection product, "0 findings" reads as *clean*;
* every TaskResult still PENDING/RUNNING would stay that way forever. Nothing revisits
  them: `app/recovery.py` sweeps RUNNING **jobs**, and this job is FAILED — a permanent
  spinner beside a finished job.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

import app.workers.tasks as tasks_mod
from app.json_utils import loads as json_loads
from app.models import AnalysisJob, Finding, JobStatus, LogFile, LogType, TaskResult, TaskStatus, WorkflowDef


@pytest.fixture()
def half_finished_job(sync_db):
    """One tool finished with two findings; a second was still running when the job died."""
    wf = WorkflowDef(name="Half WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    sync_db.add(wf)
    sync_db.flush()
    lf = LogFile(
        original_filename="half.evtx",
        stored_filename="half_abc.evtx",
        sha256="c" * 64,
        size_bytes=512,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    sync_db.add(lf)
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.RUNNING)
    sync_db.add(job)
    sync_db.flush()

    done = TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=2)
    running = TaskResult(job_id=job.id, tool_name="chainsaw", status=TaskStatus.RUNNING)
    pending_post = TaskResult(job_id=job.id, tool_name=tasks_mod.POST_TASK_ANALYTICS, status=TaskStatus.PENDING, findings_count=0)
    sync_db.add_all([done, running, pending_post])
    sync_db.flush()

    sync_db.add_all(
        [
            Finding(task_result_id=done.id, rule_id="R-1", rule_name="Critical thing", severity="critical", count=3, tags="[]", details="[]"),
            Finding(task_result_id=done.id, rule_id="R-2", rule_name="Low thing", severity="low", count=1, tags="[]", details="[]"),
        ]
    )
    sync_db.commit()
    return {"job": job, "done": done, "running": running, "post": pending_post}


def test_failed_job_reports_the_findings_it_actually_committed(sync_db, half_finished_job):
    job = half_finished_job["job"]

    tasks_mod._fail_job(sync_db, job, "worker died")

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job.id)
    assert job.status == JobStatus.FAILED
    assert job.total_findings == 4, "3 + 1 from the tool that finished"
    severity = json_loads(job.severity_summary)
    assert severity["critical"] == 3
    assert severity["low"] == 1
    # One of the two detection tools produced hits; both count as attempted.
    assert job.score_ratio == "1/2"


def test_failed_job_leaves_no_task_result_running(sync_db, half_finished_job):
    job = half_finished_job["job"]

    tasks_mod._fail_job(sync_db, job, "worker died")

    sync_db.expire_all()
    rows = sync_db.execute(select(TaskResult).where(TaskResult.job_id == job.id)).scalars().all()
    assert not [r for r in rows if r.status in (TaskStatus.PENDING, TaskStatus.RUNNING)], "a terminal job must not leave a row polling forever"

    stalled = next(r for r in rows if r.tool_name == "chainsaw")
    assert stalled.status == TaskStatus.FAILED
    assert stalled.finished_at is not None
    assert "worker died" in (stalled.error_message or "")


def test_the_sweep_does_not_touch_rows_that_already_finished(sync_db, half_finished_job):
    """A completed tool keeps its result — the job failing later does not retract it."""
    job = half_finished_job["job"]
    done_id = half_finished_job["done"].id

    tasks_mod._fail_job(sync_db, job, "worker died")

    sync_db.expire_all()
    done = sync_db.get(TaskResult, done_id)
    assert done.status == TaskStatus.COMPLETED
    assert done.findings_count == 2
    assert done.error_message is None


def test_finalize_sweeps_a_tool_the_watchdog_gave_up_on(sync_db, half_finished_job):
    """The parallel loop is bounded by the summed tool timeouts, so an unkillable tool
    reaches finalize with its row untouched."""
    job = half_finished_job["job"]

    tasks_mod._finalize_job(sync_db, job, any_success=True, any_failure=False)

    sync_db.expire_all()
    rows = sync_db.execute(select(TaskResult).where(TaskResult.job_id == job.id)).scalars().all()
    assert not [r for r in rows if r.status in (TaskStatus.PENDING, TaskStatus.RUNNING)]
    assert sync_db.get(AnalysisJob, job.id).total_findings == 4
