"""A PENDING job whose queued Huey task expired must not stay PENDING forever.

``run_analysis`` is registered with ``expires=settings.huey_queue_expiry``, so Huey
discards a message no worker claimed in time. Without this sweep nothing would transition
the row: the job page would poll forever, and ``/admin/recover-stuck-jobs`` looks at
RUNNING jobs.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.config import settings
from app.constants import RECOVERY_MSG_ADMIN, RECOVERY_MSG_EXPIRED
from app.database import utc_now_naive
from app.models import AnalysisJob, JobStatus, LogFile, LogType, TaskResult, TaskStatus, WorkflowDef
from app.recovery import EXPIRY_GRACE_SECONDS, recover_stale_jobs
from app.redis_client import CANCEL_PREFIX, HEARTBEAT_PREFIX, cancel_flag_value


@pytest.fixture()
async def make_pending_job(async_db):
    wf = WorkflowDef(name="Expiry WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()
    lf = LogFile(
        original_filename="queued.evtx",
        stored_filename="exp_queued.evtx",
        sha256="f" * 64,
        size_bytes=1024,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()

    async def _make(age_seconds: float) -> AnalysisJob:
        job = AnalysisJob(
            file_id=lf.id,
            workflow_id=wf.id,
            status=JobStatus.PENDING,
            created_at=utc_now_naive() - timedelta(seconds=age_seconds),
        )
        async_db.add(job)
        await async_db.flush()
        return job

    return _make


def _well_past_expiry() -> float:
    return settings.huey_queue_expiry + EXPIRY_GRACE_SECONDS + 60


async def test_expired_pending_job_is_failed(async_db, fake_redis, make_pending_job):
    job = await make_pending_job(_well_past_expiry())
    await async_db.commit()

    changed = await recover_stale_jobs(async_db, fake_redis, message=RECOVERY_MSG_ADMIN)

    assert changed == 1
    await async_db.refresh(job)
    assert job.status == JobStatus.FAILED
    assert job.error_message == RECOVERY_MSG_EXPIRED
    assert job.finished_at is not None


async def test_fresh_pending_job_is_left_alone(async_db, fake_redis, make_pending_job):
    """A job still inside the expiry window has a live queued task — don't touch it."""
    job = await make_pending_job(10)
    await async_db.commit()

    changed = await recover_stale_jobs(async_db, fake_redis, message=RECOVERY_MSG_ADMIN)

    assert changed == 0
    await async_db.refresh(job)
    assert job.status == JobStatus.PENDING


async def test_job_inside_the_grace_window_is_left_alone(async_db, fake_redis, make_pending_job):
    """Just past expiry but inside the grace margin: a worker may still be claiming it."""
    job = await make_pending_job(settings.huey_queue_expiry + 1)
    await async_db.commit()

    assert await recover_stale_jobs(async_db, fake_redis, message=RECOVERY_MSG_ADMIN) == 0
    await async_db.refresh(job)
    assert job.status == JobStatus.PENDING


async def test_sweep_is_idempotent(async_db, fake_redis, make_pending_job):
    await make_pending_job(_well_past_expiry())
    await async_db.commit()

    assert await recover_stale_jobs(async_db, fake_redis, message=RECOVERY_MSG_ADMIN) == 1
    assert await recover_stale_jobs(async_db, fake_redis, message=RECOVERY_MSG_ADMIN) == 0


async def test_admin_recover_route_clears_expired_pending(admin_client, async_db, make_pending_job):
    """The button the queue-age check points at must actually fix what it diagnoses."""
    job = await make_pending_job(_well_past_expiry())
    await async_db.commit()
    job_id = job.id

    resp = await admin_client.post("/admin/recover-stuck-jobs", follow_redirects=False)
    assert resp.status_code == 303
    assert "recovered=1" in resp.headers["location"]

    async_db.expire_all()
    refreshed = await async_db.get(AnalysisJob, job_id)
    assert refreshed.status == JobStatus.FAILED


async def test_status_partial_stops_polling_once_recovered(test_client, async_db, fake_redis, make_pending_job):
    """The eternal spinner is the user-visible symptom — it must end."""
    job = await make_pending_job(_well_past_expiry())
    await async_db.commit()

    spinning = await test_client.get(f"/jobs/{job.id}/status-partial")
    assert "every 3s" in spinning.text

    await recover_stale_jobs(async_db, fake_redis, message=RECOVERY_MSG_ADMIN)

    settled = await test_client.get(f"/jobs/{job.id}/status-partial")
    assert "every 3s" not in settled.text


@pytest.mark.parametrize("outcome", ["failed", "cancelled", "live"])
async def test_recovery_settles_all_unfinished_tasks_and_preserves_results(async_db, fake_redis, make_pending_job, outcome):
    job = await make_pending_job(10)
    job.status = JobStatus.RUNNING
    finished_at = utc_now_naive() - timedelta(seconds=5)
    done = TaskResult(job_id=job.id, tool_name="finished engine", status=TaskStatus.COMPLETED, findings_count=7, finished_at=finished_at)
    unfinished = [
        TaskResult(job_id=job.id, tool_name=name, status=status)
        for name, status in [("engine", TaskStatus.RUNNING), ("analytics", TaskStatus.PENDING), ("similarity", TaskStatus.PENDING)]
    ]
    async_db.add_all([done, *unfinished])
    await async_db.commit()
    if outcome == "cancelled":
        fake_redis.set(f"{CANCEL_PREFIX}{job.id}", cancel_flag_value(job))
    elif outcome == "live":
        fake_redis.set(f"{HEARTBEAT_PREFIX}{job.id}", "alive")

    changed = await recover_stale_jobs(async_db, fake_redis, message=RECOVERY_MSG_ADMIN)

    assert changed == (0 if outcome == "live" else 1)
    for task in [done, *unfinished]:
        await async_db.refresh(task)
    assert done.status == TaskStatus.COMPLETED
    assert done.findings_count == 7
    assert done.finished_at == finished_at
    if outcome == "live":
        assert job.status == JobStatus.RUNNING
        assert [task.status for task in unfinished] == [TaskStatus.RUNNING, TaskStatus.PENDING, TaskStatus.PENDING]
    else:
        assert job.status.value == outcome
        assert all(task.status.value == outcome and task.finished_at == job.finished_at for task in unfinished)
        assert all(task.error_message == job.error_message for task in unfinished)
    assert await recover_stale_jobs(async_db, fake_redis, message=RECOVERY_MSG_ADMIN) == 0
