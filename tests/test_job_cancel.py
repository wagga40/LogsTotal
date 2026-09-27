"""Integration tests for POST /jobs/{id}/cancel and the cancelled job status."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.constants import CANCEL_MSG_DEAD_WORKER, CANCEL_MSG_USER
from app.models import AnalysisJob, JobStatus, LogFile, LogType, TaskResult, TaskStatus, WorkflowDef
from app.redis_client import CANCEL_PREFIX, HEARTBEAT_PREFIX


@pytest.fixture()
async def make_job(async_db):
    """Factory: create a LogFile + WorkflowDef + AnalysisJob with given status/owner."""
    wf = WorkflowDef(
        name="Cancel WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks: []",
        is_default=True,
    )
    async_db.add(wf)
    await async_db.flush()

    lf = LogFile(
        original_filename="cancelme.evtx",
        stored_filename="abc_cancelme.evtx",
        sha256="c" * 64,
        size_bytes=1024,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()

    async def _make(status=JobStatus.PENDING, owner_id=None, with_running_task=False):
        job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=status, submitted_by_user_id=owner_id)
        async_db.add(job)
        await async_db.flush()
        if with_running_task:
            tr = TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.RUNNING, findings_count=0)
            async_db.add(tr)
        await async_db.commit()
        await async_db.refresh(job)
        return job

    return _make


async def test_cancel_requires_auth(test_client, make_job):
    job = await make_job()
    resp = await test_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 401


async def test_admin_cancels_pending_job(admin_client, fake_redis, async_db, make_job):
    job = await make_job(status=JobStatus.PENDING)
    resp = await admin_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 303
    await async_db.refresh(job)
    assert job.status == JobStatus.CANCELLED
    assert job.error_message == CANCEL_MSG_USER
    assert job.finished_at is not None
    assert fake_redis.exists(f"{CANCEL_PREFIX}{job.id}")


async def test_the_cancel_flag_names_the_job_it_was_set_for(admin_client, fake_redis, async_db, make_job):
    """Ids are reused on SQLite, so a bare "cancel job N" outlives the job it meant."""
    from app.redis_client import cancel_flag_value

    job = await make_job(status=JobStatus.PENDING)
    await admin_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert fake_redis.get(f"{CANCEL_PREFIX}{job.id}") == cancel_flag_value(job)


async def test_deleting_a_job_forgets_every_redis_key_addressed_by_its_id(admin_client, fake_redis, async_db, make_job):
    """The next upload can be given this id. A cached process tree or timeline left behind
    is then served as the new job's — to anyone who can see the new job, which may be public
    while the deleted one was private."""
    from app.intel.process_tree import _cache_key
    from app.redis_client import JOB_DEFER_PREFIX, QUEUE_POSITION_PREFIX, RECALC_PREFIX, TIMELINE_BUCKETS_PREFIX

    job = await make_job(status=JobStatus.COMPLETED)
    keys = [
        _cache_key(job.id),
        f"{TIMELINE_BUCKETS_PREFIX}{job.id}",
        f"{RECALC_PREFIX}{job.id}",
        f"{JOB_DEFER_PREFIX}{job.id}",
        f"{QUEUE_POSITION_PREFIX}{job.id}",
        f"{CANCEL_PREFIX}{job.id}",
    ]
    for key in keys:
        fake_redis.set(key, "stale", ex=600)

    resp = await admin_client.post(f"/jobs/{job.id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert [k for k in keys if fake_redis.exists(k)] == []


async def test_deleting_a_live_job_keeps_the_flag_its_worker_needs(admin_client, fake_redis, async_db, make_job):
    from app.redis_client import cancel_flag_value

    job = await make_job(status=JobStatus.RUNNING)
    expected = cancel_flag_value(job)
    await admin_client.post(f"/jobs/{job.id}/delete", follow_redirects=False)
    assert fake_redis.get(f"{CANCEL_PREFIX}{job.id}") == expected


async def test_owner_cancels_running_job_dead_worker(user_client, regular_user, fake_redis, async_db, make_job):
    """RUNNING job with no heartbeat → cancelled immediately, task results flipped."""
    job = await make_job(status=JobStatus.RUNNING, owner_id=regular_user.id, with_running_task=True)
    resp = await user_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 303
    await async_db.refresh(job)
    assert job.status == JobStatus.CANCELLED
    assert job.error_message == CANCEL_MSG_DEAD_WORKER
    trs = (await async_db.execute(select(TaskResult).where(TaskResult.job_id == job.id))).scalars().all()
    assert all(tr.status == TaskStatus.CANCELLED for tr in trs)


async def test_owner_cancel_running_live_worker_sets_flag_only(user_client, regular_user, fake_redis, async_db, make_job):
    """RUNNING job with a live heartbeat → flag set, worker finalizes (job untouched here)."""
    job = await make_job(status=JobStatus.RUNNING, owner_id=regular_user.id)
    fake_redis.set(f"{HEARTBEAT_PREFIX}{job.id}", "host:1:2", ex=60)
    resp = await user_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 303
    await async_db.refresh(job)
    assert job.status == JobStatus.RUNNING
    assert fake_redis.exists(f"{CANCEL_PREFIX}{job.id}")


async def test_non_owner_cannot_cancel(user_client, admin_user, make_job):
    job = await make_job(status=JobStatus.RUNNING, owner_id=admin_user.id)
    resp = await user_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 403


async def test_anonymous_submission_needs_admin(user_client, make_job):
    """Jobs with no submitter are admin-cancel-only."""
    job = await make_job(status=JobStatus.RUNNING, owner_id=None)
    resp = await user_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 403


async def test_cancel_terminal_job_is_noop(admin_client, fake_redis, async_db, make_job):
    job = await make_job(status=JobStatus.COMPLETED)
    resp = await admin_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 303
    await async_db.refresh(job)
    assert job.status == JobStatus.COMPLETED
    assert not fake_redis.exists(f"{CANCEL_PREFIX}{job.id}")


async def test_cancel_missing_job_404(admin_client):
    resp = await admin_client.post("/jobs/999999/cancel", follow_redirects=False)
    assert resp.status_code == 404


async def test_status_partial_cancelled_stops_polling(test_client, make_job):
    """A cancelled job is terminal: HTTP 286 stops the HTMX poll, badge renders."""
    job = await make_job(status=JobStatus.CANCELLED)
    resp = await test_client.get(f"/jobs/{job.id}/status-partial", headers={"HX-Request": "true"})
    assert resp.status_code == 286
    assert "Cancelled" in resp.text


async def test_analytics_partial_shows_skipped_for_cancelled(test_client, async_db, make_job):
    """Cancelled job with kept findings: static 'skipped' card, no infinite poll."""
    job = await make_job(status=JobStatus.CANCELLED)
    job.severity_summary = '{"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0}'
    await async_db.commit()
    resp = await test_client.get(f"/jobs/{job.id}/analytics")
    assert resp.status_code == 200
    assert "cancelled" in resp.text.lower()
    assert "every 3s" not in resp.text


async def test_cancel_button_shown_to_admin_on_running_job(admin_client, make_job):
    job = await make_job(status=JobStatus.RUNNING)
    resp = await admin_client.get(f"/jobs/{job.id}")
    assert resp.status_code == 200
    assert f"/jobs/{job.id}/cancel" in resp.text


async def test_cancel_button_hidden_from_anonymous(test_client, make_job):
    job = await make_job(status=JobStatus.RUNNING)
    resp = await test_client.get(f"/jobs/{job.id}")
    assert resp.status_code == 200
    assert f"/jobs/{job.id}/cancel" not in resp.text


async def test_recalculate_shows_progress_spinner(admin_client, fake_redis, make_job, monkeypatch):
    """Recalculate marks the job in-flight so the analytics panel polls instead
    of silently showing stale (or 'skipped') content until a manual refresh."""
    from app.redis_client import RECALC_PREFIX

    monkeypatch.setattr("app.workers.tasks.recalculate_single_analytics", lambda job_id, bg_task_id=None: None)
    job = await make_job(status=JobStatus.CANCELLED)
    resp = await admin_client.post(f"/jobs/{job.id}/recalculate-analytics", follow_redirects=False)
    assert resp.status_code == 303
    assert fake_redis.exists(f"{RECALC_PREFIX}{job.id}")
    resp = await admin_client.get(f"/jobs/{job.id}/analytics")
    assert resp.status_code == 200
    assert "Computing analytics" in resp.text
    assert "every 3s" in resp.text


# ── Redis unreachable ────────────────────────────────────────────────────────
#
# "No heartbeat" and "cannot read the heartbeat" are different facts. The route used
# to treat them alike, so with Redis down it declared a live worker dead and wrote
# CANCELLED — and the worker, which never saw a cancel flag (setting it had failed
# too), carried on and overwrote the row with its own result.


@pytest.fixture()
def redis_down(monkeypatch):
    import app.redis_client as rc

    def _boom():
        raise ConnectionError("Redis is unreachable")

    monkeypatch.setattr(rc, "get_redis", _boom)


async def test_cancel_running_job_refuses_when_redis_is_down(user_client, regular_user, async_db, make_job, redis_down):
    job = await make_job(status=JobStatus.RUNNING, owner_id=regular_user.id, with_running_task=True)
    resp = await user_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 503
    await async_db.refresh(job)
    assert job.status == JobStatus.RUNNING, "must not claim a live worker is dead"


async def test_cancel_pending_job_still_works_when_redis_is_down(user_client, regular_user, async_db, make_job, redis_down):
    """The DB row is authoritative for a queued job: the worker drops any terminal
    status at pickup, so cancelling without the flag is still correct."""
    job = await make_job(status=JobStatus.PENDING, owner_id=regular_user.id)
    resp = await user_client.post(f"/jobs/{job.id}/cancel", follow_redirects=False)
    assert resp.status_code == 303
    await async_db.refresh(job)
    assert job.status == JobStatus.CANCELLED


async def test_recalculate_hands_the_worker_the_row_it_must_close(admin_client, async_db, make_job, monkeypatch):
    """The route writes a PENDING BackgroundTask so the run shows on /admin/tasks. The task
    never learned its id, so every recalculation stayed "pending" — then was offered for
    recovery, and recovering marked a successful run FAILED."""
    from app.models import BackgroundTask

    calls: list[tuple] = []
    monkeypatch.setattr("app.workers.tasks.recalculate_single_analytics", lambda *a, **k: calls.append((a, k)))
    job = await make_job(status=JobStatus.COMPLETED)

    await admin_client.post(f"/jobs/{job.id}/recalculate-analytics", follow_redirects=False)

    row = (await async_db.execute(select(BackgroundTask))).scalars().one()
    assert calls == [((job.id,), {"bg_task_id": row.id})]
