"""Recovery for jobs no worker will ever finish.

Two ways a job gets stranded, and both are swept by the same two callers — the web app
on startup, and an admin via ``POST /admin/recover-stuck-jobs``:

* **RUNNING with a dead worker.** A worker refreshes ``logstotal:heartbeat:job:{id}``
  while it holds a job; if the process dies, that key expires and the job is left
  ``RUNNING`` forever.
* **PENDING whose queued task expired.** ``run_analysis`` is registered with
  ``expires=settings.huey_queue_expiry``, so Huey *discards* a message that no worker
  claimed in time. Nothing then transitions the row and it stays ``PENDING`` forever.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.constants import CANCEL_MSG_DEAD_WORKER, RECOVERY_MSG_EXPIRED
from app.database import utc_now_naive
from app.models import AnalysisJob, JobStatus, TaskResult, TaskStatus

#: Added to ``huey_queue_expiry`` before declaring a PENDING job expired, so the sweep
#: rarely meets a message that is about to be claimed at the boundary; when it does, the
#: conditional writes on both sides decide the winner, never both. A slot-capped
#: job re-enqueues itself but is force-accepted after ``_MAX_DEFERRALS`` (20 x <=8s),
#: which is far inside the 1800s default expiry — so age since ``created_at`` is a safe
#: signal even for a job that has been deferred its maximum number of times.
EXPIRY_GRACE_SECONDS = 60


async def recover_stale_jobs(db: AsyncSession, redis, *, message: str) -> int:
    """Finalize every job no worker will finish. Returns how many were changed.

    Commits once, only when something changed; the caller owns the session.
    """
    stale = await _recover_stale_running(db, redis, message=message)
    expired = await _fail_expired_pending(db)
    if stale or expired:
        await db.commit()
    return stale + expired


async def _recover_stale_running(db: AsyncSession, redis, *, message: str) -> int:
    """Fail RUNNING jobs whose worker heartbeat has expired.

    A job whose cancel flag is still set was cancelled while its worker was dying, so it
    is finalized as CANCELLED rather than FAILED — the user's request still stands.
    """
    from fastapi.concurrency import run_in_threadpool

    from app.redis_client import CANCEL_PREFIX, HEARTBEAT_PREFIX, cancel_flag_is_for, cancel_flag_value

    running = (await db.execute(select(AnalysisJob).where(AnalysisJob.status == JobStatus.RUNNING))).scalars().all()
    if not running:
        return 0

    # `redis` is the **sync** client — every `exists()` is a blocking round trip, and this
    # ran one per RUNNING job directly on the event loop. On the startup sweep that is
    # before the app serves anything, but `POST /admin/recover-stuck-jobs` is a live
    # request: a fleet stall leaves hundreds of RUNNING jobs, and the admin clicking
    # Recover then stalled every other request for hundreds of round trips. Pipelined into
    # one threadpool hop and two round trips.
    # Plain strings before the threadpool hop, so the closure touches no ORM instance.
    identities = {job.id: cancel_flag_value(job) for job in running}

    def _probe() -> tuple[set[int], set[int]]:
        ids = list(identities)
        pipe = redis.pipeline()
        for jid in ids:
            pipe.exists(f"{HEARTBEAT_PREFIX}{jid}")
        alive = {jid for jid, present in zip(ids, pipe.execute(), strict=True) if present}

        stale_ids = [jid for jid in ids if jid not in alive]
        if not stale_ids:
            return set(), set()
        pipe = redis.pipeline()
        for jid in stale_ids:
            pipe.get(f"{CANCEL_PREFIX}{jid}")
        return set(stale_ids), {jid for jid, value in zip(stale_ids, pipe.execute(), strict=True) if cancel_flag_is_for(value, identities[jid])}

    stale_ids, cancelling_ids = await run_in_threadpool(_probe)
    stale = [job for job in running if job.id in stale_ids]
    if not stale:
        return 0

    now = utc_now_naive()

    # Conditional on the row still being RUNNING: the SELECT above is a snapshot, and the
    # worker it judged dead may have finished — or cancelled — the job since. Overwriting
    # that terminal status would put the job back in a state the user already saw it leave.
    changed: list[int] = []
    for job in stale:
        was_cancelling = job.id in cancelling_ids
        result = await db.execute(
            update(AnalysisJob)
            .where(AnalysisJob.id == job.id, AnalysisJob.status == JobStatus.RUNNING)
            .values(
                status=JobStatus.CANCELLED if was_cancelling else JobStatus.FAILED,
                error_message=CANCEL_MSG_DEAD_WORKER if was_cancelling else message,
                finished_at=now,
            )
        )
        if result.rowcount == 1:
            changed.append(job.id)
    if not changed:
        return 0

    # One query for every recovered job's tasks, not one per job.
    task_results = (
        await db.execute(
            select(TaskResult).where(
                TaskResult.job_id.in_(changed),
                TaskResult.status.in_([TaskStatus.PENDING, TaskStatus.RUNNING]),
            )
        )
    ).scalars()
    for tr in task_results:
        was_cancelling = tr.job_id in cancelling_ids
        tr.status = TaskStatus.CANCELLED if was_cancelling else TaskStatus.FAILED
        tr.error_message = CANCEL_MSG_DEAD_WORKER if was_cancelling else message
        tr.finished_at = now

    return len(changed)


async def _fail_expired_pending(db: AsyncSession) -> int:
    """Fail PENDING jobs whose queued Huey message has expired unclaimed.

    No ``TaskResult`` sweep is needed here: ``run_analysis`` flips the job to RUNNING
    before it creates any, so a job still PENDING provably has none.
    """
    expiry = settings.huey_queue_expiry
    if not expiry:
        return 0

    cutoff = utc_now_naive() - timedelta(seconds=expiry + EXPIRY_GRACE_SECONDS)
    # One statement, so "still PENDING" is checked at write time: a worker that claimed
    # the job after a SELECT here would otherwise have its RUNNING row failed underneath it.
    result = await db.execute(
        update(AnalysisJob)
        .where(AnalysisJob.status == JobStatus.PENDING, AnalysisJob.created_at < cutoff)
        .values(status=JobStatus.FAILED, error_message=RECOVERY_MSG_EXPIRED, finished_at=utc_now_naive())
    )
    return result.rowcount or 0
