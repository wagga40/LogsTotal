"""Shared Redis client for heartbeat, queue queries, and rate limiting.

Huey manages its own Redis connection internally; this module provides a
general-purpose client for application-level Redis operations.
"""

from __future__ import annotations

import logging

import redis

from app.config import settings

_log = logging.getLogger(__name__)

_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    """Return a lazily-initialised, thread-safe Redis client."""
    global _client
    if _client is None:
        if settings.redis_url:
            _client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
        else:
            _client = redis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                password=settings.redis_password or None,
                decode_responses=True,
            )
    return _client


HEARTBEAT_PREFIX = "logstotal:heartbeat:job:"
WORKER_ALIVE_PREFIX = "logstotal:worker:alive:"
WORKER_INFO_PREFIX = "logstotal:worker:info:"
# Per-job raw-output histogram bucket cache for the case attack-timeline tab
# (routers/cases.py::case_timeline_partial); invalidated by routers/jobs.py's
# recalculate-analytics endpoint.
TIMELINE_BUCKETS_PREFIX = "logstotal:jobtlbuckets:"


def get_worker_concurrency_meta() -> list[dict]:
    """Per-process host meta published by live workers (WORKER_INFO_PREFIX).

    Returns ``[{hostname, huey_workers, cpu_count}, ...]`` — values may be Redis
    strings; app/concurrency.py coerces. Sync: FastAPI callers must off-load via
    run_in_threadpool. Shared by the admin concurrency card and system checks.
    """
    r = get_redis()
    meta: list[dict] = []
    for key in r.scan_iter(f"{WORKER_INFO_PREFIX}*"):
        info = r.hgetall(key)
        if not info:
            continue
        wid = key.replace(WORKER_INFO_PREFIX, "")
        meta.append(
            {
                "hostname": info.get("hostname") or wid.split(":", 1)[0],
                "huey_workers": info.get("huey_workers", ""),
                "cpu_count": info.get("cpu_count", ""),
            }
        )
    return meta


QUEUE_POSITION_PREFIX = "logstotal:queue_position:"
AVG_DURATION_PREFIX = "logstotal:avg_duration:"
WORKER_SLOTS_PREFIX = "logstotal:worker_slots:"
WORKER_POLICY_PREFIX = "logstotal:worker_policy:"
JOB_DEFER_PREFIX = "logstotal:job_defer:"
# Per-job cancellation flag set by POST /jobs/{id}/cancel; the worker's
# _CancelWatcher polls it and aborts running tools cooperatively.
CANCEL_PREFIX = "logstotal:cancel:job:"
# Cancel flag for one AI analysis run. Keyed by analysis id, not job id: a job can have
# several runs and cancelling one must not touch the others.
AI_CANCEL_PREFIX = "logstotal:cancel:ai:"
# Liveness for one AI run, the HEARTBEAT_PREFIX idea applied per analysis. Without it a
# worker restarted mid-inference would leave the row RUNNING forever. With it, "is anyone
# still working on this?" has an actual answer, which is what lets the cancel route
# finalise a dead run instead of setting a flag no process will ever read.
AI_HEARTBEAT_PREFIX = "logstotal:heartbeat:ai:"
# Per-job "analytics recalculation in flight" marker: set by the recalculate
# endpoint, cleared by the worker — drives the polling spinner on the job page.
RECALC_PREFIX = "logstotal:recalc:job:"

# Cancel flag for one BackgroundTask (a backfill or the output cleanup). Set by the admin
# route *before* the DB write, the POST /jobs/{id}/cancel idiom, and read at each batch
# boundary by the task itself. Deliberately a Redis flag rather than a column: the flag is
# the signal, the row is the record, and duplicating one in the other invites them to
# disagree.
BGTASK_CANCEL_PREFIX = "logstotal:cancel:bgtask:"
# Last run of a periodic task: a small hash of {ts, duration_ms, outcome, detail}, written
# by the task itself. Redis rather than a BackgroundTask row per run, because
# a run is only ever interesting until the next one — a row per run would exist purely to
# give the prune task something to delete. This is an operational fact with a natural
# expiry, exactly like WORKER_INFO_PREFIX.
TASK_LAST_RUN_PREFIX = "logstotal:task_last_run:"
# Long enough to survive a weekend of downtime and still show "last ran Friday".
TASK_LAST_RUN_TTL = 8 * 24 * 3600


def cancel_flag_value(job) -> str:
    """What a job's cancel flag holds: which job it was set for, not merely which id.

    SQLite gives the next insert the id of the newest deleted row, and a flag outlives its
    job by up to a day — deleting a PENDING job sets one. A bare "cancel job N" would then
    cancel the next upload to be given N. `created_at` tells the two jobs apart.
    """
    created = job.created_at.isoformat() if getattr(job, "created_at", None) else ""
    return f"job:{job.id}:{created}"


def cancel_flag_is_for(value, identity: str | None) -> bool:
    """Whether a cancel flag read back from Redis applies to the job `identity` names.

    `identity` is a `cancel_flag_value`; None means "any job with this id". A value that does
    not start with `job:` was written before flags carried an identity (an upgrade in flight),
    and is honoured rather than dropped.
    """
    if value is None:
        return False
    text = value.decode() if isinstance(value, bytes) else str(value)
    return identity is None or not text.startswith("job:") or text == identity


def forget_job_keys(job_id: int, *, keep_cancel_flag: bool = False) -> None:
    """Delete every Redis key addressed by a deleted job's id. Never raises.

    The id goes back into circulation on SQLite, and each of these is read by id alone: a
    cached process tree or timeline would be served as the next job's — to whoever may see
    that job — and a deferral count or queue position would be inherited. The cancel flag is
    kept for a job that was still live, whose worker needs it to stop; it carries the job's
    identity, so the next job with this id ignores it.
    """
    from app.intel.process_tree import _cache_key

    keys = [
        _cache_key(job_id),
        f"{TIMELINE_BUCKETS_PREFIX}{job_id}",
        f"{RECALC_PREFIX}{job_id}",
        f"{JOB_DEFER_PREFIX}{job_id}",
        f"{QUEUE_POSITION_PREFIX}{job_id}",
    ]
    if not keep_cancel_flag:
        keys.append(f"{CANCEL_PREFIX}{job_id}")
    try:
        get_redis().delete(*keys)
    except Exception:
        _log.warning("Could not clear Redis keys for deleted job %s", job_id, exc_info=True)
