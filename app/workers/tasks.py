"""
Huey task definitions.
All DB access here uses the sync SQLAlchemy engine.
"""

from __future__ import annotations

import logging
import shutil
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from huey import crontab

from app.config import settings
from app.constants import (
    CANCEL_MSG_USER,
    EMPTY_SEVERITY_SUMMARY,
    POST_TASK_ANALYTICS,
    POST_TASK_SIMILARITY,
    TERMINAL_AI_STATUSES,
    TERMINAL_JOB_STATUSES,
    is_post_processing_task,
)
from app.database import get_sync_session, utc_now_naive
from app.detection.workflow_runner import parse_workflow_yaml
from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.logging_config import bind as bind_log_context
from app.logging_config import silence_huey_own_handlers
from app.models import AnalysisJob, BackgroundTask, BackgroundTaskStatus, Finding, JobStatus, LogFile, TaskResult, TaskStatus, WorkerPolicy, enum_val
from app.redis_client import (
    AI_CANCEL_PREFIX,
    AI_HEARTBEAT_PREFIX,
    BGTASK_CANCEL_PREFIX,
    CANCEL_PREFIX,
    HEARTBEAT_PREFIX,
    JOB_DEFER_PREFIX,
    QUEUE_POSITION_PREFIX,
    TASK_LAST_RUN_PREFIX,
    TASK_LAST_RUN_TTL,
    WORKER_ALIVE_PREFIX,
    WORKER_INFO_PREFIX,
    WORKER_POLICY_PREFIX,
    WORKER_SLOTS_PREFIX,
    cancel_flag_is_for,
    cancel_flag_value,
    forget_job_keys,
    get_redis,
)
from app.site_settings import get_site_settings_sync
from app.storage import job_outputs_dir
from app.tools.base import CANCELLED_ERROR, ToolOutput
from app.tools.registry import get_adapter
from app.workers.huey_app import huey

_log = logging.getLogger(__name__)


_cached_hostname: str | None = None
_cached_host_meta: dict[str, str] | None = None


def _hostname() -> str:
    global _cached_hostname
    if _cached_hostname is None:
        import socket

        _cached_hostname = socket.gethostname()
    return _cached_hostname


def _host_metadata() -> dict[str, str]:
    """Static host info — computed once per process and cached."""
    global _cached_host_meta
    if _cached_host_meta is not None:
        return _cached_host_meta

    import os
    import platform

    machine = platform.machine().lower()
    if machine == "arm64":
        machine = "aarch64"

    meta: dict[str, str] = {
        "os": platform.system(),
        "arch": machine,
        "python_version": platform.python_version(),
        "cpu_count": str(os.cpu_count() or 0),
        "huey_workers": os.environ.get("HUEY_WORKERS", "2"),
    }

    mem_gb = ""
    try:
        import psutil

        mem_gb = f"{psutil.virtual_memory().total / (1024**3):.1f}"
    except ImportError:
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        mem_gb = f"{kb / (1024**2):.1f}"
                        break
        except OSError:
            pass
    meta["memory_gb"] = mem_gb

    _cached_host_meta = meta
    return _cached_host_meta


def _worker_process_id() -> str:
    """Stable ID for this worker process: ``hostname:pid``."""
    import os

    return f"{_hostname()}:{os.getpid()}"


def _worker_id() -> str:
    """Globally unique ID for this worker thread: ``hostname:pid:thread``.

    Prefixed by ``_worker_process_id()`` so fleet discovery can match
    thread-level heartbeats back to process-level alive keys.
    """
    import os
    import threading

    return f"{_hostname()}:{os.getpid()}:{threading.current_thread().name}"


def _worker_alive_ttl() -> int:
    """Keep idle-worker TTL comfortably above the heartbeat cadence."""
    return max(settings.worker_alive_ttl, settings.worker_heartbeat_interval + 60)


def _worker_ip_address() -> str:
    if settings.worker_ip:
        return settings.worker_ip

    import socket

    try:
        host = urlparse(settings.redis_url).hostname if settings.redis_url else settings.redis_host
        port = urlparse(settings.redis_url).port if settings.redis_url else settings.redis_port
        if host and host not in {"localhost", "127.0.0.1"}:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((host, int(port or settings.redis_port)))
                return sock.getsockname()[0]
    except Exception:
        pass

    try:
        return socket.gethostbyname(_hostname())
    except Exception:
        return "unknown"


def _worker_info_key(process_id: str | None = None) -> str:
    return f"{WORKER_INFO_PREFIX}{process_id or _worker_process_id()}"


_MAX_DEFERRALS = 20


def _get_max_concurrent_jobs() -> int:
    """Return this host's max_concurrent_jobs setting.

    Reads from Redis cache first, falls back to DB on miss.
    0 = unlimited (default), -1 = paused, 1+ = cap.
    """
    hostname = _hostname()
    try:
        r = get_redis()
        cached = r.get(f"{WORKER_POLICY_PREFIX}{hostname}")
        if cached is not None:
            return int(cached)
    except Exception:
        pass
    db = get_sync_session()
    try:
        policy = db.query(WorkerPolicy).filter(WorkerPolicy.hostname == hostname).first()
        value = policy.max_concurrent_jobs if policy else 0
        try:
            get_redis().set(f"{WORKER_POLICY_PREFIX}{hostname}", str(value), ex=120)
        except Exception:
            pass
        return value
    except Exception:
        return 0
    finally:
        db.close()


def _acquire_job_slot(job_id: int) -> bool:
    """Try to acquire a concurrency slot for this host.

    Returns True if the job should be processed, False if it should be deferred.
    Uses Redis INCR/DECR for lock-free atomic slot tracking.
    """
    max_jobs = _get_max_concurrent_jobs()
    hostname = _hostname()

    if max_jobs == -1:
        try:
            r = get_redis()
            alive_count = sum(1 for _ in r.scan_iter(f"{WORKER_ALIVE_PREFIX}*"))
            if alive_count <= 1:
                _log.info("Worker %s paused but is the only live worker — accepting job %d", hostname, job_id)
                # Take the slot like every other accepting branch: run_analysis's `finally`
                # calls _release_job_slot unconditionally, so returning True without an incr
                # would decrement a slot this path never took, under-reporting load on the
                # Worker Fleet page and letting the host exceed a real cap after un-pausing.
                slots_key = f"{WORKER_SLOTS_PREFIX}{hostname}"
                r.incr(slots_key)
                r.expire(slots_key, 300)
                return True
        except Exception:
            pass
        return False

    if max_jobs == 0:
        try:
            r = get_redis()
            slots_key = f"{WORKER_SLOTS_PREFIX}{hostname}"
            r.incr(slots_key)
            r.expire(slots_key, 300)
        except Exception:
            pass
        return True

    try:
        r = get_redis()
        slots_key = f"{WORKER_SLOTS_PREFIX}{hostname}"
        count = r.incr(slots_key)
        r.expire(slots_key, 300)
        if count <= max_jobs:
            return True
        r.decr(slots_key)
    except Exception:
        return True

    try:
        r = get_redis()
        defer_key = f"{JOB_DEFER_PREFIX}{job_id}"
        defer_count = r.incr(defer_key)
        r.expire(defer_key, 1800)
        if defer_count >= _MAX_DEFERRALS:
            _log.warning(
                "Job %d force-accepted by %s after %d deferrals (slot cap %d)",
                job_id,
                hostname,
                defer_count,
                max_jobs,
            )
            r.incr(f"{WORKER_SLOTS_PREFIX}{hostname}")
            r.expire(f"{WORKER_SLOTS_PREFIX}{hostname}", 300)
            r.delete(defer_key)
            return True
    except Exception:
        pass

    return False


def _release_job_slot() -> None:
    """Release a concurrency slot after job processing completes."""
    try:
        r = get_redis()
        slots_key = f"{WORKER_SLOTS_PREFIX}{_hostname()}"
        val = r.decr(slots_key)
        if val < 0:
            r.set(slots_key, "0", ex=300)
    except Exception:
        pass


def _register_worker(current_job_id: int | None = None) -> None:
    """Announce this worker process in Redis with metadata and a TTL."""
    try:
        r = get_redis()
        process_id = _worker_process_id()
        ttl = _worker_alive_ttl()
        max_jobs = _get_max_concurrent_jobs()
        try:
            active = int(r.get(f"{WORKER_SLOTS_PREFIX}{_hostname()}") or "0")
        except Exception:
            active = 0
        metadata = {
            "worker_name": settings.worker_name or _hostname(),
            "hostname": _hostname(),
            "ip_address": _worker_ip_address(),
            "pid": process_id.rsplit(":", 1)[-1],
            "last_seen": datetime.now(UTC).isoformat(),
            "max_concurrent_jobs": str(max_jobs),
            "active_jobs": str(active),
            **_host_metadata(),
        }
        if current_job_id is not None:
            metadata["current_job_id"] = str(current_job_id)

        pipe = r.pipeline()
        pipe.set(f"{WORKER_ALIVE_PREFIX}{process_id}", "1", ex=ttl)
        pipe.hset(_worker_info_key(process_id), mapping=metadata)
        pipe.expire(_worker_info_key(process_id), ttl)
        pipe.execute()
    except Exception as exc:
        _log.warning("Worker registration failed for %s: %s", _worker_process_id(), exc)


#: Thread name, so `threading.enumerate()` can find it — from a test, and from a `py-spy`
#: dump of a consumer that has stopped appearing on the fleet page.
_REGISTRATION_THREAD_NAME = "worker-registration"

_registration_lock = threading.Lock()
_registration_stop = threading.Event()
_registration_thread: threading.Thread | None = None


def _registration_refresh_interval() -> float:
    """How often this process re-announces itself, in seconds.

    Bounded below a third of the TTL rather than simply read from the setting.
    ``_worker_alive_ttl()`` is ``max(worker_alive_ttl, interval + 60)``, so raising
    ``WORKER_HEARTBEAT_INTERVAL`` buys itself only 60 seconds of headroom — one missed
    refresh from expiry, whatever the operator sets. A third keeps three attempts inside
    every window. At the defaults this is the plain 30s.
    """
    return max(1.0, min(float(settings.worker_heartbeat_interval), _worker_alive_ttl() / 3))


def _registration_loop() -> None:
    while not _registration_stop.wait(_registration_refresh_interval()):
        try:
            _register_worker()
        except Exception:
            # `_register_worker` already swallows and logs its own failures; this covers a
            # raise from anything else in the loop. A dead thread here is invisible — the
            # process keeps working and simply stops existing on the fleet page.
            _log.debug("Worker registration refresh failed", exc_info=True)


def _start_registration_refresher() -> None:
    """Start this process's own registration refresher, once.

    Registration is a per-process fact, so it needs a per-process refresher — never a Huey
    periodic task, which cannot promise delivery to a particular process. Every consumer runs
    its own scheduler (``huey/consumer.py::Scheduler``, no lock and no leader election) and
    enqueues its own copy onto the single shared queue; whichever idle thread in the fleet
    wins the ``BRPOP`` executes it, and ``_register_worker`` refreshes only *its* pid. A
    process's refresh rate would be ``C x (threads_here / threads_fleet)`` per minute — the
    shipped ``-w 2`` control plane near one refresh per 100 seconds against a 180s TTL — and
    since huey executes a task inline on the dequeuing thread, a process with every thread
    busy could not win at all. Either way the worker vanishes from /admin/workers with
    nothing logged. (``run_analysis`` is covered separately: ``_HeartbeatTimer`` refreshes
    registration off the queue.)

    The guard is load-bearing: ``@huey.on_startup()`` hooks run from
    ``huey/consumer.py::Worker.initialize``, i.e. once per WORKER THREAD, so ``-w 4`` calls
    this four times in one process.
    """
    global _registration_thread
    with _registration_lock:
        if _registration_thread is not None and _registration_thread.is_alive():
            return
        _registration_stop.clear()
        _registration_thread = threading.Thread(target=_registration_loop, name=_REGISTRATION_THREAD_NAME, daemon=True)
        _registration_thread.start()


def _stop_registration_refresher() -> None:
    """Stop the refresher and wait for it. Daemon or not, every start deserves a stop."""
    global _registration_thread
    with _registration_lock:
        thread, _registration_thread = _registration_thread, None
    _registration_stop.set()
    if thread is not None:
        thread.join(timeout=2)


@huey.on_startup()
def _on_worker_startup():
    """Register this worker process.

    Deliberately does NOT reset ``logstotal:worker_slots:<hostname>``. That counter is
    host-wide, not per-process, so a second consumer starting on the same host would zero
    the slots held by jobs the first one is still running — silently lifting the
    concurrency cap for as long as those jobs take. The counter already self-heals: it
    carries a 300s TTL and ``_release_job_slot`` floors it at zero.

    It is also where the worker's logging is finished off. ``huey_consumer`` adds its own
    ``StreamHandler`` to the ``huey`` logger *after* importing this module, and that logger
    propagates to root — so without this call every consumer line would print twice, in two
    formats, with ``LOG_LEVEL`` overridden on that tree. This hook is the earliest one that
    runs after the consumer's ``setup_logger``.
    """
    silence_huey_own_handlers()
    _register_worker()
    _start_registration_refresher()


class _HeartbeatTimer:
    """Background thread that refreshes heartbeat + alive keys on a fixed interval.

    Without this, a single tool running longer than ``worker_heartbeat_ttl``
    causes the heartbeat to expire and the job to appear stuck.
    """

    def __init__(self, job_id: int) -> None:
        self._job_id = job_id
        self._wid = _worker_id()
        self._interval = settings.worker_heartbeat_interval
        self._ttl = settings.worker_heartbeat_ttl
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        r = get_redis()
        r.set(f"{HEARTBEAT_PREFIX}{self._job_id}", self._wid, ex=self._ttl)
        r.delete(f"{QUEUE_POSITION_PREFIX}{self._job_id}")
        _register_worker(self._job_id)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                r = get_redis()
                r.set(f"{HEARTBEAT_PREFIX}{self._job_id}", self._wid, ex=self._ttl)
                slots_key = f"{WORKER_SLOTS_PREFIX}{_hostname()}"
                if r.exists(slots_key):
                    r.expire(slots_key, 300)
                _register_worker(self._job_id)
            except Exception as exc:
                _log.warning("Worker heartbeat refresh failed for job %s on %s: %s", self._job_id, self._wid, exc)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        try:
            r = get_redis()
            process_id = _worker_process_id()
            info_key = _worker_info_key(process_id)
            pipe = r.pipeline()
            pipe.delete(f"{HEARTBEAT_PREFIX}{self._job_id}")
            pipe.hdel(info_key, "current_job_id")
            pipe.hincrby(info_key, "jobs_completed", 1)
            pipe.expire(info_key, _worker_alive_ttl())
            pipe.execute()
            _register_worker()
        except Exception as exc:
            _log.warning("Worker heartbeat cleanup failed for job %s on %s: %s", self._job_id, self._wid, exc)


def _cancel_requested(job_id: int, identity: str | None = None) -> bool:
    """True when a cancel flag is set for this job — this job, not an earlier one with its id.

    `identity` is the job's `cancel_flag_value`, taken while the row is in hand; see that
    function for why the id alone is not enough.
    """
    try:
        return cancel_flag_is_for(get_redis().get(f"{CANCEL_PREFIX}{job_id}"), identity)
    except Exception:
        return False


def _ai_cancel_requested(analysis_id: int, *, scope: str = "") -> bool:
    """True when the AI cancel flag is set for this run. The twin of `_cancel_requested`."""
    try:
        return bool(get_redis().exists(f"{AI_CANCEL_PREFIX}{scope}{analysis_id}"))
    except Exception:
        return False


class _CancelWatcher:
    """Background thread that polls the per-job cancel flag and latches
    ``self.event`` once it appears; running tools check the event and abort.

    One-way latch: the thread exits as soon as the flag is seen. The heartbeat
    keeps refreshing during cancellation on purpose — a job being cancelled is
    not a stuck job.
    """

    def __init__(self, job_id: int, poll_interval: float = 2.0) -> None:
        self._job_id = job_id
        # Set at pickup, once the row is loaded; a plain string, because this thread must
        # never touch the ORM instance.
        self.identity: str | None = None
        self._poll_interval = poll_interval
        self.event = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            if _cancel_requested(self._job_id, self.identity):
                self.event.set()
                return

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


def _mark_bg_task(db, bg_task_id: int | None, status: str, detail: str | None = None, error: str | None = None):
    """Update a BackgroundTask row. No-op if bg_task_id is None."""
    if bg_task_id is None:
        return
    try:
        # Called from every backfill's `except` handler, where the session may already be
        # in a failed transaction — SQLAlchemy then rejects the status write too and the
        # admin's progress chip polls a `running` row forever. Rolling back only a
        # deactivated session keeps the success path (which has already committed its own
        # work) untouched.
        if not db.is_active:
            db.rollback()
        bt = db.get(BackgroundTask, bg_task_id)
        if not bt:
            return
        bt.status = BackgroundTaskStatus(status)
        now = utc_now_naive()
        if status == "running":
            bt.started_at = now
        # Every write is also a liveness beat, which is what lets the recover sweep tell a
        # long backfill apart from one whose worker died.
        bt.heartbeat_at = now
        if status in ("completed", "failed", "cancelled"):
            bt.finished_at = now
        if detail is not None:
            bt.detail = detail
        if error is not None:
            bt.error_message = error
        db.commit()
    except Exception:
        _log.warning("Could not update BackgroundTask %s to %s", bg_task_id, status, exc_info=True)


def _bg_task_progress(db, bg_task_id: int | None, detail: str) -> None:
    """Beat and report progress, without changing status.

    Called from each backfill's batch boundary — which is already the point at which the
    task commits, so this costs one extra UPDATE per batch and nothing else. Progress goes
    into the existing `detail` column: every backfill loops `WHERE id > last_id LIMIT n`
    with no total available, so a percentage would mean an extra COUNT(*) over the largest
    tables to decorate a bar.
    """
    if bg_task_id is None:
        return
    try:
        if not db.is_active:
            db.rollback()
        bt = db.get(BackgroundTask, bg_task_id)
        if not bt:
            return
        bt.detail = detail
        bt.heartbeat_at = utc_now_naive()
        db.commit()
    except Exception:
        _log.debug("Could not report progress for BackgroundTask %s", bg_task_id, exc_info=True)


def _bg_cancel_requested(bg_task_id: int | None) -> bool:
    """Has an admin asked this task to stop?

    Checked at batch boundaries rather than by a `_CancelWatcher`-style polling thread.
    That thread exists to latch an event a *subprocess* runner consults mid-execution; a
    backfill's loop body is a DB batch, and the commit at the end of it is already the
    consistent point to stop at. Fails open — a Redis outage must not stop a backfill.
    """
    if bg_task_id is None:
        return False
    try:
        return bool(get_redis().exists(f"{BGTASK_CANCEL_PREFIX}{bg_task_id}"))
    except Exception:
        return False


def _finish_cancelled(db, bg_task_id: int | None, detail: str) -> None:
    """Mark a cancelled run and clear its flag."""
    _mark_bg_task(db, bg_task_id, "cancelled", detail=detail)
    try:
        get_redis().delete(f"{BGTASK_CANCEL_PREFIX}{bg_task_id}")
    except Exception:
        pass


class _ScheduledRun:
    """Record a periodic task's last run in Redis, with its outcome and duration.

    Redis, not a `BackgroundTask` row. A run is only interesting until the next one, so a
    row per run would exist purely to give the prune task something to clean up after this
    instrumentation — and `cleanup_job_outputs_periodic` already carries a comment refusing
    exactly that. "When did this last run, and did it work" is an operational fact with a
    natural expiry, which is what `WORKER_INFO_PREFIX` is too.

    Used as a context manager; the task sets ``run.detail`` to say what it did — which is
    why most periodic tasks are a thin wrapper around a separate ``_…_body()`` function
    (the two that need no detail line, or build it inline, use it directly). The Scheduled
    panel on /admin/tasks is built from these records, and without them a task that
    silently stopped running looks identical to one with nothing to do.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        self.detail = ""
        self._started = 0.0

    def __enter__(self) -> _ScheduledRun:
        self._started = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, _tb) -> bool:
        outcome = "ok" if exc_type is None else "error"
        detail = self.detail if exc_type is None else str(exc)[:200]
        try:
            r = get_redis()
            key = f"{TASK_LAST_RUN_PREFIX}{self.key}"
            r.hset(
                key,
                mapping={
                    "ts": utc_now_naive().isoformat(timespec="seconds"),
                    "duration_ms": str(int((time.monotonic() - self._started) * 1000)),
                    "outcome": outcome,
                    "detail": detail or "",
                },
            )
            r.expire(key, TASK_LAST_RUN_TTL)
        except Exception:
            _log.debug("Could not record the last run of %s", self.key, exc_info=True)
        return False  # never swallow: Huey should still see a failure


def _run_tool(adapter, file_path, task_output_dir, log_type_str, cancel_event=None):
    """Pure execution — no DB access. Called from thread pool."""
    return adapter.run(file_path, task_output_dir, log_type=log_type_str, cancel_event=cancel_event)


# Slack added on top of the summed per-tool timeouts before the orchestration
# watchdog gives up on unfinished futures. With the process-group kill in
# ToolAdapter._exec this backstop should never fire.
_WATCHDOG_GRACE_SECONDS = 60


# expires= sets queue expiry (discard if not started in time), not a runtime execution timeout.
@huey.task(retries=1, retry_delay=5, expires=settings.huey_queue_expiry)
def run_analysis(job_id: int):  # noqa: C901 — known debt: the job lifecycle (slots, heartbeat, cancel, tools, finalize)
    """Main analysis task: runs the workflow's tools — serially by default, in parallel when
    `SiteSettings.parallel_execution` is on and the workflow has more than one tool.
    """
    # Every line this task and everything it calls emits carries `job_id=` — including
    # the tool adapters and the intel modules, none of which pass `extra=`.
    #
    # It MUST be cleared in the `finally` below. Huey's `-k thread` consumer reuses its
    # pool threads, and a thread's context outlives the task that ran on it, so a bind left
    # standing would stamp the *next* job's id onto lines belonging to this one.
    bind_log_context(job_id=str(job_id))
    if not _acquire_job_slot(job_id):
        import random

        delay = random.uniform(2, 8)
        _log.info(
            "Job %d deferred by worker %s (slot cap) — re-enqueuing in %.1fs",
            job_id,
            _worker_process_id(),
            delay,
        )
        run_analysis.schedule((job_id,), delay=int(delay))
        # Outside the `try` whose `finally` unbinds, so it has to be undone here.
        bind_log_context(job_id=None)
        return

    slot_acquired = True
    # Whether this run owns the job's Redis keys. The heartbeat and the cancel flag are
    # addressed by job id alone, so a run that loses the claim below — a duplicate message
    # for a job another worker is running — must not delete them in its `finally`: that
    # would drop a live cancel and make a live job look dead to the recovery sweep.
    owns_job_keys = False
    hb = _HeartbeatTimer(job_id)
    cw = _CancelWatcher(job_id)
    db = get_sync_session()
    job: AnalysisJob | None = None
    loaded_path: Path | None = None
    try:
        job = db.get(AnalysisJob, job_id)
        if not job:
            raise RuntimeError(f"Job {job_id} is missing from the worker database. Verify that web and workers share the same PostgreSQL database.")

        # Drop jobs that are already terminal at pickup — covers Huey retries, slot-cap
        # re-enqueues, jobs cancelled while still PENDING in the queue, and rows the
        # expired-PENDING sweep already failed (a late message must not resurrect one
        # and re-run analysis the user was told had failed).
        if enum_val(job.status) in TERMINAL_JOB_STATUSES:
            _log.info("Job %d already %s before pickup — dropping", job_id, enum_val(job.status))
            return
        cw.identity = cancel_flag_value(job)
        if _cancel_requested(job_id, cw.identity):
            owns_job_keys = True  # the flag has served its purpose; the finally clears it
            _set_job_status(db, job, JobStatus.CANCELLED, expected=(JobStatus.PENDING,), error_message=CANCEL_MSG_USER, finished_at=utc_now_naive())
            db.commit()
            _log.info("Job %d cancelled before pickup — dropping", job_id)
            return

        # The claim. Conditional, because the row read above can be stale by now: the
        # expired-PENDING sweep, a cancel or an enqueue-failure handler may have finalized
        # it since, and a duplicate message may have claimed it on another worker. Writing
        # RUNNING unconditionally would bring a terminal job back to life.
        claimed = _set_job_status(db, job, JobStatus.RUNNING, expected=(JobStatus.PENDING,))
        db.commit()
        if not claimed:
            _log.info("Job %d was claimed or finalized elsewhere before pickup — dropping", job_id)
            return
        owns_job_keys = True

        hb.start()
        cw.start()
        _log.info("Job %d picked up by worker %s", job_id, _worker_process_id())

        log_file = job.log_file
        workflow = job.workflow

        from app.storage import get_storage

        storage = get_storage()
        if not storage.exists_sync(log_file.stored_filename):
            _fail_job(db, job, "Upload file not found in storage.")
            return
        file_path = storage.load_sync(log_file.stored_filename)
        # Reclaimed in the finally below. On S3 this is a temp copy under .s3_cache;
        # on local disk it is the stored file itself and release_sync is a no-op.
        loaded_path = file_path

        task_configs = parse_workflow_yaml(workflow.tasks_yaml)
        if not task_configs:
            _fail_job(db, job, "Workflow has no tasks defined.")
            return

        output_dir = Path(settings.upload_dir) / f"job_{job_id}"
        # A fresh tree for every run. SQLite gives a new job the id of the newest deleted
        # one, and `task db:reset` or a restore of an older database leaves `uploads/`
        # behind, so this directory can already hold another job's raw output — and every
        # reader downstream (analytics, entities, timeline, process tree, export) parses
        # the whole tree. The stored copy goes too: on S3 the sync after this run would
        # otherwise merge with the old keys.
        try:
            storage.delete_job_outputs_sync(job_id)
        except Exception:
            _log.warning("Job %d: could not clear stored outputs left under this id", job_id, exc_info=True)
        shutil.rmtree(output_dir, ignore_errors=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        log_type_str = job.effective_log_type.value if job.effective_log_type else None
        site_settings = get_site_settings_sync(db)

        # ── Step 1: Pre-create all TaskResult rows (main thread, single commit) ──
        # work_items: (task_result_id, adapter, task_cfg, task_output_dir)
        work_items = []
        for task_cfg in task_configs:
            tool_name = task_cfg.get("tool", "")
            if not tool_name:
                continue

            task_result = TaskResult(
                job_id=job_id,
                tool_name=tool_name,
                status=TaskStatus.RUNNING,
                started_at=utc_now_naive(),
            )
            db.add(task_result)
            db.flush()

            try:
                task_cfg.setdefault("max_finding_details", site_settings.max_finding_details)
                adapter = get_adapter(tool_name, task_cfg)
            except ValueError as exc:
                task_result.status = TaskStatus.SKIPPED
                task_result.error_message = str(exc)
                task_result.finished_at = utc_now_naive()
                continue

            task_output_dir = output_dir / f"task_{task_result.id}"
            task_output_dir.mkdir(parents=True, exist_ok=True)

            work_items.append((task_result.id, adapter, task_cfg, task_output_dir))

        post_analytics_id: int | None = None
        post_similarity_id: int | None = None
        if work_items:
            tr_an = TaskResult(
                job_id=job_id,
                tool_name=POST_TASK_ANALYTICS,
                status=TaskStatus.PENDING,
                findings_count=0,
            )
            db.add(tr_an)
            db.flush()
            tr_sim = TaskResult(
                job_id=job_id,
                tool_name=POST_TASK_SIMILARITY,
                status=TaskStatus.PENDING,
                findings_count=0,
            )
            db.add(tr_sim)
            db.flush()
            post_analytics_id, post_similarity_id = tr_an.id, tr_sim.id

        db.commit()

        if not work_items:
            db.refresh(job)
            _finalize_job(db, job, any_success=False, any_failure=False)
            return

        parallel = site_settings.parallel_execution and len(work_items) > 1

        # ── Step 2: Run tools + persist each result immediately ───────────────
        any_success = False
        any_failure = False

        if parallel:
            # Per-job pool: TOOL_MAX_WORKERS is a per-job cap, so one job's tools
            # can't starve another job's parallelism (no shared FIFO across workers).
            # max(1, ...) guards against a misconfigured TOOL_MAX_WORKERS=0, which
            # would otherwise make ThreadPoolExecutor raise ValueError.
            # No context manager: __exit__ waits for all workers, so a pathological
            # hang would block finalize — the watchdog below bounds the wait instead.
            # Serial sum of per-tool timeouts is a correct upper bound at any pool width.
            budget = sum(getattr(adapter, "_timeout_seconds", 300) for _, adapter, _, _ in work_items) + _WATCHDOG_GRACE_SECONDS
            pool = ThreadPoolExecutor(max_workers=max(1, min(settings.tool_max_workers, len(work_items))))
            futures: dict = {}
            for task_result_id, adapter, _task_cfg, task_output_dir in work_items:
                f = pool.submit(_run_tool, adapter, file_path, task_output_dir, log_type_str, cw.event)
                futures[f] = task_result_id
            persisted: set[int] = set()
            try:
                for future in as_completed(futures, timeout=budget):
                    task_result_id = futures[future]
                    try:
                        output = future.result()
                    except Exception as exc:
                        output = ToolOutput(success=False, error=str(exc))
                    s, f = _persist_tool_result(db, task_result_id, output)
                    persisted.add(task_result_id)
                    any_success = any_success or s
                    any_failure = any_failure or f
            except TimeoutError:
                for future, task_result_id in futures.items():
                    if task_result_id in persisted:
                        continue
                    if future.done():
                        # Finished between the last as_completed yield and the timeout.
                        try:
                            output = future.result()
                        except Exception as exc:
                            output = ToolOutput(success=False, error=str(exc))
                        s, f = _persist_tool_result(db, task_result_id, output)
                        any_success = any_success or s
                        any_failure = any_failure or f
                        continue
                    cancelled = cw.event.is_set()
                    output = ToolOutput(
                        success=False,
                        error=CANCELLED_ERROR if cancelled else "Watchdog: tool exceeded its timeout budget",
                    )
                    _persist_tool_result(db, task_result_id, output)
                    any_failure = any_failure or not cancelled
                # Last resort: abandons the hung worker thread (reclaimed on
                # worker restart); its late result is never persisted.
                pool.shutdown(wait=False, cancel_futures=True)
            except Exception:
                # Anything else out of the loop — a _persist_tool_result commit failure
                # is not exotic here, SQLite being the default backend with a
                # `SQLITE_BUSY_TIMEOUT_MS` (15s) busy_timeout. Without this the pool is
                # never shut down: the remaining tools keep running while the outer
                # handler marks the job FAILED, and their TaskResult rows stay RUNNING
                # forever (the recovery sweep only looks at RUNNING *jobs*).
                pool.shutdown(wait=False, cancel_futures=True)
                raise
            else:
                pool.shutdown(wait=True)
        else:
            for task_result_id, adapter, _task_cfg, task_output_dir in work_items:
                try:
                    if cw.event.is_set():
                        output = ToolOutput(success=False, error=CANCELLED_ERROR)
                    else:
                        output = _run_tool(adapter, file_path, task_output_dir, log_type_str, cw.event)
                except Exception as exc:
                    output = ToolOutput(success=False, error=str(exc))
                s, f = _persist_tool_result(db, task_result_id, output)
                any_success = any_success or s
                any_failure = any_failure or f

        # ── Step 3: Analytics + TLSH / signatures (before terminal job status) ──
        # Nothing in this step may fail the job. Every tool has finished and its findings
        # are already committed, so a failure here is a failure to *summarise* results that
        # exist. Propagating would reach _fail_job, which writes status/error_message only —
        # never score_ratio, total_findings or severity_summary — so the job would render as
        # FAILED with zero findings while its Finding rows sat in the database. A single
        # "database is locked" is enough; backfill_analytics exists to recompute this later.
        try:
            if cw.event.is_set():
                # Cancelled: skip post-processing (backfill_analytics can compute it
                # later); the completed tools' findings are already persisted.
                for post_id in (post_analytics_id, post_similarity_id):
                    if post_id is not None:
                        tr_post = db.get(TaskResult, post_id)
                        tr_post.status = TaskStatus.CANCELLED
                        tr_post.error_message = CANCEL_MSG_USER
                        tr_post.finished_at = utc_now_naive()
                db.commit()
            elif post_analytics_id is not None and post_similarity_id is not None:
                _run_post_job_processing(db, job, file_path, post_analytics_id, post_similarity_id)
        except Exception as exc:
            _log.warning("Job %d: post-processing failed; keeping the job's real outcome: %s", job_id, exc)
            # Roll back before Step 4: if this was a DB error the session is in a failed
            # transaction and _finalize_job's UPDATE would be rejected too, turning a
            # swallowed error back into a failed job by another route.
            try:
                db.rollback()
            except Exception:
                _log.exception("Job %d: could not roll back after post-processing failure", job_id)
        finally:
            # Mirror tool outputs to object storage so the web tier can serve RAW ZIP
            # (S3 / multi-container). This MUST come after analytics, not before: the S3
            # backend rmtree's the local tree once uploaded, while
            # `event_timeline.extract_all_from_raw_output` reads `upload_dir/job_{id}`
            # straight off the filesystem, bypassing app/storage.py entirely. Syncing
            # first would hand the analytics pass an already-deleted directory, and every
            # S3 deployment would silently produce empty timelines, entities and threat
            # detection. In a `finally` so a post-processing failure still mirrors the
            # outputs — losing them would take the RAW ZIP export with it.
            storage.sync_job_outputs_from_worker(job_id, output_dir)
            # A Processes tab opened while the tools ran cached a partial (often empty) tree
            # for five minutes. The outputs are complete from here on, so drop it.
            from app.intel.process_tree import invalidate as invalidate_process_tree

            invalidate_process_tree(job_id)

        # ── Step 4: Finalize ──────────────────────────────────────────────────
        db.refresh(job)
        _finalize_job(db, job, any_success, any_failure, cancelled=cw.event.is_set())

    except Exception as exc:
        _log.error("Job %d failed on worker %s: %s", job_id, _worker_process_id(), exc)
        try:
            # Roll back FIRST. When the failure was itself a DB error the session is in a
            # failed transaction, and every statement on it — including the UPDATE that
            # marks the job FAILED — is rejected until it is rolled back. Without this the
            # job would stay RUNNING until the heartbeat expired and the startup sweeper
            # noticed, which is a much worse signal than "failed".
            db.rollback()
            if job is not None:
                # A run that holds the claim finalizes from RUNNING; one that failed before
                # claiming may only settle a job nobody has claimed yet.
                expected = (JobStatus.RUNNING,) if owns_job_keys else (JobStatus.PENDING,)
                if cw.event.is_set():
                    # The user asked for this to stop, and killing the tools is a
                    # plausible source of the exception — reporting "failed" would blame
                    # the platform for doing what it was told.
                    _finalize_job(db, job, any_success=False, any_failure=False, cancelled=True, expected=expected)
                else:
                    _fail_job(db, job, str(exc), expected=expected)
        except Exception:
            _log.exception("Job %d: could not record the failure", job_id)
    finally:
        cw.stop()
        if owns_job_keys:
            # Only the run that claimed the job started a heartbeat; stop() deletes the key
            # by job id, which for a losing duplicate would be the live worker's.
            hb.stop()
        if loaded_path is not None:
            # On S3 this drops the .s3_cache copy. Without it a worker accumulates a
            # permanent local copy of every log it has ever analysed, pruned by nothing.
            try:
                from app.storage import get_storage

                get_storage().release_sync(loaded_path)
            except Exception:
                _log.warning("Job %d: could not reclaim the local copy of the upload", job_id, exc_info=True)
        if slot_acquired:
            _release_job_slot()
        try:
            r = get_redis()
            r.delete(f"{JOB_DEFER_PREFIX}{job_id}")
            # The job is terminal (or dropped as already-cancelled) — the cancel
            # flag has served its purpose; don't leave it to linger until TTL. A run that
            # never owned the job leaves it alone: the flag may be a live cancel for the
            # worker that does.
            if owns_job_keys:
                r.delete(f"{CANCEL_PREFIX}{job_id}")
        except Exception:
            pass
        db.close()
        # Pool threads are reused; an unbound id would follow this thread into the next job.
        bind_log_context(job_id=None)


# ── Helpers ─────────────────────────────────────────────────────────────────────


def _combine_logs(stdout: str, stderr: str) -> str:
    from app.workers.utils import _combine_logs as _combine

    return _combine(stdout, stderr, max_bytes=settings.max_log_output_bytes)


def _persist_tool_result(db, task_result_id: int, output: ToolOutput) -> tuple[bool, bool]:
    """Write one tool's TaskResult + Finding rows and commit immediately.

    Returns (was_success, was_failure) booleans.
    """
    values = {"duration_ms": output.duration_ms, "finished_at": utc_now_naive(), "log_output": _combine_logs(output.stdout, output.stderr)}

    was_success = False
    was_failure = False

    if not output.success:
        if output.error == CANCELLED_ERROR:
            status, values["error_message"] = TaskStatus.CANCELLED, CANCEL_MSG_USER
            # Neither success nor failure: cancellation decides the job status.
        elif output.error == "not supported" or output.error.startswith("arch:skip:"):
            status, values["error_message"] = TaskStatus.SKIPPED, output.error.removeprefix("arch:skip:")
        else:
            status, values["error_message"] = TaskStatus.FAILED, output.error
            was_failure = True
    else:
        status, values["findings_count"] = TaskStatus.COMPLETED, len(output.findings)
        was_success = True

    # Only over the RUNNING row Step 1 created: the recovery sweep or the cancel route may
    # have finalized it while the tool ran, and their FAILED/CANCELLED stands, findings and all.
    if not _set_task_status(db, task_result_id, status, expected=(TaskStatus.RUNNING,), **values):
        db.commit()
        _log.info("Task result %d was finalized elsewhere while its tool ran — dropping the result", task_result_id)
        return False, False

    if was_success:
        for f in output.findings:
            finding = Finding(
                task_result_id=task_result_id,
                rule_id=f.rule_id,
                rule_name=f.rule_name,
                severity=f.severity,
                count=f.count,
                tags=json_dumps(f.tags),
                details=json_dumps(f.details),
                rule_content=f.rule_content or None,
            )
            db.add(finding)

    db.commit()
    return was_success, was_failure


def _sweep_unfinished_task_results(db, job_id: int, status: TaskStatus, message: str) -> None:
    """Move any still-PENDING/RUNNING TaskResult of *job_id* to a terminal state.

    A job can reach a terminal status while its rows do not. `_fail_job` runs from
    `run_analysis`'s catch-all, which fires from anywhere in the pipeline — including
    between a tool starting and finishing — and nothing else ever revisits those rows: the
    stale sweep in `app/recovery.py` looks for RUNNING *jobs*, and this job is FAILED. Left
    alone, they spin forever beside a finished job.

    The cancel route (`routers/jobs.py::job_cancel`) does this for the dead-worker path;
    this is the same sweep on the worker side.
    """
    from sqlalchemy import func, update

    # One conditional statement, not read-then-write: a row the recovery sweep or the cancel
    # route finalized in between keeps its status.
    db.execute(
        update(TaskResult)
        .where(TaskResult.job_id == job_id, TaskResult.status.in_([TaskStatus.PENDING, TaskStatus.RUNNING]))
        .values(status=status, error_message=func.coalesce(TaskResult.error_message, message), finished_at=utc_now_naive())
    )


def _rollup_job_counts(db, job: AnalysisJob) -> None:
    """Recompute score_ratio / total_findings / severity_summary from committed findings.

    Findings are persisted per tool as each one completes (the progressive-results
    pattern), so a job that dies part-way still has real findings in the database. Without
    this the score card would read `0/0` and `0 findings` directly above a list of them —
    in a detection product, the most dangerous possible way to be wrong.
    """
    from sqlalchemy.orm import joinedload

    task_results = db.query(TaskResult).options(joinedload(TaskResult.findings)).filter(TaskResult.job_id == job.id).all()
    detection_results = [tr for tr in task_results if not is_post_processing_task(tr.tool_name)]

    severity_counts = dict(EMPTY_SEVERITY_SUMMARY)
    total_findings = 0
    tools_with_hits = 0

    for tr in detection_results:
        if tr.findings:
            tools_with_hits += 1
        for f in tr.findings:
            total_findings += f.count
            sev = enum_val(f.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + f.count

    total_tools = len([tr for tr in detection_results if tr.status not in (TaskStatus.SKIPPED, TaskStatus.CANCELLED)])

    job.score_ratio = f"{tools_with_hits}/{total_tools}" if total_tools else "0/0"
    job.total_findings = total_findings
    job.severity_summary = json_dumps(severity_counts)


def _set_job_status(db, job: AnalysisJob, status: JobStatus, *, expected: tuple[JobStatus, ...], **values) -> bool:
    """Move *job* to *status* only while its row is still in one of *expected*.

    `UPDATE ... WHERE id = :id AND status IN :expected`, so the check and the write are one
    statement. Every writer of a job's status reads the row first and writes it later — the
    worker across a whole analysis run — and an unconditional write in between would overwrite
    whatever another actor committed meanwhile: a cancel, the recovery sweep's FAILED, an
    enqueue failure. A terminal status would then stop being final. Returns whether the row
    changed; when it did not, *job* is refreshed so the caller sees the status that won.
    """
    from sqlalchemy import update

    result = db.execute(update(AnalysisJob).where(AnalysisJob.id == job.id, AnalysisJob.status.in_(expected)).values(status=status, **values))
    if result.rowcount == 1:
        return True
    db.refresh(job, attribute_names=["status"])
    return False


def _set_task_status(db, task_result_id: int, status: TaskStatus, *, expected: tuple[TaskStatus, ...], **values) -> bool:
    """`_set_job_status` for one TaskResult row: write it only while it is still in *expected*.

    The recovery sweep and the cancel route finalize a job's unfinished rows from another
    process while its worker may still be running the tools; an unconditional write would
    put a completed result under a job that already reads FAILED or CANCELLED.
    """
    from sqlalchemy import update

    stmt = update(TaskResult).where(TaskResult.id == task_result_id, TaskResult.status.in_(expected)).values(status=status, **values)
    return db.execute(stmt).rowcount == 1


def _fail_job(db, job: AnalysisJob, message: str, expected: tuple[JobStatus, ...] = (JobStatus.RUNNING,)):
    _sweep_unfinished_task_results(db, job.id, TaskStatus.FAILED, message)
    _rollup_job_counts(db, job)
    # Never over a terminal status, and never over a job another run has claimed.
    if not _set_job_status(db, job, JobStatus.FAILED, expected=expected, error_message=message, finished_at=utc_now_naive()):
        _log.info("Job %d is already %s — not marking it failed", job.id, enum_val(job.status))
    db.commit()


def _cache_analytics(job: AnalysisJob, data: dict, job_dir: Path | None = None) -> bool:
    """Persist the analytics blob and the events-timeline marker index onto *job*.

    Both are derived from the same single pass over the raw output, and all three analytics
    write paths (inline post-processing, ``backfill_analytics``,
    ``recalculate_single_analytics``) must store both — otherwise a backfilled job gets
    fresh analytics and a stale timeline. The caller still owns the commit.

    Returns False and writes nothing when the job's raw output is gone. That case is not
    "this job had no findings", it is "we can no longer tell", and the two are
    indistinguishable downstream: ``extract_all_from_raw_output`` returns ``({}, [])`` for a
    missing directory, so persisting it would replace good analytics with an all-zero blob
    and ``pack_index(None)`` would null out ``event_markers``. Both are unrecoverable.
    Reachable on every S3 deployment (``sync_job_outputs_from_worker`` rmtree's the local
    tree after the first pass) and on any job cleaned up by ``/admin/cleanup-outputs``, where
    "Recalculate analytics" would otherwise destroy it. The inline path is unaffected:
    the tools have just written their output.
    """
    from app.analytics import analytics_json_payload
    from app.intel.event_markers import pack_index
    from app.intel.event_timeline import has_raw_output

    if not has_raw_output(job.id, job_dir=job_dir):
        return False
    job.analytics_json = json_dumps(analytics_json_payload(data))
    job.event_markers = pack_index(data.get("event_markers"))
    return True


def _run_post_job_processing(
    db,
    job: AnalysisJob,
    file_path: Path,
    analytics_tr_id: int,
    similarity_tr_id: int,
):
    """Cache analytics + entities, then TLSH + rule signatures. Updates post TaskResult rows."""
    from sqlalchemy.orm import selectinload

    from app.analytics import _compute_analytics_data
    from app.similarity.correlator import make_rule_signature
    from app.similarity.hasher import compute_tlsh

    # Warm the session identity map: this eager-loads task_results + findings onto the
    # already-loaded `job` instance (same session) in 2 batch queries, so later
    # `job.task_results`/`tr.findings` access avoids N+1 lazy loads.
    job = db.query(AnalysisJob).options(selectinload(AnalysisJob.task_results).selectinload(TaskResult.findings)).filter(AnalysisJob.id == job.id).first() or job

    tr_an = db.get(TaskResult, analytics_tr_id)
    if tr_an:
        tr_an.status = TaskStatus.RUNNING
        tr_an.started_at = utc_now_naive()
        db.commit()

    try:
        analytics_data = _compute_analytics_data(job)
        _cache_analytics(job, analytics_data)
        if tr_an:
            tr_an.finished_at = utc_now_naive()
            tr_an.duration_ms = int((tr_an.finished_at - tr_an.started_at).total_seconds() * 1000) if tr_an.started_at else None
            tr_an.status = TaskStatus.COMPLETED
        db.commit()

        from app.intel.entities import persist_entities_from_analytics

        persist_entities_from_analytics(db, job.id, analytics_data)
        db.commit()

        # Rules. Runs after entities are persisted and committed, and is best-effort: the
        # job is already terminal, and a rule failure must not change that.
        try:
            from app.intel.rules import evaluate_job_rules_for_job, evaluate_rules_for_job

            rule_result = evaluate_rules_for_job(db, job.id)
            db.commit()
            if rule_result.matches_created:
                _log.info("intel rules: %d match(es) for job %d", rule_result.matches_created, job.id)
            # Enqueue AFTER the commit — a rollback must never strand a queued delivery
            # for matches that do not exist.
            for rule_id, match_ids in rule_result.webhook_jobs:
                deliver_webhook(rule_id, job.id, match_ids)
        except Exception as exc:
            _log.warning("intel rule evaluation failed for job %s: %s", job.id, exc)
            db.rollback()

        # A second pass, in its own try/except: a broken *entity* rule must not cost the
        # job its job-rule alerts, and vice versa. Same best-effort contract — the job is
        # already terminal and neither pass may change that.
        try:
            job_rule_result = evaluate_job_rules_for_job(db, job.id)
            db.commit()
            if job_rule_result.matches_created:
                _log.info("job rules: %d match(es) for job %d", job_rule_result.matches_created, job.id)
            for rule_id in job_rule_result.webhook_rules:
                deliver_webhook(rule_id, job.id, [], job_rule_match=True)
        except Exception as exc:
            _log.warning("job rule evaluation failed for job %s: %s", job.id, exc)
            db.rollback()
    except Exception as exc:
        _log.warning("post-processing analytics failed for job %s: %s", job.id, exc)
        if tr_an:
            # Same reasoning as _mark_bg_task: when the failure *was* a DB error the
            # session is in a failed transaction and this write is rejected too, so the
            # analytics TaskResult would stay RUNNING and the job page would poll for a
            # result that is never coming. Roll back only a deactivated session.
            if not db.is_active:
                db.rollback()
            tr_an.status = TaskStatus.FAILED
            tr_an.error_message = str(exc)
            tr_an.finished_at = utc_now_naive()
            if tr_an.started_at:
                tr_an.duration_ms = int((tr_an.finished_at - tr_an.started_at).total_seconds() * 1000)
            db.commit()

    tr_sim = db.get(TaskResult, similarity_tr_id)
    if tr_sim:
        tr_sim.status = TaskStatus.RUNNING
        tr_sim.started_at = utc_now_naive()
        db.commit()

    try:
        log_file = db.get(LogFile, job.file_id)
        if log_file and not log_file.tlsh_hash:
            h = compute_tlsh(file_path)
            if h:
                log_file.tlsh_hash = h

        findings = db.query(Finding).join(TaskResult, Finding.task_result_id == TaskResult.id).filter(TaskResult.job_id == job.id, Finding.rule_signature.is_(None)).all()
        for f in findings:
            sev = enum_val(f.severity)
            f.rule_signature = make_rule_signature(f.rule_id, f.rule_name, sev)

        if tr_sim:
            tr_sim.finished_at = utc_now_naive()
            tr_sim.duration_ms = int((tr_sim.finished_at - tr_sim.started_at).total_seconds() * 1000) if tr_sim.started_at else None
            tr_sim.status = TaskStatus.COMPLETED
        db.commit()
    except Exception as exc:
        _log.warning("post-processing similarity/signatures failed for job %s: %s", job.id, exc)
        if tr_sim:
            tr_sim.status = TaskStatus.FAILED
            tr_sim.error_message = str(exc)
            tr_sim.finished_at = utc_now_naive()
            if tr_sim.started_at:
                tr_sim.duration_ms = int((tr_sim.finished_at - tr_sim.started_at).total_seconds() * 1000)
            db.commit()


# ── Where the backfills commit, and why it is not at the batch boundary ────────
#
# Every backfill below pages with `WHERE id > last_id LIMIT n`. The batch is the *query*
# window; it is not the transaction. Where the loop body is expensive — a raw-output parse,
# a TLSH digest over a 300 MB upload — the commit goes **inside** the per-item loop.
#
# SQLite has one writer. A batch-wide commit holds the writer lock from the first INSERT of
# the batch to the end of it, with all of the parsing in between; with `BATCH = 100` and
# fewer than a hundred jobs, that is the entire run. Measured on a nine-job instance:
# `backfill_analytics` held one transaction for **80 seconds**, and every write the web tier
# attempted in that window — queueing another maintenance task, saving a setting, tagging a
# job — waited out `SQLITE_BUSY_TIMEOUT_MS` and returned a 500. It looks intermittent,
# because the parse happens before the first write.
#
# Committing per item costs one fsync per row instead of one per batch, which on WAL with
# `synchronous=NORMAL` is not a fsync at all. Cheap row-wise loops (rule signatures, entity
# attributes) keep the batch commit — they never hold the lock long enough to matter.
#
# `_bg_task_progress` and `_bg_cancel_requested` stay at the batch boundary. Cancellation is
# still consistent, because every item before it has already committed.


# expires= queue expiry only; running tasks are not killed.
@huey.task(expires=settings.huey_queue_expiry)
def backfill_similarity(bg_task_id: int | None = None):
    """Compute TLSH + rule signatures for all existing records missing them."""

    from app.similarity.correlator import make_rule_signature
    from app.similarity.hasher import compute_tlsh

    BATCH = 100
    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")

        total_files = 0
        last_file_id = 0
        while True:
            batch = db.query(LogFile).filter(LogFile.tlsh_hash.is_(None), LogFile.id > last_file_id).order_by(LogFile.id).limit(BATCH).all()
            if not batch:
                break
            for lf in batch:
                from app.storage import get_storage

                _st = get_storage()
                if _st.exists_sync(lf.stored_filename):
                    fp = _st.load_sync(lf.stored_filename)
                    try:
                        h = compute_tlsh(fp)
                    finally:
                        # On S3 `fp` is a whole-file copy in `.s3_cache`, which nothing prunes.
                        _st.release_sync(fp)
                    if h:
                        lf.tlsh_hash = h
                        db.commit()  # per file — a TLSH digest reads the whole upload
            last_file_id = batch[-1].id
            total_files += len(batch)
            _bg_task_progress(db, bg_task_id, f"{total_files} files hashed…")
            if _bg_cancel_requested(bg_task_id):
                _finish_cancelled(db, bg_task_id, f"cancelled after {total_files} files")
                return
        _log.info("backfill_similarity: processed %d log files", total_files)

        total_findings = 0
        last_finding_id = 0
        while True:
            batch = db.query(Finding).filter(Finding.rule_signature.is_(None), Finding.id > last_finding_id).order_by(Finding.id).limit(BATCH).all()
            if not batch:
                break
            for f in batch:
                sev = enum_val(f.severity)
                f.rule_signature = make_rule_signature(f.rule_id, f.rule_name, sev)
            last_finding_id = batch[-1].id
            db.commit()
            total_findings += len(batch)
            _bg_task_progress(db, bg_task_id, f"{total_files} files, {total_findings} findings…")
            if _bg_cancel_requested(bg_task_id):
                _finish_cancelled(db, bg_task_id, f"cancelled after {total_files} files, {total_findings} findings")
                return
        _log.info("backfill_similarity: processed %d findings", total_findings)

        _mark_bg_task(db, bg_task_id, "completed", detail=f"{total_files} files, {total_findings} findings")
    except Exception as exc:
        _log.error("backfill_similarity failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def backfill_analytics(bg_task_id: int | None = None):
    """Recompute and cache analytics for all terminal jobs."""

    from sqlalchemy.orm import selectinload

    from app.analytics import _compute_analytics_data

    BATCH = 100
    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")

        total = 0
        skipped = 0
        last_id = 0
        while True:
            batch = (
                db.query(AnalysisJob)
                .options(
                    selectinload(AnalysisJob.task_results).selectinload(TaskResult.findings),
                )
                .filter(
                    AnalysisJob.status.in_([JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.PARTIAL, JobStatus.CANCELLED]),
                    AnalysisJob.id > last_id,
                )
                .order_by(AnalysisJob.id)
                .limit(BATCH)
                .all()
            )
            if not batch:
                break
            for job in batch:
                # Through the storage backend: on S3 the worker's local tree is gone, and
                # building the path here found nothing and skipped every job.
                with job_outputs_dir(job.id) as job_dir:
                    data = _compute_analytics_data(job, job_dir=job_dir)
                    cached = _cache_analytics(job, data, job_dir=job_dir)
                if not cached:
                    # Outputs cleaned up or synced away — leave this job's analytics alone
                    # rather than blanking them. See _cache_analytics.
                    skipped += 1
                    continue
                from app.intel.entities import persist_entities_from_analytics

                persist_entities_from_analytics(db, job.id, data)
                db.commit()  # per job — the parse above is inside the transaction
            last_id = batch[-1].id
            total += len(batch)
            _bg_task_progress(db, bg_task_id, f"{total} jobs processed…")
            if _bg_cancel_requested(bg_task_id):
                _finish_cancelled(db, bg_task_id, f"cancelled after {total} jobs ({skipped} skipped)")
                return
        _log.info("backfill_analytics: processed %d jobs (%d skipped, no raw output)", total, skipped)

        # Report the skips rather than swallowing them: "500 jobs processed" would read as
        # full coverage on an instance where half the outputs have been cleaned up.
        detail = f"{total} jobs processed"
        if skipped:
            detail += f", {skipped} skipped (raw output no longer on disk — existing analytics kept)"
        _mark_bg_task(db, bg_task_id, "completed", detail=detail)
    except Exception as exc:
        _log.error("backfill_analytics failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def recalculate_single_analytics(job_id: int, bg_task_id: int | None = None):
    """Recompute and cache analytics for a single job (background).

    `bg_task_id` is the row the recalculate route writes so the run shows on /admin/tasks.
    Every exit closes it: left alone it stays "pending", is later offered for recovery, and
    recovering marks a run that succeeded as failed.
    """

    from sqlalchemy.orm import selectinload

    from app.analytics import _compute_analytics_data

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")
        job = (
            db.query(AnalysisJob)
            .options(
                selectinload(AnalysisJob.task_results).selectinload(TaskResult.findings),
            )
            .filter(AnalysisJob.id == job_id)
            .first()
        )
        if not job:
            _log.warning("recalculate_single_analytics: job %d not found", job_id)
            _mark_bg_task(db, bg_task_id, "failed", error=f"Job #{job_id} no longer exists.")
            return
        with job_outputs_dir(job_id) as job_dir:
            data = _compute_analytics_data(job, job_dir=job_dir)
            cached = _cache_analytics(job, data, job_dir=job_dir)
        if not cached:
            # Raw output is gone (/admin/cleanup-outputs, or never synced). Recomputing
            # from nothing would overwrite good analytics with an empty blob, so stop
            # before the entity/relationship persist too — that pass would find nothing.
            _log.warning("recalculate_single_analytics: job %d has no raw output left — keeping existing analytics", job_id)
            _mark_bg_task(db, bg_task_id, "completed", detail="No raw output left for this job; its existing analytics were kept.")
            return

        from app.intel.entities import persist_entities_from_analytics

        persist_entities_from_analytics(db, job.id, data)
        db.commit()
        _mark_bg_task(db, bg_task_id, "completed", detail="Analytics recalculated.")
        _log.info("recalculate_single_analytics: job %d done", job_id)
    except Exception as exc:
        _log.error("recalculate_single_analytics failed for job %d: %s", job_id, exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc)[:500])
    finally:
        try:
            from app.redis_client import RECALC_PREFIX

            get_redis().delete(f"{RECALC_PREFIX}{job_id}")
        except Exception:
            pass
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def cleanup_old_job_outputs(bg_task_id: int | None = None):
    """Remove output directories for jobs older than JOB_OUTPUT_RETENTION_DAYS.

    No-op when job_output_retention_days is 0 (keep forever).
    Only deletes the output directory — DB records and uploaded files are kept.
    """
    from datetime import timedelta

    # Through the shared resolver, so the sweep and the page that describes it cannot
    # disagree about which window is in force.
    from app.retention import effective_retention

    _resolver_db = get_sync_session()
    try:
        retention = effective_retention("job_output_retention_days", get_site_settings_sync(_resolver_db))
        retention_days, retention_source = retention.days, retention.source
    except Exception:
        retention_days, retention_source = settings.job_output_retention_days, "JOB_OUTPUT_RETENTION_DAYS"
    finally:
        _resolver_db.close()

    if retention_days <= 0:
        # Still close out the BackgroundTask row, or it would show "pending" forever.
        db = get_sync_session()
        try:
            _mark_bg_task(db, bg_task_id, "completed", detail=f"Retention disabled ({retention_source} = 0) — nothing to delete")
        finally:
            db.close()
        return

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")

        cutoff = utc_now_naive() - timedelta(days=retention_days)
        BATCH = 200
        total = 0
        last_id = 0
        while True:
            batch = (
                db.query(AnalysisJob)
                .filter(
                    AnalysisJob.finished_at.isnot(None),
                    AnalysisJob.finished_at < cutoff,
                    AnalysisJob.id > last_id,
                )
                .order_by(AnalysisJob.id)
                .limit(BATCH)
                .all()
            )
            if not batch:
                break
            from app.storage import get_storage

            st = get_storage()
            for job in batch:
                if st.delete_job_outputs_sync(job.id):
                    total += 1
            last_id = batch[-1].id
            _bg_task_progress(db, bg_task_id, f"{total} directories removed…")
            if _bg_cancel_requested(bg_task_id):
                # Directories already removed stay removed — say so rather than implying
                # the run was undone.
                _finish_cancelled(db, bg_task_id, f"cancelled after removing {total} directories (not restored)")
                return

        _log.info("cleanup_old_job_outputs: removed %d output directories (retention=%d days)", total, retention_days)
        _mark_bg_task(db, bg_task_id, "completed", detail=f"{total} dirs removed")
    except Exception as exc:
        _log.error("cleanup_old_job_outputs failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
        if bg_task_id is None:
            # The daily sweep: no row to report into, and _ScheduledRun reads success from
            # the absence of an exception.
            raise
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def backfill_entities(bg_task_id: int | None = None):
    """Populate Entity + EntityJobLink tables from existing analytics_json blobs."""

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")

        from app.intel.entities import persist_entities_from_analytics

        BATCH = 100
        total = 0
        last_id = 0
        cancelled = False
        while True:
            batch = (
                db.query(AnalysisJob)
                .filter(
                    AnalysisJob.analytics_json.isnot(None),
                    AnalysisJob.id > last_id,
                )
                .order_by(AnalysisJob.id)
                .limit(BATCH)
                .all()
            )
            if not batch:
                break
            for job in batch:
                try:
                    data = json_loads(job.analytics_json)
                    persist_entities_from_analytics(db, job.id, data)
                    db.commit()  # per job — an entity persist is thousands of rows
                except Exception as exc:
                    # Roll the one job back rather than carrying its half-written state into
                    # the next commit; the loop is deliberately tolerant of a bad blob.
                    db.rollback()
                    _log.warning("backfill_entities: job %d failed: %s", job.id, exc)
            last_id = batch[-1].id
            total += len(batch)
            _bg_task_progress(db, bg_task_id, f"{total} jobs processed…")
            if _bg_cancel_requested(bg_task_id):
                cancelled = True
                break
        _log.info("backfill_entities: processed %d jobs", total)

        from app.intel.entities import rebuild_entity_job_counts

        # Runs on the cancel path too, and that is the point: it is one statement, and
        # skipping it would leave `Entity.job_count` inconsistent with `entity_job_link`
        # on the dashboard — a stopped backfill should not leave visibly wrong numbers.
        rebuild_entity_job_counts(db)
        db.commit()

        if cancelled:
            _finish_cancelled(db, bg_task_id, f"cancelled after {total} jobs (entity counts rebuilt)")
            return
        _mark_bg_task(db, bg_task_id, "completed", detail=f"{total} jobs processed")
    except Exception as exc:
        _log.error("backfill_entities failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def backfill_relationships(bg_task_id: int | None = None):
    """Rebuild typed EntityRelationship edges for existing jobs from raw tool output.

    Unlike the entity and analytics backfills, relationships are not stored in analytics_json
    (they are stripped before caching), so this re-parses the per-job raw output via
    ``event_timeline.extract_all_from_raw_output``. Endpoints are resolved against the
    entities already linked to each job. Jobs whose output dirs were cleaned up yield nothing.

    Safe to re-run: ``occurrence_count`` is derived from the per-job evidence rows, which
    are set wholesale per job.
    """

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")

        from app.intel.event_timeline import extract_all_from_raw_output
        from app.intel.relationships import EVIDENCE_CAP, extract_relationships, persist_relationships, trim_evidence_event
        from app.models import Entity, EntityJobLink

        BATCH = 50
        total = 0
        edges = 0
        last_id = 0
        while True:
            batch = (
                db.query(AnalysisJob)
                .filter(
                    AnalysisJob.status.in_([JobStatus.COMPLETED, JobStatus.PARTIAL, JobStatus.CANCELLED]),
                    AnalysisJob.id > last_id,
                )
                .order_by(AnalysisJob.id)
                .limit(BATCH)
                .all()
            )
            if not batch:
                break
            for job in batch:
                try:
                    with job_outputs_dir(job.id) as job_dir:
                        _buckets, all_events = extract_all_from_raw_output(job.id, job_dir=job_dir)
                    # Counted at the source, like the live analytics pass — see the note on
                    # `relationship_pairs` in app/analytics.py.
                    pairs: Counter[tuple[str, str, str, str, str]] = Counter()
                    evidence: dict[tuple[str, str, str, str, str], list[dict]] = {}
                    for ev in all_events:
                        rels = extract_relationships(ev)
                        if not rels:
                            continue
                        pairs.update(rels)
                        trimmed = None
                        for tup in rels:
                            bucket = evidence.setdefault(tup, [])
                            if len(bucket) >= EVIDENCE_CAP:
                                continue
                            if trimmed is None:
                                trimmed = trim_evidence_event(ev)
                            if trimmed:
                                bucket.append(trimmed)
                    if not pairs:
                        continue
                    entities = db.query(Entity).join(EntityJobLink, Entity.id == EntityJobLink.entity_id).filter(EntityJobLink.job_id == job.id).all()
                    entity_map = {(e.value, e.entity_type): e for e in entities}
                    edges += persist_relationships(db, job.id, pairs, entity_map, evidence=evidence)
                    db.commit()  # per job — the raw-output parse above is the expensive part
                except Exception as exc:
                    db.rollback()
                    _log.warning("backfill_relationships: job %d failed: %s", job.id, exc)
            last_id = batch[-1].id
            total += len(batch)
            _bg_task_progress(db, bg_task_id, f"{total} jobs, {edges} edges…")
            if _bg_cancel_requested(bg_task_id):
                _finish_cancelled(db, bg_task_id, f"cancelled after {total} jobs, {edges} edges")
                return
        _log.info("backfill_relationships: processed %d jobs, %d edges", total, edges)

        _mark_bg_task(db, bg_task_id, "completed", detail=f"{total} jobs, {edges} edges")
    except Exception as exc:
        _log.error("backfill_relationships failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def backfill_entity_attributes(bg_task_id: int | None = None):
    """(Re)compute per-type attributes (attributes_json) for every existing entity.

    Overwrites existing values so it doubles as a refresh after heuristic/config changes.
    """

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")

        from app.intel.attributes import compute_attributes
        from app.models import Entity

        BATCH = 500
        total = 0
        last_id = 0
        while True:
            batch = db.query(Entity).filter(Entity.id > last_id).order_by(Entity.id).limit(BATCH).all()
            if not batch:
                break
            for e in batch:
                attrs = compute_attributes(e.value, e.entity_type)
                e.attributes_json = json_dumps(attrs) if attrs is not None else None
            last_id = batch[-1].id
            db.commit()
            total += len(batch)
            _bg_task_progress(db, bg_task_id, f"{total} entities…")
            if _bg_cancel_requested(bg_task_id):
                _finish_cancelled(db, bg_task_id, f"cancelled after {total} entities")
                return
        _log.info("backfill_entity_attributes: processed %d entities", total)

        _mark_bg_task(db, bg_task_id, "completed", detail=f"{total} entities")
    except Exception as exc:
        _log.error("backfill_entity_attributes failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def backfill_builtin_labels(bg_task_id: int | None = None):
    """Apply every enabled built-in label rule to every existing entity.

    Labels are stored tags, written as each job finishes, so an entity last seen before a
    rule existed — or before a shared rule or list changed — carries none of its tags until
    something touches it again. This is the catch-up.

    Works from the **entity** table rather than by replaying jobs, because a label is a
    property of the entity, not of the run that happened to observe it: replaying jobs would
    do the same work once per (entity, job) link.

    Commits at the batch boundary, the `backfill_entity_attributes` precedent — the loop
    body is one indexed SELECT per rule, not a parse of a whole raw output. What it writes
    is bounded by `_insert_tags`, which does one savepoint per batch rather than one per row
    for exactly this reason.
    """

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")

        from sqlalchemy import select as _select

        from app.intel.queries import apply_entity_filters, parse_query, post_filter, query_needs_post_filter
        from app.intel.rules import _apply_tag, _entity_types, builtin_rules_enabled
        from app.models import Entity, IntelRule

        if not builtin_rules_enabled(db):
            _mark_bg_task(db, bg_task_id, "completed", detail="built-in label rules are switched off in Settings")
            return

        # Entity-scope only: a job rule's condition is the jobs grammar, and compiled as an
        # entity query `tag:escalated` means "entities tagged escalated" — tagging entities
        # with a job-triage label, or every entity for a pure negation.
        rules = db.execute(_select(IntelRule).where(IntelRule.is_builtin.is_(True), IntelRule.enabled.is_(True), IntelRule.scope == "entity")).scalars().all()
        if not rules:
            _mark_bg_task(db, bg_task_id, "completed", detail="no enabled built-in rules — run `./logstotal sync-rules`")
            return

        # Each rule's criteria compiled once, through the same builder the live pass and the
        # dashboard use, so a rule matches here exactly what it matches during analysis.
        compiled = [(r, parse_query(r.query or ""), _entity_types(r)) for r in rules]

        BATCH = 500
        total = 0
        tagged = 0
        last_id = 0
        while True:
            ids = [row[0] for row in db.execute(_select(Entity.id).where(Entity.id > last_id).order_by(Entity.id).limit(BATCH)).all()]
            if not ids:
                break
            for rule, parsed, types in compiled:
                stmt = apply_entity_filters(_select(Entity).where(Entity.id.in_(ids)), query=parsed, types=types)
                matched = list(db.execute(stmt).scalars().all())
                if query_needs_post_filter(parsed):
                    # Strict: a row the regex budget left unchecked is dropped, never tagged.
                    matched = post_filter(matched, parsed, strict=True)
                if matched:
                    tagged += _apply_tag(db, rule, matched)
            last_id = ids[-1]
            db.commit()
            total += len(ids)
            _bg_task_progress(db, bg_task_id, f"{total} entities, {tagged} labels…")
            if _bg_cancel_requested(bg_task_id):
                _finish_cancelled(db, bg_task_id, f"cancelled after {total} entities")
                return

        _log.info("backfill_builtin_labels: %d entities, %d labels applied", total, tagged)
        _mark_bg_task(db, bg_task_id, "completed", detail=f"{total} entities, {tagged} labels applied")
    except Exception as exc:
        _log.error("backfill_builtin_labels failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def backfill_finding_entity_links(bg_task_id: int | None = None):
    """Rebuild FindingEntityLink rows for all jobs with existing entities + findings."""

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")

        from app.intel.entities import rebuild_finding_entity_links_for_job

        BATCH = 100
        total_jobs = 0
        total_links = 0
        last_id = 0
        while True:
            batch = (
                db.query(AnalysisJob.id)
                .filter(
                    AnalysisJob.status.in_([JobStatus.COMPLETED, JobStatus.PARTIAL, JobStatus.CANCELLED]),
                    AnalysisJob.id > last_id,
                )
                .order_by(AnalysisJob.id)
                .limit(BATCH)
                .all()
            )
            if not batch:
                break
            for (jid,) in batch:
                try:
                    n = rebuild_finding_entity_links_for_job(db, jid)
                    total_links += n
                    db.commit()  # per job — a rebuild scans every finding on it
                except Exception as exc:
                    _log.warning("backfill_finding_entity_links: job %d failed: %s", jid, exc)
                    db.rollback()
            last_id = batch[-1][0]
            total_jobs += len(batch)
            _bg_task_progress(db, bg_task_id, f"{total_jobs} jobs, {total_links} links…")
            if _bg_cancel_requested(bg_task_id):
                _finish_cancelled(db, bg_task_id, f"cancelled after {total_jobs} jobs, {total_links} links")
                return

        _log.info("backfill_finding_entity_links: processed %d jobs, %d links", total_jobs, total_links)
        _mark_bg_task(db, bg_task_id, "completed", detail=f"{total_jobs} jobs, {total_links} links")
    except Exception as exc:
        _log.error("backfill_finding_entity_links failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def deliver_webhook(rule_id: int, job_id: int | None, match_ids: list[int], attempt: int = 1, *, watch_event_ids: list[int] | None = None, job_rule_match: bool = False):
    """POST a rule's matches to its webhook. One delivery per (rule, job).

    Retries are an explicit re-enqueue rather than Huey's `retries=` so `attempt` is a real,
    owner-visible number on the WebhookDelivery row and the backoff is exponential. 4xx other
    than 429 is terminal (the receiver said no); network errors, timeouts, 429 and 5xx back off.

    `job_id=None` with no matches is the "send test" path. It runs through this same
    function on purpose — same validation, same rate limit, same headers and signature — so
    a passing test actually proves the real path works.

    Four payload shapes, one delivery path. `watch_event_ids` selects `job.watch`;
    `job_rule_match` selects `job.match`, which needs no id list because a job rule's alert
    is 1:1 with (rule, job) and both are already arguments; otherwise it is `rule.match`, or
    `rule.test` when there is neither a job nor a match. Keeping them on one function is
    what makes "Test" prove anything: a second sender would have its own rate limit, its own
    header assembly and its own SSRF guard to keep in step with this one.
    """
    import time

    from sqlalchemy import select

    from app.intel.webhooks import WebhookError, build_job_rule_payload, build_job_watch_payload, build_payload, delivery_headers, send, sign, validate_url_addresses
    from app.json_utils import dumps as json_dumps
    from app.models import Entity, IntelRule, IntelRuleMatch, User, WebhookDelivery, has_intel_access

    db = get_sync_session()
    try:
        rule = db.get(IntelRule, rule_id)
        if rule is None or not rule.webhook_enabled or not rule.webhook_url:
            return
        # A delivery or its retry can be queued before the owner is deactivated or demoted and
        # run after; evaluation already refuses that owner, so the send must agree.
        if rule.owner_user_id is not None and not has_intel_access(db.get(User, rule.owner_user_id)):
            return

        def _record(ok: bool, status: int | None, error: str | None, ms: int | None = None) -> None:
            db.add(
                WebhookDelivery(
                    rule_id=rule_id,
                    job_id=job_id,
                    match_count=len(match_ids),
                    attempt=attempt,
                    status_code=status,
                    ok=ok,
                    error_message=(error or None),
                    duration_ms=ms,
                )
            )
            db.commit()

        # Per-rule rate limit. Over the limit is recorded and dropped, not retried —
        # retrying is what would turn a misconfigured rule into an outbound flood.
        try:
            from app.middleware.production import _redis_window_hits

            limit = settings.webhook_rate_limit_per_minute
            if limit and _redis_window_hits(f"logstotal:ratelimit:webhook:{rule_id}", 60) > limit:
                _record(False, None, "rate limited")
                return
        except Exception:  # Redis down must not stop delivery
            pass

        try:
            # Keep the addresses this returned: several DB round trips happen before the
            # request goes out, and re-resolving the hostname down there would make the
            # public-host guard defeatable by a short-TTL record.
            addresses = validate_url_addresses(rule.webhook_url, require_public=settings.webhook_require_public_host)
        except WebhookError as exc:
            _record(False, None, str(exc)[:280])
            return

        job = db.get(AnalysisJob, job_id) if job_id else None

        if watch_event_ids:
            # A job-watch delivery rides this rule's webhook configuration — its URL, its
            # secret, its rate limit, its retry backoff. `event` is the discriminator, and
            # the payload keeps an empty `entities` list so a receiver written against
            # rule.match does not KeyError on this shape.
            from app.models import JobWatchEvent as _WatchEvent

            events = db.execute(select(_WatchEvent).where(_WatchEvent.id.in_(watch_event_ids)).order_by(_WatchEvent.created_at)).scalars().all()
            payload = build_job_watch_payload(rule, job, list(events), total=len(watch_event_ids))
            is_test = False
        elif job_rule_match:
            # A `scope="job"` rule matched the job itself. No entity list to assemble — the
            # rule's criteria were about the job, and the payload says so.
            payload = build_job_rule_payload(rule, job)
            is_test = False
        else:
            entity_ids = db.execute(select(IntelRuleMatch.entity_id).where(IntelRuleMatch.id.in_(match_ids))).scalars().all() if match_ids else []
            entities = db.execute(select(Entity).where(Entity.id.in_(entity_ids))).scalars().all() if entity_ids else []

            payload = build_payload(rule, job, list(entities), total=len(match_ids))
            is_test = not match_ids and job_id is None
            if is_test:
                payload["event"] = "rule.test"
                payload["test"] = True
        body = json_dumps(payload)
        if isinstance(body, str):
            body = body.encode("utf-8")

        secret = None
        if rule.webhook_secret_encrypted:
            from app.auth.api_tokens import decrypt_secret

            secret = decrypt_secret(rule.webhook_secret_encrypted)

        extra = {}
        if rule.webhook_headers_json:
            try:
                loaded = json_loads(rule.webhook_headers_json)
                if isinstance(loaded, dict):
                    extra = loaded
            except Exception:
                _log.warning("webhook rule %s has unparseable headers_json; ignoring", rule_id)

        ts = str(int(time.time()))
        signature = sign(secret, ts, body) if secret else None
        headers = delivery_headers(rule_id, ts, signature, extra, event=payload["event"])

        started = time.monotonic()
        status, error = None, None
        # Every validated address is equally safe to connect to, so a connection failure
        # falls through to the next one — `localhost` is `::1` and `127.0.0.1`, and a receiver
        # listening on one family was otherwise never reached. Only on a connection failure
        # (no HTTP status): an HTTP answer is the receiver's, and asking again would deliver
        # twice. One attempt, one WebhookDelivery row, however many addresses it took.
        deadline = started + float(settings.webhook_timeout_seconds)
        for pinned_ip in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error = "timed out"
                break
            status, error = send(
                rule.webhook_url,
                body,
                headers,
                timeout=remaining,
                method=(rule.webhook_method or "POST"),
                pin_ip=pinned_ip,
            )
            if status is not None or not (error or "").startswith("ConnectError:"):
                break
        ms = int((time.monotonic() - started) * 1000)
        ok = status is not None and 200 <= status < 300
        _record(ok, status, error, ms)
        if ok:
            return

        # A test delivery is a one-shot diagnostic: retrying it would hide the failure the
        # person clicking the button is trying to see.
        terminal_4xx = status is not None and 400 <= status < 500 and status != 429
        if is_test or terminal_4xx or attempt >= max(0, settings.webhook_max_retries) + 1:
            return
        # Every payload-selecting kwarg has to ride the retry. Drop one and the second
        # attempt sends a *different message* than the first — a `job.match` retry would
        # arrive as a `rule.match` with an empty entity list, which the receiver would
        # accept and misread rather than reject.
        retry_kwargs = {}
        if watch_event_ids:
            retry_kwargs["watch_event_ids"] = watch_event_ids
        if job_rule_match:
            retry_kwargs["job_rule_match"] = True
        deliver_webhook.schedule(
            args=(rule_id, job_id, match_ids, attempt + 1),
            kwargs=retry_kwargs or None,
            delay=min(60 * (2 ** (attempt - 1)), 900),
        )
    except Exception as exc:
        _log.warning("webhook delivery failed for rule %s job %s: %s", rule_id, job_id, exc)
        db.rollback()
        # Record the failure. Without this an unexpected error (a missing optional
        # dependency, a serialization bug) leaves the rule's Deliveries tab empty, which
        # the owner reads as "it never fired" rather than "it fired and broke".
        try:
            db.add(
                WebhookDelivery(
                    rule_id=rule_id,
                    job_id=job_id,
                    match_count=len(match_ids),
                    attempt=attempt,
                    status_code=None,
                    ok=False,
                    error_message=f"{type(exc).__name__}: {exc}"[:280],
                    duration_ms=None,
                )
            )
            db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


def _job_dicts_for_ai(job: AnalysisJob, db) -> tuple[dict, list[dict], dict]:
    """Project a job into the plain dicts ``app.ai.digest`` consumes.

    The conversion lives here, in the impure half, precisely so ``digest.py`` never sees an
    ORM instance — it is a pure module and must stay testable without a database.

    Everything read here is already in the database, so this still works for a job whose
    raw tool output was removed by ``JOB_OUTPUT_RETENTION_DAYS``.
    """
    from sqlalchemy import select

    from app.ai.digest import select_top_findings
    from app.constants import SEVERITY_ORDER

    severity_summary = dict.fromkeys(SEVERITY_ORDER, 0)
    if job.severity_summary:
        try:
            severity_summary.update(json_loads(job.severity_summary))
        except (ValueError, TypeError):
            pass

    job_meta = {
        "id": job.id,
        "filename": job.filename if job.log_file else "",
        "log_type": enum_val(job.effective_log_type) if job.log_file and job.effective_log_type else "",
        "workflow": job.workflow.name if job.workflow else "",
        "status": enum_val(job.status),
        "score_ratio": job.score_ratio or "",
        "severity_summary": severity_summary,
        "created_at": job.created_at.isoformat() if job.created_at else "",
    }

    findings: list[dict] = []
    for tr in job.task_results:
        for f in tr.findings:
            try:
                tags = json_loads(f.tags or "[]")
            except (ValueError, TypeError):
                tags = []
            findings.append(
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": enum_val(f.severity),
                    "count": f.count or 0,
                    "tool": tr.tool_name,
                    "tags": tags if isinstance(tags, list) else [],
                    "events": [],
                }
            )

    # Sample events are attached only to the findings that survive the digest's cap.
    # `Finding.details` is deferred, so touching it on every finding is one query each and,
    # on a noisy job, megabytes of event JSON read to use three events from forty rows.
    # One `IN` query for exactly the kept ids instead.
    wanted = {f["id"] for f in select_top_findings(findings) if f.get("id") is not None}
    if wanted:
        rows = db.execute(select(Finding.id, Finding.details).where(Finding.id.in_(wanted))).all()
        details_by_id = {}
        for fid, raw in rows:
            try:
                parsed = json_loads(raw or "[]")
            except (ValueError, TypeError):
                parsed = []
            details_by_id[fid] = parsed if isinstance(parsed, list) else []
        for f in findings:
            f["events"] = details_by_id.get(f["id"], [])

    analytics = {}
    if job.analytics_json:
        try:
            loaded = json_loads(job.analytics_json)
            analytics = loaded if isinstance(loaded, dict) else {}
        except (ValueError, TypeError):
            analytics = {}

    return job_meta, findings, analytics


def _unexpected_error_message(exc: BaseException) -> str:
    """What an admin is shown when a run dies for a reason the code did not anticipate.

    A bare exception *type* is honest but unactionable — "unexpected error: PermissionError"
    tells you something was denied and nothing about what. For `OSError` and its subclasses
    (PermissionError, FileNotFoundError, OSError itself) the useful detail is `filename`,
    which is a filesystem path and carries no credential, so it is safe to surface where
    `str(exc)` would not be. These are the realistic production causes: a read-only volume,
    a bad bind mount, or files owned by the wrong user after a deploy.

    Everything else stays type-only. The full traceback goes to the worker log instead.
    """
    name = type(exc).__name__
    if isinstance(exc, OSError):
        target = getattr(exc, "filename", None)
        detail = f" on {target}" if target else ""
        return f"unexpected error: {name}{detail} — the worker could not access a file it needs. Check permissions and mounts on the worker host."[:500]
    return f"unexpected error: {name} — see the worker log for the traceback."[:500]


class _AiRunWatch:
    """Heartbeat *and* cancel flag for one AI run, in a single thread.

    Two facts about a run that another process needs, so both live in Redis rather than in
    this worker: is anyone still working on it, and has someone asked it to stop. They share
    a thread because they share a cadence — a cancel flag noticed a minute late is not worth
    having, and refreshing a TTL key on the same tick costs one ``SET``.

    The heartbeat is what separates a slow model from a dead worker: with no liveness key, a
    worker restarted mid-inference leaves the row at ``running`` and nothing can tell that
    apart from a model that is simply slow.

    Beating continues after the cancel latches, deliberately. A run being torn down is not
    an abandoned run, and letting the key lapse during teardown would invite another process
    to finalise a row this one is still writing.
    """

    POLL_SECONDS = 2.0

    def __init__(self, analysis_id: int, *, scope: str = "") -> None:
        self._hb_key = f"{AI_HEARTBEAT_PREFIX}{scope}{analysis_id}"
        self._cancel_key = f"{AI_CANCEL_PREFIX}{scope}{analysis_id}"
        # Never shorter than the poll interval by a comfortable margin, whatever the
        # operator set worker_heartbeat_ttl to.
        self._ttl = max(int(settings.worker_heartbeat_ttl), 30)
        self.event = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> _AiRunWatch:
        self._beat()
        self._thread = threading.Thread(target=self._loop, name=f"ai-run-{self._hb_key}", daemon=True)
        self._thread.start()
        return self

    def cancelled(self) -> bool:
        return self.event.is_set()

    def _beat(self) -> None:
        try:
            get_redis().set(self._hb_key, _worker_id(), ex=self._ttl)
        except Exception:
            # Redis being unavailable must not fail a run that is otherwise fine; the
            # consequence is only that the run looks stale to the router.
            pass

    def _loop(self) -> None:
        while not self._stop.wait(self.POLL_SECONDS):
            self._beat()
            if self.event.is_set():
                continue
            try:
                if get_redis().exists(self._cancel_key):
                    self.event.set()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        # The run is terminal: drop both keys rather than leave them to expire. A stale
        # cancel flag would abort the *next* run of the same id — there isn't one — but a
        # stale heartbeat would make a finished run look live, which the router reads.
        try:
            r = get_redis()
            r.delete(self._hb_key)
            r.delete(self._cancel_key)
        except Exception:
            pass


class _AiRunLog:
    """The run's trace, accumulated in memory and flushed to ``JobAiAnalysis.log_output``.

    Written *while the run happens*, not at the end. That is the entire point: a trace that
    only lands once the run finishes documents something the user has already stopped
    waiting for. It is the same thing ``TaskResult.log_output`` does for a tool, and it is
    capped the same way — tail-kept, with the ``...[truncated]...`` marker
    ``workers/utils._combine_logs`` uses, because on a run in flight the last line is the
    one being asked about.

    **Every line is written immediately — no throttle.** Lines are only produced when
    something happens, so a time-based throttle withholds a line and then has no later event
    to release it on — and the longest gap in a run is the silent one between the request
    being sent and the first token arriving. Measured against a local llama3.2:3b on a
    33k-char brief, that gap is **26.9 seconds of prompt processing**: precisely the window
    where the user is asking "is this working?", and where a throttle would guarantee the log
    does not move. The cost is one small UPDATE per ``PROGRESS_EVERY_CHARS`` of output —
    some tens of writes across a run.
    """

    def __init__(self, db, analysis, *, max_chars: int | None = None) -> None:
        self._db = db
        self._analysis = analysis
        self._max = max_chars or settings.max_log_output_bytes
        self._lines: list[str] = []
        self._started = time.monotonic()

    def __call__(self, message: str) -> None:
        """Record one line. Shaped as a callable so it can be passed as ``on_progress``."""
        self.add(message)

    def add(self, message: str) -> None:
        elapsed = time.monotonic() - self._started
        self._lines.append(f"[{elapsed:7.1f}s] {message}")
        self.flush()

    def text(self) -> str:
        body = "\n".join(self._lines)
        if self._max and len(body) > self._max:
            body = "...[truncated]...\n" + body[-self._max :]
        return body

    def flush(self) -> None:
        """Write the trace to the row. Never raises — a failed log must not fail the run."""
        try:
            self._analysis.log_output = self.text()
            self._db.commit()
        except Exception:
            _log.debug("Could not flush the AI run log", exc_info=True)
            try:
                self._db.rollback()
            except Exception:
                pass


@huey.task(expires=settings.huey_queue_expiry)
def run_ai_analysis(analysis_id: int):
    _execute_ai_analysis(analysis_id)


@huey.task(expires=settings.huey_queue_expiry)
def run_case_ai_analysis(analysis_id: int):
    _execute_ai_analysis(analysis_id, case_run=True)


def _execute_ai_analysis(analysis_id: int, *, case_run: bool = False):
    """Send a job or case brief to a configured LLM and record the answer.

    Modelled on ``deliver_webhook``: sync session, and **every** failure is written to the
    row rather than swallowed. A run stuck at ``running`` forever is the worst outcome here
    — the pane polls until it reaches a terminal status, so an unrecorded exception spins a
    spinner indefinitely and reads as "it never fired".

    Not retried. A second call costs a second inference, and every failure this can produce
    (bad model name, wrong base URL, unreachable service, token limit) is a configuration
    problem that a retry repeats rather than resolves. The user re-runs when it is fixed.

    **Cancellable, and observable.** ``_AiRunWatch`` publishes a heartbeat and polls the
    cancel flag; ``_AiRunLog`` writes the trace to the row as the run happens. Without them,
    the only two things a waiting user could be told are "running" and, eventually, nothing.
    """
    from sqlalchemy import select, update
    from sqlalchemy.orm import selectinload

    from app.ai.client import CANCELLED_ERROR as AI_CANCELLED_ERROR
    from app.ai.client import run_completion
    from app.ai.digest import DEFAULT_SYSTEM_PROMPT, build_job_digest, render_prompt
    from app.auth.api_tokens import decrypt_secret
    from app.models import AiAnalysisStatus, AiProvider, CaseAiAnalysis, InvestigationCase, JobAiAnalysis, User, has_intel_access, visible_case_filter

    row_type = CaseAiAnalysis if case_run else JobAiAnalysis
    scope = "case:" if case_run else ""
    db = get_sync_session()
    watch: _AiRunWatch | None = None
    try:
        analysis = db.get(row_type, analysis_id)
        if analysis is None or enum_val(analysis.status) != "pending":
            # Already picked up (a duplicate delivery); do not run inference twice.
            return

        claimed = db.execute(update(row_type).where(row_type.id == analysis_id, row_type.status == AiAnalysisStatus.PENDING).values(status=AiAnalysisStatus.RUNNING))
        db.commit()
        if not claimed.rowcount:
            return
        db.refresh(analysis)

        runlog = _AiRunLog(db, analysis)

        def _finish(*, content: str | None, error: str | None, usage: dict | None = None, ms: int | None = None, prompt_chars: int | None = None) -> None:
            # Cancellation is its own terminal status, not a failure — the same distinction
            # `tools.base.CANCELLED_ERROR` draws for a tool. Without it a user who stops a
            # run is told the run broke.
            cancelled = error == AI_CANCELLED_ERROR
            if cancelled:
                analysis.status = AiAnalysisStatus.CANCELLED
                runlog.add("Stopped at the user's request.")
            else:
                analysis.status = AiAnalysisStatus.COMPLETED if content else AiAnalysisStatus.FAILED
                runlog.add(f"Run failed: {error}" if error else "Run completed.")
            analysis.content = content
            # A cancelled run leaves error_message empty: the status is the whole story, and
            # the literal string "cancelled" sitting in an error field reads like a fault.
            analysis.error_message = None if cancelled else (error or None)
            if usage:
                analysis.input_tokens = usage.get("input_tokens")
                analysis.output_tokens = usage.get("output_tokens")
            analysis.duration_ms = ms
            if prompt_chars is not None:
                analysis.prompt_chars = prompt_chars
            analysis.finished_at = utc_now_naive()
            analysis.log_output = runlog.text()
            db.commit()
            if not case_run:
                _notify_job_watchers_of_ai(db, analysis)

        # Switched off while it sat in the queue. "Off" is the promise that job data stops
        # going to a provider, so the route that queued the run is not the only place to ask.
        if not get_site_settings_sync(db).show_ai_analysis:
            runlog.add("AI analysis was switched off before this run started.")
            _finish(content=None, error="AI analysis was switched off on this instance before the run started", ms=0)
            return

        # The atomic claim owns the row now. Check queued cancellation before starting
        # the heartbeat or building evidence; duplicate deliveries never own these keys.
        watch = _AiRunWatch(analysis_id, scope=scope) if case_run else _AiRunWatch(analysis_id)
        if watch.cancelled() or (_ai_cancel_requested(analysis_id, scope=scope) if case_run else _ai_cancel_requested(analysis_id)):
            runlog.add("Cancelled before the run started.")
            _finish(content=None, error=AI_CANCELLED_ERROR, ms=0)
            return

        watch.start()
        runlog.add(f"Picked up by worker {_worker_id()}.")

        provider = db.get(AiProvider, analysis.provider_id) if analysis.provider_id else None
        if provider is None:
            _finish(content=None, error="the provider used for this run no longer exists")
            return

        max_prompt_chars = (provider.case_max_prompt_chars if case_run else provider.job_max_prompt_chars) or settings.ai_max_prompt_chars

        if case_run:
            from app.ai.case_digest import DEFAULT_SYSTEM_PROMPT as CASE_SYSTEM_PROMPT
            from app.ai.case_evidence import case_send_allowed, prepare_case_evidence

            requester = db.get(User, analysis.requested_by_user_id) if analysis.requested_by_user_id else None
            if not has_intel_access(requester):
                _finish(content=None, error="The requester no longer has access to Intel.")
                return
            case = db.scalar(select(InvestigationCase).where(InvestigationCase.id == analysis.case_id, visible_case_filter(requester)))
            if case is None:
                _finish(content=None, error="The case is no longer accessible to the requester.")
                return
            if not provider.enabled:
                _finish(content=None, error="The provider was disabled before this run started.")
                return
            try:
                prompt, meta, sources = prepare_case_evidence(db, case, requester, max_chars=max_prompt_chars)
            except ValueError as exc:
                _finish(content=None, error=str(exc))
                return
            analysis.source_jobs_json = sources
            analysis.evidence_captured_at = utc_now_naive()
            db.commit()
            system_prompt = provider.case_system_prompt or CASE_SYSTEM_PROMPT
        else:
            job = db.execute(
                select(AnalysisJob)
                .where(AnalysisJob.id == analysis.job_id)
                .options(
                    selectinload(AnalysisJob.log_file),
                    selectinload(AnalysisJob.workflow),
                    selectinload(AnalysisJob.task_results).selectinload(TaskResult.findings),
                )
            ).scalar_one_or_none()
            if job is None:
                _finish(content=None, error="the job was deleted before the analysis ran")
                return

            job_meta, findings, analytics = _job_dicts_for_ai(job, db)
            digest = build_job_digest(job=job_meta, findings=findings, analytics=analytics)
            prompt, meta = render_prompt(digest, max_chars=max_prompt_chars)
            system_prompt = provider.system_prompt or DEFAULT_SYSTEM_PROMPT

        # What the model is actually being shown. `findings_omitted` is the number that
        # matters when an answer looks thin — the brief announces its own truncation to the
        # model, and this says the same thing to the person reading the run.
        runlog.add(f"Brief built: {meta.get('findings_rendered', 0)} finding(s) included, {meta.get('findings_omitted', 0)} omitted.")
        runlog.add(f"Prompt is {meta.get('chars', 0)} characters (limit {max_prompt_chars}).")
        runlog.add(
            f"Provider {provider.name} [{provider.kind}] at {provider.base_url}, model {provider.model}, "
            f"max_output_tokens={provider.max_output_tokens}, timeout={provider.timeout_seconds or 300}s.",
        )
        # Written now rather than only in _finish, so the pane can show the brief's size
        # while the run is still in flight. It is the one number that says how much of this
        # job the model was actually given, and a user waiting three minutes deserves it
        # before the answer rather than with it.
        analysis.prompt_chars = meta.get("chars")
        # The brief itself, when the site setting allows it. Stored before the request goes
        # out, not after it returns: the question this answers is "what did we send them?",
        # and a run that fails or is cancelled is exactly when someone wants to know.
        if get_site_settings_sync(db).show_ai_prompt:
            analysis.prompt_text = prompt
            runlog.add("Prompt stored for review (Settings → show_ai_prompt).")
        runlog.flush()

        token = decrypt_secret(provider.api_token_encrypted) if provider.api_token_encrypted else None

        if case_run and not case_send_allowed(db, analysis):
            _finish(content=None, error="AI settings or evidence access changed before the request could be sent.")
            return

        text, usage, ms, error = run_completion(
            kind=provider.kind,
            base_url=provider.base_url,
            model=provider.model,
            token=token,
            system=system_prompt,
            user=prompt,
            temperature=provider.temperature,
            max_output_tokens=provider.max_output_tokens,
            timeout=float(provider.timeout_seconds or 300),
            require_public=settings.ai_require_public_host,
            cancel_event=watch.event,
            on_progress=runlog,
        )
        if usage.get("input_tokens") or usage.get("output_tokens"):
            runlog.add(f"Tokens: {usage.get('input_tokens') or '?'} in / {usage.get('output_tokens') or '?'} out.")
        _finish(content=text, error=error, usage=usage, ms=ms, prompt_chars=meta.get("chars"))
    except Exception as exc:
        # Same reasoning as deliver_webhook's catch-all: an unexpected error (a missing
        # optional dependency, a serialization bug) must still land on the row, or the pane
        # polls forever on a run that is not going to finish.
        #
        # `exc_info=True`, unlike the messages written to the row. The no-`str(exc)` rule
        # exists because httpx puts the request URL in its exception text and that URL can
        # carry a credential — it is a rule about what reaches the *database and the
        # browser*. A server-side log is where an unexpected exception's traceback belongs,
        # and without it this branch destroys the only evidence of what actually broke.
        _log.warning("AI analysis %s failed unexpectedly", analysis_id, exc_info=True)
        db.rollback()
        try:
            from app.models import AiAnalysisStatus as _Status

            row = db.get(row_type, analysis_id)
            # "cancelled" belongs in this set beside the other two: a run torn down on
            # request can still raise on the way out, and overwriting it with FAILED would
            # tell the user their own Stop broke something.
            if row is not None and enum_val(row.status) not in TERMINAL_AI_STATUSES:
                row.status = _Status.FAILED
                row.error_message = _unexpected_error_message(exc)
                row.finished_at = utc_now_naive()
                db.commit()
                # The second of the two terminal exits. `_finish` covers every other one
                # — including cancel-before-start, which calls it — but this branch writes
                # FAILED directly and never reaches it, so a watcher would hear nothing
                # about the failures most worth hearing about.
                if not case_run:
                    _notify_job_watchers_of_ai(db, row)
        except Exception:
            db.rollback()
    finally:
        # Before db.close(): stop() drops the heartbeat, and until it is gone the router
        # still reads this run as live.
        if watch is not None:
            watch.stop()
        db.close()


def _notify_job_watchers_of_ai(db, analysis) -> None:
    """Tell a job's watchers that an AI run reached a terminal state.

    **COMPLETED and FAILED only, never CANCELLED.** A cancel is a deliberate act by a
    person, and the only person who would be notified is the one who performed it. Leaving
    it out also takes two call sites out of scope: cancel-before-start (which routes through
    `_finish`) and `routers/ai.py`'s web-tier finalisation of a dead run. If that decision is
    ever reversed, the second of those is the one that will be missed, and it needs the
    *async* recorder.

    Never raises and never rolls back the caller: the analysis row is already terminal, and
    a notification failure must not undo the result it describes.
    """
    try:
        from app import job_watch
        from app.models import AiAnalysisStatus as _Status

        if analysis is None or analysis.status not in (_Status.COMPLETED, _Status.FAILED):
            return
        outcome = "finished" if analysis.status == _Status.COMPLETED else "failed"
        job_watch.record_events_sync(
            db,
            kind="ai",
            job_id=analysis.job_id,
            ref_id=analysis.id,
            # No actor: the requester *is* notified about their own run — see
            # `job_watch.should_notify` for why this one is the exception.
            actor_user_id=None,
            summary=f"AI analysis {outcome} ({analysis.provider_name or 'provider'})",
        )
        db.commit()
    except Exception as exc:
        _log.warning("job watch: could not record AI event for analysis %s: %s", getattr(analysis, "id", "?"), exc)
        db.rollback()


@huey.periodic_task(crontab(hour="4", minute="15"))
def prune_webhook_deliveries_periodic():
    """Daily prune of the watch-rule webhook delivery log."""
    with _ScheduledRun("prune_webhook_deliveries_periodic") as run:
        run.detail = _prune_webhook_deliveries_periodic_body() or ""


def _prune_webhook_deliveries_periodic_body():
    """Drop delivery-log rows older than WEBHOOK_DELIVERY_RETENTION_DAYS."""
    from datetime import timedelta

    from app.models import WebhookDelivery

    days = settings.webhook_delivery_retention_days
    if not days or days <= 0:
        return
    db = get_sync_session()
    try:
        cutoff = utc_now_naive() - timedelta(days=days)
        n = db.query(WebhookDelivery).filter(WebhookDelivery.created_at < cutoff).delete(synchronize_session=False)
        db.commit()
        if n:
            _log.info("pruned %d webhook delivery row(s) older than %d days", n, days)
        return f"{n} row(s) removed" if n else "nothing to remove"
    except Exception as exc:
        _log.warning("webhook delivery prune failed: %s", exc)
        db.rollback()
        raise  # so _ScheduledRun records it as failed rather than "ok"
    finally:
        db.close()


@huey.periodic_task(crontab(hour="3", minute="0"))
def prune_expired_api_tokens_periodic():
    """Daily hard-delete of long-revoked API tokens."""
    with _ScheduledRun("prune_expired_api_tokens_periodic") as run:
        run.detail = _prune_expired_api_tokens_periodic_body() or ""


def _prune_expired_api_tokens_periodic_body():
    """Daily hard-delete of ApiToken rows that have been revoked for >90 days."""
    from datetime import timedelta

    from app.models import ApiToken

    db = get_sync_session()
    try:
        cutoff = utc_now_naive() - timedelta(days=90)
        deleted = db.query(ApiToken).filter(ApiToken.revoked_at.isnot(None), ApiToken.revoked_at < cutoff).delete(synchronize_session=False)
        if deleted:
            db.commit()
            _log.info("prune_expired_api_tokens: deleted %d row(s)", deleted)
        return f"{deleted} row(s) removed" if deleted else "nothing to remove"
    except Exception as exc:
        _log.warning("prune_expired_api_tokens failed: %s", exc)
        db.rollback()
        raise  # so _ScheduledRun records it as failed rather than "ok"
    finally:
        db.close()


@huey.periodic_task(crontab(minute="20"))
def refresh_rule_lists_periodic():
    """Hourly: re-fetch the rule lists whose source URL is due."""
    with _ScheduledRun("refresh_rule_lists_periodic") as run:
        run.detail = _refresh_rule_lists_periodic_body() or ""


def _refresh_rule_lists_periodic_body():
    """Re-fetch every list bound to a URL whose `refresh_hours` has elapsed.

    **Hourly, not daily**, because the interval is per list: the task's job is to notice
    which are due, and a daily sweep would round every list's interval up to a day.

    Two rules, and both are about not making things worse than leaving the list alone:

    * **A failed fetch keeps the old values.** A feed that 404s, times out or answers with
      nothing must not empty a list that every rule on the instance tests — the failure is
      recorded on the row and shown to an admin instead. This is the `job:` fail-closed
      instinct pointed the other way: the safe direction here is to change nothing.
    * **One list's failure does not stop the others.** Each is its own try/except and its
      own commit, so a dead feed cannot hold the sweep's writer lock or starve the lists
      after it in the loop.
    """
    from app.intel.rule_list_fetch import FetchError, fetch_list_values, is_due
    from app.intel.rule_lists import ListSpec, write_list_sync
    from app.models import RuleList

    db = get_sync_session()
    refreshed = 0
    failed = 0
    try:
        now = utc_now_naive()
        rows = db.query(RuleList).filter(RuleList.source_url.isnot(None), RuleList.refresh_hours > 0).all()
        due = [r for r in rows if is_due(r.last_fetched_at, r.refresh_hours, now=now)]
        for row in due:
            try:
                values = fetch_list_values(row.source_url)
            except FetchError as exc:
                row.last_fetched_at = now
                row.last_fetch_ok = False
                row.last_fetch_error = str(exc)[:300]
                failed += 1
                _log.warning("refresh_rule_lists: %s failed: %s", row.name, exc)
            except Exception as exc:  # a feed must never take the sweep down
                row.last_fetched_at = now
                row.last_fetch_ok = False
                row.last_fetch_error = f"{type(exc).__name__}: {exc}"[:300]
                failed += 1
                _log.warning("refresh_rule_lists: %s failed: %s", row.name, exc)
            else:
                spec = ListSpec(name=row.name, match=row.match, description=row.description or "", values=values)
                # `seed_hash=None`: a URL-backed list is an edited list by construction, so
                # the seeder must stop putting the shipped values back over it.
                write_list_sync(db, row, spec, seed_hash=None)
                row.last_fetched_at = now
                row.last_fetch_ok = True
                row.last_fetch_error = None
                refreshed += 1
            db.commit()
        if not due:
            return "nothing due"
        return f"{refreshed} refreshed, {failed} failed"
    except Exception as exc:
        _log.warning("refresh_rule_lists failed: %s", exc)
        db.rollback()
        raise  # so _ScheduledRun records it as failed rather than "ok"
    finally:
        db.close()


@huey.periodic_task(crontab(hour="3", minute="30"))
def prune_enrichment_results_periodic():
    """Daily prune of stale cached enrichment results."""
    with _ScheduledRun("prune_enrichment_results_periodic") as run:
        run.detail = _prune_enrichment_results_periodic_body() or ""


def _prune_enrichment_results_periodic_body():
    """Daily hard-delete of EntityEnrichmentResult rows not fetched in >30 days."""
    from datetime import timedelta

    from app.models import EntityEnrichmentResult

    db = get_sync_session()
    try:
        cutoff = utc_now_naive() - timedelta(days=30)
        deleted = db.query(EntityEnrichmentResult).filter(EntityEnrichmentResult.fetched_at < cutoff).delete(synchronize_session=False)
        if deleted:
            db.commit()
            _log.info("prune_enrichment_results: deleted %d row(s)", deleted)
        return f"{deleted} row(s) removed" if deleted else "nothing to remove"
    except Exception as exc:
        _log.warning("prune_enrichment_results failed: %s", exc)
        db.rollback()
        raise  # so _ScheduledRun records it as failed rather than "ok"
    finally:
        db.close()


#: How long a soft-deleted comment's tombstone row is kept before it is hard-deleted.
#: Longer than the 90 days used for revoked API tokens:
#: those record an expired credential or a dismissed alert, whereas this records a
#: moderation action on a shared investigation surface, which an analyst may need to
#: account for well after the fact. The body is already blanked at delete time, so only
#: the metadata (who deleted, when) is removed here.
COMMENT_TOMBSTONE_RETENTION_DAYS = 180


@huey.periodic_task(crontab(hour="4", minute="30"))
def prune_deleted_comments_periodic():
    """Daily hard-delete of soft-deleted comment tombstones."""
    with _ScheduledRun("prune_deleted_comments_periodic") as run:
        run.detail = _prune_deleted_comments_periodic_body() or ""


def _prune_deleted_comments_periodic_body():
    """Daily hard-delete of Comment rows soft-deleted more than the retention window ago."""
    from datetime import timedelta

    from app.models import Comment

    db = get_sync_session()
    try:
        # utc_now_naive, not datetime.now(UTC): Comment.deleted_at is written naive, and
        # comparing an aware value against it raises on PostgreSQL.
        cutoff = utc_now_naive() - timedelta(days=COMMENT_TOMBSTONE_RETENTION_DAYS)
        # Filter on deleted_at, never on a blank body — deleted_at IS NOT NULL is the
        # actual soft-delete predicate every read path uses.
        deleted = db.query(Comment).filter(Comment.deleted_at.isnot(None), Comment.deleted_at < cutoff).delete(synchronize_session=False)
        if deleted:
            db.commit()
            _log.info("prune_deleted_comments: deleted %d row(s)", deleted)
        return f"{deleted} row(s) removed" if deleted else "nothing to remove"
    except Exception as exc:
        _log.warning("prune_deleted_comments failed: %s", exc)
        db.rollback()
        raise  # so _ScheduledRun records it as failed rather than "ok"
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def purge_orphaned_storage(bg_task_id: int | None = None):
    """Remove stored objects the database no longer knows about.

    The retention cleanup walks `AnalysisJob` rows, so anything whose row is already gone is
    permanently unreachable by it. This walks the *storage* instead.

    It re-scans rather than acting on the ids the admin was shown: a preview is advisory,
    and between rendering it and pressing the button a job can finish and legitimately
    claim a directory. Jobs still `pending` or `running` are excluded for that reason.
    """
    from app.models import LogFile
    from app.storage import get_storage
    from app.storage_usage import classify_objects

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")
        known_files = {row[0] for row in db.query(LogFile.stored_filename).all()}
        known_jobs = {row[0] for row in db.query(AnalysisJob.id).all()}
        active_jobs = {row[0] for row in db.query(AnalysisJob.id).filter(AnalysisJob.status.in_([JobStatus.PENDING, JobStatus.RUNNING])).all()}

        st = get_storage()
        report = classify_objects(
            st.iter_objects_sync(),
            known_filenames=known_files,
            known_job_ids=known_jobs,
            active_job_ids=active_jobs,
            now=time.time(),
            worker_alive_ttl=settings.worker_alive_ttl,
        )

        removed_jobs, removed_files = 0, 0
        freed = report.reclaimable_bytes

        # The snapshot predates the walk, which on S3 can take minutes: a job picked up in
        # the meantime has a directory the snapshot never heard of. Ask again, just before
        # deleting anything.
        orphan_job_ids = set(report.orphan_job_ids)
        if orphan_job_ids:
            orphan_job_ids -= {row[0] for row in db.query(AnalysisJob.id).filter(AnalysisJob.id.in_(orphan_job_ids)).all()}

        # Job directories go through the narrow per-job delete rather than a prefix wipe:
        # the same call the retention sweep uses, on a bucket that also holds every upload.
        for jid in sorted(orphan_job_ids):
            if st.delete_job_outputs_sync(jid):
                removed_jobs += 1
            if _bg_cancel_requested(bg_task_id):
                _finish_cancelled(db, bg_task_id, f"cancelled after {removed_jobs} directories")
                return

        for key in report.removable_keys:
            try:
                st.delete_sync(key)
                removed_files += 1
            except Exception:
                _log.debug("could not remove %s", key, exc_info=True)

        from app.workers.utils import humanbytes, plural

        detail = f"{plural(removed_jobs, 'orphaned output directory', 'orphaned output directories')}, {plural(removed_files, 'stray file')}, {humanbytes(freed)} reclaimed"
        _log.info("purge_orphaned_storage: %s", detail)
        _mark_bg_task(db, bg_task_id, "completed", detail=detail)
    except Exception as exc:
        _log.error("purge_orphaned_storage failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.task(expires=settings.huey_queue_expiry)
def vacuum_database(bg_task_id: int | None = None):
    """Rewrite a SQLite database file so freed pages return to the filesystem.

    SQLite-only. Deleting rows frees pages *inside* the file and never shrinks it, so after
    a large purge the disk usage is unchanged and the admin reasonably concludes the purge
    did nothing. PostgreSQL needs none of this.

    It takes an exclusive lock and rewrites the whole file, which is why it is a queued
    task with a confirm dialog rather than a button that blocks a request.
    """
    from sqlalchemy import text

    from app.database import sync_engine

    db = get_sync_session()
    try:
        _mark_bg_task(db, bg_task_id, "running")
        if sync_engine.url.get_backend_name() != "sqlite":
            _mark_bg_task(db, bg_task_id, "completed", detail="Not a SQLite database — PostgreSQL reclaims space automatically")
            return
        path = Path(sync_engine.url.database) if sync_engine.url.database else None
        before = path.stat().st_size if path and path.exists() else 0
        # Its own connection with autocommit: VACUUM cannot run inside a transaction.
        with sync_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("VACUUM"))
        after = path.stat().st_size if path and path.exists() else 0
        freed = max(0, before - after)
        from app.workers.utils import humanbytes

        detail = f"reclaimed {humanbytes(freed)}" if freed else "nothing to reclaim"
        _log.info("vacuum_database: %s", detail)
        _mark_bg_task(db, bg_task_id, "completed", detail=detail)
    except Exception as exc:
        _log.error("vacuum_database failed: %s", exc)
        _mark_bg_task(db, bg_task_id, "failed", error=str(exc))
    finally:
        db.close()


@huey.periodic_task(crontab(hour="5", minute="30"))
def prune_old_uploads_periodic():
    """Delete uploaded logs older than UPLOAD_RETENTION_DAYS, and the jobs that own them.

    **Off by default (`0`)**, unlike every other retention window here, and that asymmetry
    is deliberate: the other sweeps remove derived data that can be regenerated or was
    never the point, while this removes the evidence a user submitted. Deleting that on a
    schedule has to be something an operator switched on, not something they inherited.
    """
    with _ScheduledRun("prune_old_uploads_periodic") as run:
        run.detail = _prune_old_uploads_periodic_body() or ""


def _clear_job_references(db, job_id: int) -> None:
    """Clear every FK to analysisjob.id before the job row is deleted.

    The worker-side twin of the block in `routers/jobs.py::_delete_job`, and it exists for
    the same reason: none of these columns carries ondelete=, and AnalysisJob declares no
    parent-side relationship to most of them, so no cascade fires. `app/database.py` sets
    PRAGMA foreign_keys=ON, so a forgotten table is not a silent orphan on the sweep path —
    it is an IntegrityError on the commit, which rolls the rows back long after the upload
    has been removed from storage. tests/test_fk_cleanup_parity.py fails if a new FK to
    analysisjob.id appears.
    """
    from sqlalchemy import delete

    from app.ai.case_evidence import invalidate_case_sources
    from app.intel.entities import remove_entity_links_for_job_sync
    from app.models import CaseJobLink, Comment, IntelRuleMatch, JobAiAnalysis, JobRuleMatch, JobTag, JobWatch, JobWatchEvent, WebhookDelivery

    db.execute(invalidate_case_sources(job_id))
    # entity_job_link, entity_relationship_evidence and finding_entity_link.
    remove_entity_links_for_job_sync(db, job_id)
    db.execute(delete(Comment).where(Comment.job_id == job_id))
    db.execute(delete(JobAiAnalysis).where(JobAiAnalysis.job_id == job_id))
    db.execute(delete(CaseJobLink).where(CaseJobLink.job_id == job_id))
    db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.job_id == job_id))
    db.execute(delete(JobRuleMatch).where(JobRuleMatch.job_id == job_id))
    db.execute(delete(WebhookDelivery).where(WebhookDelivery.job_id == job_id))
    db.execute(delete(JobTag).where(JobTag.job_id == job_id))
    # Events before watches: an event references the watch as well as the job.
    db.execute(delete(JobWatchEvent).where(JobWatchEvent.job_id == job_id))
    db.execute(delete(JobWatch).where(JobWatch.job_id == job_id))


def _prune_old_uploads_periodic_body():
    from datetime import timedelta

    from app.models import LogFile
    from app.storage import get_storage

    days = settings.upload_retention_days
    if not days or days <= 0:
        return "retention disabled"
    db = get_sync_session()
    try:
        cutoff = utc_now_naive() - timedelta(days=days)
        st = get_storage()
        removed = 0
        # Batched on an id cursor like every other sweep, so a large backlog cannot hold
        # one transaction open for the whole run.
        last_id = 0
        while True:
            batch = db.query(LogFile).filter(LogFile.uploaded_at < cutoff, LogFile.id > last_id).order_by(LogFile.id).limit(100).all()
            if not batch:
                break
            last_id = batch[-1].id
            # Nothing is removed from storage until the commit lands. A rollback restores
            # the rows; it cannot restore the file, so deleting first would destroy an upload
            # while leaving its row pointing at nothing, retried every night, forever.
            doomed_jobs: list[int] = []
            doomed_uploads: list[str] = []
            for lf in batch:
                jobs = db.query(AnalysisJob).filter(AnalysisJob.file_id == lf.id).all()
                # A job still running owns its file; leave the pair for the next sweep
                # rather than pulling the input out from under the worker.
                if any(enum_val(j.status) in ("pending", "running") for j in jobs):
                    continue
                for job in jobs:
                    _clear_job_references(db, job.id)
                    db.delete(job)
                    doomed_jobs.append(job.id)
                db.delete(lf)
                doomed_uploads.append(lf.stored_filename)
                removed += 1
            db.commit()
            for job_id in doomed_jobs:
                st.delete_job_outputs_sync(job_id)
                forget_job_keys(job_id)
            for stored_filename in doomed_uploads:
                try:
                    st.delete_sync(stored_filename)
                except Exception:
                    _log.warning("could not remove %s", stored_filename, exc_info=True)
        if removed:
            _log.info("prune_old_uploads: removed %d upload(s) older than %d days", removed, days)
        return f"{removed} upload(s) removed" if removed else "nothing to remove"
    except Exception as exc:
        _log.warning("prune_old_uploads failed: %s", exc)
        db.rollback()
        raise  # so _ScheduledRun records it as failed rather than "ok"
    finally:
        db.close()


@huey.periodic_task(crontab(hour="5", minute="15"))
def prune_background_tasks_periodic():
    """Daily prune of finished BackgroundTask rows past BACKGROUND_TASK_RETENTION_DAYS.

    Without it the table only grows — one row per backfill, cleanup and recalculation.
    Only terminal rows are removed: a row still `pending` or
    `running` is either live or stuck, and the recover sweep is what settles that.
    """
    with _ScheduledRun("prune_background_tasks_periodic") as run:
        run.detail = _prune_background_tasks_periodic_body() or ""


def _prune_background_tasks_periodic_body():
    from datetime import timedelta

    days = settings.background_task_retention_days
    if not days or days <= 0:
        return "retention disabled"
    db = get_sync_session()
    try:
        cutoff = utc_now_naive() - timedelta(days=days)
        deleted = (
            db.query(BackgroundTask)
            .filter(
                BackgroundTask.finished_at.isnot(None),
                BackgroundTask.finished_at < cutoff,
            )
            .delete(synchronize_session=False)
        )
        if deleted:
            db.commit()
            _log.info("prune_background_tasks: deleted %d row(s)", deleted)
        return f"{deleted} row(s) removed" if deleted else "nothing to remove"
    except Exception as exc:
        _log.warning("prune_background_tasks failed: %s", exc)
        db.rollback()
        raise  # so _ScheduledRun records it as failed rather than "ok"
    finally:
        db.close()


@huey.periodic_task(crontab(hour="5", minute="0"))
def prune_activity_events_periodic():
    """Daily hard-delete of activity rows past ACTIVITY_RETENTION_DAYS.

    `0` keeps forever, and that is a deliberate escape hatch rather than an oversight:
    some deployments must retain an audit trail for a fixed period, and silently deleting
    one would be the worst possible default. The pruning logic itself lives in
    `app/activity.py` so the manual admin action and this sweep cannot diverge.
    """
    from app.activity import prune_sync

    with _ScheduledRun("prune_activity_events_periodic") as run:
        deleted = prune_sync(settings.activity_retention_days)
        run.detail = f"{deleted} row(s) removed" if deleted else "nothing to remove"
        if deleted:
            _log.info("prune_activity_events: deleted %d row(s)", deleted)


@huey.periodic_task(crontab(hour="4", minute="45"))
def cleanup_job_outputs_periodic():
    """Daily sweep of raw tool-output directories."""
    with _ScheduledRun("cleanup_job_outputs_periodic") as run:
        run.detail = _cleanup_job_outputs_periodic_body() or ""


def _cleanup_job_outputs_periodic_body():
    """Daily sweep of tool-output directories past JOB_OUTPUT_RETENTION_DAYS.

    The setting reads as a retention *policy*, so like every other retention knob here it has
    a daily task behind it: run only from the admin button, raw outputs on an unattended
    instance would accumulate without bound. On a public instance that is the disk-fill
    path: uploads are anonymous, and a full volume stops SQLite writes and the app with
    them.

    Same body as `cleanup_old_job_outputs`, called with no BackgroundTask row — an
    unattended sweep has no one watching a progress chip, and creating one daily would
    fill the admin task list with noise.
    """
    from app.retention import effective_retention

    # Through the shared resolver, like `cleanup_old_job_outputs` itself: gating on the
    # environment variable alone would ignore a window set on /admin/storage. The detail line
    # has to come from the same place, or the Scheduled panel names a window nobody set.
    resolver_db = get_sync_session()
    try:
        retention = effective_retention("job_output_retention_days", get_site_settings_sync(resolver_db))
    finally:
        resolver_db.close()

    if retention.disabled:
        return "retention disabled"
    cleanup_old_job_outputs.call_local(None)
    return f"swept outputs older than {retention.days} days"


def _finalize_job(db, job: AnalysisJob, any_success: bool, any_failure: bool, cancelled: bool = False, expected: tuple[JobStatus, ...] = (JobStatus.RUNNING,)):
    # Anything still unfinished here is a tool the watchdog gave up on: the parallel
    # `as_completed` loop is bounded by the summed per-tool timeouts, so an unkillable
    # tool reaches this point with its row untouched. Sweep before the roll-up, so the
    # row is excluded from `total_tools` the same way a cancelled one is.
    if cancelled:
        _sweep_unfinished_task_results(db, job.id, TaskStatus.CANCELLED, CANCEL_MSG_USER)
    else:
        _sweep_unfinished_task_results(db, job.id, TaskStatus.FAILED, "tool did not report a result before the job finished")

    _rollup_job_counts(db, job)

    values = {"finished_at": utc_now_naive()}
    if cancelled:
        status = JobStatus.CANCELLED
        values["error_message"] = job.error_message or CANCEL_MSG_USER
    elif any_failure and not any_success:
        status = JobStatus.FAILED
    elif any_failure:
        status = JobStatus.PARTIAL
    else:
        status = JobStatus.COMPLETED

    # Only from RUNNING: while the tools ran, the recovery sweep may have failed the job
    # (its heartbeat lapsed) or the cancel route may have cancelled it. The user has been
    # shown that status; overwriting it with this run's outcome would un-finalize the job.
    finalized = _set_job_status(db, job, status, expected=expected, **values)
    db.commit()
    if not finalized:
        _log.warning("Job %d was finalized elsewhere as %s while it ran — keeping that status", job.id, enum_val(job.status))
        return

    if cancelled:
        # Don't feed a truncated run into the per-workflow duration estimate.
        return

    # Rolling per-workflow duration average — the source of the job page's
    # "Estimated: ~Xm Ys remaining". Both operands must be naive: with
    # `expire_on_commit=False`, `job.finished_at` keeps the value assigned above while
    # `job.created_at` is naive from the DB, and an aware/naive subtraction raises.
    # The failure is logged rather than swallowed, so a broken estimate is visible.
    try:
        from app.redis_client import AVG_DURATION_PREFIX, get_redis

        if job.finished_at and job.created_at:
            duration_s = (job.finished_at - job.created_at).total_seconds()
            r = get_redis()
            avg_key = f"{AVG_DURATION_PREFIX}{job.workflow_id}"
            prev = r.get(avg_key)
            new_avg = float(prev) * 0.8 + duration_s * 0.2 if prev else duration_s
            r.set(avg_key, str(round(new_avg, 1)), ex=86400)
    except Exception:
        _log.warning("Job %d: could not update the workflow duration average", job.id, exc_info=True)
