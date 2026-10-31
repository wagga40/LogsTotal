"""Event-store lifecycle: request at job claim, build in a supervised subprocess, publish, delete.

Sync (the worker's side). Never imports duckdb or `app.events.build`: the build runs as
`python -m app.events.build`, so its memory and its engine stay out of the Huey process, and a
timeout, a kill or the RSS watchdog takes down the whole process group.

A store is a derived cache of an upload. Every state change is a conditional UPDATE, so two
workers, a sweep and a delete can race without corrupting anything: whoever loses the UPDATE
cleans up what it made.
"""

from __future__ import annotations

import logging
import shutil
import sys
import uuid
from pathlib import Path

from sqlalchemy import select, update

from app.config import settings
from app.database import utc_now_naive
from app.events.manifest import BUILDER_VERSION, ManifestError, validate_manifest
from app.json_utils import dumps as json_dumps
from app.models import EventStore, EventStoreStatus, LogFile

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_STAGING = ".events_build"
#: Failed builds are retried by the sweep, at most this many attempts in all.
MAX_ATTEMPTS = 3
_RESTARTABLE = (EventStoreStatus.PENDING.value, EventStoreStatus.FAILED.value, EventStoreStatus.EVICTED.value)


def store_key(log_file_id: int, log_type: str) -> tuple[int, str, int]:
    return log_file_id, log_type, BUILDER_VERSION


def request_build_sync(db, *, log_file_id: int, log_type: str, job_id: int | None) -> int | None:
    """Make sure a store is built or on its way; return the row id to enqueue, or None.

    None when there is nothing to do: the switch is off, a store is ready, or one is already
    building. The caller commits, then enqueues: a task must never run before its row exists.
    """
    if not settings.events_enabled or not log_type:
        return None
    row = db.scalar(select(EventStore).where(EventStore.log_file_id == log_file_id, EventStore.log_type == log_type, EventStore.builder_version == BUILDER_VERSION))
    if row is None:
        row = EventStore(
            log_file_id=log_file_id,
            log_type=log_type,
            builder_version=BUILDER_VERSION,
            status=EventStoreStatus.PENDING.value,
            requested_by_job_id=job_id,
            attempts=0,
            truncated=False,
        )
        db.add(row)
        db.flush()
        return row.id
    if row.status in (EventStoreStatus.READY.value, EventStoreStatus.BUILDING.value):
        return None
    if row.status == EventStoreStatus.FAILED.value and row.attempts >= MAX_ATTEMPTS:
        return None
    if row.status in _RESTARTABLE:
        row.status = EventStoreStatus.PENDING.value
        row.requested_by_job_id = job_id
        return row.id
    return None


def _claim(db, store_id: int) -> bool:
    claimed = db.execute(
        update(EventStore)
        .where(EventStore.id == store_id, EventStore.status.in_(_RESTARTABLE))
        .values(status=EventStoreStatus.BUILDING.value, started_at=utc_now_naive(), attempts=EventStore.attempts + 1, error_message=None)
    ).rowcount
    db.commit()
    return bool(claimed)


def _rss_watchdog(limit_bytes: int):
    from app.procutil import rss_bytes

    def check(proc) -> str | None:
        used = rss_bytes(proc.pid)
        if used is not None and used > limit_bytes:
            return f"store build used {used // (1 << 20)} MB, past EVENTS_BUILD_MAX_RSS_MB ({limit_bytes // (1 << 20)} MB)"
        return None

    return check


def _fail(db, store_id: int, message: str) -> None:
    db.execute(
        update(EventStore)
        .where(EventStore.id == store_id, EventStore.status == EventStoreStatus.BUILDING.value)
        .values(status=EventStoreStatus.FAILED.value, error_message=message[:2000], finished_at=utc_now_naive())
    )
    db.commit()


def run_build(db, store_id: int) -> str:
    """Claim, build, validate, publish. Returns a one-line outcome; never raises."""
    from app.procutil import run_supervised
    from app.storage import free_bytes_for_uploads, get_storage

    if not _claim(db, store_id):
        return "not claimable (ready, building elsewhere, or gone)"
    row = db.get(EventStore, store_id)
    log_file = db.get(LogFile, row.log_file_id) if row else None
    if row is None or log_file is None:
        if row is not None:
            _fail(db, store_id, "the upload no longer exists")
        return "upload gone"
    needed = 2 * (log_file.size_bytes or 0) + settings.events_min_free_disk_mb * (1 << 20)
    free = free_bytes_for_uploads()
    if free is not None and free < needed:
        _fail(db, store_id, f"not enough free disk: {free // (1 << 20)} MB, needs {needed // (1 << 20)} MB")
        return "no disk"
    st = get_storage()
    staging = Path(settings.upload_dir) / _STAGING / f"{store_id}-{uuid.uuid4().hex[:8]}"
    source = None
    gen = f"{row.log_type}-b{BUILDER_VERSION}-{uuid.uuid4().hex[:8]}"
    try:
        source = st.load_sync(log_file.stored_filename)
        cmd = [
            sys.executable,
            "-m",
            "app.events.build",
            "--input",
            str(source),
            "--log-type",
            row.log_type,
            "--out",
            str(staging),
            "--source-sha256",
            log_file.sha256 or "",
            "--reference",
            (log_file.uploaded_at or utc_now_naive()).isoformat(),
            "--threads",
            str(settings.events_build_threads),
            "--memory-mb",
            str(settings.events_build_memory_mb),
            "--max-events",
            str(settings.events_max_events),
            "--max-columns",
            str(settings.events_max_columns),
            "--text-index",
            "1" if settings.events_text_index else "0",
        ]
        rc, _out, err = run_supervised(cmd, timeout=settings.events_build_timeout_seconds, on_tick=_rss_watchdog(settings.events_build_max_rss_mb * (1 << 20)), cwd=PROJECT_ROOT)
        if rc != 0:
            tail = (err or "").strip().splitlines()[-1:] or [f"exit code {rc}"]
            _fail(db, store_id, f"store build failed: {tail[0]}")
            return "build failed"
        manifest = validate_manifest(staging)
        # Recorded before publishing: a storage purge running while S3 uploads the files must
        # see them as this row's, not as an orphan to delete.
        db.execute(update(EventStore).where(EventStore.id == store_id, EventStore.status == EventStoreStatus.BUILDING.value).values(gen=gen))
        db.commit()
        size = st.publish_event_store_sync(log_file.sha256, gen, staging)
        ready = db.execute(
            update(EventStore)
            .where(EventStore.id == store_id, EventStore.status == EventStoreStatus.BUILDING.value)
            .values(
                status=EventStoreStatus.READY.value,
                gen=gen,
                event_count=manifest["totals"]["events"],
                column_count=len(manifest["columns"]),
                bytes=size,
                time_min=_parse(manifest["time"]["min"]),
                time_max=_parse(manifest["time"]["max"]),
                truncated=bool(manifest["totals"]["truncated"]),
                warnings_json=json_dumps(manifest.get("warnings") or []),
                finished_at=utc_now_naive(),
            )
        ).rowcount
        db.commit()
        if not ready:
            # Deleted or reset while it built: the files are nobody's.
            st.delete_event_store_sync(log_file.sha256, gen)
            return "superseded while building"
        return f"{manifest['totals']['events']} events in {manifest.get('build_seconds')} s"
    except ManifestError as exc:
        _fail(db, store_id, f"invalid store: {exc}")
        return "invalid"
    except Exception as exc:
        logger.exception("Event store %d: build failed", store_id)
        db.rollback()
        _fail(db, store_id, f"store build failed: {exc}")
        return "error"
    finally:
        if source is not None:
            st.release_sync(source)
        shutil.rmtree(staging, ignore_errors=True)


def _parse(value: str | None):
    from datetime import datetime

    return datetime.fromisoformat(value) if value else None


def known_store_prefixes_sync(db) -> set[str]:
    """`events/{sha256}/{gen}` of every store a row still owns (building or ready)."""
    rows = db.execute(
        select(LogFile.sha256, EventStore.gen)
        .join(LogFile, LogFile.id == EventStore.log_file_id)
        .where(EventStore.gen.isnot(None), EventStore.status.in_([EventStoreStatus.BUILDING.value, EventStoreStatus.READY.value]))
    ).all()
    return {f"events/{sha}/{gen}" for sha, gen in rows if sha and gen}


async def known_store_prefixes_async(db) -> set[str]:
    rows = (
        await db.execute(
            select(LogFile.sha256, EventStore.gen)
            .join(LogFile, LogFile.id == EventStore.log_file_id)
            .where(EventStore.gen.isnot(None), EventStore.status.in_([EventStoreStatus.BUILDING.value, EventStoreStatus.READY.value]))
        )
    ).all()
    return {f"events/{sha}/{gen}" for sha, gen in rows if sha and gen}


def stores_for_file_sync(db, log_file_id: int) -> list[tuple[str, str]]:
    """Delete a file's store rows (the caller commits) and return the (sha256, gen) to remove
    from storage *after* the commit — rows first, files last, as for uploads."""
    log_file = db.get(LogFile, log_file_id)
    rows = db.scalars(select(EventStore).where(EventStore.log_file_id == log_file_id)).all()
    doomed = [(log_file.sha256, r.gen) for r in rows if r.gen and log_file is not None]
    for r in rows:
        db.delete(r)
    return doomed


async def stores_for_file_async(db, log_file_id: int) -> list[tuple[str, str]]:
    """The async twin, for the job-delete route."""
    log_file = await db.get(LogFile, log_file_id)
    rows = (await db.scalars(select(EventStore).where(EventStore.log_file_id == log_file_id))).all()
    doomed = [(log_file.sha256, r.gen) for r in rows if r.gen and log_file is not None]
    for r in rows:
        await db.delete(r)
    return doomed


def delete_store_files(doomed: list[tuple[str, str]]) -> None:
    from app.storage import get_storage

    st = get_storage()
    for sha256, gen in doomed:
        try:
            st.delete_event_store_sync(sha256, gen)
        except Exception:
            logger.warning("Could not remove event store %s/%s; the storage page lists it as an orphan", sha256, gen, exc_info=True)


def sweep_sync(db) -> tuple[list[int], str]:
    """The 10-minute safety net. Returns (store ids to enqueue after the commit, summary).

    - A pending row the queue dropped (tasks expire after HUEY_QUEUE_EXPIRY) is re-enqueued.
    - A building row past its timeout belongs to a worker that died: failed, then retried.
    - A failed row is retried with backoff, at most MAX_ATTEMPTS in all.
    - Ready stores idle past EVENTS_RETENTION_DAYS, or the least recently opened past
      EVENTS_MAX_TOTAL_MB, are evicted: files deleted, row kept, rebuilt on the next request.
    """
    from datetime import timedelta

    if not settings.events_enabled:
        return [], "switched off"
    now = utc_now_naive()
    requeue: list[int] = []
    stale = now - timedelta(seconds=settings.events_build_timeout_seconds + 600)
    dead = db.execute(
        update(EventStore)
        .where(EventStore.status == EventStoreStatus.BUILDING.value, EventStore.started_at < stale)
        .values(status=EventStoreStatus.FAILED.value, error_message="the build stopped responding (its worker restarted?)", finished_at=now)
    ).rowcount
    requeue += db.scalars(select(EventStore.id).where(EventStore.status == EventStoreStatus.PENDING.value, EventStore.requested_at < now - timedelta(minutes=5))).all()
    for row in db.scalars(select(EventStore).where(EventStore.status == EventStoreStatus.FAILED.value, EventStore.attempts < MAX_ATTEMPTS)).all():
        if row.finished_at is None or row.finished_at < now - timedelta(minutes=15 * max(1, row.attempts)):
            row.status = EventStoreStatus.PENDING.value
            requeue.append(row.id)
    evicted = 0
    ready = db.execute(
        select(EventStore, LogFile.sha256)
        .join(LogFile, LogFile.id == EventStore.log_file_id)
        .where(EventStore.status == EventStoreStatus.READY.value)
        .order_by(EventStore.last_accessed_at.is_(None).desc(), EventStore.last_accessed_at, EventStore.finished_at)
    ).all()
    doomed: list[tuple[str, str]] = []
    total = sum(row.bytes or 0 for row, _ in ready)
    cap = settings.events_max_total_mb * (1 << 20)
    cutoff = now - timedelta(days=settings.events_retention_days) if settings.events_retention_days > 0 else None
    for row, sha in ready:  # least recently opened first
        idle = cutoff is not None and (row.last_accessed_at or row.finished_at or now) < cutoff
        over = cap > 0 and total > cap
        if not (idle or over):
            continue
        if sha and row.gen:
            doomed.append((sha, row.gen))
        total -= row.bytes or 0
        row.status, row.gen, row.bytes = EventStoreStatus.EVICTED.value, None, None
        evicted += 1
    db.commit()
    delete_store_files(doomed)  # after the commit: a failed commit leaves files, never dangling rows
    parts = [f"{len(set(requeue))} re-enqueued"] if requeue else []
    if dead:
        parts.append(f"{dead} stalled build(s) failed")
    if evicted:
        parts.append(f"{evicted} evicted")
    return sorted(set(requeue)), ", ".join(parts) or "nothing to do"


def ready_store_for_job(db, job) -> tuple[EventStore, str] | None:
    """The job's ready store and its upload's sha256, or None."""
    from app.models import enum_val

    log_file = db.get(LogFile, job.file_id)
    log_type = enum_val(job.effective_log_type) if job.effective_log_type else (enum_val(log_file.log_type) if log_file else None)
    if log_file is None or not log_type:
        return None
    row = db.scalar(
        select(EventStore).where(
            EventStore.log_file_id == log_file.id, EventStore.log_type == log_type, EventStore.builder_version == BUILDER_VERSION, EventStore.status == EventStoreStatus.READY.value
        )
    )
    return (row, log_file.sha256) if row is not None and row.gen else None


def jobs_for_store_sync(db, store_id: int) -> list[int]:
    """Every job an overlay should exist for once this store is ready."""
    from app.models import AnalysisJob

    row = db.get(EventStore, store_id)
    if row is None or row.status != EventStoreStatus.READY.value:
        return []
    return list(db.scalars(select(AnalysisJob.id).where(AnalysisJob.file_id == row.log_file_id)).all())


def run_overlay(db, job_id: int) -> str:
    """Join one job's detections onto its upload's store. Idempotent; never raises."""
    import hashlib

    import orjson

    from app import job_artifacts
    from app.models import AnalysisJob
    from app.procutil import run_supervised
    from app.storage import get_storage

    job = db.get(AnalysisJob, job_id)
    if job is None:
        return "job gone"
    found = ready_store_for_job(db, job)
    if found is None:
        return "no ready store yet"
    row, sha256 = found
    links = job_artifacts.get_sync(db, job_id, job_artifacts.EVENT_LINKS)
    if links is None:
        return "no detection links (analysed before they were captured; recalculate analytics)"
    links_bytes = orjson.dumps(links)
    links_sha = hashlib.sha256(links_bytes).hexdigest()[:16]
    current = job_artifacts.get_sync(db, job_id, job_artifacts.EVENT_OVERLAY)
    if current and current.get("gen") == row.gen and current.get("links_sha") == links_sha:
        return "up to date"
    st = get_storage()
    staging = Path(settings.upload_dir) / _STAGING / f"overlay-{job_id}-{uuid.uuid4().hex[:8]}"
    staging.mkdir(parents=True, exist_ok=True)
    try:
        events = st.fetch_event_store_file_sync(sha256, row.gen, "events.parquet", staging / "store")
        (staging / "links.json").write_bytes(links_bytes)
        out = staging / "out"
        cmd = [
            sys.executable,
            "-m",
            "app.events.overlay",
            "--store",
            str(events.parent),
            "--links",
            str(staging / "links.json"),
            "--out",
            str(out),
            "--memory-mb",
            str(settings.events_build_memory_mb),
        ]
        rc, _o, err = run_supervised(cmd, timeout=settings.events_build_timeout_seconds, on_tick=_rss_watchdog(settings.events_build_max_rss_mb * (1 << 20)), cwd=PROJECT_ROOT)
        if rc != 0:
            tail = (err or "").strip().splitlines()[-1:] or [f"exit code {rc}"]
            logger.warning("Job %d: overlay failed: %s", job_id, tail[0])
            return f"overlay failed: {tail[0]}"
        import json

        meta = json.loads((out / "overlay.json").read_text())
        st.put_overlay_sync(sha256, row.gen, job_id, out)
        job_artifacts.put_sync(db, job_id, job_artifacts.EVENT_OVERLAY, {**meta, "gen": row.gen, "links_sha": links_sha, "store_id": row.id})
        db.commit()
        return f"{meta['detected_events']} detected events of {row.event_count}"
    except Exception as exc:
        db.rollback()
        logger.exception("Job %d: overlay failed", job_id)
        return f"overlay failed: {exc}"
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def overlay_locations_for_job_sync(db, job) -> list[tuple[str, str]]:
    """(sha256, gen) of every store of this job's upload, for deleting its overlay with the job."""
    log_file = db.get(LogFile, job.file_id)
    if log_file is None:
        return []
    return [(log_file.sha256, gen) for gen in db.scalars(select(EventStore.gen).where(EventStore.log_file_id == log_file.id, EventStore.gen.isnot(None))).all()]


async def overlay_locations_async(db, log_file_id: int) -> list[tuple[str, str]]:
    """The async twin of overlay_locations_for_job_sync, for the job-delete route."""
    log_file = await db.get(LogFile, log_file_id)
    if log_file is None:
        return []
    gens = (await db.scalars(select(EventStore.gen).where(EventStore.log_file_id == log_file_id, EventStore.gen.isnot(None)))).all()
    return [(log_file.sha256, gen) for gen in gens]
