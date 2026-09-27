"""What is on disk, what it costs, and what nothing owns any more.

Two halves, and the split matters:

**Classification is pure.** :func:`classify_objects` takes the stored objects and the sets
of keys the database still knows about, and returns the breakdown and the orphans. No
session, no filesystem, no Redis — which is what makes the four orphan kinds testable
without manufacturing a filesystem, and what keeps the two false-positive windows below
honest.

**Gathering is impure and memoised.** The `system_checks.run_all_cached` idiom: a
`threading.Lock` plus a TTL plus an explicit `force`. The lock matters at least as much as
the TTL, for the reason that module gives — the Rescan button has no debounce, and a double
click would otherwise start a second full walk.

A local walk is O(files), not O(bytes): the 1.7 GB development tree is 39 files and walks in
well under a second. The expensive case is **S3**, where `list_objects_v2` is one network
round trip per 1,000 keys. That is what the cache is for, and why the scan is capped.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.config import settings
from app.storage import free_bytes_for_uploads, get_storage

#: Bound on a single scan. A truncated scan reports it rather than quietly under-counting —
#: the `total_edges_is_floor` / `job_fanout_suppressed` convention.
MAX_ENTRIES_SCANNED = 200_000

#: Storage changes on the timescale of a job, not a page load. Same 300s window as the
#: check suite (`system_checks.CHECK_CACHE_TTL_SECONDS`). "Rescan" sends `force=1`.
CACHE_TTL_SECONDS = 300.0

#: A spool older than this belongs to an upload that died. Generous: a 500 MB upload over a
#: slow link is legitimately slow.
TMP_SPOOL_STALE_SECONDS = 3600

_JOB_DIR_RE = re.compile(r"^job_(\d+)[/\\]")
#: Per-download private copies made by the S3 backend, named `{pid}-{uuid}`.
_S3_CACHE_PREFIX = ".s3_cache"
_HEALTH_PROBE_PREFIX = ".health-probe-"
_TMP_SPOOL_RE = re.compile(r"^tmp\w*\.upload$")


@dataclass
class OrphanGroup:
    """One kind of unowned thing, with the cost of keeping it."""

    kind: str
    label: str
    detail: str
    count: int = 0
    bytes: int = 0
    #: A few examples, for the UI. Never the whole list — that is a file browser.
    samples: list[str] = field(default_factory=list)
    #: False when nothing can safely remove it from here.
    reclaimable: bool = True


@dataclass
class UsageReport:
    uploads_bytes: int = 0
    uploads_count: int = 0
    outputs_bytes: int = 0
    outputs_count: int = 0
    other_bytes: int = 0
    other_count: int = 0
    #: Largest single uploads and largest per-job output trees, for the Largest tab.
    largest_uploads: list[tuple[str, int]] = field(default_factory=list)
    largest_jobs: list[tuple[int, int]] = field(default_factory=list)
    orphans: list[OrphanGroup] = field(default_factory=list)
    #: Every job id with output on disk but no row — the full set, not just the samples,
    #: because the purge task acts on it. Bounded by the number of orphaned directories,
    #: which is a count of jobs rather than of files.
    orphan_job_ids: set[int] = field(default_factory=set)
    #: Full keys of the stray non-job files that can be removed (spools, stale cache).
    removable_keys: list[str] = field(default_factory=list)
    truncated: bool = False
    scanned: int = 0
    free_bytes: int | None = None
    backend: str = "local"
    error: str | None = None
    ran_at: float = 0.0

    @property
    def total_bytes(self) -> int:
        return self.uploads_bytes + self.outputs_bytes + self.other_bytes

    @property
    def reclaimable_bytes(self) -> int:
        return sum(group.bytes for group in self.orphans if group.reclaimable)


def job_id_of(key: str) -> int | None:
    """The job a stored key belongs to, or ``None`` if it is not job output."""
    match = _JOB_DIR_RE.match(key.replace("\\", "/"))
    return int(match.group(1)) if match else None


def classify_objects(
    objects,
    *,
    known_filenames: set[str],
    known_job_ids: set[int],
    active_job_ids: set[int],
    now: float,
    top_n: int = 10,
    worker_alive_ttl: int = 180,
) -> UsageReport:
    """Split the stored objects into uploads, outputs and leftovers. Pure.

    *known_filenames* is every `LogFile.stored_filename`; *known_job_ids* every job that
    still exists; *active_job_ids* the ones still `pending` or `running`.

    Two exclusions are load-bearing, and both are windows where a perfectly healthy
    instance looks like a broken one:

    - **A job still running owns its output directory** even though nothing has finished
      writing it. On S3 the tree is uploaded *after* the analytics pass, so mid-job it
      exists only locally and its row is not terminal.
    - **`.s3_cache/` belongs to a live reader.** A worker downloading a 400 MB upload holds
      a private copy for the length of the analysis; it is only garbage once no worker
      could still be using it, which is what `worker_alive_ttl` bounds.
    """
    report = UsageReport()
    upload_sizes: list[tuple[str, int]] = []
    job_sizes: dict[int, int] = {}

    missing_owner = OrphanGroup(
        kind="unowned_upload",
        label="Stored files with no database row",
        detail="Uploaded logs whose LogFile row is gone — normally a job deleted while storage was unreachable.",
    )
    orphan_outputs = OrphanGroup(
        kind="orphan_outputs",
        label="Output directories for jobs that no longer exist",
        detail="Left behind when a job row was removed without its files — the retention sweep walks jobs, so it can never reach these.",
    )
    stale_spools = OrphanGroup(
        kind="tmp_spool",
        label="Abandoned upload spools",
        detail="Partial uploads whose request died before the file was moved into place.",
    )
    stale_cache = OrphanGroup(
        kind="s3_cache",
        label="Stale worker download cache",
        detail="Per-download copies the S3 backend makes; these are older than any live worker could still be reading.",
    )

    for obj in objects:
        report.scanned += 1
        if report.scanned > MAX_ENTRIES_SCANNED:
            report.truncated = True
            break

        key = obj.key.replace("\\", "/")
        name = key.rsplit("/", 1)[-1]

        if key.startswith(_S3_CACHE_PREFIX + "/"):
            report.other_bytes += obj.size
            report.other_count += 1
            if now - obj.mtime > max(worker_alive_ttl, 180) * 4:
                _add(stale_cache, key, obj.size)
                report.removable_keys.append(key)
            continue

        if name.startswith(_HEALTH_PROBE_PREFIX):
            # The storage check's own probe file; it deletes itself, so a straggler is
            # noise rather than something to offer to remove.
            report.other_bytes += obj.size
            report.other_count += 1
            continue

        job_id = job_id_of(key)
        if job_id is not None:
            report.outputs_bytes += obj.size
            report.outputs_count += 1
            job_sizes[job_id] = job_sizes.get(job_id, 0) + obj.size
            if job_id not in known_job_ids and job_id not in active_job_ids:
                _add(orphan_outputs, key, obj.size)
                report.orphan_job_ids.add(job_id)
            continue

        if _TMP_SPOOL_RE.match(name):
            report.other_bytes += obj.size
            report.other_count += 1
            if now - obj.mtime > TMP_SPOOL_STALE_SECONDS:
                _add(stale_spools, key, obj.size)
                report.removable_keys.append(key)
            continue

        report.uploads_bytes += obj.size
        report.uploads_count += 1
        upload_sizes.append((key, obj.size))
        if key not in known_filenames:
            _add(missing_owner, key, obj.size)

    report.largest_uploads = sorted(upload_sizes, key=lambda pair: pair[1], reverse=True)[:top_n]
    report.largest_jobs = sorted(job_sizes.items(), key=lambda pair: pair[1], reverse=True)[:top_n]

    report.orphans = [group for group in (orphan_outputs, missing_owner, stale_spools, stale_cache) if group.count]
    return report


def _add(group: OrphanGroup, key: str, size: int, *, sample_cap: int = 5) -> None:
    group.count += 1
    group.bytes += size
    if len(group.samples) < sample_cap:
        group.samples.append(key)


# ── The impure half ───────────────────────────────────────────────────────────

_lock = threading.Lock()
_cached: UsageReport | None = None


def gather_usage_sync(*, known_filenames: set[str], known_job_ids: set[int], active_job_ids: set[int]) -> UsageReport:
    """Walk the backend and classify. Blocking — call through a threadpool."""
    report = UsageReport(backend=settings.storage_backend, ran_at=time.time())
    try:
        storage = get_storage()
        report = classify_objects(
            storage.iter_objects_sync(),
            known_filenames=known_filenames,
            known_job_ids=known_job_ids,
            active_job_ids=active_job_ids,
            now=time.time(),
            worker_alive_ttl=settings.worker_alive_ttl,
        )
    except Exception as exc:
        report.error = str(exc)
    report.backend = settings.storage_backend
    report.ran_at = time.time()
    # Reported for BOTH backends: the local volume still spools every upload and stages
    # every worker's output even on S3 — the case where running out of space is most
    # surprising.
    report.free_bytes = free_bytes_for_uploads()
    return report


def cached_usage(*, gather, force: bool = False) -> UsageReport:
    """Memoised :func:`gather_usage_sync`, `run_all_cached`-style.

    *gather* is a zero-argument callable so this module needs no database session — the
    router hands it one already bound to the ids it looked up.
    """
    global _cached
    with _lock:
        if not force and _cached is not None and (time.time() - _cached.ran_at) < CACHE_TTL_SECONDS:
            return _cached
        _cached = gather()
        return _cached


def reset_cache() -> None:
    """For tests, and for anything that has just changed what is on disk."""
    global _cached
    with _lock:
        _cached = None


# ── Database footprint ────────────────────────────────────────────────────────


def database_footprint_sync() -> dict:
    """Where the database's bytes are, using the database's own accounting.

    Deliberately **not** ``SUM(LENGTH(col))``. On PostgreSQL `Finding.details` is TOASTed,
    so `length()` forces a detoast per row across the largest table in the schema; it also
    ignores indexes entirely, ignores TOAST compression, and counts *characters* rather
    than bytes — which under-reports on exactly the Windows paths and command lines that
    fill that column.

    PostgreSQL therefore uses `pg_total_relation_size`, which is exact and O(1). SQLite has
    no portable per-table figure without the `dbstat` virtual table, which most CPython
    builds omit — so it probes for it and **says so** when it is unavailable rather than
    reporting a number it made up.
    """
    from sqlalchemy import text

    from app.database import sync_engine

    result: dict = {"backend": "", "total_bytes": None, "tables": [], "note": None, "error": None}
    try:
        with sync_engine.connect() as conn:
            dialect = conn.dialect.name
            result["backend"] = dialect
            if dialect == "postgresql":
                rows = conn.execute(
                    text(
                        "SELECT relname, pg_total_relation_size(c.oid) AS total, pg_indexes_size(c.oid) AS idx "
                        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE c.relkind = 'r' AND n.nspname = current_schema() "
                        "ORDER BY total DESC LIMIT 25"
                    )
                ).all()
                result["tables"] = [{"name": r[0], "bytes": int(r[1]), "index_bytes": int(r[2])} for r in rows]
                result["total_bytes"] = conn.execute(text("SELECT pg_database_size(current_database())")).scalar()
                return result

            # SQLite: the file itself is the honest total.
            page_count = conn.execute(text("PRAGMA page_count")).scalar() or 0
            page_size = conn.execute(text("PRAGMA page_size")).scalar() or 0
            result["total_bytes"] = int(page_count) * int(page_size)
            try:
                rows = conn.execute(text("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name ORDER BY 2 DESC LIMIT 25")).all()
                result["tables"] = [{"name": r[0], "bytes": int(r[1] or 0), "index_bytes": 0} for r in rows]
            except Exception:
                result["note"] = "Per-table sizes need SQLite's dbstat extension, which this build does not include. The total above is the database file."
    except Exception as exc:
        result["error"] = str(exc)
    return result


def sqlite_db_paths() -> list[Path]:
    """The database file and its sidecars, for a total that matches what `du` reports."""
    from app.database import sync_engine

    url = sync_engine.url
    if url.get_backend_name() != "sqlite" or not url.database:
        return []
    main = Path(url.database)
    return [p for p in (main, Path(str(main) + "-wal"), Path(str(main) + "-shm")) if p.exists()]
