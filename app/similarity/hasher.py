"""
TLSH-based file similarity: hash computation and nearest-neighbour lookup.
All functions are graceful — import errors and computation failures log warnings
and return empty/None rather than raising.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# Hard cap on TLSH candidates to compare — brute-force TLSH diff is O(N)
MAX_TLSH_CANDIDATES = 500


@dataclass
class SimilarFile:
    """A file matched by TLSH distance, returned by find_similar_files_async()."""

    log_file_id: int
    original_filename: str
    tlsh_hash: str
    distance: int
    job_id: int | None
    job_status: str | None


_TLSH_CHUNK_SIZE = 1024 * 1024  # 1 MB chunks for incremental hashing


def compute_tlsh(file_path: Path) -> str | None:
    """Return TLSH hex digest for *file_path*, or None on error / low entropy.

    Uses the incremental TLSH API to avoid loading the entire file into memory.
    """
    try:
        import tlsh
    except ImportError:
        log.warning("py-tlsh not installed; TLSH hash computation skipped.")
        return None
    try:
        hasher = tlsh.Tlsh()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(_TLSH_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        hasher.final()
        h = hasher.hexdigest()
        if not h or h == "TNULL":
            return None
        return h
    except Exception as exc:
        log.warning("TLSH computation failed for %s: %s", file_path, exc)
        return None


async def find_similar_files_async(db, tlsh_hash: str, exclude_file_id: int, threshold: int = 100, limit: int = 10, viewer=None) -> list[SimilarFile]:
    """Async version for FastAPI routes.

    ``viewer`` (``User | None``) scopes results to the latest job each file has
    that the viewer is allowed to see. Files whose only jobs are other users'
    private submissions are omitted entirely so their filenames never leak.
    """
    try:
        import tlsh
    except ImportError:
        return []

    from sqlalchemy import func as sqlfunc
    from sqlalchemy import select

    from app.models import AnalysisJob, LogFile, visible_job_filter

    result = await db.execute(select(LogFile).where(LogFile.tlsh_hash.isnot(None), LogFile.id != exclude_file_id).order_by(LogFile.id.desc()).limit(MAX_TLSH_CANDIDATES))
    files = result.scalars().all()

    # Pre-fetch the latest viewer-visible job per file in one query.
    file_ids = [lf.id for lf in files]
    latest_jobs: dict[int, tuple[int, str, str]] = {}
    if file_ids:
        vis = visible_job_filter(viewer)
        latest_job_q = select(AnalysisJob.file_id, sqlfunc.max(AnalysisJob.id).label("max_job_id")).where(AnalysisJob.file_id.in_(file_ids))
        if vis is not True:
            latest_job_q = latest_job_q.where(vis)
        latest_job_sq = latest_job_q.group_by(AnalysisJob.file_id).subquery()
        job_result = await db.execute(
            select(AnalysisJob.file_id, AnalysisJob.id, AnalysisJob.status, AnalysisJob.filename).join(
                latest_job_sq, (AnalysisJob.file_id == latest_job_sq.c.file_id) & (AnalysisJob.id == latest_job_sq.c.max_job_id)
            )
        )
        for fid, jid, jstatus, filename in job_result.all():
            status_str = jstatus.value if hasattr(jstatus, "value") else str(jstatus)
            latest_jobs[fid] = (jid, status_str, filename)

    results: list[SimilarFile] = []
    for lf in files:
        job_info = latest_jobs.get(lf.id)
        if job_info is None:
            # No job this viewer may see → hide the file (don't leak its name).
            continue
        try:
            dist = tlsh.diff(tlsh_hash, lf.tlsh_hash)
        except Exception:
            continue
        if dist <= threshold:
            results.append(
                SimilarFile(
                    log_file_id=lf.id,
                    original_filename=job_info[2],
                    tlsh_hash=lf.tlsh_hash,
                    distance=dist,
                    job_id=job_info[0],
                    job_status=job_info[1],
                )
            )

    results.sort(key=lambda x: x.distance)
    return results[:limit]
