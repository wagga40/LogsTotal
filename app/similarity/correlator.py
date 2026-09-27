"""
Rule-level cross-job correlation via stable rule_signature identifiers.
Pure Python helpers — no FastAPI or Huey imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CorrelatedFinding:
    """A finding from another job where the same rule fired."""

    job_id: int
    file_id: int
    original_filename: str
    rule_name: str
    severity: str
    count: int
    tool_name: str
    job_created_at: datetime


def make_rule_signature(rule_id: str | None, rule_name: str, severity: str) -> str:
    """Return a stable cross-job identifier: '{id_or_slug}:{severity}'.

    Prefers rule_id when available (UUID or tool-specific ID). Falls back to a
    URL-safe slug of rule_name. Result is deterministic and index-friendly.
    """
    if rule_id and rule_id.strip():
        id_part = rule_id.strip()
    else:
        id_part = re.sub(r"[^a-z0-9]+", "-", rule_name.lower()).strip("-") or "unknown"
    return f"{id_part}:{severity}"


async def find_correlated_findings_async(db, rule_signature: str, exclude_job_id: int, limit: int = 20, viewer=None) -> list[CorrelatedFinding]:
    """Async version for FastAPI routes.

    ``viewer`` (``User | None``) restricts correlated hits to jobs the viewer is
    allowed to see, so an attacker-supplied ``rule_signature`` cannot enumerate
    other users' private jobs.
    """
    from sqlalchemy import select

    from app.models import AnalysisJob, Finding, LogFile, TaskResult, visible_job_filter

    query = (
        select(Finding, TaskResult, AnalysisJob, LogFile)
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .join(AnalysisJob, TaskResult.job_id == AnalysisJob.id)
        .join(LogFile, AnalysisJob.file_id == LogFile.id)
        .where(Finding.rule_signature == rule_signature)
        .where(AnalysisJob.id != exclude_job_id)
    )
    vis = visible_job_filter(viewer)
    if vis is not True:
        query = query.where(vis)
    result = await db.execute(query.order_by(AnalysisJob.created_at.desc()).limit(limit))
    rows = result.all()
    return [
        CorrelatedFinding(
            job_id=job.id,
            file_id=lf.id,
            original_filename=job.filename,
            rule_name=f.rule_name,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            count=f.count,
            tool_name=tr.tool_name,
            job_created_at=job.created_at,
        )
        for f, tr, job, lf in rows
    ]
