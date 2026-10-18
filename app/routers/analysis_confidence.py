"""Public analysis metadata and comparisons, gated by each job's visibility."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, undefer

from app.analysis_comparison import compare_findings
from app.analysis_confidence import job_provenance, task_metadata
from app.auth.users import current_user_optional
from app.constants import TERMINAL_JOB_STATUSES, is_post_processing_task
from app.database import get_async_session
from app.json_utils import loads
from app.models import AnalysisJob, Finding, JobStatus, LogFile, TaskResult, User, enum_val, visible_job_filter
from app.rule_attribution import rule_author
from app.templates_config import templates

router = APIRouter(prefix="/jobs")


async def _load(db: AsyncSession, job_id: int, user, *, export: bool = False):
    findings = selectinload(AnalysisJob.task_results).selectinload(TaskResult.findings)
    if export:
        findings = findings.options(undefer(Finding.rule_content))
    job = await db.scalar(
        select(AnalysisJob)
        .where(AnalysisJob.id == job_id, visible_job_filter(user))
        .options(findings, selectinload(AnalysisJob.log_file))
        .execution_options(populate_existing=True)
    )
    if job is None:
        raise HTTPException(404, "Job not found")
    return job


@router.get("/{job_id}/analysis.json")
async def analysis_report(job_id: int, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    job = await _load(db, job_id, user, export=True)
    tasks = []
    for task in job.task_results:
        if is_post_processing_task(task.tool_name):
            continue
        metadata = task_metadata(task)
        metadata["findings"] = [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": enum_val(f.severity),
                "count": f.count,
                "tags": loads(f.tags or "[]"),
                "rule_author": rule_author(task.tool_name, f.rule_id, f.rule_content),
            }
            for f in task.findings
        ]
        tasks.append(metadata)
    return JSONResponse(
        {"schema_version": 1, "job_id": job.id, "status": enum_val(job.status), "input_sha256": job.log_file.sha256, "provenance": job_provenance(job), "tasks": tasks},
        headers={"Content-Disposition": f"attachment; filename=job_{job.id}_analysis.json", "Cache-Control": "private, no-store"},
    )


@router.get("/{job_id}/compare", response_class=HTMLResponse)
async def analysis_compare(
    job_id: int,
    request: Request,
    baseline: int | None = Query(None, gt=0),
    page: int = Query(1, ge=1),
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    current = await _load(db, job_id, user)
    if enum_val(current.status) not in TERMINAL_JOB_STATUSES:
        raise HTTPException(409, "Wait for the analysis to finish before comparing runs")
    if baseline is None:
        # Compare timestamps in the database: SQLite stores server defaults and
        # Python-bound datetimes with different fractional-second precision.
        current_time = select(AnalysisJob.created_at).where(AnalysisJob.id == current.id).scalar_subquery()
        baseline = await db.scalar(
            select(AnalysisJob.id)
            .join(LogFile)
            .where(
                LogFile.sha256 == current.log_file.sha256,
                AnalysisJob.status.in_([JobStatus(s) for s in TERMINAL_JOB_STATUSES]),
                or_(AnalysisJob.created_at < current_time, and_(AnalysisJob.created_at == current_time, AnalysisJob.id < current.id)),
                visible_job_filter(user),
            )
            .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
            .limit(1)
        )
    previous = await _load(db, baseline, user) if baseline is not None else None
    if previous is not None:
        if previous.id == current.id or previous.log_file.sha256 != current.log_file.sha256:
            raise HTTPException(400, "Choose two different runs of the same file content")
        if enum_val(previous.status) not in TERMINAL_JOB_STATUSES:
            raise HTTPException(409, "Wait for the baseline analysis to finish")
    rows = compare_findings(previous, current) if previous else []
    pages = max(1, (len(rows) + 99) // 100)
    page = min(page, pages)
    context = {
        "request": request,
        "user": user,
        "job": current,
        "baseline": previous,
        "rows": rows[(page - 1) * 100 : page * 100],
        "total": len(rows),
        "page": page,
        "pages": pages,
        "current_provenance": job_provenance(current),
        "baseline_provenance": job_provenance(previous) if previous else None,
        "current_tasks": [task_metadata(t) for t in current.task_results if not is_post_processing_task(t.tool_name)],
        "baseline_tasks": [task_metadata(t) for t in previous.task_results if not is_post_processing_task(t.tool_name)] if previous else [],
    }
    return templates.TemplateResponse(request, "analysis_compare.html", context, headers={"Cache-Control": "private, no-store"})
