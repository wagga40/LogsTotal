"""Public analysis metadata and comparisons, gated by each job's visibility."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, load_only, raiseload

from app import activity
from app.analysis_comparison import compare_findings_page, comparison_baselines
from app.analysis_confidence import job_provenance, task_metadata
from app.auth.users import current_user_optional
from app.constants import POST_TASK_NAMES, TERMINAL_JOB_STATUSES, is_post_processing_task
from app.database import INT4_MAX, get_async_session
from app.models import AnalysisJob, Finding, LogFile, TaskResult, User, enum_val
from app.routers.jobs import _can_view_private, _finding_export, _load_job_full
from app.templates_config import templates

router = APIRouter(prefix="/jobs")

_COMPARE_PAGE_SIZE = 100


async def _load(db: AsyncSession, job_id: int, user, *, blobs: tuple = ()) -> AnalysisJob:
    job = await _load_job_full(db, job_id, blobs=blobs)
    if job is None or not _can_view_private(job, user):
        raise HTTPException(404, "Job not found")
    return job


async def _load_comparison_job(db: AsyncSession, job_id: int, user: User | None) -> AnalysisJob:
    if not 0 < job_id <= INT4_MAX:
        raise HTTPException(404, "Job not found")
    job = await db.scalar(
        select(AnalysisJob)
        .where(AnalysisJob.id == job_id)
        .options(
            load_only(
                AnalysisJob.id,
                AnalysisJob.file_id,
                AnalysisJob.status,
                AnalysisJob.created_at,
                AnalysisJob.execution_snapshot,
                AnalysisJob.is_private,
                AnalysisJob.submitted_by_user_id,
                raiseload=True,
            ),
            joinedload(AnalysisJob.log_file).load_only(LogFile.id, LogFile.sha256, raiseload=True),
            raiseload("*"),
        )
    )
    if job is None or not _can_view_private(job, user):
        raise HTTPException(404, "Job not found")
    return job


async def _comparison_task_metadata(db: AsyncSession, job_ids: list[int]) -> dict[int, list[dict]]:
    # Version recovery needs only the startup banner, never the entire tool log.
    rows = await db.execute(
        select(
            TaskResult.id,
            TaskResult.job_id,
            TaskResult.tool_name,
            TaskResult.status,
            TaskResult.execution_snapshot,
            TaskResult.diagnostics_json,
            func.substr(TaskResult.log_output, 1, 2048).label("log_output"),
        )
        .where(TaskResult.job_id.in_(job_ids), TaskResult.tool_name.not_in(POST_TASK_NAMES))
        .order_by(TaskResult.id)
    )
    result = {job_id: [] for job_id in job_ids}
    for row in rows:
        result[row.job_id].append(task_metadata(row))
    return result


@router.get("/{job_id}/analysis.json")
async def analysis_report(job_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    # rule_content only, for rule_author: the report never serialises the sampled events.
    job = await _load(db, job_id, user, blobs=(Finding.rule_content,))
    await activity.record("export.job_analysis", request=request, user=user, target_type="job", target_id=str(job_id))
    tasks = []
    for task in job.task_results:
        if is_post_processing_task(task.tool_name):
            continue
        metadata = task_metadata(task)
        metadata["findings"] = [_finding_export(task.tool_name, f) for f in task.findings]
        tasks.append(metadata)
    return JSONResponse(
        {"schema_version": 1, "job_id": job.id, "status": enum_val(job.status), "input_sha256": job.log_file.sha256, "provenance": job_provenance(job), "tasks": tasks},
        headers={"Content-Disposition": f"attachment; filename=job_{job.id}_analysis.json"},
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
    current = await _load_comparison_job(db, job_id, user)
    if enum_val(current.status) not in TERMINAL_JOB_STATUSES:
        raise HTTPException(409, "Wait for the analysis to finish before comparing runs")
    if baseline is not None and baseline > INT4_MAX:
        # No row can have it, and binding it is a 500 on both backends.
        raise HTTPException(404, "Job not found")
    baselines = await comparison_baselines(db, current, user)
    if baseline is None:
        baseline = baselines[0]["id"] if baselines else None
    previous = await _load_comparison_job(db, baseline, user) if baseline is not None else None
    if previous is not None:
        if enum_val(previous.status) not in TERMINAL_JOB_STATUSES:
            raise HTTPException(409, "Wait for the baseline analysis to finish")
        if not any(option["id"] == previous.id for option in baselines):
            raise HTTPException(400, "Choose an earlier finished run of the same file content")
    context = {
        "request": request,
        "user": user,
        "job": current,
        "baseline": previous,
        "baselines": baselines,
        "page": page,
    }
    headers = {"Vary": "HX-Request, HX-History-Restore-Request", "Cache-Control": "no-store"}
    fragment = request.headers.get("HX-Request") == "true" and request.headers.get("HX-History-Restore-Request") != "true"
    if fragment and previous:
        context.update(await compare_findings_page(db, previous.id, current.id, page=page, per_page=_COMPARE_PAGE_SIZE))
        history = "HX-Replace-Url" if request.headers.get("HX-Trigger") in {"comparison-results", "comparison-retry"} else "HX-Push-Url"
        headers[history] = f"/jobs/{current.id}/compare?baseline={previous.id}&page={context['page']}"
        return templates.TemplateResponse(request, "partials/_analysis_comparison_results.html", context, headers=headers)
    tasks = await _comparison_task_metadata(db, [current.id, previous.id] if previous else [current.id])
    context.update(
        {
            "current_provenance": job_provenance(current),
            "baseline_provenance": job_provenance(previous) if previous else None,
            "current_tasks": tasks[current.id],
            "baseline_tasks": tasks[previous.id] if previous else [],
        }
    )
    return templates.TemplateResponse(request, "analysis_compare.html", context, headers=headers)
