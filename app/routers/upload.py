"""
Upload router — public (no auth required).
Handles file submission, type detection, workflow selection, job creation.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api_tokens import submission_access
from app.auth.users import current_user_optional
from app.config import settings
from app.database import get_async_session
from app.detection.detector import LOG_TYPE_LABELS, detect_log_type, detect_log_type_from_bytes
from app.json_utils import loads as json_loads
from app.models import User, WorkflowDef, has_intel_access
from app.site_settings import get_site_settings
from app.submissions import submit_file
from app.templates_config import templates
from app.workers.tasks import run_analysis

router = APIRouter()


@router.get("/")
async def index(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """Homepage with upload form and recent jobs."""
    site_settings = await get_site_settings(db)
    result = await db.execute(select(WorkflowDef).order_by(WorkflowDef.name))
    workflows = result.scalars().all()

    workflows_data = [
        {
            "id": wf.id,
            "name": wf.name,
            "description": (wf.description or "")[:60],
            "is_default": wf.is_default,
            "log_types": json_loads(wf.log_types or "[]"),
        }
        for wf in workflows
    ]

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "request": request,
            "user": user,
            "site_settings": site_settings,
            "workflows": workflows,
            "workflows_data": workflows_data,
            "log_types": LOG_TYPE_LABELS,
            "max_upload_size_mb": settings.max_upload_size_mb,
            "upload_slots": max(1, min(4, settings.upload_max_concurrent)),
            "can_group_cases": has_intel_access(user),
        },
    )


_PREVIEW_MAX_BYTES = 65536


@router.post("/detect-preview")
async def detect_preview(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_async_session),
):
    """Classify the first 64 KB of a file before upload (advisory; no storage).

    The upload form calls this on file drop so the detected type is visible and
    the workflow list can be filtered *before* submission. The full-file
    detection in POST /upload remains the source of truth.
    """
    site_settings = await get_site_settings(db)
    if site_settings.demo_mode:
        raise HTTPException(403, "File submission is disabled in demo mode.")

    header = await file.read(_PREVIEW_MAX_BYTES)
    log_type = detect_log_type_from_bytes(header)
    return {"log_type": log_type.value, "label": LOG_TYPE_LABELS[log_type]}


@router.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    log_type_override: str = Form("auto"),
    workflow_id: int = Form(...),
    force_resubmit: bool = Form(False),
    is_private: bool = Form(False),
    case_id: int | None = Form(None),
    db: AsyncSession = Depends(get_async_session),
    access=Depends(submission_access("job:submit", anonymous=True)),
):
    result = await submit_file(
        request=request,
        file=file,
        workflow_id=workflow_id,
        log_type_override=log_type_override,
        force_resubmit=force_resubmit,
        is_private=is_private,
        case_id=case_id,
        key=request.headers.get("Idempotency-Key"),
        db=db,
        access=access,
        enqueue=run_analysis,
        detect=detect_log_type,
    )
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(result.payload(), status_code=result.http_status)
    url = f"/jobs/{result.job_id}"
    if result.reused:
        url += f"?dup=1&file_id={result.file_id}&workflow_id={result.workflow_id}"
    return RedirectResponse(url, status_code=303)
