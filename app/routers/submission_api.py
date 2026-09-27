"""Versioned ingestion API and lightweight browser queue reads."""

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity
from app.auth.api_tokens import submission_access
from app.database import get_async_session, parse_row_id
from app.json_utils import loads
from app.models import AnalysisJob, InvestigationCase, SubmissionReceipt, WorkflowDef, enum_val, visible_case_filter, visible_job_filter
from app.routers import upload
from app.submissions import find_receipt, fingerprint, receipt_result, submission_settings, submit_file, validate_key

router = APIRouter(prefix="/api/v1", tags=["ingestion"])


@router.post("/jobs")
async def submit_job(
    request: Request,
    file: UploadFile = File(...),
    workflow_id: int = Form(...),
    log_type_override: str = Form("auto"),
    force_resubmit: bool = Form(False),
    is_private: bool = Form(False),
    case_id: int | None = Form(None),
    db: AsyncSession = Depends(get_async_session),
    access=Depends(submission_access("job:submit")),
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
        enqueue=upload.run_analysis,
        detect=upload.detect_log_type,
    )
    return JSONResponse(result.payload(), status_code=result.http_status)


@router.get("/workflows")
async def list_submission_workflows(db: AsyncSession = Depends(get_async_session), access=Depends(submission_access("job:submit"))):
    rows = (await db.execute(select(WorkflowDef).order_by(WorkflowDef.name, WorkflowDef.id))).scalars()
    return {"workflows": [{"id": row.id, "name": row.name, "log_types": loads(row.log_types or "[]"), "is_default": row.is_default} for row in rows]}


@router.get("/jobs")
async def submission_statuses(
    ids: str = Query(..., max_length=600),
    db: AsyncSession = Depends(get_async_session),
    access=Depends(submission_access("job:read", anonymous=True)),
):
    """One small query per queue poll; omit private/nonexistent jobs identically."""
    parts = ids.split(",")
    if not 1 <= len(parts) <= 50:
        raise HTTPException(400, "Supply 1-50 job IDs")
    job_ids = [parse_row_id(part.strip()) for part in parts]
    if any(jid is None or jid <= 0 for jid in job_ids):
        raise HTTPException(400, "Invalid job ID")
    rows = (
        await db.execute(
            select(AnalysisJob.id, AnalysisJob.status, AnalysisJob.total_findings, AnalysisJob.error_message).where(AnalysisJob.id.in_(job_ids), visible_job_filter(access.user))
        )
    ).all()
    found = {row.id for row in rows}
    return {
        "jobs": [
            {"job_id": row.id, "status": enum_val(row.status), "total_findings": row.total_findings, "error": row.error_message, "job_url": f"/jobs/{row.id}"} for row in rows
        ],
        "unavailable_ids": [jid for jid in dict.fromkeys(job_ids) if jid not in found],
    }


@router.get("/submissions/{key:path}")
async def lookup_submission(key: str, db: AsyncSession = Depends(get_async_session), access=Depends(submission_access("job:submit"))):
    """Resolve uncertain network outcomes without resending the file."""
    receipt = await find_receipt(db, access.user.id, "job", validate_key(key))
    if receipt is None:
        raise HTTPException(404, "Submission not found; the request may still be in progress")
    return (await receipt_result(db, receipt, access.user)).payload()


class CaseSubmission(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    is_shared: bool = False

    @field_validator("name", mode="before")
    @classmethod
    def trim_name(cls, value):
        return value.strip() if isinstance(value, str) else value


@router.post("/cases")
async def create_submission_case(
    request: Request,
    body: CaseSubmission,
    db: AsyncSession = Depends(get_async_session),
    access=Depends(submission_access("case:write")),
):
    if (await submission_settings(db, access)).demo_mode:
        raise HTTPException(403, "File submission is disabled in demo mode.")
    key = validate_key(request.headers.get("Idempotency-Key"))
    user_id = access.user.id
    signature = fingerprint(body.model_dump())
    receipt = await find_receipt(db, user_id, "case", key)
    if receipt is None:
        case = InvestigationCase(name=body.name, is_shared=body.is_shared, status="open", created_by_user_id=user_id)
        db.add(case)
        try:
            await db.flush()
            if key:
                db.add(SubmissionReceipt(user_id=user_id, kind="case", key=key, fingerprint=signature, case_id=case.id, reused=False))
            await db.commit()
            await activity.record(
                "intel.case.create", request=request, user=access.user, actor_label=access.actor_label, target_type="case", target_id=str(case.id), summary=case.name
            )
            return JSONResponse({"case_id": case.id, "case_url": f"/intel/cases/{case.id}"}, status_code=201)
        except IntegrityError:
            await db.rollback()
            receipt = await find_receipt(db, user_id, "case", key)
            if receipt is None:
                raise
            await db.refresh(access.user)
    if receipt.fingerprint != signature:
        raise HTTPException(409, "Idempotency-Key was already used for different case options")
    case = await db.scalar(select(InvestigationCase).where(InvestigationCase.id == receipt.case_id, visible_case_filter(access.user)))
    if case is None:
        raise HTTPException(410, "The submission's case is no longer available")
    return {"case_id": case.id, "case_url": f"/intel/cases/{case.id}"}
