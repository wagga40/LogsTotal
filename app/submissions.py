"""One file through one workflow, shared by browser and API submission."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import func, inspect, select, update
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool

from app import activity
from app.config import settings
from app.database import utc_now_naive
from app.detection.workflow_runner import get_compatible_workflows
from app.middleware.upload_admission import require_upload_lease
from app.models import AnalysisJob, CaseJobLink, InvestigationCase, JobStatus, LogFile, LogType, SubmissionReceipt, WorkflowDef, can_view_job, enum_val, visible_case_filter
from app.network.client_ip import get_client_ip
from app.site_settings import get_site_settings

logger = logging.getLogger(__name__)

# Free space that must remain *after* an upload of the maximum permitted size. The
# database, the tool outputs and the uploads share one volume in every single-host
# deployment, so filling it does not merely reject the next upload — SQLite starts failing
# writes and the application stops.
_DISK_HEADROOM_BYTES = 1024 * 1024 * 1024  # 1 GiB

# Submission and legacy filenames use String(512) on both database backends.
_ORIGINAL_FILENAME_MAX = 512
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean_filename(sent: str | None) -> str:
    """The filename the client sent, made storable: control characters dropped, cut to fit.

    Filenames are display metadata; storage keys are generated independently.
    Remove control characters and keep the extension when truncating to the column limit.
    """
    name = _CONTROL_CHARS.sub("", sent or "") or "upload.bin"
    if len(name) > _ORIGINAL_FILENAME_MAX:
        ext = Path(name).suffix[:_ORIGINAL_FILENAME_MAX]
        name = name[: _ORIGINAL_FILENAME_MAX - len(ext)] + ext
    return name


def _stored_filename(log_type: LogType) -> str:
    """An opaque storage key cannot expose one submitter's name to another job."""
    suffix = {
        LogType.EVTX: ".evtx",
        LogType.JSON_EVTX: ".json",
        LogType.JSON_WINLOGBEAT: ".json",
        LogType.XML_EVTX: ".xml",
        LogType.UNKNOWN: ".bin",
    }.get(log_type, ".log")
    return uuid.uuid4().hex + suffix


def _require_workflow_supports(workflow: WorkflowDef, log_type: LogType, origin: str = "detected") -> None:
    """Reject a submission whose workflow doesn't cover the file's log type.

    Backstop behind the form's client-side filtering — without it, a mismatched
    choice produces a job whose tasks are all skipped ("0 findings" reads as
    "clean"). Empty workflow log_types means all types, including unknown.
    `origin` says where the type came from (detected, chosen, stored), so the refusal
    does not blame detection for a type nobody detected.
    """
    if not get_compatible_workflows([workflow], log_type.value):
        raise HTTPException(
            400,
            f"Workflow '{workflow.name}' does not support the {origin} log type '{log_type.value}'.",
        )


@dataclass
class SubmissionResult:
    job_id: int
    file_id: int
    workflow_id: int
    status: str
    reused: bool
    case_id: int | None
    replayed: bool = False

    @property
    def http_status(self):
        return 200 if self.reused or self.replayed else 202

    def payload(self):
        url = f"/jobs/{self.job_id}"
        if self.reused:
            url += f"?dup=1&file_id={self.file_id}&workflow_id={self.workflow_id}"
        return {"job_id": self.job_id, "status": self.status, "reused": self.reused, "job_url": url, "case_id": self.case_id}


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_key(key: str | None) -> str | None:
    if key is not None and (not key or len(key) > 128 or any(ord(c) < 33 or ord(c) > 126 for c in key)):
        raise HTTPException(400, "Idempotency-Key must contain 1-128 printable ASCII characters without spaces")
    return key


async def find_receipt(db, user_id, kind, key):
    if not key or not user_id:
        return None
    return await db.scalar(select(SubmissionReceipt).where(SubmissionReceipt.user_id == user_id, SubmissionReceipt.kind == kind, SubmissionReceipt.key == key))


async def receipt_result(db, receipt, user, expected=None):
    if expected is not None and receipt.fingerprint != expected:
        raise HTTPException(409, "Idempotency-Key was already used for different content or options")
    job = await db.get(AnalysisJob, receipt.job_id) if receipt.job_id else None
    if job is None or not can_view_job(job, user):
        raise HTTPException(410, "The submission's job is no longer available")
    return SubmissionResult(job.id, job.file_id, job.workflow_id, enum_val(job.status), receipt.reused, receipt.case_id, replayed=True)


async def validate_case(db, access, case_id):
    if case_id is None:
        return
    access.require("case:write")
    case = await db.scalar(select(InvestigationCase).where(InvestigationCase.id == case_id, visible_case_filter(access.user)))
    if case is None:
        raise HTTPException(404, "Case not found")


async def submission_settings(db, access):
    """First-use settings creation can race and roll back the request session.

    Reload any authentication objects that rollback expired before using them in
    visibility checks or audit attribution. A normal settings read adds no queries.
    """
    result = await get_site_settings(db)
    for principal in (access.user, access.token):
        if principal is not None and inspect(principal).expired:
            await db.refresh(principal)
    return result


async def link_case(db, job_id, case_id, user_id):
    if case_id is None:
        return
    # An upsert also protects simultaneous submissions reusing the same public job.
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    insert = sqlite_insert if db.bind.dialect.name == "sqlite" else pg_insert
    await db.execute(insert(CaseJobLink).values(case_id=case_id, job_id=job_id, added_by_user_id=user_id).on_conflict_do_nothing(index_elements=["case_id", "job_id"]))


async def remember_queue_position(db, job_id):
    """Preserve the job page's existing queue estimate without blocking the loop."""
    from app.redis_client import QUEUE_POSITION_PREFIX, get_redis

    try:
        pending = await db.scalar(select(func.count(AnalysisJob.id)).where(AnalysisJob.status == JobStatus.PENDING)) or 0
        await run_in_threadpool(get_redis().set, f"{QUEUE_POSITION_PREFIX}{job_id}", str(pending), ex=3600)
    except Exception:
        pass


def spool_and_detect(source, output, path, request, detect):
    """One bounded-memory disk pass, off the event loop for its entire duration.

    Starlette has already parsed the request. Reading its spool and writing ours in
    the same thread avoids two thread-pool round trips for every megabyte.
    """
    digest = hashlib.sha256()
    total = 0
    while chunk := source.read(1024 * 1024):
        require_upload_lease(request)
        total += len(chunk)
        if total > settings.max_upload_bytes:
            raise HTTPException(413, f"File exceeds {settings.max_upload_size_mb} MB limit.")
        digest.update(chunk)
        output.write(chunk)
    output.flush()
    return total, digest.hexdigest(), detect(path)


async def submit_file(*, request, file, workflow_id, log_type_override, force_resubmit, is_private, case_id, key, db, access, enqueue, detect):
    """Store one file and atomically commit the job, case link and retry receipt.

    File transfer/storage happens before the short write transaction. The unique
    receipt wins concurrent retries; the losing transaction and its stored object
    are removed. Existing content reuse remains independent of request idempotency.
    """
    if (await submission_settings(db, access)).demo_mode:
        raise HTTPException(403, "File submission is disabled in demo mode.")
    from starlette.datastructures import UploadFile

    form = await request.form()
    if sum(isinstance(value, UploadFile) for _, value in form.multi_items()) != 1:
        raise HTTPException(400, "Submit exactly one file per request")
    workflow = await db.get(WorkflowDef, workflow_id)
    if not workflow:
        raise HTTPException(400, "Selected workflow not found.")
    await validate_case(db, access, case_id)
    key = validate_key(key)
    user = access.user
    user_id = user.id if user else None
    # Anonymous requests retain content-based duplicate detection, without receipts.
    if key and user is None:
        raise HTTPException(401, "Sign in to use an Idempotency-Key")
    requested_private = bool(is_private and user is not None)
    original_name = _clean_filename(file.filename)
    from app.storage import free_bytes_for_uploads, get_storage

    if not request.scope.get("state", {}).get("upload_reserved"):
        free = await run_in_threadpool(free_bytes_for_uploads)
        if free is not None and free < settings.max_upload_bytes + _DISK_HEADROOM_BYTES:
            raise HTTPException(507, "The server is low on storage and cannot accept uploads right now.")
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(suffix=".upload", dir=settings.upload_dir)
    tmp_path = Path(name)
    saved_name = None
    committed = False
    storage = None
    try:
        with os.fdopen(fd, "wb") as output:
            total, sha256, detected = await run_in_threadpool(spool_and_detect, file.file, output, tmp_path, request, detect)
        try:
            final_type = detected if log_type_override == "auto" else LogType(log_type_override)
        except ValueError as exc:
            raise HTTPException(400, "Invalid log type override.") from exc
        _require_workflow_supports(workflow, final_type, "detected" if log_type_override == "auto" else "chosen")
        signature = fingerprint([sha256, original_name, workflow_id, log_type_override, force_resubmit, requested_private, case_id])
        previous = await find_receipt(db, user_id, "job", key)
        if previous:
            return await receipt_result(db, previous, user, signature)
        log_file = await db.scalar(select(LogFile).where(LogFile.sha256 == sha256).order_by(LogFile.id).limit(1))
        job = None
        if log_file and not force_resubmit:
            candidate = await db.scalar(
                select(AnalysisJob)
                .where(AnalysisJob.file_id == log_file.id, AnalysisJob.workflow_id == workflow_id)
                .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
                .limit(1)
            )
            if (
                candidate
                and can_view_job(candidate, user)
                and (user is None or candidate.submitted_by_user_id == user_id)
                and candidate.is_private == requested_private
                and candidate.submitted_filename == original_name
                and candidate.effective_log_type == final_type
                and candidate.status in (JobStatus.PENDING, JobStatus.RUNNING, JobStatus.COMPLETED, JobStatus.PARTIAL)
            ):
                job = candidate
        reused = job is not None
        if log_file is None:
            storage = get_storage()
            saved_name = _stored_filename(detected)
            await storage.save_path(saved_name, tmp_path)
            log_file = LogFile(
                original_filename=original_name,
                stored_filename=saved_name,
                sha256=sha256,
                size_bytes=total,
                log_type=detected,
                detected_type=detected,
                uploader_ip=get_client_ip(request),
            )
        else:
            log_file.detected_type = detected
            log_file.log_type = detected
        try:
            require_upload_lease(request)
            db.add(log_file)
            await db.flush()
            if job is None:
                job = AnalysisJob(
                    file_id=log_file.id,
                    workflow_id=workflow_id,
                    submitted_by_user_id=user_id,
                    submitter_ip=get_client_ip(request),
                    is_private=requested_private,
                    submitted_filename=original_name,
                    effective_log_type=final_type,
                )
                db.add(job)
                await db.flush()
            await link_case(db, job.id, case_id, user_id)
            if key:
                db.add(SubmissionReceipt(user_id=user_id, kind="job", key=key, fingerprint=signature, job_id=job.id, case_id=case_id, reused=reused))
            await db.commit()
            committed = True
        except IntegrityError:
            await db.rollback()
            previous = await find_receipt(db, user_id, "job", key)
            if previous:
                # `user` was expired by rollback; restore it before visibility checks.
                if user is not None:
                    await db.refresh(user)
                return await receipt_result(db, previous, user, signature)
            raise
        if not reused:
            try:
                await run_in_threadpool(enqueue, job.id)
            except Exception:
                logger.exception("Could not enqueue analysis for job %s", job.id)
                # Only while still PENDING: an enqueue can raise after the message landed,
                # and a worker may already have claimed the job.
                await db.execute(
                    update(AnalysisJob)
                    .where(AnalysisJob.id == job.id, AnalysisJob.status == JobStatus.PENDING)
                    .values(
                        status=JobStatus.FAILED,
                        error_message="The analysis could not be queued: the task queue was unreachable. Submit the file again once it is back.",
                        finished_at=utc_now_naive(),
                    )
                )
                await db.commit()
                raise HTTPException(503, "The analysis queue is unreachable, so this file cannot be analysed right now. Try again shortly.") from None
            await remember_queue_position(db, job.id)
        await activity.record(
            "job.upload",
            request=request,
            user=user,
            actor_label=access.actor_label,
            target_type="job",
            target_id=str(job.id),
            summary=job.filename,
            meta={"size_bytes": total, "log_type": enum_val(final_type), "private": requested_private, "case_id": case_id, "reused": reused},
        )
        return SubmissionResult(job.id, log_file.id, workflow_id, enum_val(job.status), reused, case_id)
    finally:
        tmp_path.unlink(missing_ok=True)
        if saved_name and not committed:
            try:
                await storage.delete(saved_name)
            except Exception:
                logger.warning("Could not clean up rejected upload %s", saved_name, exc_info=True)
