"""Storage management — `/admin/storage`.

A separate module, like `enrichment_admin.py` and `ai_admin.py`, to keep `admin.py`
manageable. Every route is `current_superuser`.

Note for anyone adding a path here that the in-app docs page mentions: this file must be
listed in `ADMIN_ROUTER_FILES` in `tests/test_docs_in_sync.py`, and every decorator must
keep a single positional path literal — that guard parses the source with a regex.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity, storage_usage
from app.auth.users import current_superuser
from app.config import settings
from app.database import get_async_session
from app.models import AnalysisJob, BackgroundTask, BackgroundTaskStatus, JobStatus, LogFile, User
from app.retention import OVERRIDABLE, effective_retention
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/admin/storage")

#: Windows shown on the page. Only the first is overridable — see `app/retention.py`.
RETENTION_KEYS = (
    (
        "job_output_retention_days",
        "Raw tool output",
        "Per-job output directories. Findings, analytics and the events timeline survive; the histogram, process tree and RAW ZIP export do not.",
    ),
    ("upload_retention_days", "Uploaded log files", "Deletes the submitted file AND its jobs. Off by default — this is the evidence a user gave you."),
    ("activity_retention_days", "Activity log", "Rows on /admin/activity. `0` keeps forever."),
    ("background_task_retention_days", "Task history", "Finished rows on /admin/tasks."),
    ("webhook_delivery_retention_days", "Webhook deliveries", "The per-attempt delivery log behind watch rules."),
)


async def _known_sets(db: AsyncSession) -> tuple[set[str], set[int], set[int]]:
    """The three id sets `classify_objects` needs, resolved before the threadpool hop.

    Resolved here rather than inside the walk for the reason `intel/process_tree.py`
    centralises: a lazy ORM read inside a worker thread is a `MissingGreenlet`.
    """
    filenames = {row[0] for row in (await db.execute(select(LogFile.stored_filename))).all()}
    job_ids = {row[0] for row in (await db.execute(select(AnalysisJob.id))).all()}
    active = {row[0] for row in (await db.execute(select(AnalysisJob.id).where(AnalysisJob.status.in_([JobStatus.PENDING, JobStatus.RUNNING])))).all()}
    return filenames, job_ids, active


async def _usage(db: AsyncSession, *, force: bool) -> storage_usage.UsageReport:
    filenames, job_ids, active = await _known_sets(db)

    def _run() -> storage_usage.UsageReport:
        return storage_usage.cached_usage(
            gather=lambda: storage_usage.gather_usage_sync(known_filenames=filenames, known_job_ids=job_ids, active_job_ids=active),
            force=force,
        )

    return await run_in_threadpool(_run)


async def _page_context(request: Request, db: AsyncSession, *, force: bool = False) -> dict:
    report = await _usage(db, force=force)
    site_settings = await get_site_settings(db)

    # The DB-recorded figure, kept alongside the on-disk one: a large gap between them is
    # itself a finding (rows whose file is gone, or files no row claims).
    row = (await db.execute(select(func.count(LogFile.id), func.coalesce(func.sum(LogFile.size_bytes), 0)))).one()
    db_file_count, db_file_bytes = row[0] or 0, row[1] or 0

    job_names = {}
    if report.largest_jobs:
        ids = [jid for jid, _ in report.largest_jobs]
        rows = (await db.execute(select(AnalysisJob.id, AnalysisJob.filename).join(LogFile, AnalysisJob.file_id == LogFile.id).where(AnalysisJob.id.in_(ids)))).all()
        job_names = {r[0]: r[1] for r in rows}

    retention = []
    for name, label, note in RETENTION_KEYS:
        resolved = effective_retention(name, site_settings)
        retention.append(
            {
                "name": name,
                "label": label,
                "note": note,
                "days": resolved.days,
                "source": resolved.source,
                "overridable": name in OVERRIDABLE,
                "overridden": resolved.overridden,
                "disabled": resolved.disabled,
            }
        )

    return {
        "report": report,
        "db_file_count": db_file_count,
        "db_file_bytes": db_file_bytes,
        "job_names": job_names,
        "retention": retention,
        "is_sqlite": settings.database_url.startswith("sqlite"),
    }


@router.get("")
async def storage_page(
    request: Request,
    force: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Usage, biggest consumers, orphans and retention."""
    ctx = await _page_context(request, db, force=bool(force))
    return templates.TemplateResponse(request, "admin/storage.html", {"request": request, "user": user, **ctx})


@router.get("/usage-partial")
async def storage_usage_partial(
    request: Request,
    force: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Just the report, for the Rescan button."""
    ctx = await _page_context(request, db, force=bool(force))
    return templates.TemplateResponse(request, "admin/partials/_storage_report.html", {"request": request, "user": user, **ctx})


@router.get("/db-footprint-partial")
async def storage_db_footprint(
    request: Request,
    user: User = Depends(current_superuser),
):
    """Where the database's own bytes are.

    Lazy-loaded rather than part of the page: on PostgreSQL it is one `pg_database_size`
    call, but on SQLite it opens a connection and reads `dbstat`, and neither belongs on
    the critical path of a page an admin opens to check free space.
    """
    footprint = await run_in_threadpool(storage_usage.database_footprint_sync)
    return templates.TemplateResponse(request, "admin/partials/_storage_database.html", {"request": request, "user": user, "footprint": footprint})


@router.post("/purge-orphans")
async def storage_purge_orphans(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Queue removal of stored objects the database no longer knows about.

    Queued rather than inline: it is a delete loop over storage, and it belongs on
    /admin/tasks with the rest of the work — including its cancel button.
    """
    from app.routers.admin import enqueue_background_task, find_active_background_task
    from app.workers.tasks import purge_orphaned_storage

    # Two purges walk and delete the same objects at once.
    if await find_active_background_task(db, "purge_orphaned_storage") is not None:
        return RedirectResponse("/admin/storage?queued=already", status_code=303)

    bt = BackgroundTask(
        name="Purge orphaned storage",
        kind="purge_orphaned_storage",
        requested_by_label=getattr(user, "email", None),
        status=BackgroundTaskStatus.PENDING,
    )
    db.add(bt)
    await db.commit()
    await db.refresh(bt)
    if not await enqueue_background_task(db, bt, lambda: purge_orphaned_storage(bt.id)):
        return RedirectResponse("/admin/storage?queued=unreachable", status_code=303)
    storage_usage.reset_cache()
    await activity.record("admin.storage.purge_orphans", request=request, user=user, target_type="background_task", target_id=str(bt.id))
    return RedirectResponse("/admin/storage?queued=purge", status_code=303)


@router.post("/run-retention")
async def storage_run_retention(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Run the output retention sweep now, rather than waiting for 04:45 UTC."""
    from app.routers.admin import enqueue_background_task, find_active_background_task
    from app.workers.tasks import cleanup_old_job_outputs

    # Same guard as the Maintenance tab's Run buttons, and it has to be here too: this page
    # and `/admin/cleanup-outputs` queue the *same* task, so a guard on only one of them
    # would be a guard on a button rather than on the work.
    if await find_active_background_task(db, "cleanup_old_job_outputs") is not None:
        return RedirectResponse("/admin/storage?queued=already", status_code=303)

    bt = BackgroundTask(
        name="Output Directory Cleanup",
        kind="cleanup_old_job_outputs",
        requested_by_label=getattr(user, "email", None),
        status=BackgroundTaskStatus.PENDING,
    )
    db.add(bt)
    await db.commit()
    await db.refresh(bt)
    if not await enqueue_background_task(db, bt, lambda: cleanup_old_job_outputs(bt.id)):
        return RedirectResponse("/admin/storage?queued=unreachable", status_code=303)
    storage_usage.reset_cache()
    await activity.record("admin.maintenance.queued", request=request, user=user, target_type="background_task", target_id=str(bt.id), summary="Output Directory Cleanup")
    return RedirectResponse("/admin/storage?queued=retention", status_code=303)


@router.post("/retention")
async def storage_set_retention(
    request: Request,
    job_output_retention_days: str = Form(""),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Set or clear the output-retention override.

    An empty field clears it, which is how the env var takes over again — so the page can
    always get back to "whatever `.env` says" without an operator having to remember what
    that was.
    """
    site_settings = await get_site_settings(db)
    raw = (job_output_retention_days or "").strip()
    if raw == "":
        new_value = None
    else:
        try:
            new_value = max(0, int(raw))
        except ValueError:
            raise HTTPException(400, "Retention must be a whole number of days, or empty to use the environment default.") from None

    before = site_settings.job_output_retention_days_override
    site_settings.job_output_retention_days_override = new_value
    await db.commit()
    if before != new_value:
        await activity.record(
            "admin.storage.retention",
            request=request,
            user=user,
            summary=f"job output retention: {before if before is not None else 'env default'} to {new_value if new_value is not None else 'env default'}",
            meta={"from": before, "to": new_value},
        )
    return RedirectResponse("/admin/storage?saved=1", status_code=303)


@router.post("/vacuum")
async def storage_vacuum(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Reclaim free pages in a SQLite database file.

    SQLite-only, deliberately: PostgreSQL autovacuums, and offering the button there would
    imply a problem that does not exist. It is offered at all because without it a large
    purge does not shrink the file — the space is freed inside it and never returned.

    It needs exclusive access and rewrites the whole file, so it is queued rather than run
    on the request, and the confirm dialog says what that means.
    """
    if not settings.database_url.startswith("sqlite"):
        raise HTTPException(400, "VACUUM applies to SQLite only; PostgreSQL reclaims space automatically.")

    from app.routers.admin import enqueue_background_task, find_active_background_task
    from app.workers.tasks import vacuum_database

    # Each VACUUM takes SQLite's exclusive lock and rewrites the whole file.
    if await find_active_background_task(db, "vacuum_database") is not None:
        return RedirectResponse("/admin/storage?queued=already", status_code=303)

    bt = BackgroundTask(
        name="Vacuum database",
        kind="vacuum_database",
        requested_by_label=getattr(user, "email", None),
        status=BackgroundTaskStatus.PENDING,
    )
    db.add(bt)
    await db.commit()
    await db.refresh(bt)
    if not await enqueue_background_task(db, bt, lambda: vacuum_database(bt.id)):
        return RedirectResponse("/admin/storage?queued=unreachable", status_code=303)
    await activity.record("admin.storage.vacuum", request=request, user=user, target_type="background_task", target_id=str(bt.id))
    return RedirectResponse("/admin/storage?queued=vacuum", status_code=303)
