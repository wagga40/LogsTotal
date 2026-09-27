"""
Admin router — superusers only.
User management + system status.
"""

from __future__ import annotations

import logging
import shutil
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi_users.exceptions import InvalidPasswordException, UserAlreadyExists, UserNotExists
from pydantic import ValidationError
from sqlalchemy import case, delete, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import activity, task_registry
from app.auth.schemas import UserCreate, UserUpdate
from app.auth.users import UserManager, current_superuser, get_user_manager
from app.config import settings
from app.constants import RECOVERY_MSG_ADMIN
from app.database import get_async_session, utc_now_naive
from app.docs_site import docs_url
from app.models import (
    ActivityEvent,
    AiAnalysisStatus,
    AiProvider,
    AnalysisJob,
    ApiToken,
    BackgroundTask,
    BackgroundTaskStatus,
    CaseAiAnalysis,
    CaseEntityLink,
    CaseJobLink,
    Comment,
    EnrichmentService,
    EntityTag,
    IntelRule,
    IntelRuleMatch,
    InvestigationCase,
    JobAiAnalysis,
    JobRuleMatch,
    JobStatus,
    JobTag,
    JobWatch,
    JobWatchEvent,
    LogFile,
    SavedSearch,
    TagDefinition,
    User,
    WebhookDelivery,
    WorkerPolicy,
    WorkflowDef,
    enum_val,
)
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/admin")

_log = logging.getLogger(__name__)


def _user_uuid(user_id: str) -> uuid.UUID:
    """Parse a `{user_id}` path parameter, 404-ing on a malformed one.

    `uuid.UUID()` raises `ValueError` on anything that is not a UUID, which FastAPI would
    turn into a 500 — a typo in the URL of an admin action reading as a server fault rather
    than "no such user". 404 rather than 422 because a malformed id and an absent one are the
    same outcome to the caller, and every one of these handlers already 404s for the latter.
    """
    try:
        return uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(404, "User not found.") from None


# Drives the Maintenance tab rows on the dashboard. `url` must match the POST
# route below (docs/reference/admin-ui.md's backfill table and tests/test_docs_in_sync.py
# pin these paths); `param` is the query-string flag used by the no-JS redirect
# fallback (`/admin?<param>=started`).
MAINTENANCE_ACTIONS = [
    {
        "key": "similarity",
        "url": "/admin/backfill-similarity",
        "param": "backfill",
        "title": "Similarity Backfill",
        "description": "Compute TLSH hashes and rule signatures for existing jobs that predate this feature.",
        "details": None,
        "confirm_title": "Queue similarity backfill",
        "confirm_message": "Queue similarity backfill for all jobs?",
    },
    {
        "key": "analytics",
        "url": "/admin/backfill-analytics",
        "param": "backfill_analytics",
        "title": "Analytics Cache",
        "description": "Recompute and cache analytics (MITRE, timeline, entities) for all completed jobs.",
        "details": None,
        "confirm_title": "Recalculate analytics",
        "confirm_message": "Recalculate analytics for all completed jobs?",
    },
    {
        "key": "entities",
        "url": "/admin/backfill-entities",
        "param": "backfill_entities",
        "title": "Entity Backfill",
        "description": "Populate the Intel entity database from existing analytics data for all completed jobs.",
        "details": None,
        "confirm_title": "Backfill entities",
        "confirm_message": "Backfill entities from all completed jobs?",
    },
    {
        "key": "builtin-labels",
        "url": "/admin/backfill-builtin-labels",
        "param": "backfill_builtin_labels",
        "title": "Shared Rules",
        "description": "Apply the shared rules (lolbin, privileged, rfc1918, …) to every existing entity.",
        "details": (
            "Labels used to be derived when a page rendered, so they were never stale. They are stored "
            "tags now, written as each job finishes — which means an entity last seen before these rules "
            "existed carries none of them. Run this once after upgrading, and again after editing a list "
            "or a shared rule's condition on the Rules page: tags already written do not move on their own."
        ),
        "confirm_title": "Apply built-in labels",
        "confirm_message": "Label every existing entity from the built-in rules?",
    },
    {
        "key": "entity-attributes",
        "url": "/admin/backfill-entity-attributes",
        "param": "backfill_entity_attributes",
        "title": "Entity Attribute Backfill",
        "description": "(Re)compute per-type attributes for every entity.",
        "details": (
            "Covers IP class (private/public/CGNAT), hash algorithm, suspicious/DGA domains, "
            "LOLBIN executables, and privileged users. Run after upgrading or after changing "
            "the threat-detection config."
        ),
        "confirm_title": "Backfill entity attributes",
        "confirm_message": "Recompute per-type attributes for all entities?",
    },
    {
        "key": "relationships",
        "url": "/admin/backfill-relationships",
        "param": "backfill_relationships",
        "title": "Relationship Backfill",
        "description": "Rebuild typed entity relationships (hashes to, resolves to, parent of, …) by re-parsing raw tool output.",
        "details": (
            "Run after upgrading; only jobs whose output files are still retained will produce edges. Safe to re-run — occurrence counts are derived per job, not incremented."
        ),
        "confirm_title": "Backfill relationships",
        "confirm_message": "Re-parse raw output for all completed jobs and rebuild typed entity relationships?",
    },
    {
        "key": "finding-entity-links",
        "url": "/admin/backfill-finding-entity-links",
        "param": "backfill_finding_entity_links",
        "title": "Finding-Entity Link Backfill",
        "description": "Rebuild the per-entity Findings view by re-scanning all stored findings for known entity values.",
        "details": "Run after upgrading or if the Findings tab on entity pages is missing data.",
        "confirm_title": "Rebuild finding-entity links",
        "confirm_message": "Re-scan every finding across all jobs and rebuild the entity link table?",
    },
    {
        "key": "cleanup",
        "url": "/admin/cleanup-outputs",
        "param": "cleanup",
        "title": "Output Cleanup",
        "description": "Remove output directories for jobs older than the configured retention period.",
        "details": None,
        "confirm_title": "Run cleanup",
        "confirm_message": "Clean up old job output directories?",
    },
]


async def find_active_background_task(db: AsyncSession, kind: str | None, *, target_id: str | None = None) -> BackgroundTask | None:
    """The newest row of this `kind` a worker is still plausibly working on, if any.

    "Plausibly" is `_bg_task_is_stalled`'s job: a row whose worker died sits at `running`
    forever, and treating that as in-flight would wedge the button permanently. A stalled
    row is not in flight, so a fresh click starts a fresh task — which is the recovery an
    admin expects from clicking Run again. `target_id` narrows a per-target task
    (recalculating job 7 is not a duplicate of recalculating job 8).
    """
    if not kind:
        return None
    stmt = select(BackgroundTask).where(
        BackgroundTask.kind == kind,
        BackgroundTask.status.in_([BackgroundTaskStatus.PENDING, BackgroundTaskStatus.RUNNING]),
    )
    if target_id is not None:
        stmt = stmt.where(BackgroundTask.target_id == target_id)
    row = await db.scalar(stmt.order_by(BackgroundTask.id.desc()).limit(1))
    if row is None or _bg_task_is_stalled(row):
        return None
    return row


QUEUE_UNREACHABLE_MSG = "Could not be queued: the task queue was unreachable."


async def enqueue_background_task(db: AsyncSession, bt: BackgroundTask, enqueue) -> bool:
    """Call `enqueue()` for a committed PENDING row. On failure, fail the row and return False.

    The row must exist before the enqueue — the task needs its id — so a queue that refuses
    the task would otherwise leave a PENDING row nothing will ever run, which the duplicate
    guard then reports as "Already queued" until it goes stale half an hour later.
    """
    try:
        result = enqueue()
    except Exception:
        _log.exception("Could not enqueue %s", bt.name)
        await db.execute(
            update(BackgroundTask).where(BackgroundTask.id == bt.id).values(status=BackgroundTaskStatus.FAILED, error_message=QUEUE_UNREACHABLE_MSG, finished_at=utc_now_naive())
        )
        await db.commit()
        await db.refresh(bt)
        return False
    await _record_huey_task_id(db, bt.id, result)
    return True


async def _queue_background_task(request: Request, db: AsyncSession, name: str, task_fn, redirect_param: str, *, user: User | None = None):
    """Create a BackgroundTask row, enqueue the Huey task, and respond.

    HTMX requests get the live status chip partial (which self-polls);
    plain form posts keep the 303 redirect as a no-JS fallback.

    `kind` is taken from the task's own function name rather than passed in, so a row can
    never claim to be a task it is not — it is the key Retry dispatches on.
    """
    # `TaskWrapper.name` is None until a Task instance exists; `.func.__name__` is the
    # stable key, and it is what `task_registry` and `huey_inspect._short_name` both use.
    kind = getattr(getattr(task_fn, "func", None), "__name__", None)

    # A second copy of a backfill that is already running is pure waste — it re-reads the
    # same raw output and re-writes the same rows — and the Run button gives no sign that
    # the first click landed, so it invites exactly that. Hand back the chip for the run in
    # flight: it self-polls, so the admin sees the work they asked for finish.
    active = await find_active_background_task(db, kind)
    if active is not None:
        if request.headers.get("hx-request"):
            return templates.TemplateResponse(request, "admin/partials/_bg_task_status.html", {"request": request, "task": active, "already": True})
        return RedirectResponse(f"/admin?{redirect_param}=running#maintenance", status_code=303)

    bt = BackgroundTask(
        name=name,
        kind=kind,
        requested_by_label=getattr(user, "email", None),
        status=BackgroundTaskStatus.PENDING,
    )
    db.add(bt)
    try:
        await db.commit()
    except OperationalError:
        # SQLite has one writer, so this is "something else is mid-transaction". The
        # backfills commit per item precisely so this cannot happen (see the note above
        # `backfill_similarity`), but a VACUUM or a very large job's own commit can still
        # outlast the busy timeout — and a stack trace where a status chip belongs is the
        # worst possible answer to a button an admin is allowed to press again.
        await db.rollback()
        _log.warning("Could not queue %s — the database was busy", name)
        if request.headers.get("hx-request"):
            return templates.TemplateResponse(request, "admin/partials/_bg_task_status.html", {"request": request, "task": None, "busy": True})
        return RedirectResponse(f"/admin?{redirect_param}=busy#maintenance", status_code=303)

    await db.refresh(bt)
    if not await enqueue_background_task(db, bt, lambda: task_fn(bt.id)):
        if request.headers.get("hx-request"):
            return templates.TemplateResponse(request, "admin/partials/_bg_task_status.html", {"request": request, "task": bt})
        return RedirectResponse(f"/admin?{redirect_param}=unreachable#maintenance", status_code=303)
    await activity.record("admin.maintenance.queued", request=request, user=user, target_type="background_task", target_id=str(bt.id), summary=name)
    if request.headers.get("hx-request"):
        return templates.TemplateResponse(request, "admin/partials/_bg_task_status.html", {"request": request, "task": bt})
    return RedirectResponse(f"/admin?{redirect_param}=started#maintenance", status_code=303)


@router.get("")
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Admin dashboard with job/user counts, system health, and backfill triggers."""
    row = (
        await db.execute(
            select(
                func.count(AnalysisJob.id),
                func.count(case((AnalysisJob.status == JobStatus.RUNNING, 1))),
                func.count(case((AnalysisJob.status == JobStatus.PENDING, 1))),
                func.count(case((AnalysisJob.status == JobStatus.COMPLETED, 1))),
            )
        )
    ).one()
    total_jobs, running_jobs, pending_jobs, completed_jobs = row[0] or 0, row[1] or 0, row[2] or 0, row[3] or 0

    # One count per Manage card, so each one says what is behind it before you open it.
    # Grouped into single round trips rather than a scalar apiece: these are seven numbers
    # decorating a nav grid, and they should not cost seven queries on every dashboard load.
    total_users, total_admins = (await db.execute(select(func.count(User.id), func.count(case((User.is_superuser.is_(True), 1)))))).one()
    total_workflows = await db.scalar(select(func.count(WorkflowDef.id))) or 0
    ai_total, ai_enabled = (await db.execute(select(func.count(AiProvider.id), func.count(case((AiProvider.enabled.is_(True), 1)))))).one()
    enrich_total, enrich_enabled = (await db.execute(select(func.count(EnrichmentService.id), func.count(case((EnrichmentService.enabled.is_(True), 1)))))).one()
    # "Active" is the token list's own definition — neither revoked nor expired — so the
    # pill and the page can never disagree about how many tokens still open a door.
    now_naive = utc_now_naive()
    active_tokens = (
        await db.scalar(
            select(func.count(ApiToken.id)).where(
                ApiToken.revoked_at.is_(None),
                (ApiToken.expires_at.is_(None)) | (ApiToken.expires_at > now_naive),
            )
        )
        or 0
    )
    activity_last_hour = await db.scalar(select(func.count(ActivityEvent.id)).where(ActivityEvent.created_at >= now_naive - timedelta(hours=1))) or 0

    # The Overview tab answers "what is happening right now", so it needs the two live
    # counts an admin actually reacts to: work in flight, and work nobody has started.
    active_bg = await db.scalar(select(func.count(BackgroundTask.id)).where(BackgroundTask.status.in_([BackgroundTaskStatus.PENDING, BackgroundTaskStatus.RUNNING]))) or 0
    active_ai_runs = await db.scalar(select(func.count(JobAiAnalysis.id)).where(JobAiAnalysis.status.in_([AiAnalysisStatus.PENDING, AiAnalysisStatus.RUNNING]))) or 0
    active_ai_runs += await db.scalar(select(func.count(CaseAiAnalysis.id)).where(CaseAiAnalysis.status.in_([AiAnalysisStatus.PENDING, AiAnalysisStatus.RUNNING]))) or 0
    # Newest first, unconditionally: the card itself tells "nothing recorded" apart from
    # "capture never enabled" (see the `activity_log_enabled` branch in dashboard.html), so
    # an empty card does not read as "nothing has happened".
    recent_activity = (await db.execute(select(ActivityEvent).order_by(ActivityEvent.created_at.desc(), ActivityEvent.id.desc()).limit(8))).scalars().all()

    # System health strip — shared checks (same logic as doctor / System Status card) —
    # plus the security nudge that flags a superuser still on the shipped default
    # password. The nudge is *not* cheap: fastapi-users hashes with Argon2id at m=65536,
    # so each verify allocates 64 MB and takes ~50 ms, once per superuser per render — so
    # it runs in the threadpool with the other checks, not on the event loop, where it
    # would stall every concurrent request including the 3-second job polls.
    from fastapi.concurrency import run_in_threadpool

    from app import system_checks
    from app.config import settings as app_settings

    superuser_hashes = (await db.execute(select(User.hashed_password).where(User.is_superuser.is_(True)))).scalars().all()

    def _health_checks():
        try:
            from fastapi_users.password import PasswordHelper

            ph = PasswordHelper()
            uses_default = any(ph.verify_and_update("changeme123", h)[0] for h in superuser_hashes if h)
        except Exception:
            uses_default = False
        return (system_checks.check_redis(), system_checks.check_storage(), uses_default)

    redis_check, storage_check, default_admin_password = await run_in_threadpool(_health_checks)
    health: dict = {
        "database": "ok",  # this request already queried the DB successfully
        "redis": "ok" if redis_check.level == system_checks.PASS else f"error: {redis_check.message}",
        "storage": f"ok ({app_settings.storage_backend})" if storage_check.level == system_checks.PASS else f"error: {storage_check.message}",
        "workers": 0,
    }
    try:
        from app.redis_client import WORKER_ALIVE_PREFIX, get_redis

        health["workers"] = sum(1 for _ in get_redis().scan_iter(f"{WORKER_ALIVE_PREFIX}*"))
    except Exception:
        pass

    # Storage details
    file_row = (await db.execute(select(func.count(LogFile.id), func.coalesce(func.sum(LogFile.size_bytes), 0)))).one()
    file_count, total_stored_bytes = file_row[0] or 0, file_row[1] or 0

    storage_info: dict = {
        "backend": app_settings.storage_backend,
        "file_count": file_count,
        "total_stored_bytes": total_stored_bytes,
    }
    if app_settings.storage_backend == "s3":
        storage_info["s3_endpoint"] = app_settings.s3_endpoint or "—"
        storage_info["s3_bucket"] = app_settings.s3_bucket
        storage_info["s3_region"] = app_settings.s3_region
    else:
        upload_path = app_settings.upload_dir.resolve()
        storage_info["upload_dir"] = str(upload_path)
        try:
            usage = shutil.disk_usage(upload_path)
            storage_info["disk_total"] = usage.total
            storage_info["disk_used"] = usage.used
            storage_info["disk_free"] = usage.free
            storage_info["disk_pct"] = round(usage.used / usage.total * 100, 1) if usage.total else 0
        except OSError:
            storage_info["disk_total"] = 0

    # Getting-started checklist — live state, server-rendered (Alpine only collapses it).
    production_warnings = app_settings.production_warnings()
    # "Set up backups" auto-detection: a fresh verified-backup receipt = done
    # (goes back to pending when the newest receipt is stale). Tiny file read.
    try:
        from app.system_checks import check_backup_receipt

        backup_receipt_fresh = check_backup_receipt().level == "PASS"
    except Exception:
        backup_receipt_fresh = False

    gs_steps = [
        {
            "title": "Change the default admin password",
            "done": not default_admin_password,
            "link": "/admin/users",
            "link_label": "User Management",
            "remedy": None,
            "manual": False,
        },
        {
            "title": "Connect a worker",
            "done": health["workers"] > 0,
            "link": None,
            "link_label": None,
            "remedy": None if health["workers"] > 0 else system_checks.WORKER_START_FIX,
            "manual": False,
        },
        {
            "title": "Complete a first analysis",
            "done": completed_jobs > 0,
            "link": "/",
            "link_label": "Upload a log",
            "remedy": None,
            "manual": False,
        },
        {
            "title": "Clear production warnings",
            "done": not production_warnings,
            "link": None,
            "link_label": None,
            "remedy": None if not production_warnings else "See the production-safety banner above and the System checks tab for the exact items and fixes.",
            "manual": False,
        },
        {
            "title": "Set up backups",
            "done": backup_receipt_fresh,
            "link": None,
            "link_label": None,
            "remedy": f"Run ./logstotal backup (verified dump + receipt), then schedule it via cron — {docs_url('runbooks/backup-and-restore.md')}",
            "manual": False,
        },
    ]
    auto_steps = [s for s in gs_steps if not s["manual"]]
    getting_started = {
        "steps": gs_steps,
        "auto_done": sum(1 for s in auto_steps if s["done"]),
        "auto_total": len(auto_steps),
        "all_done": all(s["done"] for s in auto_steps),
    }

    return templates.TemplateResponse(
        request,
        "admin/dashboard.html",
        {
            "request": request,
            "user": user,
            "stats": {
                "total_jobs": total_jobs,
                "running_jobs": running_jobs,
                "pending_jobs": pending_jobs,
                "completed_jobs": completed_jobs,
                "total_users": total_users,
                "total_admins": total_admins,
                "total_workflows": total_workflows,
                "ai_total": ai_total,
                "ai_enabled": ai_enabled,
                "enrich_total": enrich_total,
                "enrich_enabled": enrich_enabled,
                "active_tokens": active_tokens,
                "activity_last_hour": activity_last_hour,
            },
            "health": health,
            "storage_info": storage_info,
            "active_bg": active_bg,
            "active_ai_runs": active_ai_runs,
            "recent_activity": [{"created_at": e.created_at, "actor_label": e.actor_label, "label": activity.label_of(e.action), "outcome": e.outcome} for e in recent_activity],
            "default_admin_password": default_admin_password,
            "production_warnings": production_warnings,
            # The Activity card reads `activity_log_enabled` off this to label itself
            # "off" rather than looking broken when capture has never been turned on.
            "site_settings": await get_site_settings(db),
            "maintenance_actions": MAINTENANCE_ACTIONS,
            "getting_started": getting_started,
            "worker_start_fix": system_checks.WORKER_START_FIX,
        },
    )


@router.get("/system-checks-partial")
async def system_checks_partial(
    request: Request,
    force: int = 0,
    user: User = Depends(current_superuser),
):
    """Lazy-loaded System Status card body — full shared check suite (may take
    a couple of seconds: storage probe, tool binaries, disk).

    `?force=1` is what the "Re-run checks" button sends, and it is the **only** thing that
    runs the suite from here. Opening the tab passes `stale_ok=True`: it shows whatever the
    Overview readiness card already paid for, however old, with "Checked <n> ago" beside the
    button that refreshes it. Reaching a page must not cost a `docker info`.
    """
    from fastapi.concurrency import run_in_threadpool

    from app import system_checks
    from app.config import settings as app_settings

    results, ran_at = await run_in_threadpool(system_checks.run_all_cached, force=bool(force), stale_ok=True)
    return templates.TemplateResponse(
        request,
        "admin/partials/_system_checks.html",
        {
            "request": request,
            "results": results,
            "summary": system_checks.summarize(results),
            "ran_at": datetime.fromtimestamp(ran_at, tz=UTC).replace(tzinfo=None),
            "version_info": {"version": app_settings.app_version},
        },
    )


@router.get("/readiness-partial")
async def readiness_partial(
    request: Request,
    user: User = Depends(current_superuser),
):
    """Compact deployment-readiness verdict for the Overview tab (lazy-loaded).

    Same check suite + `summarize()` as the System tab card and `./logstotal doctor` —
    the CLI and the dashboard can never disagree on what "ready" means.

    Goes through the same cache as the System tab, so opening `/admin` and then clicking
    System runs the suite once between them instead of twice.
    """
    from fastapi.concurrency import run_in_threadpool

    from app import system_checks

    results, ran_at = await run_in_threadpool(system_checks.run_all_cached)
    return templates.TemplateResponse(
        request,
        "admin/partials/_readiness.html",
        {
            "request": request,
            "summary": system_checks.summarize(results),
            "ran_at": datetime.fromtimestamp(ran_at, tz=UTC).replace(tzinfo=None),
        },
    )


def _fetch_worker_concurrency_meta() -> list[dict]:
    """Sync Redis read: per-process host meta for the effective-concurrency card.

    Delegates to app/redis_client.py::get_worker_concurrency_meta (shared with
    app/system_checks.py). Sync so it can be offloaded with run_in_threadpool.
    """
    from app.redis_client import get_worker_concurrency_meta

    return get_worker_concurrency_meta()


async def _workflow_limits(db: AsyncSession) -> tuple[int, int]:
    """(max per-tool threads, max tools in one workflow) from WorkflowDef rows —
    that's what jobs actually run. Tolerates individual parse failures (skip)."""
    from app.detection.workflow_runner import parse_workflow_yaml
    from app.models import WorkflowDef

    max_threads = 1
    max_tools = 1
    for (tasks_yaml,) in (await db.execute(select(WorkflowDef.tasks_yaml))).all():
        try:
            tasks = parse_workflow_yaml(tasks_yaml or "")
        except Exception:
            continue
        if not tasks:
            continue
        max_tools = max(max_tools, len(tasks))
        for t in tasks:
            try:
                thr = int(t.get("threads", 1) or 1)
            except (TypeError, ValueError):
                thr = 1
            max_threads = max(max_threads, thr)
    return max_threads, max_tools


@router.get("/concurrency-partial")
async def concurrency_partial(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Lazy-loaded effective-concurrency card body (System tab).

    Peak-CPU model lives in app/concurrency.py (matches docs/scaling.md). Live
    worker meta comes from Redis (sync, offloaded); per-tool threads and
    tools-per-workflow are DB truth, parsed from WorkflowDef rows.
    """
    from fastapi.concurrency import run_in_threadpool

    from app.concurrency import compute_concurrency, recommend_host_settings
    from app.config import settings as app_settings

    site_settings = await get_site_settings(db)
    parallel_execution = bool(site_settings.parallel_execution)

    max_threads, max_tools = await _workflow_limits(db)

    worker_meta = await run_in_threadpool(_fetch_worker_concurrency_meta)
    hosts = compute_concurrency(
        worker_meta,
        tool_max_workers=app_settings.tool_max_workers,
        parallel_execution=parallel_execution,
        max_tools_per_workflow=max_tools,
        max_workflow_threads=max_threads,
    )
    # Current-vs-recommended workers per host (RAM unknown for remote hosts —
    # CPU-only sizing, same math as task recommend-scaling).
    recommended_workers = {h.hostname: recommend_host_settings(h.cpu_count, None, max_tools)["huey_workers"] for h in hosts if h.cpu_count}
    return templates.TemplateResponse(
        request,
        "admin/partials/_concurrency.html",
        {
            "request": request,
            "hosts": hosts,
            "parallel_execution": parallel_execution,
            "tool_max_workers": app_settings.tool_max_workers,
            "threads_per_tool": max_threads,
            "max_tools_per_workflow": max_tools,
            "recommended_workers": recommended_workers,
        },
    )


@router.get("/background-tasks/{task_id}/status-partial")
async def background_task_status_partial(
    task_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """HTMX partial: live status chip for one BackgroundTask (self-polls while active)."""
    bt = await db.get(BackgroundTask, task_id)
    if not bt:
        raise HTTPException(404)
    return templates.TemplateResponse(request, "admin/partials/_bg_task_status.html", {"request": request, "task": bt})


@router.post("/backfill-similarity")
async def backfill_similarity_trigger(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Enqueue TLSH + rule signature backfill for all existing records. Admin only."""
    from app.workers.tasks import backfill_similarity

    return await _queue_background_task(request, db, "Similarity Backfill", backfill_similarity, "backfill", user=user)


@router.post("/backfill-analytics")
async def backfill_analytics_trigger(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Recompute and cache analytics for all terminal jobs. Admin only."""
    from app.workers.tasks import backfill_analytics

    return await _queue_background_task(request, db, "Analytics Cache Rebuild", backfill_analytics, "backfill_analytics", user=user)


@router.post("/backfill-entities")
async def backfill_entities_trigger(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Populate Entity tables from existing analytics data. Admin only."""
    from app.workers.tasks import backfill_entities

    return await _queue_background_task(request, db, "Entity Backfill", backfill_entities, "backfill_entities", user=user)


@router.post("/backfill-entity-attributes")
async def backfill_entity_attributes_trigger(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Recompute per-type entity attributes for all entities. Admin only."""
    from app.workers.tasks import backfill_entity_attributes

    return await _queue_background_task(request, db, "Entity Attribute Backfill", backfill_entity_attributes, "backfill_entity_attributes", user=user)


@router.post("/backfill-builtin-labels")
async def backfill_builtin_labels_trigger(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Apply every enabled built-in label rule to every existing entity. Admin only."""
    from app.workers.tasks import backfill_builtin_labels

    return await _queue_background_task(request, db, "Shared Rules", backfill_builtin_labels, "backfill_builtin_labels", user=user)


@router.post("/backfill-relationships")
async def backfill_relationships_trigger(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Rebuild typed entity relationships from raw tool output. Admin only."""
    from app.workers.tasks import backfill_relationships

    return await _queue_background_task(request, db, "Relationship Backfill", backfill_relationships, "backfill_relationships", user=user)


@router.post("/backfill-finding-entity-links")
async def backfill_finding_entity_links_trigger(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Rebuild FindingEntityLink rows for all existing jobs. Admin only."""
    from app.workers.tasks import backfill_finding_entity_links

    return await _queue_background_task(request, db, "Finding-Entity Link Backfill", backfill_finding_entity_links, "backfill_finding_entity_links", user=user)


@router.post("/cleanup-outputs")
async def cleanup_outputs_trigger(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Enqueue cleanup of old job output directories. Admin only."""
    from app.workers.tasks import cleanup_old_job_outputs

    return await _queue_background_task(request, db, "Output Directory Cleanup", cleanup_old_job_outputs, "cleanup", user=user)


@router.get("/settings")
async def settings_page(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Render site settings form. Admin only."""
    from fastapi.concurrency import run_in_threadpool

    from app.concurrency import compute_concurrency
    from app.config import settings as app_settings

    site_settings = await get_site_settings(db)

    # Non-blocking oversubscription hint for the parallel-execution toggle: what
    # WOULD the peak look like with it ON, per live worker host (README model).
    parallel_risk: list[str] = []
    try:
        max_threads, max_tools = await _workflow_limits(db)
        worker_meta = await run_in_threadpool(_fetch_worker_concurrency_meta)
        hosts = compute_concurrency(
            worker_meta,
            tool_max_workers=app_settings.tool_max_workers,
            parallel_execution=True,
            max_tools_per_workflow=max_tools,
            max_workflow_threads=max_threads,
        )
        parallel_risk = [f"{h.hostname}: peak {h.parallel_peak} > {h.cpu_count} cores" for h in hosts if h.cpu_count and h.parallel_peak > h.cpu_count]
    except Exception:
        parallel_risk = []

    return templates.TemplateResponse(
        request,
        "admin/settings.html",
        {
            "request": request,
            "user": user,
            "site_settings": site_settings,
            "saved": bool(request.query_params.get("saved")),
            "parallel_risk": parallel_risk,
            "activity_categories": activity.CATEGORIES,
            "activity_selected": activity.parse_categories(site_settings.activity_categories),
            "activity_labels": {c: sorted({spec.label for k, spec in activity.ACTIONS.items() if spec.category == c}) for c in activity.CATEGORIES},
        },
    )


@router.post("/settings")
async def settings_save(
    parallel_execution: bool = Form(False),
    max_finding_details: int = Form(10),
    max_upload_files: int | None = Form(None, ge=1, le=500),
    show_mitre_heatmap: bool = Form(False),
    show_event_timeline: bool = Form(False),
    show_alert_timeline: bool = Form(False),
    show_entities: bool = Form(False),
    show_threat_detection: bool = Form(False),
    show_process_tree: bool = Form(False),
    builtin_rules_enabled: bool = Form(False),
    render_markdown: bool = Form(False),
    show_ai_analysis: bool = Form(False),
    show_ai_prompt: bool = Form(False),
    activity_log_enabled: bool = Form(False),
    activity_categories: list[str] = Form([]),
    demo_mode: bool = Form(False),
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Persist site-wide settings. Admin only.

    The field list here is exhaustive by design — anything absent is left untouched, which
    is what lets the retention overrides live on /admin/storage without this page silently
    resetting them from a form that never showed them.
    """
    site_settings = await get_site_settings(db)
    incoming = {
        "parallel_execution": parallel_execution,
        "max_finding_details": max(1, max_finding_details),
        "show_mitre_heatmap": show_mitre_heatmap,
        "show_event_timeline": show_event_timeline,
        "show_alert_timeline": show_alert_timeline,
        "show_entities": show_entities,
        "show_threat_detection": show_threat_detection,
        "show_process_tree": show_process_tree,
        "builtin_rules_enabled": builtin_rules_enabled,
        "render_markdown": render_markdown,
        "show_ai_analysis": show_ai_analysis,
        "show_ai_prompt": show_ai_prompt,
        "activity_log_enabled": activity_log_enabled,
        # Stored as CSV in the order `CATEGORIES` declares, so the value is stable and the
        # settings diff does not report a change when only the checkbox order differed.
        "activity_categories": ",".join(c for c in activity.CATEGORIES if c in set(activity_categories)),
        "demo_mode": demo_mode,
    }
    if max_upload_files is not None:
        incoming["max_upload_files"] = max_upload_files
    # Snapshot before assigning — `diff_settings` needs the pre-save values.
    before = {key: getattr(site_settings, key) for key in incoming}
    for key, value in incoming.items():
        setattr(site_settings, key, value)
    await db.commit()
    changed = activity.diff_settings(before, incoming)
    if changed:
        # Captured under the policy in force *before* this save: if it was recording admin
        # changes, this change is recorded even when it is the one that stops that.
        was_capturing = before["activity_log_enabled"] and activity.category_of("admin.settings.changed") in activity.parse_categories(before["activity_categories"])
        await activity.record(
            "admin.settings.changed",
            request=request,
            user=user,
            target_type="settings",
            target_id="1",
            summary=", ".join(sorted(changed)),
            meta={"changed": changed},
            force=bool(was_capturing),
        )
    return RedirectResponse("/admin/settings?saved=1", status_code=303)


async def _fetch_task_data(db: AsyncSession) -> dict:
    """Query active and recently finished jobs + background tasks + Huey queue/schedule."""
    from fastapi.concurrency import run_in_threadpool

    eager = [
        selectinload(AnalysisJob.log_file),
        selectinload(AnalysisJob.workflow),
        selectinload(AnalysisJob.submitter),
        selectinload(AnalysisJob.task_results),
    ]

    active_q = select(AnalysisJob).where(AnalysisJob.status.in_([JobStatus.PENDING, JobStatus.RUNNING])).options(*eager).order_by(AnalysisJob.created_at.desc()).limit(100)
    active_result = await db.execute(active_q)
    active_jobs = active_result.scalars().all()

    recent_q = (
        select(AnalysisJob)
        .where(AnalysisJob.status.in_([JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.PARTIAL, JobStatus.CANCELLED]))
        .options(*eager)
        .order_by(AnalysisJob.finished_at.desc())
        .limit(10)
    )
    recent_result = await db.execute(recent_q)
    recent_jobs = recent_result.scalars().all()

    active_bg_q = (
        select(BackgroundTask).where(BackgroundTask.status.in_([BackgroundTaskStatus.PENDING, BackgroundTaskStatus.RUNNING])).order_by(BackgroundTask.created_at.desc()).limit(50)
    )
    active_bg_result = await db.execute(active_bg_q)
    active_bg_tasks = active_bg_result.scalars().all()

    recent_bg_q = (
        select(BackgroundTask)
        .where(BackgroundTask.status.in_([BackgroundTaskStatus.COMPLETED, BackgroundTaskStatus.FAILED, BackgroundTaskStatus.CANCELLED]))
        .order_by(BackgroundTask.finished_at.desc())
        .limit(50)
    )
    recent_bg_result = await db.execute(recent_bg_q)
    recent_bg_tasks = recent_bg_result.scalars().all()

    # AI runs are their own record (`JobAiAnalysis`), richer than a BackgroundTask row and
    # not worth duplicating into one — but an admin watching /admin/tasks must still see a
    # model working. They get their own
    # section rather than being folded into the others: different statuses, a different
    # cancel route, and a token/duration story none of the rest have.
    ai_eager = [selectinload(JobAiAnalysis.requested_by)]
    active_ai = (
        (
            await db.execute(
                select(JobAiAnalysis)
                .where(JobAiAnalysis.status.in_([AiAnalysisStatus.PENDING, AiAnalysisStatus.RUNNING]))
                .options(*ai_eager)
                .order_by(JobAiAnalysis.created_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    recent_ai = (
        (
            await db.execute(
                select(JobAiAnalysis)
                .where(JobAiAnalysis.status.in_([AiAnalysisStatus.COMPLETED, AiAnalysisStatus.FAILED, AiAnalysisStatus.CANCELLED]))
                .options(*ai_eager)
                .order_by(JobAiAnalysis.finished_at.desc().nullslast(), JobAiAnalysis.id.desc())
                .limit(10)
            )
        )
        .scalars()
        .all()
    )
    # `JobAiAnalysis` has no `job` relationship and does not need one for this — a second
    # small query keyed by the ids we already hold beats adding a mapping just to render a
    # filename, and it is the same shape the storage page uses for its largest-jobs list.
    ai_job_names: dict[int, str] = {}
    ai_job_ids = {run.job_id for run in (*active_ai, *recent_ai)}
    if ai_job_ids:
        rows = (await db.execute(select(AnalysisJob.id, AnalysisJob.filename).join(LogFile, AnalysisJob.file_id == LogFile.id).where(AnalysisJob.id.in_(ai_job_ids)))).all()
        ai_job_names = {row[0]: row[1] for row in rows}
    # Liveness for a run comes from Redis, exactly as the job's AI panel decides it — a
    # second opinion here would let the two pages disagree about whether a run is alive.
    stale_ai_ids = await run_in_threadpool(_stalled_ai_ids, [(a.id, enum_val(a.status), a.created_at) for a in active_ai])

    # Case runs share the monitor but have distinct heartbeat identities and links.
    case_eager = selectinload(CaseAiAnalysis.requested_by)
    active_case_ai = list(
        await db.scalars(
            select(CaseAiAnalysis)
            .where(CaseAiAnalysis.status.in_([AiAnalysisStatus.PENDING, AiAnalysisStatus.RUNNING]))
            .options(case_eager)
            .order_by(CaseAiAnalysis.created_at.desc())
            .limit(50)
        )
    )
    recent_case_ai = list(
        await db.scalars(
            select(CaseAiAnalysis)
            .where(CaseAiAnalysis.status.in_([AiAnalysisStatus.COMPLETED, AiAnalysisStatus.FAILED, AiAnalysisStatus.CANCELLED]))
            .options(case_eager)
            .order_by(CaseAiAnalysis.finished_at.desc().nullslast(), CaseAiAnalysis.id.desc())
            .limit(10)
        )
    )
    case_ids = {r.case_id for r in [*active_case_ai, *recent_case_ai]}
    ai_case_names = dict((await db.execute(select(InvestigationCase.id, InvestigationCase.name).where(InvestigationCase.id.in_(case_ids)))).all()) if case_ids else {}
    stale_case_ai_ids = await run_in_threadpool(_stalled_ai_ids, [(r.id, enum_val(r.status), r.created_at) for r in active_case_ai], scope="case:")
    active_ai = sorted([*active_ai, *active_case_ai], key=lambda r: r.created_at, reverse=True)[:50]
    recent_ai = sorted([*recent_ai, *recent_case_ai], key=lambda r: r.finished_at or r.created_at, reverse=True)[:10]

    # Both snapshots and the scheduled table are sync Redis calls, so they go through one
    # threadpool hop rather than blocking the event loop.
    huey_queue, huey_scheduled, scheduled_tasks = await run_in_threadpool(_queue_views)

    stale_bg = [bt for bt in active_bg_tasks if _bg_task_is_stalled(bt)]

    has_active = len(active_jobs) > 0 or len(active_bg_tasks) > 0 or len(active_ai) > 0 or huey_queue["queue_size"] > 0 or huey_scheduled["scheduled_size"] > 0

    return {
        "active_jobs": active_jobs,
        "recent_jobs": recent_jobs,
        "active_bg_tasks": active_bg_tasks,
        "recent_bg_tasks": recent_bg_tasks,
        "active_ai": active_ai,
        "recent_ai": recent_ai,
        "ai_job_names": ai_job_names,
        "ai_case_names": ai_case_names,
        "stale_case_ai_ids": stale_case_ai_ids,
        "stale_ai_ids": stale_ai_ids,
        "huey_queue": huey_queue,
        "huey_scheduled": huey_scheduled,
        "scheduled_tasks": scheduled_tasks,
        "stale_bg_ids": {bt.id for bt in stale_bg},
        "registry": task_registry.REGISTRY,
        "cancellable": task_registry.CANCELLABLE,
        "retryable": task_registry.RETRYABLE,
        "has_active": has_active,
    }


def _queue_views() -> tuple[dict, dict, list[dict]]:
    """The three Redis-backed views, fetched together in one threadpool hop."""
    from app.huey_inspect import get_queue_snapshot, get_scheduled_snapshot, get_scheduled_task_status

    return get_queue_snapshot(limit=20), get_scheduled_snapshot(limit=20), get_scheduled_task_status()


#: A row whose worker has not beaten for this long is presumed dead. Generous relative to
#: `worker_heartbeat_ttl`, because a backfill only beats at batch boundaries and a slow
#: batch is not a dead worker.
BG_TASK_STALE_SECONDS = 900


def _stalled_ai_ids(runs: list[tuple[int, str, object]], *, scope: str = "") -> set[int]:
    """Which of these AI runs no worker is beating for.

    Sync (Redis is sync) and given plain tuples rather than ORM rows, so it can be handed
    to a threadpool without a lazy attribute read turning into a `MissingGreenlet`.

    A missing heartbeat on a *running* row means the worker died mid-inference; a *pending*
    row is judged against the queue expiry instead, since nothing beats for work nobody has
    picked up. If Redis itself is unreachable we report none — declaring a live run dead is
    the worse error, which is the same call `routers/ai.py::_is_stalled` makes.
    """
    if not runs:
        return set()
    try:
        from app.redis_client import AI_HEARTBEAT_PREFIX, get_redis

        r = get_redis()
        pipe = r.pipeline()
        for analysis_id, _status, _created in runs:
            pipe.exists(f"{AI_HEARTBEAT_PREFIX}{scope}{analysis_id}")
        beats = pipe.execute()
    except Exception:
        return set()

    now = datetime.now(UTC).replace(tzinfo=None)
    stalled: set[int] = set()
    for (analysis_id, status, created_at), alive in zip(runs, beats, strict=False):
        if alive:
            continue
        if status == "running" or (status == "pending" and created_at and (now - created_at).total_seconds() > settings.huey_queue_expiry + 60):
            stalled.add(analysis_id)
    return stalled


def _bg_task_is_stalled(bt: BackgroundTask) -> bool:
    """Has this row been abandoned by the worker that claimed it?

    `heartbeat_at` is what tells a long backfill apart from one whose worker died mid-run,
    whose chip would otherwise spin forever. A `pending` row is judged by its age
    against the queue expiry instead, since nothing beats for a task nobody has picked up.
    """
    now = datetime.now(UTC).replace(tzinfo=None)
    status = bt.status.value if hasattr(bt.status, "value") else str(bt.status)
    if status == "running":
        beat = bt.heartbeat_at or bt.started_at
        return bool(beat and (now - beat).total_seconds() > BG_TASK_STALE_SECONDS)
    if status == "pending":
        return bool(bt.created_at and (now - bt.created_at).total_seconds() > settings.huey_queue_expiry + 60)
    return False


@router.get("/tasks")
async def tasks_page(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Admin task monitor: active and recently finished jobs/background tasks."""
    data = await _fetch_task_data(db)
    return templates.TemplateResponse(
        request,
        "admin/tasks.html",
        {"request": request, "user": user, **data},
    )


@router.get("/tasks/partial")
async def tasks_partial(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """HTMX partial for the tasks table (auto-polled while active)."""
    data = await _fetch_task_data(db)
    return templates.TemplateResponse(
        request,
        "admin/partials/_tasks_table.html",
        {"request": request, "user": user, **data},
    )


_USERS_PAGE_SIZE = 50


# ── Task control ─────────────────────────────────────────────────────────────
#
# Literal paths are registered BEFORE any parameterised sibling: `/admin/tasks/partial` is
# four segments, and a `/admin/tasks/{id}` registered earlier would swallow it. The global
# shadowing guard in tests/test_route_table_is_stable.py checks this for the whole table.


@router.post("/tasks/recover")
async def tasks_recover(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Close out background tasks no worker will finish.

    The `recover_stale_jobs` idea applied to `BackgroundTask`: a row left at `running` by a
    worker that died mid-backfill would spin its progress chip forever. `heartbeat_at` is
    what tells that apart from slow progress.
    """
    stmt = select(BackgroundTask).where(BackgroundTask.status.in_([BackgroundTaskStatus.PENDING, BackgroundTaskStatus.RUNNING]))
    rows = (await db.execute(stmt)).scalars().all()
    recovered = 0
    for bt in rows:
        if not _bg_task_is_stalled(bt):
            continue
        bt.status = BackgroundTaskStatus.FAILED
        bt.error_message = "Worker lost — recovered by admin"
        bt.finished_at = utc_now_naive()
        recovered += 1
    if recovered:
        await db.commit()
        await activity.record("admin.maintenance.recover", request=request, user=user, summary=f"{recovered} background task(s) recovered", meta={"recovered": recovered})
    return RedirectResponse(f"/admin/tasks?recovered={recovered}#activity", status_code=303)


@router.post("/tasks/queue/{task_id}/revoke")
async def tasks_revoke_queued(
    task_id: str,
    request: Request,
    user: User = Depends(current_superuser),
):
    """Tell the consumer to skip a queued task when it reaches it.

    Huey's revoke marks the id in the result store; the entry stays in the queue and is
    dropped at pickup. The UI says "will be skipped" rather than "removed" for that reason.
    """
    from fastapi.concurrency import run_in_threadpool

    from app.huey_inspect import revoke_task

    ok = await run_in_threadpool(revoke_task, task_id)
    if ok:
        await activity.record("admin.maintenance.revoke", request=request, user=user, target_type="huey_task", target_id=task_id)
    return RedirectResponse(f"/admin/tasks?revoked={int(ok)}#queue", status_code=303)


@router.post("/tasks/{bg_task_id}/cancel")
async def tasks_cancel(
    bg_task_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Ask a running background task to stop at its next batch boundary.

    The Redis flag is set **before** the DB is touched, the `POST /jobs/{id}/cancel` idiom:
    a worker that reads the flag between those two writes stops for the right reason, while
    the reverse order could mark a row cancelled that the worker never learns about.

    A `pending` row is finalised here — nothing has picked it up, so nobody would ever read
    the flag — and its queue entry is revoked so it does not start after being marked.
    """
    from fastapi.concurrency import run_in_threadpool

    from app.redis_client import BGTASK_CANCEL_PREFIX, get_redis

    bt = await db.get(BackgroundTask, bg_task_id)
    if not bt:
        raise HTTPException(404, "Task not found.")
    status = bt.status.value if hasattr(bt.status, "value") else str(bt.status)
    if status not in ("pending", "running"):
        return RedirectResponse("/admin/tasks#activity", status_code=303)
    if bt.kind and bt.kind not in task_registry.CANCELLABLE:
        raise HTTPException(400, f"{task_registry.label(bt.kind)} cannot be cancelled from here.")

    def _flag() -> None:
        get_redis().set(f"{BGTASK_CANCEL_PREFIX}{bg_task_id}", str(user.id), ex=settings.huey_queue_expiry + 86400)

    try:
        await run_in_threadpool(_flag)
    except Exception:
        # Without Redis the worker can never learn it was cancelled, so refuse rather than
        # writing a row that contradicts what the worker is about to do.
        raise HTTPException(503, "Cannot reach Redis to signal the worker.") from None

    if status == "pending":
        if bt.huey_task_id:
            from app.huey_inspect import revoke_task

            await run_in_threadpool(revoke_task, bt.huey_task_id)
        bt.status = BackgroundTaskStatus.CANCELLED
        bt.detail = "Cancelled before it started"
        bt.finished_at = utc_now_naive()
        await db.commit()
    await activity.record("admin.maintenance.cancel", request=request, user=user, target_type="background_task", target_id=str(bg_task_id), summary=bt.name)
    return RedirectResponse("/admin/tasks#activity", status_code=303)


@router.post("/tasks/{bg_task_id}/retry")
async def tasks_retry(
    bg_task_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Re-run a finished task as a NEW row.

    History is never mutated: the failed run stays exactly as it was, and the retry is a
    separate record with its own outcome. Overwriting the original would destroy the only
    evidence of what went wrong.
    """
    bt = await db.get(BackgroundTask, bg_task_id)
    if not bt:
        raise HTTPException(404, "Task not found.")
    status = bt.status.value if hasattr(bt.status, "value") else str(bt.status)
    if status in ("pending", "running"):
        raise HTTPException(400, "That task is still running.")
    if not bt.kind or bt.kind not in task_registry.RETRYABLE:
        raise HTTPException(400, "That task cannot be retried automatically.")
    task_fn = task_registry.resolve_callable(bt.kind)
    if task_fn is None:
        raise HTTPException(400, "That task no longer exists in this build.")
    per_target = bt.kind == "recalculate_single_analytics"
    if await find_active_background_task(db, bt.kind, target_id=bt.target_id if per_target else None) is not None:
        raise HTTPException(400, "Another run of that task is already in progress.")

    fresh = BackgroundTask(
        name=bt.name,
        kind=bt.kind,
        target_id=bt.target_id,
        requested_by_label=user.email,
        status=BackgroundTaskStatus.PENDING,
    )
    db.add(fresh)
    await db.commit()
    await db.refresh(fresh)
    # `recalculate_single_analytics` takes the job id as well as the row id it reports into;
    # every other retryable task takes only the row id.
    if bt.kind == "recalculate_single_analytics" and bt.target_id:
        queued = await enqueue_background_task(db, fresh, lambda: task_fn(int(bt.target_id), bg_task_id=fresh.id))
    else:
        queued = await enqueue_background_task(db, fresh, lambda: task_fn(fresh.id))
    if not queued:
        raise HTTPException(503, "The task queue is unreachable, so the retry could not be queued. Try again once it is back.")
    await activity.record(
        "admin.maintenance.retry", request=request, user=user, target_type="background_task", target_id=str(fresh.id), summary=f"retry of #{bg_task_id}: {bt.name}"
    )
    return RedirectResponse("/admin/tasks#activity", status_code=303)


async def _record_huey_task_id(db: AsyncSession, bg_task_id: int, result) -> None:
    """Store the queue id for a row we just enqueued, so it can be revoked later.

    A Core UPDATE of that one column, deliberately: the row must exist before the enqueue
    (the task needs its id), so between the two a worker may already have set the row to
    `running`. The session is `expire_on_commit=False`, so flushing a stale ORM instance
    here would write back the pre-enqueue status and undo that.
    """
    task_id = getattr(result, "id", None)
    if not task_id:
        return
    try:
        await db.execute(update(BackgroundTask).where(BackgroundTask.id == bg_task_id).values(huey_task_id=str(task_id)))
        await db.commit()
    except Exception:
        pass


@router.get("/users")
async def user_list(
    request: Request,
    page: int = 1,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """List all users (paginated). Admin only."""
    page = max(1, page)  # a negative OFFSET is a hard error on PostgreSQL
    offset = (page - 1) * _USERS_PAGE_SIZE
    result = await db.execute(select(User).order_by(User.created_at.desc()).offset(offset).limit(_USERS_PAGE_SIZE))
    users = result.scalars().all()
    # `total_users` is computed for the pager anyway; the header pill needs it too, and
    # `users | length` cannot stand in for it — that is one page of 50.
    total_users, total_admins = (await db.execute(select(func.count(User.id), func.count(case((User.is_superuser.is_(True), 1)))))).one()
    total_pages = max(1, -(-total_users // _USERS_PAGE_SIZE))
    return templates.TemplateResponse(
        request,
        "admin/users.html",
        {
            "request": request,
            "user": user,
            "users": users,
            "total_users": total_users,
            "total_admins": total_admins,
            "page": page,
            "total_pages": total_pages,
            "error": request.query_params.get("error"),
        },
    )


@router.post("/users/create")
async def user_create(
    email: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(""),
    role: str = Form("user"),
    request: Request = None,
    manager: UserManager = Depends(get_user_manager),
    user: User = Depends(current_superuser),
):
    """Create a new user account. Admin only."""
    is_superuser = role == "admin"
    effective_role = role if role in ("user", "member", "admin") else "user"
    try:
        new_user = UserCreate(
            email=email,
            password=password,
            display_name=display_name or None,
            is_superuser=is_superuser,
            is_active=True,
            role=effective_role,
        )
    except ValidationError as exc:
        # The form's type=email accepts addresses the schema refuses (corp.local, a@b), and
        # the display name has a column-sized cap. Both are the admin's to correct.
        first = exc.errors()[0]
        field = ".".join(str(p) for p in first.get("loc", ())) or "input"
        message = f"{field}: {first.get('msg', 'invalid')}"
        return RedirectResponse(f"/admin/users?error={quote(message)}", status_code=303)
    try:
        await manager.create(new_user)
    except UserAlreadyExists:
        return RedirectResponse("/admin/users?error=Email+already+exists", status_code=303)
    except InvalidPasswordException as exc:
        return RedirectResponse(f"/admin/users?error={quote(exc.reason)}", status_code=303)
    await activity.record("admin.user.create", request=request, user=user, target_type="user", target_id=email, summary=f"{email} as {effective_role}")
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/set-password")
async def user_set_password(
    user_id: str,
    password: str = Form(...),
    request: Request = None,
    manager: UserManager = Depends(get_user_manager),
    user: User = Depends(current_superuser),
):
    """Set a user's password. Admin only; own password allowed (clears the default-password banner)."""
    if len(password) < 8:
        return RedirectResponse("/admin/users?error=Password+must+be+at+least+8+characters", status_code=303)
    try:
        target = await manager.get(_user_uuid(user_id))
    except UserNotExists:
        raise HTTPException(404) from None
    try:
        await manager.update(UserUpdate(password=password), target, safe=True)
    except InvalidPasswordException as exc:
        return RedirectResponse(f"/admin/users?error={quote(exc.reason)}", status_code=303)
    # The password itself is never recorded, only that it was set and for whom.
    await activity.record("admin.user.set_password", request=request, user=user, target_type="user", target_id=str(target.id), summary=target.email)
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/change-role")
async def user_change_role(
    user_id: str,
    role: str = Form(...),
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    current: User = Depends(current_superuser),
):
    """Change a user's role. Admin only; cannot change own role."""
    target = await db.get(User, _user_uuid(user_id))
    if not target:
        raise HTTPException(404)
    if target.id == current.id:
        raise HTTPException(400, "Cannot change your own role.")
    if role not in ("user", "member", "admin"):
        raise HTTPException(400, "Invalid role.")
    was = target.role
    target.role = role
    target.is_superuser = role == "admin"
    await db.commit()
    await activity.record(
        "admin.user.role_change",
        request=request,
        user=current,
        target_type="user",
        target_id=str(target.id),
        summary=f"{target.email}: {was} to {role}",
        meta={"from": was, "to": role},
    )
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/toggle-active")
async def user_toggle_active(
    user_id: str,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    current: User = Depends(current_superuser),
):
    """Toggle a user's active status. Admin only; cannot deactivate self."""
    target = await db.get(User, _user_uuid(user_id))
    if not target:
        raise HTTPException(404)
    if target.id == current.id:
        raise HTTPException(400, "Cannot deactivate yourself.")
    target.is_active = not target.is_active
    await db.commit()
    await activity.record(
        "admin.user.toggle_active",
        request=request,
        user=current,
        target_type="user",
        target_id=str(target.id),
        summary=f"{target.email} {'activated' if target.is_active else 'deactivated'}",
    )
    return RedirectResponse("/admin/users", status_code=303)


#: Every ``ForeignKey("user.id")`` column that is anonymised when a user is deleted — all
#: of them nullable. (API tokens, job watches and intel rules are deleted instead; see
#: ``_clear_user_references``.) An analyst leaving must not take the jobs, cases, tags and
#: comment history the team still works from with them.
#: Keep in lock-step with the FKs in ``app/models.py`` — no FK to ``user.id`` carries
#: ``ondelete=``, and SQLite has FK enforcement off, so a missed column is a silent
#: dangling reference there and a ``ForeignKeyViolation`` on PostgreSQL.
_USER_REFERENCES = (
    (AnalysisJob, "submitted_by_user_id"),
    (EntityTag, "created_by_user_id"),
    # Anonymised, not deleted, exactly like its entity twin: who applied a tag is
    # authorship, and the tag itself is a curation decision that outlives its author.
    (JobTag, "created_by_user_id"),
    (TagDefinition, "created_by_user_id"),
    (IntelRuleMatch, "acknowledged_by_user_id"),
    (JobRuleMatch, "acknowledged_by_user_id"),
    (InvestigationCase, "created_by_user_id"),
    (CaseEntityLink, "added_by_user_id"),
    (CaseJobLink, "added_by_user_id"),
    (Comment, "author_user_id"),
    (Comment, "deleted_by_user_id"),
    (SavedSearch, "created_by_user_id"),
    # Anonymised, not deleted: an AI analysis is a record of what was concluded about a
    # job, like a comment, and it does not *act* once its requester is gone. `provider_id`
    # is a separate question and is handled at provider deletion.
    (JobAiAnalysis, "requested_by_user_id"),
    (CaseAiAnalysis, "requested_by_user_id"),
    # Anonymised, emphatically not deleted: an audit log a user can erase by deleting
    # their own account is not an audit log. `actor_label` is the email snapshot that
    # keeps the row legible once the FK is nulled — the `JobAiAnalysis.provider_name`
    # idiom applied to an actor rather than a provider.
    (ActivityEvent, "actor_user_id"),
)


async def _clear_user_references(db: AsyncSession, user_id) -> None:
    """Null out every FK to *user_id*, and delete the rows that would still act without one.

    A private job whose owner is nulled falls back to admin-only visibility (see
    ``visible_job_filter``), as does an unshared case or saved search — the data
    survives and stays reachable, just not by the departed account.

    Three kinds of row are deleted instead of anonymised — API tokens, job watches and
    intel rules — because for them an ownerless copy is not a record but a live actor.
    ``tests/test_fk_cleanup_parity.py`` asserts that every FK to ``user.id`` is in one
    bucket or the other.
    """
    for model, column in _USER_REFERENCES:
        await db.execute(update(model).where(getattr(model, column) == user_id).values(**{column: None}))
    # An API token is a live credential, not authorship — it must not outlive its owner.
    await db.execute(delete(ApiToken).where(ApiToken.created_by_user_id == user_id))
    # A watch is deleted, not anonymised: `user_id` is NOT NULL, and an ownerless
    # subscription would still *act* — writing notification rows nobody can ever ack.
    # Same bucket as ApiToken and IntelRule, for the same reason.
    _owned_watches = select(JobWatch.id).where(JobWatch.user_id == user_id)
    await db.execute(delete(JobWatchEvent).where(JobWatchEvent.watch_id.in_(_owned_watches)))
    await db.execute(delete(JobWatch).where(JobWatch.user_id == user_id))
    # An intel rule keeps evaluating and POSTing to its webhook on every finished job, so
    # a nulled owner leaves an unattributable rule firing at a receiver nobody owns — and
    # uq_intel_rule_auto_entity would collide the moment a second departed user's ★ rule
    # for the same entity was nulled too. Delete the rules, and their children first:
    # IntelRule.matches cascades in the ORM, but this is a Core delete, so nothing fires.
    owned_rules = select(IntelRule.id).where(IntelRule.owner_user_id == user_id)
    await db.execute(delete(WebhookDelivery).where(WebhookDelivery.rule_id.in_(owned_rules)))
    await db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.rule_id.in_(owned_rules)))
    await db.execute(delete(JobRuleMatch).where(JobRuleMatch.rule_id.in_(owned_rules)))
    await db.execute(delete(IntelRule).where(IntelRule.owner_user_id == user_id))


@router.post("/users/{user_id}/delete")
async def user_delete(
    user_id: str,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    current: User = Depends(current_superuser),
):
    """Delete a user account. Admin only; cannot delete self."""
    target = await db.get(User, _user_uuid(user_id))
    if not target:
        raise HTTPException(404)
    if target.id == current.id:
        raise HTTPException(400, "Cannot delete yourself.")
    deleted_email = target.email
    await _clear_user_references(db, target.id)
    await db.delete(target)
    await db.commit()
    # Recorded *after* the commit, and on its own session. Sharing this one would have
    # committed `_clear_user_references`'s updates before `db.delete(target)` ran.
    await activity.record("admin.user.delete", request=request, user=current, target_type="user", target_id=str(user_id), summary=deleted_email)
    return RedirectResponse("/admin/users", status_code=303)


@router.get("/workers")
async def workers_page(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Worker fleet dashboard: active workers, queue depth, stuck jobs."""
    data = await _fetch_worker_data(db)
    return templates.TemplateResponse(
        request,
        "admin/workers.html",
        {"request": request, "user": user, **data},
    )


@router.get("/workers/partial")
async def workers_partial(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """HTMX partial for worker fleet data (auto-polled)."""
    data = await _fetch_worker_data(db)
    return templates.TemplateResponse(
        request,
        "admin/partials/_workers_table.html",
        {"request": request, "user": user, **data},
    )


@router.post("/recover-stuck-jobs")
async def recover_stuck_jobs(
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Fail jobs no worker will finish: RUNNING with no heartbeat, or PENDING past expiry. Admin only."""
    from app.recovery import recover_stale_jobs
    from app.redis_client import get_redis

    recovered = await recover_stale_jobs(db, get_redis(), message=RECOVERY_MSG_ADMIN)
    if recovered:
        await activity.record("admin.maintenance.recover", request=request, user=user, summary=f"{recovered} job(s) recovered", meta={"recovered": recovered})
    return RedirectResponse(f"/admin/workers?recovered={recovered}", status_code=303)


@router.post("/workers/priority")
async def workers_set_priority(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Set max_concurrent_jobs for one or more hostnames. Admin only.

    Accepts form fields named ``slots_<hostname>`` with integer values (-1 = paused, 0 = unlimited, 1+ = cap).
    """
    from app.redis_client import WORKER_POLICY_PREFIX

    form = await request.form()
    changed = 0
    r = None
    try:
        from app.redis_client import get_redis

        r = get_redis()
    except Exception:
        pass
    for key, raw_value in form.items():
        if not key.startswith("slots_"):
            continue
        hostname = key[len("slots_") :]
        if not hostname:
            continue
        try:
            slots = max(-1, int(raw_value))
        except (ValueError, TypeError):
            continue
        result = await db.execute(select(WorkerPolicy).where(WorkerPolicy.hostname == hostname))
        policy = result.scalar_one_or_none()
        if policy:
            if policy.max_concurrent_jobs != slots:
                policy.max_concurrent_jobs = slots
                changed += 1
        else:
            db.add(WorkerPolicy(hostname=hostname, max_concurrent_jobs=slots))
            changed += 1
        if r:
            try:
                r.set(f"{WORKER_POLICY_PREFIX}{hostname}", str(slots), ex=120)
            except Exception:
                pass
    if changed:
        await db.commit()
        # `hosts`, not `changed`: `changed` is a typed key meaning `{field: {from, to}}`, and
        # the activity table calls `.items()` on it. A bare count there would 500 the whole of
        # /admin/activity for every viewer until the row was pruned. `_activity_table.html`
        # also refuses a non-mapping.
        await activity.record("admin.worker.priority", request=request, user=user, summary=f"{changed} host(s) updated", meta={"hosts": changed})
    return RedirectResponse(f"/admin/workers?priority_saved={changed}", status_code=303)


def _discover_workers_sync() -> tuple[dict[str, dict], dict[str, str]]:
    """Every Redis read behind the worker fleet table, in one synchronous block.

    `app/redis_client.py` ships a **sync** client, and this sits behind a partial that
    self-polls every 5 seconds: three `scan_iter` keyspace walks plus several round trips per
    worker, which would block the event loop inline. Gathering it here lets the caller make one
    `run_in_threadpool` hop, and lets each phase use a pipeline instead of a round trip
    per key.

    Returns `(registered, heartbeat_map)` — plain dicts, so nothing ORM-shaped crosses the
    threadpool boundary.
    """
    from app.redis_client import HEARTBEAT_PREFIX, WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX, get_redis

    r = get_redis()

    # Discover registered workers from process metadata, falling back to alive keys.
    # One pipeline for the hgetall+ttl pair rather than two round trips per worker.
    info_keys = list(r.scan_iter(f"{WORKER_INFO_PREFIX}*"))
    with r.pipeline(transaction=False) as pipe:
        for key in info_keys:
            pipe.hgetall(key)
            pipe.ttl(key)
        info_results = pipe.execute()

    registered: dict[str, dict] = {}
    for idx, key in enumerate(info_keys):
        wid = key.replace(WORKER_INFO_PREFIX, "")
        info = info_results[idx * 2] or {}
        ttl = info_results[idx * 2 + 1]
        seed_job = info.get("current_job_id")
        registered[wid] = {
            "worker_id": wid,
            "worker_name": info.get("worker_name") or info.get("hostname") or wid,
            "hostname": info.get("hostname") or wid.split(":", 1)[0],
            "ip_address": info.get("ip_address") or "unknown",
            "status": "idle",
            "current_job_ids": [seed_job] if seed_job else [],
            "heartbeat_ttl": ttl,
            "jobs_completed": int(info.get("jobs_completed") or 0),
            "os": info.get("os", ""),
            "arch": info.get("arch", ""),
            "python_version": info.get("python_version", ""),
            "cpu_count": info.get("cpu_count", ""),
            "memory_gb": info.get("memory_gb", ""),
            "huey_workers": info.get("huey_workers", ""),
        }

    alive_keys = list(r.scan_iter(f"{WORKER_ALIVE_PREFIX}*"))
    with r.pipeline(transaction=False) as pipe:
        for key in alive_keys:
            pipe.ttl(key)
        alive_ttls = pipe.execute()

    for key, ttl in zip(alive_keys, alive_ttls, strict=True):
        wid = key.replace(WORKER_ALIVE_PREFIX, "")
        if wid in registered:
            registered[wid]["heartbeat_ttl"] = max(registered[wid]["heartbeat_ttl"], ttl)
            continue
        registered[wid] = {
            "worker_id": wid,
            "worker_name": wid.split(":", 1)[0],
            "hostname": wid.split(":", 1)[0],
            "ip_address": "unknown",
            "status": "idle",
            "current_job_ids": [],
            "heartbeat_ttl": ttl,
            "jobs_completed": 0,
        }

    # Map active job heartbeats to workers.
    # Thread ID format: "hostname:pid:thread", process ID: "hostname:pid".
    # Collect ALL job_ids per process (supports HUEY_WORKERS > 1).
    heartbeat_map: dict[str, str] = {}
    hb_keys = list(r.scan_iter(f"{HEARTBEAT_PREFIX}*"))
    with r.pipeline(transaction=False) as pipe:
        for key in hb_keys:
            pipe.get(key)
            pipe.ttl(key)
        hb_results = pipe.execute()

    for idx, key in enumerate(hb_keys):
        job_id = key.replace(HEARTBEAT_PREFIX, "")
        thread_worker_id = hb_results[idx * 2]
        if not thread_worker_id:
            continue
        ttl = hb_results[idx * 2 + 1]

        parts = thread_worker_id.rsplit(":", 1)
        process_id = parts[0] if len(parts) == 2 else thread_worker_id

        if process_id in registered:
            registered[process_id]["status"] = "busy"
            if job_id not in registered[process_id]["current_job_ids"]:
                registered[process_id]["current_job_ids"].append(job_id)
            registered[process_id]["heartbeat_ttl"] = min(registered[process_id]["heartbeat_ttl"], ttl)
        else:
            registered[process_id] = {
                "worker_id": process_id,
                "worker_name": process_id.split(":", 1)[0],
                "hostname": process_id.split(":", 1)[0],
                "ip_address": "unknown",
                "status": "busy",
                "current_job_ids": [job_id],
                "heartbeat_ttl": ttl,
                "jobs_completed": 0,
            }
        heartbeat_map[job_id] = registered[process_id]["worker_name"]

    return registered, heartbeat_map


def _worker_slots_sync(hostnames: list[str]) -> dict[str, int]:
    """Active job-slot counters per host, in one round trip."""
    from app.redis_client import WORKER_SLOTS_PREFIX, get_redis

    if not hostnames:
        return {}
    r = get_redis()
    try:
        with r.pipeline(transaction=False) as pipe:
            for hostname in hostnames:
                pipe.get(f"{WORKER_SLOTS_PREFIX}{hostname}")
            values = pipe.execute()
    except Exception:
        return {}
    out: dict[str, int] = {}
    for hostname, value in zip(hostnames, values, strict=True):
        try:
            out[hostname] = int(value or "0")
        except (TypeError, ValueError):
            out[hostname] = 0
    return out


def _live_heartbeat_job_ids_sync(job_ids: list[int]) -> set[int]:
    """Which of these jobs still have a worker heartbeat.

    One pipeline rather than a blocking `EXISTS` per running job — `running_jobs` is
    unbounded, so on a busy fleet per-job round trips would be the longest stall on the page.
    """
    from app.redis_client import HEARTBEAT_PREFIX, get_redis

    if not job_ids:
        return set()
    r = get_redis()
    try:
        with r.pipeline(transaction=False) as pipe:
            for job_id in job_ids:
                pipe.exists(f"{HEARTBEAT_PREFIX}{job_id}")
            results = pipe.execute()
    except Exception:
        # A Redis failure must not mark the whole fleet stuck — that is what drives the
        # "recover stuck jobs" prompt, and an empty set here would flag every running job.
        return set(job_ids)
    return {job_id for job_id, alive in zip(job_ids, results, strict=True) if alive}


async def _fetch_worker_data(db: AsyncSession) -> dict:
    """Query Redis for worker fleet status and DB for queue/stuck/pending info."""
    from fastapi.concurrency import run_in_threadpool

    from app.huey_inspect import get_queue_snapshot

    registered, heartbeat_map = await run_in_threadpool(_discover_workers_sync)

    policy_result = await db.execute(select(WorkerPolicy))
    policy_map: dict[str, int] = {p.hostname: p.max_concurrent_jobs for p in policy_result.scalars().all()}

    slot_counts = await run_in_threadpool(_worker_slots_sync, sorted({w["hostname"] for w in registered.values()}))

    # First pass: attach per-worker fields and collect per-hostname thread totals.
    # Multiple processes on the same host each contribute their thread count.
    host_threads: dict[str, int] = {}
    for w in registered.values():
        hostname = w["hostname"]
        hw = int(w.get("huey_workers") or 2)
        w["huey_workers"] = hw
        w["max_concurrent_jobs"] = policy_map.get(hostname, 0)
        w["active_slots"] = slot_counts.get(hostname, 0)
        host_threads[hostname] = host_threads.get(hostname, 0) + hw

    # Second pass: compute effective capacity (bounded by total threads on that host).
    for w in registered.values():
        hostname = w["hostname"]
        mcj = w["max_concurrent_jobs"]
        total_hw = host_threads.get(hostname, 2)
        if mcj == -1:
            w["effective_capacity"] = 0
        elif mcj > 0:
            w["effective_capacity"] = min(mcj, total_hw)
        else:
            w["effective_capacity"] = total_hw
        w["available_slots"] = max(0, w["effective_capacity"] - w["active_slots"])

    workers = sorted(registered.values(), key=lambda w: (w["status"] != "busy", w["worker_name"], w["worker_id"]))

    # Fleet-level capacity summary (deduplicated by hostname since slots are per-host).
    fleet_total_capacity = 0
    fleet_total_active = 0
    fleet_has_unlimited = False
    _host_seen: set[str] = set()
    for w in workers:
        hn = w["hostname"]
        if hn in _host_seen:
            continue
        _host_seen.add(hn)
        fleet_total_active += w["active_slots"]
        total_hw = host_threads.get(hn, 2)
        if w["max_concurrent_jobs"] == -1:
            pass
        elif w["max_concurrent_jobs"] == 0:
            fleet_has_unlimited = True
            fleet_total_capacity += total_hw
        else:
            fleet_total_capacity += min(w["max_concurrent_jobs"], total_hw)
    fleet_total_available = max(0, fleet_total_capacity - fleet_total_active)

    pending_count = await db.scalar(select(func.count(AnalysisJob.id)).where(AnalysisJob.status == JobStatus.PENDING)) or 0
    running_count = await db.scalar(select(func.count(AnalysisJob.id)).where(AnalysisJob.status == JobStatus.RUNNING)) or 0

    # Running jobs with eager-loaded relationships for the table
    eager = [selectinload(AnalysisJob.log_file), selectinload(AnalysisJob.workflow), selectinload(AnalysisJob.submitter)]
    running_result = await db.execute(select(AnalysisJob).where(AnalysisJob.status == JobStatus.RUNNING).options(*eager).order_by(AnalysisJob.created_at))
    running_jobs = running_result.scalars().all()

    live_job_ids = await run_in_threadpool(_live_heartbeat_job_ids_sync, [job.id for job in running_jobs])
    stuck_jobs = [job for job in running_jobs if job.id not in live_job_ids]

    # Pending jobs for the queue table
    pending_result = await db.execute(select(AnalysisJob).where(AnalysisJob.status == JobStatus.PENDING).options(*eager).order_by(AnalysisJob.created_at).limit(50))
    pending_jobs = pending_result.scalars().all()

    huey_queue = await run_in_threadpool(get_queue_snapshot, 0)

    return {
        "active_workers": workers,
        "pending_count": pending_count,
        "running_count": running_count,
        "running_jobs": running_jobs,
        "pending_jobs": pending_jobs,
        "heartbeat_map": heartbeat_map,
        "stuck_jobs": stuck_jobs,
        "huey_queue_size": huey_queue["queue_size"],
        "has_active": len(workers) > 0 or pending_count > 0 or huey_queue["queue_size"] > 0,
        "fleet_total_capacity": fleet_total_capacity,
        "fleet_total_active": fleet_total_active,
        "fleet_total_available": fleet_total_available,
        "fleet_has_unlimited": fleet_has_unlimited,
    }
