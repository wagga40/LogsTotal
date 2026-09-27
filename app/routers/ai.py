"""AI analysis of a job — the job-facing half.

Registered with ``prefix="/jobs"`` **after** ``jobs.router``. Every second path segment in
``routers/jobs.py`` is a literal (``status-partial``, ``analytics``, ``process-tree``, …),
so there is no ``/{job_id}/{anything}`` catch-all for these to be swallowed by. A test
pins that, because the failure mode is a 422 rather than a 404 and reads as a bug in the
partial rather than a routing collision.

**Two different gates, deliberately.** Running an analysis is member-or-above, because it
spends money or a GPU. *Viewing* one is open to anyone who can view the job, so a finished
analysis is part of the job's public record like its findings are — the run button simply
does not render for someone who cannot use it.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import activity
from app.auth.users import MEMBER_ROLES, current_member_or_above, current_user_optional
from app.config import settings
from app.constants import AI_ELIGIBLE_JOB_STATUSES, TERMINAL_AI_STATUSES
from app.database import get_async_session, utc_now_naive
from app.models import AiAnalysisStatus, AiProvider, AnalysisJob, JobAiAnalysis, User, can_view_job, enum_val
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/jobs")

_log = logging.getLogger(__name__)

# Runs listed in the history picker. A job accumulating more than this is someone
# comparing models, not someone who needs the 21st answer still on screen.
HISTORY_LIMIT = 20

# The statuses whose partial keeps polling — the complement of
# constants.TERMINAL_AI_STATUSES, which the worker's finaliser reads. Written out rather
# than derived so the poll trigger reads plainly; the property that matters is that the two
# stay disjoint and between them cover every AiAnalysisStatus member — nothing asserts it.
ACTIVE_STATUSES = ("pending", "running")

# Runs deletable in one request. Generous — the point of the feature is clearing out a
# job's accumulated history — but not unbounded, because the ids arrive from a form.
MAX_DELETE_PER_REQUEST = 100

# Grace on top of the *observable* signals below, not a substitute for them.
#
# RUNNING: the worker publishes a heartbeat (`AI_HEARTBEAT_PREFIX`), so liveness is a fact
# rather than an inference. This grace covers only the gap between the row flipping to
# RUNNING and the first beat landing.
#
# PENDING: there is nothing to beat yet — the task is in Huey's queue. What bounds it is
# `expires=settings.huey_queue_expiry`: past that Huey discards the task, so a row still
# pending afterwards is one no worker will ever claim.
RUNNING_GRACE_SECONDS = 120
PENDING_GRACE_SECONDS = 120

# Fallback bound for when Redis cannot be reached and the heartbeat cannot be consulted.
# Deliberately loose: with no liveness signal, calling a slow run dead is the worse error.
STALE_GRACE_SECONDS = 900
DEFAULT_PROVIDER_TIMEOUT = 300


def _can_run(user: User | None) -> bool:
    return user is not None and (user.is_superuser or user.role in MEMBER_ROLES)


def _can_manage(analysis: JobAiAnalysis, user: User | None) -> bool:
    """True when *user* may stop or delete *analysis*.

    Admin, or the person who started it. Not "anyone who can run an analysis": a member
    deleting a colleague's saved assessment off a shared job is a different act from
    starting one of their own, and this is history rather than a cache.
    """
    if user is None:
        return False
    if user.is_superuser:
        return True
    return analysis.requested_by_user_id is not None and analysis.requested_by_user_id == user.id


def _has_heartbeat(analysis_id: int, *, scope: str = "") -> bool | None:
    """Is a worker still on this run? ``None`` when Redis cannot answer.

    Three-valued on purpose. "No heartbeat" and "cannot tell" lead to different decisions —
    the first finalises a dead run, the second must not.
    """
    try:
        from app.redis_client import AI_HEARTBEAT_PREFIX, get_redis

        return bool(get_redis().exists(f"{AI_HEARTBEAT_PREFIX}{scope}{analysis_id}"))
    except Exception:
        _log.debug("AI heartbeat check skipped: Redis unavailable")
        return None


def _job_is_analysable(job: AnalysisJob) -> bool:
    """Has this job produced anything for a model to read?

    Only `completed` and `partial` have. A `pending` or `running` job has no findings yet,
    and a `failed` or `cancelled` one never will — in every one of those cases the brief
    would be empty and the answer confident nonsense about nothing. `partial` counts: the
    tools that did run produced real findings, and the brief says which did not.
    """
    return enum_val(job.status) in AI_ELIGIBLE_JOB_STATUSES


def _analysable_refusal(job: AnalysisJob) -> str:
    """Why this job cannot be analysed — phrased for whoever is looking at it."""
    status = enum_val(job.status)
    if status in ("pending", "running"):
        return "This job is still running. An AI analysis reads its findings, so it can only be started once the analysis has finished."
    return f"This job {'failed' if status == 'failed' else 'was cancelled'} before producing findings, so there is nothing for a model to read."


async def _load_visible_job(db: AsyncSession, job_id: int, user: User | None) -> AnalysisJob:
    job = await db.get(AnalysisJob, job_id)
    if job is None or not can_view_job(job, user):
        # One reply for "no such job" and "private job", so this is not an existence oracle.
        raise HTTPException(404, "Job not found.")
    return job


async def _history(db: AsyncSession, job_id: int) -> list[JobAiAnalysis]:
    """Runs for this job, newest first.

    Both relationships are eager-loaded, and that is not an optimisation: the template reads
    `requested_by` and `_is_stalled` reads `provider`, and a lazy load on a detached — or
    merely async — instance raises `MissingGreenlet` rather than returning nothing. It also
    turns the history list into one query instead of 2N.
    """
    rows = await db.execute(
        select(JobAiAnalysis)
        .where(JobAiAnalysis.job_id == job_id)
        .options(selectinload(JobAiAnalysis.provider), selectinload(JobAiAnalysis.requested_by))
        .order_by(JobAiAnalysis.created_at.desc(), JobAiAnalysis.id.desc())
        .limit(HISTORY_LIMIT)
    )
    return list(rows.scalars().all())


async def _enabled_providers(db: AsyncSession) -> list[AiProvider]:
    rows = await db.execute(select(AiProvider).where(AiProvider.enabled.is_(True)).order_by(AiProvider.is_default.desc(), AiProvider.name))
    return list(rows.scalars().all())


async def _render_panel(
    request: Request,
    db: AsyncSession,
    job: AnalysisJob,
    user: User | None,
    *,
    selected_id: int | None = None,
    message: str | None = None,
) -> HTMLResponse:
    """Render the whole pane. One function, so a POST reply and a poll cannot disagree."""
    history = await _history(db, job.id)
    selected = None
    if selected_id is not None:
        selected = next((a for a in history if a.id == selected_id), None)
    if selected is None and history:
        selected = history[0]

    is_active = selected is not None and enum_val(selected.status) in ACTIVE_STATUSES
    is_stalled = is_active and _is_stalled(selected)

    site_settings = await get_site_settings(db)
    return templates.TemplateResponse(
        request,
        "partials/_ai_analysis.html",
        {
            "request": request,
            "user": user,
            "job": job,
            "analysis": selected,
            "history": history,
            "providers": await _enabled_providers(db),
            "can_run": _can_run(user) and bool(site_settings.show_ai_analysis),
            # Whether *this job* can be analysed right now, as opposed to whether *this
            # viewer* may start one. Two separate questions, so two separate flags: the
            # template needs to tell "you may not press this" apart from "there is nothing
            # to analyse yet", and they have different remedies.
            "can_run_now": _job_is_analysable(job),
            # Per-run, not per-user: a job's history can hold runs started by several
            # people, and the Stop and Delete controls must render per row.
            "manageable_ids": {a.id for a in history if _can_manage(a, user)},
            # A stalled run is not active: it must stop polling, or a worker restart leaves
            # every viewer of this job requesting the partial every 3s forever.
            "is_active": is_active and not is_stalled,
            "is_stalled": is_stalled,
            "message": message,
            "site_settings": site_settings,
        },
    )


def _is_stalled(analysis: JobAiAnalysis, *, scope: str = "") -> bool:
    """True when a pending/running row has nothing behind it anymore.

    Asks the two questions that have real answers, rather than guessing from ``created_at``
    age — which would leave a run whose worker restarted mid-inference spinning for the best
    part of an hour:

    * **pending** — Huey drops a task that is not claimed within ``huey_queue_expiry``, so
      past that the row is waiting for something that no longer exists.
    * **running** — the worker publishes a heartbeat for the whole run. Its absence is the
      signal; the grace only covers the moment between the status flipping and the first
      beat.

    Presentational, and not a write: a GET must not mutate. The cancel route acts on the
    same signal, so a dead run is *finalisable* rather than merely displayable.
    """
    status = enum_val(analysis.status)
    if status not in ACTIVE_STATUSES:
        return False
    started = analysis.created_at
    if started is None:
        return False
    age = (utc_now_naive() - started).total_seconds()

    if status == "pending":
        return age > settings.huey_queue_expiry + PENDING_GRACE_SECONDS

    beating = _has_heartbeat(analysis.id, scope=scope) if scope else _has_heartbeat(analysis.id)
    if beating:
        return False
    if beating is None:
        # Redis is unreachable, so liveness is unknowable. Fall back to an age bound —
        # loose on purpose, because declaring a live run dead is the worse mistake.
        timeout = DEFAULT_PROVIDER_TIMEOUT
        provider = analysis.provider
        if provider is not None and provider.timeout_seconds:
            timeout = provider.timeout_seconds
        return age > timeout + STALE_GRACE_SECONDS
    return age > RUNNING_GRACE_SECONDS


@router.get("/{job_id}/ai-analysis-partial", response_class=HTMLResponse)
async def ai_analysis_partial(
    job_id: int,
    request: Request,
    analysis_id: int | None = None,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """The AI Analysis pane. Self-polls while a run is pending or running."""
    job = await _load_visible_job(db, job_id, user)
    return await _render_panel(request, db, job, user, selected_id=analysis_id)


@router.post("/{job_id}/ai-analysis")
async def ai_analysis_start(
    job_id: int,
    request: Request,
    provider_id: int = Form(...),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Queue an analysis run. Member-or-above, and only for a job they can already see."""
    job = await _load_visible_job(db, job_id, user)

    # Off means job data does not go to a provider, not merely that the tab is hidden: a
    # member with the form still open, or a script, would otherwise start a run anyway.
    if not (await get_site_settings(db)).show_ai_analysis:
        return await _render_panel(request, db, job, user, message="AI analysis is switched off on this instance.")

    # Before the rate limit, because refusing an impossible run must not spend the caller's
    # budget. Rendered through _render_panel like every other refusal here, so the no-JS 303
    # path below stays the only other exit.
    if not _job_is_analysable(job):
        return await _render_panel(request, db, job, user, message=_analysable_refusal(job))

    if _rate_limited(user):
        return await _render_panel(
            request, db, job, user, message=f"You have started too many analyses in the last minute (limit {settings.ai_rate_limit_per_minute}). Try again shortly."
        )

    provider = await db.get(AiProvider, provider_id)
    if provider is None or not provider.enabled:
        # Same reply for both, matching the job-scope convention: a disabled provider and a
        # deleted one are the same thing to someone who just picked it from a stale form.
        return await _render_panel(request, db, job, user, message="That AI provider is no longer available. Pick another.")

    analysis = JobAiAnalysis(
        job_id=job.id,
        provider_id=provider.id,
        provider_name=provider.name,
        model=provider.model,
        status=AiAnalysisStatus.PENDING,
        requested_by_user_id=user.id,
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    from app.workers.tasks import run_ai_analysis

    try:
        run_ai_analysis(analysis.id)
    except Exception:
        # The row is already committed, so an unreachable queue would leave a run PENDING
        # with a pane polling it every 3s until `_is_stalled` finally gives up on it. Its
        # own FAILED status says what happened, which is what the history is for.
        _log.exception("Could not enqueue AI analysis %s", analysis.id)
        analysis.status = AiAnalysisStatus.FAILED
        analysis.error_message = "Could not be queued: the task queue was unreachable."
        analysis.finished_at = utc_now_naive()
        await db.commit()
        raise HTTPException(503, "The task queue is unreachable, so an analysis cannot be started right now. Try again shortly.") from None
    # The provider and model, because this is the moment a job's findings are queued to
    # leave the instance — the same class of event as an export.
    await activity.record(
        "job.ai_run",
        request=request,
        user=user,
        target_type="job",
        target_id=str(job.id),
        summary=f"{analysis.provider_name} / {analysis.model}",
        meta={"analysis_id": analysis.id, "provider": analysis.provider_name, "model": analysis.model},
    )

    if request.headers.get("hx-request"):
        return await _render_panel(request, db, job, user, selected_id=analysis.id)
    # No-JS fallback, same shape as _queue_background_task's.
    return RedirectResponse(f"/jobs/{job.id}#ai", status_code=303)


async def _load_run(db: AsyncSession, job: AnalysisJob, analysis_id: int) -> JobAiAnalysis:
    """One run of *job*, or 404. One reply for "no such run" and "run on another job"."""
    analysis = await db.get(JobAiAnalysis, analysis_id)
    if analysis is None or analysis.job_id != job.id:
        raise HTTPException(404, "Analysis not found.")
    return analysis


@router.post("/{job_id}/ai-analysis/{analysis_id}/cancel")
async def ai_analysis_cancel(
    job_id: int,
    analysis_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Stop a queued or running analysis. Admin, or whoever started it.

    The three cases are ``POST /jobs/{id}/cancel``'s, because the failure modes are the
    same ones:

    * **pending** — finalised here. The worker re-reads the flag at pickup and drops the
      task, so marking the row now is safe *and* is the only thing that helps when no
      worker will ever pick it up (queue expired, fleet down).
    * **running with a heartbeat** — flag only. A live worker owns this row; two writers
      would race, and it is the worker that knows when the connection is actually gone.
    * **running with no heartbeat** — finalised here. The worker died mid-inference and
      nothing is left to read a flag.

    The flag is set **before** the DB is touched, exactly as the job route does it, so the
    window where a worker could pick the task up after the row was marked does not exist.
    """
    job = await _load_visible_job(db, job_id, user)
    analysis = await _load_run(db, job, analysis_id)

    if not _can_manage(analysis, user):
        raise HTTPException(403, "Only an administrator or the person who started this analysis can stop it.")

    status = enum_val(analysis.status)
    if status in TERMINAL_AI_STATUSES:
        return await _respond(request, db, job, user, selected_id=analysis_id, message="That analysis had already finished.")

    _set_cancel_flag(analysis_id)

    beating = _has_heartbeat(analysis_id)
    if status == "pending" or beating is False:
        analysis.status = AiAnalysisStatus.CANCELLED
        analysis.finished_at = utc_now_naive()
        await db.commit()
        note = "Analysis stopped." if status == "pending" else "Analysis stopped — no worker was still processing it."
        return await _respond(request, db, job, user, selected_id=analysis_id, message=note)

    # A worker is on it (or Redis cannot tell us). Leave the row to the worker, which
    # records the cancellation itself along with the run log.
    return await _respond(request, db, job, user, selected_id=analysis_id, message="Stopping — the worker will close the connection to the provider.")


def _parse_ids(raw: str) -> list[int]:
    """``"3, 4, 4, x"`` -> ``[3, 4]``. Order-preserving, deduped, junk dropped.

    One comma-separated field rather than repeated ``analysis_ids`` inputs, because the
    selection lives in an Alpine store (the pane morph-swaps every 3s while a run is live,
    so DOM-held ticks would be wiped). The template writes one hidden input imperatively
    before calling ``requestSubmit``: htmx serializes the form synchronously while Alpine
    applies bindings on its own scheduler, so a bound input could post a stale value.
    """
    out: list[int] = []
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            value = int(chunk)
        except ValueError:
            continue
        if value not in out:
            out.append(value)
    return out


@router.post("/{job_id}/ai-analysis/delete")
async def ai_analysis_delete(
    job_id: int,
    request: Request,
    analysis_ids: str = Form(default=""),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Delete past runs of this job's analysis, one or many.

    A hard delete, unlike ``Comment``'s soft delete, and unlike ``ai_delete``'s NULLing of
    ``provider_id``. The distinction is what the row is *for*: a comment is one side of a
    conversation others replied to, and a provider's identity is the attribution a past
    answer depends on. A run is a self-contained artefact whose author asked for it to be
    gone — there is nothing left pointing at it to keep honest.

    An **active** run is refused rather than deleted. A worker holding that row is about to
    commit to it, and deleting underneath it turns a clean cancel into a lost update. The
    message says to stop it first, which is one click away.
    """
    job = await _load_visible_job(db, job_id, user)

    wanted = _parse_ids(analysis_ids)[:MAX_DELETE_PER_REQUEST]
    if not wanted:
        return await _respond(request, db, job, user, message="Select at least one analysis to delete.")

    rows = await db.execute(select(JobAiAnalysis).where(JobAiAnalysis.job_id == job.id, JobAiAnalysis.id.in_(wanted)))
    found = list(rows.scalars().all())

    deletable, active, forbidden = [], 0, 0
    for row in found:
        if enum_val(row.status) not in TERMINAL_AI_STATUSES:
            active += 1
        elif not _can_manage(row, user):
            forbidden += 1
        else:
            deletable.append(row.id)

    if deletable:
        await db.execute(sa_delete(JobAiAnalysis).where(JobAiAnalysis.id.in_(deletable)))
        await db.commit()

    return await _respond(request, db, job, user, message=_delete_message(len(deletable), active, forbidden, len(wanted) - len(found)))


def _delete_message(deleted: int, active: int, forbidden: int, missing: int) -> str:
    """Say what happened to every id that was submitted.

    Reporting only the successes is what makes a bulk action feel broken: a user who ticks
    four boxes and is told "deleted 2" with no reason assumes the feature is unreliable.
    """
    parts = [f"Deleted {deleted} analysis run(s)." if deleted else "Nothing was deleted."]
    if active:
        parts.append(f"{active} still running — stop it first.")
    if forbidden:
        parts.append(f"{forbidden} was started by someone else.")
    if missing:
        parts.append(f"{missing} no longer existed.")
    return " ".join(parts)


def _set_cancel_flag(analysis_id: int, *, scope: str = "") -> None:
    """Ask the worker to stop. Best-effort: Redis being down must not block the DB write.

    One hour of TTL is far longer than any run, and the worker deletes the key when it
    finishes — the TTL only bounds a key whose worker never came back.
    """
    try:
        from app.redis_client import AI_CANCEL_PREFIX, get_redis

        get_redis().set(f"{AI_CANCEL_PREFIX}{scope}{analysis_id}", b"1", ex=3600)
    except Exception:
        _log.debug("Could not set the AI cancel flag: Redis unavailable")


async def _respond(
    request: Request,
    db: AsyncSession,
    job: AnalysisJob,
    user: User | None,
    *,
    selected_id: int | None = None,
    message: str | None = None,
):
    """Re-render the pane for htmx, or fall back to the 303 a plain form needs."""
    if request.headers.get("hx-request"):
        return await _render_panel(request, db, job, user, selected_id=selected_id, message=message)
    return RedirectResponse(f"/jobs/{job.id}#ai", status_code=303)


def _rate_limited(user: User) -> bool:
    """Per-user fixed-window limit. Fails **open** when Redis is unreachable.

    Same call as every other limiter in the app (`_redis_window_hits`), and the same
    trade-off: Redis being down should not take a feature offline. The cost of failing open
    here is bounded by the fact that only members can reach this route at all.
    """
    limit = settings.ai_rate_limit_per_minute
    if not limit or limit <= 0:
        return False
    try:
        from app.middleware.production import _redis_window_hits

        return _redis_window_hits(f"logstotal:ratelimit:ai:{user.id}", 60) > limit
    except Exception:
        _log.debug("AI rate limit check skipped: Redis unavailable")
        return False
