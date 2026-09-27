"""Member-facing Case AI runs, with evidence-based access to saved assessments."""

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import activity
from app.ai.case_evidence import evidence_exists, readable_runs
from app.auth.users import current_member_or_above
from app.constants import TERMINAL_AI_STATUSES
from app.database import get_async_session, parse_row_id, utc_now_naive
from app.models import AiAnalysisStatus, AiProvider, CaseAiAnalysis, User, enum_val
from app.routers import ai
from app.routers.cases import _load_case_or_404
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/intel/cases")
_log = logging.getLogger(__name__)


async def _panel(request, db, case, user, *, selected_id=None, message=None):
    if selected_id is not None and parse_row_id(selected_id) is None:
        raise HTTPException(404, "Analysis not found.")
    query = (
        select(CaseAiAnalysis)
        .where(CaseAiAnalysis.case_id == case.id)
        .options(selectinload(CaseAiAnalysis.provider), selectinload(CaseAiAnalysis.requested_by))
        .order_by(CaseAiAnalysis.created_at.desc(), CaseAiAnalysis.id.desc())
        .limit(ai.HISTORY_LIMIT)
    )
    history = await readable_runs(db, list((await db.scalars(query)).all()), user)
    selected = next((r for r in history if r.id == selected_id), None)
    if selected_id is not None and selected is None:
        selected = await db.get(CaseAiAnalysis, selected_id, options=[selectinload(CaseAiAnalysis.provider), selectinload(CaseAiAnalysis.requested_by)])
        if selected is None or selected.case_id != case.id or not await readable_runs(db, [selected], user):
            raise HTTPException(404, "Analysis not found.")
    selected = selected or (history[0] if history else None)
    active = selected is not None and enum_val(selected.status) in ai.ACTIVE_STATUSES
    stalled = active and ai._is_stalled(selected, scope="case:")
    site = await get_site_settings(db)
    return templates.TemplateResponse(
        request,
        "partials/_ai_analysis.html",
        {
            "request": request,
            "user": user,
            "case": case,
            "ai_subject": "case",
            "ai_base": f"/intel/cases/{case.id}",
            "analysis": selected,
            "history": history,
            "providers": await ai._enabled_providers(db),
            "can_run": bool(site.show_ai_analysis),
            "can_run_now": bool(await db.scalar(evidence_exists(case.id, user))),
            "manageable_ids": {r.id for r in [*history, *([selected] if selected else [])] if ai._can_manage(r, user)},
            "is_active": active and not stalled,
            "is_stalled": stalled,
            "message": message,
            "site_settings": site,
        },
    )


async def _respond(request, db, case, user, **kwargs):
    if request.headers.get("hx-request"):
        return await _panel(request, db, case, user, **kwargs)
    return RedirectResponse(f"/intel/cases/{case.id}#ai", status_code=303)


@router.get("/{case_id}/ai-analysis-partial")
async def case_ai_partial(
    case_id: int, request: Request, analysis_id: int | None = None, db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)
):
    case = await _load_case_or_404(db, case_id, user)
    return await _panel(request, db, case, user, selected_id=analysis_id)


@router.post("/{case_id}/ai-analysis")
async def case_ai_start(case_id: int, request: Request, provider_id: int = Form(...), db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)):
    case = await _load_case_or_404(db, case_id, user)
    message = None
    provider = await db.get(AiProvider, provider_id) if parse_row_id(provider_id) is not None else None
    if not (await get_site_settings(db)).show_ai_analysis:
        message = "AI analysis is switched off on this instance."
    elif not await db.scalar(evidence_exists(case.id, user)):
        message = "Add a completed or partial job, or an entity, before running an analysis."
    elif provider is None or not provider.enabled:
        message = "That AI provider is no longer available. Pick another."
    elif ai._rate_limited(user):
        message = "You have started too many analyses in the last minute. Try again shortly."
    if message:
        return await _respond(request, db, case, user, message=message)
    run = CaseAiAnalysis(case_id=case.id, provider_id=provider.id, provider_name=provider.name, model=provider.model, requested_by_user_id=user.id, status=AiAnalysisStatus.PENDING)
    db.add(run)
    await db.commit()
    await db.refresh(run)
    from app.workers.tasks import run_case_ai_analysis

    try:
        run_case_ai_analysis(run.id)
    except Exception:
        _log.exception("Could not enqueue Case AI analysis %s", run.id)
        run.status = AiAnalysisStatus.FAILED
        run.error_message = "Could not be queued: the task queue was unreachable."
        run.finished_at = utc_now_naive()
        await db.commit()
        raise HTTPException(503, "The task queue is unreachable. Try again shortly.") from None
    await activity.record(
        "intel.case.ai_run", request=request, user=user, target_type="case", target_id=str(case.id), summary=f"{provider.name} / {provider.model}", meta={"analysis_id": run.id}
    )
    return await _respond(request, db, case, user, selected_id=run.id)


@router.post("/{case_id}/ai-analysis/{analysis_id}/cancel")
async def case_ai_cancel(case_id: int, analysis_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)):
    case = await _load_case_or_404(db, case_id, user)
    run = await db.get(CaseAiAnalysis, analysis_id)
    if run is None or run.case_id != case.id:
        raise HTTPException(404, "Analysis not found.")
    if not ai._can_manage(run, user):
        if not await readable_runs(db, [run], user):
            raise HTTPException(404, "Analysis not found.")
        raise HTTPException(403, "Only an administrator or the requester can stop this analysis.")
    if enum_val(run.status) not in TERMINAL_AI_STATUSES:
        ai._set_cancel_flag(run.id, scope="case:")
        if enum_val(run.status) == "pending" or ai._has_heartbeat(run.id, scope="case:") is False:
            run.status = AiAnalysisStatus.CANCELLED
            run.finished_at = utc_now_naive()
            await db.commit()
    return await _respond(request, db, case, user, message="Stop requested.")


@router.post("/{case_id}/ai-analysis/delete")
async def case_ai_delete(
    case_id: int, request: Request, analysis_ids: str = Form(""), db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)
):
    case = await _load_case_or_404(db, case_id, user)
    wanted = [i for chunk in analysis_ids.split(",") if (i := parse_row_id(chunk.strip())) is not None][: ai.MAX_DELETE_PER_REQUEST]
    rows = list(await db.scalars(select(CaseAiAnalysis).where(CaseAiAnalysis.case_id == case.id, CaseAiAnalysis.id.in_(wanted))))
    visible = {r.id for r in await readable_runs(db, rows, user)}
    deletable, active, forbidden = [], 0, 0
    for run in rows:
        if not ai._can_manage(run, user):
            forbidden += int(run.id in visible)
        elif enum_val(run.status) not in TERMINAL_AI_STATUSES:
            active += 1
        else:
            deletable.append(run.id)
    if deletable:
        await db.execute(delete(CaseAiAnalysis).where(CaseAiAnalysis.id.in_(deletable), CaseAiAnalysis.status.in_([AiAnalysisStatus(s) for s in TERMINAL_AI_STATUSES])))
        await db.commit()
    return await _respond(request, db, case, user, message=ai._delete_message(len(deletable), active, forbidden, 0))
