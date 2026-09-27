"""Reading the activity log — `/admin/activity`.

A separate module from `admin.py`, like `enrichment_admin.py` and `ai_admin.py`, to keep
that file manageable. Every route here is `current_superuser`.

Reading is deliberately **not** gated by ``SiteSettings.activity_log_enabled``. That flag
stops new rows being written; an operator who turns capture off must still be able to read
what was already captured, and Prune is how they remove it.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import activity
from app.auth.users import current_superuser
from app.config import settings
from app.csv_utils import csv_safe
from app.database import get_async_session, utc_now_naive
from app.json_utils import loads as json_loads
from app.models import ActivityEvent, User
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/admin/activity")

PAGE_SIZE = 50
#: An export is a download, not a report — bounded so a year of rows cannot stall a worker.
CSV_MAX_ROWS = 10_000

#: Windows offered by the range filter, in the order they appear.
RANGES = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}


def _filtered_query(*, category: str, action: str, actor: str, target: str, outcome: str, q: str, since_days: int | None):
    """The one query builder behind the table, the count and the CSV.

    Shared so a filter that narrows the page cannot silently widen the export — the same
    argument as `_entity_findings_count_stmt` on the entity page.
    """
    stmt = select(ActivityEvent)
    if category:
        stmt = stmt.where(ActivityEvent.category == category)
    if action:
        stmt = stmt.where(ActivityEvent.action == action)
    if actor:
        stmt = stmt.where(ActivityEvent.actor_label.ilike(f"%{actor}%"))
    if target:
        stmt = stmt.where(ActivityEvent.target_id == target)
    if outcome:
        stmt = stmt.where(ActivityEvent.outcome == outcome)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(ActivityEvent.summary.ilike(like), ActivityEvent.actor_ip.ilike(like), ActivityEvent.request_id.ilike(like)))
    if since_days:
        stmt = stmt.where(ActivityEvent.created_at >= utc_now_naive() - timedelta(days=since_days))
    return stmt


def _view(row: ActivityEvent) -> dict:
    meta = None
    if row.metadata_json:
        try:
            meta = json_loads(row.metadata_json)
        except Exception:
            meta = None
    return {
        "id": row.id,
        "created_at": row.created_at,
        "actor_label": row.actor_label,
        "actor_user_id": row.actor_user_id,
        "actor_ip": row.actor_ip,
        "action": row.action,
        "label": activity.label_of(row.action),
        "category": row.category,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "summary": row.summary,
        "meta": meta,
        "request_id": row.request_id,
        "outcome": row.outcome,
    }


async def _page_context(request: Request, db: AsyncSession, *, page: int) -> dict:
    category = (request.query_params.get("category") or "").strip()
    action = (request.query_params.get("action") or "").strip()
    actor = (request.query_params.get("actor") or "").strip()
    target = (request.query_params.get("target") or "").strip()
    outcome = (request.query_params.get("outcome") or "").strip()
    q = (request.query_params.get("q") or "").strip()
    rng = (request.query_params.get("range") or "").strip()
    since_days = RANGES.get(rng)

    stmt = _filtered_query(category=category, action=action, actor=actor, target=target, outcome=outcome, q=q, since_days=since_days)
    total = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    page = max(1, page)
    rows = (
        (
            await db.execute(
                stmt.options(selectinload(ActivityEvent.actor)).order_by(ActivityEvent.created_at.desc(), ActivityEvent.id.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)
            )
        )
        .scalars()
        .all()
    )
    site_settings = await get_site_settings(db)
    filters = {"category": category, "action": action, "actor": actor, "target": target, "outcome": outcome, "q": q, "range": rng}
    return {
        "events": [_view(r) for r in rows],
        "total": total,
        "page": page,
        "total_pages": max(1, -(-total // PAGE_SIZE)),
        "filters": filters,
        "categories": activity.CATEGORIES,
        "actions": sorted(activity.ACTIONS),
        "ranges": list(RANGES),
        "capture_enabled": bool(site_settings.activity_log_enabled),
        "retention_days": settings.activity_retention_days,
        # The filter alone, preserved across the pager and the export links so a filtered view
        # exports what it shows. Never the request's own query string: that carries `page`,
        # the pager prepends its own, the last one wins, and the log sticks on page 2.
        "query_string": urlencode({k: v for k, v in filters.items() if v}),
    }


@router.get("")
async def activity_page(
    request: Request,
    page: int = 1,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """The activity log, filtered and paged."""
    ctx = await _page_context(request, db, page=page)
    # Header pill only, so it is computed here rather than in `_page_context` — that builder
    # is shared with `/partial`, which re-renders the table on every filter change and has
    # no header to put this in. Deliberately *unfiltered*: it answers "is anything happening
    # right now", which a filtered count cannot.
    last_hour = await db.scalar(select(func.count(ActivityEvent.id)).where(ActivityEvent.created_at >= utc_now_naive() - timedelta(hours=1))) or 0
    return templates.TemplateResponse(request, "admin/activity.html", {"request": request, "user": user, "last_hour": last_hour, **ctx})


@router.get("/partial")
async def activity_partial(
    request: Request,
    page: int = 1,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Just the table, for the filter form and the pager."""
    ctx = await _page_context(request, db, page=page)
    return templates.TemplateResponse(request, "admin/partials/_activity_table.html", {"request": request, "user": user, **ctx})


def _filters_from(request: Request) -> dict:
    """The filter set a request is asking for. Shared by both exports, so a filter that
    narrows what you see cannot silently widen what you download. The page parses the same
    params in `_page_context`; what it shares with them is `_filtered_query`."""
    return {
        "category": (request.query_params.get("category") or "").strip(),
        "action": (request.query_params.get("action") or "").strip(),
        "actor": (request.query_params.get("actor") or "").strip(),
        "target": (request.query_params.get("target") or "").strip(),
        "outcome": (request.query_params.get("outcome") or "").strip(),
        "q": (request.query_params.get("q") or "").strip(),
        "since_days": RANGES.get((request.query_params.get("range") or "").strip()),
    }


@router.get("/export.csv")
async def activity_csv(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Export the *current filter* as CSV, capped at CSV_MAX_ROWS."""
    stmt = _filtered_query(**_filters_from(request))
    rows = (await db.execute(stmt.order_by(ActivityEvent.created_at.desc(), ActivityEvent.id.desc()).limit(CSV_MAX_ROWS))).scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "actor", "actor_ip", "action", "category", "target_type", "target_id", "outcome", "summary", "request_id"])
    for row in rows:
        writer.writerow(
            [
                row.created_at.isoformat() if row.created_at else "",
                csv_safe(row.actor_label),
                csv_safe(row.actor_ip),
                csv_safe(row.action),
                csv_safe(row.category),
                csv_safe(row.target_type),
                csv_safe(row.target_id),
                csv_safe(row.outcome),
                csv_safe(row.summary),
                csv_safe(row.request_id),
            ]
        )
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=logstotal-activity-{stamp}.csv"},
    )


@router.get("/export.json")
async def activity_json(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """The same rows as the CSV, as JSON, for anything that will parse them.

    CSV flattens `metadata_json` into a string nobody can read, so the changed-field diff
    on a settings save — the single most useful thing recorded here — survives the export
    only in JSON. Both go through the same `_filtered_query`, so the two cannot disagree
    about what a filter means.
    """
    stmt = _filtered_query(**_filters_from(request))
    rows = (await db.execute(stmt.order_by(ActivityEvent.created_at.desc(), ActivityEvent.id.desc()).limit(CSV_MAX_ROWS))).scalars().all()

    def _meta(raw):
        if not raw:
            return None
        try:
            return json_loads(raw)
        except Exception:
            # Round-trip what was stored rather than dropping it: a row whose metadata
            # cannot be parsed is itself worth seeing in an export.
            return {"_unparsed": raw}

    payload = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "count": len(rows),
        # Says so when the cap bit, rather than presenting a slice as the whole set.
        "truncated": len(rows) >= CSV_MAX_ROWS,
        "filters": {key: value for key, value in _filters_from(request).items() if value},
        "events": [
            {
                "id": row.id,
                "timestamp": row.created_at.isoformat() if row.created_at else None,
                "action": row.action,
                "category": row.category,
                "outcome": row.outcome,
                "actor": {"label": row.actor_label, "user_id": str(row.actor_user_id) if row.actor_user_id else None, "ip": row.actor_ip},
                "target": {"type": row.target_type, "id": row.target_id},
                "summary": row.summary,
                "metadata": _meta(row.metadata_json),
                "request_id": row.request_id,
            }
            for row in rows
        ],
    }
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return JSONResponse(payload, headers={"Content-Disposition": f"attachment; filename=logstotal-activity-{stamp}.json"})


@router.post("/prune")
async def activity_prune(
    request: Request,
    days: int = Form(0),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Delete rows older than *days*, now, rather than waiting for the daily sweep.

    This is the answer to "turn it off and remove what you already have" — which is why
    disabling capture does not hide existing rows. Runs inline: it is one bounded DELETE,
    and an admin asking to remove audit data wants to see that it happened.
    """
    from starlette.concurrency import run_in_threadpool

    if days <= 0:
        raise HTTPException(400, "A positive number of days is required.")
    deleted = await run_in_threadpool(activity.prune_sync, days)
    # Recorded, deliberately: pruning an audit log is itself an auditable act, and the row
    # survives its own prune because it is written after the cutoff has passed.
    await activity.record("admin.activity.prune", request=request, user=user, summary=f"{deleted} row(s) older than {days} days", meta={"days": days, "deleted": deleted})
    return RedirectResponse(f"/admin/activity?pruned={deleted}", status_code=303)
