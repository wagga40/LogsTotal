"""Investigation Cases — group entities and jobs into a named analyst investigation.

Member-or-above gating. Each case is owned by its creator; `is_shared=False` cases are
visible only to the owner (and admins). Sharing flips the flag globally.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import activity
from app.auth.api_tokens import current_user_or_api_token, principal_actor_label, principal_user
from app.auth.users import current_member_or_above
from app.comments import clean_text, comment_counts_for
from app.constants import ENTITY_TYPES, SEVERITY_ORDER, SEVERITY_RANK, TERMINAL_JOB_STATUSES
from app.database import get_async_session, parse_row_id, utc_now_naive
from app.intel.cases import (
    build_case_list_rows,
    build_case_stix_bundle,
    build_findings_rollup,
    build_similar_pivot_rows,
    merge_correlated_hit,
    rank_correlated_pivot_rows,
)
from app.intel.event_timeline import (
    build_key_events,
    extract_all_from_raw_output,
    format_timeline,
    has_raw_output,
    merge_buckets,
)
from app.intel.graph import CASE_MAX_NODES, build_case_graph
from app.intel.graph_payload import client_schema, to_graphml
from app.intel.ioc_pack import build_case_ioc_pack
from app.intel.misp import build_misp_event, sighting_counts_from_links, threat_level_for_entities
from app.intel.queries import escape_like
from app.intel.tactics import (
    _MITRE_TACTIC_COLORS,
    _MITRE_TACTICS_SET,
    _OTHER_TACTIC,
    _OTHER_TACTIC_COLOR,
    TACTIC_LABELS,
    _build_findings_index,
)
from app.json_utils import loads as json_loads
from app.models import (
    AnalysisJob,
    CaseEntityLink,
    CaseJobLink,
    Entity,
    EntityJobLink,
    EntityTag,
    Finding,
    FindingEntityLink,
    InvestigationCase,
    LogFile,
    Severity,
    TaskResult,
    User,
    can_view_job,
    enum_val,
    severity_rank_sql,
    visible_case_filter,
    visible_job_filter,
)
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/intel/cases")

_VALID_STATUSES = {"open", "monitoring", "closed"}
_VALID_CASE_LIST_SORTS = {"updated", "activity", "severity", "findings", "name"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_NAME_MAX = 200
_SUMMARY_MAX = 8000
_PICKER_MIN_CHARS = 2
_PICKER_LIMIT = 20
_BULK_ENTITY_CAP = 500
_BULK_LINK_CAP = 50  # entity/job selections per multi-select submit
_NOTES_MAX = 8000  # InvestigationCase.notes cap, mirroring Entity.notes
_LINK_NOTE_MAX = 500  # CaseEntityLink.note / CaseJobLink.note cap
# The **API and export** bound on a case's links (the HTML tabs are paged instead; see
# `_CASE_PAGE_SIZE`). `detail.json` is Bearer-token reachable and an uncapped dump of a
# 50,000-entity case is a denial of service; the exports build their documents synchronously
# inside a request and want the same protection. `detail.json` reports `truncated`.
_CASE_LINK_CAP = 200

# Rows per page on the Entities and Jobs tabs. Matches `intel.py`'s PAGE_SIZE.
_CASE_PAGE_SIZE = 50

# Options in the case graph's job filter. A `<select>`, not a search box, so it has to be
# bounded; a case with more jobs than this is better narrowed from the Jobs tab.
_CASE_JOB_PICKER_LIMIT = 200

# Pivot suggestions (Overview tab) — bounds for each of the three sections.
_PIVOT_ENTITY_LIMIT = 10
_PIVOT_SIMILAR_LIMIT = 8
_PIVOT_SIMILAR_SOURCE_JOBS = 10  # how many of the case's most-recent visible jobs *with a TLSH hash* to probe for TLSH neighbors
_PIVOT_CORRELATED_LIMIT = 10
_PIVOT_CORRELATED_SIGNATURE_CAP = 20  # bounds how many distinct rule_signatures get a find_correlated_findings_async call

# Per-job raw-output histogram bucket cache — mirrors the process-tree cache idiom in
# routers/jobs.py (best-effort Redis, self-expiring). Keyed by job so a job shared across
# cases is parsed once; invalidated by the job's recalculate endpoint.
_TIMELINE_BUCKETS_CACHE_TTL = 900

# Tactic → hex colour map for key-event chips (MITRE rainbow + the grey "_other").
_TACTIC_COLORS = {**_MITRE_TACTIC_COLORS, _OTHER_TACTIC: _OTHER_TACTIC_COLOR}


def _visible_filter(stmt, user: User):
    """Limit a query to cases the user can see: their own + shared + (admin sees all).

    Delegates to `models.visible_case_filter`, the same clause the entity/job "in these
    cases" backlinks use (`routers/intel.py`, `routers/jobs.py`).
    `routers/comments.py::_resolve_target` enforces the identical rule by hand — it tests a
    loaded case, not a query — so a change here has to be mirrored there.
    """
    vis = visible_case_filter(user)
    return stmt if vis is True else stmt.where(vis)


async def _principal_user(db: AsyncSession, principal) -> User | None:
    """Thin alias over ``app/auth/api_tokens.py``, which intel shares.

    A ``case:read`` token cannot reach a case its creator could not, and the same holds for
    ``ioc_feed:read``.
    """
    return await principal_user(db, principal)


async def _load_case_or_404(db: AsyncSession, case_id: int, user: User | None) -> InvestigationCase:
    case = await db.get(InvestigationCase, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    # `user` may be None for a token whose creator was removed — such a request sees
    # shared cases only. getattr keeps that path from raising instead of 404ing.
    if not getattr(user, "is_superuser", False) and (user is None or case.created_by_user_id != user.id) and not case.is_shared:
        raise HTTPException(404, "Case not found")
    return case


def _is_owner(case: InvestigationCase, user: User) -> bool:
    return bool(user.is_superuser) or case.created_by_user_id == user.id


def _can_edit_link_note(case: InvestigationCase, link, user: User) -> bool:
    """Adder-or-owner: whoever added the link, or the case owner, may edit its note."""
    return link.added_by_user_id == user.id or _is_owner(case, user)


def _clean_note(raw: str, cap: int) -> str | None:
    """Strip a freeform note; empty -> None; over *cap* chars -> 400.

    Thin alias over the shared `app.comments.clean_text` so this router, the
    comment routes and the entity-notes route cannot drift apart.
    """
    return clean_text(raw, cap, label="Note")


def _build_case_tabs(entity_count: int, job_count: int, comment_count: int = 0, *, show_ai: bool = False) -> list[dict]:
    """Assemble the case-detail tab list. Mirrors `routers/intel.py::_build_entity_tabs` —
    same dict shape (`key`, `label`, `badge`, `lazy_event`, `icon`) so the entity page's
    Alpine tab component works unchanged. The `timeline` tab sits second (after overview)
    and lazy-loads its pane via the `loadTimeline` body event, exactly like `graph`/`loadGraph`.
    """
    return [
        {"key": "overview", "label": "Overview", "badge": None, "lazy_event": None, "icon": "info"},
        {"key": "timeline", "label": "Timeline", "badge": None, "lazy_event": "loadTimeline", "icon": "clock"},
        # Both lazy, because they are paged: the badge counts come from two cheap COUNTs
        # in `case_detail`, and the rows arrive only if you open the tab.
        {"key": "entities", "label": "Entities", "badge": entity_count, "lazy_event": "loadEntities", "icon": "users"},
        {"key": "jobs", "label": "Jobs", "badge": job_count, "lazy_event": "loadJobs", "icon": "files"},
        {"key": "processes", "label": "Processes", "badge": None, "lazy_event": "loadProcesses", "icon": "tree"},
        {"key": "graph", "label": "Graph", "badge": None, "lazy_event": "loadGraph", "icon": "graph"},
        # The narrative lives on Overview, so this is the conversation alone — same split
        # as the entity page, same lazy event as the job page. Discussions stays last here
        # too, so the two detail pages put Graph and Discussions in the same place.
        *([{"key": "ai", "label": "AI Analysis", "badge": None, "lazy_event": "loadAiAnalysis", "icon": "sparkles"}] if show_ai else []),
        {"key": "discussion", "label": "Discussions", "badge": comment_count or None, "lazy_event": "loadComments", "icon": "chat"},
    ]


def _tactic_counts_from_tag_rows(rows: list[tuple[str | None, int]]) -> dict[str, int]:
    """Resolve `attack.<tactic>` finding tags into canonical MITRE tactic counts.

    `rows` is `(Finding.tags, Finding.count)` pairs; `tags` is a JSON string. Tag
    normalization mirrors `app.intel.tactics._build_findings_index` (lowercase, strip an
    `attack.` prefix, dash/space → underscore) so results agree with the job-detail MITRE
    view. Tags that don't resolve to a canonical tactic (including bare technique IDs) are
    ignored — this only counts tactics, not techniques.
    """
    counts: dict[str, int] = {}
    for tags_json, cnt in rows:
        if not tags_json:
            continue
        try:
            tags = json_loads(tags_json)
        except ValueError:
            continue
        if not isinstance(tags, list):
            continue
        for tag in tags:
            key = str(tag).lower()
            if key.startswith("attack."):
                key = key[len("attack.") :]
            key = key.replace("-", "_").replace(" ", "_")
            if key in _MITRE_TACTICS_SET:
                counts[key] = counts.get(key, 0) + (cnt or 0)
    return counts


async def _fetch_entity_tags(db: AsyncSession, entity_ids: list[int]) -> dict[int, list[dict]]:
    """Bulk-load analyst tags for the given entities — mirrors `routers/intel.py`'s
    `entities_partial`. Used by every surface that renders `_case_entity_row.html`."""
    if not entity_ids:
        return {}
    rows = (await db.execute(select(EntityTag.entity_id, EntityTag.tag, EntityTag.color).where(EntityTag.entity_id.in_(entity_ids)).order_by(EntityTag.tag))).all()
    out: dict[int, list[dict]] = {}
    for eid, tag, color in rows:
        out.setdefault(eid, []).append({"tag": tag, "color": color})
    return out


def _note_update_targets(requested: list[int], existing: set[int], note: str | None) -> list[int]:
    """Ids that are already linked and whose note this request should overwrite.

    Re-adding something already in a case updates its note: a silent no-op would swallow
    the note, leaving the row editor as the only way to attach a reason to an existing link.

    **An empty note is not an instruction to clear one.** The field is blank by default on
    every one of these forms, so treating blank as "erase" would delete a colleague's note
    on any re-add. Clearing is what the inline note editor is for, where it is deliberate.
    """
    if not note:
        return []
    return [i for i in requested if i in existing]


async def _link_entities(db: AsyncSession, case_id: int, entity_ids: list[int], added_by_user_id, note: str | None) -> int:
    """Link entities to a case, skipping ones already linked. Returns the count added.

    Diff-then-insert against the existing links in one commit — the same discipline as
    `_bulk_add_job_entities`, and it avoids the per-row IntegrityError/rollback dance
    (rollback expires the session's identity map, which is the `MissingGreenlet` hazard
    documented on `case_add_job`).
    """
    if not entity_ids:
        return 0
    unique = list(dict.fromkeys(entity_ids))
    existing = set((await db.execute(select(CaseEntityLink.entity_id).where(CaseEntityLink.case_id == case_id))).scalars().all())
    to_link = [eid for eid in unique if eid not in existing]
    for entity_id in to_link:
        db.add(CaseEntityLink(case_id=case_id, entity_id=entity_id, added_by_user_id=added_by_user_id, note=note))
    already = _note_update_targets(unique, existing, note)
    if already:
        await db.execute(update(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id.in_(already)).values(note=note))
    if to_link or already:
        await db.commit()
    return len(to_link)


async def _link_jobs(db: AsyncSession, case_id: int, job_ids: list[int], added_by_user_id, note: str | None, *, viewer: User) -> list[int]:
    """Link jobs to a case after checking every id is viewable.

    Returns every requested id — newly linked and already-linked alike — so the bulk caller
    imports each job's entities either way.

    Visibility is validated for ALL ids before any write: a partial success would be an
    existence oracle for another member's private jobs, so one unviewable id 404s the
    whole request with the same "Job not found" message used everywhere else.
    """
    if not job_ids:
        return []
    unique = list(dict.fromkeys(job_ids))
    jobs = (await db.execute(select(AnalysisJob).where(AnalysisJob.id.in_(unique)))).scalars().all()
    by_id = {j.id: j for j in jobs}
    for jid in unique:
        job = by_id.get(jid)
        if job is None or not can_view_job(job, viewer):
            raise HTTPException(404, "Job not found")

    existing = set((await db.execute(select(CaseJobLink.job_id).where(CaseJobLink.case_id == case_id))).scalars().all())
    to_link = [jid for jid in unique if jid not in existing]
    for job_id in to_link:
        db.add(CaseJobLink(case_id=case_id, job_id=job_id, added_by_user_id=added_by_user_id, note=note))
    already = _note_update_targets(unique, existing, note)
    if already:
        await db.execute(update(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id.in_(already)).values(note=note))
    if to_link or already:
        await db.commit()
    return unique


async def _bulk_add_job_entities(db: AsyncSession, case_id: int, job_id: int, added_by_user_id) -> int:
    """Link every entity that appeared in job *job_id* to case *case_id*, skipping ones already linked.

    Takes plain ids rather than ORM objects: a caller that just handled an
    IntegrityError (e.g. `case_add_job` re-adding an already-linked job) will have
    called `db.rollback()`, which expires every object in the session's identity map —
    touching an attribute like `case.id` afterwards would trigger an implicit sync
    refresh and crash with MissingGreenlet under the async engine. Plain ints have no
    such hazard.

    Capped at `_BULK_ENTITY_CAP` per call. Commits when there's something to add — no
    per-row IntegrityError dance since the diff is computed against existing links first.
    Returns the number of new links created.
    """
    existing_ids = set((await db.execute(select(CaseEntityLink.entity_id).where(CaseEntityLink.case_id == case_id))).scalars().all())
    candidate_ids = (await db.execute(select(EntityJobLink.entity_id).where(EntityJobLink.job_id == job_id))).scalars().all()
    to_link = [eid for eid in dict.fromkeys(candidate_ids) if eid not in existing_ids][:_BULK_ENTITY_CAP]
    for entity_id in to_link:
        db.add(CaseEntityLink(case_id=case_id, entity_id=entity_id, added_by_user_id=added_by_user_id))
    if to_link:
        await db.commit()
    return len(to_link)


@router.get("", response_class=HTMLResponse)
async def cases_list(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    status: str = "",
    q: str = "",
    sort: str = "",
):
    """List cases visible to the current user (own + shared, or all for admin).

    Triage aggregates: per-case findings-severity counts — privacy-filtered via
    `visible_job_filter` so a private job linked into a shared case never contributes its
    findings to a non-owner viewer's counts/derived severity, same discipline as
    `case_summary_partial` — plus last job/entity link activity. `build_case_list_rows`
    turns these into rows and applies the (Python-side) `sort`.
    """
    stmt = _visible_filter(select(InvestigationCase), user)
    if status and status in _VALID_STATUSES:
        stmt = stmt.where(InvestigationCase.status == status)
    if q:
        # Escaped like the other search boxes in this file — an unescaped `%` here would
        # match every case, and `_` any character.
        stmt = stmt.where(InvestigationCase.name.ilike(f"%{escape_like(q.strip())}%", escape="\\"))
    stmt = stmt.order_by(InvestigationCase.updated_at.desc()).limit(200)
    cases = (await db.execute(stmt)).scalars().all()

    counts_stmt = select(InvestigationCase.status, func.count(InvestigationCase.id)).group_by(InvestigationCase.status)
    counts = dict((await db.execute(_visible_filter(counts_stmt, user))).all())

    case_ids = [c.id for c in cases]
    entity_counts: dict[int, int] = {}
    job_counts: dict[int, int] = {}
    severity_counts_by_case: dict[int, dict[str, int]] = {}
    job_activity: dict[int, datetime] = {}
    entity_activity: dict[int, datetime] = {}
    if case_ids:
        entity_counts = dict(
            (await db.execute(select(CaseEntityLink.case_id, func.count(CaseEntityLink.id)).where(CaseEntityLink.case_id.in_(case_ids)).group_by(CaseEntityLink.case_id))).all()
        )
        # Jobs the viewer can see only, like the severity roll-up below and the case's own
        # Jobs tab — joined to AnalysisJob, which also drops links to deleted jobs.
        vis = visible_job_filter(user)
        visible_links = (
            select(CaseJobLink.case_id, CaseJobLink.id, CaseJobLink.added_at).join(AnalysisJob, CaseJobLink.job_id == AnalysisJob.id).where(CaseJobLink.case_id.in_(case_ids))
        )
        if vis is not True:
            visible_links = visible_links.where(vis)
        visible_links = visible_links.subquery()
        job_counts = dict((await db.execute(select(visible_links.c.case_id, func.count(visible_links.c.id)).group_by(visible_links.c.case_id))).all())

        sev_stmt = (
            select(CaseJobLink.case_id, Finding.severity, func.count(Finding.id))
            .join(AnalysisJob, CaseJobLink.job_id == AnalysisJob.id)
            .join(TaskResult, TaskResult.job_id == AnalysisJob.id)
            .join(Finding, Finding.task_result_id == TaskResult.id)
            .where(CaseJobLink.case_id.in_(case_ids))
        )
        if vis is not True:
            sev_stmt = sev_stmt.where(vis)
        sev_stmt = sev_stmt.group_by(CaseJobLink.case_id, Finding.severity)
        for case_id, severity, cnt in (await db.execute(sev_stmt)).all():
            severity_counts_by_case.setdefault(case_id, {})[enum_val(severity)] = cnt or 0

        # Filtered the same way: when a private job was linked is itself a fact about it.
        job_activity = dict((await db.execute(select(visible_links.c.case_id, func.max(visible_links.c.added_at)).group_by(visible_links.c.case_id))).all())
        entity_activity = dict(
            (await db.execute(select(CaseEntityLink.case_id, func.max(CaseEntityLink.added_at)).where(CaseEntityLink.case_id.in_(case_ids)).group_by(CaseEntityLink.case_id))).all()
        )

    sort_value = sort if sort in _VALID_CASE_LIST_SORTS else "updated"
    rows = build_case_list_rows(cases, severity_counts_by_case, job_activity, entity_activity, sort_value)

    return templates.TemplateResponse(
        request,
        "intel/cases_list.html",
        {
            "request": request,
            "user": user,
            "rows": rows,
            "counts": counts,
            "entity_counts": entity_counts,
            "job_counts": job_counts,
            "current_status": status,
            "current_q": q,
            "current_sort": sort_value,
        },
    )


@router.post("")
async def case_create(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    name: str = Form(...),
    summary: str = Form(""),
    severity: str = Form(""),
    is_shared: int = Form(0),
):
    """Create a case; redirects to its detail page."""
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Name is required")
    if len(name) > _NAME_MAX:
        raise HTTPException(400, f"Name too long (max {_NAME_MAX} chars)")
    if len(summary) > _SUMMARY_MAX:
        raise HTTPException(400, f"Summary too long (max {_SUMMARY_MAX} chars)")
    sev = severity.strip().lower() if severity else None
    if sev and sev not in _VALID_SEVERITIES:
        sev = None
    case = InvestigationCase(
        name=name,
        summary=summary or None,
        severity=sev,
        created_by_user_id=user.id,
        is_shared=bool(is_shared),
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return RedirectResponse(f"/intel/cases/{case.id}", status_code=303)


@router.post("/quick-create")
async def case_quick_create(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    name: str = Form(...),
    entity_id: int = Form(0),
    job_id: int = Form(0),
    include_job_entities: int = Form(0),
    note: str = Form(""),
):
    """Create a case and optionally link an entity/job in one step.

    This is the friction-killer path invoked from the entity/job "Add to case" dialogs
    when the analyst types a new case name instead of picking an existing one. Validation
    mirrors `case_create`; entity/job lookups happen before the case is created so a 404
    never leaves an orphan case behind. `note` mirrors `case_add_entity`/`case_add_job`'s
    validation (strip/500-cap/400) and is stored on whichever link(s) get created — the
    same note text isn't split between entity and job, it's just applied to each linked
    row when both are present.
    """
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Name is required")
    if len(name) > _NAME_MAX:
        raise HTTPException(400, f"Name too long (max {_NAME_MAX} chars)")
    clean_note = _clean_note(note, _LINK_NOTE_MAX)

    entity = None
    if entity_id > 0:
        entity = await db.get(Entity, entity_id)
        if not entity:
            raise HTTPException(404, "Entity not found")

    job = None
    if job_id > 0:
        job = await db.get(AnalysisJob, job_id)
        # Treat a private job the adder can't see as non-existent (mirrors case_add_job).
        if not job or not can_view_job(job, user):
            raise HTTPException(404, "Job not found")

    case = InvestigationCase(
        name=name,
        summary=None,
        severity=None,
        created_by_user_id=user.id,
        is_shared=False,
    )
    db.add(case)
    await db.flush()  # assigns case.id so the links below can reference it
    if entity is not None:
        db.add(CaseEntityLink(case_id=case.id, entity_id=entity.id, added_by_user_id=user.id, note=clean_note))
    if job is not None:
        db.add(CaseJobLink(case_id=case.id, job_id=job.id, added_by_user_id=user.id, note=clean_note))
    await db.commit()
    await db.refresh(case)

    if job is not None and include_job_entities:
        await _bulk_add_job_entities(db, case.id, job.id, user.id)

    return RedirectResponse(f"/intel/cases/{case.id}", status_code=303)


@router.get("/pickers/entities.json")
async def cases_picker_entities(
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    q: str = "",
):
    """Entity search for the case-detail/add-to-case pickers.

    Empty `q` browses (the busiest entities first) so opening the dialog shows something
    to pick rather than a blank box; 1 char still returns nothing, because answering
    mid-keystroke with an unfiltered list is worse than answering with nothing. 2+ chars
    searches. Allowlisted entities are excluded — the browse default should surface
    useful observables, not muted ones.
    """
    q = (q or "").strip()
    stmt = select(Entity).where(Entity.allowlisted.is_(False))
    if q:
        if len(q) < _PICKER_MIN_CHARS:
            return JSONResponse([])
        stmt = stmt.where(Entity.value.ilike(f"%{escape_like(q)}%", escape="\\"))
    stmt = stmt.order_by(Entity.job_count.desc(), Entity.last_seen_at.desc()).limit(_PICKER_LIMIT)
    entities = (await db.execute(stmt)).scalars().all()
    return JSONResponse([{"id": e.id, "value": e.value, "entity_type": e.entity_type, "job_count": e.job_count or 0} for e in entities])


@router.get("/pickers/jobs.json")
async def cases_picker_jobs(
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    q: str = "",
):
    """Job search for the case-detail/add-to-case pickers.

    Empty `q` browses the most recent visible jobs, so you can pick without already
    knowing a filename or id. A purely numeric `q` matches the job id exactly; otherwise
    it needs 2+ chars and matches the original filename. `visible_job_filter` is applied
    unconditionally, so the browse list is privacy-safe by construction — another user's
    private jobs never appear, regardless of query shape.
    """
    q = (q or "").strip()
    vis = visible_job_filter(user)
    stmt = select(AnalysisJob).options(selectinload(AnalysisJob.log_file))
    if vis is not True:
        stmt = stmt.where(vis)
    if q.isascii() and q.isdigit():
        numeric_q = parse_row_id(q)
        # A long digit string can overflow int4 — on PostgreSQL that 500s at bind time
        # rather than just matching nothing. Degrade to "no match".
        if numeric_q is None:
            return JSONResponse([])
        stmt = stmt.where(AnalysisJob.id == numeric_q)
    elif q:
        if len(q) < _PICKER_MIN_CHARS:
            return JSONResponse([])
        pattern = f"%{escape_like(q)}%"
        stmt = stmt.join(LogFile, AnalysisJob.file_id == LogFile.id).where(AnalysisJob.filename.ilike(pattern, escape="\\"))
    stmt = stmt.order_by(AnalysisJob.created_at.desc()).limit(_PICKER_LIMIT)
    jobs = (await db.execute(stmt)).scalars().all()
    return JSONResponse(
        [
            {
                "id": j.id,
                "filename": j.filename if j.log_file else f"job {j.id}",
                "created_at": j.created_at.strftime("%Y-%m-%d %H:%M") if j.created_at else "",
                "status": enum_val(j.status),
            }
            for j in jobs
        ]
    )


# JSON variant used by the "Add to case" modal on entity/job detail.
# Declared before /{case_id} so FastAPI doesn't try to parse "list.json" as an int.
@router.get("/list.json")
async def cases_list_json(
    db: AsyncSession = Depends(get_async_session),
    _principal=Depends(current_user_or_api_token("case:read")),
    status: str = "",
    limit: int = 100,
):
    """Case index. Cookie auth (member-or-above) OR a Bearer token with `case:read`.

    Defaults to open+monitoring cases, as the in-app picker expects; pass
    `status=closed` (or `status=all`) to widen it for an external integration.
    """
    user = await _principal_user(db, _principal)
    stmt = _visible_filter(select(InvestigationCase), user)
    status = (status or "").strip().lower()
    if status in _VALID_STATUSES:
        stmt = stmt.where(InvestigationCase.status == status)
    elif status != "all":
        stmt = stmt.where(InvestigationCase.status != "closed")
    stmt = stmt.order_by(InvestigationCase.updated_at.desc()).limit(max(1, min(limit, 500)))
    cases = (await db.execute(stmt)).scalars().all()
    return JSONResponse([{"id": c.id, "name": c.name, "status": c.status, "is_shared": c.is_shared} for c in cases])


def _case_entity_links_stmt(case_id: int, *, count: bool = False, q: str = "", entity_type: str = ""):
    """Entity links of a case, newest first — the one definition, count and rows alike.

    The `Entity` join is not decoration. An older database can hold links whose `Entity` is
    gone, and dropping those **in Python after the LIMIT** makes offset/limit pagination
    ragged — a page of 50 rendering 47 rows, the missing three on no page at all. An INNER
    JOIN removes them before the window, so every page is full and every row is reachable.

    **`CaseEntityLink.id` is the tiebreaker and it is load-bearing.** `added_at` is not
    unique: `POST /{case_id}/jobs/{id}/add-entities` links hundreds of entities with one
    timestamp, and SQL may return tied rows in any order per query — so without it paging
    shows a row twice and skips another. `intel.py`'s entity sort does the same.
    """
    base = (select(func.count(CaseEntityLink.id)) if count else select(CaseEntityLink)).join(Entity, CaseEntityLink.entity_id == Entity.id).where(CaseEntityLink.case_id == case_id)
    # Filters live on the shared builder so the count and the rows cannot disagree — a
    # filtered list under an unfiltered total is the same class of lie as an unfiltered
    # tab badge over a scoped pane.
    q = (q or "").strip()
    if q:
        base = base.where(Entity.value.ilike(f"%{escape_like(q)}%", escape="\\"))
    if entity_type in ENTITY_TYPES:
        base = base.where(Entity.entity_type == entity_type)
    if count:
        return base
    return base.options(selectinload(CaseEntityLink.entity), selectinload(CaseEntityLink.added_by)).order_by(CaseEntityLink.added_at.desc(), CaseEntityLink.id.desc())


def _case_job_links_stmt(case_id: int, user: User | None, *, count: bool = False):
    """Job links of a case, newest first, visibility-filtered **in SQL**.

    A `can_view_job` pass after the LIMIT would silently shorten the page by every private
    job another member linked into a shared case — the entity side's ragged-page problem.
    The count query filters the same way, so the two agree by construction.

    The INNER JOIN also drops links whose `AnalysisJob` is gone.
    """
    join_target = (
        (select(func.count(CaseJobLink.id)) if count else select(CaseJobLink)).join(AnalysisJob, CaseJobLink.job_id == AnalysisJob.id).where(CaseJobLink.case_id == case_id)
    )
    vis = visible_job_filter(user)
    if vis is not True:
        join_target = join_target.where(vis)
    if count:
        return join_target
    return join_target.options(selectinload(CaseJobLink.job).selectinload(AnalysisJob.log_file), selectinload(CaseJobLink.added_by)).order_by(
        CaseJobLink.added_at.desc(), CaseJobLink.id.desc()
    )


def _page_window(total: int, page: int) -> tuple[int, int, int]:
    """`(clamped_page, total_pages, offset)` — the arithmetic every paged list here uses."""
    total_pages = max(1, -(-total // _CASE_PAGE_SIZE))
    page = max(1, min(page, total_pages))
    return page, total_pages, (page - 1) * _CASE_PAGE_SIZE


@router.get("/{case_id}/process-tree-partial", response_class=HTMLResponse)
async def case_process_tree_partial(
    request: Request,
    case_id: int,
    job: int = 0,
    entity_id: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Process lineage for one of the case's jobs, optionally anchored on one of its entities.

    **A job alone is enough to draw.** The job draws the full forest, exactly as the job page
    does, and the entity is a refinement on top of it. Requiring an entity first would send
    the analyst out of the case to read a tree the case can render itself, through an anchor
    picker a freshly added job may not have contributed to at all.

    The anchor still buys three things when set: the server-side prune to chains that name
    it, the amber highlight, and the Relationships panel underneath. Unanchored is strictly
    the cheaper call — `load_job_forest` caches the *unfiltered* forest and the prune runs
    after it, so drawing without an anchor skips a pass rather than adding one.

    Three filter values, three different dispositions, and they are deliberate:

    * an unusable `job` is silently dropped (`_resolve_case_job_scope`) — a case renders
      unfiltered by default;
    * an `entity_id` outside the case still 404s with one message, so it cannot become an
      enumeration oracle for the rest of the database;
    * an in-case entity that this job never saw is **dropped**, with a note. That is the
      only state a job change can leave behind, and blanking the pane for it would be a
      dead end.
    """
    from app.intel.lineage import PROCESS_TREE_ENTITY_TYPES
    from app.intel.process_tree import load_job_forest
    from app.routers.intel import fetch_relationship_groups

    case = await _load_case_or_404(db, case_id, user)
    site_settings = await get_site_settings(db)

    job = await _resolve_case_job_scope(db, case_id, job, user)
    job_options = await _case_job_options(db, case_id, user)
    # A case with one job adopts it rather than making you pick it out of a list of one —
    # server-side, not by pre-selecting the `<option>`: the placeholder below branches on
    # `job`, so a template-only default would show job #N in the select while the pane still
    # read "Choose a job to read lineage from".
    if not job and len(job_options) == 1:
        job = job_options[0]["id"]

    entity = None
    anchor_dropped = False
    if entity_id:
        linked = await db.scalar(select(CaseEntityLink.id).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity_id))
        if not linked:
            raise HTTPException(404, "Entity not found")
        entity = await db.get(Entity, entity_id)
        if not entity or entity.entity_type not in PROCESS_TREE_ENTITY_TYPES:
            raise HTTPException(404, "Entity not found")
        # Checked *after* case membership, so the two failures keep their separate answers:
        # outside the case is still indistinguishable from non-existent, while inside the
        # case but absent from this job is a state the analyst produced themselves by
        # changing the job, and is worth explaining. `EntityJobLink` is the right test even
        # though it is broader than "names a process node" — an entity the job saw only in a
        # network event survives here and the tree's own empty state then says precisely why
        # it anchors nothing, which is more useful than a cleared field.
        if job and entity and not await db.scalar(select(EntityJobLink.id).where(EntityJobLink.entity_id == entity.id, EntityJobLink.job_id == job)):
            entity = None
            anchor_dropped = True

    ctx = {
        "request": request,
        "case": case,
        "job": job,
        "entity": entity,
        "job_options": job_options,
        "eligible_types": ",".join(sorted(PROCESS_TREE_ENTITY_TYPES)),
        "disabled": not site_settings.show_process_tree,
        "anchor_dropped": anchor_dropped,
        "forest": None,
        "scope_label": "",
        "groups": [],
        "rel_total": 0,
        "rel_capped": False,
    }
    if job and site_settings.show_process_tree:
        if entity:
            # Plain strings resolved before the threadpool hop — never an ORM instance.
            ctx["forest"] = await load_job_forest(job, entity_type=entity.entity_type, entity_value=entity.value)
            ctx["scope_label"] = f"job #{job} · {entity.value}"
            # The two halves of one question: the tree says how this binary *ran*, the typed
            # edges say what it touched. Same grouping code as the Intel Relationships tab —
            # a second implementation would drift from it within a release. Scoped to the same
            # job by co-occurrence, so both panels describe one run.
            groups, total, capped = await fetch_relationship_groups(db, entity.id, job)
            ctx.update(groups=groups, rel_total=total, rel_capped=capped)
        else:
            ctx["forest"] = await load_job_forest(job)
    return templates.TemplateResponse(request, "intel/partials/_case_processes.html", ctx)


@router.get("/{case_id}/entities-partial", response_class=HTMLResponse)
async def case_entities_partial(
    request: Request,
    case_id: int,
    page: int = 1,
    q: str = "",
    entity_type: str = "",
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """One page of the case's entity links, optionally filtered.

    Filtering server-side rather than in the browser because the list is paged: a
    client-side filter would only ever search the fifty rows currently loaded, which on a
    500-entity case is a search that quietly misses 90% of the answer.
    """
    case = await _load_case_or_404(db, case_id, user)
    q = (q or "").strip()[:200]
    entity_type = entity_type if entity_type in ENTITY_TYPES else ""
    total = await db.scalar(_case_entity_links_stmt(case_id, count=True, q=q, entity_type=entity_type)) or 0
    page, total_pages, offset = _page_window(total, page)
    links = (await db.execute(_case_entity_links_stmt(case_id, q=q, entity_type=entity_type).offset(offset).limit(_CASE_PAGE_SIZE))).scalars().all()
    return templates.TemplateResponse(
        request,
        "intel/partials/_case_entities.html",
        {
            "request": request,
            "user": user,
            "case": case,
            "entity_links": links,
            "entity_total": total,
            # The unfiltered count, so the header can say "12 of 498" rather than leaving
            # the analyst wondering whether the case shrank.
            "entity_grand_total": await db.scalar(_case_entity_links_stmt(case_id, count=True)) or 0,
            "q": q,
            "entity_type": entity_type,
            "entity_types": list(ENTITY_TYPES),
            "page": page,
            "total_pages": total_pages,
            "page_size": _CASE_PAGE_SIZE,
            "is_owner": _is_owner(case, user),
            # Bulk-loaded for *this page*. `_case_entity_row.html` reads it per row, and
            # without it every tag chip silently disappears.
            "tags_by_entity": await _fetch_entity_tags(db, [el.entity_id for el in links]),
        },
    )


@router.get("/{case_id}/jobs-partial", response_class=HTMLResponse)
async def case_jobs_partial(
    request: Request,
    case_id: int,
    page: int = 1,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """One page of the case's job links, visibility-filtered in SQL."""
    case = await _load_case_or_404(db, case_id, user)
    total = await db.scalar(_case_job_links_stmt(case_id, user, count=True)) or 0
    page, total_pages, offset = _page_window(total, page)
    links = (await db.execute(_case_job_links_stmt(case_id, user).offset(offset).limit(_CASE_PAGE_SIZE))).scalars().all()
    return templates.TemplateResponse(
        request,
        "intel/partials/_case_jobs.html",
        {
            "request": request,
            "user": user,
            "case": case,
            "job_links": links,
            "job_total": total,
            "page": page,
            "total_pages": total_pages,
            "page_size": _CASE_PAGE_SIZE,
            "is_owner": _is_owner(case, user),
        },
    )


@router.get("/{case_id}", response_class=HTMLResponse)
async def case_detail(
    request: Request,
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    case = await _load_case_or_404(db, case_id, user)

    # Only the two counts here — the rows themselves are lazy-loaded by the paged partials
    # below, because most visits land on Overview. The badges still show the true totals: a
    # tab reading "200" on a case with 900 entities would be its own small lie.
    entity_total = await db.scalar(_case_entity_links_stmt(case_id, count=True)) or 0
    job_total = await db.scalar(_case_job_links_stmt(case_id, user, count=True)) or 0

    comment_count = (await comment_counts_for(db, "case", [case_id])).get(case_id, 0)
    site = await get_site_settings(db)
    tabs = _build_case_tabs(entity_total, job_total, comment_count, show_ai=site.show_ai_analysis)

    return templates.TemplateResponse(
        request,
        "intel/case_detail.html",
        {
            "request": request,
            "user": user,
            "case": case,
            "entity_total": entity_total,
            "job_total": job_total,
            "is_owner": _is_owner(case, user),
            "valid_statuses": sorted(_VALID_STATUSES),
            "tabs": tabs,
            "site_settings": await get_site_settings(db),
        },
    )


@router.get("/{case_id}/detail.json")
async def case_detail_json(
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    _principal=Depends(current_user_or_api_token("case:read")),
):
    """Machine-readable case detail. Cookie auth OR a Bearer token with `case:read`.

    Named `/detail.json` rather than `/{case_id}.json` deliberately: the latter shares a
    path shape with the HTML `/{case_id}` route, and `case_id: int` would reject
    "5.json" with a 422 before any fallthrough — the same registration-order trap the
    comment routes document.

    Job members are filtered by `visible_job_filter`, so a private job another member
    linked into a shared case does not leak its filename or id here.
    """
    user = await _principal_user(db, _principal)
    case = await _load_case_or_404(db, case_id, user)

    entities = (
        (
            await db.execute(
                select(Entity)
                .join(CaseEntityLink, CaseEntityLink.entity_id == Entity.id)
                .where(CaseEntityLink.case_id == case_id)
                .order_by(Entity.job_count.desc(), Entity.value)
                .limit(_CASE_LINK_CAP)
            )
        )
        .scalars()
        .all()
    )

    job_stmt = select(AnalysisJob).join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id).where(CaseJobLink.case_id == case_id)
    job_vis = visible_job_filter(user)
    if job_vis is not True:
        job_stmt = job_stmt.where(job_vis)
    jobs = (await db.execute(job_stmt.options(selectinload(AnalysisJob.log_file)).order_by(AnalysisJob.created_at.desc()).limit(_CASE_LINK_CAP))).scalars().all()

    return JSONResponse(
        {
            "id": case.id,
            "name": case.name,
            "summary": case.summary,
            "status": case.status,
            "severity": case.severity,
            "is_shared": case.is_shared,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "updated_at": case.updated_at.isoformat() if case.updated_at else None,
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "entities": [{"id": e.id, "value": e.value, "entity_type": e.entity_type, "job_count": e.job_count} for e in entities],
            "jobs": [
                {
                    "id": j.id,
                    "status": enum_val(j.status),
                    "score_ratio": j.score_ratio,
                    "total_findings": j.total_findings,
                    "filename": j.filename if j.log_file else None,
                    "created_at": j.created_at.isoformat() if j.created_at else None,
                }
                for j in jobs
            ],
            "truncated": len(entities) >= _CASE_LINK_CAP or len(jobs) >= _CASE_LINK_CAP,
        }
    )


@router.get("/{case_id}/entities.json")
async def case_entities_json(
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    _principal=Depends(current_user_or_api_token("case:read")),
    q: str = "",
    types: str = "",
    job: int = 0,
):
    """Search this case's linked entities — backs the timeline and Processes search boxes.

    Scoped to the case (the timeline filter only accepts case members anyway, see
    `case_timeline_partial`), and capped, so a case with thousands of entities costs a
    bounded query instead of rendering every one into a `<select>`. Empty `q` browses the
    busiest entities so the box is useful before you type.

    `types` is a CSV the Processes tab passes so its picker only offers the entity types a
    lineage node can match. Without it an analyst picks an `ip_address` and gets an
    unexplained empty tree. Purely a narrowing of an already case-scoped query, so it
    changes nothing about visibility.

    `job` narrows further, to entities that job actually saw, and the Processes tab passes
    it for the same reason it passes `types`: the case's entity set and one job's entity set
    are not the same list. Without it the picker would offer the case links with the highest
    **instance-wide** `job_count` — usually unrelated to the selected job, while that job's
    own observables go unlisted (a freshly linked job contributes them only when the adder
    ticked "include entities", and never past `_BULK_ENTITY_CAP`). Job-scoped, the ranking
    can also be the honest one: `EntityJobLink.occurrence_count`, relevance *within that
    run* rather than popularity across the database.

    An unusable `job` is dropped through `_resolve_case_job_scope`, exactly as its sibling
    routes do it, so passing another case's job id — or one that does not exist — returns
    the same unscoped list as passing nothing, and the parameter cannot be used to probe
    which jobs a case holds.
    """
    user = await _principal_user(db, _principal)
    await _load_case_or_404(db, case_id, user)  # authz side-effect
    job = await _resolve_case_job_scope(db, case_id, job, user)
    stmt = select(Entity).join(CaseEntityLink, CaseEntityLink.entity_id == Entity.id).where(CaseEntityLink.case_id == case_id)
    wanted = [t.strip() for t in (types or "").split(",") if t.strip() in ENTITY_TYPES]
    if wanted:
        stmt = stmt.where(Entity.entity_type.in_(wanted))
    # Capped like `case_entities_partial` does it. This is token-reachable, and the minimum
    # length below does not short-circuit a job-scoped query — so without the ceiling an
    # arbitrarily long `ilike` pattern reaches the database.
    q = (q or "").strip()[:200]
    if q:
        # The minimum only guards the *unscoped* query, which walks every entity the case
        # links. A job scope bounds the candidate set to one run's observables through an
        # indexed join, so a single character is cheap there — and refusing it would make the
        # dropdown vanish on the first keystroke and come back on the second.
        if not job and len(q) < _PICKER_MIN_CHARS:
            return JSONResponse([])
        stmt = stmt.where(Entity.value.ilike(f"%{escape_like(q)}%", escape="\\"))
    if job:
        stmt = stmt.join(EntityJobLink, EntityJobLink.entity_id == Entity.id).where(EntityJobLink.job_id == job).order_by(EntityJobLink.occurrence_count.desc(), Entity.value)
    else:
        stmt = stmt.order_by(Entity.job_count.desc(), Entity.value)
    entities = (await db.execute(stmt.limit(_PICKER_LIMIT))).scalars().all()
    return JSONResponse([{"id": e.id, "value": e.value, "entity_type": e.entity_type} for e in entities])


@router.get("/{case_id}/summary-partial", response_class=HTMLResponse)
async def case_summary_partial(
    request: Request,
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Findings roll-up for the Overview tab: severity totals, top rules, tactic mix.

    Case jobs are visibility-filtered **in the SELECT**, before any aggregation runs — a
    private job another member linked into a shared case must never contribute findings to
    a non-owner viewer's roll-up.

    Deliberately still unbounded: this is an *aggregation*, not a listing. Capping it would
    make the numbers wrong, which is worse than making them slow. The real cost here is
    per-job, not per-row, and belongs to a pre-aggregation fix rather than a pagination one.
    """
    case = await _load_case_or_404(db, case_id, user)

    # Visibility applied in SQL rather than as a Python pass afterwards: the rows a member
    # may not see are never loaded, and the eager `log_file` for each of them is never
    # fetched. `visible_job_filter` and `can_view_job` are the same rule, one as a clause
    # and one as a predicate.
    jobs_stmt = select(AnalysisJob).join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id).where(CaseJobLink.case_id == case_id).options(selectinload(AnalysisJob.log_file))
    vis = visible_job_filter(user)
    if vis is not True:
        jobs_stmt = jobs_stmt.where(vis)
    jobs = (await db.execute(jobs_stmt)).scalars().all()
    job_ids = [j.id for j in jobs]

    severity_rows: list[tuple[str, int, int]] = []
    rule_rows: list[tuple[str, str, int]] = []
    tactic_counts: dict[str, int] = {}

    if job_ids:
        raw_severity_rows = (
            await db.execute(
                select(Finding.severity, func.count(Finding.id), func.sum(Finding.count))
                .join(TaskResult, Finding.task_result_id == TaskResult.id)
                .where(TaskResult.job_id.in_(job_ids))
                .group_by(Finding.severity)
            )
        ).all()
        severity_rows = [(enum_val(sev), cnt or 0, total or 0) for sev, cnt, total in raw_severity_rows]

        raw_rule_rows = (
            await db.execute(
                select(Finding.rule_name, Finding.severity, func.sum(Finding.count).label("events"))
                .join(TaskResult, Finding.task_result_id == TaskResult.id)
                .where(TaskResult.job_id.in_(job_ids))
                .group_by(Finding.rule_name, Finding.severity)
            )
        ).all()
        rule_rows = sorted(
            ((rule_name, enum_val(sev), events or 0) for rule_name, sev, events in raw_rule_rows),
            key=lambda r: (SEVERITY_RANK.get(r[1], len(SEVERITY_RANK)), -r[2], r[0]),
        )[:10]

        tag_rows = (await db.execute(select(Finding.tags, Finding.count).join(TaskResult, Finding.task_result_id == TaskResult.id).where(TaskResult.job_id.in_(job_ids)))).all()
        tactic_counts = _tactic_counts_from_tag_rows(tag_rows)

    rollup = build_findings_rollup(severity_rows, rule_rows, tactic_counts)

    return templates.TemplateResponse(
        request,
        "intel/partials/_case_summary.html",
        {"request": request, "case": case, "rollup": rollup},
    )


@router.get("/{case_id}/timeline-partial", response_class=HTMLResponse)
async def case_timeline_partial(
    request: Request,
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    job_id: int = 0,
    severity: str = "",
    entity_id: int = 0,
):
    """Case attack-timeline tab: a merged MITRE-stacked histogram (from each job's raw tool
    output, Redis-cached per job) plus a durable chronological key-events list from
    `Finding.details` in the DB (the latter survives raw-output retention cleanup).

    Visibility discipline: member jobs are filtered through `can_view_job` **before** any
    bucket merge or key-events query — a private job another member linked into a shared case
    never contributes its histogram buckets *or* its findings' events to a non-owner viewer.
    404s use one message per resource ("Job not found" / "Entity not found") so a filter
    value cannot become an existence oracle.
    """
    case = await _load_case_or_404(db, case_id, user)

    # Visibility in SQL, matching case_summary_partial. Filtering in Python afterwards would
    # scale with other people's data: this query eager-loads task_results *and* their
    # findings, so every private job's findings tree would be materialised and thrown away —
    # on a shared case, the bulk of the work on the slowest page in the application.
    jobs_stmt = (
        select(AnalysisJob)
        .join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id)
        .where(CaseJobLink.case_id == case_id)
        .options(
            selectinload(AnalysisJob.log_file),
            selectinload(AnalysisJob.task_results).selectinload(TaskResult.findings),
        )
    )
    vis = visible_job_filter(user)
    if vis is not True:
        jobs_stmt = jobs_stmt.where(vis)
    member_jobs = (await db.execute(jobs_stmt)).scalars().all()
    member_job_ids = {j.id for j in member_jobs}

    # Optional job filter (applies to BOTH histogram and key events). A job_id not among the
    # visible member ids is indistinguishable from "does not exist": one 404 message.
    if job_id and job_id not in member_job_ids:
        raise HTTPException(404, "Job not found")
    filtered_jobs = [j for j in member_jobs if not job_id or j.id == job_id]
    filtered_job_ids = [j.id for j in filtered_jobs]

    # Severity normalization (never 404s — an invalid value is just ignored) and the
    # entity-membership 404 both run BEFORE any per-job index building or histogram/
    # threadpool work below, so an invalid request never pays for the full raw-output
    # parse just to be rejected.
    sev_filter = severity.strip().lower() if severity else ""
    sev_enum = Severity(sev_filter) if sev_filter in _VALID_SEVERITIES else None

    if entity_id:
        # Entity must be linked to THIS case (else 404 "Entity not found" — one message).
        linked = await db.scalar(select(CaseEntityLink.id).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity_id))
        if not linked:
            raise HTTPException(404, "Entity not found")

    # Per-job rule→tactic / technique→tactic maps via the same resolver the job analytics
    # use. Built here off already-loaded ORM collections, then handed to the threadpool as
    # plain dicts (the threadpool must never touch ORM objects).
    rt_by_job: dict[int, dict[str, str]] = {}
    tt_by_job: dict[int, dict[str, str]] = {}
    for job in filtered_jobs:
        rt, tt, _counts = _build_findings_index(job)
        rt_by_job[job.id] = rt
        tt_by_job[job.id] = tt

    # Only terminal jobs get their buckets cached. A job still running has no raw output
    # yet, so caching its empty result would freeze an empty histogram and a false "raw
    # outputs were cleaned up" notice for the full 15-minute TTL — long after the job
    # finished and the data existed.
    terminal_job_ids = {j.id for j in filtered_jobs if enum_val(j.status) in TERMINAL_JOB_STATUSES}

    def _build_histogram() -> tuple[dict[str, dict[str, int]], int]:
        from app.json_utils import dumps as json_dumps
        from app.redis_client import TIMELINE_BUCKETS_PREFIX

        bucket_dicts: list[dict[str, dict[str, int]]] = []
        covered = 0
        for jid in filtered_job_ids:
            cache_key = f"{TIMELINE_BUCKETS_PREFIX}{jid}"
            cacheable = jid in terminal_job_ids
            buckets: dict | None = None
            has_raw: bool | None = None
            try:
                from app.redis_client import get_redis

                cached = get_redis().get(cache_key) if cacheable else None
                if cached:
                    data = json_loads(cached)
                    if isinstance(data, dict):
                        b = data.get("buckets")
                        buckets = b if isinstance(b, dict) else {}
                        has_raw = bool(data.get("has_raw"))
            except Exception:
                buckets, has_raw = None, None
            if buckets is None or has_raw is None:
                # Cache the has_raw flag *separately* from the buckets: a job can have raw
                # outputs on disk yet produce zero timestamped buckets — without the flag a
                # legitimately-empty job would be misreported as "cleaned up".
                # Same storage detour as the process tree: on S3 the tree is not on this
                # machine's disk, so reading `upload_dir` directly reports every job as
                # "raw output cleaned up" and the coverage notice quietly under-counts.
                from app.storage import job_outputs_dir

                with job_outputs_dir(jid) as job_dir:
                    has_raw = has_raw_output(jid, job_dir)
                    buckets, _events = extract_all_from_raw_output(jid, rt_by_job.get(jid, {}), tt_by_job.get(jid, {}), job_dir=job_dir)
                if cacheable:
                    try:
                        from app.redis_client import get_redis

                        get_redis().set(
                            cache_key,
                            json_dumps({"buckets": buckets, "has_raw": has_raw}),
                            ex=_TIMELINE_BUCKETS_CACHE_TTL,
                        )
                    except Exception:
                        pass
            if has_raw:
                covered += 1
            bucket_dicts.append(buckets)
        return merge_buckets(bucket_dicts), covered

    merged_buckets, histogram_jobs_covered = await run_in_threadpool(_build_histogram)
    timeline, timeline_tactics = format_timeline(merged_buckets)

    # ── Key events (DB-only, durable) ─────────────────────────────────────────────
    # (severity normalization + the entity-membership 404 already ran above, before the
    # histogram build.)
    raw_findings: list[tuple] = []
    if filtered_job_ids:
        # Columns, not entities. Only four fields are read, and this walks every finding of
        # every job on the case — hydrating ORM instances (and holding them in the identity
        # map) for all of them would be the largest allocation on the slowest page in the app.
        #
        # Deliberately **not** capped in SQL: `build_key_events` sorts chronologically
        # across the whole set before taking its 200, and reports the true total beside
        # them. A LIMIT here would silently change *which* events appear and make "Showing
        # 200 of N" a lie. The cost is real and is documented in `docs/limitations.md`; the
        # fix is a cache, not a cap.
        #
        # `Finding.details` is deferred at the mapper, which does not apply to a column
        # select — that is only a concern when loading the entity.
        kev_stmt = (
            select(Finding.rule_name, Finding.severity, Finding.id, Finding.details, TaskResult.job_id)
            .join(TaskResult, Finding.task_result_id == TaskResult.id)
            .where(TaskResult.job_id.in_(filtered_job_ids))
        )
        if sev_enum is not None:
            kev_stmt = kev_stmt.where(Finding.severity == sev_enum)
        if entity_id:
            kev_stmt = kev_stmt.where(Finding.id.in_(select(FindingEntityLink.finding_id).where(FindingEntityLink.entity_id == entity_id)))
        for rule_name, finding_severity, finding_id, details, jid in (await db.execute(kev_stmt)).all():
            # Resolve the finding's tactic via the same rule→tactic map the histogram uses
            # (first-seen-wins per rule, exactly like the job analytics) — no parallel logic.
            tactic = rt_by_job.get(jid, {}).get(rule_name, _OTHER_TACTIC)
            raw_findings.append((rule_name, enum_val(finding_severity), tactic, jid, finding_id, details))

    def _build_key_events() -> tuple[list[dict], int]:
        plain: list[dict] = []
        for rule_name, sev, tactic, jid, fid, details_str in raw_findings:
            try:
                events = json_loads(details_str) if details_str else []
            except (ValueError, TypeError):
                events = []
            if not isinstance(events, list):
                events = []
            plain.append({"rule_name": rule_name, "severity": sev, "tactic": tactic, "job_id": jid, "finding_id": fid, "events": events})
        return build_key_events(plain, cap=200)

    key_events, key_events_total = await run_in_threadpool(_build_key_events)

    # The entity filter is a search box backed by `/{case_id}/entities.json`, not a
    # <select>: a real case can carry a four-figure entity count, and rendering every one
    # into an option list would make the control unusable (and bloat every timeline refresh).
    # We only need "are there any?" plus the label of the current selection.
    member_entities_total = await db.scalar(select(func.count(CaseEntityLink.id)).where(CaseEntityLink.case_id == case_id)) or 0
    sel_entity_value = ""
    if entity_id:
        sel_entity_value = await db.scalar(select(Entity.value).where(Entity.id == entity_id)) or ""

    return templates.TemplateResponse(
        request,
        "intel/partials/_case_timeline.html",
        {
            "request": request,
            "case": case,
            # Gates the events timeline (show_alert_timeline) and picks its renderer.
            "site_settings": await get_site_settings(db),
            "timeline": timeline,
            "timeline_tactics": timeline_tactics,
            "key_events": key_events,
            "key_events_total": key_events_total,
            "key_events_shown": len(key_events),
            "histogram_jobs_covered": histogram_jobs_covered,
            "histogram_jobs_total": len(filtered_jobs),
            "tactic_colors": _TACTIC_COLORS,
            "tactic_labels": TACTIC_LABELS,
            "member_jobs": member_jobs,
            "member_entities_total": member_entities_total,
            "severities": SEVERITY_ORDER,
            "sel_job_id": job_id,
            "sel_severity": sev_filter if sev_enum is not None else "",
            "sel_entity_id": entity_id,
            "sel_entity_value": sel_entity_value,
        },
    )


@router.get("/{case_id}/events-timeline")
async def case_events_timeline(
    case_id: int,
    frm: int | None = None,
    to: int | None = None,
    resolution: int | None = None,
    job_id: int = 0,
    severity: str = "",
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Merged range query across the case's visible jobs, for the zoomable events timeline.

    Same visibility discipline as `case_timeline_partial`: jobs are filtered through
    `can_view_job` **before** any index is read, so a private job another member linked into
    a shared case never contributes a marker to a non-owner viewer. A `job_id` outside the
    visible member set 404s with the same message an unknown one gets, so the filter cannot
    become an existence oracle.
    """
    from app.routers.jobs import _events_timeline_payload

    await _load_case_or_404(db, case_id, user)

    # Filtered in SQL, like the other case queries here. `visible_job_filter` is the
    # query-layer mirror of `can_view_job`, so the rule is identical — without hydrating
    # every linked job just to discard most of them in Python.
    visible_ids = list(
        (await db.execute(select(AnalysisJob.id).join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id).where(CaseJobLink.case_id == case_id, visible_job_filter(user))))
        .scalars()
        .all()
    )
    if job_id:
        if job_id not in visible_ids:
            raise HTTPException(404, "Job not found")
        visible_ids = [job_id]

    rows: list[tuple[int, bytes | None]] = []
    if visible_ids:
        # One round trip for every member index, not N+1. The column is deferred, so it has
        # to be named explicitly — which is also what keeps the blobs off the `jobs` query
        # above, where they would be pure waste.
        rows = list((await db.execute(select(AnalysisJob.id, AnalysisJob.event_markers).where(AnalysisJob.id.in_(visible_ids)))).all())

    # Every member job's index is gunzipped and sliced here. On a case with many jobs that
    # is the longest pure-CPU stretch in the web tier, so it runs off the event loop.
    return JSONResponse(await run_in_threadpool(_events_timeline_payload, rows, frm, to, resolution, severity))


@router.get("/{case_id}/graph-active.json")
async def case_graph_active(
    case_id: int,
    frm: int | None = None,
    to: int | None = None,
    job_id: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Which entities a rule fired for inside `[frm, to]` (epoch **milliseconds**).

    This is the graph's time link, and it is deliberately case-only: an entity graph's job
    set is unbounded, so a brush there would re-derive a whole traversal per tick, whereas a
    case's job set is one indexed `CaseJobLink` query.

    **Say what this actually resolves to.** `link_findings_to_entities_for_job` links an
    entity to a *Finding*, and a Finding aggregates every matched event for one rule inside
    one TaskResult. So the chain answers *"a rule this entity is linked to fired in this
    window"*, not *"this entity appeared in this window"*. The UI says exactly that; it is
    not buried here.

    Two empty states that are **not** "nothing was active", reported separately because
    they need different responses from the analyst:

    * `jobs_without_index` — the job has no marker index at all (analytics predate it, or
      the blob was never written). Re-run analytics.
    * `jobs_without_finding_ids` — the index exists but its `keys` rows are the older 6-wide
      shape, with no `finding_id` column. Nothing resolves, and no amount of
      brushing will change that until a backfill runs.

    Visibility: every `CaseJobLink` job goes through `can_view_job` **before** any
    `event_markers` blob is read — the index carries rule names, computers, tools and event
    timestamps. The finding→entity lookup is filtered again on the same visible set, as
    belt-and-braces against a stale index pointing at a re-parented finding.
    """
    from app.intel.event_markers import active_finding_ids, unpack_index

    await _load_case_or_404(db, case_id, user)

    # Filtered in SQL, like the other case queries here. `visible_job_filter` is the
    # query-layer mirror of `can_view_job`, so the rule is identical — without hydrating
    # every linked job just to discard most of them in Python.
    visible_ids = list(
        (await db.execute(select(AnalysisJob.id).join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id).where(CaseJobLink.case_id == case_id, visible_job_filter(user))))
        .scalars()
        .all()
    )
    if job_id:
        if job_id not in visible_ids:
            raise HTTPException(404, "Job not found")
        visible_ids = [job_id]

    if not visible_ids:
        return JSONResponse({"entity_ids": [], "jobs": 0, "jobs_without_index": 0, "jobs_without_finding_ids": 0, "index_missing": True})

    # `AnalysisJob.event_markers` is `deferred()`. Reading it off an ORM instance raises
    # MissingGreenlet on a detached object under async SQLAlchemy — and this route iterates
    # ORM jobs — so it is selected as an explicit column, in one round trip.
    rows = list((await db.execute(select(AnalysisJob.id, AnalysisJob.event_markers).where(AnalysisJob.id.in_(visible_ids)))).all())

    frm_s = frm // 1000 if frm is not None else None
    to_s = -(-to // 1000) if to is not None else None

    def _scan() -> tuple[set[int], int, int]:
        """One gunzip + scan per member job — CPU, so off the event loop."""
        ids_out: set[int] = set()
        no_index = 0
        no_finding_ids = 0
        for _jid, blob in rows:
            payload = unpack_index(blob)
            if payload is None:
                no_index += 1
                continue
            ids = active_finding_ids(payload, frm_s, to_s)
            keys = payload.get("keys") or []
            if not ids and keys and all(len(row) < 7 for row in keys):
                no_finding_ids += 1
                continue
            ids_out |= ids
        return ids_out, no_index, no_finding_ids

    finding_ids, without_index, without_finding_ids = await run_in_threadpool(_scan)

    entity_ids: list[int] = []
    if finding_ids:
        stmt = (
            select(FindingEntityLink.entity_id)
            .join(Finding, FindingEntityLink.finding_id == Finding.id)
            .join(TaskResult, Finding.task_result_id == TaskResult.id)
            .where(FindingEntityLink.finding_id.in_(finding_ids), TaskResult.job_id.in_(visible_ids))
            .distinct()
        )
        entity_ids = [int(r[0]) for r in (await db.execute(stmt)).all()]

    # No server-side intersection with the graph's node set: the client already holds it,
    # and re-deriving the graph here would double the cost of every brush tick. The
    # intersection is a display concern, not a security control — the visibility filters
    # above are the control.
    return JSONResponse(
        {
            "entity_ids": entity_ids,
            "jobs": len(rows),
            "jobs_without_index": without_index,
            "jobs_without_finding_ids": without_finding_ids,
            "index_missing": without_index == len(rows),
        }
    )


async def _build_case_pivots(db: AsyncSession, case_id: int, user: User) -> dict:
    """Compute the three Overview-tab pivot-suggestion sections: entities, similar files,
    and correlated findings that touch this case's *visible* jobs but aren't yet case
    members.

    Re-run from scratch on every call (the `GET .../pivots-partial` endpoint and the
    `pivot=1` HTMX branch of `case_add_entity` / `case_add_job` both call this directly) —
    no caching, so a just-added row never lingers in the response.

    Privacy discipline: `all_case_job_ids` (used only to exclude already-linked jobs from
    the similarity/correlation suggestions) intentionally includes jobs the viewer cannot
    see too — an existing member must never be re-suggested regardless of visibility.
    `visible_job_ids`, by contrast, is filtered through `can_view_job` **before** it is used
    as a *source* for any suggestion query below — a private job another member linked into
    a shared case must never contribute co-occurring entities, TLSH neighbors, or
    correlated rule hits to a non-owner viewer, mirroring `case_summary_partial` /
    `case_timeline_partial`.
    """
    all_case_job_ids = set((await db.execute(select(CaseJobLink.job_id).where(CaseJobLink.case_id == case_id))).scalars().all())
    case_entity_ids = set((await db.execute(select(CaseEntityLink.entity_id).where(CaseEntityLink.case_id == case_id))).scalars().all())

    # Visibility in SQL — same rule, same shape as case_summary_partial and the timeline.
    pivot_stmt = select(AnalysisJob).join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id).where(CaseJobLink.case_id == case_id).options(selectinload(AnalysisJob.log_file))
    pivot_vis = visible_job_filter(user)
    if pivot_vis is not True:
        pivot_stmt = pivot_stmt.where(pivot_vis)
    visible_jobs = (await db.execute(pivot_stmt)).scalars().all()
    visible_job_ids = [j.id for j in visible_jobs]

    # ── 1. Co-occurring entities ────────────────────────────────────────────────
    entity_rows: list[dict] = []
    if visible_job_ids:
        ent_stmt = (
            select(Entity, func.sum(EntityJobLink.occurrence_count))
            .join(EntityJobLink, EntityJobLink.entity_id == Entity.id)
            .where(EntityJobLink.job_id.in_(visible_job_ids))
            .where(Entity.allowlisted.is_(False))
        )
        if case_entity_ids:
            ent_stmt = ent_stmt.where(Entity.id.not_in(case_entity_ids))
        ent_stmt = ent_stmt.group_by(Entity.id).order_by(func.sum(EntityJobLink.occurrence_count).desc()).limit(_PIVOT_ENTITY_LIMIT)
        entity_rows = [{"entity": entity, "count": total or 0} for entity, total in (await db.execute(ent_stmt)).all()]

    # ── 2. Similar files ─────────────────────────────────────────────────────────
    from app.similarity.hasher import find_similar_files_async

    similar_candidates = []
    # Filter to hash-bearing jobs FIRST, then take the most recent — not the reverse.
    # compute_tlsh() is best-effort (returns None for small/low-entropy files), so the
    # case's 10 newest jobs might all lack a hash while an older job has one; slicing
    # by recency before filtering would silently starve this section in that case.
    hash_bearing_jobs = [j for j in visible_jobs if j.log_file and j.log_file.tlsh_hash]
    source_jobs = sorted(hash_bearing_jobs, key=lambda j: j.created_at or datetime.min, reverse=True)[:_PIVOT_SIMILAR_SOURCE_JOBS]
    for job in source_jobs:
        neighbors = await find_similar_files_async(db, job.log_file.tlsh_hash, exclude_file_id=job.file_id, viewer=user)
        similar_candidates.extend((job.id, sf) for sf in neighbors)
    similar_rows = build_similar_pivot_rows(similar_candidates, all_case_job_ids, cap=_PIVOT_SIMILAR_LIMIT)

    # ── 3. Correlated findings ───────────────────────────────────────────────────
    from app.similarity.correlator import find_correlated_findings_async

    correlated_rows_by_job: dict[int, dict] = {}
    if visible_job_ids:
        sig_rows = (
            await db.execute(
                select(Finding.rule_signature, Finding.severity, TaskResult.job_id)
                .join(TaskResult, Finding.task_result_id == TaskResult.id)
                .where(TaskResult.job_id.in_(visible_job_ids))
                .where(Finding.rule_signature.isnot(None))
            )
        ).all()
        # Rank distinct signatures worst-severity-first (using the severity from the
        # Finding rows themselves, not re-parsed from the signature string), capped to
        # bound how many `find_correlated_findings_async` calls follow.
        sig_best_severity: dict[str, str] = {}
        sig_source_job: dict[str, int] = {}
        for sig, sev, jid in sig_rows:
            sev_str = enum_val(sev)
            # rule_signature already embeds severity ("{id_or_slug}:{severity}"), so every
            # Finding row sharing a signature should carry the same severity and this
            # "worse severity replaces" comparison should never actually trigger — it's
            # defensive only, in case that invariant is ever violated upstream.
            if sig not in sig_best_severity or SEVERITY_RANK.get(sev_str, len(SEVERITY_RANK)) < SEVERITY_RANK.get(sig_best_severity[sig], len(SEVERITY_RANK)):
                sig_best_severity[sig] = sev_str
                sig_source_job[sig] = jid
        ranked_sigs = sorted(sig_best_severity, key=lambda s: SEVERITY_RANK.get(sig_best_severity[s], len(SEVERITY_RANK)))[:_PIVOT_CORRELATED_SIGNATURE_CAP]

        for sig in ranked_sigs:
            # Bound total helper calls: stop once the row cap is already met.
            if len(correlated_rows_by_job) >= _PIVOT_CORRELATED_LIMIT:
                break
            hits = await find_correlated_findings_async(db, sig, exclude_job_id=sig_source_job[sig], viewer=user)
            for hit in hits:
                if hit.job_id in all_case_job_ids:
                    continue
                merge_correlated_hit(correlated_rows_by_job, hit.job_id, hit.original_filename, hit.severity, sig)

    correlated_rows = rank_correlated_pivot_rows(correlated_rows_by_job, cap=_PIVOT_CORRELATED_LIMIT)

    return {"entity_rows": entity_rows, "similar_rows": similar_rows, "correlated_rows": correlated_rows}


@router.get("/{case_id}/pivots-partial", response_class=HTMLResponse)
async def case_pivots_partial(
    request: Request,
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Overview tab lazy region: co-occurring entities, similar files, and correlated
    findings from the case's visible jobs that aren't yet case members, each with a
    one-click Add (see `case_add_entity` / `case_add_job`'s `pivot=1` branch)."""
    await _load_case_or_404(db, case_id, user)  # authz side-effect
    ctx = await _build_case_pivots(db, case_id, user)
    return templates.TemplateResponse(request, "intel/partials/_case_pivots.html", {"request": request, "case_id": case_id, **ctx})


@router.post("/{case_id}/notes", response_class=HTMLResponse)
async def case_notes_save(
    request: Request,
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    body: str = Form(""),
):
    """Save (or clear, when empty) the case's running investigation narrative. Owner-only."""
    case = await _load_case_or_404(db, case_id, user)
    if not _is_owner(case, user):
        raise HTTPException(403, "Only the case owner can edit case notes")
    case.notes = _clean_note(body, _NOTES_MAX)
    await db.commit()
    return templates.TemplateResponse(
        request,
        "intel/partials/_case_notes.html",
        {"request": request, "case": case, "is_owner": True, "site_settings": await get_site_settings(db)},
    )


@router.post("/{case_id}/entities", response_class=HTMLResponse)
async def case_add_entity(
    request: Request,
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    entity_id: int = Form(...),
    note: str = Form(""),
    pivot: int = Form(0),
):
    """Link an entity to the case. When `pivot=1` AND the request is HTMX (the pivot
    suggestions panel's one-click Add form), respond with the freshly re-rendered pivots
    partial instead of the normal 303 redirect — see `_build_case_pivots`.
    """
    await _load_case_or_404(db, case_id, user)  # authz side-effect
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")
    clean_note = _clean_note(note, _LINK_NOTE_MAX)
    # Capture before a possible rollback below (mirrors case_add_job): rollback() expires
    # every ORM object in the session's identity map (including `user`), so touching an
    # attribute like user.id afterwards would trigger an implicit sync refresh and crash
    # with MissingGreenlet under the async engine. Plain ints/db.get() re-fetches don't.
    user_id = user.id
    try:
        db.add(CaseEntityLink(case_id=case_id, entity_id=entity_id, added_by_user_id=user_id, note=clean_note))
        await db.commit()
    except IntegrityError:
        # Already linked. That is not an error — and the note that came with this request is
        # the one thing the caller can still usefully contribute, so it lands. A blank note is
        # left alone; see `_note_update_targets`.
        await db.rollback()
        if clean_note:
            await db.execute(update(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity_id).values(note=clean_note))
            await db.commit()
    if pivot and request.headers.get("hx-request"):
        fresh_user = await db.get(User, user_id)
        ctx = await _build_case_pivots(db, case_id, fresh_user)
        return templates.TemplateResponse(request, "intel/partials/_case_pivots.html", {"request": request, "case_id": case_id, **ctx})
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/entities/bulk")
async def case_add_entities_bulk(
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    entity_ids: list[int] = Form([]),
    note: str = Form(""),
):
    """Link several entities at once (the multi-select picker on the case Entities tab)."""
    await _load_case_or_404(db, case_id, user)  # authz side-effect
    if len(entity_ids) > _BULK_LINK_CAP:
        raise HTTPException(400, f"Too many selections (max {_BULK_LINK_CAP})")
    known = set((await db.execute(select(Entity.id).where(Entity.id.in_(entity_ids)))).scalars().all()) if entity_ids else set()
    if any(eid not in known for eid in entity_ids):
        raise HTTPException(404, "Entity not found")
    await _link_entities(db, case_id, entity_ids, user.id, _clean_note(note, _LINK_NOTE_MAX))
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/jobs/bulk")
async def case_add_jobs_bulk(
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    job_ids: list[int] = Form([]),
    include_entities: int = Form(1),
    note: str = Form(""),
):
    """Link several jobs at once, pulling in each job's entities by default.

    Unlike the single-job route (whose `include_entities=0` default is a form contract
    callers rely on), this defaults to on — importing a job's observables is what you
    almost always want when adding it to a case.
    """
    await _load_case_or_404(db, case_id, user)  # authz side-effect
    if len(job_ids) > _BULK_LINK_CAP:
        raise HTTPException(400, f"Too many selections (max {_BULK_LINK_CAP})")
    user_id = user.id
    linked = await _link_jobs(db, case_id, job_ids, user_id, _clean_note(note, _LINK_NOTE_MAX), viewer=user)
    if include_entities:
        for job_id in linked:
            await _bulk_add_job_entities(db, case_id, job_id, user_id)
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/entities/{entity_id}/note", response_class=HTMLResponse)
async def case_entity_note_save(
    request: Request,
    case_id: int,
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    note: str = Form(""),
):
    """Edit the per-link "why is this here" note on a case/entity pairing. Adder-or-owner only."""
    case = await _load_case_or_404(db, case_id, user)
    link = (
        await db.execute(
            select(CaseEntityLink)
            .where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity_id)
            .options(selectinload(CaseEntityLink.entity), selectinload(CaseEntityLink.added_by))
        )
    ).scalar_one_or_none()
    if not link:
        raise HTTPException(404, "Entity not linked to this case")
    if not _can_edit_link_note(case, link, user):
        raise HTTPException(403, "Only the link's adder or the case owner can edit this note")
    link.note = _clean_note(note, _LINK_NOTE_MAX)
    await db.commit()
    return templates.TemplateResponse(
        request,
        "intel/partials/_case_entity_row.html",
        {
            "request": request,
            "case": case,
            "el": link,
            "user": user,
            "is_owner": _is_owner(case, user),
            # This route re-renders one row standalone; without the tags the chips would
            # vanish from that row the moment someone edited its note.
            "tags_by_entity": await _fetch_entity_tags(db, [entity_id]),
        },
    )


@router.post("/{case_id}/jobs", response_class=HTMLResponse)
async def case_add_job(
    request: Request,
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    job_id: int = Form(...),
    include_entities: int = Form(0),
    note: str = Form(""),
    pivot: int = Form(0),
):
    """Link a job to the case. When `pivot=1` AND the request is HTMX (the pivot
    suggestions panel's one-click Add form), respond with the freshly re-rendered pivots
    partial instead of the normal 303 redirect — see `_build_case_pivots`.
    """
    await _load_case_or_404(db, case_id, user)  # authz side-effect
    job = await db.get(AnalysisJob, job_id)
    # Treat a private job the adder can't see as non-existent so it cannot be
    # pulled into a (possibly shared) case and leaked to other members.
    if not job or not can_view_job(job, user):
        raise HTTPException(404, "Job not found")
    clean_note = _clean_note(note, _LINK_NOTE_MAX)
    # Capture before a possible rollback below: rollback() expires every ORM object
    # in the session's identity map (including `user`, fetched via the same session
    # by current_member_or_above), so touching user.id afterwards would trigger an
    # implicit sync refresh and crash with MissingGreenlet under the async engine.
    user_id = user.id
    try:
        db.add(CaseJobLink(case_id=case_id, job_id=job_id, added_by_user_id=user_id, note=clean_note))
        await db.commit()
    except IntegrityError:
        # Already linked — use the plain ints (case_id/job_id/user_id) captured
        # above from here on, not case.id/job.id/user.id. The note still lands: it is the
        # only part of a duplicate add that carries new information.
        await db.rollback()
        if clean_note:
            await db.execute(update(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job_id).values(note=clean_note))
            await db.commit()
    if include_entities:
        await _bulk_add_job_entities(db, case_id, job_id, user_id)
    if pivot and request.headers.get("hx-request"):
        fresh_user = await db.get(User, user_id)
        ctx = await _build_case_pivots(db, case_id, fresh_user)
        return templates.TemplateResponse(request, "intel/partials/_case_pivots.html", {"request": request, "case_id": case_id, **ctx})
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/jobs/{job_id}/note", response_class=HTMLResponse)
async def case_job_note_save(
    request: Request,
    case_id: int,
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    note: str = Form(""),
):
    """Edit the per-link "why is this here" note on a case/job pairing. Adder-or-owner only."""
    case = await _load_case_or_404(db, case_id, user)
    link = (
        await db.execute(
            select(CaseJobLink)
            .where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job_id)
            .options(selectinload(CaseJobLink.job).selectinload(AnalysisJob.log_file), selectinload(CaseJobLink.added_by))
        )
    ).scalar_one_or_none()
    # Both "no such link" and "link exists but the job is private and the requester
    # can't view it" return the identical 404 below — mirrors case_add_job's
    # treatment. A distinct message for the second case would be an existence oracle
    # (any case member could learn a given job_id IS linked to the case, and is
    # private, just from which 404 text comes back). The adder can always view their
    # own job, so this only ever blocks a *different* case member (typically the
    # owner) from confirming/editing a note on a link to a job they cannot see.
    if not link or not can_view_job(link.job, user):
        raise HTTPException(404, "Job not found")
    if not _can_edit_link_note(case, link, user):
        raise HTTPException(403, "Only the link's adder or the case owner can edit this note")
    link.note = _clean_note(note, _LINK_NOTE_MAX)
    await db.commit()
    return templates.TemplateResponse(
        request,
        "intel/partials/_case_job_row.html",
        {"request": request, "case": case, "jl": link, "user": user, "is_owner": _is_owner(case, user)},
    )


@router.post("/{case_id}/jobs/{job_id}/add-entities")
async def case_add_job_entities(
    case_id: int,
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Bulk-link all of a member job's entities to the case (per-job-row button).

    Visibility gate mirrors case_job_note_save: "no such link" and "link exists but
    the job is private and invisible to this requester" return the identical 404 —
    a distinct message for the second case would be an existence oracle, letting any
    case member learn that a given job_id is (privately) linked to the case just
    from which 404 text comes back. Without this gate a member could bulk-import the
    entity roster of a private job they cannot otherwise see at all.
    """
    await _load_case_or_404(db, case_id, user)  # authz side-effect
    link = (await db.execute(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job_id).options(selectinload(CaseJobLink.job)))).scalar_one_or_none()
    if not link or not can_view_job(link.job, user):
        raise HTTPException(404, "Job not found")
    await _bulk_add_job_entities(db, case_id, job_id, user.id)
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/edit")
async def case_edit(
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    name: str = Form(...),
    summary: str = Form(""),
    severity: str = Form(""),
):
    """Owner-only edit of name/summary/severity."""
    case = await _load_case_or_404(db, case_id, user)
    if not _is_owner(case, user):
        raise HTTPException(403, "Only the case owner can edit the case")
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Name is required")
    if len(name) > _NAME_MAX:
        raise HTTPException(400, f"Name too long (max {_NAME_MAX} chars)")
    if len(summary) > _SUMMARY_MAX:
        raise HTTPException(400, f"Summary too long (max {_SUMMARY_MAX} chars)")
    sev = severity.strip().lower() if severity else None
    if sev and sev not in _VALID_SEVERITIES:
        sev = None
    case.name = name
    case.summary = summary or None
    case.severity = sev
    await db.commit()
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/entities/{entity_id}/remove")
async def case_remove_entity(
    case_id: int,
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    case = await _load_case_or_404(db, case_id, user)
    if not _is_owner(case, user):
        raise HTTPException(403, "Only the case owner can remove members")
    link = (await db.execute(select(CaseEntityLink).where(CaseEntityLink.case_id == case_id, CaseEntityLink.entity_id == entity_id))).scalar_one_or_none()
    if link:
        await db.delete(link)
        await db.commit()
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/jobs/{job_id}/remove")
async def case_remove_job(
    case_id: int,
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    case = await _load_case_or_404(db, case_id, user)
    if not _is_owner(case, user):
        raise HTTPException(403, "Only the case owner can remove members")
    link = (await db.execute(select(CaseJobLink).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job_id))).scalar_one_or_none()
    if link:
        await db.delete(link)
        await db.commit()
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/status")
async def case_status_update(
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    status: str = Form(...),
    is_shared: int = Form(0),
):
    case = await _load_case_or_404(db, case_id, user)
    if not _is_owner(case, user):
        raise HTTPException(403, "Only the case owner can change status")
    status = (status or "").strip().lower()
    if status not in _VALID_STATUSES:
        raise HTTPException(400, "Invalid status")
    case.status = status
    case.is_shared = bool(is_shared)
    case.closed_at = utc_now_naive() if status == "closed" else None
    await db.commit()
    return RedirectResponse(f"/intel/cases/{case_id}", status_code=303)


@router.post("/{case_id}/delete")
async def case_delete(
    case_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    case = await _load_case_or_404(db, case_id, user)
    if not _is_owner(case, user):
        raise HTTPException(403, "Only the case owner can delete the case")
    case_name = case.name
    await db.delete(case)
    await db.commit()
    # Deletion cascades to every entity and job link, so this is the one case action
    # that destroys an analyst's grouping rather than editing it.
    await activity.record("intel.case.delete", request=request, user=user, target_type="case", target_id=str(case_id), summary=case_name)
    return RedirectResponse("/intel/cases", status_code=303)


async def _entity_severity_map(db: AsyncSession, entity_ids: list[int], user: User) -> dict[int, str]:
    """Worst finding severity per entity, across jobs *user* may see.

    The `severity_by_entity` map `build_misp_event` and `build_case_ioc_pack` accept. Without
    it every MISP export ships `threat_level_id: "4"` (undefined) and every IOC pack row a
    blank severity — the two fields a downstream MISP instance actually triages on.
    """
    if not entity_ids:
        return {}
    rank = severity_rank_sql()
    stmt = (
        select(FindingEntityLink.entity_id, func.min(rank))
        .join(Finding, FindingEntityLink.finding_id == Finding.id)
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .join(AnalysisJob, TaskResult.job_id == AnalysisJob.id)
        .where(FindingEntityLink.entity_id.in_(entity_ids))
        .group_by(FindingEntityLink.entity_id)
    )
    vis = visible_job_filter(user)
    if vis is not True:
        stmt = stmt.where(vis)
    rows = (await db.execute(stmt)).all()
    return {int(eid): SEVERITY_ORDER[int(r)] for eid, r in rows if r is not None and 0 <= int(r) < len(SEVERITY_ORDER)}


async def _load_case_export_context(db: AsyncSession, case_id: int, user: User) -> tuple[list, dict[int, list]]:
    """Case member entities plus their per-job links, scoped to jobs *user* may see.

    Shared by the STIX and MISP exports. The `visible_job_filter` is the point: a private job
    another member linked into a shared case must not contribute sightings — which carry a
    job id and a timestamp — to a non-owner's export. That is the same rule
    `case_summary_partial` already applies to findings.

    Bounded by `_CASE_LINK_CAP`: both exports build a document from the member entities
    in-request, over a Bearer-token-reachable route. Ordered by link id so the cap is
    deterministic.
    """
    entity_links = (
        (
            await db.execute(
                select(CaseEntityLink).where(CaseEntityLink.case_id == case_id).options(selectinload(CaseEntityLink.entity)).order_by(CaseEntityLink.id).limit(_CASE_LINK_CAP)
            )
        )
        .scalars()
        .all()
    )
    entities = [el.entity for el in entity_links if el.entity is not None]

    job_stmt = select(CaseJobLink.job_id).join(AnalysisJob, CaseJobLink.job_id == AnalysisJob.id).where(CaseJobLink.case_id == case_id)
    vis = visible_job_filter(user)
    if vis is not True:
        job_stmt = job_stmt.where(vis)
    case_job_ids = [row[0] for row in (await db.execute(job_stmt)).all()]

    job_links_by_entity: dict[int, list] = {}
    if entities and case_job_ids:
        rows = (
            (
                await db.execute(
                    select(EntityJobLink)
                    .where(EntityJobLink.entity_id.in_([e.id for e in entities]), EntityJobLink.job_id.in_(case_job_ids))
                    .options(selectinload(EntityJobLink.job))
                )
            )
            .scalars()
            .all()
        )
        for jl in rows:
            job_links_by_entity.setdefault(jl.entity_id, []).append(jl)
    return entities, job_links_by_entity


@router.get("/{case_id}/stix")
async def case_stix_export(
    case_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    _principal=Depends(current_user_or_api_token("case:read")),
):
    """Export this case as a STIX 2.1 bundle (indicators + sightings).

    Cookie auth (member-or-above) OR a Bearer token with `case:read`.
    """
    user = await _principal_user(db, _principal)
    case = await _load_case_or_404(db, case_id, user)
    await activity.record(
        "export.stix", request=request, user=user, actor_label=principal_actor_label(_principal, user), target_type="case", target_id=str(case_id), summary=case.name
    )
    entities, job_links_by_entity = await _load_case_export_context(db, case_id, user)

    bundle = build_case_stix_bundle(case.name, entities, job_links_by_entity, case_id=case_id)
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="case-{case_id}-stix.json"'},
    )


@router.get("/{case_id}/ioc-pack")
async def case_ioc_pack(
    case_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    _principal=Depends(current_user_or_api_token("case:read")),
):
    """Compact IOC pack JSON for a case (one row per member entity).

    Cookie auth (member-or-above) OR a Bearer token with `case:read`.
    """
    user = await _principal_user(db, _principal)
    case = await _load_case_or_404(db, case_id, user)
    await activity.record(
        "export.case", request=request, user=user, actor_label=principal_actor_label(_principal, user), target_type="case", target_id=str(case_id), summary=case.name
    )
    # Capped like the other two exports: an IOC pack is meant to be pasted into a ticket,
    # and an uncapped one on a 50,000-entity case is neither pasteable nor cheap.
    entity_links = (
        (
            await db.execute(
                select(CaseEntityLink).where(CaseEntityLink.case_id == case_id).options(selectinload(CaseEntityLink.entity)).order_by(CaseEntityLink.id).limit(_CASE_LINK_CAP)
            )
        )
        .scalars()
        .all()
    )
    entities = [el.entity for el in entity_links if el.entity is not None]
    sighting_counts = {e.id: e.job_count or 0 for e in entities}
    severity_by_entity = await _entity_severity_map(db, [e.id for e in entities], user)
    pack = build_case_ioc_pack(case.name, entities, sighting_counts=sighting_counts, severity_by_entity=severity_by_entity)
    return JSONResponse(pack)


@router.get("/{case_id}/misp")
async def case_misp_export(
    case_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    _principal=Depends(current_user_or_api_token("case:read")),
):
    """Export this case as a MISP Event JSON.

    Cookie auth (member-or-above) OR a Bearer token with `case:read`.
    """
    user = await _principal_user(db, _principal)
    case = await _load_case_or_404(db, case_id, user)
    await activity.record(
        "export.misp", request=request, user=user, actor_label=principal_actor_label(_principal, user), target_type="case", target_id=str(case_id), summary=case.name
    )
    entities, job_links_by_entity = await _load_case_export_context(db, case_id, user)

    severity_by_entity = await _entity_severity_map(db, [e.id for e in entities], user)
    event = build_misp_event(
        case_id=case_id,
        info=f"LogsTotal Case: {case.name}",
        entities=entities,
        sighting_counts=sighting_counts_from_links(job_links_by_entity),
        threat_level=threat_level_for_entities(entities, severity_by_entity),
    )
    return JSONResponse(
        event,
        headers={"Content-Disposition": f'attachment; filename="case-{case_id}-misp.json"'},
    )


@router.get("/{case_id}/graph-partial", response_class=HTMLResponse)
async def case_graph_partial(
    request: Request,
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Graph view shell — the payload is fetched separately by graph.json.

    `client_schema()` rides in the shell so the palette exists before the renderer is
    constructed; see the entity twin in routers/intel.py.
    """
    case = await _load_case_or_404(db, case_id, user)
    graph_opts = {
        "scope": "case",
        "caseId": case.id,
        # Unfiltered by default, unlike the entity graph: cross-job correlation is the
        # whole point of a case, so gating it would hide the case's main view on open.
        "jobId": 0,
        "jsonUrl": f"/intel/cases/{case.id}/graph.json",
        "graphmlBase": f"/intel/cases/{case.id}/graph.graphml",
        # The time link is case-only: an entity's job set is unbounded, so a time brush
        # there would re-derive a whole traversal per tick.
        "activeUrl": f"/intel/cases/{case.id}/graph-active.json",
        "pngPrefix": f"case-{case.id}",
        "schema": client_schema(),
    }
    return templates.TemplateResponse(
        request,
        "intel/partials/_case_graph.html",
        {"request": request, "case": case, "graph_opts": graph_opts, "job_options": await _case_job_options(db, case_id, user)},
    )


async def _case_job_options(db: AsyncSession, case_id: int, user: User | None) -> list[dict]:
    """Bounded `<option>` source for the case's job pickers (graph filter, Processes tab).

    Visibility-scoped, so a private job another member linked into a shared case never
    names its filename in a dropdown — the picker would otherwise leak exactly what
    `_case_job_links_stmt` is careful to hide from the Jobs tab.
    """
    stmt = (
        select(AnalysisJob.id, AnalysisJob.filename)
        .join(LogFile, AnalysisJob.file_id == LogFile.id)
        .join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id)
        .where(CaseJobLink.case_id == case_id)
        .order_by(AnalysisJob.id.desc())
        .limit(_CASE_JOB_PICKER_LIMIT)
    )
    vis = visible_job_filter(user)
    if vis is not True:
        stmt = stmt.where(vis)
    return [{"id": jid, "filename": name} for jid, name in (await db.execute(stmt)).all()]


async def _resolve_case_job_scope(db: AsyncSession, case_id: int, job: int, user: User | None) -> int:
    """Return *job* if it is linked to this case and visible to *user*, else 0.

    Same one-message discipline as `case_timeline_partial`'s entity check: a job that is
    not in the case, a job that does not exist, and a job the viewer may not see all
    produce the same outcome, so the filter cannot become an existence oracle.

    Unlike the entity graph, an unusable value here *drops* rather than emptying the
    result. A case renders unfiltered by default — cross-job correlation is the whole
    point of a case — so widening back to the default view is the correct fallback, and
    it is the same call `entities_partial` makes on the dashboard.
    """
    if not job:
        return 0
    stmt = select(CaseJobLink.job_id).join(AnalysisJob, AnalysisJob.id == CaseJobLink.job_id).where(CaseJobLink.case_id == case_id, CaseJobLink.job_id == job)
    vis = visible_job_filter(user)
    if vis is not True:
        stmt = stmt.where(vis)
    return job if await db.scalar(stmt) else 0


async def _case_graph_entity_ids(db: AsyncSession, case_id: int, job: int) -> list[int]:
    """The case's entity set, optionally narrowed to those the given job also saw.

    Bounded at `CASE_MAX_NODES`. The builder caps the node set anyway, but it does so one
    query too late: this list becomes a literal `IN (...)` in every query underneath, and
    PostgreSQL refuses a statement with more than 65,535 bind parameters — so a large
    enough case would be a hard 500 rather than a truncated graph. Ordered by entity id so the
    cut is deterministic across the several queries that consume it.
    """
    stmt = select(CaseEntityLink.entity_id).where(CaseEntityLink.case_id == case_id)
    if job:
        stmt = stmt.where(CaseEntityLink.entity_id.in_(select(EntityJobLink.entity_id).where(EntityJobLink.job_id == job)))
    stmt = stmt.order_by(CaseEntityLink.entity_id).limit(CASE_MAX_NODES)
    return [row[0] for row in (await db.execute(stmt)).all()]


@router.get("/{case_id}/graph.json")
async def case_graph_json(
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    include_allowlisted: int = 0,
    job_edges: int = 1,
    q: str = "",
    job: int = 0,
):
    """Columnar graph payload for a case — bounded by member entities, no hop expansion.

    `job_edges=0` omits job-co-occurrence edges server-side. The UI hides them by
    default, so this is what keeps a large case's payload small; the server default
    stays 1 so a bare GET returns the full graph for any existing consumer.

    `q` behaves exactly as on the entity route: only its `re:` terms are evaluated here.
    """
    from app.intel.queries import parse_query

    case = await _load_case_or_404(db, case_id, user)
    job = await _resolve_case_job_scope(db, case_id, job, user)
    entity_ids = await _case_graph_entity_ids(db, case_id, job)
    payload = await build_case_graph(
        db,
        entity_ids,
        include_allowlisted=bool(include_allowlisted),
        viewer=user,
        job_edges=bool(job_edges),
        query=parse_query(q) if q.strip() else None,
        case_id=case.id,
        job_id=job or None,
    )
    payload["case_name"] = case.name
    return JSONResponse(payload)


@router.get("/{case_id}/graph.graphml")
async def case_graph_graphml(
    case_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    include_allowlisted: int = 0,
    job_edges: int = 1,
    job: int = 0,
):
    """GraphML export of the case-bounded relationship graph."""
    from fastapi.responses import Response

    from app.intel.graph import EXPORT_MAX_EDGES, EXPORT_MAX_NODES

    await _load_case_or_404(db, case_id, user)  # authz side-effect
    job = await _resolve_case_job_scope(db, case_id, job, user)
    entity_ids = await _case_graph_entity_ids(db, case_id, job)
    payload = await build_case_graph(
        db,
        entity_ids,
        include_allowlisted=bool(include_allowlisted),
        viewer=user,
        job_edges=bool(job_edges),
        job_id=job or None,
        max_edges=EXPORT_MAX_EDGES,
        max_nodes=EXPORT_MAX_NODES,
        # GraphML carries no threat columns: they are four extra queries for data the
        # format has no way to explain, and yEd would render them as bare integers.
        threat=False,
    )
    xml = to_graphml(payload, name=f"case-{case_id}")
    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="case-{case_id}-graph.graphml"'},
    )
