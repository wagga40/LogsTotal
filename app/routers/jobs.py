"""
Jobs router — public read access; admin-only for delete.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from html import escape
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, undefer

from app import activity, job_watch
from app.auth.users import MEMBER_ROLES, current_member_or_above, current_superuser, current_user_optional, current_user_required
from app.comments import comment_counts_for
from app.config import settings
from app.constants import (
    AI_ELIGIBLE_JOB_STATUSES,
    ALLOWED_JOBS_VIEWS,
    CANCEL_MSG_DEAD_WORKER,
    CANCEL_MSG_USER,
    CASE_BACKLINK_LIMIT,
    DEFAULT_JOBS_PER_PAGE,
    DEFAULT_JOBS_VIEW,
    JOBS_PER_PAGE_CHOICES,
    JOBS_PER_PAGE_COOKIE,
    JOBS_VIEW_COOKIE,
    SEVERITY_COLORS,
    SEVERITY_ORDER,
    TAG_COLORS,
    TERMINAL_JOB_STATUSES,
    is_post_processing_task,
)
from app.database import get_async_session, utc_now_naive
from app.intel import process_tree
from app.intel.entities import remove_entity_links_for_job_async
from app.intel.queries import TAG_QUERY_MAX, caret_token, escape_like, normalize_tag, parse_tags_csv
from app.intel.tactics import (
    _MITRE_TACTIC_COLORS,
    _MITRE_TACTICS,
    _OTHER_TACTIC,
    _OTHER_TACTIC_COLOR,
    _hex_to_rgb,
)
from app.jobs_query import COMPLETABLE_PREFIXES, IS_FLAGS, PREFIX_HELP, apply_jobs_query, describe, parse_jobs_query, query_errors
from app.json_utils import loads as json_loads
from app.models import (
    AnalysisJob,
    CaseJobLink,
    Comment,
    Finding,
    IntelRuleMatch,
    InvestigationCase,
    JobAiAnalysis,
    JobRuleMatch,
    JobStatus,
    JobTag,
    JobWatch,
    JobWatchEvent,
    LogFile,
    LogType,
    TagDefinition,
    TaskResult,
    TaskStatus,
    User,
    WebhookDelivery,
    WorkflowDef,
    can_view_job,
    enum_val,
    visible_case_filter,
    visible_job_filter,
)
from app.network.client_ip import get_client_ip
from app.rule_attribution import rule_author
from app.site_settings import get_site_settings
from app.storage import get_storage
from app.tags import BULK_TAG_CAP, ensure_tag_definition, parse_id_csv, parse_tag_write, set_tag_color, tag_rows
from app.templates_config import negotiated as _negotiated
from app.templates_config import templates

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jobs")

# Bulk delete is one transaction per job (each cleans storage), so keep the batch bounded.
_BULK_DELETE_CAP = 100


def _can_view_private(job: AnalysisJob, user: User | None) -> bool:
    """Return True if the user is allowed to see this (possibly private) job."""
    return can_view_job(job, user)


def _private_filter(user: User | None):
    """`visible_job_filter`: hides private jobs from non-owners — or the literal `True` for an admin, hence the `if vis is not True` guard at the call sites."""
    return visible_job_filter(user)


def _jobs_filter(tags: str, q: str, *, may_see_tags: bool = True) -> tuple[list[str], dict, str]:
    """`(tag list, parsed query, the fragment to thread into every URL that must keep it)`.

    Two ways in, one filter. `?tags=` is what a chip click produces and `?q=tag:…` is what
    someone types; supplying both merges them rather than letting one silently win — the
    same fold `routers/intel.py` does for the entity dashboard.

    The fragment is built here with `urlencode` rather than assembled in Jinja, because it
    has to reach several places and each is a separate chance to get the escaping wrong.

    **Tags are member-only**, and the list hides them from everyone else, so for those
    viewers any tag filter becomes one refused term that matches nothing — whether or not
    the tag exists. Narrowing to the tagged jobs would confirm a label they cannot see, and
    guessing names would read out the analysts' triage state.
    """
    tag_list = parse_tags_csv(tags)
    parsed = parse_jobs_query(q)
    if not may_see_tags and (tag_list or any(t["kind"] == "tag" for t in parsed["terms"])):
        refused = {"kind": "tag", "tags": [], "negated": False, "error": "tags are only searchable by members"}
        parsed = {**parsed, "terms": [t for t in parsed["terms"] if t["kind"] != "tag"] + [refused], "invalid": True}
        tag_list = []

    # A single positive `tag:` term is the same filter reached the other way. Fold it in and
    # drop it from the conjunction, so the union is applied once rather than intersected
    # with itself — `?tags=a` plus `q=tag:b` means "a or b", which is what any-of means
    # everywhere else in this app.
    tag_terms = [t for t in parsed["terms"] if t["kind"] == "tag" and not t.get("negated")]
    if tag_list and len(tag_terms) == 1:
        tag_list = list(dict.fromkeys([*tag_list, *tag_terms[0]["tags"]]))[:TAG_QUERY_MAX]
        parsed = {**parsed, "terms": [t for t in parsed["terms"] if t is not tag_terms[0]]}

    params = {}
    if tag_list:
        params["tags"] = ",".join(tag_list)
    if q.strip():
        params["q"] = q.strip()
    return tag_list, parsed, (urlencode(params) if params else "")


def _may_see_tags(user: User | None) -> bool:
    return user is not None and (user.is_superuser or user.role in MEMBER_ROLES)


_SUGGEST_LIMIT = 20

#: The shapes a free-form term accepts, offered as examples rather than enumerated values.
#: A date picker would be a different feature; these are the three spellings people forget.
_VALUE_EXAMPLES: dict[str, tuple[tuple[str, str], ...]] = {
    "findings:": ((">10", "more than ten"), ("=0", "none at all"), ("5..50", "a range")),
    "after:": (("7d", "the last week"), ("24h", "the last day"), ("2026-01-01", "an exact date")),
    "before:": (
        ("7d", "older than a week"),
        ("2026-01-01", "an exact date"),
    ),
}


def _jobs_view(request: Request, view: str) -> str:
    """Which row shape to draw: an explicit `?view=` wins, else the cookie, else the default.

    Resolved on the server rather than in Alpine because `/jobs/table-partial` re-renders the
    rows every 5 seconds — a mode the server does not know about would be reverted by the
    first poll, and only while a job is running.

    Both sources are clamped against `ALLOWED_JOBS_VIEWS`: the cookie is not HttpOnly, so
    it is untrusted input on read.
    """
    if view in ALLOWED_JOBS_VIEWS:
        return view
    cookie = request.cookies.get(JOBS_VIEW_COOKIE, "")
    return cookie if cookie in ALLOWED_JOBS_VIEWS else DEFAULT_JOBS_VIEW


def _jobs_per_page(request: Request, per: str) -> int:
    """Rows per page: an explicit `?per=` wins, else the cookie, else the default.

    The `_jobs_view` arrangement, for the same reason: the 5s table poll re-renders the rows,
    so a page size only the page knew about would be undone by the first tick. Both sources
    are clamped against `JOBS_PER_PAGE_CHOICES` — the cookie is untrusted on read, and `?per=`
    is typed `str` so a junk value degrades instead of 422-ing a shared link.
    """
    for raw in (per, request.cookies.get(JOBS_PER_PAGE_COOKIE, "")):
        if raw.isdigit() and int(raw) in JOBS_PER_PAGE_CHOICES:
            return int(raw)
    return DEFAULT_JOBS_PER_PAGE


def _per_page_links(page: int, per_page: int, filter_qs: str, view: str) -> list[dict]:
    """The rows-per-page switch. Each link lands on the page holding the first row you were
    looking at — switching from page 3 at 20 (row 41) to 50 lands on page 1, not on page 3
    of a different slicing — and carries the filter and view with it.
    """
    rest = _list_qs(filter_qs, view)
    first_row = (page - 1) * per_page
    return [{"per": p, "active": p == per_page, "url": f"/jobs?per={p}&page={first_row // p + 1}" + (f"&{rest}" if rest else "")} for p in JOBS_PER_PAGE_CHOICES]


def _list_qs(filter_qs: str, view: str, per_page: int = DEFAULT_JOBS_PER_PAGE) -> str:
    """Everything after `?page=N` on a jobs-list URL: the filter, and the view and page size
    if they are not the defaults.

    Assembled here, once, because it has to reach the poll URL, the pager and the density
    toggle — and it is joined with `&` in exactly one place rather than concatenated in
    three templates, which is how a `?page=2&&view=roomy` gets shipped.

    The default view contributes nothing at all, so a URL carries only what was actually
    asked for.
    """
    parts = [
        filter_qs,
        "" if view == DEFAULT_JOBS_VIEW else f"view={view}",
        "" if per_page == DEFAULT_JOBS_PER_PAGE else f"per={per_page}",
    ]
    return "&".join(p for p in parts if p)


def _jobs_page_stmt(user: User | None, tag_list: list[str], parsed: dict | None = None):
    """The jobs-list query. **One builder for both the page and its 5s poll partial.**

    Two copies are how a filter comes to exist on one and not the other — and the failure
    mode is nasty, because the page looks right until the first poll silently replaces the
    rows with an unfiltered set.

    `selectinload(AnalysisJob.tags)` matters more here than it looks: without it a 20-row
    page costs 20 extra queries, and the poll partial runs twelve times a minute. Do not
    add an `undefer` while in here — `AnalysisJob.event_markers` is `deferred()` on purpose.
    """
    stmt = (
        select(AnalysisJob)
        .options(
            selectinload(AnalysisJob.log_file),
            selectinload(AnalysisJob.workflow),
            selectinload(AnalysisJob.submitter),
            selectinload(AnalysisJob.tags),
        )
        # `created_at` has one-second resolution and a multi-file upload creates jobs in
        # bursts (measured: 359 jobs over 54 distinct timestamps). Without the id, ties come
        # back in any order and a page boundary through a burst repeats or skips a job.
        .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
    )
    stmt = _apply_jobs_tag_filter(stmt, tag_list)
    return apply_jobs_query(stmt, parsed or {}, viewer_id=(user.id if user else None))


def _apply_jobs_tag_filter(stmt, tag_list: list[str]):
    """Any-of, as an EXISTS — the same semantics and shape as `apply_entity_filters`.

    Any-of because a tag chip is a pivot: clicking a second one should widen the net, not
    narrow it to the intersection of two labels nothing carries at once.
    """
    if tag_list:
        stmt = stmt.where(select(JobTag.id).where(JobTag.job_id == AnalysisJob.id, JobTag.tag.in_(tag_list)).exists())
    return stmt


async def _watched_ids(db: AsyncSession, user: User | None, jobs) -> set[int]:
    """Which of these jobs the viewer watches — one query per page, not one per row.

    A property of the *viewer*, not of the job, which is why it is computed here rather than
    eager-loaded onto the rows: two people looking at the same list see different marks.
    """
    if user is None or not jobs:
        return set()
    from app.models import JobWatch

    ids = [j.id for j in jobs]
    rows = await db.execute(select(JobWatch.job_id).where(JobWatch.user_id == user.id, JobWatch.job_id.in_(ids)))
    return set(rows.scalars().all())


@router.get("")
async def job_list(
    request: Request,
    page: int = 1,
    tags: str = "",
    q: str = "",
    view: str = "",
    per: str = "",
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """Paginated list of all analysis jobs, filtered by `?q=` and/or `?tags=`."""
    from sqlalchemy import func

    vis = _private_filter(user)
    # Clamped: `?page=0` would produce OFFSET -20, which PostgreSQL rejects outright
    # ("OFFSET must not be negative") — an unauthenticated 500. SQLite clamps it silently,
    # so only production would ever see it.
    page = max(1, page)
    per_page = _jobs_per_page(request, per)
    tag_list, parsed, filter_qs = _jobs_filter(tags, q, may_see_tags=_may_see_tags(user))

    # The same filter on the count, or the pager offers pages the filter cannot fill. Counted
    # first so a page past the end lands on the last page — it used to render "No jobs yet"
    # with no pager, which a stale bookmark or a shrunken filter reaches easily.
    count_q = _apply_jobs_tag_filter(select(func.count(AnalysisJob.id)), tag_list)
    count_q = apply_jobs_query(count_q, parsed, viewer_id=(user.id if user else None))
    if vis is not True:
        count_q = count_q.where(vis)
    total = await db.scalar(count_q) or 0
    total_pages = max(1, -(-total // per_page))
    page = min(page, total_pages)

    offset = (page - 1) * per_page
    stmt = _jobs_page_stmt(user, tag_list, parsed)
    if vis is not True:
        stmt = stmt.where(vis)
    result = await db.execute(stmt.offset(offset).limit(per_page))
    jobs = result.scalars().all()

    # Real colours for the active-filter chips. From the vocabulary rather than from the
    # rows on screen, because under a filter that matches nothing there are no rows to read
    # a colour off — and that is exactly when the chips have to render.
    active_colors: dict[str, str] = {}
    if tag_list:
        rows = await db.execute(select(TagDefinition.tag, TagDefinition.color).where(TagDefinition.tag.in_(tag_list)))
        active_colors = {t: c or "gray" for t, c in rows.all()}

    has_running = any(enum_val(j.status) in ("pending", "running") for j in jobs)
    resolved_view = _jobs_view(request, view)

    response = templates.TemplateResponse(
        request,
        "jobs.html",
        {
            "request": request,
            "user": user,
            "jobs": jobs,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "per_page": per_page,
            "per_page_links": _per_page_links(page, per_page, filter_qs, resolved_view),
            "has_running": has_running,
            "watched_ids": await _watched_ids(db, user, jobs),
            "active_tags": tag_list,
            "active_tag_colors": active_colors,
            "tags_qs": filter_qs,
            "tag_colors": TAG_COLORS,
            "query": q,
            "query_chips": [describe(t) for t in parsed["terms"]],
            "query_errors": query_errors(parsed),
            "tabs": await _jobs_tabs_for(db, user),
            "view": resolved_view,
            "list_qs": _list_qs(filter_qs, resolved_view, per_page),
        },
    )
    # Remembered only when it was asked for. Setting it on every render would make the
    # first visit stamp a preference nobody expressed, and a shared link carrying
    # `?view=roomy` would silently change the recipient's default.
    if view in ALLOWED_JOBS_VIEWS:
        response.set_cookie(JOBS_VIEW_COOKIE, view, max_age=60 * 60 * 24 * 365, path="/", samesite="lax", secure=settings.cookie_secure, httponly=False)
    if per.isdigit() and int(per) in JOBS_PER_PAGE_CHOICES:
        response.set_cookie(JOBS_PER_PAGE_COOKIE, per, max_age=60 * 60 * 24 * 365, path="/", samesite="lax", secure=settings.cookie_secure, httponly=False)
    return response


@router.get("/table-partial", response_class=HTMLResponse)
async def jobs_table_partial(
    request: Request,
    page: int = 1,
    tags: str = "",
    q: str = "",
    view: str = "",
    per: str = "",
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """HTMX partial — returns just the rows for the jobs list.

    Shares `_jobs_page_stmt` with `job_list`. It must: this runs every 5s while anything
    is running, so a filter the page applies and the poll does not is a filter that lasts
    five seconds.
    """
    vis = _private_filter(user)
    page = max(1, page)  # see job_list: a negative OFFSET 500s on PostgreSQL
    per_page = _jobs_per_page(request, per)
    offset = (page - 1) * per_page
    tag_list, parsed, filter_qs = _jobs_filter(tags, q, may_see_tags=_may_see_tags(user))
    stmt = _jobs_page_stmt(user, tag_list, parsed)
    if vis is not True:
        stmt = stmt.where(vis)
    result = await db.execute(stmt.offset(offset).limit(per_page))
    jobs = result.scalars().all()

    has_running = any(enum_val(j.status) in ("pending", "running") for j in jobs)

    resolved_view = _jobs_view(request, view)
    return templates.TemplateResponse(
        request,
        # Two row shapes, one query, one poll. The template is chosen here rather than
        # branched inside one file because each renders a different *element* — a <tbody>
        # for the table, a <div> for the cards — and htmx swaps the response by outerHTML.
        "partials/_jobs_cards.html" if resolved_view == "roomy" else "partials/_jobs_table_body.html",
        {
            "request": request,
            "user": user,
            "jobs": jobs,
            "page": page,
            "has_running": has_running,
            "watched_ids": await _watched_ids(db, user, jobs),
            "tags_qs": filter_qs,
            "view": resolved_view,
            "list_qs": _list_qs(filter_qs, resolved_view, per_page),
        },
    )


@router.get("/search-suggest")
async def jobs_search_suggest(
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
    q: str = "",
    pos: int = 0,
):
    """Completions for the term under the caret in the jobs search box.

    The twin of `/intel/search-suggest`: the two boxes share a tokenizer, and an analyst who
    learns a dialect on one list should not find the other one mute.

    Caret parsing is `queries.caret_token` over `COMPLETABLE_PREFIXES`.

    **Registered before `/{job_id}`**, or the path is read as a job id and 422s — which
    renders as a picker that silently never opens.

    What it will not complete, each for a reason:
      * `id:` and `sha256:` — omitted from `COMPLETABLE_PREFIXES`; the reason is on that
        constant.
      * `tag:` for a viewer who is not a member — the jobs list hides tags from them, so
        offering the vocabulary here would hand over what the page withholds.
    """
    token = caret_token(q, pos, COMPLETABLE_PREFIXES)
    prefix, fragment = token["prefix"], token["fragment"]
    # Only the last value of a CSV is being typed; the earlier ones are already committed.
    needle = fragment.rsplit(",", 1)[-1].strip().lower()
    is_member = bool(user and (user.is_superuser or user.role == "member"))

    def _wrap(items: list[dict]) -> JSONResponse:
        return JSONResponse({"start": token["start"], "end": token["end"], "prefix": prefix, "suggestions": items[:_SUGGEST_LIMIT]})

    def _item(value: str, *, label: str = "", detail: str = "") -> dict:
        """One completion, preserving the negation and any earlier CSV values — every
        multi-valued term here is any-of, so completing `status:failed,` must extend the
        list rather than replace it."""
        typed = token["text"]
        neg = "-" if typed.startswith("-") else ""
        kept = fragment.rsplit(",", 1)[0] + "," if "," in fragment else ""
        return {"insert": f"{neg}{prefix}{kept}{value}", "label": label or value, "detail": detail}

    if prefix is None:
        typed = needle
        offered = [p for p in PREFIX_HELP if is_member or p[0] != "tag:"]
        return _wrap([{"insert": p, "label": p, "detail": help_text} for p, help_text in offered if not typed or p.startswith(typed)])

    if prefix == "tag:":
        if not is_member:
            return _wrap([])
        rows = await tag_rows(db, needle, "count", limit=_SUGGEST_LIMIT, job_filter=_private_filter(user))
        return _wrap([_item(r["tag"], detail=f"{r['job_count']} job{'' if r['job_count'] == 1 else 's'}") for r in rows if r["job_count"] or not needle])

    if prefix == "status:":
        return _wrap([_item(m.value) for m in JobStatus if needle in m.value])

    if prefix == "type:":
        return _wrap([_item(m.value) for m in LogType if needle in m.value and m.value != "unknown"])

    if prefix == "sev:":
        return _wrap([_item(sv) for sv in SEVERITY_ORDER if needle in sv])

    if prefix == "is:":
        return _wrap([_item(flag, detail=meaning) for flag, meaning in sorted(IS_FLAGS.items()) if needle in flag])

    if prefix == "workflow:":
        stmt = select(WorkflowDef.name).order_by(WorkflowDef.name)
        if needle:
            stmt = stmt.where(WorkflowDef.name.ilike(f"%{escape_like(needle)}%", escape="\\"))
        names = (await db.execute(stmt.limit(_SUGGEST_LIMIT))).scalars().all()
        # Quoted when it has a space, because the tokenizer splits on whitespace and an
        # unquoted "Windows Full Analysis" would insert three terms.
        return _wrap([_item(f'"{n}"' if " " in n else n, label=n) for n in names])

    if prefix == "tool:":
        # From what has actually run, not from the registry: a tool nobody has used matches
        # nothing, and offering it makes the picker look broken.
        stmt = select(TaskResult.tool_name).join(AnalysisJob, TaskResult.job_id == AnalysisJob.id).where(_private_filter(user)).distinct().order_by(TaskResult.tool_name)
        names = (await db.execute(stmt.limit(_SUGGEST_LIMIT * 2))).scalars().all()
        # `TaskResult` also holds the post-processing pseudo-tasks ("Computing analytics",
        # "File similarity"). They are real rows, so `tool:` matches them, but offering them
        # as tools is a lie about what ran on the log.
        return _wrap([_item(n) for n in names if needle in n.lower() and not is_post_processing_task(n)])

    if prefix == "findings":
        return _wrap([])

    # findings:, after: and before: take free-form values; the shapes they accept are in the
    # help panel, and enumerating dates would be noise.
    return _wrap([_item(v, detail=d) for v, d in _VALUE_EXAMPLES.get(prefix, ()) if needle in v])


@router.get("/recent-partial", response_class=HTMLResponse)
async def jobs_recent_partial(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """HTMX partial — compact recent jobs list for homepage."""
    vis = _private_filter(user)
    q = (
        select(AnalysisJob)
        .options(
            selectinload(AnalysisJob.log_file),
            selectinload(AnalysisJob.workflow),
            selectinload(AnalysisJob.submitter),
        )
        .order_by(AnalysisJob.created_at.desc())
    )
    if vis is not True:
        q = q.where(vis)
    result = await db.execute(q.limit(8))
    jobs = result.scalars().all()
    has_running = any(enum_val(j.status) in ("pending", "running") for j in jobs)

    return templates.TemplateResponse(
        request,
        "partials/_jobs_recent.html",
        {
            "request": request,
            "jobs": jobs,
            "has_running": has_running,
        },
    )


def _build_jobs_page_tabs(user: User | None, *, watched: int = 0) -> list[dict]:
    """Tabs for the jobs *list* page — the `{key, label, badge, lazy_event, icon}` shape
    every other strip in the app uses, so `resourceTabs()`, `tab_icon()` and `tab_badge()`
    all work unchanged.

    Gated **server-side, in the list**, never with `x-show` on a rendered tab: `/jobs` is
    anonymous-viewable, and a tab whose pane 403s is worse than no tab. Anonymous therefore
    gets a one-entry list, and the template renders the table with no strip at all — the
    `job.html` idiom.
    """
    tabs = [{"key": "list", "label": "Jobs", "badge": None, "lazy_event": None, "icon": "queue"}]
    if user is not None:
        # Any logged-in user, mirroring the watch toggle itself.
        tabs.append({"key": "watching", "label": "Watching", "badge": watched or None, "lazy_event": "loadJobWatching", "icon": "eye"})
    return tabs


@router.get("/watching", response_class=HTMLResponse)
async def jobs_watching(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """The jobs this user watches. Nothing else lists them — the bell shows only the newest
    unacknowledged events, across both streams, and says nothing about a quiet subscription.
    """
    return await _render_watching(request, db, user)


async def _render_watching(request: Request, db: AsyncSession, user: User) -> HTMLResponse:
    rows = await job_watch.watched_rows(db, user)
    return _negotiated(
        request,
        page="jobs_watching.html",
        fragment="partials/_jobs_watching.html",
        context={
            "request": request,
            "user": user,
            "rows": rows,
            "unread": sum(r["unread"] for r in rows),
            # What the tab badge shows, and therefore what this pane must swap back into it
            # — `rows` IS the watch list, so no second query.
            "watched": len(rows),
            "tabs": await _jobs_tabs_for(db, user),
        },
    )


async def _jobs_tabs_for(db: AsyncSession, user: User | None) -> list[dict]:
    """The tab list, with its badges. One helper so the three surfaces that render the strip
    cannot disagree about the counts on it."""
    watched = await job_watch.watched_count(db, user) if user is not None else 0
    return _build_jobs_page_tabs(user, watched=watched)


@router.post("/watching/{job_id}/ack", response_class=HTMLResponse)
async def jobs_watching_ack(
    request: Request,
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Mark one watched job's notifications as read, and re-render the pane.

    The middle ground between the bell's ack-all, which clears everything, and its per-row
    ack, which clears one event.
    """
    await job_watch.ack_job_events(db, job_id, user)
    await db.commit()
    return await _render_watching(request, db, user)


@router.post("/watching/{job_id}/stop", response_class=HTMLResponse)
async def jobs_watching_stop(
    request: Request,
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Unsubscribe from here, and re-render the pane.

    Not a reuse of `POST /jobs/{id}/watch`: that returns the header button, so htmx would
    swap a lone button in place of this list.
    """
    if await job_watch.remove_watch_async(db, job_id, user.id):
        await db.commit()
        await activity.record("job.watch", request=request, user=user, target_type="job", target_id=str(job_id), summary="no longer watching", meta={"on": False})
    return await _render_watching(request, db, user)


@router.get("/{job_id}")
async def job_detail(
    job_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """Full job detail page with findings, analytics, and similarity panels."""
    job = await _load_job_full(db, job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    if not _can_view_private(job, user):
        raise HTTPException(404, "Job not found.")

    findings_by_severity = _group_findings(job)
    status = enum_val(job.status)
    is_terminal = status in TERMINAL_JOB_STATUSES
    summary = _parse_summary(job) if is_terminal else _compute_live_summary(job)
    tlsh_hash = job.log_file.tlsh_hash if job.log_file else None
    site_settings = await get_site_settings(db)

    # Duplicate banner data: file_id and workflow list for resubmit form
    workflows = []
    if request.query_params.get("dup"):
        result = await db.execute(select(WorkflowDef).order_by(WorkflowDef.name))
        workflows = result.scalars().all()

    member_cases = await _member_case_backlinks(db, job_id, user)
    comment_count = (await comment_counts_for(db, "job", [job_id])).get(job_id, 0) if user else 0
    tabs = _build_job_tabs(user, comment_count, show_ai=await _show_ai_tab(db, job_id, user, site_settings, job_status=status))

    return templates.TemplateResponse(
        request,
        "job.html",
        {
            "tabs": tabs,
            "request": request,
            "user": user,
            "job": job,
            "findings_by_severity": findings_by_severity,
            "summary": summary,
            "workflows": workflows,
            "is_duplicate": bool(request.query_params.get("dup")),
            "can_resubmit": await _can_resubmit(db, job.file_id, user),
            "tlsh_hash": tlsh_hash,
            "site_settings": site_settings,
            "member_cases": member_cases,
            "tags": sorted(job.tags, key=lambda t: t.tag),
            "tag_colors": TAG_COLORS,
            "job_id": job.id,
            "watching": (await job_watch.is_watching_async(db, job_id, user.id)) if user else False,
        },
    )


async def _can_resubmit(db: AsyncSession, file_id: int, user: User | None) -> bool:
    """Whether `POST /jobs/resubmit` would accept this viewer for this file — the same
    test, so the button is never offered to someone the route then 401s or 403s."""
    if user is None:
        return False
    if user.is_superuser:
        return True
    return await db.scalar(select(AnalysisJob.id).where(AnalysisJob.file_id == file_id, AnalysisJob.submitted_by_user_id == user.id).limit(1)) is not None


async def _show_ai_tab(db: AsyncSession, job_id: int, user: User | None, site_settings, *, job_status: str = "") -> bool:
    """Whether the AI Analysis tab belongs on this page for this viewer.

    Member-and-above get it whenever the feature is on, because they can start a run —
    *unless* the job has finished without anything to analyse. Anyone else gets it only
    when a run already exists: a finished analysis is part of the job's record like its
    findings are, but a tab whose only content is a button they cannot press is worse than
    no tab.

    **The gate is "terminal and ineligible", not simply "ineligible"**, and the difference
    is what keeps this a one-line change instead of a live-updating tab strip. A `failed`
    or `cancelled` job will never become analysable, so hiding its tab costs nothing. A
    `pending` or `running` one will, and hiding the tab there would mean re-rendering the
    strip mid-poll — the strip lives inside the `resourceTabs` `x-data` beside the comment
    pane, so swapping it would wipe a half-typed comment. Instead the tab stays and the
    panel explains itself, which `_ai_analysis.html` does through `can_run_now`.

    `job_status` is keyword-only with a default; an empty string means "unknown" and stays
    permissive rather than hiding the tab on a caller that never passed it.

    The count query still runs for a member+ on an ineligible job, because a past run must
    remain readable on a job that has since been re-run into a failure.
    """
    from sqlalchemy import func

    if not getattr(site_settings, "show_ai_analysis", False):
        return False
    finished_with_nothing = job_status in TERMINAL_JOB_STATUSES and job_status not in AI_ELIGIBLE_JOB_STATUSES
    if not finished_with_nothing and user is not None and (user.is_superuser or user.role in MEMBER_ROLES):
        return True
    return bool(await db.scalar(select(func.count(JobAiAnalysis.id)).where(JobAiAnalysis.job_id == job_id)))


def _build_job_tabs(user: User | None, comment_count: int, *, show_ai: bool = False) -> list[dict]:
    """Job-detail tabs, same `{key, label, badge, lazy_event, icon}` shape as the entity
    and case pages so they can share `resourceTabs()`.

    Anonymous visitors get a single-entry list: the template then renders the results
    with no tab strip rather than one pointless tab.

    `show_ai` is keyword-only with a default, the way `_build_entity_tabs`'
    `show_process_tree` is, so positional call sites stay unchanged.
    """
    tabs = [{"key": "results", "label": "Results", "badge": None, "lazy_event": None, "icon": "shield"}]
    if show_ai:
        tabs.append({"key": "ai", "label": "AI Analysis", "badge": None, "lazy_event": "loadAiAnalysis", "icon": "sparkles"})
    if user is not None:
        tabs.append({"key": "discussion", "label": "Discussions", "badge": comment_count or None, "lazy_event": "loadComments", "icon": "chat"})
    return tabs


async def _member_case_backlinks(db: AsyncSession, job_id: int, user: User | None) -> list:
    """Cases this job is linked to, for the header chips — member+ only.

    Cases are a member-and-above feature, so anonymous and `role=user` viewers get an
    empty list and the partial renders nothing. `visible_case_filter` then keeps another
    member's unshared case name out of the response.
    """
    if user is None or not (user.is_superuser or user.role in MEMBER_ROLES):
        return []
    stmt = (
        select(InvestigationCase)
        .join(CaseJobLink, CaseJobLink.case_id == InvestigationCase.id)
        .where(CaseJobLink.job_id == job_id)
        .order_by(InvestigationCase.updated_at.desc())
        .limit(CASE_BACKLINK_LIMIT)
    )
    vis = visible_case_filter(user)
    if vis is not True:
        stmt = stmt.where(vis)
    return list((await db.execute(stmt)).scalars().all())


@router.get("/{job_id}/status-partial", response_class=HTMLResponse)
async def job_status_partial(
    job_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """HTMX partial — returns full job status (score card + findings + panels).

    Polls every 3s while running; returns HTTP 286 when terminal so HTMX
    cancels the polling timer (the official way to stop ``every Xs`` triggers).
    """
    job = await _load_job_full(db, job_id)
    if not job or not _can_view_private(job, user):
        return HTMLResponse("<div>Job not found.</div>")

    findings_by_severity = _group_findings(job)
    status = enum_val(job.status)
    is_terminal = status in TERMINAL_JOB_STATUSES
    summary = _parse_summary(job) if is_terminal else _compute_live_summary(job)
    tlsh_hash = job.log_file.tlsh_hash if job.log_file else None
    site_settings = await get_site_settings(db)

    queue_position = None
    estimated_remaining = None
    if not is_terminal:
        try:
            from app.redis_client import AVG_DURATION_PREFIX, QUEUE_POSITION_PREFIX, get_redis

            r = get_redis()
            qp = r.get(f"{QUEUE_POSITION_PREFIX}{job_id}")
            if qp:
                queue_position = int(qp)
            avg = r.get(f"{AVG_DURATION_PREFIX}{job.workflow_id}")
            if avg and job.created_at:
                # created_at is naive UTC (models use DateTime without timezone), so this
                # must be too — subtracting an aware now() raises TypeError, and the except
                # below would swallow it, leaving the ETA permanently blank.
                elapsed = (utc_now_naive() - job.created_at).total_seconds()
                remaining = max(0, float(avg) - elapsed)
                if remaining > 0:
                    estimated_remaining = int(remaining)
        except Exception:
            logger.warning("Could not compute queue position/ETA for job %s", job_id, exc_info=True)

    return templates.TemplateResponse(
        request,
        "partials/_job_status_poll.html",
        {
            "request": request,
            "user": user,
            "job": job,
            "findings_by_severity": findings_by_severity,
            "summary": summary,
            "tlsh_hash": tlsh_hash,
            "site_settings": site_settings,
            "queue_position": queue_position,
            "estimated_remaining": estimated_remaining,
            "can_resubmit": await _can_resubmit(db, job.file_id, user),
        },
        status_code=286 if is_terminal else 200,
    )


@router.get("/{job_id}/similar", response_class=HTMLResponse)
async def job_similar_files(
    job_id: int,
    request: Request,
    threshold: int = 100,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """HTMX partial — files with similar TLSH hash to this job's file."""
    from app.similarity.hasher import find_similar_files_async

    job = await db.get(AnalysisJob, job_id)
    if not job:
        return HTMLResponse("")
    if not _can_view_private(job, user):
        raise HTTPException(404)

    log_file = await db.get(LogFile, job.file_id)
    tlsh_hash = log_file.tlsh_hash if log_file else None

    similar_files = []
    if tlsh_hash:
        similar_files = await find_similar_files_async(db, tlsh_hash, exclude_file_id=log_file.id, threshold=threshold, viewer=user)

    return templates.TemplateResponse(
        request,
        "partials/_similar_files.html",
        {
            "request": request,
            "job_id": job_id,
            "tlsh_hash": tlsh_hash,
            "similar_files": similar_files,
            "threshold": threshold,
        },
    )


@router.get("/{job_id}/correlated", response_class=HTMLResponse)
async def job_correlated_findings(
    job_id: int,
    request: Request,
    rule_signature: str = "",
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """HTMX partial — other jobs where the same rule fired."""
    from app.similarity.correlator import find_correlated_findings_async

    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404)
    if not _can_view_private(job, user):
        raise HTTPException(404)

    correlated_findings = []
    if rule_signature:
        correlated_findings = await find_correlated_findings_async(db, rule_signature, exclude_job_id=job_id, viewer=user)

    return templates.TemplateResponse(
        request,
        "partials/_correlated_findings.html",
        {
            "request": request,
            "correlated_findings": correlated_findings,
        },
    )


async def _load_finding_job(db: AsyncSession, finding_id: int) -> tuple[Finding | None, AnalysisJob | None]:
    """Return (finding, owning_job) for auth checks; both None if finding absent.

    Undefers the two blobs: both callers are the routes that render them, and a deferred
    attribute on an attached instance issues its own SELECT — which raises
    `MissingGreenlet` under async SQLAlchemy rather than lazily loading.
    """
    finding = await db.scalar(select(Finding).options(undefer(Finding.details), undefer(Finding.rule_content)).where(Finding.id == finding_id))
    if not finding:
        return None, None
    tr = await db.get(TaskResult, finding.task_result_id)
    if not tr:
        return finding, None
    job = await db.get(AnalysisJob, tr.job_id)
    return finding, job


@router.get("/findings/{finding_id}/rule", response_class=HTMLResponse)
async def get_finding_rule(
    finding_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """Return the original Sigma rule YAML for a finding as an HTML partial."""
    finding, job = await _load_finding_job(db, finding_id)
    if not finding or not job:
        raise HTTPException(404)
    if not _can_view_private(job, user):
        raise HTTPException(404)
    if not finding.rule_content:
        return HTMLResponse('<p class="text-xs text-gray-500 italic">Rule content not available for this finding.</p>')

    stripped = finding.rule_content.strip()
    lang = "sql" if re.match(r"(?i)^(SELECT|INSERT|CREATE|WITH)\b", stripped) else "yaml"

    tr = await db.get(TaskResult, finding.task_result_id)
    return templates.TemplateResponse(
        request,
        "partials/_finding_rule.html",
        {
            "request": request,
            "finding": finding,
            "rule_content": finding.rule_content,
            "rule_author": rule_author(tr.tool_name if tr else None, finding.rule_id, finding.rule_content),
            "lang": lang,
        },
    )


@router.get("/findings/{finding_id}/events", response_class=HTMLResponse)
async def get_finding_events(
    finding_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """HTMX partial — lazy-load event details for a single finding."""
    from app.site_settings import get_site_settings as _gss

    finding, job = await _load_finding_job(db, finding_id)
    if not finding or not job:
        raise HTTPException(404)
    if not _can_view_private(job, user):
        raise HTTPException(404)

    details = json_loads(finding.details or "[]")
    site_settings = await _gss(db)

    return templates.TemplateResponse(
        request,
        "partials/_finding_events.html",
        {
            "request": request,
            "finding": finding,
            "details": details,
            "max_finding_details": site_settings.max_finding_details,
        },
    )


@router.get("/{job_id}/analytics", response_class=HTMLResponse)
async def job_analytics(
    job_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """HTMX partial — lazy-load analytics cards (MITRE, timeline, entities, threat detection)."""
    job = await _load_job_full(db, job_id)
    if not job:
        return HTMLResponse("")
    if not _can_view_private(job, user):
        raise HTTPException(404)

    summary = _parse_summary(job)
    # An admin-triggered recalculation in flight shows the polling spinner even
    # over stale cached analytics (and over the cancelled "skipped" card).
    recalc_running = False
    try:
        from app.redis_client import RECALC_PREFIX, get_redis

        recalc_running = bool(get_redis().exists(f"{RECALC_PREFIX}{job_id}"))
    except Exception:
        pass
    analytics_skipped = False
    analytics_skipped_reason = "cancelled"
    if job.analytics_json and not recalc_running:
        analytics = _hydrate_analytics(json_loads(job.analytics_json))
        analytics_pending = False
    else:
        analytics = _empty_analytics()
        status = enum_val(job.status)
        # Nothing is coming when the analytics step is not going to run (or already ran and
        # failed) — render a static card instead of polling every 3s forever. Cancelled
        # jobs skip the step by design; a FAILED post-processing TaskResult means the
        # worker tried and gave up.
        analytics_failed = not recalc_running and any(is_post_processing_task(tr.tool_name) and enum_val(tr.status) == "failed" for tr in job.task_results)
        analytics_skipped = not recalc_running and (status == "cancelled" or analytics_failed) and summary["total"] > 0
        analytics_pending = recalc_running or (not analytics_failed and status in ("completed", "failed", "partial") and summary["total"] > 0)
        analytics_skipped_reason = "failed" if analytics_failed else "cancelled"

    site_settings = await get_site_settings(db)
    log_type = job.effective_log_type.value if job.log_file and job.effective_log_type else ""

    return templates.TemplateResponse(
        request,
        "partials/_analytics.html",
        {
            "request": request,
            "user": user,
            "job": job,
            "analytics": analytics,
            "analytics_pending": analytics_pending,
            "analytics_skipped": analytics_skipped,
            "analytics_skipped_reason": analytics_skipped_reason,
            "site_settings": site_settings,
            "log_type": log_type,
        },
    )


@router.get("/{job_id}/process-tree", response_class=HTMLResponse)
async def job_process_tree(
    job_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """HTMX partial — lazy-load the process lineage tree (Sysmon 1 / Security 4688).

    The cache, the parse and the threadpool hop live in `app/intel/process_tree.py`, shared
    with the entity and case Processes tabs. Anonymous-viewable for a public job, which is
    exactly why this route takes no `entity_id`: that would make it an entity-existence
    oracle for anyone at all. The Intel-side routes are member-gated and check membership.
    """
    from app.intel.process_tree import load_job_forest

    job = await db.get(AnalysisJob, job_id)
    if not job:
        return HTMLResponse("")
    if not _can_view_private(job, user):
        raise HTTPException(404)

    forest = await load_job_forest(job_id)

    return templates.TemplateResponse(
        request,
        "partials/_process_tree.html",
        {
            "request": request,
            "job": job,
            "forest": forest,
        },
    )


@router.get("/task-results/{task_result_id}/log", response_class=HTMLResponse)
async def get_task_log(
    task_result_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    _: User = Depends(current_superuser),
):
    """HTMX partial — lazy-load task log output. Admin only."""
    tr = await db.get(TaskResult, task_result_id)
    if not tr:
        raise HTTPException(404)

    return templates.TemplateResponse(
        request,
        "partials/_task_log.html",
        {
            "request": request,
            "tr": tr,
        },
    )


@router.get("/{job_id}/download")
async def job_download_artifact(
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    _: User = Depends(current_superuser),
):
    """Download the original uploaded log file. Admin only."""
    from fastapi.concurrency import run_in_threadpool

    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    log_file = await db.get(LogFile, job.file_id)
    if not log_file:
        raise HTTPException(404, "File not found.")
    storage = get_storage()
    # exists_sync is a blocking head_object on the S3 backend — keep it off the loop
    # like the load() below it.
    if not await run_in_threadpool(storage.exists_sync, log_file.stored_filename):
        raise HTTPException(404, "File missing from storage.")
    path = await storage.load(log_file.stored_filename)
    from starlette.background import BackgroundTask as ResponseCleanup

    return FileResponse(
        path=str(path),
        filename=job.filename,
        media_type="application/octet-stream",
        # On S3 `path` is a whole-file copy in `.s3_cache`; released once it has been sent.
        background=ResponseCleanup(storage.release_sync, path),
    )


@router.get("/{job_id}/export-raw")
async def job_export_raw(
    job_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    _: User = Depends(current_superuser),
):
    """Download raw tool output files as a ZIP archive. Admin only."""
    import tempfile
    import zipfile

    from fastapi.concurrency import run_in_threadpool
    from starlette.background import BackgroundTask as BgTask

    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found.")

    storage = get_storage()
    resolved = await storage.resolve_job_outputs_dir(job_id)
    if resolved is None:
        raise HTTPException(404, "No raw output files found for this job.")
    job_dir, cleanup_dir = resolved

    # The rawest thing this application will hand you — every matched event, unredacted.
    await activity.record("export.job_raw", request=request, user=_, target_type="job", target_id=str(job_id))

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)  # noqa: SIM115  # handed to BackgroundTask; unlinked after response
    try:
        # DEFLATE over a job's whole output tree is CPU- and IO-bound; on the event loop it
        # would stall every other request for the duration — tens of seconds on a large EVTX
        # run. Offloaded like the process-tree route.
        def _build_archive() -> None:
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in sorted(job_dir.rglob("*")):
                    if path.is_file():
                        zf.write(path, str(path.relative_to(job_dir)))
            tmp.close()

        await run_in_threadpool(_build_archive)

        if os.path.getsize(tmp.name) == 0:
            os.unlink(tmp.name)
            if cleanup_dir:
                shutil.rmtree(job_dir, ignore_errors=True)
            raise HTTPException(404, "No raw output files found for this job.")

        def _cleanup() -> None:
            os.unlink(tmp.name)
            if cleanup_dir:
                shutil.rmtree(job_dir, ignore_errors=True)

        return FileResponse(
            path=tmp.name,
            filename=f"job_{job_id}_raw_results.zip",
            media_type="application/zip",
            background=BgTask(_cleanup),
        )
    except HTTPException:
        raise
    except Exception:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        if cleanup_dir:
            shutil.rmtree(job_dir, ignore_errors=True)
        raise


@router.get("/{job_id}/findings.json")
async def job_findings_json(
    job_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """Download all findings as JSON."""
    job = await _load_job_full(db, job_id, with_blobs=True)
    if not job:
        raise HTTPException(404)
    if not _can_view_private(job, user):
        raise HTTPException(404)
    await activity.record("export.job_findings", request=request, user=user, target_type="job", target_id=str(job_id))

    export = []
    for tr in job.task_results:
        for f in tr.findings:
            export.append(
                {
                    "tool": tr.tool_name,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": enum_val(f.severity),
                    "count": f.count,
                    "tags": json_loads(f.tags or "[]"),
                    "details": json_loads(f.details or "[]"),
                    "rule_signature": f.rule_signature,
                    # Detection Rule License 1.1: match output keeps the rule author.
                    "rule_author": rule_author(tr.tool_name, f.rule_id, f.rule_content),
                }
            )

    return JSONResponse(export, headers={"Content-Disposition": f"attachment; filename=job_{job_id}_findings.json"})


_ANALYTICS_SECTIONS = {
    "mitre": ["mitre_tactics"],
    "timeline": ["timeline", "timeline_tactics"],
    "entities": [
        "users",
        "computers",
        "ip_addresses",
        "hashes",
        "executables",
        "domains",
        "cmdline_files",
        "services",
        "tasks",
    ],
    "threats": ["threat_detection"],
}


@router.get("/{job_id}/analytics.json")
async def job_analytics_json(
    job_id: int,
    sections: str | None = None,
    db: AsyncSession = Depends(get_async_session),
    _: User = Depends(current_superuser),
):
    """Download cached analytics as JSON. Admin only.

    Optional ``sections`` query param: comma-separated list from
    ``mitre``, ``timeline``, ``entities``, ``threats``.
    Omit to export everything.
    """
    job = await _load_job_full(db, job_id)
    if not job:
        raise HTTPException(404)
    if not job.analytics_json:
        raise HTTPException(404, detail="Analytics not yet computed for this job.")

    data = json_loads(job.analytics_json)

    if sections:
        requested = {s.strip() for s in sections.split(",") if s.strip()}
        allowed_keys: set[str] = set()
        for sec in requested:
            allowed_keys.update(_ANALYTICS_SECTIONS.get(sec, []))
        data = {k: v for k, v in data.items() if k in allowed_keys}

    return JSONResponse(data, headers={"Content-Disposition": f"attachment; filename=job_{job_id}_analytics.json"})


@router.get("/{job_id}/events-timeline")
async def job_events_timeline(
    job_id: int,
    frm: int | None = None,
    to: int | None = None,
    resolution: int | None = None,
    severity: str = "",
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """Range query over the job's marker index, for the zoomable events timeline.

    ``frm``/``to`` are epoch **milliseconds** (what the client's axis speaks); the index
    stores seconds. No disk access and no raw re-parse — one indexed column read, a gunzip,
    and a bisect, measured at 3-5 ms.
    """
    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404)
    if not _can_view_private(job, user):
        raise HTTPException(404)

    # Query the column explicitly rather than touching ``job.event_markers``: it is
    # deferred, and a deferred attribute on a detached instance raises MissingGreenlet
    # under async SQLAlchemy.
    blob = await db.scalar(select(AnalysisJob.event_markers).where(AnalysisJob.id == job_id))
    # gunzip + orjson + slice, all CPU on a blob that can be hundreds of KB. One job is
    # cheap; the case endpoint does this per member job, and both share this call.
    from fastapi.concurrency import run_in_threadpool

    return JSONResponse(await run_in_threadpool(_events_timeline_payload, [(job_id, blob)], frm, to, resolution, severity))


def _events_timeline_payload(
    rows: list[tuple[int, bytes | None]],
    frm: int | None,
    to: int | None,
    resolution: int | None,
    severity: str = "",
) -> dict:
    """Slice one or more jobs' marker indexes into a single response body.

    Shared by the job and case endpoints so the two can never drift on units, caps or the
    palette. ``index_missing`` is a 200, not an error: jobs analysed before the index
    existed and jobs whose analytics never ran simply have no index yet, and
    ``backfill_analytics`` fills them in.

    The reply always frames on the full extent: an opening window the *server* picks is one
    the client then has to be told about and given a way out of, and that state does not
    survive a re-render — the case Timeline tab swaps this panel on every filter change.
    """
    from app.intel.event_markers import merge_sliced, slice_index, unpack_index

    severities = {s.strip().lower() for s in severity.split(",") if s.strip()} or None

    slices = []
    missing = 0
    for jid, blob in rows:
        payload = unpack_index(blob)
        if payload is None:
            missing += 1
            continue
        slices.append(
            slice_index(
                payload,
                None if frm is None else frm // 1000,
                None if to is None else -(-to // 1000),  # ceil, so the closing edge is inclusive
                resolution,
                job_id=jid,
                severities=severities,
            )
        )

    out = merge_sliced(slices)
    out["index_missing"] = not slices and missing > 0
    out["jobs_without_index"] = missing
    out["colors"] = {"severity": dict(SEVERITY_COLORS), "tactic": _tactic_color_map()}
    return out


def _tactic_color_map() -> dict[str, str]:
    """Tactic → hex, including the ``_other`` bucket the resolver falls back to."""
    return {**_MITRE_TACTIC_COLORS, _OTHER_TACTIC: _OTHER_TACTIC_COLOR}


@router.get("/{job_id}/mitre-layer")
async def job_mitre_layer(
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User | None = Depends(current_user_optional),
):
    """Export MITRE ATT&CK Navigator layer for a single job."""
    from app.routers.intel import _build_mitre_layer

    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404)
    if not _can_view_private(job, user):
        raise HTTPException(404)
    layer = await _build_mitre_layer(
        db,
        name=f"LogsTotal — Job #{job_id}",
        description=f"MITRE ATT&CK technique coverage for job #{job_id}.",
        job_ids=[job_id],
        viewer=user,
    )
    return JSONResponse(
        layer,
        headers={"Content-Disposition": f'attachment; filename="job-{job_id}-mitre-layer.json"'},
    )


@router.post("/resubmit")
async def job_resubmit(
    request: Request,
    file_id: int = Form(...),
    workflow_id: int = Form(...),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Create a new job for an already-stored file (force re-analysis)."""
    log_file = await db.get(LogFile, file_id)
    if not log_file:
        raise HTTPException(404, "File not found.")
    # A regular user can only resubmit files they previously submitted.
    if not await _can_resubmit(db, file_id, user):
        raise HTTPException(403, "Not allowed to resubmit this file.")
    workflow = await db.get(WorkflowDef, workflow_id)
    if not workflow:
        raise HTTPException(400, "Workflow not found.")
    from app.models import AnalysisJob as AJ

    # Imported from the upload router rather than lifted into app/detection/: that package
    # is deliberately dependency-free and this helper raises HTTPException.
    from app.submissions import _require_workflow_supports
    from app.workers.tasks import run_analysis

    # Submission metadata comes only from the requester's latest own job.
    source = await db.scalar(
        select(AnalysisJob)
        .where(AnalysisJob.file_id == log_file.id, AnalysisJob.submitted_by_user_id == user.id)
        .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
        .limit(1)
    )
    if source is not None:
        effective_type = source.effective_log_type
    else:
        effective_type = log_file.detected_type
        if effective_type is None:
            from fastapi.concurrency import run_in_threadpool

            from app.detection.detector import detect_log_type

            storage = get_storage()
            path = await storage.load(log_file.stored_filename)
            try:
                effective_type = await run_in_threadpool(detect_log_type, path)
            finally:
                await run_in_threadpool(storage.release_sync, path)
            log_file.detected_type = effective_type
            log_file.log_type = effective_type
    _require_workflow_supports(workflow, effective_type, "chosen")

    client_ip = get_client_ip(request)
    job = AJ(
        file_id=log_file.id,
        workflow_id=workflow_id,
        submitted_by_user_id=user.id if user else None,
        submitter_ip=client_ip,
        is_private=bool(source and source.is_private),
        submitted_filename=source.submitted_filename if source else None,
        effective_log_type=effective_type,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    try:
        run_analysis(job.id)
    except Exception:
        # The row is already committed, so an unreachable queue would otherwise leave a job
        # polling PENDING until `HUEY_QUEUE_EXPIRY` sweeps it. Same treatment as /upload:
        # fail it here, where the reason is still known.
        logger.exception("Could not enqueue analysis for job %s", job.id)
        # Only while still PENDING: an enqueue can raise after the message landed, and a
        # worker may already have claimed the job.
        await db.execute(
            update(AnalysisJob)
            .where(AnalysisJob.id == job.id, AnalysisJob.status == JobStatus.PENDING)
            .values(
                status=JobStatus.FAILED,
                error_message="The analysis could not be queued: the task queue was unreachable. Resubmit once it is back.",
                finished_at=utc_now_naive(),
            )
        )
        await db.commit()
        raise HTTPException(503, "The analysis queue is unreachable, so this file cannot be analysed right now. Try again shortly.") from None
    # Resubmit takes a file id, not a job id — the new job is the only id in scope here.
    await activity.record(
        "job.resubmit",
        request=request,
        user=user,
        target_type="job",
        target_id=str(job.id),
        summary=job.filename,
        meta={"file_id": file_id, "workflow_id": workflow_id},
    )
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


@router.post("/{job_id}/cancel")
async def job_cancel(
    job_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Cancel a pending/running job. Admins may cancel any job; users only
    jobs they submitted (anonymous submissions are admin-cancel-only)."""
    from app.redis_client import CANCEL_PREFIX, HEARTBEAT_PREFIX, cancel_flag_value, get_redis

    job = await db.get(AnalysisJob, job_id)
    if not job or not _can_view_private(job, user):
        raise HTTPException(404)
    if not user.is_superuser and (job.submitted_by_user_id is None or job.submitted_by_user_id != user.id):
        raise HTTPException(403, "Not allowed to cancel this job.")

    status = enum_val(job.status)
    if status not in ("pending", "running"):
        # Already terminal — idempotent no-op (double-click safe).
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    # Flag FIRST so the worker's watcher sees it even if the job flips
    # PENDING→RUNNING concurrently. TTL covers the max queue wait plus the
    # max clamped tool timeout plus slack.
    heartbeat_alive = False
    redis_ok = False
    try:
        r = get_redis()
        r.set(f"{CANCEL_PREFIX}{job_id}", cancel_flag_value(job), ex=settings.huey_queue_expiry + 86400 + 300)
        heartbeat_alive = bool(r.exists(f"{HEARTBEAT_PREFIX}{job_id}"))
        redis_ok = True
    except Exception:
        logger.warning("Redis unavailable while cancelling job %s", job_id, exc_info=True)

    if status == "running" and not redis_ok:
        # "No heartbeat" and "cannot read the heartbeat" are different facts. Treating an
        # unreadable one as dead would write CANCELLED while a live worker carries on and
        # overwrites the row with its own result — a cancellation undoing itself — and the
        # flag was never set, so nothing would stop the tools either.
        raise HTTPException(503, "Cannot cancel a running job while the queue backend is unreachable. Try again once Redis is back.")

    if status == "pending" or not heartbeat_alive:
        # Queued job, or a RUNNING job whose worker is gone: finalize here.
        # A RUNNING job with a live heartbeat converges via the flag within
        # seconds (its worker persists tool results and the terminal status).
        message = CANCEL_MSG_USER if status == "pending" else CANCEL_MSG_DEAD_WORKER
        # Conditional: the status read above is a snapshot. A job that finished meanwhile
        # keeps its result, and a worker that claims it after this commit sees CANCELLED.
        result = await db.execute(
            update(AnalysisJob)
            .where(AnalysisJob.id == job_id, AnalysisJob.status.in_([JobStatus.PENDING, JobStatus.RUNNING]))
            .values(status=JobStatus.CANCELLED, error_message=message, finished_at=utc_now_naive())
        )
        if result.rowcount == 1:
            # Conditional too: a worker that is still alive may commit a tool's result meanwhile.
            await db.execute(
                update(TaskResult)
                .where(TaskResult.job_id == job_id, TaskResult.status.in_([TaskStatus.PENDING, TaskStatus.RUNNING]))
                .values(status=TaskStatus.CANCELLED, error_message=message, finished_at=utc_now_naive())
            )
        await db.commit()

    await activity.record("job.cancel", request=request, user=user, target_type="job", target_id=str(job_id))
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


@router.post("/{job_id}/recalculate-analytics")
async def recalculate_analytics(
    job_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    _: User = Depends(current_superuser),
):
    """Enqueue analytics recomputation for a single job. Admin only."""
    from app.workers.tasks import recalculate_single_analytics

    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404)
    # Mark the recalc in flight BEFORE enqueuing so the job page shows the
    # polling "Computing analytics…" card; the worker clears the flag when done
    # (TTL covers a task that is never picked up).
    try:
        from app.redis_client import RECALC_PREFIX, TIMELINE_BUCKETS_PREFIX, get_redis

        r = get_redis()
        r.set(f"{RECALC_PREFIX}{job_id}", "1", ex=settings.huey_queue_expiry + 600)
        # Invalidate the case attack-timeline histogram bucket cache so a recalculated
        # job's buckets (and has_raw flag) are rebuilt on the next case Timeline view.
        r.delete(f"{TIMELINE_BUCKETS_PREFIX}{job_id}")
    except Exception:
        pass
    # Same argument for the process forest: both are parsed from the same raw output, so
    # recalculating one while serving a stale copy of the other is a view of two epochs.
    process_tree.invalidate(job_id)
    # A row so the run is visible on /admin/tasks and retryable from there, rather than
    # queued and then invisible until it finishes.
    from app.models import BackgroundTask, BackgroundTaskStatus

    bt = BackgroundTask(
        name=f"Recalculate analytics (job #{job_id})",
        kind="recalculate_single_analytics",
        target_id=str(job_id),
        requested_by_label=getattr(_, "email", None),
        status=BackgroundTaskStatus.PENDING,
    )
    db.add(bt)
    await db.commit()
    try:
        recalculate_single_analytics(job_id, bg_task_id=bt.id)
    except Exception:
        # The row is committed and the RECALC flag is set, so an unreachable queue leaves
        # the analytics panel polling "Computing analytics…" and /admin/tasks showing a
        # pending run that nothing will ever pick up.
        logger.exception("Could not enqueue analytics recalculation for job %s", job_id)
        bt.status = BackgroundTaskStatus.FAILED
        bt.error_message = "Could not be queued: the task queue was unreachable."
        bt.finished_at = utc_now_naive()
        await db.commit()
        raise HTTPException(503, "The task queue is unreachable, so analytics cannot be recalculated right now. Try again shortly.") from None
    await activity.record("job.recalculate", request=request, user=_, target_type="job", target_id=str(job_id))
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


async def _delete_job(db: AsyncSession, job: AnalysisJob) -> None:
    """Delete one job plus its dependent rows, output files, and now-orphaned upload.

    Shared by the single-job and bulk delete routes so the two can't drift on which
    child tables get cleaned.
    """
    job_id = job.id
    file_id = job.file_id
    was_live = enum_val(job.status) in ("pending", "running")

    # Stop the worker first if this job is still live. Deleting the rows does not stop
    # anything: the worker holds its own session and keeps writing into
    # `uploads/job_{id}/`, so the `delete_job_outputs_sync` below races it and whatever
    # lands after that call is leaked forever — no row references the directory anymore,
    # and `/admin/cleanup-outputs` walks jobs, not the filesystem. Setting the cancel flag
    # makes `_CancelWatcher` latch within its 2s poll and the job unwind on its own.
    if was_live:
        try:
            from app.redis_client import CANCEL_PREFIX, cancel_flag_value, get_redis

            get_redis().set(f"{CANCEL_PREFIX}{job_id}", cancel_flag_value(job), ex=settings.huey_queue_expiry + 86400 + 300)
        except Exception:
            # Redis down: the delete still proceeds. A leaked directory is recoverable;
            # refusing to delete a job because the queue backend is unreachable is not
            # what an admin clicking Delete wants.
            logger.warning("Redis unavailable while cancelling job %s before delete", job_id, exc_info=True)

    from app.ai.case_evidence import invalidate_case_sources

    await db.execute(invalidate_case_sources(job_id))
    await remove_entity_links_for_job_async(db, job_id)
    # Every FK to analysisjob.id that isn't handled above must be cleared here. None of
    # them carries ondelete=, and AnalysisJob declares no parent-side relationship to
    # them, so no cascade fires: a missed table dangles silently on SQLite (FKs off) and
    # raises ForeignKeyViolation on PostgreSQL, which makes the job undeletable and
    # aborts a bulk delete mid-batch. Comments do cascade via AnalysisJob.comments but
    # are cleared here too, so the order is explicit rather than relationship-dependent.
    # `remove_entity_links_for_job_async` covers entity_job_link and
    # entity_relationship_evidence, and taskresult cascades; that leaves the ones below.
    # tests/test_fk_cleanup_parity.py fails if a new FK to analysisjob.id appears.
    await db.execute(delete(Comment).where(Comment.job_id == job_id))
    # AnalysisJob.ai_analyses declares delete-orphan, but this is a Core delete, so no
    # ORM cascade fires — the same trap the comments line above documents.
    await db.execute(delete(JobAiAnalysis).where(JobAiAnalysis.job_id == job_id))
    await db.execute(delete(CaseJobLink).where(CaseJobLink.job_id == job_id))
    # Watch-rule alerts and their webhook attempts. IntelRuleMatch.job_id is NOT NULL, so
    # on PostgreSQL this is the one that 500s; on SQLite the orphaned rows keep the nav
    # bell's count non-zero over a dropdown that inner-joins AnalysisJob and finds nothing.
    await db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.job_id == job_id))
    # Its job-scope twin. `job_rule_match.job_id` is NOT NULL for the same reason and fails
    # the same two ways — a 500 on PostgreSQL, a bell counting alerts for a job that is gone
    # on SQLite.
    await db.execute(delete(JobRuleMatch).where(JobRuleMatch.job_id == job_id))
    await db.execute(delete(WebhookDelivery).where(WebhookDelivery.job_id == job_id))
    # Analyst tags. AnalysisJob.tags declares delete-orphan and, again, this is a Core
    # delete — the third table in this block to need saying so explicitly.
    await db.execute(delete(JobTag).where(JobTag.job_id == job_id))
    # Watch subscriptions and their unread notifications. Events first: they reference the
    # watch, and on PostgreSQL the other order is a ForeignKeyViolation.
    await db.execute(delete(JobWatchEvent).where(JobWatchEvent.job_id == job_id))
    await db.execute(delete(JobWatch).where(JobWatch.job_id == job_id))
    await db.delete(job)
    await db.commit()

    from fastapi.concurrency import run_in_threadpool

    from app.redis_client import forget_job_keys

    # After the commit: the id is free for the next insert from here on (SQLite).
    await run_in_threadpool(forget_job_keys, job_id, keep_cancel_flag=was_live)

    st = get_storage()
    # Threadpooled like job_download_artifact and job_export_raw: on the S3 backend these
    # are a paginated list_objects_v2 plus delete_objects, and a DeleteObject — blocking
    # boto3 calls. On the event loop, one bulk delete (capped at 100 jobs) would make
    # hundreds of them in a single request and stall every other caller, including the
    # 3s job-status polls and /health.
    await run_in_threadpool(st.delete_job_outputs_sync, job_id)

    # If no other jobs reference this LogFile, remove the file and DB record
    remaining = await db.scalar(select(AnalysisJob.id).where(AnalysisJob.file_id == file_id).limit(1))
    if remaining is None:
        log_file = await db.get(LogFile, file_id)
        if log_file:
            await run_in_threadpool(st.delete_sync, log_file.stored_filename)
            await db.delete(log_file)
            await db.commit()


# ── Analyst tags ─────────────────────────────────────────────────────────────
#
# Member-and-above, all four. Tagging is not a per-job annotation: applying a tag writes to
# the instance-wide vocabulary (a colour, and a `TagDefinition` row if the name is new),
# which is the same vocabulary Intel curates. Letting a `role=user` write to it would give
# the one role with no Intel access the ability to reshape what Intel sees.
#
# Every write checks `can_view_job` first. Without it, tagging is an existence oracle for
# another member's private job: the response differs between "tagged" and "no such job".


@router.post("/bulk-tag", response_class=HTMLResponse)
async def jobs_bulk_tag(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    job_ids: str = Form(""),
    tag: str = Form(...),
    color: str = Form("gray"),
):
    """Apply one or more tags to many jobs at once."""
    ids = parse_id_csv(job_ids, BULK_TAG_CAP)
    pairs = parse_tag_write(tag, color)
    if not pairs or not ids:
        raise HTTPException(400, "Tag and selection are required")

    # Visible ids only, silently — a member selecting a page that happens to include
    # someone else's private job should tag what they can see, not get a 404 naming it.
    vis = _private_filter(user)
    q = select(AnalysisJob.id).where(AnalysisJob.id.in_(ids))
    if vis is not True:
        q = q.where(vis)
    visible = set((await db.execute(q)).scalars().all())

    # `touched` is how many jobs gained something; `links` is how many rows that took. With
    # several tags per submission the two differ, and reporting rows as jobs would claim to
    # have tagged more jobs than were selected.
    touched: set[int] = set()
    links = 0
    for norm, safe_color in pairs:
        await ensure_tag_definition(db, norm, safe_color, user.id)
        await set_tag_color(db, norm, safe_color)
        already = set((await db.execute(select(JobTag.job_id).where(JobTag.tag == norm, JobTag.job_id.in_(visible)))).scalars().all())
        added = [jid for jid in ids if jid in visible and jid not in already]
        for jid in added:
            db.add(JobTag(job_id=jid, tag=norm, color=safe_color, created_by_user_id=user.id))
        touched.update(added)
        links += len(added)
    n = len(touched)
    await db.commit()

    names = ", ".join(t for t, _ in pairs)
    if n:
        # One row carrying the count, not one per job — the rule the intel.tag.* bulk
        # paths follow, so 500 jobs cannot flood the activity log.
        await activity.record(
            "job.tag.add",
            request=request,
            user=user,
            target_type="tag",
            target_id=pairs[0][0],
            summary=f"'{names}' added to {n} job{'' if n == 1 else 's'}",
            meta={"count": n, "links": links, "bulk": True, "tags": [t for t, _ in pairs]},
        )
    return HTMLResponse(f'<span class="text-xs text-green-300">Tagged {n} job{"" if n == 1 else "s"} with \u201c{escape(names)}\u201d.</span>')


@router.post("/bulk-untag", response_class=HTMLResponse)
async def jobs_bulk_untag(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    job_ids: str = Form(""),
    tag: str = Form(...),
):
    """Remove one or more tags from many jobs at once."""
    ids = parse_id_csv(job_ids, BULK_TAG_CAP)
    names = [t for t, _ in parse_tag_write(tag)]
    if not names or not ids:
        raise HTTPException(400, "Tag and selection are required")

    vis = _private_filter(user)
    q = select(AnalysisJob.id).where(AnalysisJob.id.in_(ids))
    if vis is not True:
        q = q.where(vis)
    visible = list((await db.execute(q)).scalars().all())

    result = await db.execute(delete(JobTag).where(JobTag.tag.in_(names), JobTag.job_id.in_(visible)))
    await db.commit()
    n = result.rowcount or 0
    label = ", ".join(names)
    if n:
        await activity.record(
            "job.tag.remove",
            request=request,
            user=user,
            target_type="tag",
            target_id=names[0],
            summary=f"'{label}' removed from {n} job tag{'' if n == 1 else 's'}",
            meta={"count": n, "bulk": True, "tags": names},
        )
    return HTMLResponse(f'<span class="text-xs text-green-300">Removed \u201c{escape(label)}\u201d from {n} job tag{"" if n == 1 else "s"}.</span>')


@router.post("/bulk-delete")
async def jobs_bulk_delete(
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    _: User = Depends(current_superuser),
    job_ids: list[int] = Form([]),
):
    """Delete several jobs at once from the jobs-list selection. Admin only.

    Unknown ids are skipped rather than failing the batch: the selection can go stale
    against the 5s table poll, and a half-completed 404 would be worse than a no-op.
    """
    if len(job_ids) > _BULK_DELETE_CAP:
        raise HTTPException(400, f"Too many jobs selected (max {_BULK_DELETE_CAP})")
    deleted = []
    for job_id in dict.fromkeys(job_ids):
        job = await db.get(AnalysisJob, job_id)
        if job is not None:
            await _delete_job(db, job)
            deleted.append(job_id)
    if deleted:
        await activity.record(
            "job.delete",
            request=request,
            user=_,
            target_type="job",
            target_id=",".join(str(i) for i in deleted[:8]),
            summary=f"{len(deleted)} job(s) deleted",
            meta={"job_ids": deleted},
        )
    return RedirectResponse("/jobs", status_code=303)


@router.post("/{job_id}/delete")
async def job_delete(
    job_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    _: User = Depends(current_superuser),
):
    """Delete a job, intel entity links, its results, output files, and orphaned uploads. Admin only."""
    job = await db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(404)
    await _delete_job(db, job)
    await activity.record("job.delete", request=request, user=_, target_type="job", target_id=str(job_id))
    return RedirectResponse("/jobs", status_code=303)


# ── Helpers ─────────────────────────────────────────────────────────────────────


async def _load_job_full(db: AsyncSession, job_id: int, *, with_blobs: bool = False) -> AnalysisJob | None:
    """The job with its task results and findings.

    Backs the 3-second job-status poll, so `Finding.details` and `Finding.rule_content`
    stay deferred: the page uses `details` only as a boolean (`Finding.has_details`, a
    selected expression) and `rule_content` not at all. `with_blobs=True` is for the
    exports, which genuinely serialise them.
    """
    findings_loader = selectinload(AnalysisJob.task_results).selectinload(TaskResult.findings)
    if with_blobs:
        findings_loader = findings_loader.options(undefer(Finding.details), undefer(Finding.rule_content))
    result = await db.execute(
        select(AnalysisJob)
        .where(AnalysisJob.id == job_id)
        .options(
            selectinload(AnalysisJob.log_file),
            selectinload(AnalysisJob.workflow),
            selectinload(AnalysisJob.submitter),
            # Eager, not lazy: the header renders these, and a lazy load on an async
            # session is a MissingGreenlet rather than an extra query.
            selectinload(AnalysisJob.tags),
            findings_loader,
        )
    )
    return result.scalar_one_or_none()


def _hydrate_analytics(data: dict) -> dict:
    """Add color/rgb to MITRE tactics and threat detection for template rendering."""
    tactic_counts = data.get("mitre_tactics", {})
    hydrated = dict(data)
    hydrated["mitre_tactics"] = [
        {
            "name": t,
            "count": tactic_counts.get(t, 0),
            "color": _MITRE_TACTIC_COLORS[t],
            "rgb": _hex_to_rgb(_MITRE_TACTIC_COLORS[t]),
        }
        for t in _MITRE_TACTICS
    ]

    # Key each threat-detection category and sort by severity, then by total
    td = data.get("threat_detection", {})
    if td and td.get("categories"):
        _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        hydrated_td = dict(td)
        sorted_cats = []
        for key, cat in td["categories"].items():
            hcat = dict(cat)
            hcat["key"] = key
            # No colour is added here: `_analytics.html` paints the category with
            # `sev_tab(cat.severity)` from `_severity_macros.html`. The canonical hex map, for
            # the surfaces that genuinely need one (the WebGL graph, the events timeline), is
            # `constants.SEVERITY_COLORS`.
            sorted_cats.append(hcat)
        sorted_cats.sort(key=lambda c: (_sev_rank.get(c["severity"], 99), -c["total"]))
        hydrated_td["sorted_categories"] = sorted_cats
        hydrated["threat_detection"] = hydrated_td

    return hydrated


def _group_findings(job: AnalysisJob) -> dict:
    grouped: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    for tr in job.task_results:
        for f in tr.findings:
            sev = enum_val(f.severity)
            if sev not in grouped:
                sev = "informational"
            grouped[sev].append(
                {
                    "finding": f,
                    "tool_name": tr.tool_name,
                    "has_details": bool(f.has_details),
                    "tags": json_loads(f.tags or "[]"),
                }
            )
    return grouped


def _parse_summary(job: AnalysisJob) -> dict:
    base = dict.fromkeys(SEVERITY_ORDER, 0)
    if job.severity_summary:
        try:
            base.update(json_loads(job.severity_summary))
        except (ValueError, KeyError):
            pass
    base["total"] = sum(base[k] for k in SEVERITY_ORDER)
    base["ratio"] = job.score_ratio or "—"
    return base


def _compute_live_summary(job: AnalysisJob) -> dict:
    """Build summary from currently-available findings (for in-progress jobs)."""
    base = dict.fromkeys(SEVERITY_ORDER, 0)
    total_findings = 0
    tools_with_hits = 0
    completed_tools = 0

    for tr in job.task_results:
        if is_post_processing_task(tr.tool_name):
            continue
        tr_status = enum_val(tr.status)
        if tr_status == "skipped":
            continue
        if tr_status in ("completed", "failed"):
            completed_tools += 1
        if tr.findings:
            tools_with_hits += 1
            for f in tr.findings:
                sev = enum_val(f.severity)
                base[sev] = base.get(sev, 0) + f.count
                total_findings += f.count

    total_tools = sum(1 for tr in job.task_results if not is_post_processing_task(tr.tool_name) and (enum_val(tr.status)) != "skipped")

    base["total"] = total_findings
    base["ratio"] = f"{tools_with_hits}/{total_tools}" if total_tools else "—"
    return base


def _empty_analytics() -> dict:
    """Return a minimal analytics dict for jobs with no cached analytics yet."""
    return _hydrate_analytics(
        {
            "mitre_tactics": dict.fromkeys(_MITRE_TACTICS, 0),
            "timeline": [],
            "timeline_tactics": [],
            "users": [],
            "computers": [],
            "ip_addresses": [],
            "hashes": [],
            "executables": [],
            "domains": [],
            "cmdline_files": [],
            "services": [],
            "tasks": [],
            "threat_detection": {"total_indicators": 0, "total_categories": 0, "categories": {}},
        }
    )


async def _render_job_tags(request: Request, db: AsyncSession, job: AnalysisJob, user: User | None) -> HTMLResponse:
    tags = (await db.execute(select(JobTag).where(JobTag.job_id == job.id).order_by(JobTag.tag))).scalars().all()
    return templates.TemplateResponse(
        request,
        "partials/_job_header_tags.html",
        {"request": request, "user": user, "job": job, "tags": tags, "tag_colors": TAG_COLORS},
    )


@router.post("/{job_id}/tags", response_class=HTMLResponse)
async def job_tag_add(
    request: Request,
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    tag: str = Form(...),
    color: str = Form("gray"),
):
    """Add one or more tags to a job (or recolour them); returns the header tags region.

    Same contract as `entity_tag_add`, including the part that surprises people: a tag name
    carries **one colour instance-wide**, so the submitted colour is applied to every row
    bearing that name rather than only this job's. The picker pre-fills a known tag's
    colour, so the normal flow preserves it and only a deliberate change recolours.
    """
    job = await db.get(AnalysisJob, job_id)
    if job is None or not can_view_job(job, user):
        raise HTTPException(404, "Job not found.")
    pairs = parse_tag_write(tag, color)
    if not pairs:
        raise HTTPException(400, "Tag cannot be empty")

    added: list[str] = []
    for norm, safe_color in pairs:
        await ensure_tag_definition(db, norm, safe_color, user.id)
        await set_tag_color(db, norm, safe_color)

        existing = (await db.execute(select(JobTag).where(JobTag.job_id == job.id, JobTag.tag == norm))).scalar_one_or_none()
        if existing is None:
            db.add(JobTag(job_id=job.id, tag=norm, color=safe_color, created_by_user_id=user.id))
            added.append(norm)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()  # lost an insert race; the row exists, which is what we wanted
    if added:
        names = ", ".join(added)
        await activity.record(
            "job.tag.add",
            request=request,
            user=user,
            target_type="job",
            target_id=str(job_id),
            summary=names,
            meta={"tags": added},
        )
        # Only genuine additions notify. Re-adding to change a colour is a recolour, and a
        # bell that fires on those is a bell people turn off.
        #
        # ONE event for the submission, not one per tag: a watcher wants to know the job was
        # labelled, and three bell entries from one click is the noise that teaches people to
        # ignore the bell. `ref_id` is the first new row's id, which keeps the
        # `(watch_id, kind, ref_id)` idempotency guarantee — a retried request finds the rows
        # already there, adds nothing, and so records nothing.
        fresh_rows = (await db.execute(select(JobTag).where(JobTag.job_id == job_id, JobTag.tag.in_(added)).order_by(JobTag.id))).scalars().all()
        if fresh_rows:
            event_ids = await job_watch.record_events_async(db, kind="tag", job_id=job_id, ref_id=fresh_rows[0].id, actor_user_id=user.id, summary=f"tagged '{names}'")
            await db.commit()
            # After the commit, like the comment hook: a rollback must not strand a
            # queued delivery for events that do not exist.
            await job_watch.enqueue_webhooks_async(db, job_id, event_ids)
    fresh = await db.get(AnalysisJob, job_id)
    return await _render_job_tags(request, db, fresh, user)


# Names belong in form data, never in action paths.
@router.post("/{job_id}/tags/remove", response_class=HTMLResponse)
async def job_tag_remove(
    request: Request,
    job_id: int,
    tag: str = Form(...),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Remove one tag from one job; returns the header tags region."""
    job = await db.get(AnalysisJob, job_id)
    if job is None or not can_view_job(job, user):
        raise HTTPException(404, "Job not found.")
    norm = normalize_tag(tag)
    result = await db.execute(delete(JobTag).where(JobTag.job_id == job.id, JobTag.tag == norm))
    await db.commit()
    if result.rowcount:
        await activity.record(
            "job.tag.remove",
            request=request,
            user=user,
            target_type="job",
            target_id=str(job_id),
            summary=norm,
            meta={"tag": norm},
        )
    return await _render_job_tags(request, db, job, user)


# ── Watching a job ───────────────────────────────────────────────────────────


async def _render_job_watch(request: Request, db: AsyncSession, job_id: int, user: User, *, notice: str | None = None) -> HTMLResponse:
    watching = await job_watch.is_watching_async(db, job_id, user.id)
    return templates.TemplateResponse(
        request,
        "partials/_job_watch_button.html",
        {"request": request, "user": user, "job_id": job_id, "watching": watching, "notice": notice},
    )


@router.post("/{job_id}/watch", response_class=HTMLResponse)
async def job_watch_toggle(
    request: Request,
    job_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Subscribe to, or unsubscribe from, a job's activity.

    `current_user_required`, **not** `current_member_or_above`, and that mirrors commenting
    exactly: a job thread is open to any logged-in viewer who passes `can_view_job`, and a
    watch is the notification half of the same act. Anonymous cannot watch — there would be
    nowhere to notify.
    """
    job = await db.get(AnalysisJob, job_id)
    if job is None or not can_view_job(job, user):
        raise HTTPException(404, "Job not found.")

    if await job_watch.is_watching_async(db, job_id, user.id):
        await job_watch.remove_watch_async(db, job_id, user.id)
        on = False
    else:
        on = await job_watch.ensure_watch_async(db, job_id, user.id) is not None
        if not on:
            # The per-user cap. `ensure_watch_async` stays silent for the comment path that
            # also calls it; a click on Watch has to say why nothing happened. A 200, so htmx
            # swaps it in, and no audit row: nothing changed.
            return await _render_job_watch(request, db, job_id, user, notice=f"Watch limit reached ({job_watch.JOB_WATCH_MAX_PER_USER} jobs). Stop watching another job first.")
    await db.commit()

    await activity.record(
        "job.watch",
        request=request,
        user=user,
        target_type="job",
        target_id=str(job_id),
        summary="watching" if on else "no longer watching",
        meta={"on": on},
    )
    return await _render_job_watch(request, db, job_id, user)


@router.post("/watch-events/{event_id}/ack", response_class=HTMLResponse)
async def job_watch_event_ack(
    request: Request,
    event_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Acknowledge one job-watch notification, and re-render the bell dropdown.

    A separate route from `/intel/watchlist-events/{id}/ack` rather than an overload: the
    two ids come from different tables, and letting one route guess which would turn an
    off-by-one into a cross-user acknowledgement.
    """
    from app.models import JobWatch as _Watch
    from app.models import JobWatchEvent as _Event

    row = (await db.execute(select(_Event).join(_Watch, _Watch.id == _Event.watch_id).where(_Event.id == event_id, _Watch.user_id == user.id))).scalar_one_or_none()
    # Someone else's notification is a 404, not a 403 — same reasoning as the rule-alert
    # twin: the reply must not confirm that the event exists.
    if row is None:
        raise HTTPException(404, "Notification not found.")
    if row.acknowledged_at is None:
        row.acknowledged_at = utc_now_naive()
        await db.commit()

    from app.routers.intel import render_watchlist_dropdown

    return await render_watchlist_dropdown(request, db, user)
