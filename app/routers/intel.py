"""
Intel router — entity intelligence dashboard and CTI exports.

Member-or-above on every endpoint except the two nav-bell routes
(``/watchlist-events-partial`` and ``/watchlist-events/ack-all``), which take any logged-in
user because job-watch events belong to anyone who can view a job. ``/ioc-feed``
additionally accepts a Bearer token carrying the ``ioc_feed:read`` scope.
"""

from __future__ import annotations

import csv
import io
import logging
import re
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy import String, and_, cast, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, selectinload

from app import activity, job_watch, notifications
from app.auth.api_tokens import current_user_or_api_token, principal_actor_label, principal_user
from app.auth.users import current_member_or_above, current_user_required
from app.comments import comment_counts_for
from app.config import settings
from app.constants import CASE_BACKLINK_LIMIT, ENTITY_TYPE_META, ENTITY_TYPES, SEVERITY_ORDER, TAG_COLORS
from app.constants import SEVERITY_RANK as _SEVERITY_RANK
from app.csv_utils import csv_safe
from app.database import get_async_session, utc_now_naive
from app.intel.attributes import attribute_keys
from app.intel.cases import build_entity_stix_bundle, stix_pattern
from app.intel.enrichment import get_enrichment_links
from app.intel.queries import (
    ATTR_FILTERS,
    TAG_QUERY_MAX,
    TYPE_ALIASES,
    apply_entity_filters,
    caret_token,
    escape_like,
    job_terms,
    list_terms,
    parse_query,
    parse_since,
    parse_tags_csv,
    parse_types_csv,
    post_filter,
    query_needs_post_filter,
    resolve_job_terms,
    unknown_list_errors,
)
from app.intel.tactics import build_navigator_layer
from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.models import (
    AnalysisJob,
    CaseEntityLink,
    EnrichmentService,
    Entity,
    EntityEnrichmentResult,
    EntityJobLink,
    EntityRelationship,
    EntityRelationshipEvidence,
    EntityTag,
    Finding,
    FindingEntityLink,
    IntelRule,
    IntelRuleMatch,
    InvestigationCase,
    JobRuleMatch,
    JobStatus,
    LogFile,
    SavedSearch,
    TaskResult,
    User,
    WebhookDelivery,
    severity_rank_sql,
    visible_case_filter,
    visible_job_filter,
)
from app.notifications import alert_rule_ids
from app.routers.intel_rules import ack_all_visible_alerts
from app.site_settings import get_site_settings
from app.tags import tag_rows
from app.templates_config import templates

_log = logging.getLogger(__name__)


router = APIRouter(prefix="/intel")

PAGE_SIZE = 50


def _visible_job_ids_subquery(user: User | None):
    """Subquery of ``AnalysisJob.id`` values *user* may see, or ``None`` for admins.

    Applied to every per-entity job/finding/evidence listing so members cannot
    discover other users' private-job IDs, filenames, or sample events.
    """
    vis = visible_job_filter(user)
    if vis is True:
        return None
    return select(AnalysisJob.id).where(vis)


# ─── Per-entity job scope ────────────────────────────────────────────────────────
#
# `?job=N` narrows the whole entity page — Findings, Relationships, MITRE, Graph and
# Processes — to what one job observed. It is a query param rather than client state
# because the *tab badges* are computed in `entity_detail`: a scope the server does not
# know about leaves the Findings badge reading the unfiltered total beside a filtered
# list, which is the same small lie the badge counts already exist to avoid.
#
# Authorization: every other filter on this page is a property of the entity, which is a
# global observable. A job id is a reference to someone else's submission, so an unchecked
# `?job=` would let a member probe private jobs one id at a time. The check drops the
# filter rather than 404-ing, and it collapses three distinct outcomes — the job does not
# exist, it exists but is private, it is visible but unrelated to this entity — into one
# message, so the response is not an oracle for any of them.
JOB_SCOPE_DROPPED = "That job is not available, so the job filter was ignored."

# The picker is a `<select>`, not a search box. An entity seen in thousands of jobs would
# otherwise render thousands of <option>s into every page load.
JOB_PICKER_LIMIT = 200


async def _resolve_entity_job_scope(db: AsyncSession, entity_id: int, job: int, user: User | None) -> int:
    """Return *job* if this viewer may scope this entity to it, else 0.

    Used by the tab partials, which are directly reachable. `entity_detail` itself does
    the same test against the `all_job_ids` set it already has in hand, for no extra query.
    """
    if not job:
        return 0
    stmt = select(EntityJobLink.job_id).join(AnalysisJob, AnalysisJob.id == EntityJobLink.job_id).where(EntityJobLink.entity_id == entity_id, EntityJobLink.job_id == job)
    vis = visible_job_filter(user)
    if vis is not True:
        stmt = stmt.where(vis)
    return job if await db.scalar(stmt) else 0


def _entity_findings_count_stmt(entity_id: int, job_vis, job_id: int = 0):
    """The single definition of "findings touching this entity", badge and list alike.

    Written once because the admin branch — where `job_vis` is None and the `TaskResult`
    join would otherwise be skipped — is easy to miss when a new filter arrives. The join is
    added whenever *either* reason needs it, so a scope can never apply to one and not the
    other.
    """
    if job_vis is None and not job_id:
        return select(func.count(FindingEntityLink.id)).where(FindingEntityLink.entity_id == entity_id)
    stmt = (
        select(func.count(Finding.id))
        .select_from(FindingEntityLink)
        .join(Finding, FindingEntityLink.finding_id == Finding.id)
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .where(FindingEntityLink.entity_id == entity_id)
    )
    if job_vis is not None:
        stmt = stmt.where(TaskResult.job_id.in_(job_vis))
    if job_id:
        stmt = stmt.where(TaskResult.job_id == job_id)
    return stmt


def _relationships_touching(entity_id: int, job_id: int = 0):
    """Typed edges touching *entity_id*, optionally narrowed to one job.

    `EntityRelationship` is a **cross-job aggregate** — it has no job column at all. The
    only per-job dimension is `EntityRelationshipEvidence`, and filtering through that
    would be wrong in the one direction that matters: evidence is trimmed to `EVIDENCE_CAP`
    samples and absent for an edge recorded without it, so the tab would silently drop real
    relationships.

    Co-occurrence is the honest narrowing: keep the edge when the *other* endpoint also
    appears in that job. It never hides a true edge, costs one indexed `IN`, and it is the
    same semantics the graph gives typed edges under a job scope (there the node set is
    job-scoped and `_typed_edges` runs unfiltered over it) — so the tab and the graph
    agree, which matters more here than strictness. The template says so in one line.
    """
    if not job_id:
        return or_(EntityRelationship.source_entity_id == entity_id, EntityRelationship.target_entity_id == entity_id)
    in_job = select(EntityJobLink.entity_id).where(EntityJobLink.job_id == job_id)
    return or_(
        and_(EntityRelationship.source_entity_id == entity_id, EntityRelationship.target_entity_id.in_(in_job)),
        and_(EntityRelationship.target_entity_id == entity_id, EntityRelationship.source_entity_id.in_(in_job)),
    )


# ─── Dashboard ───────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse)
async def intel_dashboard(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    job: int = 0,
):
    """Intel dashboard — entity table with stats and filters.

    `job` is the only filter this route resolves server-side: the chip needs the job's
    filename, which the client cannot know, and the id must be visibility-checked before
    it is echoed back. Every other filter is client-hydrated from the query string by the
    Alpine root.
    """
    from app.models import InvestigationCase, LogFile

    total_entities = await db.scalar(select(func.count(Entity.id))) or 0

    rows = (await db.execute(select(Entity.entity_type, func.count(Entity.id)).group_by(Entity.entity_type))).all()
    type_counts: dict[str, int] = dict(rows)

    # Both of these count rows the viewer may not be allowed to see, so they are scoped to
    # the viewer like `unacked_alerts` below — unscoped, a member would learn how many
    # private jobs and unshared cases other people hold.
    jobs_with_entities = (
        await db.scalar(select(func.count(func.distinct(EntityJobLink.job_id))).join(AnalysisJob, EntityJobLink.job_id == AnalysisJob.id).where(visible_job_filter(user)))
    ) or 0
    watchlisted_count = await db.scalar(select(func.count(Entity.id)).where(Entity.watchlist.is_(True))) or 0
    allowlisted_count = await db.scalar(select(func.count(Entity.id)).where(Entity.allowlisted.is_(True))) or 0
    cases_count = await db.scalar(select(func.count(InvestigationCase.id)).where(InvestigationCase.status != "closed", visible_case_filter(user))) or 0
    unacked_alerts = (await db.scalar(select(func.count(IntelRuleMatch.id)).where(IntelRuleMatch.rule_id.in_(alert_rule_ids(user)), IntelRuleMatch.acknowledged_at.is_(None)))) or 0

    tag_count = await db.scalar(select(func.count(func.distinct(EntityTag.tag)))) or 0
    known_tags = (await db.execute(select(EntityTag.tag).group_by(EntityTag.tag).order_by(func.count(EntityTag.id).desc()).limit(200))).scalars().all()

    # The facet panel's label chips, from the database rather than a registry: a label is
    # whatever an enabled built-in rule writes, so the panel offers `tag:<its tag>` — what a
    # rule wrote — and not `attr:<key>`, what the engine derived. Before the labels backfill
    # has run those chips honestly match nothing, which is the truth about the tags.
    builtin_rows = (
        await db.execute(
            select(IntelRule.name, IntelRule.action_tag, IntelRule.action_tag_color)
            .where(IntelRule.is_builtin.is_(True), IntelRule.enabled.is_(True), IntelRule.scope == "entity")
            .order_by(IntelRule.created_at, IntelRule.id)
        )
    ).all()
    builtin_labels = [{"tag": tag.split(",")[0].strip(), "name": name, "color": (color or "gray").split(",")[0].strip()} for name, tag, color in builtin_rows if tag]

    job_context = None
    if job:
        row = (
            await db.execute(select(AnalysisJob.id, AnalysisJob.filename).join(LogFile, AnalysisJob.file_id == LogFile.id).where(AnalysisJob.id == job, visible_job_filter(user)))
        ).first()
        if row:
            job_context = {"id": row[0], "label": row[1]}

    return templates.TemplateResponse(
        request,
        "intel/dashboard.html",
        {
            "request": request,
            "user": user,
            "job_context": job_context,
            "total_entities": total_entities,
            "type_counts": type_counts,
            "jobs_with_entities": jobs_with_entities,
            "watchlisted_count": watchlisted_count,
            "allowlisted_count": allowlisted_count,
            "cases_count": cases_count,
            "unacked_alerts": unacked_alerts,
            "entity_type_meta": ENTITY_TYPE_META,
            "tag_count": tag_count,
            "builtin_labels": builtin_labels,
            "tag_colors": TAG_COLORS,
            "known_tags": known_tags,
        },
    )


@router.get("/entities-partial", response_class=HTMLResponse)
async def entities_partial(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    entity_type: str = "",
    types: str = "",
    tags: str = "",
    q: str = "",
    sort: str = "last_seen",
    page: int = 1,
    watchlist: int = 0,
    since: str = "",
    min_jobs: int = 0,
    include_allowlisted: int = 1,
    job: int = 0,
    user: User = Depends(current_member_or_above),
):
    """HTMX partial: filtered/paginated entity table.

    Filter inputs:
      * `entity_type` — single-type back-compat; `types` (CSV) takes precedence.
      * `tags` — CSV of analyst tags, any-of. Also reachable as `q=tag:a,b`; when both
        are supplied the two lists are merged (still any-of).
      * `q` — smart parser: `tag:apt28`, `cidr:1.2.0.0/16`, `re:/<pat>/`, `term*` wildcard,
        else literal.
      * `since` — ISO date or datetime, filters by `last_seen_at >= since`.
      * `min_jobs` — only entities seen in ≥ N jobs.
      * `watchlist=1` — watchlisted entities only.
      * `include_allowlisted=0` — hide allowlisted entities (default: show).
      * `job` — only entities observed in that job.

    The `job` filter is the one input here that carries job visibility, so it is checked
    against `visible_job_filter` *before* reaching the query. Everything else on this
    dashboard is a property of the entity itself; a job id is a reference to someone
    else's submission, and an unchecked filter would let any member enumerate a private
    job's entity set one id at a time.
    """
    valid_types = set(ENTITY_TYPE_META.keys())
    type_list = parse_types_csv(types, valid_types) if types else ([entity_type] if entity_type in valid_types else [])
    parsed_q = parse_query(q)
    if list_terms(parsed_q):
        # The parser cannot know which lists exist; the box must, or a typo in `list:`
        # reads as an empty result.
        from app.intel.rule_lists import list_names

        parsed_q["errors"].extend(unknown_list_errors(parsed_q, await list_names(db)))
    since_dt = parse_since(since)

    tag_list = parse_tags_csv(tags)
    tag_terms = [t for t in parsed_q["terms"] if t.get("kind") == "tag" and not t.get("negated")]
    if tag_list and len(tag_terms) == 1:
        # `tags=` and `q=tag:` are the same filter reached two ways, and the documented
        # behaviour is a union. Merging both into `tag_list` while `apply_entity_filters`
        # also applied the `tag:` term would AND them, so the single term is folded in and
        # dropped from the conjunction: the union is applied exactly once.
        tag_list = list(dict.fromkeys([*tag_list, *tag_terms[0]["tags"]]))[:TAG_QUERY_MAX]
        parsed_q = {**parsed_q, "terms": [t for t in parsed_q["terms"] if t is not tag_terms[0]]}

    job_error: str | None = None
    if job:
        visible = await db.scalar(select(AnalysisJob.id).where(AnalysisJob.id == job, visible_job_filter(user)))
        if not visible:
            # Drop the filter rather than 404 — the table still renders, and a member
            # probing ids learns only that the filter did not apply, not whether the job
            # exists.
            job = 0
            job_error = "That job is not available, so the job filter was ignored."

    # `job:` terms inside the query string carry the same disclosure risk as `?job=` and get
    # the same check, in one round trip however many ids were named. The message deliberately
    # says nothing about whether the job exists — one that distinguished "no such job" from
    # "not yours" would be exactly the id oracle this check exists to close.
    q_job_terms = job_terms(parsed_q)
    if q_job_terms:
        wanted = {i for term in q_job_terms for i in term.get("job_ids", [])}
        rows = await db.execute(select(AnalysisJob.id).where(AnalysisJob.id.in_(wanted), visible_job_filter(user)))
        if resolve_job_terms(parsed_q, set(rows.scalars().all())):
            job_error = job_error or "Some jobs in that search are not available, so they matched nothing."

    query = select(Entity)
    query = apply_entity_filters(
        query,
        query=parsed_q,
        types=type_list or None,
        since=since_dt,
        min_jobs=max(0, min_jobs),
        watchlist_only=(watchlist == 1),
        allowlisted_visible=bool(include_allowlisted),
        tags=tag_list or None,
        job_id=job or None,
    )

    sort_map = {
        "last_seen": Entity.last_seen_at.desc(),
        "first_seen": Entity.first_seen_at.asc(),
        "jobs": Entity.job_count.desc(),
        "value": Entity.value.asc(),
        "watchlist": Entity.watchlist.desc(),
    }
    # `Entity.id` breaks ties. Every sort column here is non-unique — one analysis run
    # stamps an identical `last_seen_at` on every entity it touches — and SQL is free to
    # return tied rows in any order per query, so without a tiebreaker paging through the
    # dashboard could show a row twice and skip another.
    query = query.order_by(sort_map.get(sort, Entity.last_seen_at.desc()), Entity.id.desc())

    needs_post_filter = query_needs_post_filter(parsed_q)
    if needs_post_filter:
        # Regex/CIDR are post-filtered in Python; widen the fetch to give the filter
        # enough material, then paginate the post-filter result. Total is approximate.
        result = await db.execute(query.limit(1000))
        all_matching = post_filter(list(result.scalars().all()), parsed_q)
        total = len(all_matching)
        total_pages = max(1, -(-total // PAGE_SIZE))
        page = max(1, min(page, total_pages))
        offset = (page - 1) * PAGE_SIZE
        entities = all_matching[offset : offset + PAGE_SIZE]
    else:
        total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
        total_pages = max(1, -(-total // PAGE_SIZE))
        page = max(1, min(page, total_pages))
        offset = (page - 1) * PAGE_SIZE
        result = await db.execute(query.offset(offset).limit(PAGE_SIZE))
        entities = result.scalars().all()

    # Bulk-load tags for these entities so the table can show chips.
    entity_ids = [e.id for e in entities]
    tag_rows = (
        (await db.execute(select(EntityTag.entity_id, EntityTag.tag, EntityTag.color).where(EntityTag.entity_id.in_(entity_ids)).order_by(EntityTag.tag))).all()
        if entity_ids
        else []
    )
    tags_by_entity: dict[int, list[dict]] = defaultdict(list)
    for eid, tag, color in tag_rows:
        tags_by_entity[eid].append({"tag": tag, "color": color})

    # Tags only: a label is what a built-in rule writes as a tag, so rendering derived chips
    # as well would put `lolbin` on the row twice, once inert and once clickable.
    labels_by_entity = {
        e.id: [{"key": t["tag"], "label": t["tag"], "color": t.get("color") or "gray", "source": "tag", "token": f"tag:{t['tag']}"} for t in tags_by_entity.get(e.id, [])]
        for e in entities
    }

    # Which of these the *viewer* watches. One IN query over the page, not per row.
    watched_by_me = (
        set((await db.execute(select(IntelRule.auto_entity_id).where(IntelRule.owner_user_id == user.id, IntelRule.auto_entity_id.in_(entity_ids)))).scalars().all())
        if entity_ids
        else set()
    )

    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_table.html",
        {
            "request": request,
            "entities": entities,
            "entity_type_meta": ENTITY_TYPE_META,
            "tags_by_entity": tags_by_entity,
            "labels_by_entity": labels_by_entity,
            "watched_by_me": watched_by_me,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "current_type": entity_type,
            "current_types": ",".join(type_list),
            "current_tags": ",".join(tag_list),
            "current_q": q,
            "current_sort": sort,
            "current_watchlist": watchlist,
            "current_since": since,
            "current_min_jobs": min_jobs,
            "current_include_allowlisted": include_allowlisted,
            "current_job": job,
            "query_error": (parsed_q["errors"][0] if parsed_q["errors"] else None) or job_error,
            "query_kind": parsed_q["terms"][0]["kind"] if parsed_q["terms"] else "literal",
            "approximate_total": needs_post_filter,
        },
    )


# ─── Entity detail ───────────────────────────────────────────────────────────────

# `_SEVERITY_RANK` (imported from app.constants) is shared by the entity "Threat Context"
# panel (_compute_entity_threat_context) and the IOC feed (_build_ioc_data). Both read
# per-job threat_detection from analytics_json.

THREAT_CATEGORY_META = {
    "lolbin_usage": {"label": "LOLBin Usage", "color": "orange"},
    "cmdline_obfuscation": {"label": "Command-Line Obfuscation", "color": "yellow"},
    "credential_access": {"label": "Credential Access", "color": "red"},
    "suspicious_network": {"label": "Suspicious Network", "color": "green"},
    "execution_anomalies": {"label": "Execution Anomalies", "color": "purple"},
    "persistence": {"label": "Persistence Mechanisms", "color": "indigo"},
    "defense_evasion": {"label": "Defense Evasion", "color": "cyan"},
    "data_staging": {"label": "Data Staging & Exfiltration", "color": "rose"},
    "typosquatting": {"label": "Typosquatting", "color": "amber"},
}


async def _compute_entity_threat_context(
    db: AsyncSession,
    job_ids: list[int],
) -> dict:
    """Aggregate threat detection categories from linked jobs' analytics_json."""
    if not job_ids:
        return {"categories": [], "max_severity": "", "total_indicators": 0}

    result = await db.execute(select(AnalysisJob.id, AnalysisJob.analytics_json).where(AnalysisJob.id.in_(job_ids)).where(AnalysisJob.analytics_json.isnot(None)))
    cat_counts: dict[str, int] = Counter()
    cat_severities: dict[str, str] = {}
    total_indicators = 0
    max_sev = "informational"

    for _jid, aj in result.all():
        try:
            data = json_loads(aj)
        except (ValueError, TypeError):
            continue
        td = data.get("threat_detection", {})
        if not td or not td.get("categories"):
            continue
        for cat_key, cat in td["categories"].items():
            if cat.get("indicators"):
                cat_counts[cat_key] += 1
                total_indicators += cat.get("total", len(cat["indicators"]))
                s = cat.get("severity", "informational")
                if _SEVERITY_RANK.get(s, 99) < _SEVERITY_RANK.get(cat_severities.get(cat_key, "informational"), 99):
                    cat_severities[cat_key] = s
                if _SEVERITY_RANK.get(s, 99) < _SEVERITY_RANK.get(max_sev, 99):
                    max_sev = s

    categories = []
    for cat_key in sorted(cat_counts, key=lambda k: (-cat_counts[k], k)):
        meta = THREAT_CATEGORY_META.get(cat_key, {"label": cat_key, "color": "gray"})
        categories.append(
            {
                "key": cat_key,
                "label": meta["label"],
                "color": meta["color"],
                "severity": cat_severities.get(cat_key, "informational"),
                "job_count": cat_counts[cat_key],
            }
        )

    return {
        "categories": categories,
        "max_severity": max_sev if cat_counts else "",
        "total_indicators": total_indicators,
    }


@router.get("/entities/{entity_id}", response_class=HTMLResponse)
async def entity_detail(
    request: Request,
    entity_id: int,
    job: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Entity investigation page: co-occurring entities, linked jobs, enrichment links.

    `job` narrows the tabbed half of the page to one job — see the job-scope block near
    `_resolve_entity_job_scope`. The Overview half (co-occurring entities, threat context,
    linked cases) deliberately stays global: those are the entity's history, and scoping
    them would leave the page with no unscoped view of the entity at all.
    """
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")

    job_vis = _visible_job_ids_subquery(user)
    link_stmt = select(EntityJobLink).where(EntityJobLink.entity_id == entity_id)
    if job_vis is not None:
        link_stmt = link_stmt.where(EntityJobLink.job_id.in_(job_vis))
    link_result = await db.execute(link_stmt.options(selectinload(EntityJobLink.job)).order_by(EntityJobLink.job_id.desc()).limit(PAGE_SIZE))
    job_links = link_result.scalars().all()

    job_ids = [jl.job_id for jl in job_links]
    log_files_map: dict[int, str] = {}
    if job_ids:
        lf_result = await db.execute(select(AnalysisJob.id, AnalysisJob.filename).join(LogFile, AnalysisJob.file_id == LogFile.id).where(AnalysisJob.id.in_(job_ids)))
        log_files_map = dict(lf_result.all())

    # Scoped through `job_vis` like the paged list above: this set drives the co-occurring
    # entities and the Threat Context card, both of which would otherwise summarise jobs
    # the viewer cannot open.
    all_job_ids_stmt = select(EntityJobLink.job_id).where(EntityJobLink.entity_id == entity_id)
    if job_vis is not None:
        all_job_ids_stmt = all_job_ids_stmt.where(EntityJobLink.job_id.in_(job_vis))
    all_job_ids = [row[0] for row in (await db.execute(all_job_ids_stmt)).all()]

    # `all_job_ids` is already both visibility-scoped and entity-scoped, so membership in
    # it is the whole authorization check for `?job=` — no second round trip, and a
    # private job, a deleted job and an unrelated job are indistinguishable in the reply.
    job_error: str | None = None
    if job and job not in set(all_job_ids):
        job = 0
        job_error = JOB_SCOPE_DROPPED

    # One job means "all jobs" and "that job" are the same picture, and the Graph tab refuses
    # to draw unscoped — so the picker is a dead click that hides a whole tab behind it. Land
    # on the scope instead, and let the URL say so.
    #
    # The guard is `?job=` being *absent*, not `job` being falsy, and it carries three jobs at
    # once: a supplied-but-dropped job keeps its `job_error` instead of being redirected out
    # from under the message, `?job=0` stays an explicit "show me everything" escape hatch, and
    # every test that asserts a private job is indistinguishable from a nonexistent one passes
    # `?job=` explicitly and so can never reach this branch.
    if request.query_params.get("job") is None and len(all_job_ids) == 1:
        return RedirectResponse(f"/intel/entities/{entity_id}?job={all_job_ids[0]}", status_code=303)

    co_occurring = []
    if all_job_ids:
        co_query = (
            select(
                Entity.id,
                Entity.value,
                Entity.entity_type,
                func.count(func.distinct(EntityJobLink.job_id)).label("shared"),
            )
            .join(EntityJobLink, Entity.id == EntityJobLink.entity_id)
            .where(
                EntityJobLink.job_id.in_(all_job_ids),
                Entity.id != entity_id,
            )
            .group_by(Entity.id, Entity.value, Entity.entity_type)
            .order_by(func.count(func.distinct(EntityJobLink.job_id)).desc())
            .limit(40)
        )
        co_result = await db.execute(co_query)
        co_occurring = co_result.all()

    threat_context = await _compute_entity_threat_context(db, all_job_ids)

    total_jobs_stmt = select(func.count(EntityJobLink.id)).where(EntityJobLink.entity_id == entity_id)
    if job_vis is not None:
        total_jobs_stmt = total_jobs_stmt.where(EntityJobLink.job_id.in_(job_vis))
    total_jobs = await db.scalar(total_jobs_stmt) or 0
    total_pages = max(1, -(-total_jobs // PAGE_SIZE))

    enrichment_urls = await get_enrichment_links(db, entity.entity_type, entity.value)

    tags = (await db.execute(select(EntityTag).where(EntityTag.entity_id == entity_id).order_by(EntityTag.tag))).scalars().all()
    # Counted the same way the tab counts its rows — one statement builder, carrying the job
    # scope — so the badge and the list cannot disagree.
    findings_total = await db.scalar(_entity_findings_count_stmt(entity_id, job_vis, job)) or 0
    relationships_total = await db.scalar(select(func.count(EntityRelationship.id)).where(_relationships_touching(entity_id, job))) or 0

    associated_groups = await _fetch_associated_groups(db, entity_id, entity.entity_type) if relationships_total else []

    # "In these cases" backlinks. `visible_case_filter` keeps an unshared case owned by
    # another member out of the list — the case name itself is the thing worth hiding.
    case_stmt = (
        select(InvestigationCase)
        .join(CaseEntityLink, CaseEntityLink.case_id == InvestigationCase.id)
        .where(CaseEntityLink.entity_id == entity_id)
        .order_by(InvestigationCase.updated_at.desc())
        .limit(CASE_BACKLINK_LIMIT)
    )
    case_vis = visible_case_filter(user)
    if case_vis is not True:
        case_stmt = case_stmt.where(case_vis)
    member_cases = (await db.execute(case_stmt)).scalars().all()

    comment_count = (await comment_counts_for(db, "entity", [entity_id])).get(entity_id, 0)
    site_settings = await get_site_settings(db)
    tabs = _build_entity_tabs(entity, findings_total, relationships_total, comment_count, show_process_tree=bool(site_settings.show_process_tree))

    # Options for the job-scope picker. Bounded, and newest first — an entity seen in
    # thousands of jobs must not render thousands of <option>s. If the active scope falls
    # outside that window it is prepended, so a deep link never renders a picker that
    # disagrees with the page it is on.
    picker_stmt = (
        select(AnalysisJob.id, AnalysisJob.filename)
        .join(LogFile, AnalysisJob.file_id == LogFile.id)
        .join(EntityJobLink, EntityJobLink.job_id == AnalysisJob.id)
        .where(EntityJobLink.entity_id == entity_id)
        .order_by(AnalysisJob.id.desc())
        .limit(JOB_PICKER_LIMIT)
    )
    if job_vis is not None:
        picker_stmt = picker_stmt.where(AnalysisJob.id.in_(job_vis))
    job_options = [{"id": jid, "filename": name} for jid, name in (await db.execute(picker_stmt)).all()]
    if job and job not in {o["id"] for o in job_options}:
        job_options.insert(0, {"id": job, "filename": log_files_map.get(job, "")})

    watching_this = (await db.scalar(select(func.count(IntelRule.id)).where(IntelRule.owner_user_id == user.id, IntelRule.auto_entity_id == entity.id))) or 0
    return templates.TemplateResponse(
        request,
        "intel/entity.html",
        {
            "request": request,
            "user": user,
            "entity": entity,
            "tags": tags,
            "findings_total": findings_total,
            "tag_colors": TAG_COLORS,
            "job_links": job_links,
            "log_files_map": log_files_map,
            "co_occurring": co_occurring,
            "entity_type_meta": ENTITY_TYPE_META,
            "page": 1,
            "total_pages": total_pages,
            "enrichment_urls": enrichment_urls,
            "threat_context": threat_context,
            "watching": watching_this,
            # Overview tab: what the attribute engine derived, as `attr:` keys. The header
            # renders this entity's *tags* — what a rule wrote — and the gap between the
            # two is the diagnosis (see `attribute_keys`).
            "attribute_keys": attribute_keys(entity.attributes_json),
            "associated_groups": associated_groups,
            "member_cases": member_cases,
            "tabs": tabs,
            "job": job,
            "job_error": job_error,
            "job_options": job_options,
            "job_total": len(all_job_ids),
            "job_picker_limit": JOB_PICKER_LIMIT,
            "site_settings": site_settings,
        },
    )


def _build_entity_tabs(
    entity: Entity,
    findings_total: int,
    relationships_total: int = 0,
    comment_count: int = 0,
    *,
    show_process_tree: bool = True,
) -> list[dict]:
    """Assemble the entity-detail tab list.

    Each tab is a dict: key, label, icon (a glyph name `tab_icon()` knows), badge (None or
    int), and optional lazy_event (for HTMX lazy-load partials).

    The Discussions badge counts comments. The analyst note lives on Overview; this tab is
    the conversation alone, matching the job page.

    **Processes appears only for entity types a lineage node can actually match** — see
    `lineage.PROCESS_TREE_ENTITY_TYPES`. An `ip_address` has no corresponding node field,
    so it gets no tab rather than a tab that permanently reads "not applicable".
    `show_process_tree` mirrors the site setting: an admin who turned the job-page panel
    off should not get it back through a side door. Keyword-only with a default so
    positional call sites stay unchanged.
    """
    from app.intel.lineage import PROCESS_TREE_ENTITY_TYPES

    tabs = [
        {"key": "overview", "label": "Overview", "badge": None, "lazy_event": None, "icon": "info"},
        {"key": "findings", "label": "Findings", "badge": findings_total, "lazy_event": "loadFindings", "icon": "shield"},
        {"key": "relationships", "label": "Relationships", "badge": relationships_total, "lazy_event": "loadRelationships", "icon": "link"},
        {"key": "mitre", "label": "MITRE", "badge": None, "lazy_event": "loadMitre", "icon": "grid"},
    ]
    if show_process_tree and entity.entity_type in PROCESS_TREE_ENTITY_TYPES:
        tabs.append({"key": "processes", "label": "Processes", "badge": None, "lazy_event": "loadProcesses", "icon": "tree"})
    tabs.append({"key": "graph", "label": "Graph", "badge": None, "lazy_event": "loadGraph", "icon": "graph"})
    tabs.append({"key": "discussion", "label": "Discussions", "badge": comment_count or None, "lazy_event": "loadComments", "icon": "chat"})
    return tabs


@router.get("/entities/{entity_id}/jobs-partial", response_class=HTMLResponse)
async def entity_jobs_partial(
    request: Request,
    entity_id: int,
    page: int = 1,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """HTMX partial: paginated jobs linked to an entity."""
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404)

    job_vis = _visible_job_ids_subquery(user)
    total_stmt = select(func.count(EntityJobLink.id)).where(EntityJobLink.entity_id == entity_id)
    if job_vis is not None:
        total_stmt = total_stmt.where(EntityJobLink.job_id.in_(job_vis))
    total = await db.scalar(total_stmt) or 0
    total_pages = max(1, -(-total // PAGE_SIZE))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * PAGE_SIZE

    link_stmt = select(EntityJobLink).where(EntityJobLink.entity_id == entity_id)
    if job_vis is not None:
        link_stmt = link_stmt.where(EntityJobLink.job_id.in_(job_vis))
    link_result = await db.execute(link_stmt.options(selectinload(EntityJobLink.job)).order_by(EntityJobLink.job_id.desc()).offset(offset).limit(PAGE_SIZE))
    job_links = link_result.scalars().all()

    job_ids = [jl.job_id for jl in job_links]
    log_files_map: dict[int, str] = {}
    if job_ids:
        lf_result = await db.execute(select(AnalysisJob.id, AnalysisJob.filename).join(LogFile, AnalysisJob.file_id == LogFile.id).where(AnalysisJob.id.in_(job_ids)))
        log_files_map = dict(lf_result.all())

    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_jobs.html",
        {
            "request": request,
            "entity": entity,
            "job_links": job_links,
            "log_files_map": log_files_map,
            "page": page,
            "total_pages": total_pages,
        },
    )


# ─── Findings for one job, from the Intel side ───────────────────────────────────

# Entity chips per finding row. Six is what fits on one line beside the rule name at the
# narrowest supported width; the exact overflow count is reported rather than a "…".
_FINDING_ENTITY_CHIPS = 6


async def _entity_chips_for_findings(db: AsyncSession, finding_ids: list[int]) -> dict[int, tuple[list, int]]:
    """`{finding_id: ([top entities], overflow_count)}` in ONE query for the whole page.

    A chip list per row is the obvious shape and the wrong query: fifty findings would be
    fifty round trips. The windowed form is the same idiom `_fetch_associated_groups`
    already uses here — `ROW_NUMBER()` for the top-N and `COUNT()` for the true total,
    both partitioned by finding, so the "+N more" is exact rather than a guess.

    Entity rows carry no per-job visibility of their own; the caller has already
    established that this job is visible, and a finding's entities are part of it.
    """
    if not finding_ids:
        return {}
    rn = func.row_number().over(partition_by=FindingEntityLink.finding_id, order_by=(Entity.job_count.desc(), Entity.id)).label("rn")
    total = func.count().over(partition_by=FindingEntityLink.finding_id).label("total")
    sub = (
        select(FindingEntityLink.finding_id.label("fid"), Entity.id.label("eid"), Entity.value.label("value"), Entity.entity_type.label("etype"), rn, total)
        .join(Entity, Entity.id == FindingEntityLink.entity_id)
        .where(FindingEntityLink.finding_id.in_(finding_ids))
        .subquery()
    )
    rows = (await db.execute(select(sub.c.fid, sub.c.eid, sub.c.value, sub.c.etype, sub.c.total).where(sub.c.rn <= _FINDING_ENTITY_CHIPS).order_by(sub.c.fid, sub.c.rn))).all()

    out: dict[int, tuple[list, int]] = {}
    for fid, eid, value, etype, tot in rows:
        chips, _ = out.setdefault(fid, ([], 0))
        chips.append({"id": eid, "value": value, "entity_type": etype})
        out[fid] = (chips, max(0, int(tot) - _FINDING_ENTITY_CHIPS))
    return out


@router.get("/jobs/{job_id}/findings", response_class=HTMLResponse)
async def job_findings_page(
    request: Request,
    job_id: int,
    page: int = 1,
    severity: str = "",
    entity_id: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Every finding in one job, with the entities each one touched.

    Deliberately *not* a second job page. `/jobs/{id}` already renders the findings
    grouped by severity with rule and event expanders, and it is linked from the header
    here in the first position. What this page adds is the thing Intel knows and the job
    page does not: which entities each finding resolved to, as chips that pivot straight
    back into Intel. A flat paged list rather than severity accordions, because the point
    is scanning a job's findings against an entity, not triaging by severity.
    """
    job = (
        await db.execute(
            select(AnalysisJob).options(selectinload(AnalysisJob.log_file), selectinload(AnalysisJob.workflow)).where(AnalysisJob.id == job_id, visible_job_filter(user))
        )
    ).scalar_one_or_none()
    # One message: a private job and a nonexistent one must look the same from here.
    if not job:
        raise HTTPException(404, "Job not found")

    focus = await db.get(Entity, entity_id) if entity_id else None

    base = select(Finding.id).join(TaskResult, Finding.task_result_id == TaskResult.id).where(TaskResult.job_id == job_id)
    if severity in SEVERITY_ORDER:
        base = base.where(Finding.severity == severity)
    if entity_id:
        base = base.where(Finding.id.in_(select(FindingEntityLink.finding_id).where(FindingEntityLink.entity_id == entity_id)))

    total = await db.scalar(select(func.count()).select_from(base.subquery())) or 0
    total_pages = max(1, -(-total // PAGE_SIZE))
    page = max(1, min(page, total_pages))

    rows_stmt = (
        select(
            Finding.id,
            Finding.rule_id,
            Finding.rule_name,
            Finding.severity,
            Finding.count,
            TaskResult.tool_name,
            TaskResult.job_id.label("job_id"),
            # Same column, same reason, as `entity_findings_partial`: a boolean, not the blob.
            Finding.has_details,
        )
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .where(Finding.id.in_(base))
        .order_by(severity_rank_sql(), Finding.rule_name.asc(), Finding.id.asc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    )
    findings = (await db.execute(rows_stmt)).all()
    chips = await _entity_chips_for_findings(db, [f.id for f in findings])

    return templates.TemplateResponse(
        request,
        "intel/job_findings.html",
        {
            "request": request,
            "user": user,
            "job": job,
            "findings": findings,
            "chips": chips,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "severity": severity if severity in SEVERITY_ORDER else "",
            "severities": SEVERITY_ORDER,
            "entity_id": entity_id,
            "focus": focus,
        },
    )


# ─── Entity workbench: watchlist, allowlist ──────────────────────────────────


@router.post("/entities/{entity_id}/watchlist", response_class=HTMLResponse)
async def entity_watchlist_toggle(
    request: Request,
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Watch this entity — a one-click shortcut for a personal watch rule.

    The star creates a rule owned by the clicking user, so "watch this entity" and "watch
    anything matching this" are the same feature, alerts and acknowledgement are per-user,
    and the rule it makes is visible and editable on /intel/rules like any other.

    `Entity.watchlist` is maintained purely as the derived "somebody is watching this" flag
    that the graph highlight, the star column, `sort=watchlist` and the IOC feed read. It is
    cleared only when the *last* rule watching the entity goes away.
    """
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")

    mine = (await db.execute(select(IntelRule).where(IntelRule.owner_user_id == user.id, IntelRule.auto_entity_id == entity.id))).scalar_one_or_none()

    if mine is not None:
        await db.execute(delete(WebhookDelivery).where(WebhookDelivery.rule_id == mine.id))
        await db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.rule_id == mine.id))
        await db.delete(mine)
        await db.flush()
        watching = False
    else:
        owned = await db.scalar(select(func.count(IntelRule.id)).where(IntelRule.owner_user_id == user.id)) or 0
        if owned >= settings.watch_rules_max_per_user:
            raise HTTPException(400, f"You already have {owned} watch rules (max {settings.watch_rules_max_per_user}).")
        db.add(
            IntelRule(
                name=entity.value[:120],
                description="Created by the Watch button on the entity page.",
                owner_user_id=user.id,
                auto_entity_id=entity.id,
                # A quoted literal is exactly what the search box would produce, so the rule
                # reads the same as a query the analyst could have typed — and stays editable.
                query=f'"{entity.value}"'[:500],
                entity_types=json_dumps([entity.entity_type]),
            )
        )
        await db.flush()
        watching = True

    still_watched = await db.scalar(select(func.count(IntelRule.id)).where(IntelRule.auto_entity_id == entity.id)) or 0
    entity.watchlist = still_watched > 0
    await db.commit()

    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_watchlist_button.html",
        {"request": request, "entity": entity, "watching": watching},
    )


@router.post("/entities/{entity_id}/allowlist", response_class=HTMLResponse)
async def entity_allowlist_toggle(
    request: Request,
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    _user: User = Depends(current_member_or_above),
):
    """Toggle the allowlist flag. Allowlisted entities are suppressed from /intel/ioc-feed and
    the TAXII feed, excluded by default from the relationship graph and the case entity
    pickers/pivots, and rendered muted on the dashboard — but never hidden from listings."""
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")
    entity.allowlisted = not bool(entity.allowlisted)
    await db.commit()
    # Allowlisting suppresses an entity from the IOC feed, so it changes what leaves the
    # instance — the reason it belongs in the log rather than being a display preference.
    await activity.record(
        "intel.entity.allowlist",
        request=request,
        user=_user,
        target_type="entity",
        target_id=str(entity.id),
        summary=f"{entity.value} {'allowlisted' if entity.allowlisted else 'un-allowlisted'}",
    )
    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_allowlist_button.html",
        {"request": request, "entity": entity},
    )


# ─── Watchlist events (nav bell) ─────────────────────────────────────────────


@router.get("/watchlist-events-partial", response_class=HTMLResponse)
async def watchlist_events_partial(
    request: Request,
    count_only: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Bell counter (count_only=1) or the dropdown, over *both* alert streams.

    `current_user_required`, not member-or-above, since job-watch events belong to anyone
    who can view a job. Relaxing it exposes nothing new on the rule side: those are scoped
    to rules the user owns, and a non-member owns none by construction.

    The route names keep the `watchlist` spelling so bookmarks and the pinned route table
    hold. The union itself lives
    in `app/notifications.py` — both this router and `/jobs` acknowledge into it.
    """
    if count_only == 1:
        return HTMLResponse(str(await notifications.unacked_total(db, user)))
    return await render_watchlist_dropdown(request, db, user)


async def render_watchlist_dropdown(request: Request, db: AsyncSession, user: User) -> HTMLResponse:
    """The dropdown itself. Also the reply to acknowledging from either stream, so one
    click leaves both halves consistent rather than only the one that was touched."""
    items = await notifications.dropdown_items(db, user)
    return templates.TemplateResponse(
        request,
        "intel/partials/_watchlist_events_dropdown.html",
        {
            "request": request,
            "user": user,
            "items": items,
            "total": await notifications.unacked_total(db, user),
            "limit": notifications.DROPDOWN_LIMIT,
            "entity_type_meta": ENTITY_TYPE_META,
        },
    )


@router.post("/watchlist-events/{event_id}/ack", response_class=HTMLResponse)
async def watchlist_event_ack(
    request: Request,
    event_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Acknowledge one alert from the nav bell. The `watchlist` path is kept so bookmarked
    partials keep working; the row it touches is an `intel_rule_match`."""
    row = (await db.execute(select(IntelRuleMatch).where(IntelRuleMatch.id == event_id, IntelRuleMatch.rule_id.in_(alert_rule_ids(user))))).scalar_one_or_none()
    if row is None:
        # A match on someone else's rule 404s rather than 403s — the same
        # existence-oracle discipline the rest of Intel uses.
        raise HTTPException(404, "Alert not found")
    row.acknowledged_at = func.now()
    row.acknowledged_by_user_id = user.id
    await db.commit()
    return await render_watchlist_dropdown(request, db, user)


@router.post("/watchlist-events/job-rule/{match_id}/ack", response_class=HTMLResponse)
async def watchlist_job_rule_ack(
    request: Request,
    match_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """The bell's ack for a job-rule alert.

    A separate route from `intel_rules.rule_job_alert_ack` even though the write is
    identical, and for the reason the two streams beside it already have separate routes:
    **what comes back differs**. The Rules page swaps `#rules-region`; the bell swaps
    `#watchlist-events-list`. Pointing the dropdown at the page's route would put a whole
    rules section inside the dropdown.
    """
    row = (await db.execute(select(JobRuleMatch).where(JobRuleMatch.id == match_id, JobRuleMatch.rule_id.in_(alert_rule_ids(user))))).scalar_one_or_none()
    if row is None:
        # Same existence-oracle discipline as its entity twin above.
        raise HTTPException(404, "Alert not found")
    row.acknowledged_at = func.now()
    row.acknowledged_by_user_id = user.id
    await db.commit()
    return await render_watchlist_dropdown(request, db, user)


@router.post("/watchlist-events/ack-all", response_class=HTMLResponse)
async def watchlist_events_ack_all(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Acknowledge everything in the bell — *both* streams, never anyone else's.

    Two writes, one per stream, and that asymmetry with the Rules page's own ack-all is
    deliberate: this button is over a dropdown that shows both kinds, so clearing only the
    rule half would leave a badge the user just pressed "clear" on. The Rules page's button
    stays rule-only for the mirror-image reason — it never displayed a job event, so it must
    not silently discard one.
    """
    acked = await ack_all_visible_alerts(db, user)
    acked += await job_watch.ack_all_job_watch_events(db, user)
    await db.commit()
    # The bell and the Rules page share the write and the record, so an acknowledgement
    # looks the same in the log wherever it was made.
    await activity.record("intel.watch_alert.ack", request=request, user=user, summary=f"{acked} alert(s) acknowledged", meta={"count": acked, "bulk": True, "via": "bell"})
    return await render_watchlist_dropdown(request, db, user)


_SAVED_SEARCH_NAME_MAX = 120
_SAVED_SEARCH_JSON_MAX = 4000


def _visible_saved_searches(stmt, user: User):
    if user.is_superuser:
        return stmt
    return stmt.where((SavedSearch.created_by_user_id == user.id) | (SavedSearch.is_shared.is_(True)))


@router.get("/saved-searches-partial", response_class=HTMLResponse)
async def saved_searches_partial(
    request: Request,
    scope: str = "entities",
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Return a dropdown of saved searches available to the user."""
    stmt = _visible_saved_searches(select(SavedSearch), user).where(SavedSearch.scope == scope).order_by(SavedSearch.updated_at.desc()).limit(50)
    searches = (await db.execute(stmt)).scalars().all()
    return templates.TemplateResponse(
        request,
        "intel/partials/_saved_searches_dropdown.html",
        {"request": request, "searches": searches, "scope": scope, "user": user},
    )


@router.post("/saved-searches")
async def saved_search_create(
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    name: str = Form(...),
    scope: str = Form("entities"),
    query_json: str = Form(...),
    is_shared: int = Form(0),
):
    """Persist the current filter state as a named search."""
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Name is required")
    if len(name) > _SAVED_SEARCH_NAME_MAX:
        raise HTTPException(400, f"Name too long (max {_SAVED_SEARCH_NAME_MAX} chars)")
    if scope not in {"entities"}:
        raise HTTPException(400, "Invalid scope")
    if len(query_json) > _SAVED_SEARCH_JSON_MAX:
        raise HTTPException(400, "Query payload too large")
    try:
        parsed = json_loads(query_json)
        if not isinstance(parsed, dict):
            raise ValueError("must be a JSON object")
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, f"Invalid query_json: {exc}") from exc
    search = SavedSearch(
        name=name,
        scope=scope,
        query_json=json_dumps(parsed),
        created_by_user_id=user.id,
        is_shared=bool(is_shared),
    )
    db.add(search)
    await db.commit()
    await db.refresh(search)
    return JSONResponse({"id": search.id, "name": search.name, "query": parsed, "is_shared": search.is_shared})


@router.delete("/saved-searches/{search_id}")
async def saved_search_delete(
    search_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Delete a saved search. Only the owner (or an admin) can delete."""
    search = await db.get(SavedSearch, search_id)
    if not search:
        raise HTTPException(404, "Saved search not found")
    if not user.is_superuser and search.created_by_user_id != user.id:
        raise HTTPException(403, "Not your saved search")
    await db.delete(search)
    await db.commit()
    return JSONResponse({"deleted": search_id})


_SUGGEST_LIMIT = 20

# What each completable prefix is for, shown beside it while the analyst is still typing
# the key. Ordered as offered.
_PREFIX_HELP = (
    ("tag:", "your analyst tags"),
    ("type:", "entity type"),
    ("job:", "entities seen in a job"),
    ("label:", "tags and derived attributes"),
    ("attr:", "derived attribute only"),
    ("list:", "in a named list"),
    ("cidr:", "IPs inside any of these networks"),
    ("re:/", "regular expression"),
)


def _suggest_payload(token: dict, items: list[dict]) -> dict:
    """Wrap suggestions with the span the client must replace."""
    return {"start": token["start"], "end": token["end"], "prefix": token["prefix"], "suggestions": items[:_SUGGEST_LIMIT]}


def _completion(token: dict, value: str, *, label: str, detail: str = "") -> dict:
    """Build one completion, preserving the analyst's negation and any earlier CSV values.

    `tag:`, `type:` and `job:` are all any-of, so completing `tag:a,b` must extend the list
    rather than replace it — otherwise picking a second value silently discards the first.
    """
    typed = token["text"]
    neg = "-" if typed.startswith("-") else ""
    kept = token["fragment"].rsplit(",", 1)[0] + "," if "," in token["fragment"] else ""
    return {"insert": f"{neg}{token['prefix']}{kept}{value}", "label": label, "detail": detail}


@router.get("/search-suggest")
async def search_suggest(
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    q: str = "",
    pos: int = 0,
):
    """Completions for the term under the caret in the Intel search box.

    The caret parsing lives in `queries.caret_token`, on the same scanner the parser uses,
    so the dropdown cannot disagree with the grammar about where a term starts and ends —
    `re:/^svc a/` is one token, `(tag:a` is a group plus a term, and editing mid-query
    replaces only the term being edited.

    `job:` completions run through `visible_job_filter`. A list that named jobs the viewer
    cannot open would be precisely the enumeration oracle the `job:` term itself is careful
    to avoid, only served up unprompted.
    """
    token = caret_token(q, pos)
    prefix, fragment = token["prefix"], token["fragment"]
    # Only the last value of a CSV is being typed; the earlier ones are already committed.
    needle = fragment.rsplit(",", 1)[-1].strip().lower()

    if prefix is None:
        typed = needle
        items = [{"insert": p, "label": p, "detail": help_text} for p, help_text in _PREFIX_HELP if not typed or p.startswith(typed)]
        return JSONResponse(_suggest_payload(token, items))

    if prefix == "tag:":
        rows = await tag_rows(db, needle, "count", limit=_SUGGEST_LIMIT)
        items = [_completion(token, r["tag"], label=r["tag"], detail=f"{r['count']} {'entity' if r['count'] == 1 else 'entities'}") for r in rows]
        return JSONResponse(_suggest_payload(token, items))

    if prefix == "type:":
        items = [_completion(token, t, label=t, detail=ENTITY_TYPE_META[t]["label"]) for t in ENTITY_TYPES if needle in t]
        return JSONResponse(_suggest_payload(token, items))

    if prefix == "attr:":
        items = [_completion(token, k, label=k, detail="attribute") for k in sorted(ATTR_FILTERS) if needle in k]
        return JSONResponse(_suggest_payload(token, items))

    if prefix == "label:":
        # One vocabulary, so the picker shows both halves of it. Concatenated, the attribute
        # keys would fill the whole budget and hide the analyst's own tags, so the budget is
        # split and either side may use what the other does not need. The attribute half is
        # every key `label:` can resolve (`ATTR_FILTERS`).
        system = [_completion(token, k, label=k, detail="attribute") for k in sorted(ATTR_FILTERS) if needle in k]
        rows = await tag_rows(db, needle, "count", limit=_SUGGEST_LIMIT)
        tags = [_completion(token, r["tag"], label=r["tag"], detail=f"tag · {r['count']}") for r in rows if r["tag"] not in ATTR_FILTERS]
        share = _SUGGEST_LIMIT // 2
        keep_system = system[: max(share, _SUGGEST_LIMIT - len(tags))]
        keep_tags = tags[: _SUGGEST_LIMIT - len(keep_system)]
        return JSONResponse(_suggest_payload(token, keep_system + keep_tags))

    if prefix == "job:":
        stmt = select(AnalysisJob.id, AnalysisJob.filename).join(LogFile, AnalysisJob.file_id == LogFile.id).where(visible_job_filter(user))
        if needle:
            # Escaped, like every other user-supplied LIKE term in the codebase: a bare `%`
            # in the box otherwise matches every job, and `_` matches any character.
            safe = escape_like(needle)
            stmt = stmt.where(or_(AnalysisJob.filename.ilike(f"%{safe}%", escape="\\"), cast(AnalysisJob.id, String).like(f"{safe}%", escape="\\")))
        rows = (await db.execute(stmt.order_by(AnalysisJob.id.desc()).limit(_SUGGEST_LIMIT))).all()
        items = [_completion(token, str(jid), label=f"#{jid}", detail=fname or "") for jid, fname in rows]
        return JSONResponse(_suggest_payload(token, items))

    if prefix == "list:":
        from app.intel.rule_lists import LIST_MATCH_LABELS, load_lists

        items = [
            _completion(token, spec.name, label=spec.name, detail=f"{len(spec.values)} values, {LIST_MATCH_LABELS.get(spec.match, spec.match)}")
            for _row, spec in await load_lists(db)
            if needle in spec.name
        ]
        return JSONResponse(_suggest_payload(token, items))

    # cidr: and re:/ take free-form values there is nothing useful to enumerate.
    return JSONResponse(_suggest_payload(token, []))


@router.get("/tags.json")
async def tags_list_json(
    db: AsyncSession = Depends(get_async_session),
    _user: User = Depends(current_member_or_above),
    q: str = "",
    limit: int = 50,
):
    """Distinct tags with usage counts — powers the tag picker.

    Includes tags nobody has applied yet, or a vocabulary agreed up front would be
    invisible in the very control meant to encourage reuse.
    """
    rows = await tag_rows(db, q, "count", limit=min(max(limit, 1), 200))
    return JSONResponse([{"tag": r["tag"], "count": r["count"], "color": r["color"]} for r in rows])


async def _entity_technique_counts(db: AsyncSession, entity_id: int, user: User | None, job_id: int = 0) -> Counter:
    """Count MITRE techniques across the findings linked to this entity that *user* may see.

    Scoped by :func:`_visible_job_ids_subquery` like every other per-entity listing:
    without it, the technique IDs and per-technique event counts (and the Navigator
    layer's ``comment`` strings built from them) are derived from other users' private
    jobs.

    The ``TaskResult`` join is added when *either* the visibility scope or ``job_id``
    needs it. Admins take the no-visibility branch, so keying it on visibility alone would
    make a job scope silently do nothing for them.
    """
    stmt = select(Finding.tags, Finding.count).join(FindingEntityLink, FindingEntityLink.finding_id == Finding.id).where(FindingEntityLink.entity_id == entity_id)
    job_vis = _visible_job_ids_subquery(user)
    if job_vis is not None or job_id:
        stmt = stmt.join(TaskResult, Finding.task_result_id == TaskResult.id)
    if job_vis is not None:
        stmt = stmt.where(TaskResult.job_id.in_(job_vis))
    if job_id:
        stmt = stmt.where(TaskResult.job_id == job_id)
    rows = (await db.execute(stmt)).all()
    counts: Counter = Counter()
    for tags_json, cnt in rows:
        for tid, c in _extract_techniques_from_tags(tags_json, cnt):
            counts[tid] += c
    return counts


@router.get("/entities/{entity_id}/mitre-partial", response_class=HTMLResponse)
async def entity_mitre_partial(
    request: Request,
    entity_id: int,
    job: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """In-tab summary of MITRE techniques covered by this entity's findings."""
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404)

    job = await _resolve_entity_job_scope(db, entity_id, job, user)
    counts = await _entity_technique_counts(db, entity_id, user, job)
    sorted_items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_mitre.html",
        {
            "request": request,
            "entity": entity,
            "technique_total": len(counts),
            "event_total": sum(counts.values()),
            "techniques": sorted_items[:20],
            "job": job,
        },
    )


@router.get("/entities/{entity_id}/mitre-layer")
async def entity_mitre_layer(
    entity_id: int,
    job: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Download a MITRE Navigator layer JSON scoped to this entity's findings."""
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404)

    job = await _resolve_entity_job_scope(db, entity_id, job, user)
    counts = await _entity_technique_counts(db, entity_id, user, job)
    # The scope belongs in the file, not just the URL — a downloaded layer outlives the
    # page it came from, and a job-scoped one looks identical to a global one otherwise.
    scope_suffix = f" (job #{job})" if job else ""
    layer = build_navigator_layer(
        name=f"LogsTotal — {entity.entity_type}:{entity.value[:60]}{scope_suffix}",
        description=f"MITRE coverage for entity #{entity.id} ({entity.entity_type}={entity.value}){scope_suffix}.",
        counts=counts,
        comment=lambda _tid, cnt: f"{cnt} event{'s' if cnt != 1 else ''} on {entity.entity_type}={entity.value}",
    )
    return JSONResponse(
        layer,
        headers={"Content-Disposition": f'attachment; filename="entity-{entity_id}-mitre-layer.json"'},
    )


@router.get("/entities/{entity_id}/findings-partial", response_class=HTMLResponse)
async def entity_findings_partial(
    request: Request,
    entity_id: int,
    page: int = 1,
    job: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Paginated list of findings touching this entity (via FindingEntityLink)."""
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404)

    job = await _resolve_entity_job_scope(db, entity_id, job, user)
    job_vis = _visible_job_ids_subquery(user)
    total = await db.scalar(_entity_findings_count_stmt(entity_id, job_vis, job)) or 0
    total_pages = max(1, -(-total // PAGE_SIZE))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * PAGE_SIZE

    rows_stmt = (
        select(
            Finding.id,
            Finding.rule_id,
            Finding.rule_name,
            Finding.severity,
            Finding.count,
            TaskResult.tool_name,
            AnalysisJob.id.label("job_id"),
            # Whether to offer the "Show events" expander — NOT the events themselves.
            # `Finding.details` is a JSON array of matched events, so selecting it would
            # pull up to `max_finding_details` event blobs per row across a 50-row page.
            # The expander lazy-loads them one finding at a time from the job page's own
            # endpoint. `Finding.has_details` is the mapped `coalesce(...) != ''` column
            # property, shared with the job page so the two cannot disagree.
            Finding.has_details,
        )
        .join(FindingEntityLink, FindingEntityLink.finding_id == Finding.id)
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .join(AnalysisJob, TaskResult.job_id == AnalysisJob.id)
        .where(FindingEntityLink.entity_id == entity_id)
    )
    if job_vis is not None:
        rows_stmt = rows_stmt.where(AnalysisJob.id.in_(job_vis))
    if job:
        rows_stmt = rows_stmt.where(AnalysisJob.id == job)
    rows = (await db.execute(rows_stmt.order_by(AnalysisJob.id.desc(), severity_rank_sql(), Finding.rule_name.asc(), Finding.id.asc()).offset(offset).limit(PAGE_SIZE))).all()

    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_findings.html",
        {
            "request": request,
            "entity": entity,
            "findings": rows,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "job": job,
        },
    )


_RELATIONSHIPS_CAP = 1000

# Pills shown per group on the Overview "Associated Entities" card.
_ASSOCIATIONS_PER_GROUP = 10


async def _fetch_associated_groups(db: AsyncSession, entity_id: int, entity_type: str) -> list[dict]:
    """Curated typed associations for the Overview card (top N per group + overflow)."""
    from app.intel.relationships import ASSOCIATIONS, build_association_groups

    specs = ASSOCIATIONS.get(entity_type, ())
    if not specs:
        return []
    rows_by_direction: dict[str, list] = {"out": [], "in": []}
    for direction in ("out", "in"):
        rel_types = sorted({s.rel_type for s in specs if s.direction == direction})
        if not rel_types:
            continue
        if direction == "out":
            where_col, other_col = EntityRelationship.source_entity_id, EntityRelationship.target_entity_id
        else:
            where_col, other_col = EntityRelationship.target_entity_id, EntityRelationship.source_entity_id
        # One windowed query per direction: top-N rows per relationship_type
        # plus the uncapped per-group total (for the "+N more" overflow pill).
        rn = (
            func.row_number()
            .over(
                partition_by=EntityRelationship.relationship_type,
                order_by=(EntityRelationship.occurrence_count.desc(), EntityRelationship.id.asc()),
            )
            .label("rn")
        )
        total = func.count().over(partition_by=EntityRelationship.relationship_type).label("total")
        sub = (
            select(
                EntityRelationship.relationship_type.label("rel_type"),
                EntityRelationship.occurrence_count.label("occ"),
                other_col.label("other_id"),
                rn,
                total,
            )
            .where(where_col == entity_id, EntityRelationship.relationship_type.in_(rel_types))
            .subquery()
        )
        stmt = (
            select(sub.c.rel_type, sub.c.occ, sub.c.total, Entity)
            .join(Entity, Entity.id == sub.c.other_id)
            .where(sub.c.rn <= _ASSOCIATIONS_PER_GROUP)
            .order_by(sub.c.rel_type, sub.c.rn)
        )
        rows_by_direction[direction] = (await db.execute(stmt)).all()
    return build_association_groups(entity_type, rows_by_direction)


@router.get("/entities/{entity_id}/relationships-partial", response_class=HTMLResponse)
async def entity_relationships_partial(
    request: Request,
    entity_id: int,
    job: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Typed entity relationships, grouped by type + direction (outgoing/incoming).

    `job` narrows by co-occurrence, not by evidence — see `_relationships_touching` for
    why that is the honest reading of a cross-job aggregate.
    """
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404)

    job = await _resolve_entity_job_scope(db, entity_id, job, user)
    groups, total, capped = await fetch_relationship_groups(db, entity_id, job)

    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_relationships.html",
        {
            "request": request,
            "entity": entity,
            "groups": groups,
            "total": total,
            "capped": capped,
            "job": job,
            "entity_type_meta": ENTITY_TYPE_META,
        },
    )


async def fetch_relationship_groups(db: AsyncSession, entity_id: int, job: int = 0) -> tuple[list[dict], int, bool]:
    """Typed relationships for one entity, grouped by (type, direction). `(groups, total, capped)`.

    Extracted from `entity_relationships_partial` so the case Processes tab can render the
    same thing beside its process tree — a lineage tree says how a binary *ran*, and the
    typed edges say what it touched; the two answer halves of one question and a second
    implementation of the grouping would drift from this one immediately.

    `job` narrows by co-occurrence, not through `EntityRelationshipEvidence` — see
    `_relationships_touching` for why that is the honest reading of a cross-job aggregate.
    Callers are responsible for validating `job` first.
    """
    from app.intel.relationships import RELATIONSHIP_LABELS, RELATIONSHIP_TYPES

    async def _fetch(direction: str):
        if direction == "out":
            join_col, where_col = EntityRelationship.target_entity_id, EntityRelationship.source_entity_id
        else:
            join_col, where_col = EntityRelationship.source_entity_id, EntityRelationship.target_entity_id
        stmt = (
            select(EntityRelationship.id, EntityRelationship.relationship_type, EntityRelationship.occurrence_count, EntityRelationship.last_seen_at, Entity)
            .join(Entity, Entity.id == join_col)
            .where(where_col == entity_id)
            .order_by(EntityRelationship.occurrence_count.desc(), Entity.value.asc())
            .limit(_RELATIONSHIPS_CAP)
        )
        if job:
            stmt = stmt.where(join_col.in_(select(EntityJobLink.entity_id).where(EntityJobLink.job_id == job)))
        return (await db.execute(stmt)).all()

    out_rows = await _fetch("out")
    in_rows = await _fetch("in")

    buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for direction, rows in (("out", out_rows), ("in", in_rows)):
        for rel_id, rel_type, occ, last_seen, other in rows:
            buckets[(rel_type, direction)].append({"relationship_id": rel_id, "other": other, "occurrence_count": occ, "last_seen_at": last_seen})

    # Canonical relationship order, outgoing before incoming.
    groups = []
    for rel_type in RELATIONSHIP_TYPES:
        for direction in ("out", "in"):
            rows = buckets.get((rel_type, direction))
            if not rows:
                continue
            groups.append(
                {
                    "rel_type": rel_type,
                    "label": RELATIONSHIP_LABELS.get(rel_type, rel_type.replace("_", " ")),
                    "direction": direction,
                    "rows": rows,
                    "count": len(rows),
                }
            )

    return groups, len(out_rows) + len(in_rows), len(out_rows) >= _RELATIONSHIPS_CAP or len(in_rows) >= _RELATIONSHIPS_CAP


_RELATIONSHIP_EVIDENCE_JOB_CAP = 50


@router.get("/relationships/{relationship_id}/evidence-partial", response_class=HTMLResponse)
async def relationship_evidence_partial(
    request: Request,
    relationship_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """HTMX partial: the jobs + sample events that back a single relationship edge.

    Jobs come from the reliable ``EntityJobLink`` co-occurrence join (both endpoints
    present in the same job), so this works for historical edges too. Sample events,
    where captured, come from ``EntityRelationshipEvidence``.
    """
    from app.intel.relationships import RELATIONSHIP_LABELS

    rel = await db.get(EntityRelationship, relationship_id)
    if not rel:
        raise HTTPException(404)

    source = await db.get(Entity, rel.source_entity_id)
    target = await db.get(Entity, rel.target_entity_id)

    # Jobs where both endpoints co-occur (self-join on EntityJobLink),
    # restricted to jobs the viewer may see so private-job filenames/events
    # (and sample events) never leak cross-user.
    j_src = aliased(EntityJobLink)
    j_tgt = aliased(EntityJobLink)
    job_vis = _visible_job_ids_subquery(user)
    job_stmt = (
        select(AnalysisJob, AnalysisJob.filename)
        .join(j_src, j_src.job_id == AnalysisJob.id)
        .join(j_tgt, j_tgt.job_id == AnalysisJob.id)
        .join(LogFile, AnalysisJob.file_id == LogFile.id)
        .where(j_src.entity_id == rel.source_entity_id, j_tgt.entity_id == rel.target_entity_id)
    )
    if job_vis is not None:
        job_stmt = job_stmt.where(AnalysisJob.id.in_(job_vis))
    job_rows = (await db.execute(job_stmt.order_by(AnalysisJob.id.desc()).limit(_RELATIONSHIP_EVIDENCE_JOB_CAP))).all()

    job_ids = [job.id for job, _ in job_rows]
    evidence_map: dict[int, dict] = {}
    if job_ids:
        ev_rows = (
            await db.execute(
                select(EntityRelationshipEvidence.job_id, EntityRelationshipEvidence.occurrence_count, EntityRelationshipEvidence.sample_events_json).where(
                    EntityRelationshipEvidence.relationship_id == relationship_id,
                    EntityRelationshipEvidence.job_id.in_(job_ids),
                )
            )
        ).all()
        for jid, occ, samples_json in ev_rows:
            events = []
            if samples_json:
                try:
                    events = json_loads(samples_json)
                except Exception:
                    events = []
            evidence_map[jid] = {"occurrence_count": occ, "events": events}

    jobs = [
        {
            "job": job,
            "filename": filename,
            "occurrence_count": evidence_map.get(job.id, {}).get("occurrence_count"),
            "events": evidence_map.get(job.id, {}).get("events", []),
        }
        for job, filename in job_rows
    ]

    return templates.TemplateResponse(
        request,
        "intel/partials/_relationship_evidence.html",
        {
            "request": request,
            "relationship": rel,
            "source": source,
            "target": target,
            "rel_label": RELATIONSHIP_LABELS.get(rel.relationship_type, rel.relationship_type.replace("_", " ")),
            "jobs": jobs,
        },
    )


@router.get("/relationships/{relationship_id}/timespan.json")
async def relationship_timespan(
    relationship_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """When a typed relationship was observed, from its sample events. Honest about how.

    Three things this endpoint refuses to do, all of them because the alternative would be
    false precision on a surface (the graph's edge panel) where an analyst is deciding what
    to believe:

    * **It never reports `EntityRelationship.first_seen_at`/`last_seen_at` as event time.**
      Those columns are ``server_default=func.now()`` — ingest wall-clock, i.e. when the
      worker happened to run. `time_source` says which of the two the caller is looking at,
      and the words "first seen"/"last seen" do not appear.
    * **It parses timestamps with `event_markers.event_epoch_seconds`, not
      `normalize_event_time`.** The latter preserves the offset verbatim, which is right for
      the histogram and wrong here: a job mixing `+09:00` and `Z` would place the same edge
      hours apart. This one is strict UTC.
    * **It says the window is a sample.** ``EVIDENCE_CAP`` is 3 events per edge per job, so
      the earliest and latest sample are not the earliest and latest occurrence.

    Evidence rows are filtered to jobs the viewer may see — the same rule
    `relationship_evidence_partial` already applies. `_typed_edges` deliberately does not
    filter the *existence* of a typed edge (see `app/intel/graph.py`), but everything
    derived from one does.
    """
    from app.intel.event_markers import event_epoch_seconds
    from app.intel.relationships import EVIDENCE_CAP, RELATIONSHIP_LABELS

    rel = await db.get(EntityRelationship, relationship_id)
    if not rel:
        raise HTTPException(404)

    stmt = select(EntityRelationshipEvidence.job_id, EntityRelationshipEvidence.occurrence_count, EntityRelationshipEvidence.sample_events_json).where(
        EntityRelationshipEvidence.relationship_id == relationship_id
    )
    job_vis = _visible_job_ids_subquery(user)
    if job_vis is not None:
        stmt = stmt.where(EntityRelationshipEvidence.job_id.in_(job_vis))
    rows = (await db.execute(stmt)).all()

    epochs: list[int] = []
    occurrences = 0
    jobs_with_events = 0
    for _job_id, occ, samples_json in rows:
        occurrences += int(occ or 0)
        if not samples_json:
            continue
        try:
            events = json_loads(samples_json)
        except Exception:
            continue
        if not isinstance(events, list):
            continue
        found = False
        for event in events:
            if not isinstance(event, dict):
                continue
            for key in ("UtcTime", "Timestamp", "SystemTime"):
                epoch = event_epoch_seconds(event.get(key))
                if epoch is not None:
                    epochs.append(epoch)
                    found = True
                    break
        if found:
            jobs_with_events += 1

    if epochs:
        payload = {
            "time_source": "event",
            "from": min(epochs) * 1000,
            "to": max(epochs) * 1000,
            "sampled": True,
            "sample_cap": EVIDENCE_CAP,
            "jobs": jobs_with_events,
        }
    else:
        # No parseable event timestamp anywhere — Linux/auditd relationships routinely land
        # here, because `EVIDENCE_FIELDS` is deliberately not widened to carry free-form
        # auditd `msg=` bodies. Report ingest time and label it as such rather than
        # returning nothing.
        payload = {
            "time_source": "ingest",
            # The columns are naive UTC; a bare `.timestamp()` would read them as host-local.
            "from": int(rel.first_seen_at.replace(tzinfo=UTC).timestamp() * 1000) if rel.first_seen_at else None,
            "to": int(rel.last_seen_at.replace(tzinfo=UTC).timestamp() * 1000) if rel.last_seen_at else None,
            "sampled": False,
            "sample_cap": EVIDENCE_CAP,
            "jobs": len(rows),
        }

    payload.update(
        {
            "relationship_id": rel.id,
            "rel_type": rel.relationship_type,
            "rel_label": RELATIONSHIP_LABELS.get(rel.relationship_type, rel.relationship_type.replace("_", " ")),
            "occurrence_count": rel.occurrence_count,
            "evidence_occurrences": occurrences,
        }
    )
    return JSONResponse(payload)


async def _enrichment_context(db: AsyncSession, entity: Entity) -> tuple[list[EnrichmentService], dict[int, EntityEnrichmentResult]]:
    """Applicable live-enrichment services for this entity + their cached results."""
    services = (
        (
            await db.execute(
                select(EnrichmentService)
                .where(EnrichmentService.enabled.is_(True), EnrichmentService.api_template.isnot(None))
                .order_by(EnrichmentService.display_order, EnrichmentService.name)
            )
        )
        .scalars()
        .all()
    )
    applicable = []
    for s in services:
        try:
            types = json_loads(s.entity_types) if s.entity_types else []
        except (ValueError, TypeError):
            types = []
        if entity.entity_type in types:
            applicable.append(s)

    results: dict[int, EntityEnrichmentResult] = {}
    if applicable:
        rows = (
            (
                await db.execute(
                    select(EntityEnrichmentResult).where(EntityEnrichmentResult.entity_id == entity.id, EntityEnrichmentResult.service_id.in_([s.id for s in applicable]))
                )
            )
            .scalars()
            .all()
        )
        results = {r.service_id: r for r in rows}
    return applicable, results


@router.get("/entities/{entity_id}/enrichment-partial", response_class=HTMLResponse)
async def entity_enrichment_partial(
    request: Request,
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    _user: User = Depends(current_member_or_above),
):
    """Live-enrichment section: applicable API services + any cached results."""
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404)
    services, results = await _enrichment_context(db, entity)
    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_enrichment.html",
        {"request": request, "entity": entity, "services": services, "results": results},
    )


@router.post("/entities/{entity_id}/enrich/{service_id}", response_class=HTMLResponse)
async def entity_enrich(
    request: Request,
    entity_id: int,
    service_id: int,
    force: str | None = Form(None),
    db: AsyncSession = Depends(get_async_session),
    _user: User = Depends(current_member_or_above),
):
    """Trigger a live enrichment lookup (synchronous, bounded by httpx timeout)."""
    from app.intel.live_enrichment import fetch_enrichment

    entity = await db.get(Entity, entity_id)
    service = await db.get(EnrichmentService, service_id)
    if not entity or not service:
        raise HTTPException(404)
    if not service.enabled or not service.api_template:
        raise HTTPException(400, "service is not configured for live enrichment")
    # The admin's type scoping is the control that keeps internal identities off a third
    # party's API. The panel only offers matching services, but this route is reachable with
    # any pair of ids — so it checks the same list the panel reads. Same 404 as a missing row.
    try:
        allowed_types = json_loads(service.entity_types) if service.entity_types else []
    except (ValueError, TypeError):
        allowed_types = []
    if entity.entity_type not in allowed_types:
        raise HTTPException(404)

    try:
        await fetch_enrichment(db, entity, service, force=bool(force))
        await db.commit()
    except Exception as exc:
        await db.rollback()
        # The rollback expired both rows; reading an attribute off either now would lazy-load
        # outside the greenlet (MissingGreenlet). Reload them explicitly.
        await db.refresh(entity)
        await db.refresh(service)
        _log.warning("entity_enrich failed for entity=%s service=%s: %s", entity_id, service_id, type(exc).__name__)
        # Persist the failure, or the re-rendered panel is indistinguishable from a lookup
        # that was never attempted. Only the exception *type* is stored: the message can
        # carry the URL, and the URL carries the decrypted API token.
        try:
            row = (
                await db.execute(select(EntityEnrichmentResult).where(EntityEnrichmentResult.entity_id == entity_id, EntityEnrichmentResult.service_id == service_id))
            ).scalar_one_or_none()
            if row is None:
                row = EntityEnrichmentResult(entity_id=entity_id, service_id=service_id)
                db.add(row)
            row.ok = False
            row.error_message = f"lookup failed ({type(exc).__name__})"
            row.response_json = None
            row.summary_json = None
            row.fetched_at = utc_now_naive()
            row.expires_at = row.fetched_at
            await db.commit()
        except Exception:
            await db.rollback()

    services, results = await _enrichment_context(db, entity)
    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_enrichment.html",
        {"request": request, "entity": entity, "services": services, "results": results},
    )


# ─── MITRE ATT&CK Navigator Export ──────────────────────────────────────────────

_RE_TECHNIQUE = re.compile(r"[Tt](\d{4})(?:\.(\d{3}))?")


def _extract_techniques_from_tags(tags_json: str, count: int) -> list[tuple[str, int]]:
    """Parse MITRE technique IDs from a Finding's tags JSON, returning (technique_id, count) pairs."""
    try:
        tags = json_loads(tags_json) if tags_json else []
    except (ValueError, TypeError):
        return []
    results = []
    for tag in tags:
        key = tag.lower()
        if key.startswith("attack."):
            key = key[len("attack.") :]
        m = _RE_TECHNIQUE.match(key)
        if m:
            tid = f"T{m.group(1)}"
            if m.group(2):
                tid += f".{m.group(2)}"
            results.append((tid.upper(), count))
    return results


async def _build_mitre_layer(
    db: AsyncSession,
    name: str,
    description: str,
    job_ids: list[int] | None = None,
    *,
    viewer: User | None,
) -> dict:
    """Build a MITRE ATT&CK Navigator layer JSON from Finding tags.

    *viewer* is keyword-only and has **no default**, deliberately: filtering on job *status*
    alone would aggregate the technique scores and per-technique event counts a member
    downloads over every private job on the instance, and a parameter you have to supply is
    the only version of this that cannot regress by omission.
    """
    query = (
        select(Finding.tags, Finding.count)
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .join(AnalysisJob, TaskResult.job_id == AnalysisJob.id)
        .where(AnalysisJob.status.in_([JobStatus.COMPLETED, JobStatus.PARTIAL, JobStatus.CANCELLED]))
        .where(visible_job_filter(viewer))
    )
    if job_ids is not None:
        query = query.where(AnalysisJob.id.in_(job_ids))

    result = await db.execute(query)
    rows = result.all()

    technique_counts: dict[str, int] = Counter()
    for tags_json, count in rows:
        for tid, cnt in _extract_techniques_from_tags(tags_json, count):
            technique_counts[tid] += cnt

    return build_navigator_layer(name=name, description=description, counts=dict(technique_counts))


@router.get("/mitre-layer")
async def intel_mitre_layer(
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Export aggregate MITRE ATT&CK Navigator layer across the jobs this member can see."""
    layer = await _build_mitre_layer(
        db,
        name="LogsTotal — All Jobs",
        description="Aggregated MITRE ATT&CK technique coverage across the log files you can see.",
        viewer=user,
    )
    return JSONResponse(
        layer,
        headers={"Content-Disposition": 'attachment; filename="logstotal-mitre-layer.json"'},
    )


# ─── IOC Feed ────────────────────────────────────────────────────────────────────


async def _build_ioc_data(
    db: AsyncSession,
    entity_types: list[str] | None = None,
    since: str | None = None,
    limit: int = 1000,
    include_allowlisted: bool = False,
    *,
    viewer: User | None = None,
) -> tuple[list[dict], list[Entity]]:
    """Build the IOC list plus the `Entity` rows it was built from, in the same order.

    Returning both lets the MISP branch use the very rows summarised here, rather than a
    near-copy of this query zipped positionally — two copies drift, and a drifted type
    filter silently produces an event with no entities.

    Allowlisted entities are excluded by default; pass include_allowlisted=True to override.

    *viewer* scopes the job-derived half. The entity rows themselves are instance-wide by
    design (an `Entity` is a shared observable, and the dashboard shows the same set), but
    `threat_categories` and `max_severity` are read out of `AnalysisJob.analytics_json`,
    which is per-job data — unfiltered, a member would receive threat context computed from
    other members' private jobs, in the STIX labels and the MISP export too. Keyword-only so
    a caller cannot pass it positionally by accident and
    silently widen the feed.
    """
    query = select(Entity).order_by(Entity.last_seen_at.desc(), Entity.id.desc())
    if entity_types:
        valid = [t for t in entity_types if t in ENTITY_TYPE_META]
        if valid:
            query = query.where(Entity.entity_type.in_(valid))
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            # The column is naive UTC. An offset has to be applied, not dropped — and an aware
            # value cannot be bound to it on PostgreSQL at all.
            if since_dt.tzinfo is not None:
                since_dt = since_dt.astimezone(UTC).replace(tzinfo=None)
            query = query.where(Entity.last_seen_at >= since_dt)
        except ValueError:
            pass
    if not include_allowlisted:
        query = query.where(Entity.allowlisted.is_(False))
    query = query.limit(limit)
    result = await db.execute(query)
    entities = result.scalars().all()

    if not entities:
        return [], []

    entity_ids = [e.id for e in entities]
    link_result = await db.execute(select(EntityJobLink.entity_id, EntityJobLink.job_id).where(EntityJobLink.entity_id.in_(entity_ids)))
    entity_job_map: dict[int, list[int]] = defaultdict(list)
    all_job_ids: set[int] = set()
    for eid, jid in link_result.all():
        entity_job_map[eid].append(jid)
        all_job_ids.add(jid)

    job_threats: dict[int, set[str]] = {}
    job_max_sev: dict[int, str] = {}
    if all_job_ids:
        job_result = await db.execute(
            select(AnalysisJob.id, AnalysisJob.analytics_json)
            .where(AnalysisJob.id.in_(list(all_job_ids)))
            .where(AnalysisJob.analytics_json.isnot(None))
            .where(visible_job_filter(viewer))
        )
        for jid, aj in job_result.all():
            try:
                data = json_loads(aj)
            except (ValueError, TypeError):
                continue
            td = data.get("threat_detection", {})
            if not td or not td.get("categories"):
                continue
            cats: set[str] = set()
            max_sev = "informational"
            for cat_key, cat in td["categories"].items():
                if cat.get("indicators"):
                    cats.add(cat_key)
                    s = cat.get("severity", "informational")
                    if _SEVERITY_RANK.get(s, 99) < _SEVERITY_RANK.get(max_sev, 99):
                        max_sev = s
            job_threats[jid] = cats
            job_max_sev[jid] = max_sev

    iocs = []
    for e in entities:
        linked_jids = entity_job_map.get(e.id, [])
        threat_cats: set[str] = set()
        max_sev = "informational"
        for jid in linked_jids:
            threat_cats.update(job_threats.get(jid, set()))
            js = job_max_sev.get(jid, "informational")
            if _SEVERITY_RANK.get(js, 99) < _SEVERITY_RANK.get(max_sev, 99):
                max_sev = js

        iocs.append(
            {
                "value": e.value,
                "type": e.entity_type,
                "first_seen": e.first_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ") if e.first_seen_at else "",
                "last_seen": e.last_seen_at.strftime("%Y-%m-%dT%H:%M:%SZ") if e.last_seen_at else "",
                "job_count": e.job_count or 0,
                "threat_categories": ";".join(sorted(threat_cats)) if threat_cats else "",
                "max_severity": max_sev if threat_cats else "",
            }
        )
    return iocs, list(entities)


@router.get("/ioc-feed")
async def ioc_feed(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    format: str = "json",
    types: str = "",
    since: str = "",
    limit: int = 1000,
    include_allowlisted: int = 0,
    _principal=Depends(current_user_or_api_token("ioc_feed:read")),
):
    """IOC feed — entities with threat context in CSV, JSON, STIX, or MISP format.

    Accepts cookie auth (member-or-above) OR Bearer API token with the `ioc_feed:read` scope.
    Allowlisted entities are excluded unless `include_allowlisted=1` is passed.

    The threat context is scoped to the principal — a token sees exactly what its creator
    sees, no more. Every output format goes through this one call, so CSV, JSON, STIX and
    MISP cannot disagree about what the caller is allowed to know.
    """
    entity_types = None
    if types:
        # The dashboard grammar's aliases (`ip`, `exe`), and a refusal for anything else. An
        # unknown type used to drop the filter and return every type — the wrong set, to an
        # integration that has no way to notice.
        entity_types = [TYPE_ALIASES.get(t.strip().lower(), t.strip().lower()) for t in types.split(",") if t.strip()]
        unknown = [t for t in entity_types if t not in ENTITY_TYPE_META]
        if unknown:
            raise HTTPException(400, f"unknown entity type: {', '.join(unknown)} (known: {', '.join(ENTITY_TYPE_META)})")
    limit = max(1, min(limit, 5000))
    # Resolved once and reused: it scopes the data *and* attributes the audit row, and
    # those two must not be able to disagree about who is asking.
    viewer = await principal_user(db, _principal)
    iocs, ioc_entities = await _build_ioc_data(
        db,
        entity_types=entity_types,
        since=since or None,
        limit=limit,
        include_allowlisted=bool(include_allowlisted),
        viewer=viewer,
    )

    # Recorded once, before the format branch: the export has happened either way, and
    # four call sites would be four chances for one of them to be forgotten. This is the
    # highest-value row in the log — it is the only record that observables left here, and
    # a Bearer token has no session to attribute it by otherwise.
    await activity.record(
        "export.ioc_feed",
        request=request,
        user=viewer,
        actor_label=principal_actor_label(_principal, viewer),
        summary=f"{len(iocs)} indicator(s) as {format}",
        meta={"format": format, "count": len(iocs), "types": entity_types or None, "include_allowlisted": bool(include_allowlisted)},
    )

    if format == "csv":
        output = io.StringIO()
        if iocs:
            writer = csv.DictWriter(output, fieldnames=iocs[0].keys())
            writer.writeheader()
            # Defused on the way out, and the whole row rather than `value` alone: only
            # `value` is attacker-controlled today (user/computer/service/task entities are
            # stored off an anonymous upload with no charset constraint), but a column added
            # later would otherwise have to remember this. The JSON, STIX and MISP branches
            # are deliberately left verbatim — nothing evaluates a cell in those.
            writer.writerows({key: csv_safe(val) for key, val in ioc.items()} for ioc in iocs)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=logstotal-iocs.csv"},
        )
    elif format == "stix":
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'logstotal')}"
        objects = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now,
                "modified": now,
                "name": "LogsTotal",
                "identity_class": "system",
            }
        ]
        for ioc in iocs:
            pattern = stix_pattern(ioc["type"], ioc["value"])
            ioc_key = f"logstotal:ioc:{ioc['type']}:{ioc['value']}"
            iid = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, ioc_key)}"
            labels = [ioc["type"]]
            if ioc["max_severity"]:
                labels.append(f"severity:{ioc['max_severity']}")
            if ioc["threat_categories"]:
                labels.extend(ioc["threat_categories"].split(";"))
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": iid,
                    "created": now,
                    "modified": now,
                    "name": ioc["value"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": ioc["first_seen"] or now,
                    "labels": labels,
                    "created_by_ref": identity_id,
                }
            )
        bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
        return JSONResponse(
            bundle,
            headers={"Content-Disposition": "attachment; filename=logstotal-iocs-stix.json"},
        )
    elif format == "misp":
        # One result set, no second query and no positional zip: `_build_ioc_data` hands
        # back the very rows it summarised, so entity and severity can never desync.
        from app.intel.misp import build_misp_event, threat_level_for_entities

        entities = ioc_entities
        sighting_counts: dict[int, int] = {e.id: (e.job_count or 0) for e in entities}
        severity_by_id: dict[int, str] = {ent.id: ioc.get("max_severity") or "informational" for ent, ioc in zip(entities, iocs, strict=True)}
        event = build_misp_event(
            info="LogsTotal IOC feed export",
            entities=entities,
            sighting_counts=sighting_counts,
            threat_level=threat_level_for_entities(entities, severity_by_id),
        )
        return JSONResponse(
            event,
            headers={"Content-Disposition": "attachment; filename=logstotal-iocs-misp.json"},
        )
    else:
        return JSONResponse(
            iocs,
            headers={"Content-Disposition": "attachment; filename=logstotal-iocs.json"},
        )


# ─── STIX 2.1 export ────────────────────────────────────────────────────────────


@router.get("/entities/{entity_id}/ioc-pack")
async def entity_ioc_pack(
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Compact IOC pack JSON for an entity (with top neighbors).

    Neighbours and threat context come from the viewer's visible jobs only — this pack
    gets pasted into tickets, so it must not carry another member's private-job context.
    """
    from app.intel.ioc_pack import build_entity_ioc_pack

    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404)

    job_vis = _visible_job_ids_subquery(user)
    all_job_ids_q = select(EntityJobLink.job_id).where(EntityJobLink.entity_id == entity_id)
    if job_vis is not None:
        all_job_ids_q = all_job_ids_q.where(EntityJobLink.job_id.in_(job_vis))
    neighbors = (
        (
            await db.execute(
                select(Entity)
                .join(EntityJobLink, Entity.id == EntityJobLink.entity_id)
                .where(EntityJobLink.job_id.in_(all_job_ids_q), Entity.id != entity_id)
                .group_by(Entity.id)
                .order_by(func.count(func.distinct(EntityJobLink.job_id)).desc())
                .limit(10)
            )
        )
        .scalars()
        .all()
    )

    tags = (await db.execute(select(EntityTag).where(EntityTag.entity_id == entity_id))).scalars().all()

    threat_context = await _compute_entity_threat_context(db, [row[0] for row in (await db.execute(all_job_ids_q)).all()])
    focal_categories = [c["key"] for c in threat_context.get("categories", [])]
    focal_severity = threat_context.get("max_severity") or None

    pack = build_entity_ioc_pack(
        entity,
        neighbors=neighbors,
        focal_threat_categories=focal_categories,
        focal_severity=focal_severity,
        focal_tags=tags,
    )
    return JSONResponse(pack)


@router.get("/entities/{entity_id}/stix")
async def entity_stix_export(
    entity_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Export entity and its neighborhood as a STIX 2.1 bundle.

    Both the neighbourhood and the sightings are scoped to jobs *user* may see —
    a STIX sighting carries a job id and timestamp, so an unscoped export would leak what
    `_visible_job_ids_subquery` exists to protect.
    """
    from app.intel.graph import neighbors_of

    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404)

    await activity.record("export.stix", request=request, user=user, target_type="entity", target_id=str(entity_id), summary=entity.value)

    neighbors_pairs = await neighbors_of(db, entity_id, limit=50, include_allowlisted=True, viewer=user)
    neighbors = [n for n, _shared in neighbors_pairs]

    job_vis = _visible_job_ids_subquery(user)
    links_stmt = select(EntityJobLink).where(EntityJobLink.entity_id == entity_id)
    if job_vis is not None:
        links_stmt = links_stmt.where(EntityJobLink.job_id.in_(job_vis))
    job_links = (await db.execute(links_stmt.options(selectinload(EntityJobLink.job)).limit(50))).scalars().all()

    bundle = build_entity_stix_bundle(entity, neighbors, job_links)

    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="entity-{entity_id}-stix.json"'},
    )


# ─── Process tree and relationship graph ───────────────────────────────────────


@router.get("/entities/{entity_id}/process-tree-partial", response_class=HTMLResponse)
async def entity_process_tree_partial(
    request: Request,
    entity_id: int,
    job: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Process lineage for one job, pruned to the chains that mention this entity.

    A separate route from `/jobs/{id}/process-tree` rather than an `?entity_id=` on it:
    that one is `current_user_optional` and anonymous-viewable for a public job, so
    accepting an entity id there would turn it into an entity-existence oracle for anyone
    at all. This one is member-gated and checks that the job is actually linked to the
    entity, dropping an unusable one back to the empty state rather than 404-ing — the
    same discipline as every other job scope on this page.

    Pruning happens server-side because `build_process_forest` truncates at
    `DEFAULT_MAX_NODES` **during the parse**, before relevance is known — on a busy job the
    entity's own processes may not be among the first the client would ever see. The
    client's free-text filter still works, on top of the pruned tree.
    """
    from app.intel.lineage import PROCESS_TREE_ENTITY_TYPES
    from app.intel.process_tree import load_job_forest

    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")
    if entity.entity_type not in PROCESS_TREE_ENTITY_TYPES:
        raise HTTPException(404, "Entity not found")

    job = await _resolve_entity_job_scope(db, entity_id, job, user)
    site_settings = await get_site_settings(db)
    if not job or not site_settings.show_process_tree:
        return templates.TemplateResponse(
            request,
            "intel/partials/_entity_processes_empty.html",
            {"request": request, "entity": entity, "disabled": not site_settings.show_process_tree},
        )

    # Resolved to plain strings *before* the threadpool hop — the closure it hands off must
    # never touch an ORM instance (a deferred/lazy read there raises MissingGreenlet).
    forest = await load_job_forest(job, entity_type=entity.entity_type, entity_value=entity.value)
    return templates.TemplateResponse(
        request,
        "partials/_process_tree.html",
        {"request": request, "job": None, "forest": forest, "scope_label": f"job #{job} · {entity.value}"},
    )


def _empty_graph_stats() -> dict:
    """The stats block for a refused graph request.

    Built through `graph._stats` rather than hand-rolled so it carries every key the
    client's decoder expects — a payload missing one is a `undefined` read in a reducer,
    which draws a blank canvas with no error.
    """
    from app.intel.graph import _stats

    return _stats(0, 0, total_nodes=0, total_edges=0)


@router.get("/entities/{entity_id}/graph-partial", response_class=HTMLResponse)
async def entity_graph_partial(
    request: Request,
    entity_id: int,
    job: int = 0,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Lazy-loaded Graph tab shell. The graph data is fetched separately by graph.json.

    `client_schema()` is rendered *into* the shell rather than fetched with the data: the
    renderer needs the palette and the enum orders at construction time, and a palette that
    arrives with the payload is `undefined` when the first frame draws.

    **The "pick a job first" gate lives here, in the server-rendered shell** — not in
    `graphComponent` and not in `graph.json`. Without a job the template renders a branch
    carrying no `x-data` at all, which means: no WebGL context is created for a view that
    shows nothing, there is no `graphmlUrl()` in scope to export a graph you cannot see,
    no Alpine bindings exist to be left uninitialised, and the gate cannot disagree with
    the server's own idea of whether `job` was valid. An entity's unscoped neighbourhood
    on a mature database is a hairball; the job scope is what makes it readable.
    """
    from app.intel.graph_payload import client_schema

    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")

    job = await _resolve_entity_job_scope(db, entity_id, job, user)
    graph_opts = None
    if job:
        # One dict, one `| tojson`, one single-quoted attribute. Interpolating the schema
        # inline would put double quotes inside a double-quoted `x-data`, which truncates the
        # expression and leaves a silently dead component —
        # `test_htmx_partials_have_intact_alpine_expressions` exists for that.
        graph_opts = {
            "scope": "entity",
            "focalId": entity.id,
            "jobId": job,
            "jsonUrl": f"/intel/entities/{entity.id}/graph.json",
            "graphmlBase": f"/intel/entities/{entity.id}/graph.graphml",
            "pngPrefix": f"entity-{entity.id}-job-{job}",
            "schema": client_schema(),
        }
    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_graph.html",
        {"request": request, "entity": entity, "graph_opts": graph_opts, "job": job},
    )


@router.get("/entities/{entity_id}/graph.json")
async def entity_graph_json(
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    hops: int = 1,
    limit: int = 30,
    include_allowlisted: int = 0,
    q: str = "",
    job: int = 0,
):
    """Columnar graph payload for the entity neighbourhood at `hops` depth.

    `q` is parsed by the shared grammar and only its `re:` terms are evaluated here — a JS
    `RegExp` has no timeout, so a catastrophic pattern has to stay on the server side of
    the budget. Everything else in the grammar is matched client-side against decoded node
    attributes, instantly and with no round trip, which is the entire point of the filter.

    An invalid `job` fails the **opposite** way to the dashboard's `?job=`. There, dropping
    the filter widens to a table that is still correct. Here, dropping it would render the
    full unscoped graph — contradicting the gate the shell just applied — so an unusable
    job returns the same empty payload a nonexistent one does, byte for byte.
    """
    from app.intel.graph import build_entity_graph
    from app.intel.graph_payload import build_payload
    from app.intel.queries import parse_query

    if not await db.get(Entity, entity_id):
        raise HTTPException(404, "Entity not found")
    if job and not await _resolve_entity_job_scope(db, entity_id, job, user):
        return JSONResponse(build_payload(scope="entity", focal_id=entity_id, nodes=[], edges=[], stats=_empty_graph_stats()))
    payload = await build_entity_graph(
        db,
        entity_id,
        hops=hops,
        limit=limit,
        include_allowlisted=bool(include_allowlisted),
        viewer=user,
        query=parse_query(q) if q.strip() else None,
        job_id=job or None,
    )
    return JSONResponse(payload)


@router.get("/entities/{entity_id}/graph.graphml")
async def entity_graph_graphml(
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    hops: int = 1,
    limit: int = 100,
    include_allowlisted: int = 0,
    job: int = 0,
):
    """GraphML export of the entity neighbourhood."""
    from fastapi.responses import Response

    from app.intel.graph import EXPORT_MAX_EDGES, EXPORT_MAX_NODES, build_entity_graph
    from app.intel.graph_payload import build_payload, to_graphml

    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")
    # Same discipline as graph.json: an unusable job yields an empty document rather than
    # quietly widening the export to every job the entity was ever seen in.
    if job and not await _resolve_entity_job_scope(db, entity_id, job, user):
        empty = to_graphml(build_payload(scope="entity", focal_id=entity_id, nodes=[], edges=[], stats=_empty_graph_stats()), name=f"entity-{entity_id}")
        return Response(content=empty, media_type="application/xml", headers={"Content-Disposition": f'attachment; filename="entity-{entity_id}-graph.graphml"'})
    payload = await build_entity_graph(
        db,
        entity_id,
        hops=hops,
        limit=limit,
        include_allowlisted=bool(include_allowlisted),
        viewer=user,
        job_id=job or None,
        # The render budget exists to keep the browser responsive; a downloaded file has
        # neither that constraint nor a banner to say edges were dropped. The *node* budget
        # is pinned separately and deliberately low: MAX_NODES is read inside the builder,
        # so without this the export would inherit every interactive cap raise for free and
        # build a 5,000-node document synchronously inside a request.
        max_edges=EXPORT_MAX_EDGES,
        max_nodes=EXPORT_MAX_NODES,
        threat=False,
    )
    xml = to_graphml(payload, name=f"entity-{entity_id}")
    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="entity-{entity_id}-graph.graphml"'},
    )
