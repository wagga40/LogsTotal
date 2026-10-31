"""Explore: search, filter, chart and export every event of a job's upload, or of a case.

Two routers share every handler through `_Target`:

- `router`, at `/jobs`, mounted after `jobs.router` and `ai.router` (whose literal second
  segments keep their precedence): `/{job_id}/explore…`.
- `case_router`, at `/intel/cases`, mounted after `cases.router`: `/{case_id}/explore…`,
  every event of every visible job in the case, as one table (`engine.UnionView`).

**Access is narrower than the job page.** Explore shows events no rule fired on, so a job
needs `models.can_explore_job` (active, `can_view_job`, and member+ or the job's own
signed-in submitter), and a case needs member+ and a case the viewer may see, with each of
its jobs through `visible_job_filter`. Both need `EVENTS_ENABLED` and
`SiteSettings.show_explore`. **Every refusal is the 404 a missing job or case answers**,
so the routes cannot be used to probe what exists.

Queries are blocking DuckDB work in `app/events/engine.py`; every call goes through
`run_in_threadpool`, and the closures handed over take plain values only — never an ORM
instance, whose lazy read inside a worker thread is a `MissingGreenlet`.
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace

import orjson
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity, job_artifacts
from app.auth.users import current_member_or_above, current_user_optional
from app.config import settings
from app.constants import SEVERITY_COLORS
from app.csv_utils import csv_safe
from app.database import get_async_session
from app.events import cache, detail
from app.events.engine import EngineBusy, EngineError, EngineTimeout, StorePart, StoreView, UnionView, get_engine
from app.events.query import LEVELS, QueryError, Rule, Schema, column_filter_to_terms, combine, compile_query
from app.events.state import PER_PAGE, ExploreState, column_label, default_columns
from app.events.store import link_failure, request_build_async, store_for_job_async
from app.models import AnalysisJob, CaseJobLink, EventStoreStatus, Finding, InvestigationCase, LogFile, TaskResult, User, can_explore_job, visible_job_filter
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/jobs", tags=["explore"])
case_router = APIRouter(prefix="/intel/cases", tags=["explore"])
logger = logging.getLogger(__name__)

NOT_FOUND = "Job not found."
CASE_NOT_FOUND = "Case not found"
CSV_MAX_ROWS = 500_000
NDJSON_MAX_ROWS = 100_000
STACK_ROWS = 1000
FIELDS_SHOWN = 60
#: Uploads one case Explore reads at once; past it the banner says which were left out.
CASE_STORES_MAX = 20
#: Case jobs considered (the coverage banner counts them all).
CASE_JOBS_MAX = 500
_TECHNIQUE = re.compile(r"^t\d{4}(?:\.\d{3})?$")
_COLORS = {"events": "#60a5fa", "detected": SEVERITY_COLORS["high"], "brush": "rgba(148,163,184,0.25)"}


# ── what Explore runs over ──────────────────────────────────────────────────


@dataclass
class _JobOverlay:
    """One job's detections on a store: plain values, safe for the threadpool."""

    job_id: int
    tag: str
    rules: list[list]
    tags: dict[tuple[str, str], list[str]]


@dataclass
class _Part:
    sha256: str
    gen: str
    label: str
    events: int
    overlays: list[_JobOverlay] = field(default_factory=list)
    job_ids: list[int] = field(default_factory=list)


@dataclass
class _Target:
    """A job's upload, or a case's uploads. Every handler below takes one."""

    kind: str
    id: int
    page_url: str
    parts: list[_Part]
    coverage: dict | None = None
    link_failure: str | None = None

    @property
    def base_url(self) -> str:
        return f"{self.page_url}/explore"

    @property
    def events(self) -> int:
        return sum(p.events for p in self.parts)

    @property
    def labels(self) -> list[str]:
        return [p.label for p in self.parts]

    @property
    def union(self) -> bool:
        return self.kind == "case"


def _rules(overlay: _JobOverlay, offset: int) -> list[Rule]:
    from app.intel.tactics import normalize_tactic_tag

    out = []
    for ix, (tool, key, name, level) in enumerate(overlay.rules):
        tags = overlay.tags.get((tool, key)) or overlay.tags.get((tool, name)) or []
        stripped = [t.lower().removeprefix("attack.") for t in tags]
        tactics = tuple(dict.fromkeys(t for t in (normalize_tactic_tag(tag) for tag in tags) if t))
        techniques = tuple(dict.fromkeys(t.upper() for t in stripped if _TECHNIQUE.match(t)))
        out.append(Rule(offset + ix, tool, key, name, level, tactics, techniques))
    return out


_manifests: dict[str, dict] = {}


def _manifest(root) -> dict:
    from app.json_utils import load_file

    key = str(root)
    if key not in _manifests:
        if len(_manifests) > 64:
            _manifests.clear()
        _manifests[key] = load_file(root / "manifest.json")
    return _manifests[key]


@contextlib.contextmanager
def _open(target: _Target):
    """The target's stores and overlays at local paths, as (view, schema). Blocking."""
    with contextlib.ExitStack() as stack:
        parts: list[StorePart] = []
        rules: list[Rule] = []
        tags: list[str] = []
        for part in target.parts:
            root = stack.enter_context(cache.store_dir(part.sha256, part.gen))
            manifest = _manifest(root)
            overlays = []
            for ov in part.overlays:
                path = cache.overlay_dir(part.sha256, part.gen, ov.job_id, ov.tag)
                if path is None:
                    continue
                overlays.append((path, len(rules)))
                rules.extend(_rules(ov, len(rules)))
                tags.append(f"{ov.job_id}:{ov.tag}")
            parts.append(StorePart(root, manifest, tuple(overlays)))
        tag = hashlib.sha256("|".join(tags).encode()).hexdigest()[:16] if tags else ""
        if target.union:
            gen = "case-" + hashlib.sha256("|".join(p.gen for p in target.parts).encode()).hexdigest()[:16]
            view = UnionView(parts, gen=gen, overlay_tag=tag)
        else:
            only = parts[0]
            view = StoreView(root=only.root, manifest=only.manifest, gen=target.parts[0].gen, overlay=only.overlays[0][0] if only.overlays else None, overlay_tag=tag)
        linked = view.levels_source is not None
        yield view, Schema.from_manifest(view.manifest, overlay=linked, rules=tuple(rules) if linked else ())


async def _rule_tags(db: AsyncSession, job_id: int) -> dict[tuple[str, str], list[str]]:
    """Sigma tags per (tool, rule id or name), from the job's findings, for tactic:/technique:."""
    rows = await db.execute(
        select(TaskResult.tool_name, Finding.rule_id, Finding.rule_name, Finding.tags).join(Finding, Finding.task_result_id == TaskResult.id).where(TaskResult.job_id == job_id)
    )
    out: dict[tuple[str, str], list[str]] = {}
    for tool, rule_id, rule_name, tags in rows.all():
        try:
            parsed = orjson.loads(tags) if tags else []
        except orjson.JSONDecodeError:
            parsed = []
        names = [str(t) for t in parsed] if isinstance(parsed, list) else []
        for key in {str(rule_id or ""), str(rule_name or "")} - {""}:
            out.setdefault((tool or "", key), []).extend(names)
    return out


async def _job_overlay(db: AsyncSession, job_id: int, gen: str) -> _JobOverlay | None:
    meta = await job_artifacts.get_payload(db, job_id, job_artifacts.EVENT_OVERLAY)
    overlay = job_artifacts.unpack(meta) if meta else None
    if not overlay or overlay.get("gen") != gen:
        _ask_for_overlay(job_id)
        return None
    return _JobOverlay(job_id, str(overlay.get("links_sha") or ""), list(overlay.get("rules") or []), await _rule_tags(db, job_id))


def _ask_for_overlay(job_id: int) -> None:
    """Explore was opened on a stale or missing overlay: ask the worker, at most once a minute."""
    try:
        from app.redis_client import get_redis

        if not get_redis().set(f"logstotal:events:overlay-asked:{job_id}", 1, ex=60, nx=True):
            return
        from app.workers.tasks import build_event_overlay

        build_event_overlay(job_id)
    except Exception:
        logger.debug("Could not ask for job %d's overlay", job_id, exc_info=True)


async def _explorable_job(db: AsyncSession, job_id: int, user: User | None):
    job = await db.get(AnalysisJob, job_id)
    if job is None or not settings.events_enabled or not can_explore_job(job, user):
        raise HTTPException(404, NOT_FOUND)
    site = await get_site_settings(db)
    if not site.show_explore:
        raise HTTPException(404, NOT_FOUND)
    return job, site


async def _job_target(db: AsyncSession, job, request: Request, user, site) -> tuple[_Target | None, HTMLResponse | None]:
    """The job's target, or the status response for an upload without a ready index."""
    row, sha = await store_for_job_async(db, job)
    if row is None or row.status != EventStoreStatus.READY.value or not row.gen or not sha:
        return None, _job_status(request, job, row, user, site)
    part = _Part(sha, row.gen, "", row.event_count or 0)
    overlay = await _job_overlay(db, job.id, row.gen)
    if overlay is not None:
        part.overlays.append(overlay)
    return _Target("job", job.id, f"/jobs/{job.id}", [part], link_failure=None if overlay else link_failure(job.id)), None


async def _explorable_case(db: AsyncSession, case_id: int, user: User):
    case = await db.get(InvestigationCase, case_id)
    if case is None or not (user.is_superuser or case.created_by_user_id == user.id or case.is_shared) or not settings.events_enabled:
        raise HTTPException(404, CASE_NOT_FOUND)
    site = await get_site_settings(db)
    if not site.show_explore:
        raise HTTPException(404, CASE_NOT_FOUND)
    return case, site


async def _case_target(db: AsyncSession, case, request: Request, user, site) -> tuple[_Target | None, HTMLResponse | None]:
    """The case's visible jobs' indexed uploads, deduplicated, at most CASE_STORES_MAX."""
    stmt = (
        select(AnalysisJob.id, LogFile.original_filename)
        .join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id)
        .join(LogFile, LogFile.id == AnalysisJob.file_id)
        .where(CaseJobLink.case_id == case.id)
        .order_by(AnalysisJob.id)
        .limit(CASE_JOBS_MAX)
    )
    vis = visible_job_filter(user)
    if vis is not True:
        stmt = stmt.where(vis)
    jobs = (await db.execute(stmt)).all()
    parts: dict[tuple[str, str], _Part] = {}
    missing: list[dict] = []
    skipped = 0
    for job_id, filename in jobs:
        job = await db.get(AnalysisJob, job_id)
        row, sha = await store_for_job_async(db, job)
        if row is None or row.status != EventStoreStatus.READY.value or not row.gen or not sha:
            missing.append({"id": job_id, "filename": filename})
            continue
        key = (sha, row.gen)
        if key not in parts:
            if len(parts) >= CASE_STORES_MAX:
                skipped += 1
                continue
            parts[key] = _Part(sha, row.gen, filename or sha[:12], row.event_count or 0)
        part = parts[key]
        part.job_ids.append(job_id)
        overlay = await _job_overlay(db, job_id, row.gen)
        if overlay is not None:
            part.overlays.append(overlay)
    for part in parts.values():
        # One upload can sit under several jobs of the case: the Source column names them all.
        part.label = f"{part.label} (" + ", ".join(f"#{j}" for j in part.job_ids) + ")"
    coverage = {"jobs": len(jobs), "indexed": len(jobs) - len(missing) - skipped, "uploads": len(parts), "missing": missing[:10], "missing_total": len(missing), "skipped": skipped}
    if not parts:
        return None, _render(
            request,
            "partials/_explore_status.html",
            {"phase": "case-none", "coverage": coverage, "pane_url": f"/intel/cases/{case.id}/explore-partial", "user": user, "site_settings": site},
        )
    return _Target("case", case.id, f"/intel/cases/{case.id}", list(parts.values()), coverage), None


# ── shared pieces ───────────────────────────────────────────────────────────


def _compile(state: ExploreState, schema: Schema, *, with_range: bool = True):
    """The typed query AND the controls' terms. Raises QueryError for the typed query only."""
    typed = compile_query(state.q, schema)
    return combine(typed, compile_query(state.control_terms(linked=schema.overlay, with_range=with_range), schema))


def _columns_meta(view) -> list[dict]:
    total = max(1, int((view.manifest.get("totals") or {}).get("events") or 1))
    cols = sorted(view.manifest.get("columns") or [], key=lambda c: (-int(c.get("count") or 0), c["name"].lower()))
    return [{"name": c["name"], "path": c.get("path") or c["name"], "type": c["type"], "coverage": round(100 * int(c.get("count") or 0) / total, 1)} for c in cols]


def _results_context(view, schema: Schema, state: ExploreState, target: _Target) -> dict:
    """Run the page's queries. Blocking: called inside the threadpool."""
    engine = get_engine()
    columns = [c for c in state.columns_or(default_columns(view.manifest, union=target.union)) if c in view.columns]
    try:
        compiled = _compile(state, schema)
    except QueryError as exc:
        return {"error": str(exc), "error_span": (exc.start, exc.end), "columns": columns}
    try:
        total = engine.count(view, compiled)
        pages = max(1, -(-total // PER_PAGE))
        if state.page > pages:
            state = replace(state, page=pages)
        page = engine.page(view, compiled, offset=state.offset, limit=PER_PAGE, columns=columns, sort=state.sort, desc=state.desc)
        stack = _stack(engine, view, compiled, state) if state.stack else None
    except EngineBusy:
        return {"busy": True, "columns": columns}
    except EngineTimeout:
        return {"error": f"That search took longer than {settings.events_query_timeout_seconds} s. Narrow it with a field or a time range.", "columns": columns}
    except EngineError as exc:
        return {"error": str(exc), "columns": columns}
    return {"rows": page.rows, "total": total, "pages": pages, "state": state, "columns": columns, "stack": stack}


def _stack(engine, view, compiled, state: ExploreState) -> dict:
    """Value combinations of the stacked fields among the matches, rarest first, each with the
    terms that narrow the search to it (built here, carried in data-term)."""
    result = engine.stack(view, compiled, list(state.stack), limit=STACK_ROWS)
    rows = []
    for values, n in result["rows"]:
        terms = [
            filter_term(name, "=" + _cell(v)) if v is not None else ("" if name.startswith("_lt_") else f"-{column_filter_to_terms(name, '*')}")
            for name, v in zip(state.stack, values, strict=True)
        ]
        rows.append({"cells": [_cell(v) for v in values], "n": n, "term": " ".join(t for t in terms if t)})
    return {"fields": list(state.stack), "rows": rows, "groups": result["groups"], "shown": len(rows)}


def _render(request: Request, template: str, context: dict, *, headers: dict | None = None) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"request": request, **context}, headers=headers)


def _base(target: _Target, view, schema: Schema, state: ExploreState, user, site) -> dict:
    return {
        "user": user,
        "state": state,
        "store": {
            "events": target.events,
            "time": view.manifest.get("time") or {},
            "warnings": view.manifest.get("warnings") or [],
            "truncated": (view.manifest.get("totals") or {}).get("truncated"),
        },
        "coverage": target.coverage,
        "link_failure": target.link_failure,
        "link_status_url": f"{target.base_url}/link-status" if target.kind == "job" else None,
        "store_labels": target.labels,
        "linked": schema.overlay,
        "levels": LEVELS,
        "column_label": column_label,
        "filterable_fixed": FILTERABLE_FIXED,
        "column_types": view.columns,
        "per_page": PER_PAGE,
        "base_url": target.base_url,
        "site_settings": site,
        # Shipped to the canvas as data, never declared in the client: one palette.
        "colors": _COLORS,
    }


async def _in_threadpool(target: _Target, request: Request, fn: Callable):
    def work():
        with _open(target) as (view, schema):
            return fn(view, schema, ExploreState.from_params(request.query_params, set(view.columns)))

    return await run_in_threadpool(work)


# ── handlers, shared by the job and the case routes ─────────────────────────


async def _pane(request: Request, target: _Target, user, site) -> HTMLResponse:
    cold = [p for p in target.parts if not cache.is_local_or_cached(p.sha256, p.gen)]
    if cold:
        for p in cold:
            cache.prefetch(p.sha256, p.gen)
        return _render(request, "partials/_explore_status.html", {"phase": "preparing", "pane_url": f"{target.base_url}-partial", "user": user, "site_settings": site})

    def run(view, schema, state):
        return view, schema, state, _results_context(view, schema, state, target), _columns_meta(view)

    view, schema, state, results, fields = await _in_threadpool(target, request, run)
    context = _base(target, view, schema, state, user, site) | results | {"fields": fields[:FIELDS_SHOWN], "field_count": len(fields)}
    return _render(request, "partials/_explore.html", context)


async def _results(request: Request, target: _Target, user, site) -> HTMLResponse:
    def run(view, schema, state):
        fcol, fval = request.query_params.get("fcol"), request.query_params.get("fval")
        if fcol and fcol in view.columns and fval is not None:
            term = filter_term(fcol, fval)
            if term:
                state = replace(state, q=f"{state.q} {term}".strip(), page=1)
        return view, schema, state, _results_context(view, schema, state, target)

    view, schema, state, results = await _in_threadpool(target, request, run)
    state = results.get("state", state)
    qs = state.qs()
    headers = {
        "HX-Replace-Url": f"{target.page_url}{'?' + qs if qs else ''}#explore",
        "HX-Trigger": orjson.dumps({"exploreResults": {"qs": state.qs(ev=None, page=1), "q": state.q}}).decode(),
    }
    return _render(request, "partials/_explore_results.html", _base(target, view, schema, state, user, site) | results, headers=headers)


async def _histogram(request: Request, target: _Target, width: int) -> JSONResponse:
    def run(view, schema, state):
        try:
            compiled = _compile(state, schema, with_range=False)
        except QueryError as exc:
            return {"error": str(exc)}
        try:
            return get_engine().histogram(view, compiled, start=state.start, end=state.end, width_px=max(100, min(4000, width)))
        except EngineBusy:
            return {"busy": True}
        except EngineError as exc:
            return {"error": str(exc)}

    return JSONResponse(await _in_threadpool(target, request, run))


async def _field(request: Request, target: _Target, f: str) -> HTMLResponse:
    def run(view, schema, state):
        if f not in view.columns:
            return {"error": "No such field."}
        try:
            facet = get_engine().facet(view, _compile(state, schema), f, limit=10)
        except QueryError as exc:
            return {"error": str(exc)}
        except EngineBusy:
            return {"error": "Busy; try again in a moment."}
        except EngineError as exc:
            return {"error": str(exc)}
        rows = []
        for value, n in facet["values"]:
            text = _cell(value)
            rows.append(
                {
                    "value": text,
                    "n": n,
                    "pct": round(100 * n / max(1, facet["matched"]), 1),
                    "plus": column_filter_to_terms(f, "=" + text),
                    "minus": column_filter_to_terms(f, "!=" + text),
                }
            )
        return {"facet": facet, "rows": rows}

    out = await _in_threadpool(target, request, run)
    return _render(request, "partials/_explore_field.html", {"field": f, "label": column_label(f), **out})


async def _event(request: Request, target: _Target, uid: int) -> HTMLResponse:
    def run(view, schema, state):
        try:
            event = get_engine().event(view, uid) if uid >= 0 else None
        except EngineError as exc:
            return {"error": str(exc)}
        if event is None:
            return {"error": "No such event."}
        fields = dict(event["fields"])
        if "_lt_store" in fields and 0 <= int(fields["_lt_store"]) < len(target.labels):
            fields["_lt_store"] = target.labels[int(fields["_lt_store"])]
        return {
            "uid": uid,
            "groups": detail.group_fields(fields, view.manifest),
            "json": orjson.dumps(detail.rebuild_json(fields, view.manifest), option=orjson.OPT_INDENT_2).decode(),
            "matched": [r for r in schema.rules if r.ix in set(event["rules"])],
            "plus": _plus_terms(fields),
            "around": _around(fields),
        }

    out = await _in_threadpool(target, request, run)
    return _render(request, "partials/_explore_event.html", out)


async def _suggest(request: Request, target: _Target, q: str, pos: int) -> JSONResponse:
    from app.events.query import SHORTCUTS
    from app.intel.queries import caret_token

    def run(view, schema, state):
        names = sorted(c["name"] for c in view.manifest.get("columns") or [])
        prefixes = tuple(f"{s}:" for s in SHORTCUTS) + tuple(f"{n.lower()}:" for n in names)
        token = caret_token(q, pos if pos >= 0 else len(q), prefixes, quoted_values=True)
        fragment = token["fragment"].lower()
        if token["prefix"] is None:
            options = [f"{s}:" for s in SHORTCUTS] + [f"{n}:" for n in names]
            return token, [o for o in options if o.lower().startswith(fragment)][:20]
        key = token["prefix"][:-1]
        if key == "level":
            return token, [lv for lv in LEVELS if lv.startswith(fragment.lstrip("<>="))]
        if key == "det":
            return token, ["yes", "no"]
        if key in ("tool", "rule", "rulekey"):
            attr = {"tool": "tool", "rulekey": "key", "rule": "name"}[key]
            values = sorted({str(getattr(r, attr)) for r in schema.rules})
            return token, [v for v in values if fragment in v.lower()][:20]
        column = schema.resolve(key)
        if column is None:
            return token, []
        try:
            facet = get_engine().facet(view, compile_query("", schema), column, limit=20)
        except EngineError:
            return token, []
        return token, [str(v) for v, _n in facet["values"] if fragment in str(v).lower()][:12]

    token, suggestions = await _in_threadpool(target, request, run)
    return JSONResponse({"start": token["start"], "end": token["end"], "prefix": token["prefix"], "suggestions": suggestions})


def _export_limited(user: User) -> bool:
    """Per-user fixed window, failing open when Redis is down (the AI limiter's trade-off)."""
    limit = settings.events_export_rate_limit_per_minute
    if not limit or limit <= 0:
        return False
    try:
        from app.middleware.production import _redis_window_hits

        return _redis_window_hits(f"logstotal:ratelimit:events-export:{user.id}", 60) > limit
    except Exception:
        return False


async def _export(request: Request, target: _Target, user: User, fmt: str) -> Response:
    """The matching events as CSV (visible columns, 500k rows) or NDJSON (every field, 100k)."""
    if _export_limited(user):
        return Response(f"Too many exports in the last minute (limit {settings.events_export_rate_limit_per_minute}). Try again shortly.", status_code=429, media_type="text/plain")
    held = _open(target)
    view, schema = await run_in_threadpool(held.__enter__)
    try:
        state = ExploreState.from_params(request.query_params, set(view.columns))
        try:
            compiled = _compile(state, schema)
        except QueryError as exc:
            await run_in_threadpool(held.__exit__, None, None, None)
            return Response(str(exc), status_code=400, media_type="text/plain")
        if fmt == "csv":
            columns = [c for c in state.columns_or(default_columns(view.manifest, union=target.union)) if c in view.columns]
            max_rows = CSV_MAX_ROWS
        else:
            columns = list(view.columns)
            max_rows = NDJSON_MAX_ROWS
        stream = get_engine().export(view, compiled, columns, max_rows=max_rows)
        first = await run_in_threadpool(next, stream, None)
    except EngineBusy:
        await run_in_threadpool(held.__exit__, None, None, None)
        return Response("Another export is running. Try again shortly.", status_code=429, media_type="text/plain")
    except Exception:
        await run_in_threadpool(held.__exit__, None, None, None)
        raise
    audit = {
        "request": request,
        "user": user,
        "target_type": target.kind,
        "target_id": str(target.id),
        "summary": f"{fmt}: {state.q or 'all events'}"[:200],
        "meta": {"format": fmt, "query": state.q, "det": state.det, "max_rows": max_rows},
    }
    # Literal action keys: tests/test_activity_log.py reads them off the call sites.
    if target.union:
        await activity.record("export.case_events", **audit)
    else:
        await activity.record("export.job_events", **audit)
    labels = target.labels

    def body():
        try:
            batch = first
            out = io.StringIO()
            writer = csv.writer(out)
            if fmt == "csv":
                yield "﻿"
                writer.writerow([column_label(c) for c in columns])
            while batch:
                for row in batch:
                    if fmt == "csv":
                        writer.writerow([csv_safe(_cell(labels[v] if c == "_lt_store" and v is not None and v < len(labels) else v)) for c, v in zip(columns, row, strict=True)])
                    else:
                        out.write(orjson.dumps({c: v for c, v in zip(columns, row, strict=True) if v is not None}, default=str).decode() + "\n")
                yield out.getvalue()
                out.seek(0)
                out.truncate()
                batch = next(stream, None)
        finally:
            stream.close()
            held.__exit__(None, None, None)

    media = "text/csv; charset=utf-8" if fmt == "csv" else "application/x-ndjson"
    return StreamingResponse(body(), media_type=media, headers={"Content-Disposition": f'attachment; filename="{target.kind}-{target.id}-events.{fmt}"'})


#: The fixed columns the drawer offers a + for, by the shortcut that searches them.
_FIXED_SHORTCUTS = {"_lt_host": "host", "_lt_channel": "channel", "_lt_eid": "eid"}
#: Columns whose filter-row cell means something (every other fixed one has no term).
FILTERABLE_FIXED = frozenset({*_FIXED_SHORTCUTS, "_lt_time"})


def filter_term(column: str, cell: str) -> str:
    """A filter-row cell as a query term. The fixed columns go through their shortcuts
    (`_lt_eid` is searched as `eid:`), and Time takes a comparison as after:/before:."""
    if column in _FIXED_SHORTCUTS:
        return column_filter_to_terms(_FIXED_SHORTCUTS[column], cell, shortcut=True)
    if column == "_lt_time":
        cell = (cell or "").strip()
        for op, key in ((">=", "after"), (">", "after"), ("<=", "before"), ("<", "before")):
            if cell.startswith(op) and cell[len(op) :].strip():
                return f"{key}:{cell[len(op) :].strip()}"
        return ""
    if column.startswith("_lt_"):
        return ""
    return column_filter_to_terms(column, cell)


def _plus_terms(fields: dict) -> dict[str, str]:
    """A "+ add to the search" term for every field shown in the drawer."""
    out = {}
    for name, value in fields.items():
        if value is None:
            continue
        if name in _FIXED_SHORTCUTS:
            out[name] = column_filter_to_terms(_FIXED_SHORTCUTS[name], "=" + str(value), shortcut=True)
        elif not name.startswith("_lt_"):
            out[name] = column_filter_to_terms(name, "=" + _cell(value))
    return out


def _around(fields: dict) -> dict | None:
    """The "±5 minutes on this host" search: the host term and the time window."""
    from datetime import timedelta

    host, when = fields.get("_lt_host"), fields.get("_lt_time")
    if not host or when is None:
        return None
    return {
        "term": column_filter_to_terms("host", "=" + str(host), shortcut=True),
        "from": (when - timedelta(minutes=5)).isoformat(),
        "to": (when + timedelta(minutes=5)).isoformat(),
    }


def _cell(value) -> str:
    if value is None:
        return ""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


# ── job routes ──────────────────────────────────────────────────────────────


def _job_status(request: Request, job, row, user, site) -> HTMLResponse:
    phase = "none" if row is None else row.status
    return _render(
        request,
        "partials/_explore_status.html",
        {
            "phase": phase,
            "row": row,
            "user": user,
            "site_settings": site,
            "pane_url": f"/jobs/{job.id}/explore-partial",
            "build_url": f"/jobs/{job.id}/explore/build",
            "can_build": site.explore_build_enabled and phase in ("none", "failed", "evicted"),
        },
    )


async def _job_or_status(db, job_id, request, user):
    job, site = await _explorable_job(db, job_id, user)
    target, status = await _job_target(db, job, request, user, site)
    return target, status, site


@router.get("/{job_id}/explore-partial", response_class=HTMLResponse)
async def explore_partial(job_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """The whole Explore pane, or its status when the upload has no ready index."""
    target, status, site = await _job_or_status(db, job_id, request, user)
    return status or await _pane(request, target, user, site)


@router.post("/{job_id}/explore/build", response_class=HTMLResponse)
async def explore_build(job_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """Ask for this upload's event index (jobs analysed before indexes existed, or a retry)."""
    job, site = await _explorable_job(db, job_id, user)
    if not site.explore_build_enabled:
        raise HTTPException(404, NOT_FOUND)
    store_id = await request_build_async(db, job, manual=True)
    await db.commit()
    if store_id is not None:
        from app.workers.tasks import build_event_store

        try:
            build_event_store(store_id)
        except Exception:
            logger.warning("Job %d: could not queue the event index build", job_id, exc_info=True)
        await activity.record("job.events_index", request=request, user=user, target_type="job", target_id=str(job_id))
    row, _sha = await store_for_job_async(db, job)
    return _job_status(request, job, row, user, site)


@router.get("/{job_id}/explore/link-status", response_class=HTMLResponse)
async def explore_link_status(job_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """While a job's detections are being linked: the notice that polls for the end of it.

    Answers the notice again (still polling) until the overlay exists, then a notice with a
    button that reloads the pane, never the pane itself: the user may be typing a search.
    """
    job, _site = await _explorable_job(db, job_id, user)
    row, _sha = await store_for_job_async(db, job)
    meta = await job_artifacts.get_payload(db, job.id, job_artifacts.EVENT_OVERLAY)
    overlay = job_artifacts.unpack(meta) if meta else None
    linked = bool(row and overlay and overlay.get("gen") == row.gen)
    context = {
        "linked": linked,
        "link_failure": None if linked else link_failure(job.id),
        "link_status_url": f"/jobs/{job.id}/explore/link-status",
        "base_url": f"/jobs/{job.id}/explore",
    }
    return _render(request, "partials/_explore_link_status.html", context)


@router.get("/{job_id}/explore/results", response_class=HTMLResponse)
async def explore_results(job_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """The table, its counts and its pager, for the current search. Sets the address bar."""
    target, status, site = await _job_or_status(db, job_id, request, user)
    return status or await _results(request, target, user, site)


@router.get("/{job_id}/explore/histogram.json")
async def explore_histogram(job_id: int, request: Request, width: int = 800, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    target, status, _site = await _job_or_status(db, job_id, request, user)
    return JSONResponse({"error": "not indexed"}) if status else await _histogram(request, target, width)


@router.get("/{job_id}/explore/field", response_class=HTMLResponse)
async def explore_field(job_id: int, request: Request, f: str = "", db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """The most frequent values of one field among the current matches, with + / - terms."""
    target, status, _site = await _job_or_status(db, job_id, request, user)
    return HTMLResponse("") if status else await _field(request, target, f)


@router.get("/{job_id}/explore/event", response_class=HTMLResponse)
async def explore_event(job_id: int, request: Request, uid: int = -1, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """One event in the drawer: its fields by group, the rules that matched it, its JSON."""
    target, status, _site = await _job_or_status(db, job_id, request, user)
    return HTMLResponse("") if status else await _event(request, target, uid)


@router.get("/{job_id}/explore/suggest")
async def explore_suggest(
    job_id: int, request: Request, q: str = "", pos: int = -1, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)
):
    """Completions for the term under the caret: field names and shortcuts, or a field's values."""
    target, status, _site = await _job_or_status(db, job_id, request, user)
    return JSONResponse({"start": 0, "end": 0, "prefix": None, "suggestions": []}) if status else await _suggest(request, target, q, pos)


@router.get("/{job_id}/explore/export.{fmt}")
async def explore_export(job_id: int, fmt: str, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    if fmt not in ("csv", "ndjson"):
        raise HTTPException(404, NOT_FOUND)
    target, status, _site = await _job_or_status(db, job_id, request, user)
    if status is not None:
        raise HTTPException(404, NOT_FOUND)
    return await _export(request, target, user, fmt)


# ── case routes ─────────────────────────────────────────────────────────────


async def _case_or_status(db, case_id, request, user):
    case, site = await _explorable_case(db, case_id, user)
    target, status = await _case_target(db, case, request, user, site)
    return target, status, site


@case_router.get("/{case_id}/explore-partial", response_class=HTMLResponse)
async def case_explore_partial(case_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)):
    """Every event of every visible job in the case, as one Explore pane."""
    target, status, site = await _case_or_status(db, case_id, request, user)
    return status or await _pane(request, target, user, site)


@case_router.get("/{case_id}/explore/results", response_class=HTMLResponse)
async def case_explore_results(case_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)):
    target, status, site = await _case_or_status(db, case_id, request, user)
    return status or await _results(request, target, user, site)


@case_router.get("/{case_id}/explore/histogram.json")
async def case_explore_histogram(case_id: int, request: Request, width: int = 800, db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)):
    target, status, _site = await _case_or_status(db, case_id, request, user)
    return JSONResponse({"error": "not indexed"}) if status else await _histogram(request, target, width)


@case_router.get("/{case_id}/explore/field", response_class=HTMLResponse)
async def case_explore_field(case_id: int, request: Request, f: str = "", db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)):
    target, status, _site = await _case_or_status(db, case_id, request, user)
    return HTMLResponse("") if status else await _field(request, target, f)


@case_router.get("/{case_id}/explore/event", response_class=HTMLResponse)
async def case_explore_event(case_id: int, request: Request, uid: int = -1, db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)):
    target, status, _site = await _case_or_status(db, case_id, request, user)
    return HTMLResponse("") if status else await _event(request, target, uid)


@case_router.get("/{case_id}/explore/suggest")
async def case_explore_suggest(
    case_id: int, request: Request, q: str = "", pos: int = -1, db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)
):
    target, status, _site = await _case_or_status(db, case_id, request, user)
    return JSONResponse({"start": 0, "end": 0, "prefix": None, "suggestions": []}) if status else await _suggest(request, target, q, pos)


@case_router.get("/{case_id}/explore/export.{fmt}")
async def case_explore_export(case_id: int, fmt: str, request: Request, db: AsyncSession = Depends(get_async_session), user: User = Depends(current_member_or_above)):
    if fmt not in ("csv", "ndjson"):
        raise HTTPException(404, CASE_NOT_FOUND)
    target, status, _site = await _case_or_status(db, case_id, request, user)
    if status is not None:
        raise HTTPException(404, CASE_NOT_FOUND)
    return await _export(request, target, user, fmt)
