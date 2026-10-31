"""Explore: search, filter, chart and export every event of a job's upload.

Mounted at `/jobs` after `jobs.router` and `ai.router`, whose literal second segments keep
their precedence; every route here is `/{job_id}/explore…`.

**Access is narrower than the job page.** Explore shows events no rule fired on, so it needs
`models.can_explore_job` (active, `can_view_job`, and member+ or the job's own signed-in
submitter) on top of `EVENTS_ENABLED` and `SiteSettings.show_explore`. **Every refusal is
`HTTPException(404, "Job not found.")`**, the body `job_detail` answers for a job that does
not exist: a public job someone may read but not explore, a private job, an off switch and
a missing id must be indistinguishable, or the 404 becomes a probe.

Queries are blocking DuckDB work in `app/events/engine.py`; every call goes through
`run_in_threadpool`, and the closure handed over takes plain values only — never an ORM
instance, whose lazy read inside a worker thread is a `MissingGreenlet`.
"""

from __future__ import annotations

import contextlib
import csv
import io
import logging
import re
from dataclasses import dataclass, field, replace

import orjson
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity, job_artifacts
from app.auth.users import current_user_optional
from app.config import settings
from app.constants import SEVERITY_COLORS
from app.csv_utils import csv_safe
from app.database import get_async_session
from app.events import cache, detail
from app.events.engine import EngineBusy, EngineError, EngineTimeout, StoreView, get_engine
from app.events.query import LEVELS, QueryError, Rule, Schema, column_filter_to_terms, combine, compile_query
from app.events.state import PER_PAGE, ExploreState, column_label, default_columns
from app.events.store import request_build_async, store_for_job_async
from app.models import AnalysisJob, EventStoreStatus, Finding, TaskResult, User, can_explore_job
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/jobs", tags=["explore"])
logger = logging.getLogger(__name__)

NOT_FOUND = "Job not found."
CSV_MAX_ROWS = 500_000
NDJSON_MAX_ROWS = 100_000
FIELDS_SHOWN = 60
_TECHNIQUE = re.compile(r"^t\d{4}(?:\.\d{3})?$")


async def _explorable(db: AsyncSession, job_id: int, user: User | None):
    job = await db.get(AnalysisJob, job_id)
    if job is None or not settings.events_enabled or not can_explore_job(job, user):
        raise HTTPException(404, NOT_FOUND)
    site = await get_site_settings(db)
    if not site.show_explore:
        raise HTTPException(404, NOT_FOUND)
    return job, site


@dataclass
class _Ctx:
    """Everything a query needs, as plain values: safe to hand to a threadpool."""

    job_id: int
    sha256: str
    gen: str
    event_count: int
    overlay_tag: str = ""
    rules: list[list] = field(default_factory=list)
    tags: dict[tuple[str, str], list[str]] = field(default_factory=dict)


async def _ready_ctx(db: AsyncSession, job) -> tuple[_Ctx | None, object | None]:
    """(_Ctx, None) for a ready store, else (None, the store row or None)."""
    row, sha = await store_for_job_async(db, job)
    if row is None or row.status != EventStoreStatus.READY.value or not row.gen or not sha:
        return None, row
    ctx = _Ctx(job_id=job.id, sha256=sha, gen=row.gen, event_count=row.event_count or 0)
    meta = await job_artifacts.get_payload(db, job.id, job_artifacts.EVENT_OVERLAY)
    overlay = job_artifacts.unpack(meta) if meta else None
    if overlay and overlay.get("gen") == row.gen:
        ctx.overlay_tag, ctx.rules = str(overlay.get("links_sha") or ""), list(overlay.get("rules") or [])
        ctx.tags = await _rule_tags(db, job.id)
    else:
        _ask_for_overlay(job.id)
    return ctx, row


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


def _schema(ctx: _Ctx, manifest: dict, *, linked: bool) -> Schema:
    """The store's columns, and the job's rules when its overlay is at hand."""
    from app.intel.tactics import normalize_tactic_tag

    if not linked:
        return Schema.from_manifest(manifest)
    rules = []
    for ix, (tool, key, name, level) in enumerate(ctx.rules):
        tags = ctx.tags.get((tool, key)) or ctx.tags.get((tool, name)) or []
        tactics = tuple(dict.fromkeys(t for t in (normalize_tactic_tag(tag) for tag in tags) if t))
        techniques = tuple(dict.fromkeys(tag.lower().removeprefix("attack.").upper() for tag in tags if _TECHNIQUE.match(tag.lower().removeprefix("attack."))))
        rules.append(Rule(ix, tool, key, name, level, tactics, techniques))
    return Schema.from_manifest(manifest, overlay=True, rules=tuple(rules))


_manifests: dict[tuple[str, str], dict] = {}


def _manifest(root) -> dict:
    from app.json_utils import load_file

    key = (str(root), root.name)
    if key not in _manifests:
        if len(_manifests) > 32:
            _manifests.clear()
        _manifests[key] = load_file(root / "manifest.json")
    return _manifests[key]


@contextlib.contextmanager
def _view(ctx: _Ctx):
    """The store and the job's overlay at local paths, for the length of the block. Blocking."""
    with cache.store_dir(ctx.sha256, ctx.gen) as root:
        overlay = cache.overlay_dir(ctx.sha256, ctx.gen, ctx.job_id, ctx.overlay_tag) if ctx.overlay_tag else None
        manifest = _manifest(root)
        view = StoreView(root=root, manifest=manifest, gen=ctx.gen, overlay=overlay, overlay_tag=ctx.overlay_tag if overlay else "")
        yield view, _schema(ctx, manifest, linked=overlay is not None)


def _compile(state: ExploreState, schema: Schema, *, with_range: bool = True):
    """The typed query AND the controls' terms. Raises QueryError for the typed query only."""
    typed = compile_query(state.q, schema)
    return combine(typed, compile_query(state.control_terms(linked=schema.overlay, with_range=with_range), schema))


def _columns_meta(view: StoreView) -> list[dict]:
    total = max(1, int((view.manifest.get("totals") or {}).get("events") or 1))
    cols = sorted(view.manifest.get("columns") or [], key=lambda c: (-int(c.get("count") or 0), c["name"].lower()))
    return [{"name": c["name"], "path": c.get("path") or c["name"], "type": c["type"], "coverage": round(100 * int(c.get("count") or 0) / total, 1)} for c in cols]


def _results_context(view: StoreView, schema: Schema, state: ExploreState) -> dict:
    """Run the page's queries. Blocking: called inside the threadpool."""
    engine = get_engine()
    columns = [c for c in state.columns_or(default_columns(view.manifest)) if c in view.columns]
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
    except EngineBusy:
        return {"busy": True, "columns": columns}
    except EngineTimeout:
        return {"error": f"That search took longer than {settings.events_query_timeout_seconds} s. Narrow it with a field or a time range.", "columns": columns}
    except EngineError as exc:
        return {"error": str(exc), "columns": columns}
    return {"rows": page.rows, "total": total, "pages": pages, "state": state, "columns": columns}


def _render(request: Request, template: str, context: dict, *, headers: dict | None = None) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"request": request, **context}, headers=headers)


def _base(job, ctx: _Ctx, view: StoreView, schema: Schema, state: ExploreState, user, site) -> dict:
    return {
        "job": job,
        "user": user,
        "state": state,
        "store": {
            "events": ctx.event_count,
            "time": view.manifest.get("time") or {},
            "warnings": view.manifest.get("warnings") or [],
            "truncated": (view.manifest.get("totals") or {}).get("truncated"),
        },
        "linked": schema.overlay,
        "rules": ctx.rules,
        "levels": LEVELS,
        "column_label": column_label,
        "filterable_fixed": FILTERABLE_FIXED,
        "column_types": view.columns,
        "per_page": PER_PAGE,
        "base_url": f"/jobs/{job.id}/explore",
        "site_settings": site,
        # Shipped to the canvas as data, never declared in the client: one palette.
        "colors": {"events": "#60a5fa", "detected": SEVERITY_COLORS["high"], "brush": "rgba(148,163,184,0.25)"},
    }


# ── the pane ────────────────────────────────────────────────────────────────


@router.get("/{job_id}/explore-partial", response_class=HTMLResponse)
async def explore_partial(job_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """The whole Explore pane, or its status when the upload has no ready index."""
    job, site = await _explorable(db, job_id, user)
    ctx, row = await _ready_ctx(db, job)
    if ctx is None:
        return _status(request, job, row, user, site)
    if not cache.is_local_or_cached(ctx.sha256, ctx.gen):
        cache.prefetch(ctx.sha256, ctx.gen)
        return _render(request, "partials/_explore_status.html", {"job": job, "phase": "preparing", "user": user, "site_settings": site})

    def work():
        with _view(ctx) as (view, schema):
            state = ExploreState.from_params(request.query_params, set(view.columns))
            return view, schema, state, _results_context(view, schema, state), _columns_meta(view)

    view, schema, state, results, fields = await run_in_threadpool(work)
    context = _base(job, ctx, view, schema, state, user, site) | results | {"fields": fields[:FIELDS_SHOWN], "field_count": len(fields)}
    return _render(request, "partials/_explore.html", context)


def _status(request: Request, job, row, user, site) -> HTMLResponse:
    phase = "none" if row is None else row.status
    return _render(
        request,
        "partials/_explore_status.html",
        {"job": job, "phase": phase, "row": row, "user": user, "site_settings": site, "can_build": site.explore_build_enabled and phase in ("none", "failed", "evicted")},
    )


@router.post("/{job_id}/explore/build", response_class=HTMLResponse)
async def explore_build(job_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """Ask for this upload's event index (jobs analysed before indexes existed, or a retry)."""
    job, site = await _explorable(db, job_id, user)
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
    return _status(request, job, row, user, site)


# ── results, chart, fields, drawer ──────────────────────────────────────────


async def _with_ready(db, job_id, request, user, fn):
    job, site = await _explorable(db, job_id, user)
    ctx, row = await _ready_ctx(db, job)
    if ctx is None:
        return None, _status(request, job, row, user, site)

    def work():
        with _view(ctx) as (view, schema):
            return fn(view, schema, ExploreState.from_params(request.query_params, set(view.columns)))

    return (job, site, ctx), await run_in_threadpool(work)


@router.get("/{job_id}/explore/results", response_class=HTMLResponse)
async def explore_results(job_id: int, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """The table, its counts and its pager, for the current search. Sets the address bar."""

    def run(view, schema, state):
        fcol, fval = request.query_params.get("fcol"), request.query_params.get("fval")
        if fcol and fcol in view.columns and fval is not None:
            term = filter_term(fcol, fval)
            if term:
                state = replace(state, q=f"{state.q} {term}".strip(), page=1)
        return view, schema, state, _results_context(view, schema, state)

    held, out = await _with_ready(db, job_id, request, user, run)
    if held is None:
        return out
    job, site, ctx = held
    view, schema, state, results = out
    state = results.get("state", state)
    headers = {
        "HX-Replace-Url": f"/jobs/{job.id}{'?' + state.qs() if state.qs() else ''}#explore",
        "HX-Trigger": orjson.dumps({"exploreResults": {"qs": state.qs(ev=None, page=1), "q": state.q}}).decode(),
    }
    return _render(request, "partials/_explore_results.html", _base(job, ctx, view, schema, state, user, site) | results, headers=headers)


@router.get("/{job_id}/explore/histogram.json")
async def explore_histogram(job_id: int, request: Request, width: int = 800, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
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

    held, out = await _with_ready(db, job_id, request, user, run)
    if held is None:
        return JSONResponse({"error": "not indexed"})
    return JSONResponse(out)


@router.get("/{job_id}/explore/field", response_class=HTMLResponse)
async def explore_field(job_id: int, request: Request, f: str = "", db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """The most frequent values of one field among the current matches, with + / - terms."""

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
            text = value.isoformat() if hasattr(value, "isoformat") else str(value)
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

    held, out = await _with_ready(db, job_id, request, user, run)
    if held is None:
        return HTMLResponse("")
    return _render(request, "partials/_explore_field.html", {"field": f, "label": column_label(f), **out})


@router.get("/{job_id}/explore/event", response_class=HTMLResponse)
async def explore_event(job_id: int, request: Request, uid: int = -1, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """One event in the drawer: its fields by group, the rules that matched it, its JSON."""

    def run(view, schema, state):
        try:
            event = get_engine().event(view, uid) if uid >= 0 else None
        except EngineError as exc:
            return {"error": str(exc)}
        if event is None:
            return {"error": "No such event."}
        fields = event["fields"]
        return {
            "uid": uid,
            "groups": detail.group_fields(fields, view.manifest),
            "json": orjson.dumps(detail.rebuild_json(fields, view.manifest), option=orjson.OPT_INDENT_2).decode(),
            "matched": [schema.rules[ix] for ix in event["rules"] if ix < len(schema.rules)],
            "plus": _plus_terms(fields),
            "around": _around(fields),
        }

    held, out = await _with_ready(db, job_id, request, user, run)
    if held is None:
        return HTMLResponse("")
    job, _site, _ctx = held
    return _render(request, "partials/_explore_event.html", {"job": job, **out})


#: The fixed columns the drawer offers a + for, by the shortcut that searches them.
_FIXED_SHORTCUTS = {"_lt_host": "host", "_lt_channel": "channel", "_lt_eid": "eid"}


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


#: Columns whose filter-row cell means something (every other fixed one has no term).
FILTERABLE_FIXED = frozenset({*_FIXED_SHORTCUTS, "_lt_time"})


def _plus_terms(fields: dict) -> dict[str, str]:
    """A "+ add to the search" term for every field shown in the drawer."""
    out = {}
    for name, value in fields.items():
        if value is None:
            continue
        if name in _FIXED_SHORTCUTS:
            out[name] = column_filter_to_terms(_FIXED_SHORTCUTS[name], "=" + str(value), shortcut=True)
        elif not name.startswith("_lt_"):
            out[name] = column_filter_to_terms(name, "=" + (value.isoformat() if hasattr(value, "isoformat") else str(value)))
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


@router.get("/{job_id}/explore/suggest")
async def explore_suggest(
    job_id: int, request: Request, q: str = "", pos: int = -1, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)
):
    """Completions for the term under the caret: field names and shortcuts, or a field's values."""
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

    held, out = await _with_ready(db, job_id, request, user, run)
    if held is None:
        return JSONResponse({"start": 0, "end": 0, "prefix": None, "suggestions": []})
    token, suggestions = out
    return JSONResponse({"start": token["start"], "end": token["end"], "prefix": token["prefix"], "suggestions": suggestions})


# ── export ──────────────────────────────────────────────────────────────────


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


@router.get("/{job_id}/explore/export.{fmt}")
async def explore_export(job_id: int, fmt: str, request: Request, db: AsyncSession = Depends(get_async_session), user: User | None = Depends(current_user_optional)):
    """The matching events as CSV (visible columns, 500k rows) or NDJSON (every field, 100k)."""
    if fmt not in ("csv", "ndjson"):
        raise HTTPException(404, NOT_FOUND)
    job, _site = await _explorable(db, job_id, user)
    ctx, _row = await _ready_ctx(db, job)
    if ctx is None:
        raise HTTPException(404, NOT_FOUND)
    if _export_limited(user):
        return Response(f"Too many exports in the last minute (limit {settings.events_export_rate_limit_per_minute}). Try again shortly.", status_code=429, media_type="text/plain")

    held = _view(ctx)
    view, schema = await run_in_threadpool(held.__enter__)
    try:
        state = ExploreState.from_params(request.query_params, set(view.columns))
        try:
            compiled = _compile(state, schema)
        except QueryError as exc:
            await run_in_threadpool(held.__exit__, None, None, None)
            return Response(str(exc), status_code=400, media_type="text/plain")
        if fmt == "csv":
            columns = [c for c in state.columns_or(default_columns(view.manifest)) if c in view.columns]
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
    await activity.record(
        "export.job_events",
        request=request,
        user=user,
        target_type="job",
        target_id=str(job_id),
        summary=f"{fmt}: {state.q or 'all events'}"[:200],
        meta={"format": fmt, "query": state.q, "det": state.det, "max_rows": max_rows},
    )

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
                        writer.writerow([csv_safe(_cell(v)) for v in row])
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
    return StreamingResponse(body(), media_type=media, headers={"Content-Disposition": f'attachment; filename="job-{job_id}-events.{fmt}"'})


def _cell(value) -> str:
    if value is None:
        return ""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)
