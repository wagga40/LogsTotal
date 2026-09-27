"""
Shared Jinja2Templates instance with custom filters.
Import this instead of creating new Jinja2Templates in each router.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from app.config import settings
from app.docs_site import docs_url
from app.pagination import page_window, qs_pairs, qs_without_page


def _asset_version(path: str) -> str:
    """Cache-buster for a first-party static asset: its mtime, falling back to the app version.

    Must be used for every asset we edit ourselves. `/static/` is served with
    `Cache-Control: public, max-age=3600` (see app/main.py), so an asset pinned to the
    static `app_version` keeps serving a stale copy for an hour after a code change.
    """
    try:
        return str(int(Path(path).stat().st_mtime))
    except OSError:
        return settings.app_version


def _time_ago(dt: datetime | None) -> str:
    """Relative timestamp for display ("5m ago"); naive datetimes are UTC (DB convention)."""
    if dt is None:
        return ""
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    delta = datetime.now(UTC).replace(tzinfo=None) - dt
    seconds = delta.total_seconds()
    if seconds < 60:  # includes future timestamps (clock skew) — clamp to "just now"
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    if delta.days <= 30:
        return f"{delta.days}d ago"
    return dt.strftime("%Y-%m-%d")


templates = Jinja2Templates(directory="app/templates")
templates.env.filters["from_json"] = json.loads
templates.env.filters["time_ago"] = _time_ago


def _humanbytes(value) -> str:
    """`1841842509` -> `1.7 GB`. One implementation, so every page agrees on the boundaries.

    Binary units, because that is what `du` and every disk gauge in this UI report.
    """
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return "—"
    if size < 1024:
        return f"{int(size)} B"
    for unit in ("KB", "MB", "GB", "TB"):
        size /= 1024
        if size < 1024:
            return f"{size:.1f} {unit}"
    return f"{size:.1f} PB"


templates.env.filters["humanbytes"] = _humanbytes
templates.env.globals["app_version"] = settings.app_version
# Exposed as a callable, not a precomputed value: uvicorn's --reload only watches *.py by
# default, so a JS/CSS-only edit would otherwise keep serving the mtime captured at import
# and the browser would never re-fetch. One stat() per render is free next to the template.
# Vendor bundles keep `app_version` — they only change via `task vendor:update`, which is
# a deliberate, versioned event.
templates.env.globals["asset_version"] = _asset_version
# The pager's window and its go-to form's hidden fields — see app/pagination.py.
templates.env.globals["page_window"] = page_window
# The documentation website; see app/docs_site.py.
templates.env.globals["docs_url"] = docs_url
templates.env.globals["qs_pairs"] = qs_pairs
templates.env.globals["qs_without_page"] = qs_without_page


def _register_syntax_help() -> None:
    """The two search grammars' help panels, as globals rather than context keys.

    Both are static application data — the list the *parser* reads — not per-request state,
    and each is rendered from more than one place: the entity grammar's help hangs off
    the dashboard box, the rule condition field and the graph filter, whose contexts are
    built in three different routers and two included partials. A context key missed at one
    of those sites renders a perfectly good `?` button over an empty panel, which no route
    test would notice. Imported lazily inside the function so this module keeps importing
    without dragging the intel package in at definition time.
    """
    from app.intel.queries import SYNTAX_HELP as ENTITY_SYNTAX_HELP
    from app.intel.queries import SYNTAX_INTRO as ENTITY_SYNTAX_INTRO
    from app.jobs_query import SYNTAX_HELP as JOBS_SYNTAX_HELP

    templates.env.globals["entity_syntax_help"] = ENTITY_SYNTAX_HELP
    templates.env.globals["entity_syntax_intro"] = ENTITY_SYNTAX_INTRO
    templates.env.globals["jobs_syntax_help"] = JOBS_SYNTAX_HELP


_register_syntax_help()


def _register_condition_grammar() -> None:
    """What the condition editor needs to colour a term, taken from the parsers.

    The editor is a highlight overlay behind a real `<textarea>`, so it has to tokenise in
    JavaScript — and a second grammar written by hand there is a grammar that drifts. Only
    the *structural* vocabulary crosses over: which prefixes exist, and the two boolean
    words. Values do not, and neither does validity.

    **Nothing here lets the client call a term invalid.** In both grammars an unrecognised
    `word:value` is a deliberate literal search — filenames and rule ids contain colons —
    so painting an unknown prefix red would report a working query as broken. The client
    flags only what is structurally certain (an unclosed quote, regex or paren); everything
    else is the 400 ms server preview's job, which is the only thing that actually parses.
    """
    from app.intel.queries import _AND, _OR, _PREFIXES
    from app.jobs_query import PREFIXES as JOB_PREFIXES

    templates.env.globals["condition_grammar"] = {
        # Longest-first, so `re:/` is tried before any shorter prefix could claim its head.
        "entity": {"prefixes": sorted(_PREFIXES, key=len, reverse=True), "suggest_url": "/intel/search-suggest"},
        "job": {"prefixes": sorted(JOB_PREFIXES, key=len, reverse=True), "suggest_url": "/jobs/search-suggest"},
        "operators": [_OR, _AND],
        "regex_prefix": "re:/",
    }


_register_condition_grammar()


def _register_tag_write_max() -> None:
    """How many tags one submission may carry, for the picker's `max`.

    From the server's constant rather than a literal in each of the six templates that
    instantiate the picker: a client cap above the server's silently drops the tail of what
    the analyst typed, and one below makes a supported thing look unsupported.
    """
    from app.tags import TAG_WRITE_MAX

    templates.env.globals["tag_write_max"] = TAG_WRITE_MAX


_register_tag_write_max()


def _tojson_safe(v, **kw):
    rv = json.dumps(v, **kw)
    # Escape characters that are dangerous in HTML/attribute contexts. Single
    # quotes are escaped too (matching Jinja's built-in tojson) so the output is
    # safe inside single-quoted attributes such as Alpine `x-data='...'`.
    rv = rv.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("'", "\\u0027")
    return Markup(rv)  # noqa: S704  # pre-escaped &, <, >, ' above; output is JSON-safe for HTML contexts


templates.env.filters["tojson"] = _tojson_safe


def _markdown(value):
    """Render analyst prose as Markdown. See app/markdown_render.py for why it is safe.

    Registered as a filter so templates read `{{ text | markdown }}`, but never call it
    directly — go through the `rich_text()` macro in `partials/_rich_text.html`, which also
    honours the `render_markdown` site setting. A template that reaches past the macro will
    render Markdown on an instance that switched it off.
    """
    from app.markdown_render import render

    return render(value)


templates.env.filters["markdown"] = _markdown


def negotiated(request, *, page: str, fragment: str, context: dict):
    """One URL, two representations of the same surface.

    HTMX callers (the Intel dashboard's section tabs, and every action inside those panels)
    get the region alone; a plain navigation gets the full page. Both render from the *same*
    context, so a tab and its standalone page cannot drift — which is what a second
    `-partial` route invites.

    `Vary: HX-Request` because the two representations share a URL: without it a cache in
    front could hand a browser navigation the bare fragment, or paste a whole page into a
    tab pane. GZipMiddleware appends its own `Accept-Encoding` to this rather than
    replacing it.

    Lives here rather than in a router because several routers render this way.
    """
    response = templates.TemplateResponse(request, fragment if request.headers.get("HX-Request") else page, context)
    response.headers["Vary"] = "HX-Request"
    return response
