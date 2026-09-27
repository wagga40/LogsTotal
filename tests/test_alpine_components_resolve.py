"""Static guard: every Alpine component factory referenced by a template must be
resolvable at runtime.

This exists because of a real bug: `resourceTabs` was hoisted into app.js and aliased
with `const entityTabs = resourceTabs`. A top-level `const` in a classic script lands in
*script scope*, not on `window`, and Alpine evaluates `x-data` against the global object —
so every entity and case page died with "entityTabs is not defined". Server-rendered
markup looked perfectly correct, so no route test could have caught it.

A factory counts as resolvable if it is a top-level `function NAME(` declaration (which
does become a global), an explicit `window.NAME =` assignment, or an
`Alpine.data('NAME', …)` registration — in the shared static JS or in an inline <script>
in the same template.
"""

from __future__ import annotations

import re
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"
TEMPLATES = APP / "templates"
STATIC_JS = [
    APP / "static" / "app.js",
    APP / "static" / "graph.js",
    APP / "static" / "timeline.js",
]

# `x-data="foo(...)"` / `x-data='foo(...)'` — only factory *calls*, not object literals.
_X_DATA_FACTORY = re.compile(r"""x-data=(["'])\s*([A-Za-z_$][\w$]*)\s*\(""")

# Alpine and the browser provide these; they are never page-defined.
_BUILTINS = {"$store"}


def _defines(source: str, name: str) -> bool:
    escaped = re.escape(name)
    return (
        # Top-level function declarations do land on window.
        re.search(rf"^\s*function\s+{escaped}\s*\(", source, re.MULTILINE) is not None
        or re.search(rf"window\.{escaped}\s*=", source) is not None
        # Alpine.data() registration — the idiomatic form, resolved by Alpine itself.
        or re.search(rf"""Alpine\.data\(\s*["']{escaped}["']""", source) is not None
    )


def _shared_js() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in STATIC_JS if p.exists())


def _function_body(source: str, header: str) -> str:
    """The balanced `{…}` block of the function whose declaration starts with `header`.

    Slicing to the next `return {` silently re-anchors whenever the surrounding component
    is edited, so assertions could scan the wrong text.
    Brace matching depends only on the function itself.
    """
    start = source.index(header)
    open_brace = source.index("{", start)
    depth = 0
    for i in range(open_brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace : i + 1]
    raise AssertionError(f"unbalanced braces after {header!r}")


def test_every_x_data_factory_is_globally_resolvable():
    shared = _shared_js()
    missing: list[str] = []

    for template in sorted(TEMPLATES.rglob("*.html")):
        source = template.read_text(encoding="utf-8")
        # Page-local classic scripts execute while parsing, before deferred Alpine.
        assets = re.findall(r'<script(?![^>]*\bdefer\b)[^>]*src="/static/([\w.-]+\.js)', source)
        page_js = "\n".join((APP / "static" / asset).read_text(encoding="utf-8") for asset in assets)
        for _quote, name in _X_DATA_FACTORY.findall(source):
            if name in _BUILTINS:
                continue
            if _defines(source, name) or _defines(page_js, name) or _defines(shared, name):
                continue
            missing.append(f"{template.relative_to(TEMPLATES)} → {name}()")

    assert not missing, "Alpine factories referenced by x-data but not resolvable as globals:\n  " + "\n  ".join(missing)


def test_our_js_is_loaded_before_alpine():
    """Scripts defining Alpine factories must execute before alpine.min.js.

    Alpine's CDN build ends with `queueMicrotask(() => Alpine.start())`, and the HTML spec
    runs a microtask checkpoint after each script. So Alpine walks the DOM and evaluates
    every `x-data` in the microtask straight after its own script — before any *later*
    deferred script has run. Deferred scripts execute in document order, so a factory
    defined in a deferred script listed after Alpine is undefined exactly when it is
    needed. That is the "caseTabs is not defined" failure.
    """
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    alpine = base.index("/static/vendor/alpine.min.js")
    for asset in ("/static/app.js", "/static/graph.js", "/static/timeline.js", "/static/timeline-canvas.js"):
        assert asset in base, f"{asset} is not loaded from base.html"
        assert base.index(asset) < alpine, f"{asset} must be listed before alpine.min.js or its Alpine factories will not exist at Alpine.start()"


def test_alpine_start_is_still_queued_as_a_microtask():
    """Pin the assumption the ordering rule rests on.

    If a future `task vendor:update` ships an Alpine build that starts differently (e.g.
    on DOMContentLoaded), the ordering constraint above may no longer be required — but
    this test failing is the signal to re-derive it rather than silently rely on it.
    """
    alpine = (APP / "static" / "vendor" / "alpine.min.js").read_text(encoding="utf-8", errors="replace")
    assert "queueMicrotask" in alpine, "Alpine build changed; re-check the script-ordering requirement in base.html"
    assert re.search(r"window\.Alpine\s*=\s*\w+\s*;\s*queueMicrotask", alpine), "Alpine no longer auto-starts via queueMicrotask — re-derive the load-order rule in base.html"


def test_first_party_static_assets_are_cache_busted_by_mtime():
    """Assets we edit must not be pinned to the static `app_version`.

    `/static/` is served with `Cache-Control: public, max-age=3600` (app/main.py), so an
    asset whose query string never changes keeps serving a stale copy for an hour after a
    code change — which is how an already-fixed JS bug kept reproducing in the browser.
    """
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    for asset in ("app.js", "graph.js", "themes.css", "timeline.js", "timeline-canvas.js"):
        match = re.search(rf"/static/{re.escape(asset)}\?v=\{{\{{\s*(.+?)\s*\}}\}}", base)
        assert match, f"{asset} is not referenced with a cache-buster in base.html"
        expr = match.group(1)
        assert expr != "app_version", f"{asset} is cache-busted by `app_version`, which does not change when the file does"
        assert expr.startswith("asset_version("), f"{asset} should use asset_version(); got {expr!r}"


def test_shared_tab_component_is_on_window_and_has_no_stale_aliases():
    """`resourceTabs` must be a window property, and nothing may alias it.

    Pages call it directly, so the rule is: one name on window, and no alias for a name no
    template uses.
    """
    shared = _shared_js()
    assert re.search(r"window\.resourceTabs\s*=", shared), "resourceTabs must be assigned to window for Alpine to resolve it"

    # A bare top-level `const resourceTabs = ...` is exactly what this file exists to catch.
    assert not re.search(r"^\s*const\s+resourceTabs\s*=", shared, re.MULTILINE)

    called = {m.group(2) for p in TEMPLATES.rglob("*.html") for m in _X_DATA_FACTORY.finditer(p.read_text(encoding="utf-8"))}
    for alias in re.findall(r"window\.(\w+)\s*=\s*resourceTabs\s*;", shared):
        assert alias in called, f"window.{alias} aliases resourceTabs but no template calls it — drop the alias"


def test_lazy_tab_event_is_queued_behind_htmxs_domcontentloaded_handler():
    """A deep link to a lazy tab (#timeline, #graph) must not dispatch into the void.

    htmx attaches every `hx-trigger="… from:body"` listener when it processes the document
    from its own DOMContentLoaded handler, registered while <head> was parsed. `fireLoad`
    runs from Alpine's init — and Alpine schedules `$nextTick` on a 0 ms timer, whose order
    against the queued DOMContentLoaded task is not knowable. Dispatching on a guess is the
    bug: the pane spins forever and only loads once a tab switch re-fires the event.

    `document.readyState` cannot express the constraint — the spec sets it to "interactive"
    *before* deferred scripts run and fires DOMContentLoaded *after* them, so app.js always
    reads "interactive" and a `readyState === 'loading'` gate falls through to an immediate
    dispatch. Only the event itself, latched, says whether DOMContentLoaded has fired.
    """
    src = (APP / "static" / "app.js").read_text(encoding="utf-8")
    body = _function_body(src, "function resourceTabs(")

    assert "readyState" not in body, (
        "the tab component must not gate on document.readyState: it already reads 'interactive' while the deferred app.js runs, before DOMContentLoaded has fired"
    )

    latch = re.search(
        r"^(?:let|var)\s+(\w+)\s*=\s*document\.readyState\s*===\s*'complete'\s*;",
        src,
        re.MULTILINE,
    )
    assert latch, "expected a module-level latch seeded `= document.readyState === 'complete'` — 'complete' is the only readyState value that implies DOMContentLoaded has fired"
    flag = latch.group(1)

    assert re.search(rf"'DOMContentLoaded'[^;]*{re.escape(flag)}\s*=\s*true", src), f"{flag} must be set from a real DOMContentLoaded listener"
    helper = _function_body(src, "function dispatchWhenReady(")
    assert flag in helper, "dispatchWhenReady must consult the DOMContentLoaded latch before dispatching"
    assert "DOMContentLoaded" in helper, "dispatchWhenReady must fall back to a DOMContentLoaded listener while the latch is unset"
    assert "dispatchWhenReady" in body, "fireLoad must go through the shared helper rather than re-deriving the gate"


def test_no_template_hand_rolls_the_lazy_dispatch_gate():
    """The same trap, one level out: an inline page script doing it by hand.

    `resourceTabs` is guarded above, but the Intel dashboard dispatches its own section
    events from an inline `x-data`, and it shipped with exactly the broken gate:

        if (document.readyState === 'complete') fire();
        else document.addEventListener('DOMContentLoaded', fire, { once: true });

    `readyState` is 'interactive' between DOMContentLoaded and `load`, so clicking a lazy
    tab while images are still loading takes the else branch and registers a listener for an
    event that has already fired — the pane never loads. The user-visible symptom is simply
    "clicking the tab does nothing", intermittently.
    """
    offenders = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        if "dispatchEvent(new CustomEvent" not in text:
            continue
        # Strip Jinja comments and JS line comments: prose *about* the trap is how the
        # reasoning stays next to the code, and must not read as the trap itself.
        code = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
        code = "\n".join(re.sub(r"//.*$", "", line) for line in code.splitlines())
        if "readyState" in code:
            offenders.append(str(path.relative_to(TEMPLATES)))
    assert not offenders, "these templates gate a lazy dispatch on document.readyState; call window.dispatchWhenReady(event) instead:\n  " + "\n  ".join(offenders)


def test_htmx_is_evaluated_before_our_js_so_its_domcontentloaded_handler_registers_first():
    """`fireLoad` queues its lazy-tab event behind htmx's DOMContentLoaded handler.

    That works only because htmx's <script> is evaluated first: blocking, in <head>, it
    registers the handler that runs htmx.process(document.body) while the page is still
    parsing. Same-target listeners fire in registration order, so app.js — deferred and
    listed after it — can only ever be later.
    """
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")

    htmx_tag = re.search(r"<script[^>]*/static/vendor/htmx\.min\.js[^>]*>", base)
    assert htmx_tag, "htmx.min.js is not loaded from base.html"
    assert "async" not in htmx_tag.group(0), "an async htmx may be evaluated after app.js, losing the registration-order guarantee"

    app_tag = re.search(r"<script[^>]*/static/app\.js[^>]*>", base)
    assert app_tag, "app.js is not loaded from base.html"
    assert "defer" in app_tag.group(0), (
        "app.js must stay deferred: it seeds its DOMContentLoaded latch from readyState (sound only for a script that runs before the event) and binds document.body at top level"
    )
    assert htmx_tag.start() < app_tag.start(), "htmx.min.js must be listed before app.js so htmx registers its handler first"


def test_vendored_htmx_still_processes_the_document_on_domcontentloaded():
    """Pin the vendor assumption `fireLoad`'s deferral rests on.

    If `task vendor:update` ships an htmx that boots differently — earlier, later, or
    lazily — re-derive the lazy-tab dispatch gate in app.js instead of silently relying on
    this. Same rationale as test_alpine_start_is_still_queued_as_a_microtask.
    """
    htmx = (APP / "static" / "vendor" / "htmx.min.js").read_text(encoding="utf-8", errors="replace")
    assert re.search(r"""addEventListener\(\s*["']DOMContentLoaded["']""", htmx), (
        "vendored htmx no longer defers document processing to DOMContentLoaded — re-derive the lazy-tab dispatch gate in app/static/app.js"
    )
    assert re.search(r"""readyState\s*===\s*["']complete["']""", htmx), "vendored htmx no longer short-circuits on readyState === 'complete'"


def test_entity_filter_writes_the_hidden_input_before_htmx_serializes():
    """The filter must not depend on Alpine's binding having flushed.

    htmx serializes the form synchronously inside the dispatched `change`, so relying on
    `:value="entityId"` raced Alpine's scheduler: htmx sent the previous entity_id, the
    server returned an unfiltered partial, and the selection was silently wiped.
    """
    src = (APP / "static" / "app.js").read_text(encoding="utf-8")
    refetch = src[src.index("_refetch()") : src.index("clear()", src.index("_refetch()"))]
    assert "querySelector('input[name=\"entity_id\"]')" in refetch, "_refetch must set the hidden entity_id itself"
    assert "hidden.value" in refetch
    assert refetch.index("hidden.value") < refetch.index("dispatchEvent"), "the hidden value must be written BEFORE the change event is dispatched"


# ── Alpine already calls init(); x-init="init()" runs it twice ───────────────


def test_no_template_calls_init_from_x_init():
    """Alpine 3 invokes `init()` on the x-data object automatically.

    Adding `x-init="init()"` on top of that runs every component's setup twice. It is not
    cosmetic: `resourceTabs.init()` ends in `fireLoad(this.tab)`, so a deep link to a lazy
    tab dispatches its load event twice and HTMX issues two requests for the same pane;
    `graphComponent.init()` builds the graph twice over the same container.

    `x-init` with a *different* expression is fine — only the redundant self-call is
    banned, so this matches the exact string.
    """
    offenders = [str(p.relative_to(TEMPLATES)) for p in TEMPLATES.rglob("*.html") if 'x-init="init()"' in p.read_text(encoding="utf-8")]
    assert not offenders, 'x-init="init()" double-runs Alpine\'s automatic init() in: ' + ", ".join(sorted(offenders))


# ── The shared confirm dialog must not carry a decision between dialogs ──────


def test_confirm_dialog_latches_acceptance_instead_of_reading_return_value():
    """`dialog.returnValue` is not reset by showModal() on every engine.

    Reading it in the `close` handler meant that once an action had been confirmed, the
    value stayed 'confirm' and dismissing the *next* confirm dialog with Escape fired that
    next action anyway — a destructive action running on a cancel.
    """
    source = (APP / "static" / "app.js").read_text(encoding="utf-8")
    assert "dialog.returnValue === 'confirm'" not in source, "confirm dialog still trusts a returnValue that can survive from the previous dialog"
    assert "accepted = false;" in source, "expected an explicit acceptance flag reset when the dialog is shown"


# ── One severity palette, one file ──────────────────────────────────────────


def test_severity_palettes_live_only_in_the_shared_macro():
    """No template may re-declare the severity→Tailwind-class mapping.

    Copies drift — `bg-red-900/40` in one, `/50` in the next, a hand-written
    `{% if severity == 'critical' %}` chain elsewhere. `partials/_severity_macros.html` is
    the single source; every other
    template imports from it.
    """
    macros = TEMPLATES / "partials" / "_severity_macros.html"
    offenders = []
    for path in TEMPLATES.rglob("*.html"):
        if path == macros:
            continue
        body = path.read_text(encoding="utf-8")
        # A dict literal keyed by severity, or an if-chain emitting Tailwind classes.
        # `{% if case.severity == 'critical' %}selected{% endif %}` on a <select> is fine —
        # only class output counts, hence the bg-/text-/border- anchor.
        if "'critical':" in body or '"critical":' in body:
            offenders.append(f"{path.relative_to(TEMPLATES)} (severity dict literal)")
        if re.search(r"severity\s*==\s*'critical'\s*%\}\s*(bg|text|border)-", body):
            offenders.append(f"{path.relative_to(TEMPLATES)} (severity if-chain)")

    assert not offenders, "severity palette duplicated outside partials/_severity_macros.html: " + ", ".join(sorted(offenders))


#: Jinja `{# … #}`, JS `/* … */` and JS `// …` — replaced by blanks of the same shape, so
#: a guard can scan for real code without losing its line numbers.
_COMMENTS = re.compile(r"\{#.*?#\}|/\*.*?\*/|//[^\n]*", re.S)


def _blank_comments(source: str) -> str:
    return _COMMENTS.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)


def test_only_app_js_reaches_navigator_clipboard():
    """`navigator.clipboard` exists ONLY in a secure context — HTTPS, or http on
    localhost/127.0.0.1.

    LogsTotal ships a supported plain-HTTP mode (`COOKIE_INSECURE=true`, Docker without
    the `proxy` profile), and on it the whole API is `undefined`: a direct
    `navigator.clipboard.writeText(…)` throws `TypeError: can't access property "writeText"`
    on click, and a guarded one silently does nothing.

    So the API has exactly one caller, `ltCopy()` in app.js, which falls back to
    `document.execCommand('copy')` — the only thing that works outside a secure context —
    and raises the shared toast when even that is refused. A route test cannot see this:
    the button renders identically whether or not it can ever work.
    """
    offenders: list[str] = []
    for path in [*sorted(TEMPLATES.rglob("*.html")), *STATIC_JS]:
        if path.name == "app.js":
            continue
        # Comments may still name it — several of them explain why not to call it. Blanked
        # rather than deleted so the reported line numbers stay true.
        body = _blank_comments(path.read_text(encoding="utf-8"))
        for line_no, line in enumerate(body.splitlines(), 1):
            if "navigator.clipboard" in line:
                offenders.append(f"{path.relative_to(APP)}:{line_no}")

    assert not offenders, "Call `ltCopy()` (app.js) instead — `navigator.clipboard` is undefined on any page served over plain HTTP: " + ", ".join(offenders)


def test_the_copy_helper_and_the_toast_are_on_window():
    """Both are reached from outside app.js — `ltCopy` from `graph.js` and from two inline
    `copyIocPack` functions, `ltToast` from `dismissHtmxError`'s neighbours — and a
    top-level `const` in a classic script lands in script scope, not on `window`. That is
    the exact bug this module was created for (`entityTabs`), one file over.
    """
    js = _shared_js()
    for name in ("ltCopy", "ltToast"):
        assert _defines(js, name), f"{name} is not globally resolvable"
