"""Source-shape guards for the relationship-graph client.

There is no JS test runner in the Python suite, so these are grep-style assertions in the
same genre as `tests/test_alpine_components_resolve.py`. They exist because every trap they
pin produces a **working-looking** server response and a broken frame — no route test can
reach any of them.

The highest-value one is `test_layout_never_uses_a_blob_worker`: every graphology layout
example reaches for `FA2Layout`, which builds its worker from a `blob:` URL, and our CSP
declares no `worker-src`/`child-src`. The worker is blocked *silently*, so a contributor
copying the docs would ship a layout that simply never runs.

The pure logic these files contain — the emphasis precedence table, the query engine, the
payload merge — is covered by `task test:js` (`tests/js/*.test.mjs`), which is where
behaviour belongs. Grep cannot test behaviour and these tests do not pretend to.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from _taskfile import all_raw, taskfile_paths

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
STATIC = APP / "static"
VENDOR = STATIC / "vendor"
PARTIALS = APP / "templates" / "intel" / "partials"

GRAPH_JS = STATIC / "graph.js"
GRAPH_VIEW_JS = STATIC / "graph-view.js"
GRAPH_ALGO_JS = STATIC / "graph-algo.js"
GRAPH_RENDER_JS = STATIC / "graph-render.js"
GRAPH_FILES = [GRAPH_JS, GRAPH_VIEW_JS, GRAPH_ALGO_JS, GRAPH_RENDER_JS]

BASE_HTML = APP / "templates" / "base.html"
GRAPH_SHELLS = [PARTIALS / "_entity_graph.html", PARTIALS / "_case_graph.html"]


def _strip_jinja_comments(source: str) -> str:
    """Drop `{# … #}` blocks, so prose about a banned construct doesn't trip an assertion."""
    return re.sub(r"\{#.*?#\}", "", source, flags=re.S)


def _strip_comments(source: str) -> str:
    """Drop `//` line comments so prose about a banned construct doesn't trip an assertion."""
    return "\n".join(re.sub(r"//.*$", "", line) for line in source.splitlines())


# ── The CSP trap ───────────────────────────────────────────────────────────


def test_layout_never_uses_a_blob_worker():
    """FA2 must run synchronously and chunked, never in a worker.

    `SecurityHeadersMiddleware` sets no `worker-src`/`child-src`, so a `blob:` worker falls
    back to `default-src 'self'` and is refused. The failure is silent: the layout object
    constructs, `start()` resolves, and nothing ever moves.
    """
    src = _strip_comments(GRAPH_ALGO_JS.read_text())
    for banned in ("FA2Layout", "ForceLayout", "NoverlapLayout", "new Worker", "createObjectURL"):
        assert banned not in src, (
            f"{banned} builds or drives a blob: worker, which this app's CSP blocks silently. Use layoutForceAtlas2.assign chunked over requestAnimationFrame."
        )
    assert "layoutForceAtlas2" in src
    assert "requestAnimationFrame" in src


def test_csp_still_has_no_worker_directive():
    """Pins the premise of the test above rather than letting it quietly become vacuous."""
    csp = (APP / "middleware" / "production.py").read_text()
    assert "worker-src" not in csp
    assert "child-src" not in csp


# ── Load order ─────────────────────────────────────────────────────────────


def test_vendor_bundles_precede_first_party_and_alpine():
    """One block, in dependency order, all before alpine.min.js.

    Alpine's build ends with `queueMicrotask(() => Alpine.start())` and the HTML spec runs
    a microtask checkpoint after each script, so Alpine evaluates every `x-data` before any
    later deferred script has run. Our factory must already exist — and our modules must
    already see `window.Sigma` / `window.graphology`.

    This also pins the *single* block: the previous arrangement had vendor at the bottom of
    <body> and ours in <head>, bridged by a 5 s poll, which is exactly how two lists drift.
    """
    html = BASE_HTML.read_text()
    order = [
        "vendor/graphology.umd.min.js",
        "vendor/graphology-library.min.js",
        "vendor/sigma.min.js",
        "static/graph-view.js",
        "static/graph-algo.js",
        "static/graph-render.js",
        "static/graph.js",
        "vendor/alpine.min.js",
    ]
    positions = [html.index(name) for name in order]
    assert positions == sorted(positions), f"script order is wrong: {list(zip(order, positions, strict=True))}"


def test_no_cytoscape_code_remains():
    """Comments are stripped first, so a note that names Cytoscape to explain a design
    choice does not trip the guard."""
    for path in [*GRAPH_FILES, BASE_HTML, *taskfile_paths(), *GRAPH_SHELLS]:
        text = _strip_comments(path.read_text()) if path.suffix == ".js" else path.read_text()
        if path.suffix == ".html":
            text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
        assert "cytoscape" not in text.lower(), f"{path.name} still references Cytoscape"
    assert not (VENDOR / "cytoscape.min.js").exists()


def test_vendor_bundles_are_present_and_expose_what_we_call():
    """A `task vendor:update` that drops or renames a namespace should fail loudly here.

    Sigma composes event names (`rightClick` + `"Node"`), so grepping the minified bundle
    for `rightClickNode` returns nothing — that is expected, and why the sigma probes below
    are the uncomposed halves.
    """
    expectations = {
        "graphology.umd.min.js": ["MultiGraph", "addDirectedEdgeWithKey", "addUndirectedEdgeWithKey"],
        "graphology-library.min.js": ["communitiesLouvain", "layoutForceAtlas2", "inferSettings", "circlepack", "pagerank", "canvas"],
        "sigma.min.js": [
            "nodeReducer",
            "edgeReducer",
            "createNodeBorderProgram",
            "EdgeCurveProgram",
            "EdgeArrowProgram",
            "EdgeRectangleProgram",
            "viewportToGraph",
            "preventSigmaDefault",
            "getCanvases",
            "allowInvalidContainer",
            "enableCameraPanning",
            "hideEdgesOnMove",
            "labelRenderedSizeThreshold",
        ],
    }
    for name, symbols in expectations.items():
        path = VENDOR / name
        assert path.exists(), f"{name} is missing — run `task vendor:update`"
        blob = path.read_text(errors="replace")
        for symbol in symbols:
            assert symbol in blob, f"{name} no longer contains {symbol!r} — the client calls it"


# ── The palette lives on the server ────────────────────────────────────────

_HEX = re.compile(r"#(?:[0-9a-fA-F]{3}){1,2}\b")

# The one place a hex is legitimate on the client: the two neutral surface colours the
# renderer needs before any payload has landed. Everything semantic — entity type,
# severity, tactic, edge kind — arrives in `schema.colors`.
_ALLOWED_CLIENT_HEXES: set[str] = set()


def test_graph_client_declares_no_palette():
    """Mirrors `test_severity_palettes_live_only_in_the_shared_macro`.

    Copies of a palette drift. The graph is worse: it paints into a WebGL canvas, so it
    cannot use a Tailwind class at
    all, and the legend and the node must agree exactly. Both read `schema.colors`, which
    the server builds from `constants` + `tactics`.
    """
    for path in [*GRAPH_FILES, PARTIALS / "_graph_legend.html", PARTIALS / "_graph_toolbar.html", PARTIALS / "_graph_panel.html"]:
        found = set(_HEX.findall(_strip_comments(path.read_text()))) - _ALLOWED_CLIENT_HEXES
        assert not found, f"{path.name} declares colours ({sorted(found)}) — read them from schema.colors instead"


def test_legend_renders_every_schema_enum_rather_than_a_hardcoded_list():
    """No entity types or hexes spelled out by hand."""
    legend = (PARTIALS / "_graph_legend.html").read_text()
    assert "schema.types" in legend
    assert "schema.colors.type[" in legend
    assert "schema.severities" in legend
    assert "schema.tactics" in legend


# ── Server-decided defaults ────────────────────────────────────────────────


def test_graph_client_reads_default_hidden_types():
    """`defaults.hidden_types` moved server-side; the client must actually read it.

    A route assertion alone would silently lose coverage of the client half — an inline
    `isEntity || k !== 'hash'` would pass a test that only checks the payload while the
    client kept its own opinion.
    """
    src = _strip_comments(GRAPH_JS.read_text())
    assert "hiddenTypes" in src
    assert "hidden_types" in _strip_comments(GRAPH_VIEW_JS.read_text())
    assert "'hash'" not in src, "the hidden-type default belongs to the server, not the client"


# ── Abort discipline ─────────────────────────────────────────────────────────


def _function_body(source: str, header: str) -> str:
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


def test_reload_keeps_its_abort_discipline():
    """Three behaviours, each of which was a real bug once.

    1. A duplicate identical request is collapsed (the pane is initialized twice — Alpine's
       MutationObserver *and* base.html's htmx:afterSwap hook).
    2. A different query aborts the previous one, or hops 1->3->1 leaves two requests
       racing and the last to resolve wins.
    3. A reload aborts a pending expand but **never the reverse**: an expand sets no
       `loading` flag, so cancelling a reload would leave nothing to clear it.
    """
    body = _strip_comments(_function_body(GRAPH_JS.read_text(), "reload() {"))
    assert "this._inflight === query" in body
    assert "this._abort.abort()" in body
    assert "this._expandAbort.abort()" in body
    assert "this._abort !== controller" in body, "the .finally() guard must not clear a newer controller's state"


def test_expand_never_aborts_a_reload():
    body = _strip_comments(_function_body(GRAPH_JS.read_text(), "_expandNode(entityId, label, relType) {"))
    assert "this._abort.abort()" not in body, "an expand must never cancel a reload — the reload's `loading` flag would have no one left to clear it"
    assert "this._expandAbort.abort()" in body


# ── Renderer lifecycle ─────────────────────────────────────────────────────


def test_renderer_suspends_on_zero_size_not_on_scroll():
    """The pane can be swapped in while `display:none`, and each swap must not leak a
    WebGL context — browsers cap live contexts at around sixteen.

    The trigger is the container collapsing to 0x0 (the `x-show` tab being switched away),
    **not** leaving the viewport. An IntersectionObserver is wrong here: the graph pane
    sits ~840 px down the entity page, so it would suspend before the analyst ever scrolled
    to it and churn a context on every scroll past.
    """
    src = GRAPH_RENDER_JS.read_text()
    assert "ResizeObserver" in src
    assert "IntersectionObserver" not in _strip_comments(src), "scrolled-past is not hidden"
    observe = _function_body(src, "function observe() {")
    assert "box.width < 2 || box.height < 2" in observe
    assert "suspend()" in observe and "resume()" in observe
    destroy = _function_body(src, "function destroy() {")
    assert "disconnect()" in destroy
    assert "state.sigma.kill()" in destroy


def test_webgl_probe_releases_its_context():
    """A probe context that is never released is one of sixteen, leaked per page load."""
    body = _strip_comments(_function_body(GRAPH_RENDER_JS.read_text(), "function webglAvailable() {"))
    assert "WEBGL_lose_context" in body
    assert "loseContext()" in body


def test_context_loss_is_handled_and_prevents_default():
    """Unhandled upstream (sigma#1321). `preventDefault()` is mandatory: without it the
    browser never fires a restore event and the canvas stays black for good."""
    src = _strip_comments(GRAPH_RENDER_JS.read_text())
    assert "webglcontextlost" in src
    assert "ev.preventDefault()" in src
    assert "state.recoveries" in src, "repeated loss must give one clear message, not a burning tab"


def test_drag_cancels_all_three_default_behaviours():
    """Miss any one and the stage pans underneath the node being dragged."""
    src = _strip_comments(GRAPH_RENDER_JS.read_text())
    for call in ("preventSigmaDefault()", "original.preventDefault()", "original.stopPropagation()"):
        assert call in src, f"node drag needs {call}"


def test_count_dependent_settings_are_applied_after_the_payload():
    """At construction the graph is empty, so both gates would read zero forever."""
    body = _strip_comments(_function_body(GRAPH_RENDER_JS.read_text(), "function applyCountDependentSettings() {"))
    assert "hideEdgesOnMove" in body
    assert "enableEdgeEvents" in body
    assert "state.graph.size" in body


def test_no_library_is_touched_at_module_evaluation_time():
    """Belt-and-braces on top of load order: a top-level `window.Sigma.x` would throw
    before the vendor bundle had run, taking the whole factory with it."""
    for path in (GRAPH_VIEW_JS, GRAPH_ALGO_JS, GRAPH_RENDER_JS):
        src = _strip_comments(path.read_text())
        # Everything lives inside one IIFE; the only top-level statement is the wrapper.
        assert src.lstrip().startswith("(function ()"), f"{path.name} should wrap its body in an IIFE"


def test_factories_are_reachable_from_alpine():
    """A top-level `const foo = …` in a classic script lands in script scope, not on
    `window`, so Alpine cannot see it. The component factory must be a `function`
    declaration and each module must publish one explicit namespace."""
    assert re.search(r"^function graphComponent\(", GRAPH_JS.read_text(), re.M)
    for path, name in (
        (GRAPH_VIEW_JS, "LogsTotalGraphView"),
        (GRAPH_ALGO_JS, "LogsTotalGraphAlgo"),
        (GRAPH_RENDER_JS, "LogsTotalGraphRender"),
    ):
        assert f"window.{name} =" in path.read_text()


# ── Template shells ────────────────────────────────────────────────────────


def test_graph_container_ref_matches_the_one_the_renderer_watches():
    assert "this.$refs.graph" in GRAPH_JS.read_text()
    for shell in GRAPH_SHELLS:
        assert re.search(r'x-ref=["\']graph["\']', shell.read_text()), f'{shell.name} lost its x-ref="graph"'


@pytest.mark.parametrize("shell", GRAPH_SHELLS, ids=lambda p: p.name)
def test_options_blob_is_one_single_quoted_tojson(shell: Path):
    """`| tojson` emits double quotes, so a double-quoted `x-data` truncates the expression
    and leaves a component that renders fine and does nothing."""
    html = shell.read_text()
    assert "x-data='graphComponent({{ graph_opts | tojson }})'" in html


def test_route_supplies_every_option_the_component_reads():
    """The blob is built in the router, so a missing key is a runtime `undefined`
    rather than a template error."""
    for router, keys in (
        ("intel.py", {"scope", "focalId", "jsonUrl", "graphmlBase", "pngPrefix", "schema"}),
        ("cases.py", {"scope", "caseId", "jsonUrl", "graphmlBase", "activeUrl", "pngPrefix", "schema"}),
    ):
        src = (APP / "routers" / router).read_text()
        block = src[src.index("graph_opts = {") : src.index("graph_opts = {") + 700]
        for key in keys:
            assert f'"{key}"' in block, f"{router} does not pass {key!r} to graphComponent"


def test_schema_is_json_serialisable_and_complete():
    """The blob goes through `| tojson`; a set or a tuple-keyed dict would 500 the partial."""
    from app.intel.graph_payload import client_schema

    schema = client_schema()
    round_tripped = json.loads(json.dumps(schema))
    assert round_tripped == schema
    for key in ("flags", "types", "subtypes", "attr_flags", "severities", "tactics", "rels", "verdicts", "colors", "labels"):
        assert key in schema


def test_js_fixture_schema_matches_client_schema():
    """`tests/js/schema.fixture.json` is a copy of `client_schema()` for the Node tests.

    A copy is the right trade here — the JS suite must not import Python — but a stale copy
    would let a new entity type or attribute pass the JS tests while breaking the browser.
    Regenerate with:

        pdm run -- python3 -c "import json;from app.intel.graph_payload import client_schema;\
print(json.dumps(client_schema(), indent=2, sort_keys=True))" > tests/js/schema.fixture.json
    """
    from app.intel.graph_payload import client_schema

    fixture = json.loads((ROOT / "tests" / "js" / "schema.fixture.json").read_text())
    assert fixture == client_schema(), "tests/js/schema.fixture.json is stale — regenerate it (see this test's docstring)"


def test_js_suite_is_wired_into_the_taskfile():
    """`task test:js` must exist and must skip rather than fail when node is absent —
    the repo's "no Node" value bends here, and it may not bend into a hard dependency."""
    taskfile = all_raw()
    assert "test:js:" in taskfile
    block = taskfile[taskfile.index("test:js:") : taskfile.index("test:js:") + 1200]
    assert "node --test" in block and "tests/js/*.test.mjs" in block
    assert "command -v node" in block, "must skip cleanly on a Python-only box"


# ── Feedback fixes: panels, defaults, edge labels ──────────────────────────


def test_the_floating_panels_are_mutually_exclusive():
    """Legend, Help and Pivots share one corner of a fixed-height canvas.

    With two open at once the Pivots card sat on top of the Legend's own toggle, so the
    legend could be opened and then not closed. One `panel` value, plus an explicit close
    button on each and an Escape branch — three ways out instead of none.
    """
    src = _strip_comments(GRAPH_JS.read_text())
    assert "togglePanel(name)" in src
    assert "this.activePanel = this.activePanel === name ? '' : name" in src
    escape = _function_body(src, "onEscape() {")
    assert "this.activePanel" in escape, "Escape must close an open panel"

    for name in ("_graph_legend.html", "_graph_help.html", "_graph_pivots.html"):
        html = (PARTIALS / name).read_text()
        assert "activePanel === '" in html, f"{name} must be gated on the shared panel slot"
        assert "@click=\"activePanel = ''\"" in html, f"{name} needs its own close button"


def test_job_edges_start_hidden_and_the_ui_says_so():
    """They are the bulk of every graph and carry the least — "named in the same log
    file". Hiding them silently would be worse than the crowding, so the toolbar says it."""
    from app.intel.graph import DEFAULT_HIDDEN_EDGE_KINDS

    assert DEFAULT_HIDDEN_EDGE_KINDS == ["job"]
    assert "hidden_kinds" in _strip_comments(GRAPH_VIEW_JS.read_text())
    assert "this.hiddenKinds = new Set(this.decoded.hiddenKinds)" in _strip_comments(GRAPH_JS.read_text())
    toolbar = (PARTIALS / "_graph_toolbar.html").read_text()
    assert "hiddenKinds.has('job')" in toolbar, "the analyst must be told the edges are hidden"


def test_typed_edges_are_labelled_at_rest():
    """An unlabelled arrow makes `runs_as` and `parent_of` indistinguishable, which is most
    of the point of having typed edges. Labels are drawn at rest below a size threshold."""
    assert "edgeLabelsAtRest" in GRAPH_RENDER_JS.read_text()
    src = _strip_comments(GRAPH_JS.read_text())
    assert "showEdgeLabels()" in src
    assert "setEdgeLabels" in src
    assert "edgeLabels" in (PARTIALS / "_graph_toolbar.html").read_text()


def test_node_labels_are_a_setting_not_a_forced_label():
    """Node names must be reachable through Sigma's own bounds, not through `forceLabel`.

    `forceLabel` bypasses labelRenderedSizeThreshold / labelDensity / labelGridCellSize —
    the three settings that bound label cost — which is why it is capped at
    MAX_FORCED_LABELS and reserved for overlay and selection. The "a first-seen entity is
    never named" problem is a *threshold* problem: node size comes from job_count, so a
    threshold of 7 silently meant `job_count >= 4`. Fixing it by forcing more labels would
    have removed the bound instead of correcting it.
    """
    render = _strip_comments(GRAPH_RENDER_JS.read_text())
    assert "NODE_LABEL_MODES" in render
    assert "setNodeLabels" in render
    assert "setSetting('labelRenderedSizeThreshold'" in render, "the mode must move the real Sigma setting"

    src = _strip_comments(GRAPH_JS.read_text())
    assert "setNodeLabels" in src
    assert "nodeLabels" in src

    toolbar = (PARTIALS / "_graph_toolbar.html").read_text()
    assert "setNodeLabels" in toolbar, "the mode must be reachable from the toolbar"

    # The 'auto' threshold has to admit a job_count == 1 entity, or the default is still
    # "names are missing". nodeSize(1) == 4 + sqrt(1)*1.6 == 5.6, and at the default camera
    # ratio the rendered size is the raw size.
    threshold = re.search(r"auto:\s*\{\s*threshold:\s*([0-9.]+)", render)
    assert threshold, "could not read the 'auto' label threshold"
    assert float(threshold.group(1)) <= 5.6, "a first-seen entity (job_count == 1) must still be able to draw its name"


def test_toolbar_controls_use_the_shared_inline_primitive():
    """`.lt-label` stacks its caption above the field, which is right for a form column and
    wrong for a dense toolbar — mixing the two is what left "Include allowlisted" a few
    pixels off its neighbours and needed an `items-end`/`pb-1.5` nudge to hide it."""
    assert ".lt-ctl " in BASE_HTML.read_text(), "the shared inline control primitive is missing"
    for name in ("_graph_toolbar.html", "_entity_graph.html", "_case_graph.html"):
        # Jinja comments are stripped, so prose explaining why `items-end` is wrong does not
        # trip the guard.
        html = _strip_jinja_comments((PARTIALS / name).read_text())
        assert "lt-ctl" in html, f"{name} should use the shared inline control primitive"
        assert "items-end" not in html, f"{name} still hand-nudges a control's baseline"


def test_selects_are_width_constrained():
    """A select sized by its longest `<option>` is what made "Severity ≥ informational"
    overflow its row."""
    toolbar = (PARTIALS / "_graph_toolbar.html").read_text()
    selects = re.findall(r"<select[^>]*class=\"([^\"]*)\"", toolbar)
    assert selects, "expected selects in the toolbar"
    for cls in selects:
        assert re.search(r"\bw-\d+\b", cls), f"select has no explicit width: {cls}"


def test_the_canvas_is_viewport_relative_and_expandable():
    """A fixed 36rem box letterboxed the graph on a large screen."""
    for shell in GRAPH_SHELLS:
        html = shell.read_text()
        assert "100vh" in html, f"{shell.name} still uses a fixed canvas height"
        assert "tall ?" in html, f"{shell.name} lost its expand toggle"
    assert "toggleTall()" in _strip_comments(GRAPH_JS.read_text())


def test_a_help_panel_explains_the_edge_kinds():
    """The three edge kinds look similar and claim very different things; that is the one
    thing a graph cannot explain by drawing it."""
    help_html = (PARTIALS / "_graph_help.html").read_text()
    assert "schema.colors.kind.job" in help_html
    assert "schema.colors.kind.finding" in help_html
    assert "schema.colors.kind.typed" in help_html
    assert "never moves a node" in help_html.lower() or "never moves" in help_html.lower()


def test_the_panel_property_keeps_its_distinctive_name():
    """`panel` did not work; `activePanel` does. Renaming was the entire fix.

    With the property named `panel`, reads were correct — `Alpine.evaluate(el, 'panel')`
    returned the new value — but the `x-show` effect never re-ran: `_x_isShown` stayed false
    and the inline `display: none` was never cleared, so the Legend could be opened from the
    switcher and then not closed. Nothing else changed.

    The mechanism is a working theory (a scope-resolution collision in Alpine's evaluator),
    not a diagnosis, which is why the guard is the name itself: renaming back would silently
    reintroduce a panel that opens and will not close, and no route test can see it.
    """
    src = GRAPH_JS.read_text()
    assert "activePanel: ''" in src
    assert re.search(r"^\s+panel: ", src, re.M) is None, "the property named `panel` did not track reactively"
    for name in ("_graph_overlay.html", "_graph_legend.html", "_graph_help.html", "_graph_pivots.html"):
        html = _strip_jinja_comments((PARTIALS / name).read_text())
        assert "panel ===" not in html.replace("activePanel ===", ""), f"{name} still binds on the bare `panel` name"


def test_transient_messages_live_in_a_reserved_row():
    """Nothing that appears during interaction may change the height above the canvas.

    A message block that toggles on hover makes the graph jump: the ego overlay demotes
    every other node, a "dimmed by your filters" line appears above the canvas, and it
    vanishes again on mouse-out. The layout must not depend on getting a count right —
    every transient message renders into one fixed-height row
    that is present from the start and usually empty.
    """
    stats = (PARTIALS / "_graph_stats.html").read_text()
    assert "min-h-[1.5rem]" in stats, "the status row must reserve its height"

    # The toolbar must not carry any of them: it sits above the canvas too.
    toolbar = _strip_jinja_comments((PARTIALS / "_graph_toolbar.html").read_text())
    for transient in ("counts.zeroMatches", "matchesPartial", "queryError", "timeState.active", "isolateWindow"):
        assert transient not in toolbar, f"{transient} belongs in the reserved status row, not the toolbar"

    # The two notes that *can* toggle inside the toolbar get their own reserved row.
    assert "min-h-[1rem]" in toolbar


def test_the_dimmed_count_ignores_overlays():
    """Hovering is not a filter, and counting it as one is what moved the canvas."""
    src = _strip_comments(GRAPH_VIEW_JS.read_text())
    assert "state.structural && !state.lens" in src, "dimmed must count lens failures, not MUTED levels"
    assert "if (state.level === MUTED) dimmedNodes++" not in src


def test_every_url_builder_carries_the_job_scope():
    """Four places build a graph URL, and only two of them go through `_query()`.

    `graphmlUrl()` calls `_query()`, so it inherits the scope. `_expandNode` does **not** —
    it always asks for one hop from a *different* entity and spells its own query string —
    so it needs `_jobParam()` explicitly. A builder that forgets returns a perfectly valid
    unscoped graph: HTTP 200, nodes drawn, wrong answer. Nothing in the Python suite and
    nothing in a browser screenshot can tell the two apart, which is why this is a grep.
    """
    src = _strip_comments(GRAPH_JS.read_text())
    assert "_jobParam()" in src, "the shared job-scope helper is gone"

    query_body = _function_body(src, "_query() {")
    assert query_body.count("_jobParam()") == 2, "both branches of _query() (entity and case) must append the job scope"

    expand_body = _function_body(src, "_expandNode(entityId, label, relType) {")
    assert "_jobParam()" in expand_body, "_expandNode builds its own query string and must append the job scope itself"


def test_the_entity_graph_shell_gates_on_a_job_before_it_declares_a_component():
    """No `graphComponent` x-data at all until a job is picked.

    Gating inside the component instead would construct a Sigma renderer (and take one of
    the browser's ~16 WebGL contexts) for a view that shows nothing, and would leave
    `graphmlUrl()` in scope to export a graph nobody can see.
    """
    shell = (PARTIALS / "_entity_graph.html").read_text()
    gate = shell.index("{% if not graph_opts %}")
    component = shell.index("graphComponent(")
    assert gate < component, "the empty-state branch must come before the component is declared"
    assert "{% else %}" in shell and "{% endif %}" in shell


def test_the_case_graph_keeps_its_job_filter_optional():
    """A case's whole point is cross-job correlation, so it renders unfiltered."""
    shell = (PARTIALS / "_case_graph.html").read_text()
    assert 'x-model.number="jobId"' in shell, "the case shell needs an in-place job control"
    assert '<option value="0">' in shell, "0 must mean every job in the case"
    assert "{% if not graph_opts %}" not in shell, "the case graph must not be gated on a job"
