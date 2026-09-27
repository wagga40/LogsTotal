"""Integration guard: every Alpine binding on a rendered page must sit inside an
`x-data` scope, or Alpine never initializes it and the control silently does nothing.

The failure hides well. Jobs-list selection checkboxes in `<thead>`/`<tbody>` with no
`x-data` ancestor anywhere on the page are inert, because Alpine only walks subtrees rooted
at an `x-data` element — except while a job is running, when the 5s table poll makes
base.html's `htmx:afterSwap` hook call `Alpine.initTree()` on the swapped `<tbody>` and the
row boxes spring to life. "Works only when a job is running" is the symptom.

Static template analysis cannot catch this (a partial legitimately relies on scope from
the page that includes it), so this asserts against fully rendered HTML.


A second class sits on top of that: a binding can have a perfectly good `x-data` ancestor
that does not provide what the expression names. Deleting a key from an inline `x-data`
leaves every binding that used it logging `Alpine Expression Error: X is not defined` while
the page still renders and every test still passes — the control just silently does nothing.
That is `assert_scope_identifiers_resolve` below.

It cannot work *per template file*, where scope genuinely is not knowable — a partial
inherits it from whichever page includes it. Resolving against a fully rendered page makes
the whole ancestor chain visible, and the check stays quiet unless every scope in that chain
is an inline object literal it can actually read (a factory call like `savedSearchManager()`
keeps its keys in JS, so its subtree is skipped outright rather than guessed at).

What none of this covers is a key that exists but holds the wrong thing. For that, read the
browser console — capture `Runtime.exceptionThrown` and `Runtime.consoleAPICalled` when
driving the page, not just the rendered DOM.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import AnalysisJob, Entity, EntityTag, InvestigationCase, JobStatus, LogFile, User, WorkflowDef

pytestmark = pytest.mark.anyio

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

# Attributes Alpine evaluates against a component scope. `x-data` itself and the
# Alpine-independent `x-cloak` are excluded.
_BINDING = re.compile(r"^(?:x-(?:show|text|html|model|if|for|effect|bind|on|init|transition)\b|[:@])")

# `$store` / `$el` etc. still require an initialized tree, so they are NOT exempt.
_SKIP_ATTRS = {"x-data", "x-cloak", "x-ref", "x-id"}


class BindingScopeChecker(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []  # (tag, is_x_data_root)
        self.orphans: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        is_root = "x-data" in a
        in_scope = is_root or any(root for _t, root in self.stack)
        if not in_scope:
            for name, value in a.items():
                if name in _SKIP_ATTRS:
                    continue
                if _BINDING.match(name):
                    self.orphans.append((tag, name, (value or "")[:60]))
        if tag not in VOID:
            self.stack.append((tag, is_root))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break


#: Every attribute whose value Alpine compiles as an expression. `x-data` was the only one
#: checked for a long time, and the truncation class is not specific to it — see
#: `assert_x_data_expressions_are_intact`.
_EXPRESSION_ATTR_PREFIXES = ("x-data", "x-show", "x-if", "x-text", "x-html", "x-model", "x-effect", "x-init", "x-for", "@", ":")

#: Attributes that merely *name* something rather than carrying an expression.
_NOT_EXPRESSIONS = frozenset({"x-ref", "x-id", "x-cloak", "x-transition"})


class XDataCollector(HTMLParser):
    """Collect every rendered Alpine expression, with the attribute it came from."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.expressions: list[str] = []
        self.attributes: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if not value or name in _NOT_EXPRESSIONS:
                continue
            if name == "x-data":
                self.expressions.append(value)
            if name.startswith(_EXPRESSION_ATTR_PREFIXES):
                self.attributes.append((name, value))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def _is_unbalanced(expr: str) -> bool:
    depth = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    for ch in expr:
        if ch in depth:
            depth[ch] += 1
        elif ch in closing:
            depth[closing[ch]] -= 1
    return any(v != 0 for v in depth.values())


def assert_alpine_expressions_are_intact(html: str, label: str) -> None:
    """**Every** Alpine expression must be complete, not just `x-data`.

    The truncation class: interpolating the shared `tojson` filter (which escapes `& < > '`
    and deliberately not `"`) into a *double*-quoted attribute ends the attribute at the
    JSON string's own opening quote. Unbalanced brackets are the tell.

    Not `x-data` alone: a broken component is the worst case, but not the only one. A
    `@click` carrying `$dispatch('seed-new-rule', { name: {{ … | tojson }} })` closes at the
    JSON quote, so the handler fails to compile and the button silently does nothing — no
    server error, no console message anyone is reading, and every route test still green.
    """
    collector = XDataCollector()
    collector.feed(html)
    broken = [f"{name}={value!r}" for name, value in collector.attributes if _is_unbalanced(value)]
    assert not broken, f"{label}: truncated/unbalanced Alpine expression(s):\n  " + "\n  ".join(broken)


def test_the_expression_guard_catches_a_tojson_truncated_handler():
    """The handler case, reproduced.

    `@click="$dispatch('seed-new-rule', { name: "Copy of X" })"` is what a `| tojson` inside
    a double-quoted attribute renders. The parser ends the attribute at the JSON string's
    own opening quote, so the handler is `$dispatch('seed-new-rule', { name: ` — which fails
    to compile, silently, leaving a button that looks correct and does nothing.
    """
    broken = '<button @click="$dispatch(\'seed\', { name: "Copy of X" })">go</button>'
    with pytest.raises(AssertionError, match="unbalanced"):
        assert_alpine_expressions_are_intact(broken, "synthetic")

    # …and the fixed form, which passes the data through `data-*` instead.
    fixed = '<button data-seed-name="Copy of X" @click="$dispatch(\'seed\', { name: $el.dataset.seedName })">go</button>'
    assert_alpine_expressions_are_intact(fixed, "synthetic")


def test_the_guard_looks_past_x_data():
    """It checked `x-data` alone for a long time, which is how the handler above got through."""
    collector = XDataCollector()
    collector.feed('<div x-data="foo()" x-show="a" @click="b()" :class="c" x-text="d" x-ref="e"></div>')
    names = {name for name, _ in collector.attributes}
    assert names == {"x-data", "x-show", "@click", ":class", "x-text"}, "x-ref names a thing; it is not an expression"


# ── scope-content resolution ─────────────────────────────────────────────────────────
#
# Everything below answers "does the enclosing x-data actually declare what this binding
# names?", as opposed to the ancestor-existence check above.

# Identifiers an expression may use without any component declaring them. Alpine magics are
# listed because they resolve through Alpine, not the scope object.
_AMBIENT = frozenset(
    {
        # keywords and operators
        *("true", "false", "null", "undefined", "this", "new", "typeof", "instanceof", "delete", "void", "in", "of"),
        *("return", "if", "else", "let", "const", "var", "function", "async", "await", "try", "catch", "finally"),
        *("throw", "class", "super", "yield"),
        # standard globals
        *("window", "document", "location", "history", "navigator", "console", "JSON", "Math", "Date", "Object"),
        *("Array", "String", "Number", "Boolean", "RegExp", "Set", "Map", "Promise", "Symbol", "Error", "URL"),
        *("URLSearchParams", "FormData", "setTimeout", "clearTimeout", "setInterval", "clearInterval"),
        *("requestAnimationFrame", "queueMicrotask", "parseInt", "parseFloat", "isNaN", "fetch", "structuredClone"),
        *("encodeURIComponent", "decodeURIComponent"),
        # vendored libraries, the implicit event-handler argument, and Alpine's magics
        *("htmx", "Alpine", "event"),
        *("$event", "$el", "$refs", "$store", "$nextTick", "$dispatch", "$watch", "$data", "$id", "$root", "$persist"),
    }
)

# Attributes whose value is not a JS expression Alpine evaluates against the scope.
_NON_EXPRESSION = {"x-transition", "x-cloak", "x-ref", "x-id", "x-teleport", "x-modelable"}

_STRINGS = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`")
_MEMBER = re.compile(r"[.?]\s*[A-Za-z_$][\w$]*")
_OBJ_KEY = re.compile(r"[{,]\s*[A-Za-z_$][\w$]*\s*:")
_ARROW_PARAMS = re.compile(r"\(([^()]*)\)\s*=>|([A-Za-z_$][\w$]*)\s*=>")
_LOCAL_DECL = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)")
_IDENT = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)")
_X_FOR = re.compile(r"^\s*\(?\s*([\w$]+)\s*(?:,\s*([\w$]+)\s*)?\)?\s+(?:in|of)\s")


def _skip_comment(src: str, i: int) -> int | None:
    """End index of a JS comment starting at `i`, or None if one doesn't."""
    if src.startswith("//", i):
        nl = src.find("\n", i)
        return len(src) if nl == -1 else nl
    if src.startswith("/*", i):
        end = src.find("*/", i + 2)
        return len(src) if end == -1 else end + 2
    return None


def _literal_scope_keys(expr: str) -> set[str] | None:
    """Top-level keys of an inline `x-data` object literal, or None if it isn't one.

    None means "opaque": a factory call, a bare `x-data`, or anything this cannot read.
    Callers must treat opaque scopes as providing *anything*, never as providing nothing.

    Keys are only read at key *positions* — immediately after the opening `{` or after a
    top-level `,`. Matching identifiers anywhere at depth 1 instead would pull value-side
    calls (`foo: barBaz(1)` → `barBaz`) into the scope and quietly defeat the check.
    """
    src = expr.strip()
    if not src.startswith("{") or not src.endswith("}"):
        return None
    keys: set[str] = set()
    depth = 0
    at_key = False
    i = 0
    while i < len(src):
        end = _skip_comment(src, i)
        if end is not None:
            i = end
            continue
        ch = src[i]
        if ch in "'\"`":
            m = _STRINGS.match(src, i)
            if at_key and depth == 1 and m:  # quoted key: {'foo': 1}
                keys.add(m.group(0)[1:-1])
                at_key = False
            i = m.end() if m else i + 1
            continue
        if ch in "{[(":
            depth += 1
            at_key = depth == 1 and ch == "{"
            i += 1
            continue
        if ch in "}])":
            depth -= 1
            at_key = False
            i += 1
            continue
        if ch.isspace():
            i += 1
            continue
        if depth == 1 and ch == ",":
            at_key = True
            i += 1
            continue
        if depth == 1 and at_key:
            m = re.match(r"[A-Za-z_$][\w$]*", src[i:])
            if m:
                name = m.group(0)
                i += len(name)
                # `get`/`set`/`async` are modifiers — the key is the identifier after them.
                if name not in ("get", "set", "async", "static"):
                    keys.add(name)
                    at_key = False
                continue
        at_key = False
        i += 1
    return keys


def _referenced_identifiers(expr: str) -> set[str]:
    """Bare identifiers an expression reads from scope.

    Strips the things that look like identifiers but never resolve against the component:
    string contents, `.member` accesses, object-literal keys, arrow parameters and locals.
    Each strip can only *remove* candidates, so a parsing miss costs a missed warning
    rather than a false one.
    """
    src = _STRINGS.sub("''", expr)
    src = re.sub(r"//[^\n]*|/\*.*?\*/", " ", src, flags=re.S)
    bound = {m.group(1) for m in _LOCAL_DECL.finditer(src)}
    for group in _ARROW_PARAMS.findall(src):
        for chunk in group:
            for part in chunk.split(","):
                name = part.strip().removeprefix("...").strip()
                if re.fullmatch(r"[A-Za-z_$][\w$]*", name or ""):
                    bound.add(name)
    src = _MEMBER.sub("", src)
    src = _OBJ_KEY.sub("{", src)
    return {m.group(1) for m in _IDENT.finditer(src)} - _AMBIENT - bound


# Page-level helpers Alpine reaches through the global scope rather than the component.
# Only the two forms that actually land on the global object: a classic script's top-level
# `const` stays in script scope where Alpine cannot see it (see the base.html note), so
# collecting those here would mask exactly the bug that rule exists to catch.
_PAGE_GLOBAL = re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|^\s*window\.([A-Za-z_$][\w$]*)\s*=", re.M)


class _ScriptHarvester(HTMLParser):
    """Global function names declared by the page's own inline `<script>` blocks."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.names: set[str] = set()
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._in_script = tag == "script"

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.names |= {n for pair in _PAGE_GLOBAL.findall(data) for n in pair if n}


class ScopeContentChecker(HTMLParser):
    """Resolve each binding's identifiers against its chain of inline `x-data` literals."""

    def __init__(self, page_globals: frozenset[str] = frozenset()) -> None:
        super().__init__(convert_charrefs=True)
        # (tag, scope keys or None=opaque, contributes_an_x_data)
        self.stack: list[tuple[str, set[str] | None, bool]] = []
        self.unresolved: list[tuple[str, str, str]] = []  # (attr, identifier, expression)
        self.page_globals = page_globals

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        own: set[str] = set()
        opaque = False
        if "x-data" in a:
            keys = _literal_scope_keys(a["x-data"] or "")
            if keys is None:
                opaque = True
            else:
                own |= keys
        # `x-for` binds its loop variables for this element's own bindings (`:key` sits on
        # the same <template>) as well as for the subtree.
        for name, value in a.items():
            if name.split(":")[0] == "x-for" and value:
                m = _X_FOR.match(value)
                if m:
                    own |= {g for g in m.groups() if g}

        frame: set[str] | None = None if opaque else own
        chain = [scope for _t, scope, _d in self.stack] + [frame]
        has_x_data = "x-data" in a or any(is_data for _t, _s, is_data in self.stack)

        # Quiet unless the entire chain is readable, and only where an `x-data` exists at
        # all — a partial with no root inherits its scope from the page that includes it.
        if has_x_data and all(scope is not None for scope in chain):
            available = set(self.page_globals)
            for scope in chain:
                available |= scope  # type: ignore[arg-type]
            for name, value in a.items():
                if not value or name in _SKIP_ATTRS or name in _NON_EXPRESSION:
                    continue
                if name.startswith("x-transition") or not _BINDING.match(name):
                    continue
                for ident in sorted(_referenced_identifiers(value) - available):
                    self.unresolved.append((name, ident, value.strip()[:110]))

        if tag not in VOID:
            self.stack.append((tag, frame, "x-data" in a))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break


def assert_scope_identifiers_resolve(html: str, label: str) -> None:
    harvester = _ScriptHarvester()
    harvester.feed(html)
    checker = ScopeContentChecker(page_globals=frozenset(harvester.names))
    checker.feed(html)
    assert not checker.unresolved, (
        f"{label}: Alpine binding names something its x-data does not declare "
        f"(the handler throws ReferenceError and the control silently does nothing):\n  " + "\n  ".join(f'{ident!r} in {attr}="{expr}"' for attr, ident, expr in checker.unresolved)
    )


def assert_all_bindings_scoped(html: str, label: str) -> None:
    checker = BindingScopeChecker()
    checker.feed(html)
    assert not checker.orphans, f"{label}: Alpine bindings with no x-data ancestor (Alpine will never initialize them):\n  " + "\n  ".join(
        f'<{t} {n}="{v}">' for t, n, v in checker.orphans
    )


async def _create_user(async_db, *, email: str, role: str = "admin", is_superuser: bool = True) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=is_superuser, is_active=True, role=role))


@pytest.fixture()
async def page_data(async_db):
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    await async_db.commit()
    user = await _create_user(async_db, email="pages@ui.example.com")
    job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED)
    entity = Entity(value="10.0.0.9", entity_type="ip_address", job_count=1)
    async_db.add_all([job, entity])
    await async_db.commit()
    async_db.add(EntityTag(entity_id=entity.id, tag="apt28", color="red"))
    case = InvestigationCase(name="UI Case", created_by_user_id=user.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()
    for obj in (job, entity, case):
        await async_db.refresh(obj)
    return {"job": job, "entity": entity, "case": case}


async def test_rendered_pages_have_no_orphan_alpine_bindings(test_client, page_data):
    resp = await test_client.post("/auth/cookie/login", data={"username": "pages@ui.example.com", "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303)

    pages = {
        "/jobs": "jobs list",
        f"/jobs/{page_data['job'].id}": "job detail",
        f"/intel/entities/{page_data['entity'].id}": "entity detail",
        f"/intel/cases/{page_data['case'].id}": "case detail",
        "/intel": "intel dashboard",
        "/intel/tags": "tag manager",
        "/intel/rules": "rules panel",
        "/intel/cases": "cases list",
        "/admin": "admin dashboard",
    }
    for url, label in pages.items():
        page = await test_client.get(url)
        assert page.status_code == 200, f"{label} ({url}) returned {page.status_code}"
        assert_all_bindings_scoped(page.text, label)
        assert_alpine_expressions_are_intact(page.text, label)


async def test_rendered_pages_resolve_every_alpine_identifier(test_client, page_data):
    """A binding must not name something its enclosing `x-data` stopped declaring.

    The shape: `searchTimeout: null` deleted from the Intel dashboard's root `x-data` while
    the search box's `@input` handler still calls `clearTimeout(searchTimeout)`. Alpine
    evaluates bindings under `with(scope)`, so the bare read throws `ReferenceError` before it
    can schedule anything — typing in the box updates `searchQuery` and never refreshes the
    table, while the page renders fine.
    """
    await test_client.post("/auth/cookie/login", data={"username": "pages@ui.example.com", "password": "pass123456"}, follow_redirects=False)

    pages = {
        "/jobs": "jobs list",
        f"/jobs/{page_data['job'].id}": "job detail",
        f"/intel/entities/{page_data['entity'].id}": "entity detail",
        f"/intel/cases/{page_data['case'].id}": "case detail",
        "/intel": "intel dashboard",
        "/intel/tags": "tag manager",
        "/intel/rules": "rules panel",
        "/intel/cases": "cases list",
        "/admin": "admin dashboard",
    }
    # Collected across every page, not asserted per page: failing on the first one hides
    # how far the damage spreads, and a deleted key usually breaks several controls at once.
    failures: list[str] = []
    for url, label in pages.items():
        page = await test_client.get(url)
        assert page.status_code == 200, f"{label} ({url}) returned {page.status_code}"
        try:
            assert_scope_identifiers_resolve(page.text, label)
        except AssertionError as exc:
            failures.append(str(exc))
    assert not failures, "\n".join(failures)


async def test_intel_search_debounce_handle_is_declared(test_client, page_data):
    """Pin the exact pairing, so deleting either half fails loudly rather than silently."""
    await test_client.post("/auth/cookie/login", data={"username": "pages@ui.example.com", "password": "pass123456"}, follow_redirects=False)
    html = (await test_client.get("/intel")).text

    assert "clearTimeout(searchTimeout)" in html, "search box lost its debounced @input handler"
    assert re.search(r"\bsearchTimeout\s*:", html), "searchTimeout is used by a binding but not declared in any x-data"


async def test_jobs_selection_controls_are_inside_an_alpine_scope(test_client, page_data):
    """The specific case: selection must not depend on a poll to come alive."""
    await test_client.post("/auth/cookie/login", data={"username": "pages@ui.example.com", "password": "pass123456"}, follow_redirects=False)
    html = (await test_client.get("/jobs")).text

    assert "$store.jobSelection.setAllVisible(" in html, "select-all control missing"
    assert "$store.jobSelection.toggle(" in html, "row checkboxes missing"
    assert_all_bindings_scoped(html, "jobs list")

    # And the standalone tbody partial keeps working when swapped in by the poll.
    body = (await test_client.get("/jobs/table-partial")).text
    assert "$store.jobSelection.toggle(" in body


async def test_htmx_partials_have_intact_alpine_expressions(test_client, async_db, page_data):
    """Lazily-swapped partials need the same checks as full pages.

    The case timeline's entity search box shipped with a truncated `x-data` and nothing
    caught it: the page-level guards never see a partial, and substring assertions on the
    factory name matched the broken markup happily.
    """
    from app.models import CaseEntityLink, CaseJobLink

    case, job, entity = page_data["case"], page_data["job"], page_data["entity"]
    async_db.add_all(
        [
            CaseJobLink(case_id=case.id, job_id=job.id),
            CaseEntityLink(case_id=case.id, entity_id=entity.id),
        ]
    )
    await async_db.commit()

    await test_client.post("/auth/cookie/login", data={"username": "pages@ui.example.com", "password": "pass123456"}, follow_redirects=False)

    partials = {
        f"/intel/cases/{case.id}/timeline-partial": "case timeline",
        # Both `caseEntityFilter` call sites, and they do not pass the same arity — the
        # Processes one appends the selected job. A single-quoted x-data holding a JSON
        # string is exactly the shape `_tojson_safe` exists for, so both belong here.
        f"/intel/cases/{case.id}/process-tree-partial": "case processes",
        f"/intel/cases/{case.id}/summary-partial": "case summary",
        f"/intel/cases/{case.id}/pivots-partial": "case pivots",
        f"/intel/cases/{case.id}/graph-partial": "case graph",
        f"/intel/entities/{entity.id}/graph-partial": "entity graph",
        f"/comments/case/{case.id}": "case comments",
        f"/jobs/{job.id}/status-partial": "job status",
        f"/jobs/{job.id}/analytics": "job analytics",
        "/jobs/table-partial": "jobs table body",
        "/intel/entities-partial": "entity table",
    }
    for url, label in partials.items():
        resp = await test_client.get(url)
        assert resp.status_code in (200, 286), f"{label} ({url}) returned {resp.status_code}"
        assert_alpine_expressions_are_intact(resp.text, label)


async def test_timeline_entity_filter_submits_a_usable_entity_id(test_client, async_db, page_data):
    """An empty `entity_id=` 422s the route on int coercion, so the hidden input must
    carry a server-rendered default rather than relying on Alpine having bound it."""
    from app.models import CaseEntityLink, CaseJobLink

    case, job, entity = page_data["case"], page_data["job"], page_data["entity"]
    async_db.add_all([CaseJobLink(case_id=case.id, job_id=job.id), CaseEntityLink(case_id=case.id, entity_id=entity.id)])
    await async_db.commit()

    await test_client.post("/auth/cookie/login", data={"username": "pages@ui.example.com", "password": "pass123456"}, follow_redirects=False)
    html = (await test_client.get(f"/intel/cases/{case.id}/timeline-partial")).text
    assert 'name="entity_id" value="0"' in html, "hidden entity_id must have a non-empty default"

    # The round trip the filter form actually makes.
    ok = await test_client.get(f"/intel/cases/{case.id}/timeline-partial?job_id=0&severity=&entity_id=0")
    assert ok.status_code == 200


def test_every_lazy_tab_trigger_is_once():
    """A lazy pane must load exactly once per page view.

    `resourceTabs.select()` re-dispatches the tab's `lazy_event` on every activation, so a
    trigger without `once` refetches the pane each time the analyst switches back —
    rebuilding the graph from scratch and discarding the layout and any filtering they
    had set up.
    """
    import re
    from pathlib import Path

    templates = Path(__file__).resolve().parent.parent / "app" / "templates"
    pattern = re.compile(r'hx-trigger="(load(\w+) from:body)((?: once)?)"')

    # Deliberately repeatable: the nav bell is a live notification list, not a tab pane —
    # it *should* re-query every time the dropdown is opened.
    REPEATABLE = {"WatchlistEvents"}

    offenders = []
    for path in templates.rglob("*.html"):
        for trigger, event, once in pattern.findall(path.read_text(encoding="utf-8")):
            if not once and event not in REPEATABLE:
                offenders.append(f"{path.relative_to(templates)}: {trigger}")

    assert not offenders, "lazy-tab triggers missing `once` (pane will refetch on every tab switch): " + ", ".join(sorted(offenders))


# ── The morph swap style ─────────────────────────────────────────────────────


class TestMorphSwapSpelling:
    """`hx-swap="morph"` must be spelled exactly as the extension matches it.

    This is a source-shape test because every symptom of getting it wrong reads as a
    different bug, and none of them reads as "wrong swap style".

    `htmx-ext-alpine-morph.js` compares `swapStyle === 'morph'` and declines anything else.
    htmx only consults extensions from its `default:` branch, and when none of them handles
    the style it falls through to `htmx.config.defaultSwapStyle` — **innerHTML**. So
    `hx-swap="morph:outerHTML"`, which looks like a more precise spelling of the same thing,
    silently means innerHTML.

    What that produced, all reported separately:

    * every child of the region destroyed and rebuilt on each 3s poll — visible flicker;
    * the log `<pre>` recreated, so its scroll position reset while being read;
    * `hx-trigger="every 3s"` left on the *outer* element, which innerHTML never touches, so
      polling continued after the run finished and only a page reload stopped it.
    """

    EXTENSION = Path("app/static/vendor/htmx-ext-alpine-morph.js")

    def _handled_styles(self) -> set[str]:
        """The swap-style literals the vendored extension actually compares against."""
        src = self.EXTENSION.read_text()
        return set(re.findall(r"swapStyle\s*===\s*'([^']+)'", src))

    def test_the_extension_still_matches_a_bare_morph(self):
        """If a vendor update changes this, the templates below must change with it."""
        assert self._handled_styles() == {"morph"}, "the alpine-morph extension no longer handles exactly 'morph'; update the hx-swap values in the templates to match"

    def test_every_morph_swap_uses_a_style_the_extension_handles(self):
        handled = self._handled_styles()
        offenders = []
        for path in Path("app/templates").rglob("*.html"):
            for value in re.findall(r'hx-swap="([^"]*morph[^"]*)"', path.read_text()):
                if value not in handled:
                    offenders.append(f"{path}: hx-swap={value!r}")
        assert not offenders, f"these swap styles fall through to htmx.config.defaultSwapStyle (innerHTML) instead of morphing: {offenders}"

    def test_a_morph_swap_always_loads_the_extension(self):
        """`hx-swap="morph"` with no `hx-ext` is the same innerHTML fallback."""
        offenders = []
        for path in Path("app/templates").rglob("*.html"):
            text = path.read_text()
            if 'hx-swap="morph"' in text and "alpine-morph" not in text:
                offenders.append(str(path))
        assert not offenders, f'morph swap without hx-ext="alpine-morph" in: {offenders}'

    def test_the_regions_that_poll_are_the_ones_that_morph(self):
        """Both self-polling regions morph; a plain swap there is the bug above."""
        for path in ("app/templates/partials/_job_status.html", "app/templates/partials/_ai_analysis.html"):
            text = Path(path).read_text()
            assert 'hx-trigger="every 3s"' in text, path
            assert 'hx-swap="morph"' in text, path
            assert 'hx-ext="alpine-morph"' in text, path


def test_nothing_jumps_into_a_resource_tab_by_assigning_the_property():
    """A shortcut into a lazy pane must go through `select()`, not `tab = '…'`.

    Assigning the property moves the pane into view and skips everything `select()` does:
    it never writes the hash, and it never dispatches the tab's `lazy_event` — so the pane
    is displayed still showing its placeholder, and only loads once the tab strip is
    clicked. The Overview's **All checks →** button did exactly this, which is why reaching
    the System card cost a fresh run of the whole suite: the shortcut left it unloaded, and
    the later click through the strip was the first real load.

    Invisible to a route test — the server renders the identical HTML either way. Scoped to
    templates that actually use `resourceTabs`; a page with its own local
    `x-data="{ tab: 'users' }"` (the analytics panel) has no lazy events to miss.
    """
    import re
    from pathlib import Path

    templates = Path(__file__).resolve().parent.parent / "app" / "templates"
    assign = re.compile(r"""@click="\s*tab\s*=\s*['"]""")

    offenders = []
    for path in sorted(templates.rglob("*.html")):
        body = path.read_text(encoding="utf-8")
        if "resourceTabs(" not in body and "entityTabs(" not in body and "caseTabs(" not in body:
            continue
        for line_no, line in enumerate(body.splitlines(), 1):
            if assign.search(line):
                offenders.append(f"{path.relative_to(templates)}:{line_no}")

    assert not offenders, "use select('<key>') so the lazy pane actually loads: " + ", ".join(offenders)


# ── Nullable component state read through a plain `.` ─────────────────────────


class TestNullableRootsAreGuarded:
    """An `x-show` on an ancestor does NOT stop a child's expression from evaluating.

    Reported from a production deployment (Firefox, `/intel/entities/489?job=1`, Graph tab)::

        Alpine Expression Error: can't access property "job_id", stats is null
        Expression: "'/intel/jobs/' + stats.job_id + '/findings'"

    `graph.js` starts `stats: null` and assigns it only once the payload lands — and resets
    it to null when a reload fails. `_graph_stats.html` wrapped the job chip in
    `<span x-show="stats && stats.job_scoped">` and then read `stats.job_id` on the child.
    `x-show` toggles `display`; it does not defer initialization, so Alpine evaluates the
    child's `:href` and `x-text` on the very first walk, while `stats` is still null.

    Measured in Chromium 151 and Firefox 153 against this repo's own `alpine.min.js`: two
    `Alpine Expression Error` warnings plus two uncaught `TypeError`s per graph mount, and
    again every time a reload fails. The href *self-heals* — the compiled expression reads
    `stats` off the reactive proxy before it throws, so the dependency is registered and the
    effect re-runs — and the chip is hidden for the same condition, so nothing is visibly
    broken. That is precisely what makes it worth a test: the only symptom is console noise,
    which is where a real error would have to be noticed.

    Only `<template x-if>` / `<template x-for>` genuinely gate a subtree — Alpine does not
    clone the content until the condition holds. That is why `partials/_events_timeline.html`
    may read `stats.shown` bare, and it is the distinction this guard is built around.

    Three restrictions keep false positives at zero, in order of importance:

    1. **The nullable set is learned, not listed.** For every factory a template names in
       `x-data="factory(…)"`, the balanced body of its `return { … }` is read out of the
       shared static JS (or a page's own inline `<script>`), and its *depth-1* keys
       initialised to `null` become that component's nullable roots. Nested nulls
       (`menu: { index: null }`) are not roots. A factory whose object cannot be located
       contributes nothing rather than being guessed at.
    2. **The set is scoped by the include graph.** `timeline.js` has `selected: null` while
       `graph.js` has `selected: { … }`; applying one component's nullability to another's
       template is the obvious way to manufacture false positives.
    3. **Event handlers are exempt.** `@click="renderer.centerOn(…)"` runs when the analyst
       clicks, by which time the renderer exists. Only bindings Alpine evaluates on its own
       schedule are in scope.
    """

    #: `"<template path>:<root>"` → why an unguarded read there is correct.
    #: Deliberately empty: every current read is either guarded or inside `<template x-if>`.
    UNGUARDED_OK: dict[str, str] = {}

    _JS_COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
    _JINJA_BLOCK = re.compile(r"\{#.*?#\}|\{%.*?%\}", re.S)
    _JINJA_VAR = re.compile(r"\{\{.*?\}\}", re.S)
    _X_DATA_FACTORY = re.compile(r"""x-data=(["'])\s*([A-Za-z_$][\w$]*)\s*\(""")
    _INCLUDE = re.compile(r"""\{%-?\s*include\s+(["'])([^"']+)\1""")
    _INLINE_SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.S)
    #: The shapes an Alpine factory is declared in across this codebase. The second covers
    #: `window.lineageTree = window.lineageTree || function () {`.
    _FACTORY_HEADS = (
        r"^[ \t]*function\s+{n}\s*\(",
        r"window\.{n}\s*=\s*(?:[^;=\n]*\|\|\s*)?function\s*\(",
        r"window\.{n}\s*=\s*\([^)]*\)\s*=>",
        r"""Alpine\.data\(\s*['\"]{n}['\"]\s*,""",
    )

    @staticmethod
    def _templates() -> Path:
        return Path(__file__).resolve().parent.parent / "app" / "templates"

    @staticmethod
    def _static() -> Path:
        return Path(__file__).resolve().parent.parent / "app" / "static"

    # ── source plumbing ──────────────────────────────────────────────────────

    @classmethod
    def _strip_js(cls, src: str) -> str:
        return _STRINGS.sub("''", cls._JS_COMMENTS.sub(" ", src))

    @staticmethod
    def _balanced(src: str, start: int) -> str | None:
        """The bracket-balanced slice beginning at `src[start]`, or None if unbalanced."""
        depth = 0
        for i in range(start, len(src)):
            ch = src[i]
            if ch in "{[(":
                depth += 1
            elif ch in "}])":
                depth -= 1
                if depth == 0:
                    return src[start : i + 1]
        return None

    @classmethod
    def _all_js(cls) -> str:
        """Every byte an Alpine factory could be declared in, comments and strings blanked."""
        parts = [p.read_text(encoding="utf-8") for p in sorted(cls._static().glob("*.js"))]
        for path in sorted(cls._templates().rglob("*.html")):
            parts.extend(cls._INLINE_SCRIPT.findall(path.read_text(encoding="utf-8")))
        return cls._strip_js("\n".join(parts))

    @classmethod
    def _nullable_roots(cls, js: str, factory: str) -> set[str] | None:
        """Depth-1 keys of `factory`'s returned object that start as `null`.

        None means "could not read it", which the caller must treat as *no* claim about
        nullability rather than as "nothing is nullable".
        """
        head = None
        for pattern in cls._FACTORY_HEADS:
            head = re.search(pattern.format(n=re.escape(factory)), js, re.M)
            if head:
                break
        if not head:
            return None
        brace = js.find("{", head.end() - 1)
        if brace < 0:
            return None
        body = cls._balanced(js, brace)
        if body is None:
            return None
        ret = re.search(r"\breturn\s*\{", body)
        if not ret:
            return None
        obj = cls._balanced(body, body.index("{", ret.start() + len("return")))
        if obj is None:
            return None

        keys: set[str] = set()
        depth = 0
        for i, ch in enumerate(obj):
            if ch in "{[(":
                depth += 1
            elif ch in "}])":
                depth -= 1
            elif depth == 1 and not (i and re.match(r"[\w$.]", obj[i - 1])):
                m = re.match(r"([A-Za-z_$][\w$]*)\s*:\s*null\s*[,}]", obj[i:])
                if m:
                    keys.add(m.group(1))
        return keys

    @classmethod
    def _factories_by_template(cls) -> dict[str, set[str]]:
        """Which component scopes reach each template, following `{% include %}`."""
        templates = cls._templates()
        declared: dict[str, set[str]] = {}
        includes: dict[str, set[str]] = {}
        for path in sorted(templates.rglob("*.html")):
            src = path.read_text(encoding="utf-8")
            rel = path.relative_to(templates).as_posix()
            declared[rel] = {m.group(2) for m in cls._X_DATA_FACTORY.finditer(src)}
            includes[rel] = {m.group(2) for m in cls._INCLUDE.finditer(src)}

        reach = {rel: set(names) for rel, names in declared.items()}
        for _ in range(len(reach)):  # bounded: propagation is monotone and finite
            changed = False
            for parent, children in includes.items():
                for child in children:
                    if child in reach and not reach[parent] <= reach[child]:
                        reach[child] |= reach[parent]
                        changed = True
            if not changed:
                break
        return reach

    # ── expression analysis ──────────────────────────────────────────────────

    @staticmethod
    def _guards(expr: str, root: str) -> bool:
        """Does this one expression establish `root` before dereferencing it?"""
        src = _STRINGS.sub("''", expr)
        name = re.escape(root)
        return bool(
            # `stats && …`, `stats ? … : …`, `stats || …`
            re.search(rf"(?<![\w$.]){name}\s*(?:&&|\|\||\?(?!\.))", src)
            # `!stats || …`
            or re.search(rf"!\s*{name}(?![\w$.])", src)
        )

    @staticmethod
    def _bare_dereferences(expr: str, root: str) -> bool:
        """`stats.x` / `stats[…]` — but not `stats?.x`, which is one of the fixes."""
        src = _STRINGS.sub("''", expr)
        return bool(re.search(rf"(?<![\w$.]){re.escape(root)}\s*(?:\.(?!\?)|\[)", src))

    @staticmethod
    def _mentions(expr: str, root: str) -> bool:
        src = _STRINGS.sub("''", expr)
        return bool(re.search(rf"(?<![\w$.]){re.escape(root)}(?![\w$])", src))

    @classmethod
    def _neutralise_jinja(cls, src: str) -> str:
        """Make a Jinja template parseable as HTML without moving any line."""
        src = cls._JINJA_BLOCK.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), src)
        return cls._JINJA_VAR.sub(lambda m: "J" + "\n" * m.group(0).count("\n"), src)

    class _Scanner(HTMLParser):
        def __init__(self, outer: type, roots: set[str]) -> None:
            super().__init__(convert_charrefs=True)
            self.outer = outer
            self.roots = roots
            self.stack: list[tuple[str, set[str]]] = []
            self.offenders: list[tuple[int, str, str, str, str]] = []

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            a = dict(attrs)
            gated: set[str] = set()
            for _tag, names in self.stack:
                gated |= names

            for name, value in a.items():
                if not value or name in _SKIP_ATTRS or name in _NON_EXPRESSION:
                    continue
                if not _BINDING.match(name):
                    continue
                if name.startswith("@") or name.startswith("x-on"):
                    continue  # handlers evaluate on the event, not on the init walk
                for root in sorted(self.roots):
                    if root in gated or self.outer._guards(value, root):
                        continue
                    if self.outer._bare_dereferences(value, root):
                        self.offenders.append((self.getpos()[0], tag, name, value.strip()[:90], root))

            # Only a <template> genuinely defers its subtree.
            own: set[str] = set()
            if tag == "template":
                for name, value in a.items():
                    if name in ("x-if", "x-for") and value:
                        own |= {r for r in self.roots if self.outer._mentions(value, r)}
            if tag not in VOID:
                self.stack.append((tag, own))

        def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self.handle_starttag(tag, attrs)

        def handle_endtag(self, tag: str) -> None:
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i][0] == tag:
                    del self.stack[i:]
                    break

    # ── the guards ───────────────────────────────────────────────────────────

    def test_the_nullable_set_is_actually_learned(self):
        """A silent extraction failure would make the guard below vacuously green.

        It asserts a property, not a list: at least one Alpine factory must be locatable and
        declare at least one `null` root. Rewriting `graph.js`'s factory into a shape
        `_FACTORY_HEADS` cannot see fails here rather than quietly disarming the real check.
        """
        js = self._all_js()
        factories = {f for names in self._factories_by_template().values() for f in names}
        assert factories, "no x-data factories found — the template scan is broken"
        learned = {f: self._nullable_roots(js, f) for f in factories}
        assert any(learned.values()), f"no factory's returned object could be read, so the nullable-root guard is inert; factories seen: {sorted(factories)}"

    def test_no_template_dereferences_a_nullable_root_behind_an_x_show(self):
        js = self._all_js()
        templates = self._templates()
        reach = self._factories_by_template()
        cache: dict[str, set[str] | None] = {}

        offenders: list[str] = []
        for rel, factories in sorted(reach.items()):
            roots: set[str] = set()
            for factory in factories:
                if factory not in cache:
                    cache[factory] = self._nullable_roots(js, factory)
                roots |= cache[factory] or set()
            if not roots:
                continue
            src = self._neutralise_jinja((templates / rel).read_text(encoding="utf-8"))
            scanner = self._Scanner(type(self), roots)
            scanner.feed(src)
            for line, tag, attr, expr, root in scanner.offenders:
                if f"{rel}:{root}" in self.UNGUARDED_OK:
                    continue
                offenders.append(f'{rel}:{line} <{tag} {attr}="{expr}"> dereferences `{root}`, which starts null')

        assert not offenders, (
            "Alpine evaluates these while the component's state is still null — `x-show` on an "
            "ancestor does not defer evaluation. Write `root?.key`, `root && root.key`, or move "
            "the markup inside a <template x-if>:\n  " + "\n  ".join(offenders)
        )


def test_a_picker_search_box_never_lets_its_native_change_reach_the_form():
    """A nameless search box inside an `hx-trigger="change"` form must stop that event.

    A text input fires a native `change` on **blur** whenever its value differs from what it
    was at focus. Both `caseEntityFilter` boxes sit inside a form htmx triggers on `change`,
    so clicking a suggestion — which blurs the box — raced the row's own click: the browser
    dispatched `change` first, htmx re-fetched with the *stale* `entity_id` and swapped the
    whole partial, destroying the button before `choose()` could run. The pick silently did
    not take, roughly whenever you had typed something before clicking.

    This is the sibling of `test_timeline_entity_filter_submits_a_usable_entity_id` below,
    and of the `_refetch()` ordering guard in `tests/test_alpine_components_resolve.py`: all
    three are ways the same field can serialize the wrong value. Invisible to a route test —
    the server renders identical HTML either way, and the request it answers is a perfectly
    valid one for the value it was sent.

    The box carries no `name`, so it submits nothing and the native event is pure noise;
    `_refetch()` dispatches the form's `change` itself once the hidden field is written.
    """
    import re
    from pathlib import Path

    templates = Path(__file__).resolve().parent.parent / "app" / "templates"
    # The search box is the `x-model="label"` input the component owns; the hidden field and
    # the job `<select>` beside it must keep bubbling, so this cannot be a form-wide rule.
    box = re.compile(r"""<input\s+type="text"\s+x-model="label"[^>]*>""", re.S)

    checked = 0
    offenders = []
    for path in sorted(templates.rglob("*.html")):
        body = path.read_text(encoding="utf-8")
        if "caseEntityFilter(" not in body:
            continue
        for match in box.finditer(body):
            checked += 1
            if "@change.stop" not in match.group(0):
                line_no = body[: match.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(templates)}:{line_no}")

    assert checked >= 2, f"expected both caseEntityFilter search boxes, found {checked}"
    assert not offenders, "picker search box must carry @change.stop: " + ", ".join(offenders)


def test_the_lineage_tree_survives_a_forest_with_no_roots():
    """`x-ref="tree"` is inside the `forest.roots` guard, so it can legitimately be absent.

    `init()` runs regardless, and an unguarded `this.$refs.tree.dataset` throws
    `reading 'dataset'` — which aborts Alpine's init for that component and takes every
    control on the panel down with it. The case Processes tab draws for whatever job is
    picked, so a job with no process-creation events is an ordinary outcome, not an edge.
    """
    from pathlib import Path

    body = (Path(__file__).resolve().parent.parent / "app" / "templates" / "partials" / "_process_tree.html").read_text(encoding="utf-8")

    assert 'x-ref="tree"' in body
    assert "{% if forest.roots %}" in body, "the ref is only rendered when there are roots — that is the whole hazard"
    init = body[body.index("init() {") : body.index("_all()")]
    assert "if (!tree) return;" in init, "init() must tolerate a missing tree ref"
    assert "this.$refs.tree ? this.$refs.tree" in body, "_all() must tolerate it too"


def test_no_alpine_expression_interpolates_a_tag_name():
    """A tag is analyst- or admin-written text, and `normalize_tag` keeps quotes and spaces.
    Put inside a quoted JS literal, `o'brien` ends the string (Jinja's `&#39;` is decoded back
    before Alpine reads it) and `known good` builds two search terms. Carry the value in a
    `data-*` attribute and read it from `$el.dataset`, as `_tag_chip.html` does."""
    offenders = []
    pattern = re.compile(r"""(?:@|:|x-)[\w.:-]*="[^"]*'[^'"]*\{\{[^}]*\btag\b[^}]*\}\}""")
    for path in Path("app/templates").rglob("*.html"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path}:{n}")
    assert offenders == []


async def test_a_shared_rule_chip_carries_its_tag_as_data(member_client, async_db):
    from app.models import IntelRule

    async_db.add_all(
        [
            IntelRule(name="Quoted", query="x", entity_types="[]", is_builtin=True, builtin_key="quoted", enabled=True, action_tag="o'brien"),
            IntelRule(name="Spaced", query="y", entity_types="[]", is_builtin=True, builtin_key="spaced", enabled=True, action_tag="known good"),
        ]
    )
    await async_db.commit()

    body = (await member_client.get("/intel")).text
    assert 'data-token="tag:o&#39;brien"' in body
    assert 'data-token="&#34;tag:known good&#34;"' in body, "a tag with a space is one quoted term"
