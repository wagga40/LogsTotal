"""The shared confirm dialog must actually be wired up wherever a destructive action renders.

`app.js::setupConfirmDialog` reads `dataset.confirmMessage` and *gates* on it
(`if (!elt.dataset.confirmMessage) return`). A template spelling it `data-confirm-body` /
`data-confirm-ok` makes the listener return early and htmx issue the request unprompted —
"Remove this tag everywhere" would run on the first click. Nothing errors; the attributes
simply address a handler that is not listening for them.

`test_every_confirm_attribute_in_a_template_is_one_app_js_reads` derives the supported names
from app.js itself, so the template side cannot drift from the reader.

The dialog *element* is a different matter and is already safe: base.html renders
`partials/_confirm_dialog.html` once for every page. The checks below pin that arrangement
from both ends — a page must have it (`setupConfirmDialog` bails at `if (!dialog) return`,
which would silently disarm every confirm on that page), and it must appear exactly once,
because a second include is a duplicate `id` whose element `getElementById` would never
return.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.anyio

TEMPLATES = Path(__file__).resolve().parent.parent / "app" / "templates"
APP_JS = Path(__file__).resolve().parent.parent / "app" / "static" / "app.js"

# The attribute the handler gates on. Anything else is decoration that never fires alone.
REQUIRED_ATTR = "data-confirm-message"


def _kebab(camel: str) -> str:
    return "data-" + re.sub(r"(?<!^)(?=[A-Z])", "-", camel).lower()


def _attrs_app_js_reads() -> set[str]:
    """Derive the supported attribute names from app.js, so the two cannot drift apart."""
    src = APP_JS.read_text(encoding="utf-8")
    return {_kebab(name) for name in re.findall(r"dataset\.(confirm[A-Za-z]*)", src)}


def test_every_confirm_attribute_in_a_template_is_one_app_js_reads():
    supported = _attrs_app_js_reads()
    assert REQUIRED_ATTR in supported, "app.js no longer reads data-confirm-message; update this guard"

    unknown: list[str] = []
    for path in TEMPLATES.rglob("*.html"):
        for attr in set(re.findall(r"\bdata-confirm-[a-z-]+", path.read_text(encoding="utf-8"))):
            if attr not in supported:
                unknown.append(f"{path.relative_to(TEMPLATES)}: {attr}")
    assert not unknown, f"confirm attributes app.js never reads (the dialog will not open, and the action fires unprompted); it reads {sorted(supported)}:\n  " + "\n  ".join(
        sorted(unknown)
    )


def test_no_template_decorates_a_confirm_without_the_attribute_that_triggers_it():
    """`data-confirm-title` alone reads like a wired-up confirm and is a no-op."""
    offenders: list[str] = []
    for path in TEMPLATES.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        decorated = re.search(r"\bdata-confirm-(title|accept)\b", text)
        if decorated and REQUIRED_ATTR not in text:
            offenders.append(f"{path.relative_to(TEMPLATES)}: has {decorated.group(0)} but no {REQUIRED_ATTR}")
    assert not offenders, "\n".join(offenders)


PAGES_NEEDING_LOGIN = ["/jobs", "/intel", "/intel/tags", "/intel/rules", "/intel/cases"]


@pytest.mark.parametrize("url", PAGES_NEEDING_LOGIN)
async def test_every_page_ships_exactly_one_confirm_dialog(member_client, url):
    """Zero disarms every confirm on the page; two is a duplicate id.

    base.html includes the partial for all pages, so the correct count is always exactly one
    — a page template adding its own is the failure this catches (three did, and the extra
    element sat dead in the markup because getElementById returns the first match).
    """
    resp = await member_client.get(url)
    assert resp.status_code == 200, f"{url} returned {resp.status_code}"
    count = resp.text.count('id="confirm-dialog"')
    assert count == 1, f"{url} renders {count} #confirm-dialog elements, expected exactly 1 (base.html provides it; page templates must not include it again)"


def test_no_page_template_re_includes_the_dialog_base_html_already_provides():
    """The static half of the check above — it names the offending file directly."""
    offenders = [
        str(path.relative_to(TEMPLATES))
        for path in TEMPLATES.rglob("*.html")
        if path.name != "_confirm_dialog.html"
        and path.relative_to(TEMPLATES).as_posix() != "base.html"
        and "_confirm_dialog.html" in path.read_text(encoding="utf-8")
        and "{% include" in path.read_text(encoding="utf-8").split("_confirm_dialog.html")[0].rsplit("\n", 1)[-1]
    ]
    assert not offenders, "duplicate confirm-dialog include (base.html already renders it):\n  " + "\n  ".join(offenders)


@pytest.fixture()
async def seeded_panes(member_client, async_db):
    """A tag and a watch rule, so the panes actually render their destructive rows.

    Without this the delete buttons live inside per-row loops that never execute, both panes
    come back with no `data-confirm-*` at all, and any check over them passes vacuously —
    which is exactly what the first version of the test below did.
    """
    from sqlalchemy import select

    from app.models import Entity, EntityTag, IntelRule, User

    entity = Entity(value="10.7.7.7", entity_type="ip_address", job_count=1)
    async_db.add(entity)
    await async_db.commit()
    await async_db.refresh(entity)

    owner_id = await async_db.scalar(select(User.id).where(User.role == "member"))
    async_db.add(EntityTag(entity_id=entity.id, tag="omega", color="red"))
    async_db.add(IntelRule(name="Rule One", query="label:dga", owner_user_id=owner_id))
    await async_db.commit()
    return entity


async def test_the_intel_dashboard_lazily_loads_no_uncovered_pane(member_client, seeded_panes):
    """A lazily loaded pane must not carry an uncovered destructive action.

    A pane that arrives by `htmx.ajax`, not `{% include %}`, never puts its
    `data-confirm-*` in the page's own HTML, so the page-level check above cannot see it.
    Tags and Rules are top-level pages that `PAGES_NEEDING_LOGIN` covers directly. If the
    dashboard ever declares a lazy pane, it has to ship the dialog its pane's destructive
    rows will need, and this asserts the pair rather than assuming the machinery stays gone.
    """
    page = await member_client.get("/intel")
    assert page.status_code == 200

    section_urls = re.search(r"sectionUrls:\s*\{([^}]*)\}", page.text)
    urls = re.findall(r"'(/[^']+)'", section_urls.group(1)) if section_urls else []
    for url in urls:
        pane = await member_client.get(url, headers={"HX-Request": "true"})
        assert pane.status_code == 200, f"{url} returned {pane.status_code}"
        if REQUIRED_ATTR not in pane.text:
            continue
        assert 'id="confirm-dialog"' in page.text, (
            f"the pane at {url} carries {REQUIRED_ATTR}, but /intel does not include partials/_confirm_dialog.html — its destructive actions fire on first click"
        )


async def test_the_destructive_intel_actions_are_actually_confirmed(member_client, seeded_panes):
    """Belt and braces on the two that regressed, named individually."""
    tags = await member_client.get("/intel/tags")
    assert "/intel/tags/delete" in tags.text, "the tag delete button did not render"
    assert REQUIRED_ATTR in tags.text, "the tag delete lost its confirm"

    rules = await member_client.get("/intel/rules")
    assert "/delete" in rules.text, "the rule delete button did not render"
    assert REQUIRED_ATTR in rules.text, "the rule delete lost its confirm"
