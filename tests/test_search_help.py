"""One help affordance, and help text generated from the list the parser reads.

Two failure modes motivated this file, and neither is visible to a route test.

The first is drift. The entity grammar's help existed in three hand-written copies — a
`<details>` on the dashboard, a paragraph in the graph help panel, and `/docs` — and all
three had gone stale in the same direction: none mentioned `job:`, `type:` or `attr:`,
which the parser has accepted for months and the placeholder advertises. Generating the
panel from `queries.SYNTAX_HELP` makes "documented but unimplemented" and "implemented but
undiscoverable" both fail here instead of silently misleading an analyst.

The second is the affordance itself. There were eight hand-written "?" buttons in two
geometries, and the two search boxes that mattered most disagreed about whether the panel
opened on hover or on click. A copy renders perfectly, so only a static check catches it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.intel.queries import _PREFIXES, SYNTAX_HELP, SYNTAX_INTRO, parse_query
from app.jobs_query import SYNTAX_HELP as JOBS_SYNTAX_HELP

TEMPLATES = Path(__file__).resolve().parent.parent / "app" / "templates"
BASE_HTML = TEMPLATES / "base.html"


# ── the help is generated from the parser's own list ────────────────────────────────────


@pytest.mark.parametrize("example", [row[0] for row in SYNTAX_HELP])
def test_every_advertised_example_parses(example: str):
    """A term the panel shows and the parser rejects is worse than no help at all."""
    parsed = parse_query(example)
    assert not parsed.get("errors"), f"{example!r} is advertised but does not parse: {parsed.get('errors')}"


def test_every_prefix_the_parser_knows_is_advertised():
    """The other direction: a term nobody can discover is the same as one that is off."""
    advertised = " ".join(syntax for syntax, _ in SYNTAX_HELP)
    for prefix in _PREFIXES:
        assert prefix in advertised, f"{prefix} is implemented but appears in no help row"


def test_the_two_grammars_share_one_row_shape():
    """`help_popover(rows=…)` renders both, so both must be `(syntax, meaning)` pairs."""
    for rows in (SYNTAX_HELP, JOBS_SYNTAX_HELP):
        for row in rows:
            assert len(row) == 2, f"{row!r} is not a (syntax, meaning) pair"
            assert all(isinstance(part, str) and part for part in row), row


def test_the_help_reaches_templates_as_a_global():
    """Not a per-route context key: the entity grammar's panel is rendered from three
    templates whose contexts are built in three different routers, and a key missed at one
    of them renders a working `?` over an empty panel."""
    from app.templates_config import templates

    assert templates.env.globals["entity_syntax_help"] is SYNTAX_HELP
    assert templates.env.globals["jobs_syntax_help"] is JOBS_SYNTAX_HELP
    assert templates.env.globals["entity_syntax_intro"] == SYNTAX_INTRO


# ── one affordance ──────────────────────────────────────────────────────────────────────


def _templates() -> list[Path]:
    return sorted(TEMPLATES.rglob("*.html"))


_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)


def _markup(path: Path) -> str:
    """A template with its `{# … #}` comments removed.

    These assertions are about markup, not prose, and this project's templates explain
    *why* a construct is avoided in a comment right beside where it would go — so a naive
    substring check fails on the sentence describing it.
    """
    return _JINJA_COMMENT.sub("", path.read_text())


def test_no_template_hand_writes_the_help_button():
    """The hand-written "?" recipe. `help_popover()` owns it, and `.lt-help` owns its
    geometry, so a call site cannot drift by editing a class string."""
    offenders = [p.name for p in _templates() if "rounded-full bg-gray-700/80" in p.read_text()]
    assert not offenders, f"hand-written help buttons remain in {offenders}"


def test_the_help_primitive_is_defined_once():
    css = BASE_HTML.read_text()
    for cls in (".lt-help ", ".lt-help-panel ", ".lt-help-wrap "):
        assert css.count(cls + "{") + css.count(cls + " {") >= 1, f"{cls} is not defined in base.html"
    assert css.count("\n    .lt-help {") == 1, "the help button is defined more than once"


def test_the_panel_opens_on_click_and_can_be_read_from():
    """A hover panel cannot be opened on a touch device, and `pointer-events-none` — which
    every hover copy needed so it would not swallow a click aimed at the field — also makes
    it impossible to select the query syntax it exists to show."""
    macro = _markup(TEMPLATES / "partials" / "_help_popover.html")
    assert "@click.prevent=" in macro and "@click.outside=" in macro
    assert "@keydown.escape=" in macro, "Esc must close it"
    assert ":aria-expanded=" in macro
    assert "pointer-events-none" not in macro
    assert "@mouseenter" not in macro, "one trigger, and it is click"


# ── every grammar-bearing box has one ────────────────────────────────────────────────────

#: Boxes that accept the query grammar, and therefore need the panel. A box that does plain
#: substring matching is deliberately absent: a `?` over "type part of a name" is noise.
GRAMMAR_BOXES = {
    "partials/_jobs_list_pane.html": "jobs_syntax_help",
    "intel/dashboard.html": "entity_syntax_help",
    # The rule form moved out of `_rules_body.html` when it stopped being rendered with
    # the page — the Condition field, and therefore the grammar box, went with it.
    "intel/partials/_rule_form.html": "entity_syntax_help",
    "intel/partials/_graph_toolbar.html": "entity_syntax_help",
}


@pytest.mark.parametrize(("name", "rows"), sorted(GRAMMAR_BOXES.items()))
def test_every_grammar_box_offers_the_shared_help(name: str, rows: str):
    text = (TEMPLATES / name).read_text()
    assert "help_popover(" in text, f"{name} has a query box with no help"
    assert f"rows={rows}" in text, f"{name} does not feed the panel from the parser's list"
    assert "_help_popover.html" in text, f"{name} uses the macro without importing it"


def test_the_watch_rule_no_longer_points_at_another_page():
    """It read `· same syntax as the dashboard search` — a cross-reference to a `<details>`
    that is not on `/intel/rules` at all, so the only way to read it was to leave."""
    for name in ("_rules_body.html", "_rule_form.html"):
        assert "same syntax as the dashboard search" not in _markup(TEMPLATES / "intel" / "partials" / name)


def test_the_dashboard_no_longer_hides_its_syntax_in_a_details():
    """At the bottom of the *collapsed* Filters panel — two clicks and a scroll from the
    field it describes — the syntax help drifts out of date unnoticed."""
    text = _markup(TEMPLATES / "intel" / "dashboard.html")
    assert not re.search(r"<summary[^>]*>\s*Search syntax", text)


def test_the_graph_help_points_rather_than_copies():
    """Spelling the terms out a second time makes a copy that drifts — one that omits
    `job:`, `type:` or `attr:`."""
    text = _markup(TEMPLATES / "intel" / "partials" / "_graph_help.html")
    assert "Filter syntax" in text, "the section is still worth having — it just points now"
    assert "cidr:10.0.0.0/8" not in text, "the graph help re-copied the term list"
