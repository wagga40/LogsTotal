"""Render-smoke tests for the readiness/concurrency admin partials.

Jinja errors (bad attribute, syntax slip in a `{% set %}`) only surface at
render time — these tests render the partials with realistic context so a
template regression fails in CI instead of on an admin's screen.
"""

from __future__ import annotations

from app.concurrency import compute_host_concurrency
from app.system_checks import CheckResult, summarize
from app.templates_config import templates


def _render(name: str, **context) -> str:
    return templates.env.get_template(name).render(**context)


def test_readiness_partial_renders_every_verdict():
    for levels, expected in (
        (["PASS"], "Ready"),
        (["PASS", "WARN"], "Ready with warnings"),
        (["FAIL", "WARN"], "Not ready"),
    ):
        results = [CheckResult("S", level, f"check-{i}", "msg", "fix") for i, level in enumerate(levels)]
        html = _render("admin/partials/_readiness.html", summary=summarize(results))
        assert expected in html
        # The CLI-only note must always be present.
        assert "./logstotal doctor" in html


def test_readiness_partial_lists_top_fixes():
    results = [
        CheckResult("Workers", "FAIL", "workers", "0 alive", "start one: task worker"),
        CheckResult("Backups", "WARN", "verified backup", "no receipt", "run: task backup"),
    ]
    html = _render("admin/partials/_readiness.html", summary=summarize(results))
    assert "0 alive" in html
    assert "run: task backup" in html


def test_system_checks_partial_renders_with_summary_banner():
    results = [
        CheckResult("Services", "PASS", "database", "reachable"),
        CheckResult("Workers", "WARN", "queue age", "old", "add workers"),
    ]
    html = _render(
        "admin/partials/_system_checks.html",
        results=results,
        summary=summarize(results),
        version_info={"version": "0.1.0"},
    )
    assert "Ready with warnings" in html
    assert "queue age" in html


def test_concurrency_partial_renders_recommendation_column():
    host = compute_host_concurrency(
        hostname="box",
        huey_workers=8,
        cpu_count=4,
        tool_max_workers=2,
        parallel_execution=False,
        max_tools_per_workflow=3,
        max_workflow_threads=2,
    )
    html = _render(
        "admin/partials/_concurrency.html",
        hosts=[host],
        parallel_execution=False,
        tool_max_workers=2,
        threads_per_tool=2,
        max_tools_per_workflow=3,
        recommended_workers={"box": 2},
    )
    assert "Rec." in html
    # Over-provisioned host (peak 16 > 4 cores) shows the inline hint.
    assert "recommend-scaling" in html


class TestAdminIcons:
    """Every admin card and settings section draws a glyph, and every glyph is drawable.

    A name the dictionary does not know renders **nothing, silently** — the macro's lookup
    simply misses. That is invisible to a route test (the page is still 200) and to review
    (the name looks plausible), so it is asserted from the outside, exactly as
    `TestTabIcons` does for the tab strips.
    """

    def _known_glyphs(self) -> set[str]:
        import re
        from pathlib import Path

        src = Path("app/templates/partials/_icons.html").read_text(encoding="utf-8")
        block = src[src.index("{%- set d = {") : src.index("} -%}")]
        return set(re.findall(r"^\s*'([a-z]+)':", block, re.M))

    def _named_glyphs(self, path: str) -> set[str]:
        import re
        from pathlib import Path

        # Three spellings, and the third is why this helper is worth the trouble: a glyph
        # can be named directly (`icon("x", …)`), as the first argument to the settings
        # page's `card("x", …)`, or as the *second* argument to the dashboard's
        # `manage_card(href, "x", …)`. When the Manage grid's hand-written cards collapsed
        # into that macro, the first two patterns stopped matching anything on the
        # dashboard and this guard went silently blind — which is the same failure mode it
        # exists to catch, one level up.
        text = Path(path).read_text(encoding="utf-8")
        return (
            set(re.findall(r'\bicon\(\s*"([a-z]+)"', text))
            | set(re.findall(r'(?<!manage_)\bcard\(\s*"([a-z]+)"', text))
            | set(re.findall(r'\bmanage_card\(\s*"[^"]*"\s*,\s*"([a-z]+)"', text))
        )

    def test_every_glyph_the_dashboard_names_is_drawable(self):
        named = self._named_glyphs("app/templates/admin/dashboard.html")
        assert named, "the dashboard should name at least one glyph"
        assert named <= self._known_glyphs(), f"undrawable glyph(s): {sorted(named - self._known_glyphs())}"

    def test_every_glyph_the_settings_page_names_is_drawable(self):
        named = self._named_glyphs("app/templates/admin/settings.html")
        assert named, "the settings page should name at least one glyph"
        assert named <= self._known_glyphs(), f"undrawable glyph(s): {sorted(named - self._known_glyphs())}"

    def test_every_glyph_the_upload_page_names_is_drawable(self):
        """The upload queue picks its row glyph from `upload.js::glyph()` and draws each
        candidate through `icon()`, so an unknown name leaves a row with an empty tile."""
        import re
        from pathlib import Path

        named = self._named_glyphs("app/templates/index.html")
        assert named, "the upload page should name at least one glyph"
        assert named <= self._known_glyphs(), f"undrawable glyph(s): {sorted(named - self._known_glyphs())}"
        # Every name `glyph()` can return has a matching `<template x-if>` in the page.
        script = Path("app/static/upload.js").read_text(encoding="utf-8")
        body = script[script.index("    glyph(row) {") : script.index("    badge(row) {")]
        returned = set(re.findall(r"'([a-z]+)'", body)) - {"idle", "busy", "ok", "warn", "bad", "queued", "waiting"}
        assert returned <= named, f"glyph() returns names the page never draws: {sorted(returned - named)}"

    def test_the_settings_sections_all_carry_one(self):
        """A section with no glyph in a column of sections that have one reads as a bug."""
        import re
        from pathlib import Path

        src = Path("app/templates/admin/settings.html").read_text(encoding="utf-8")
        calls = re.findall(r"\{%\s*call card\(([^)]*)\)", src)
        assert calls, "expected the settings page to use the card macro"
        for call in calls:
            assert call.strip().startswith('"'), f"card({call}) does not lead with a glyph name"

    async def test_the_glyphs_reach_the_rendered_pages(self, admin_client):
        """The macro has to actually be called — importing it and forgetting it is silent."""
        import re

        page = (await admin_client.get("/admin")).text
        cards = re.findall(r'<a href="[^"]+" class="group bg-gray-900.*?</a>', page, re.S)
        assert len(cards) >= 10, f"expected the Manage grid, found {len(cards)} cards"
        assert all("<svg " in card for card in cards), "a Manage card rendered without its icon"

        settings = (await admin_client.get("/admin/settings")).text
        sections = re.findall(r'<section class="bg-gray-900.*?</section>', settings, re.S)
        assert len(sections) >= 6, f"expected the settings sections, found {len(sections)}"
        assert all("<svg " in section for section in sections), "a settings section rendered without its icon"
