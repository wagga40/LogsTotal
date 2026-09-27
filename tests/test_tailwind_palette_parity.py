"""Guards against silent drift of the themed gray palette between three sources:

- tailwind.config.js      → used by `task css:build` (production CSS)
- app/templates/base.html → inline Play-CDN config (dev mode)
- app/static/themes.css   → --ui-gray-* custom properties the above reference

If any file's set of keys drifts, one of dev/prod will silently render the wrong
palette. This test parses each source with a regex and asserts all three agree
on the same 11 keys (50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950).
"""

from __future__ import annotations

import re
from pathlib import Path

from _taskfile import all_raw

EXPECTED_KEYS = {"50", "100", "200", "300", "400", "500", "600", "700", "800", "900", "950"}

REPO_ROOT = Path(__file__).parent.parent


def _palette_keys_from_var_refs(text: str) -> set[str]:
    return set(re.findall(r"rgb\(var\(--ui-gray-(\d+)\)\s*/\s*<alpha-value>\)", text))


def _palette_keys_from_definitions(text: str) -> set[str]:
    return set(re.findall(r"--ui-gray-(\d+)\s*:", text))


def test_tailwind_config_palette_complete():
    text = (REPO_ROOT / "tailwind.config.js").read_text()
    assert _palette_keys_from_var_refs(text) == EXPECTED_KEYS


def test_base_html_palette_complete():
    text = (REPO_ROOT / "app" / "templates" / "base.html").read_text()
    assert _palette_keys_from_var_refs(text) == EXPECTED_KEYS


def test_themes_css_defines_every_palette_key():
    """`:root` must define every --ui-gray-N var Tailwind resolves against.

    There is one theme, so one block, and the check is that it is complete, because a
    missing key renders a whole Tailwind gray shade as nothing.
    """
    text = (REPO_ROOT / "app" / "static" / "themes.css").read_text()
    block = re.search(r":root\s*\{([^}]+)\}", text)
    assert block, ":root block not found in themes.css"
    missing = EXPECTED_KEYS - _palette_keys_from_definitions(block.group(1))
    assert not missing, f"themes.css is missing ui-gray keys: {sorted(missing)}"


def test_no_theme_attribute_selectors_remain():
    """One theme means nothing keys off `[data-theme]` — a leftover rule would be dead CSS
    that only ever applies if someone hand-edits the DOM."""
    text = (REPO_ROOT / "app" / "static" / "themes.css").read_text()
    assert "[data-theme" not in text


def test_tailwind_config_and_base_html_agree():
    """Dev (base.html Play CDN) and prod (tailwind.config.js) must reference the same keys."""
    tw = _palette_keys_from_var_refs((REPO_ROOT / "tailwind.config.js").read_text())
    base = _palette_keys_from_var_refs((REPO_ROOT / "app" / "templates" / "base.html").read_text())
    assert tw == base, f"tailwind.config.js vs base.html key drift: {tw ^ base}"


def test_the_css_mode_swap_is_idempotent():
    """`css:build` and `css:dev` must not accrete whitespace on every round trip.

    Both tasks rewrite the `<!-- TAILWIND:START -->…<!-- TAILWIND:END -->` block in
    base.html with a perl substitution. Capturing the end marker as `(\\s*<!-- TAILWIND:END
    -->)` and then prefixing the replacement with its own `\\n  ` meant the captured
    whitespace and the emitted whitespace *both* landed — two blank lines per round trip.

    `task package` runs build-then-dev, so every maintainer packaging a release silently
    dirtied a tracked template, which is the same failure `scripts/upgrade.sh` had with the
    VERSION manifest: a build that cannot be run twice from a clean tree.

    Asserted on the source rather than by running the tasks, because the Tailwind standalone
    CLI is gitignored — a behavioural test would skip on CI, which is where it matters.
    """
    taskfile = all_raw()
    # The match half and the replacement half of each `s{…}\n{…}s`. Scoped to the
    # substitutions rather than grepping the whole file, so the comment above each one is
    # free to quote the broken form.
    swaps = re.findall(r"s\{\(?(<!-- TAILWIND:START -->.*?)\}\s*\n\s*\{(.*?)\}s", taskfile, re.S)
    assert len(swaps) == 2, f"expected the two TAILWIND block swaps (css:prod, css:dev), found {len(swaps)}"

    for pattern, replacement in swaps:
        assert "(\\s*<!-- TAILWIND:END -->)" not in pattern, (
            f"this TAILWIND swap captures the end marker with its leading whitespace: s{{{pattern}}}. "
            "Match it unparenthesised and emit `<!-- TAILWIND:END -->` literally in the replacement — "
            "capturing it makes the substitution accrete a blank line per round trip."
        )
        assert "<!-- TAILWIND:END -->" in replacement, (
            f"a TAILWIND swap replacement does not re-emit the end marker literally: {replacement!r}. "
            "Without it the marker survives only by capture, which is what made the swap non-idempotent."
        )


def test_css_build_points_base_html_through_css_prod():
    """`css:build` compiles, `css:prod` points base.html at the result — and `css:build`
    must reach the second through the first rather than carrying its own copy.

    scripts/package.sh needs the pointing half WITHOUT the CLI (PACKAGE_USE_COMMITTED_CSS),
    and a hand-written fourth copy of that perl — Taskfile build, Taskfile dev, Dockerfile,
    package.sh — is how the swap stops being reversible: css:dev only restores blocks that
    look the way css:dev expects.
    """
    taskfile = all_raw()
    build = re.search(r"\n  css:build:\n(.*?)\n  css:prod:", taskfile, re.S)
    assert build, "css:build no longer precedes css:prod in the Taskfile"
    assert "task: css:prod" in build.group(1), "css:build does not delegate the base.html swap to css:prod"
    assert "TAILWIND:START" not in build.group(1), "css:build grew its own copy of the swap again"
