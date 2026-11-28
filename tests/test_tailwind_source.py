"""One Tailwind source, compiled by both builds, resolving the way the UI was built for.

Production compiles app/static/tailwind-input.css with the standalone CLI; development
compiles in the browser. Both read app/templates/partials/_tailwind.css — the theme, the
layer order and the Tailwind 3 compatibility rules — so the only thing the two builds do
differently is where they find class names. These guards keep it that way, and pin the
three decisions in that file whose failure renders a page wrong without an error:

- gray resolves through the --ui-gray-* variables in app/static/themes.css;
- utilities are UNLAYERED (base.html's `.lt-*` CSS is unlayered too, and an unlayered rule
  beats any layered one regardless of specificity);
- line heights are lengths, not ratios (a ratio inherits differently).
"""

from __future__ import annotations

import re
from pathlib import Path

from _taskfile import all_raw

EXPECTED_KEYS = {"50", "100", "200", "300", "400", "500", "600", "700", "800", "900", "950"}

REPO_ROOT = Path(__file__).parent.parent
SOURCE = REPO_ROOT / "app" / "templates" / "partials" / "_tailwind.css"
INPUT = REPO_ROOT / "app" / "static" / "tailwind-input.css"
BASE_HTML = REPO_ROOT / "app" / "templates" / "base.html"


def _theme_block() -> str:
    m = re.search(r"^@theme \{(.*?)^\}", SOURCE.read_text(), re.S | re.M)
    assert m, "_tailwind.css has no top-level @theme block"
    return m.group(1)


def test_both_builds_compile_the_one_source():
    """Production imports the partial; development includes it. A second copy of the theme
    is how the two builds drift — base.html used to carry a hand-mirrored Play CDN config."""
    assert re.search(r'^@import "\.\./templates/partials/_tailwind\.css";', INPUT.read_text(), re.M), "tailwind-input.css does not import the shared source"
    assert '{% include "partials/_tailwind.css" %}' in BASE_HTML.read_text(), "base.html's dev block does not include the shared source"
    assert not (REPO_ROOT / "tailwind.config.js").exists(), "Tailwind 4 reads no JS config; a tailwind.config.js here would be a third, unread copy"


def test_gray_resolves_through_the_theme_variables():
    keys = set(re.findall(r"--color-gray-(\d+):\s*rgb\(var\(--ui-gray-\1\)\);", _theme_block()))
    assert keys == EXPECTED_KEYS, f"gray shades not mapped onto --ui-gray-*: {sorted(EXPECTED_KEYS ^ keys)}"


def test_themes_css_defines_every_palette_key():
    """`:root` must define every --ui-gray-N var Tailwind resolves against.

    There is one theme, so one block, and the check is that it is complete, because a
    missing key renders a whole Tailwind gray shade as nothing.
    """
    text = (REPO_ROOT / "app" / "static" / "themes.css").read_text()
    block = re.search(r":root\s*\{([^}]+)\}", text)
    assert block, ":root block not found in themes.css"
    missing = EXPECTED_KEYS - set(re.findall(r"--ui-gray-(\d+)\s*:", block.group(1)))
    assert not missing, f"themes.css is missing ui-gray keys: {sorted(missing)}"


def test_no_theme_attribute_selectors_remain():
    """One theme means nothing keys off `[data-theme]` — a leftover rule would be dead CSS
    that only ever applies if someone hand-edits the DOM."""
    text = (REPO_ROOT / "app" / "static" / "themes.css").read_text()
    assert "[data-theme" not in text


def test_utilities_are_unlayered_and_the_rest_is_layered():
    """`@import "tailwindcss"` would put utilities in a layer, and every `.lt-*` rule in
    base.html — unlayered — would then beat every utility beside it, whatever the
    specificity: `hover:` states on a control, and the `:where(.lt-menu)` padding rule that
    exists so a `p-3` can win. Theme and preflight belong in layers, so any class beats them."""
    text = SOURCE.read_text()
    assert '@import "tailwindcss";' not in text
    assert re.search(r'^@import "tailwindcss/theme\.css" layer\(theme\);', text, re.M)
    assert re.search(r'^@import "tailwindcss/preflight\.css" layer\(base\);', text, re.M)
    utilities = re.search(r'^@import "tailwindcss/utilities\.css"([^;]*);', text, re.M)
    assert utilities, "the utilities import is gone"
    assert "layer(" not in utilities.group(1), "utilities were put in a cascade layer; .lt-* CSS would now win every pairing"
    assert "source(none)" in utilities.group(1), "without source(none) the CLI auto-detects classes across the whole repository"


def test_line_heights_are_lengths():
    """v4's ratios (`calc(1.25 / 0.875)`) inherit as ratios: a `text-[10px]` badge inside a
    `text-sm` tab got a 14px line box instead of 20px and every tab strip lost 4px."""
    block = _theme_block()
    for size in ("xs", "sm", "base", "lg", "xl", "2xl", "3xl", "4xl"):
        m = re.search(rf"--text-{size}--line-height:\s*([^;]+);", block)
        assert m and m.group(1).strip().endswith("rem"), f"text-{size} line height is not pinned to a length"


def test_the_source_is_safe_to_include():
    """Development includes the file into a `<script type="text/plain">` through Jinja."""
    text = SOURCE.read_text()
    assert not re.search(r"\{[%#{]", text), "a Jinja delimiter in _tailwind.css breaks every page in development"
    assert "</script" not in text.lower(), "a closing script tag in _tailwind.css ends the dev holder early"


def test_the_dev_block_keeps_the_source_out_of_any_html_style_element():
    """Chromium's preload scanner fetches @import URLs out of every <style> in the HTML
    source whatever its `type`, so a literal <style type="text/tailwindcss"> holding the
    imports cost two 404s and two console errors per page."""
    block = re.search(r"<!-- TAILWIND:START -->\n(.*?)<!-- TAILWIND:END -->", BASE_HTML.read_text(), re.S)
    assert block, "base.html has no TAILWIND block"
    assert "<style" not in block.group(1)
    assert '<script type="text/plain" id="lt-tailwind-source">' in block.group(1)


def test_the_entity_chip_colours_are_kept_by_the_production_build():
    """The palettes in _analytics.html and _tag_chip.html are looked up, not assembled, but
    a shade no template spells out would still be dropped from the compiled sheet."""
    text = INPUT.read_text()
    assert re.search(r'^@source "\.\./templates";', text, re.M)
    colours = "{blue,purple,green,cyan,yellow,orange,rose,teal,indigo}"
    for pattern in (f"bg-{colours}-900/{{40,50,60}}", f"text-{colours}-{{200,300,400}}", f"border-{colours}-700/{{40,50,60}}"):
        assert f'@source inline("{pattern}");' in text, f"safelist entry missing: {pattern}"


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
