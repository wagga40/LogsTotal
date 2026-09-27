"""Static guard: every control in the app lines up, and stays lined up.

A *derived* height — line-height + 2*py + 2*border — drifts every time someone hand-writes a
class string. Representative failures:

  * a `text-sm` input (34px) among `text-xs` siblings (30px) in one filter bar
  * four heights in one row of tag controls: 22 / 22 / 20 / 16
  * Cancel/Primary pairs differing by exactly 2px, because the primary omits `border`

The guards cover the whole template tree, including the upload form and the login page —
the two surfaces a first-time visitor sees.

The `.lt-*` classes in base.html declare `height` outright, so font-size and padding cannot
shift it. These tests hold the line on things the CSS alone cannot:

1. every `lt-` class a template uses actually exists (a typo renders an unstyled control,
   which no route test would notice);
2. no element mixes an `.lt-*` class with the sizing utilities it replaces. That matters for
   correctness, not just tidiness: in dev the Play CDN injects its stylesheet at runtime,
   after base.html's inline <style>, so a leftover utility wins at equal specificity and the
   control silently takes the utility's height.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = REPO_ROOT / "app" / "templates"
BASE_HTML = TEMPLATES / "base.html"
THEMES_CSS = REPO_ROOT / "app" / "static" / "themes.css"

# The whole template tree: there is no area where a raw utility beside an `.lt-*` class is
# expected. A `pr-8` beside `.lt-field`, for one, resolves differently in dev and prod.
SCOPED_DIRS = [TEMPLATES]

_CLASS_ATTR = re.compile(r'class="([^"]*)"')
_LT_CLASS = re.compile(r"\blt-[a-z0-9-]+\b")

# Utilities that fight an .lt-* class for the same property. Plain `border` is not listed
# because callers legitimately use `border-t`/`border-b` on unrelated elements.
_CONFLICTING = re.compile(
    r"^(?:"
    r"px-[\d.]+|py-[\d.]+|p-[\d.]+|p[trbl]-[\d.]+|"
    r"text-xs|text-sm|text-base|text-\[\d+px\]|"
    r"rounded|rounded-(?:sm|md|lg|xl|full|none)|"
    r"border|"
    r"h-\d+|h-\[[^\]]+\]|"
    r"inline-flex|items-center|"
    r"gap-[\d.]+"
    r")$"
)

# Border *colour* is owned by .lt-btn and .lt-field, but deliberately NOT by .lt-chip:
# a chip takes its whole palette from `tag_classes()`, which is the only place those
# Tailwind class names exist as literals the scanner can see.
_BORDER_COLOUR = re.compile(r"^border-(?:gray|red|orange|yellow|green|blue|purple|rose|teal|cyan|amber|indigo)-\d+")


def _templates() -> list[Path]:
    out: list[Path] = []
    for root in SCOPED_DIRS:
        out.extend(sorted(root.rglob("*.html")))
    return out


_STYLE_BLOCK = re.compile(r"<style[^>]*>(.*?)</style>", re.S)


def _defined_lt_classes() -> set[str]:
    """Every `.lt-…` selector the browser will actually see a rule for.

    base.html's block and themes.css hold the shared primitives; a template may also carry
    its own `<style>` for classes that are local to it — `_process_tree.html` styles its
    collapsible rows that way, and those are legitimately not shared geometry. Both count,
    because the failure this guards is "the class has no rule anywhere", which renders a
    completely unstyled control and which no route test can see.
    """
    text = BASE_HTML.read_text() + THEMES_CSS.read_text()
    for path in sorted(TEMPLATES.rglob("*.html")):
        text += "".join(_STYLE_BLOCK.findall(path.read_text()))
    return set(re.findall(r"\.(lt-[a-z0-9-]+)", text))


def test_every_lt_class_used_in_a_template_is_defined():
    defined = _defined_lt_classes()
    missing: list[str] = []
    for path in [*_templates(), BASE_HTML]:
        for attr in _CLASS_ATTR.findall(path.read_text()):
            for cls in _LT_CLASS.findall(attr):
                if cls not in defined:
                    missing.append(f"{path.relative_to(REPO_ROOT)}: {cls}")
    assert not missing, "Undefined lt-* classes (a typo here renders a completely unstyled control, and no route test would catch it):\n  " + "\n  ".join(sorted(set(missing)))


def test_lt_controls_do_not_carry_the_utilities_they_replace():
    """A leftover utility wins over the inline <style> under the dev Play CDN."""
    offenders: list[str] = []
    for path in _templates():
        for attr in _CLASS_ATTR.findall(path.read_text()):
            classes = attr.split()
            if not any(c in ("lt-btn", "lt-field", "lt-chip", "lt-copy") for c in classes):
                continue
            clashes = [c for c in classes if _CONFLICTING.match(c)]
            if "lt-chip" not in classes:
                clashes += [c for c in classes if _BORDER_COLOUR.match(c)]
            if clashes:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {' '.join(clashes)}  (in: {attr[:90]})")
    assert not offenders, (
        "These elements mix an lt-* primitive with the sizing utilities it replaces. Delete "
        "the utilities — the primitive owns height, padding, font-size, radius and border:\n  " + "\n  ".join(offenders)
    )


def test_every_lt_var_read_by_base_html_is_defined():
    """A `var(--lt-…)` with no declaration behind it resolves to nothing — an unstyled
    control, which no route test can see.

    It catches a misspelt variable on either side — the reader or the declaration.
    """
    css = THEMES_CSS.read_text()
    used = set(re.findall(r"var\((--lt-[a-z-]+)\)", BASE_HTML.read_text()))
    # `--lt-h`, `--lt-px`, `--lt-fs`, `--lt-radius` are local geometry knobs set by the
    # size modifiers themselves, not themed values.
    themed = {v for v in used if v not in {"--lt-h", "--lt-px", "--lt-fs", "--lt-radius"}}
    assert themed, "expected base.html to read themed --lt-* vars"

    match = re.search(r":root\s*\{([^}]+)\}", css)
    assert match, "no :root declaration block found in themes.css"
    missing = sorted(v for v in themed if f"{v}:" not in match.group(1))
    assert not missing, f"themes.css is missing control vars: {missing}"


def _all_templates() -> list[Path]:
    """Every template.

    Identical to `_templates()` while SCOPED_DIRS is the whole tree. Kept as its own name
    because the `.lt-scroll` guards below mean "everywhere" — collapsing them would quietly
    re-tie that meaning to a
    constant that could narrow again.
    """
    return sorted(TEMPLATES.rglob("*.html"))


def test_every_lt_scroll_class_is_defined_anywhere_in_the_templates():
    """The narrow SCOPED_DIRS typo guard, applied tree-wide to the scroll family only."""
    defined = _defined_lt_classes()
    missing = [
        f"{path.relative_to(REPO_ROOT)}: {cls}"
        for path in _all_templates()
        for attr in _CLASS_ATTR.findall(path.read_text())
        for cls in _LT_CLASS.findall(attr)
        if cls.startswith("lt-scroll") and cls not in defined
    ]
    assert not missing, "Undefined lt-scroll* classes:\n  " + "\n  ".join(sorted(set(missing)))


def test_lt_scroll_never_shares_an_element_with_overflow_hidden():
    """`overflow-hidden` sets BOTH axes, so it and `.lt-scroll` fight over `overflow-y`.

    Which one wins is stylesheet-order dependent — and dev disagrees with prod: the Play
    CDN injects its sheet at runtime, while the built sheet is linked *before* base.html's
    inline <style>. A list that scrolls in `task dev` and silently clips in production is
    exactly the failure to guard against. The fix is always structural: outer
    element carries `rounded-* overflow-hidden`, an inner child carries `.lt-scroll`.
    """
    offenders: list[str] = []
    for path in _all_templates():
        for attr in _CLASS_ATTR.findall(path.read_text()):
            classes = attr.split()
            if "lt-scroll" in classes and "overflow-hidden" in classes:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {attr[:120]}")
    assert not offenders, "These elements carry both `lt-scroll` and `overflow-hidden`. Move the scroll to an inner child:\n  " + "\n  ".join(offenders)


def test_lt_scroll_boxes_do_not_swallow_their_pager():
    """A pager inside the scroll box means scrolling fifty rows to reach "Next".

    Checked structurally rather than by eye: in every partial that has both, the last
    `lt-scroll` element must close before the first pagination control appears.
    """
    offenders: list[str] = []
    for path in _all_templates():
        text = path.read_text()
        if "lt-scroll" not in text or "-partial?page=" not in text:
            continue
        scroll_open = text.index("lt-scroll")
        pager = text.index("-partial?page=")
        # The scroll box opens before the pager; what matters is that the pager is not
        # nested inside it, which for these flat partials means it comes after the
        # matching close. Approximate with the enclosing `{% endfor %}` of the row loop.
        tail = text[scroll_open:pager]
        if "{% endfor %}" not in tail:
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, "Pagination controls appear to sit inside the scroll box in:\n  " + "\n  ".join(offenders)


def test_no_inert_checkbox_styling_in_scoped_templates():
    """`text-blue-600` on a native checkbox needs @tailwindcss/forms, which is not installed."""
    offenders: list[str] = []
    for path in _templates():
        for line in path.read_text().splitlines():
            if 'type="checkbox"' in line and "text-blue-600" in line:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {line.strip()[:100]}")
    assert not offenders, (
        "tailwind.config.js has plugins: [], so there is no @tailwindcss/forms and "
        "`text-blue-600` on a native checkbox styles nothing. Use `lt-check`:\n  " + "\n  ".join(offenders)
    )


#: Control primitives whose text is clipped to the element's box, so the glyph box has to
#: be tall enough to hold a descender. `<input>`/`<select>` clip by definition, and
#: `.lt-combo-pill`'s label span carries `overflow: hidden` for its ellipsis.
_CLIPPING_PRIMITIVES = (".lt-field", ".lt-chip", ".lt-combo", ".lt-combo-input", ".lt-combo-pill")


def test_clipping_controls_do_not_squeeze_their_line_box():
    """`line-height: 1` cuts the tails off g/y/p/q.

    At `line-height: 1` the glyph box is exactly `1em`, but a typical face needs ~1.15em
    for ascender-to-descender — so anything that clips to its box loses the descenders. It
    shows most in the tag field and the tag pill, where the text is 11px and the difference
    is a visibly chopped `g`.

    This does NOT weaken the rule these primitives exist for. Every one of them declares
    `height` (or `min-height`) outright and centres with flex, so line-height cannot shift
    a control — which is exactly why the fix is safe and why the tempting alternative,
    adding vertical padding, is not.
    """
    css = BASE_HTML.read_text()
    offenders: list[str] = []
    for selector in _CLIPPING_PRIMITIVES:
        start = css.find(f"\n    {selector} {{")
        assert start != -1, f"{selector} is not defined in base.html"
        block = css[start : css.index("}", start)]
        if "line-height: 1;" in block:
            offenders.append(selector)
    assert not offenders, "these clip their text, so `line-height: 1` cuts descenders off: " + ", ".join(offenders)


def test_the_condition_field_has_no_hanging_indent():
    """A hanging indent on a multi-line field indents typed newlines too.

    `.lt-cond__hl, .lt-cond__input` carried `text-indent: -1.25rem` against an equal extra
    `padding-left`, so that a soft-wrapped 500-character `cidr:` would sit under its first
    term. CSS indents the first line of the BOX, not the first line after each forced break
    — `text-indent: … each-line` says the latter and is implemented in no engine — so a
    newline the analyst typed was shifted exactly like a wrap the browser chose, and read as
    Enter inserting a tab. A newline is whitespace to both grammars, so laying a long
    condition out one term per line is a supported thing to do and has to look like one.

    Asserted from the outside because nothing else can see it: the server renders the same
    bytes either way, and `tests/js` does not run a layout engine.
    """
    css = BASE_HTML.read_text()
    start = css.find("\n    .lt-cond__hl, .lt-cond__input {")
    assert start != -1, ".lt-cond__hl, .lt-cond__input is not defined in base.html"
    # Comments stripped first: the block explains at length why there is no indent, and the
    # explanation names the property it is warning about.
    block = re.sub(r"/\*.*?\*/", "", css[start : css.index("}", start)], flags=re.S)
    assert "text-indent" not in block, "the condition field indents every line after the first, typed ones included"
    # The two layers must stay metric-identical or the colours slide out from under the
    # glyphs, so a `padding-left` override on the shared selector is not the bug — a
    # *hanging* one is. Guard the shorthand instead: one declaration, both layers.
    assert block.count("padding") == 1, "padding on the condition layers is declared once, as a shorthand"


def test_list_rows_share_one_hover_treatment():
    """`/30` with no transition on the admin tables and `/50 transition` on the analyst
    ones is the kind of difference nobody decides and everybody sees. One rule, stated in
    base.html beside the other conventions."""
    offenders: list[str] = []
    for path in _templates():
        text = path.read_text()
        if "hover:bg-gray-800/30" in text:
            offenders.append(f"{path.relative_to(REPO_ROOT)}: uses the /30 hover")
        for match in re.finditer(r"hover:bg-gray-800/50(?! transition)", text):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: /50 hover with no transition (offset {match.start()})")
    assert not offenders, "list rows must all hover the same way:\n  " + "\n  ".join(offenders)


#: Floating surfaces that are deliberately NOT menus.
#:
#: The graph overlay's panels are docked to the canvas rather than opened over the page, and
#: they carry an explicit `/90`-`/95` alpha — so unlike a menu they do not depend on the
#: theme's panel rules for a background, and cannot inherit the 0.30 that made a dropdown
#: unreadable. `_scroll_top` is a button, which those rules skip anyway.
_NOT_MENUS = ("_graph_panel.html", "_graph_pivots.html", "_graph_help.html", "_graph_legend.html")


def test_every_floating_surface_uses_the_shared_menu_class():
    """Hand-written dropdowns drift — radii, border colours, z-indexes, shadows — so every
    floating surface is `lt-menu`.

    The heuristic is "shadow + a gray background with no alpha of its own", because that is
    exactly the set of floating surfaces taking their background from the theme. An element
    that states its own alpha has opted out and is listed above.
    """
    # Tag-aware: buttons, inputs, selects, textareas and links are controls, not floating
    # surfaces — the "Back to top" button is the case in point.
    shadowed = re.compile(r"<(\w+)[^>]*?class=\"([^\"]*\bshadow-(?:2xl|xl|lg)\b[^\"]*)\"", re.S)
    offenders: list[str] = []
    for path in _templates():
        if path.name in _NOT_MENUS:
            continue
        for tag, attr in shadowed.findall(path.read_text()):
            if tag in ("button", "input", "select", "textarea", "a"):
                continue
            classes = attr.split()
            if "lt-menu" in classes or "lt-help-panel" in classes:
                continue
            # `bg-gray-900/95` states its own alpha; `bg-gray-900` inherits the theme's.
            if any(c in ("bg-gray-800", "bg-gray-900") for c in classes):
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {attr[:100]}")
    assert not offenders, (
        "a floating surface whose background comes from the theme must be `lt-menu`, or it "
        "inherits a panel's translucency and becomes unreadable over one:\n  " + "\n  ".join(offenders)
    )


def test_a_menu_takes_its_background_from_one_place():
    """`--lt-menu-bg`, not whichever `bg-gray-*` a call site reached for. That is what made
    two dropdowns look different from each other.

    Nothing creates a stacking context around a card, so a menu's own z-index competes
    globally and the card hosting it needs no raising.
    """
    assert "--lt-menu-bg" in THEMES_CSS.read_text(), "the menu background is not defined"
    assert "background-color: var(--lt-menu-bg)" in BASE_HTML.read_text()


# ── The count pill ────────────────────────────────────────────────────────────

#: The pill's five palettes live in one macro file. Everything else that wants one imports
#: it, on the `_severity_macros.html` rule.
_COUNT_PILL_MACRO = TEMPLATES / "partials" / "_count_pill.html"

#: A `rounded-full` span carrying a `bg-<colour>-900/<alpha>` fill and a matching border —
#: the recipe `_count_pill.html` owns.
_HANDWRITTEN_PILL = re.compile(r'class="[^"]*\bbg-(?:gray|green|blue|yellow|red)-900/\d+[^"]*\brounded-full\b[^"]*"')


def test_the_count_pill_recipe_lives_in_one_macro():
    """A palette written out at the call site is a palette that drifts at the call site.

    The severity map follows the same rule. The
    macro renders `.lt-chip` for the geometry and a literal Tailwind triple for the colour,
    which is also what keeps the class names visible to the production CSS scanner.
    """
    offenders = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        if path == _COUNT_PILL_MACRO:
            continue
        for match in _HANDWRITTEN_PILL.finditer(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: {match.group(0)[:90]}")
    assert not offenders, "hand-written count pill — import count_pill from partials/_count_pill.html instead:\n" + "\n".join(offenders)


def test_every_admin_page_header_that_can_show_a_count_does():
    """The pills are a navigation aid, and one page silently missing its own is the state
    that made the Manage grid look inconsistent in the first place.

    Settings is the deliberate exception: there is no count on it that means anything.
    """
    expected = {
        "admin/users.html",
        "admin/tasks.html",
        "admin/activity.html",
        "admin/storage.html",
        "admin/ai.html",
        "admin/enrichment.html",
        "admin/api_tokens.html",
        "admin/workers.html",
        "workflows/list.html",
    }
    missing = [name for name in sorted(expected) if "pills=" not in (TEMPLATES / name).read_text(encoding="utf-8")]
    assert not missing, f"page_header without a count pill: {missing}"


# ── Tailwind class names must be literals ─────────────────────────────────────

#: A colour utility whose shade arrives from a Jinja interpolation.
_ASSEMBLED_UTILITY = re.compile(r"\b(?:bg|text|border|ring|from|via|to|fill|stroke|shadow|decoration|outline|accent|caret|divide|placeholder)-\{\{")
#: Jinja comments — several templates quote the broken form while explaining why not to.
_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)


def test_no_template_assembles_a_tailwind_class_name():
    """`bg-{{ color }}-900/40` cannot work in a production CSS build.

    `task css:build` scans these files for *complete* class names; an interpolated one is
    never there to find, so the element ships with no styling. Dev does not show it — the
    Play CDN generates from the live DOM — so this reaches a deployment intact, and it
    presents as "some of them look wrong", which reads like a data problem.

    Coverage is accidental: a shade that happens to be written out literally elsewhere still
    works, which is exactly what makes the failure look arbitrary.

    The answer is always a literal lookup
    (`_tag_chip.html::tag_classes`, `_entity_type_badge.html::type_badge_classes`,
    `_count_pill.html::pill_tone`).
    """
    offenders = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        body = _JINJA_COMMENT.sub("", path.read_text(encoding="utf-8"))
        for line_no, line in enumerate(body.splitlines(), 1):
            for attr in _CLASS_ATTR.finditer(line):
                if _ASSEMBLED_UTILITY.search(attr.group(1)):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{line_no}")
    assert not offenders, "Tailwind class names must appear as literals the production build can scan — use a lookup like _tag_chip.html::tag_classes: " + ", ".join(offenders)


# ── The copy button ───────────────────────────────────────────────────────────


COPY_MACRO = TEMPLATES / "partials" / "_copy_button.html"


def test_every_copy_button_comes_from_the_one_macro():
    """A hand-rolled copy button is a broken one.

    Each copy carries its own `x-data="{ copied: false }"`, its own `$refs` lookup, its own
    inline SVGs — and its own direct `navigator.clipboard.writeText(…)`, which is
    `undefined` on any page served over plain HTTP. One recipe copied N times is how N
    buttons come to share one bug; the same argument as `count_pill`, `pager` and
    `help_popover`.
    """
    offenders = []
    for path in _all_templates():
        if path == COPY_MACRO:
            continue
        body = path.read_text(encoding="utf-8")
        for marker in ("logstotal-copy-btn", "logstotal-copy-icon-"):
            if marker in body:
                offenders.append(f"{path.relative_to(REPO_ROOT)} ({marker})")
    assert not offenders, "hand-written copy button — import copy_button from partials/_copy_button.html instead: " + ", ".join(sorted(offenders))


def test_every_copy_button_names_a_source():
    """A `copy_button()` with neither `target=` nor `source=` renders perfectly and copies
    nothing: app.js resolves no element and returns before it ever reaches the clipboard.

    Exactly the failure mode `TestTabIcons` guards for an unknown glyph name — silent, and
    invisible to a route test, because the button is still there and still 200s.
    """
    call = re.compile(r"copy_button\(([^)]*)\)", re.S)
    offenders = []
    for path in _all_templates():
        if path == COPY_MACRO:
            continue
        for match in call.finditer(path.read_text(encoding="utf-8")):
            args = match.group(1)
            if "target=" not in args and "source=" not in args:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: copy_button({args.strip()[:60]})")
    assert not offenders, "copy_button() with nothing to copy: " + ", ".join(offenders)


# ── A button never fires on an empty required field ─────────────────────────
#
# Every ordinary text field in the app carries `required`, so the browser refuses the
# submit and no request is made. Two shapes are outside what `required` can express, and
# without a gate both post and are refused with a 400:
#
#   * a `tagCombobox` posts its value through a **hidden** input, and hidden inputs are
#     barred from constraint validation by spec — `required` there can never fire;
#   * "at least one of this checkbox group" has no native spelling at all.
#
# The gate is `:disabled` on the submit, the `_jobs_bulk_actions.html` idiom — and these
# guards are here because the failure is invisible from the server: the page
# renders identically either way, and the 400 it provokes is a swap htmx declines, i.e. a
# click that looks like nothing happened.


class _SubmitScopes(HTMLParser):
    """Collect every `<button type="submit">` with the nearest enclosing `<form>`'s x-data.

    Scoping to the *form* is what makes the rule precise with no exemption list. The tag
    manager's colour swatches are submits too, and they always carry a colour — they sit in
    their own recolour form, which has no `x-data`. The rule form's Save is a submit whose
    combobox is optional (a rule may alert without tagging), and its `tagCombobox` is on an
    inner `<div>`, so the enclosing form is not a combobox form either.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        #: `(enclosing form's attributes, the button's attributes)` per submit.
        self.submits: list[tuple[dict, dict]] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self.forms.append(a)
        elif tag == "button" and a.get("type") == "submit":
            self.submits.append((self.forms[-1] if self.forms else {}, a))

    def handle_endtag(self, tag):
        if tag == "form" and self.forms:
            self.forms.pop()


#: Jinja comments are stripped before parsing, and that is not tidiness. Two of these
#: partials explain themselves with the words "not an inline <script>" inside a `{# #}`
#: block; HTMLParser does not know Jinja, sees `<script>`, switches to CDATA mode and
#: swallows the rest of the file — so the guard found nothing there and passed. The
#: `seen >= 9` floor below is what catches that class of silence.
_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.DOTALL)


def _submits(path: Path) -> list[tuple[dict, dict]]:
    parser = _SubmitScopes()
    parser.feed(_JINJA_COMMENT.sub("", path.read_text()))
    return parser.submits


def _submits_in_combobox_forms(path: Path) -> list[dict]:
    return [button for form, button in _submits(path) if "tagCombobox(" in form.get("x-data", "")]


def test_a_tag_write_button_is_dead_until_the_field_has_something_in_it():
    offenders = []
    seen = 0
    for path in _all_templates():
        for attrs in _submits_in_combobox_forms(path):
            seen += 1
            if attrs.get(":disabled") != "isEmpty()":
                offenders.append(f"{path.relative_to(TEMPLATES)}: {attrs.get('class', '?')}")
    assert seen >= 9, f"the parser stopped finding the tag-write submits (found {seen}) — check the form nesting"
    assert not offenders, "these submit with an empty tag field and get a 400 back:\n  " + "\n  ".join(offenders)


def test_isEmpty_is_the_one_spelling_of_that_gate():
    """`:disabled="!values.length"` would look right and be wrong: `sync()` posts a
    half-typed name too, so a gate on the pills alone dims a button over a field the
    reader can see they filled in. One predicate, defined beside `sync()`."""
    offenders = [str(p.relative_to(TEMPLATES)) for p in _all_templates() if re.search(r':disabled="!?\s*(values|query)\b', p.read_text())]
    assert not offenders, f"these gate a tag field on its internals instead of isEmpty(): {offenders}"


#: `template: (checkbox group, how many submits must wait for it)`. Named rather than
#: discovered: "this group is required" is not expressible in the markup, which is the whole
#: reason the guard exists. Enrichment has two — the create form and the per-service edit.
_REQUIRED_CHECKBOX_GROUPS = {
    "admin/api_tokens.html": ("scopes", 1),
    "admin/enrichment.html": ("entity_types", 2),
}


def test_a_form_needing_one_ticked_box_waits_for_one():
    """Asserted through the parser, not by grepping the file.

    A substring check passes on markup where the submit is not in that form at all — which
    is precisely the state the unterminated `<form>` tag left these pages in, and what
    `test_no_start_tag_swallows_the_element_after_it` exists to catch from the other side.
    """
    for rel, (group, expected) in _REQUIRED_CHECKBOX_GROUPS.items():
        counted = [(form, button) for form, button in _submits(TEMPLATES / rel) if f"input[name={group}]:checked" in form.get("@change", "")]
        assert len(counted) == expected, f"{rel}: {len(counted)} submits sit in a form counting its {group} boxes, expected {expected}"
        for form, button in counted:
            assert "chosen" in form.get("x-data", ""), f"{rel}: the form counts {group} into no declared state"
            assert button.get(":disabled") == "!chosen", f"{rel}: {button.get('class', '?')} still submits with no {group} ticked"


def test_no_start_tag_swallows_the_element_after_it():
    """An unterminated start tag is invisible to every other kind of test.

    Adding an attribute to a multi-line `<form …>` and dropping its closing `>` leaves the
    next element's tag name and attributes parsed as attributes of the form — Jinja renders
    it happily, a route test gets its 200, and the page is quietly wrong. Adding three
    `x-data` counters to the admin forms did exactly this.

    The tell is an attribute whose name starts with `<`, which is unambiguous: no valid
    attribute can.
    """

    class _Unterminated(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.bad: list[str] = []

        def handle_starttag(self, tag, attrs):
            for name, _value in attrs:
                if name.startswith("<"):
                    self.bad.append(f"<{tag}> swallowed {name}")

    offenders = []
    for path in _all_templates():
        parser = _Unterminated()
        parser.feed(_JINJA_COMMENT.sub("", path.read_text()))
        offenders += [f"{path.relative_to(TEMPLATES)}: {b}" for b in parser.bad]
    assert not offenders, "unterminated start tags:\n  " + "\n  ".join(offenders)


def test_a_box_that_filters_as_you_type_keeps_focus_across_the_swap():
    """htmx restores focus and the caret after a swap only to an element with the same `id`.
    The case Entities search box sits inside the region its own keyup re-renders and had
    none, so after the first 300 ms pause the box was replaced, focus fell to `<body>`, and
    every keystroke after that went nowhere. `#tagmgr-q` is the working counterpart."""
    trigger = re.compile(r"<form\b[^>]*hx-trigger=\"[^\"]*keyup[^\"]*from:find input\[name='([^']+)'\][^\"]*\"[^>]*>(.*?)</form>", re.S)
    seen = 0
    for path in _all_templates():
        for name, body in trigger.findall(path.read_text()):
            box = re.search(rf"<input\b[^>]*\bname=\"{re.escape(name)}\"[^>]*>", body)
            assert box, f"{path.name}: the trigger names input[name='{name}'] and the form has none"
            assert re.search(r"\sid=\"[^\"]+\"", box.group(0)), f"{path.name}: {box.group(0)}"
            seen += 1
    assert seen >= 2, "the guard matched no filter forms — its pattern has gone stale"
