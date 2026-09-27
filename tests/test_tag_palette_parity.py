"""The analyst tag palette is defined once in Python and once in Tailwind classes.

`app/constants.py::TAG_COLORS` is the **validation** list: a colour absent from it is
silently downgraded to `"gray"` on every write path. `templates/intel/partials/_tag_chip.html`
holds the **rendering** map, spelled out class by class because a Tailwind class assembled
at runtime (`bg-{{ color }}-900/30`) is invisible to the scanner and renders unstyled in a
production CSS build.

Two definitions is one more than ideal and unavoidable — but they must agree. The failure
is quiet in both directions: a colour in Python but not the
template renders as an unstyled chip; a colour in the template but not Python is offered in
the swatch row and rejected on save.

Copied into each router (`intel.py`, `intel_rules.py`, `intel_tags.py`), the Python half
would also let a colour be accepted by one editor and refused by another.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.constants import TAG_COLORS

REPO_ROOT = Path(__file__).parent.parent
CHIP_TEMPLATE = REPO_ROOT / "app" / "templates" / "intel" / "partials" / "_tag_chip.html"


def _palette_keys(block_name: str) -> set[str]:
    """Keys of one dict literal in the chip template (`_tag_palette` or `_tag_dots`)."""
    text = CHIP_TEMPLATE.read_text(encoding="utf-8")
    match = re.search(rf"{block_name}\s*=\s*\{{(.*?)\}}", text, re.S)
    assert match, f"{block_name} not found in {CHIP_TEMPLATE.name}"
    return set(re.findall(r"'([a-z]+)'\s*:", match.group(1)))


def test_the_chip_palette_covers_every_validated_colour():
    missing = set(TAG_COLORS) - _palette_keys("_tag_palette")
    assert not missing, f"constants.TAG_COLORS offers colours the chip template cannot style: {sorted(missing)}. They save successfully and render unstyled."


def test_the_dot_palette_covers_every_validated_colour():
    missing = set(TAG_COLORS) - _palette_keys("_tag_dots")
    assert not missing, f"constants.TAG_COLORS offers colours with no swatch dot: {sorted(missing)}"


def test_the_template_offers_no_colour_the_validators_reject():
    extra = _palette_keys("_tag_palette") - set(TAG_COLORS)
    assert not extra, f"the chip template styles colours that constants.TAG_COLORS rejects: {sorted(extra)}. They appear in the swatch row and silently save as gray."


def test_the_palette_is_defined_exactly_once_in_python():
    """One tuple, not a validator copy per router."""
    offenders = []
    for path in sorted((REPO_ROOT / "app").rglob("*.py")):
        if path.name == "constants.py":
            continue
        if re.search(r"^TAG_COLORS\s*[:=]", path.read_text(encoding="utf-8"), re.M):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, (
        f"TAG_COLORS is redefined outside app/constants.py: {offenders}. Import it — three validators that must agree is how a colour ends up accepted by one editor and refused by another."
    )
