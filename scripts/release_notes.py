#!/usr/bin/env python3
"""Print one version's CHANGELOG section as release notes, with the hard wrap undone.

    python3 scripts/release_notes.py 1.4.0 [CHANGELOG.md] > release-notes.md

CHANGELOG.md is wrapped at ~95 columns, like every other file here. GitHub and Forgejo
render a release body with each newline as a line break, so the wrapped source broke every
sentence of the release page mid-line. Each paragraph and list item is joined back onto one
line; headings, nested list items, tables, quotes, link definitions and fenced code keep
their lines. Exits 1, printing nothing, when the version has no section or an empty one —
both release workflows refuse to publish an empty body.

Stdlib only: it runs on the release runners before any dependency is installed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_HEADING = re.compile(r"^#{1,6}\s")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_FENCE = re.compile(r"^\s*(?:```|~~~)")
# Lines that always begin a block of their own and are never joined onto, or into.
_OWN_LINE = re.compile(r"^\s*(?:\||>|<!--|\[[^\]]+\]:\s)")
# The compare links at the foot of the file belong to the whole changelog, not to the
# oldest section, which they would otherwise trail.
_COMPARE_LINK = re.compile(r"^\[(?:Unreleased|\d+\.\d+\.\d+)\]:\s")


def section(text: str, version: str) -> list[str] | None:
    """The lines under `## [version]`, up to the next `## [` heading or the compare links."""
    start = re.compile(rf"^## \[{re.escape(version)}\]")
    lines: list[str] | None = None
    for line in text.splitlines():
        if lines is None:
            if start.match(line):
                lines = []
        elif line.startswith("## [") or _COMPARE_LINK.match(line):
            break
        else:
            lines.append(line)
    return lines


def _hard_break(raw: str) -> bool:
    """Markdown's explicit line break: two trailing spaces or a trailing backslash."""
    return raw.endswith(("  ", "\\"))


def _trim(raw: str) -> str:
    """Trailing whitespace off, unless it is the two-space hard break."""
    return raw.rstrip() + "  " if raw.endswith("  ") and raw.strip() else raw.rstrip()


def unwrap(lines: list[str]) -> list[str]:
    """Join each paragraph's and list item's continuation lines onto the line they continue."""
    out: list[str] = []
    in_fence = False
    joinable = False  # may the next plain line continue out[-1]?
    prev_raw = ""
    for raw in lines:
        if _FENCE.match(raw):
            in_fence = not in_fence
            out.append(raw.rstrip())
            joinable = False
        elif in_fence:
            out.append(raw)
        elif not raw.strip():
            out.append("")
            joinable = False
        elif _HEADING.match(raw) or _OWN_LINE.match(raw):
            out.append(raw.rstrip())
            joinable = False
        elif _LIST_ITEM.match(raw):
            out.append(_trim(raw))
            joinable = True
        elif joinable and not _hard_break(prev_raw):
            out[-1] = f"{out[-1]} {_trim(raw).lstrip()}"
        else:
            out.append(_trim(raw))
            joinable = True
        prev_raw = raw
    while out and not out[0]:
        out.pop(0)
    while out and not out[-1]:
        out.pop()
    return out


def release_notes(text: str, version: str) -> str | None:
    lines = section(text, version)
    if lines is None:
        return None
    body = unwrap(lines)
    return "\n".join(body) + "\n" if body else None


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print("usage: release_notes.py VERSION [CHANGELOG.md]", file=sys.stderr)
        return 2
    version = argv[1].removeprefix("v")
    path = Path(argv[2] if len(argv) == 3 else "CHANGELOG.md")
    notes = release_notes(path.read_text(encoding="utf-8"), version)
    if notes is None:
        print(f"no '## [{version}]' section with any content in {path}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
