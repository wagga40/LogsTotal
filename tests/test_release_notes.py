"""scripts/release_notes.py: one CHANGELOG section, unwrapped for a release page.

GitHub and Forgejo render each newline of a release body as a line break, so the
changelog's ~95-column wrap broke every sentence of the 1.4.0 release page mid-line.
"""

from __future__ import annotations

import itertools
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_notes  # noqa: E402

CHANGELOG = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

SAMPLE = """\
# Changelog

## [Unreleased]

## [2.0.0] — 2027-01-01

### Updated

- A list item that the changelog
  wraps across two lines.
- A single-line item.
  - A nested item
    with its own continuation.

A paragraph that also
wraps, then ends.

A hard break stays\\
where it was, and so does<SP><SP>
the two-space kind.

```sh
./logstotal upgrade
  --keep-this-indent
```

| a | b |
|---|---|

[link]: https://example.org

## [1.9.0] — 2026-12-01

- Not part of 2.0.0.
""".replace("<SP>", " ")  # a two-space hard break, spelled so no editor trims it


def notes(text: str = SAMPLE, version: str = "2.0.0") -> list[str]:
    out = release_notes.release_notes(text, version)
    assert out is not None
    return out.splitlines()


def test_a_wrapped_list_item_becomes_one_line():
    assert "- A list item that the changelog wraps across two lines." in notes()


def test_a_wrapped_paragraph_becomes_one_line():
    assert "A paragraph that also wraps, then ends." in notes()


def test_a_nested_item_keeps_its_own_line_and_indent():
    lines = notes()
    assert "- A single-line item." in lines
    assert "  - A nested item with its own continuation." in lines


def test_headings_blank_lines_and_block_boundaries_survive():
    lines = notes()
    assert lines[0] == "### Updated"
    assert lines[1] == ""
    assert "| a | b |" in lines and "|---|---|" in lines
    assert "[link]: https://example.org" in lines


def test_fenced_code_is_left_exactly_as_written():
    lines = notes()
    i = lines.index("```sh")
    assert lines[i : i + 4] == ["```sh", "./logstotal upgrade", "  --keep-this-indent", "```"]


def test_an_explicit_hard_break_is_not_joined_and_keeps_its_marker():
    lines = notes()
    assert "A hard break stays\\" in lines
    assert "where it was, and so does  " in lines
    assert "the two-space kind." in lines


def test_the_oldest_section_stops_at_the_compare_links():
    text = "## [1.0.0] — 2026-09-27\n\n- First.\n\n[Unreleased]: https://x/compare/v1.0.0...HEAD\n[1.0.0]: https://x/v1.0.0\n"
    assert release_notes.release_notes(text, "1.0.0") == "- First.\n"


def test_only_the_named_section_is_printed():
    text = "\n".join(notes())
    assert "Not part of 2.0.0" not in text
    assert "Unreleased" not in text


def test_a_missing_or_empty_section_is_none():
    assert release_notes.release_notes(SAMPLE, "3.0.0") is None
    assert release_notes.release_notes("## [1.0.0]\n\n## [0.9.0]\n- x\n", "1.0.0") is None


@pytest.mark.parametrize("version", re.findall(r"^## \[(\d+\.\d+\.\d+)\]", CHANGELOG, re.M))
def test_every_released_section_unwraps_without_losing_a_word(version):
    raw = release_notes.section(CHANGELOG, version)
    body = release_notes.release_notes(CHANGELOG, version)
    assert raw is not None and body is not None
    assert " ".join(" ".join(raw).split()) == " ".join(body.split())
    # No line of a paragraph or list item is left ending where the 95-column wrap put it.
    lines = body.splitlines()
    for line, following in itertools.pairwise(lines):
        if line and following:
            assert following.startswith(("#", "-", "  -")), f"{version}: {following!r} still continues {line!r}"


def test_the_command_line_exits_nonzero_and_prints_nothing_for_an_unknown_version(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(SAMPLE, encoding="utf-8")
    script = REPO_ROOT / "scripts" / "release_notes.py"
    ok = subprocess.run([sys.executable, "-I", str(script), "v2.0.0", str(changelog)], capture_output=True, text=True, check=False)
    assert ok.returncode == 0 and ok.stdout.startswith("### Updated\n")
    bad = subprocess.run([sys.executable, "-I", str(script), "3.0.0", str(changelog)], capture_output=True, text=True, check=False)
    assert bad.returncode == 1 and bad.stdout == "" and "3.0.0" in bad.stderr


@pytest.mark.parametrize("workflow", [".github/workflows/release.yml", ".forgejo/workflows/release.yml"])
def test_both_release_workflows_publish_the_unwrapped_notes(workflow):
    text = (REPO_ROOT / workflow).read_text(encoding="utf-8")
    assert re.search(r"python3 (-I )?scripts/release_notes\.py \"\$version\" > release-notes\.md", text), workflow
    assert "CHANGELOG.md > release-notes.md" not in text, f"{workflow} still extracts the wrapped section with awk"
