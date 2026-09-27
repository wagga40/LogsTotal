"""The file-drop parser and `normalize_values` must agree.

`tests/js/list-values-drop.test.mjs` runs these same cases through the JavaScript. They are
written out twice on purpose: the drop zone reports "68 new, 4 already here" *before* the
analyst chooses Replace or Add, and that count is computed on the client. A client that
split, trimmed, lowercased or deduped differently from the server would be quietly lying
about what is about to happen — and the save would then do something else.

There is no upload route. A dropped file is written into the `values` textarea the form
already posts, so the save path, its validation and its activity row are untouched, and
there is no second way to write a list to keep in step with the first.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.intel.rule_lists import normalize_values

#: Exactly the table in the JS test, in the same order.
CASES = [
    ("a\nb\nc", ["a", "b", "c"]),
    ("a,b,c", ["a", "b", "c"]),
    ("A\nB", ["a", "b"]),
    ("  a  \n\tb\t", ["a", "b"]),
    ("a\n\n\nb", ["a", "b"]),
    ("a\nb\na", ["a", "b"]),
    ("b\na", ["b", "a"]),
    ("", []),
    ("a\r\nb", ["a", "b"]),
]


@pytest.mark.parametrize(("raw", "expected"), CASES)
def test_the_server_parses_what_the_client_previewed(raw, expected):
    assert list(normalize_values(raw)) == expected


def test_the_client_parser_is_the_only_one_in_the_javascript():
    """One `normalize` in `listValuesDrop`, used by the preview, the diff and the write.

    Three passes that each split the text their own way is how the count and the saved list
    come to disagree — and the disagreement is invisible, because both look reasonable.
    """
    src = Path("app/static/app.js").read_text()
    factory = src[src.index("function listValuesDrop(") :]
    factory = factory[: factory.index("window.listValuesDrop")]
    assert factory.count("split(/[\\n,]/)") == 1, "the value split must happen in exactly one place"


def test_the_two_parsers_split_on_the_same_characters():
    """Pinned against the Python regex rather than restated, so widening one is caught."""
    server = re.search(r're\.split\(r"\[([^"]+)\]"', Path("app/intel/rule_lists.py").read_text())
    assert server, "normalize_values no longer splits with a character class — check the client"
    client = re.search(r"split\(/\[([^\]]+)\]/\)", Path("app/static/app.js").read_text())
    assert client, "listValuesDrop no longer splits with a character class"
    assert server.group(1) == client.group(1)
