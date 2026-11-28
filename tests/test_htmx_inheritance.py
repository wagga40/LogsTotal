"""No request may depend on an htmx attribute it used to inherit.

htmx 2 let every hx-* attribute flow down to descendants; htmx 4 inherits only what is
written `attr:inherited`. A descendant that issued a request and relied on its parent's
`hx-target` or `hx-swap` keeps working — it just does something else: the Untag buttons in
both bulk bars would have swapped the response into themselves, and the rule form's live
preview turned out to have been inheriting the form's `outerHTML`, which replaced its own
target on the first keystroke so every later preview had nowhere to land.

The rule: for each element that issues a request, every one of the attributes htmx 2 would
have handed it must be on the element itself, or on an ancestor that says `:inherited`.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "templates"
VERBS = {"hx-get", "hx-post", "hx-put", "hx-patch", "hx-delete"}
# The attributes htmx 2 inherited that change where a response goes or what is sent.
INHERITED = ("hx-target", "hx-swap", "hx-include", "hx-sync", "hx-confirm", "hx-vals", "hx-headers", "hx-encoding", "hx-select")
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


def _strip_jinja(text: str) -> str:
    """Drop Jinja, keeping every newline so the reported line numbers are the file's."""

    def keep_lines(replacement: str):
        return lambda m: replacement + "\n" * m.group(0).count("\n")

    text = re.sub(r"\{#.*?#\}", keep_lines(""), text, flags=re.S)
    text = re.sub(r"\{%.*?%\}", keep_lines(""), text, flags=re.S)
    return re.sub(r"\{\{.*?\}\}", keep_lines("x"), text, flags=re.S)


class _Walker(HTMLParser):
    def __init__(self, path: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.path = path
        self.stack: list[tuple[str, dict]] = []
        self.offenders: list[str] = []
        self.requests = 0

    def handle_starttag(self, tag, attrs):
        names = {k for k, _ in attrs}
        if names & VERBS:
            self.requests += 1
            for attr in INHERITED:
                if attr in names:
                    continue
                for _ptag, pnames in reversed(self.stack):
                    if f"{attr}:inherited" in pnames:
                        break
                    if attr in pnames:
                        line = self.getpos()[0]
                        self.offenders.append(f"{self.path.relative_to(TEMPLATES)}:{line} <{tag}> relied on an ancestor's {attr}")
                        break
        if tag not in VOID:
            self.stack.append((tag, names))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break


def test_no_request_depends_on_an_attribute_it_no_longer_inherits():
    offenders, requests = [], 0
    for path in sorted(TEMPLATES.rglob("*.html")):
        walker = _Walker(path)
        walker.feed(_strip_jinja(path.read_text(encoding="utf-8")))
        offenders += walker.offenders
        requests += walker.requests
    assert requests > 100, f"only {requests} request-issuing elements seen — the walk stopped parsing the templates"
    assert not offenders, "htmx 4 does not inherit these; declare them on the element or mark the ancestor's `:inherited`:\n" + "\n".join(offenders)
