"""Structural guard: no router loses or duplicates a definition.

`app/routers/intel.py` is ~2000 lines, and editing it by slicing between two anchors is
easy to get wrong: a slice taken from one route to another silently swallows every
definition that happens to sit between them. That happened three times while this router
was being extended — once removing `tags.json` and the saved-search routes, once the whole
watch-rules section — and each time the module still imported cleanly, so only an unrelated
test caught it.

These assertions are cheap and catch that class of damage immediately:

* a duplicated definition means an edit was applied twice (the later one silently wins);
* a duplicated route path means two handlers race for the same URL (registration order
  decides, which is not something anyone reasons about);
Undefined *names* left behind by such a slice are deliberately not checked here — ruff's
F821 already does that with real scope analysis, and it runs in `task check`. A hand-rolled
version flags every function parameter as undefined.
"""

from __future__ import annotations

import ast
import collections
from pathlib import Path

import pytest

ROUTERS = sorted((Path(__file__).resolve().parent.parent / "app" / "routers").glob("*.py"))


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text())


def _defs(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


@pytest.mark.parametrize("path", ROUTERS, ids=lambda p: p.name)
def test_no_duplicate_top_level_definitions(path):
    names = collections.Counter(n.name for n in _defs(_tree(path)))
    dupes = {n: c for n, c in names.items() if c > 1}
    assert not dupes, f"{path.name}: duplicate definitions {dupes} — an edit was applied twice"


@pytest.mark.parametrize("path", ROUTERS, ids=lambda p: p.name)
def test_no_duplicate_route_paths(path):
    routes = collections.Counter()
    for node in _defs(_tree(path)):
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.args:
                arg = dec.args[0]
                if isinstance(arg, ast.Constant) and dec.func.attr in {"get", "post", "put", "patch", "delete"}:
                    routes[(dec.func.attr, arg.value)] += 1
    dupes = {k: v for k, v in routes.items() if v > 1}
    assert not dupes, f"{path.name}: two handlers registered for {dupes} — registration order decides the winner"
