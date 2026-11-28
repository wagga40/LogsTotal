"""A `bool` form parameter defaults to False — an unticked checkbox posts nothing.

FastAPI 0.162 stopped inferring `False` for an omitted boolean form field: an absent
field now takes the parameter's declared default, like every other field. For a
`bool = Form(False)` that is the same answer as before. For a `bool = Form(True)` it is the
opposite one: the box could no longer be switched off, because unticking it posts nothing
and nothing means True.

The routes that need a default of "on" for scripted callers use `int = Form(1)` with a
hidden `value="0"` in front of the checkbox (tests/test_checkbox_fallbacks.py). This guard
keeps the `bool` spelling to the one default that cannot invert.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROUTERS = Path(__file__).resolve().parents[1] / "app" / "routers"


def _is_bool(annotation: ast.expr | None) -> bool:
    if annotation is None:
        return False
    text = ast.unparse(annotation).replace(" ", "")
    return text in {"bool", "bool|None", "Optional[bool]", "None|bool"}


def _form_default(default: ast.expr | None) -> ast.expr | None:
    if isinstance(default, ast.Call) and getattr(default.func, "id", None) == "Form":
        return default.args[0] if default.args else next((k.value for k in default.keywords if k.arg == "default"), None)
    return None


def test_every_boolean_form_parameter_defaults_to_false():
    offenders, seen = [], 0
    for path in sorted(ROUTERS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            args = fn.args.args + fn.args.kwonlyargs
            defaults = [None] * (len(fn.args.args) - len(fn.args.defaults)) + list(fn.args.defaults) + list(fn.args.kw_defaults)
            for arg, default in zip(args, defaults, strict=True):
                if not _is_bool(arg.annotation) or not (isinstance(default, ast.Call) and getattr(default.func, "id", None) == "Form"):
                    continue
                seen += 1
                value = _form_default(default)
                if not (isinstance(value, ast.Constant) and value.value is False):
                    offenders.append(f"{path.name}:{arg.lineno} {fn.name}({arg.arg}={ast.unparse(default)})")
    assert seen >= 15, f"found only {seen} boolean Form parameters — the walk stopped seeing them"
    assert not offenders, "a bool Form default other than False cannot be switched off by an unticked box:\n" + "\n".join(offenders)
