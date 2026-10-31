"""duckdb stays out of the Huey process and out of every module that is not an engine.

The worker runs the store builder (and, later, the overlay) as subprocesses so it can kill a
whole process group on timeout, cancel or memory use, and so the engine's memory is never
inside the long-lived Huey process. The web tier imports it lazily, in the engine alone.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "app"
#: The only modules allowed to import duckdb.
ENGINES = {"app/events/build.py", "app/events/overlay.py", "app/events/engine.py"}
#: Subprocess entrypoints: nothing in the worker may import them, it runs them.
SUBPROCESS_ONLY = {"app.events.build", "app.events.overlay"}


def _imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_only_the_engines_import_duckdb():
    offenders = [str(p.relative_to(ROOT.parent)) for p in ROOT.rglob("*.py") if any(m == "duckdb" or m.startswith("duckdb.") for m in _imports(p))]
    assert set(offenders) <= ENGINES, offenders


def test_the_worker_never_imports_a_subprocess_entrypoint():
    worker_side = [ROOT / "workers" / "tasks.py", ROOT / "workers" / "huey_app.py", *(ROOT / "events").glob("*.py")]
    for path in worker_side:
        rel = str(path.relative_to(ROOT.parent))
        if rel in ENGINES:
            continue
        assert not (_imports(path) & SUBPROCESS_ONLY), f"{rel} imports a subprocess entrypoint"
