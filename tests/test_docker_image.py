"""The interpreter the image ships, and the one thing that breaks quietly when it moves.

`Dockerfile` names a Python version in exactly one place — every later stage derives from
`deps` — and that version is the one an operator actually runs. Nothing else in the tree
declares it: `requires-python` gives a floor, the CI matrix gives a tested set, and neither
is the shipped runtime. These tests keep those three from disagreeing.

The second half is the expensive lesson from the 3.12 → 3.14 bump. `python:3.14-slim`
records `CXX = gcc` in its sysconfig where 3.12-slim recorded `g++`, so a C++ extension
built from an sdist links without libstdc++ and raises `ImportError: undefined symbol:
__gxx_personality_v0` on import. `py-tlsh` is that extension here, it publishes no wheels,
and `app/similarity/hasher.py` catches ImportError at both call sites on purpose — so the
image built, booted, reported healthy and simply never computed a similarity hash again,
with 4,219 tests green because the host compiles it correctly. A build-time import is what
turns that into a failed build.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")


def _base_python() -> tuple[int, int]:
    """The (major, minor) the image is built on."""
    match = re.search(r"^FROM python:(\d+)\.(\d+)-slim AS deps$", DOCKERFILE, re.MULTILINE)
    assert match, "the Dockerfile no longer opens with a pinned python:X.Y-slim deps stage"
    return int(match.group(1)), int(match.group(2))


def _deps_stage() -> str:
    """The stage that installs requirements.txt, where the compiler decision lives."""
    return DOCKERFILE.split("AS deps", 1)[1].split("\nFROM ", 1)[0]


def test_the_image_python_is_one_ci_actually_tests():
    """A base image bump that CI never runs is a bump nothing verified.

    The matrix is allowed to be wider than the image — it carries the `requires-python`
    floor for Path A operators on a distro interpreter — but it may never be narrower on
    the one version that ships.
    """
    workflow = yaml.safe_load((REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    tested = set(workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"])
    major, minor = _base_python()
    assert f"{major}.{minor}" in tested, f"the image runs {major}.{minor}; CI tests {sorted(tested)}"


def test_the_image_python_satisfies_the_declared_floor():
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requires = pyproject["project"]["requires-python"]
    floor = tuple(int(part) for part in re.search(r">=\s*(\d+)\.(\d+)", requires).groups())
    assert _base_python() >= floor, f"the image is older than {requires}"


def test_only_one_stage_names_an_interpreter():
    """Every other stage is `FROM deps` or `FROM <stage>`, so the version is stated once.

    A second `FROM python:` is how a runtime stage comes to run a different interpreter
    from the one the wheels in it were built for — which resolves at import time, in
    production, as a missing or ABI-mismatched extension module.
    """
    pinned = re.findall(r"^FROM (python:\S+)", DOCKERFILE, re.MULTILINE)
    assert len(pinned) == 1, f"more than one stage names an interpreter: {pinned}"


def test_the_deps_stage_proves_the_cpp_extension_imports():
    """THE guard. The env vars below are this year's fix; this is what catches the next one.

    Any C++ sdist can be mislinked by an interpreter whose recorded `CXX` is wrong, and
    every consequence of that is invisible until a user notices a feature quietly missing.
    """
    stage = _deps_stage()
    assert "import tlsh" in stage, "nothing proves the C++ extension is importable at build time"
    assert "assert tlsh.hash(" in stage, "importing is not enough — the check must run C++ code"


def test_the_cpp_linker_is_named_for_the_install():
    stage = _deps_stage()
    install = next(line for line in stage.splitlines() if "pip install" in line)
    assert "CXX=g++" in install, f"py-tlsh will link without libstdc++: {install.strip()!r}"
    assert "LDCXXSHARED=" in install, f"the C++ link step is still gcc's: {install.strip()!r}"
