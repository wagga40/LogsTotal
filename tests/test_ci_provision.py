"""scripts/ci-provision.sh treats a cached tool as cached only at the pinned version.

A host runner keeps ~/.local/bin between runs. Keyed on presence alone, the cache kept
whatever version it was first filled with, so a pin bump never reached the runner: CI went on
linting with one shellcheck while the pin named another.

Real bash, a throwaway HOME, stub tools that print a version banner, and a `curl` stub that
fails — so "installing" is observable as a download attempt and nothing is fetched.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "ci-provision.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _pin(name: str) -> str:
    m = re.search(rf'^{name}="([^"]+)"', SCRIPT.read_text(encoding="utf-8"), re.M)
    assert m, f"ci-provision.sh no longer assigns {name}"
    return m.group(1)


def _stub(path: Path, banner: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\ncat <<'EOF'\n" + banner + "\nEOF\n")
    path.chmod(0o755)


def _run(tmp_path: Path, *tools: str) -> subprocess.CompletedProcess:
    shims = tmp_path / "shims"
    _stub(shims / "curl", "")
    (shims / "curl").write_text("#!/bin/sh\nexit 22\n")
    # Only the shims and the base system: a developer's own jq or 7z must not stand in for
    # the cached copy under test.
    env = {"HOME": str(tmp_path / "home"), "PATH": f"{shims}:/usr/bin:/bin", "NO_COLOR": "1"}
    return subprocess.run(["bash", str(SCRIPT), *tools], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)


def _cache(tmp_path: Path) -> Path:
    return tmp_path / "home" / ".local" / "bin"


def test_the_pinned_version_is_cached(tmp_path):
    _stub(_cache(tmp_path) / "jq", f"jq-{_pin('JQ_VERSION')}")
    r = _run(tmp_path, "jq")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "jq: cached" in r.stdout


def test_another_version_is_reinstalled(tmp_path):
    _stub(_cache(tmp_path) / "jq", "jq-1.7.1")
    r = _run(tmp_path, "jq")
    assert "jq: installing" in r.stdout, "a stale cached jq was kept"
    assert r.returncode != 0 and "download failed" in r.stderr, "the reinstall never reached the download"


def test_a_runners_own_p7zip_is_replaced(tmp_path):
    """Every release archive is built by the one pinned 7-Zip, not whichever the runner has."""
    _stub(_cache(tmp_path) / "7z", "\n7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21")
    assert "7z: installing" in _run(tmp_path, "7z").stdout
    _stub(_cache(tmp_path) / "7z", f"\n7-Zip (z) {_pin('SEVENZIP_VERSION')} (x64) : Copyright (c) 1999-2026 Igor Pavlov")
    assert "7z: cached" in _run(tmp_path, "7z").stdout


def test_shellcheck_matches_the_whole_version_line(tmp_path):
    want = _pin("SHELLCHECK_VERSION").removeprefix("v")
    _stub(_cache(tmp_path) / "shellcheck", f"ShellCheck - shell script analysis tool\nversion: {want}1\nlicense: GPLv3")
    assert "shellcheck: installing" in _run(tmp_path, "shellcheck").stdout, f"{want}1 was taken for {want}"
    _stub(_cache(tmp_path) / "shellcheck", f"ShellCheck - shell script analysis tool\nversion: {want}\nlicense: GPLv3")
    assert "shellcheck: cached" in _run(tmp_path, "shellcheck").stdout


def test_a_long_banner_does_not_defeat_the_tailwind_check(tmp_path):
    """The check used to be `--help | head -n 3 | grep -q` under pipefail. When the reader
    stops early the writer can take a SIGPIPE, the pipeline fails although the version
    matched, and every run downloaded the 46 MB CLI again."""
    banner = f"≈ tailwindcss v{_pin('TAILWIND_VERSION')}\n" + "\n".join(f"  --option-{i}  some help text" for i in range(5000))
    _stub(tmp_path / "tools" / "tailwind" / "tailwindcss", banner)
    r = _run(tmp_path, "tailwind")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "tailwind: cached" in r.stdout


def test_an_unknown_tool_is_refused(tmp_path):
    r = _run(tmp_path, "nonesuch")
    assert r.returncode != 0
    assert "unknown tool: nonesuch" in r.stderr


def test_sqlite_pin_decodes_to_the_release_it_names():
    """3540100 is sqlite.org's spelling of 3.54.1, and the version check compares the two."""
    out = subprocess.run(
        ["bash", "-c", f'eval "$(sed -n "/^SQLITE_VERSION=/p; /^sqlite_dotted()/,/^}}/p" {SCRIPT})"; sqlite_dotted'],
        capture_output=True,
        text=True,
        env={**os.environ},
    ).stdout.strip()
    raw = _pin("SQLITE_VERSION")
    assert out == f"{int(raw[0])}.{int(raw[1:3])}.{int(raw[3:5])}"
