"""Syntax gate for shell scripts: `bash -n` every script under scripts/ plus the
repo-root Docker entrypoints.

Parametrized over a glob collected at import time, so new scripts (later
extraction tasks add scripts/*.sh files that source scripts/lib/common.sh)
are automatically covered without touching this file. This is a cheap syntax
check only — behavior tests for extracted task bodies come in later tasks.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Repo-root entrypoints run in Docker (POSIX /bin/sh); they are covered by the
# same syntax gate as the extracted scripts/ helpers.
_ROOT_ENTRYPOINTS = (PROJECT_ROOT / "docker-entrypoint.sh", PROJECT_ROOT / "docker-caddy-entrypoint.sh", PROJECT_ROOT / "garage-entrypoint.sh")

SHELL_SCRIPTS = sorted((*PROJECT_ROOT.glob("scripts/*.sh"), *PROJECT_ROOT.glob("scripts/lib/*.sh"), *_ROOT_ENTRYPOINTS))

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda p: str(p.relative_to(PROJECT_ROOT)))
def test_shell_script_syntax_is_valid(script: Path):
    result = subprocess.run(
        ["bash", "-n", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"{script}: bash -n failed:\n{result.stderr}"
