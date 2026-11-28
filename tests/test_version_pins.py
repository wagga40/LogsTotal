"""One version, written in several places, must say the same thing everywhere.

Each pin below is duplicated on purpose. The Dockerfile cannot read the Taskfile, CI
provisioning runs before go-task exists, and THIRD_PARTY_NOTICES.md is prose. But nothing
compared the copies, and they had drifted:

- the release archives were built with Tailwind CLI 3.4.17 while the image used 3.4.19;
- the notices listed htmx 2.0.3, Alpine 3.15.8 and Mermaid 11.16.0, three bumps behind
  what `app/static/vendor/` actually serves.

These guards make a bump that touches one copy fail until every copy has been touched.
"""

from __future__ import annotations

import re

import pytest
import yaml

from tests._taskfile import REPO_ROOT, ROOT_TASKFILE

NOTICES = REPO_ROOT / "THIRD_PARTY_NOTICES.md"
DOCKERFILE = REPO_ROOT / "Dockerfile"
CI_PROVISION = REPO_ROOT / "scripts" / "ci-provision.sh"


def _taskfile_vars() -> dict[str, str]:
    return {k: str(v) for k, v in (yaml.safe_load(ROOT_TASKFILE.read_text(encoding="utf-8")).get("vars") or {}).items()}


def _notices_version(component: str) -> str:
    """The Version cell of the notices row whose first cell is exactly `component`."""
    for line in NOTICES.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 2 and cells[0] == component:
            return cells[1]
    raise AssertionError(f"THIRD_PARTY_NOTICES.md has no row for {component!r}")


def _shell_assignment(path, name: str) -> str:
    m = re.search(rf'^{name}="([^"]+)"', path.read_text(encoding="utf-8"), re.M)
    assert m, f"{path.name} no longer assigns {name}"
    return m.group(1)


def test_the_tailwind_cli_is_one_version_everywhere():
    """The image, the release archive and a contributor's `css:build` must compile the
    same stylesheet: Tailwind emits different CSS across versions, and the archive is
    what a fleet runs."""
    taskfile = _taskfile_vars()["TAILWIND_VERSION"]
    m = re.search(r"^ARG TAILWIND_VERSION=(\S+)$", DOCKERFILE.read_text(encoding="utf-8"), re.M)
    assert m, "Dockerfile no longer declares ARG TAILWIND_VERSION"
    assert m.group(1) == taskfile, "Dockerfile ARG TAILWIND_VERSION differs from Taskfile.yml"
    assert _shell_assignment(CI_PROVISION, "TAILWIND_VERSION") == taskfile, "scripts/ci-provision.sh builds release CSS with a different Tailwind CLI"
    assert _notices_version("**Tailwind CSS CLI** (standalone, build-time only)") == taskfile


# Notices row → the Taskfile var `vendor:update` downloads it with.
VENDORED = {
    "htmx": "HTMX_VERSION",
    # Ships inside the htmx package, so it carries htmx's version.
    "htmx alpine-compat extension (`hx-alpine-compat.js`)": "HTMX_VERSION",
    "Alpine.js": "ALPINE_VERSION",
    "Tailwind CSS (Play CDN build, dev mode only)": "TAILWIND_CDN_VERSION",
    "Prism.js (+ json/sql/yaml, Tomorrow theme)": "PRISM_VERSION",
    "Mermaid": "MERMAID_VERSION",
    "Sigma.js": "SIGMA_VERSION",
    "@sigma/node-border (rewritten to a classic script by `vendor:update`)": "SIGMA_NODE_BORDER_VERSION",
    "graphology": "GRAPHOLOGY_VERSION",
    "graphology-library": "GRAPHOLOGY_LIBRARY_VERSION",
}


@pytest.mark.parametrize(("component", "var"), sorted(VENDORED.items()))
def test_the_notices_name_the_vendored_version(component, var):
    assert _notices_version(component) == _taskfile_vars()[var], (
        f"THIRD_PARTY_NOTICES.md lists {component} at a version app/static/vendor/ does not serve; Taskfile.yml {var} is the source of truth"
    )
