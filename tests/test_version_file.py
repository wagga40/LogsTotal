"""The VERSION manifest holds one fact, and only a release writes it.

No build provenance — `git_sha`, `git_branch`, `build_date` — because a *tracked* file
rewritten by a *build* causes trouble everywhere: `scripts/upgrade.sh` would need a
workaround to check out a ref at all, `scripts/deploy-package-gate.sh` could never reuse an
archive because the tree would be permanently dirty, and `git add -A` would sweep the file
into unrelated commits.

The provenance would also be wrong: a file committed *into* a commit cannot name that
commit.
"""

from pathlib import Path

import pytest
from _taskfile import taskfile_paths

from app.config import version_from_manifest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = PROJECT_ROOT / "VERSION"

#: Every way a file gets written that a static scan can see.
_WRITE_PATTERNS = ("> VERSION", ">> VERSION", "tee VERSION", "version:write")

#: The one place allowed to write it.
_ALLOWED_WRITERS = {"scripts/release.py"}


def test_the_manifest_holds_only_a_version():
    keys = {line.partition(":")[0] for line in VERSION_FILE.read_text(encoding="utf-8").splitlines() if line.strip()}
    assert keys == {"version"}, (
        f"VERSION carries {sorted(keys)}. It holds the release number and nothing else — build provenance in a tracked file is stale the moment it is committed."
    )


def test_the_declared_version_parses():
    assert version_from_manifest(VERSION_FILE.read_text(encoding="utf-8"))


class TestVersionFromManifest:
    def test_reads_the_one_line_form(self):
        assert version_from_manifest("version: 1.2.3\n") == "1.2.3"

    def test_reads_a_legacy_four_key_manifest(self):
        """An upgraded host keeps the old manifest until the next release lands on it."""
        legacy = "version: 1.2.3\ngit_sha: abc1234\ngit_branch: main\nbuild_date: 2026-01-01T00:00:00Z\n"
        assert version_from_manifest(legacy) == "1.2.3"

    @pytest.mark.parametrize("text", ["", "\n\n", "git_sha: abc\n", "version:\n", "nonsense"])
    def test_returns_none_rather_than_raising(self, text: str):
        assert version_from_manifest(text) is None


def test_no_build_step_regenerates_the_manifest():
    """Nothing but the release tool may write VERSION.

    `task package` and `task upgrade:*` regenerating a tracked file would force dirty-tree
    workarounds in scripts/upgrade.sh and permanently defeat archive reuse in
    scripts/deploy-package-gate.sh.
    """
    scanned = list(taskfile_paths())
    scanned += sorted((PROJECT_ROOT / "scripts").glob("*.sh"))
    scanned += sorted((PROJECT_ROOT / "scripts" / "lib").glob("*.sh"))
    scanned += sorted((PROJECT_ROOT / "scripts").glob("*.py"))

    offenders = []
    for path in scanned:
        rel = path.relative_to(PROJECT_ROOT).as_posix()
        if rel in _ALLOWED_WRITERS:
            continue
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for pattern in _WRITE_PATTERNS:
                if pattern in line:
                    offenders.append(f"{rel}: {line.strip()}")

    assert not offenders, "these write or regenerate VERSION outside the release tool:\n  " + "\n  ".join(offenders)
