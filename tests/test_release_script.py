"""`scripts/release.py` — the tool that makes VERSION a release fact.

A release touches three declared versions, a changelog section and two link definitions,
and the version strings scattered through the docs. By hand, every one of them is a chance
to ship a tag that disagrees with the code.

Each refusal here is a failure the release workflow would otherwise discover after the tag
was already public.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release  # noqa: E402

CHANGELOG_SEED = """# Changelog

## [Unreleased]

### Changed

- Something worth releasing.

## [1.0.0] — 2026-01-01

### Added

- The first one.

[Unreleased]: https://example.com/o/r/compare/v1.0.0...HEAD
[1.0.0]: https://example.com/o/r/releases/tag/v1.0.0
"""


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(repo / "scripts" / "release.py"), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A minimal tree with the files a release touches, under real git."""
    (tmp_path / "app").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "docs").mkdir()

    (tmp_path / "app" / "config.py").write_text('    app_version: str = "1.0.0"\n', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    (tmp_path / "VERSION").write_text("version: 1.0.0\n", encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(CHANGELOG_SEED, encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "Install: `7z x logstotal-1.0.0.7z`\n"
        "Upgrade: `task upgrade:docker REF=v1.0.0`\n"
        "The default changed in 1.0.0, which is history and must not be rewritten.\n"
        "Unrelated prose mentioning 1.0.0 with no marker on the line.\n",
        encoding="utf-8",
    )
    # cli_color.py too: release.py imports it as a sibling (the deploy_fleet_env.py idiom),
    # so a tree with only release.py in it is not one release.py runs in. Nothing here is
    # asserting that it is standalone — the fixture is "the files a release touches".
    for name in ("release.py", "cli_color.py"):
        (tmp_path / "scripts" / name).write_bytes((REPO_ROOT / "scripts" / name).read_bytes())

    # The real repo ignores __pycache__/; this fixture must too, or release.py importing
    # its cli_color sibling writes a .pyc into the tree and then refuses to release because
    # the tree is dirty — a failure that exists only in the fixture.
    (tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")

    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "seed")
    return tmp_path


class TestPrepareRefuses:
    def test_a_version_that_is_not_semver(self, repo: Path):
        res = _run(repo, "prepare", "--version", "1.0")
        assert res.returncode == 1
        assert "not X.Y.Z" in res.stderr

    def test_a_non_increase(self, repo: Path):
        res = _run(repo, "prepare", "--version", "1.0.0")
        assert res.returncode == 1
        assert "not greater than" in res.stderr

    def test_a_dirty_worktree(self, repo: Path):
        (repo / "README.md").write_text("edited\n", encoding="utf-8")
        res = _run(repo, "prepare", "--version", "1.1.0")
        assert res.returncode == 1
        assert "uncommitted changes" in res.stderr
        assert "README.md" in res.stderr, "it must name the files, not just complain"

    def test_a_tag_that_already_exists(self, repo: Path):
        _git(repo, "tag", "v1.1.0")
        res = _run(repo, "prepare", "--version", "1.1.0")
        assert res.returncode == 1
        assert "already exists" in res.stderr

    def test_an_empty_unreleased_section(self, repo: Path):
        (repo / "CHANGELOG.md").write_text(
            CHANGELOG_SEED.replace("### Changed\n\n- Something worth releasing.\n\n", ""),
            encoding="utf-8",
        )
        _git(repo, "commit", "-qam", "empty the section")
        res = _run(repo, "prepare", "--version", "1.1.0")
        assert res.returncode == 1
        assert "Unreleased" in res.stderr

    def test_and_writes_nothing_when_it_refuses(self, repo: Path):
        """Every check runs before every write.

        Inside the rewrite, which runs *after* the three declarations are bumped, the
        changelog check would refuse an empty [Unreleased] with the tree half-released and
        the operator holding a diff they did not ask for.
        """
        (repo / "CHANGELOG.md").write_text(
            CHANGELOG_SEED.replace("### Changed\n\n- Something worth releasing.\n\n", ""),
            encoding="utf-8",
        )
        _git(repo, "commit", "-qam", "empty the section")
        before = (repo / "app" / "config.py").read_text(encoding="utf-8")

        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 1

        assert (repo / "app" / "config.py").read_text(encoding="utf-8") == before
        assert (repo / "VERSION").read_text(encoding="utf-8") == "version: 1.0.0\n"


class TestPrepare:
    def test_updates_all_three_declarations_together(self, repo: Path):
        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 0
        assert 'app_version: str = "1.1.0"' in (repo / "app" / "config.py").read_text(encoding="utf-8")
        assert 'version = "1.1.0"' in (repo / "pyproject.toml").read_text(encoding="utf-8")
        assert (repo / "VERSION").read_text(encoding="utf-8") == "version: 1.1.0\n"

    def test_moves_the_changelog_body_under_the_new_heading(self, repo: Path):
        assert _run(repo, "prepare", "--version", "1.1.0", "--date", "2026-02-03").returncode == 0
        text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")

        assert "## [1.1.0] — 2026-02-03" in text
        assert release.unreleased_body(text) == "", "[Unreleased] must be left empty"
        body = text.split("## [1.1.0]")[1].split("## [1.0.0]")[0]
        assert "- Something worth releasing." in body

    def test_release_notes_are_moved_verbatim_whatever_characters_they_hold(self, repo: Path):
        """The body went into `re.subn` as a replacement *template*, where a backslash is an
        escape: a note quoting `DOMAIN\\user` raised `bad escape \\u` — after the three
        declarations had already been bumped, leaving a half-released tree."""
        note = r"- Values like `DOMAIN\user`, `C:\Windows\Temp` and `\g<0>` are escaped."
        (repo / "CHANGELOG.md").write_text(CHANGELOG_SEED.replace("- Something worth releasing.", note), encoding="utf-8")
        _git(repo, "commit", "-qam", "a note with backslashes")

        res = _run(repo, "prepare", "--version", "1.1.0")

        assert res.returncode == 0, res.stderr
        body = (repo / "CHANGELOG.md").read_text(encoding="utf-8").split("## [1.1.0]")[1].split("## [1.0.0]")[0]
        assert note in body

    def test_rewrites_both_link_definitions(self, repo: Path):
        """The new link must compare against the PREVIOUS tag.

        Read back out of app/config.py — which prepare has already bumped by then — the
        previous version would make the link `compare/v1.1.0...v1.1.0`, pointing a release's
        diff at itself.
        """
        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 0
        text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")

        assert "[Unreleased]: https://example.com/o/r/compare/v1.1.0...HEAD" in text
        assert "[1.1.0]: https://example.com/o/r/compare/v1.0.0...v1.1.0" in text

    def test_sweeps_only_the_lines_the_docs_guard_polices(self, repo: Path):
        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 0
        readme = (repo / "README.md").read_text(encoding="utf-8")

        assert "logstotal-1.1.0.7z" in readme
        assert "REF=v1.1.0" in readme
        assert "The default changed in 1.0.0" in readme, "historical prose must survive a release"
        assert "Unrelated prose mentioning 1.0.0" in readme, "a line with no marker is out of scope"


class TestFinish:
    @staticmethod
    def _stub_task(repo: Path, exit_code: int) -> dict[str, str]:
        import os

        # Outside the repo: a stub dir inside it is an untracked change, which finish
        # correctly refuses as "not part of a release".
        binv = repo.parent / "stub"
        binv.mkdir(exist_ok=True)
        (binv / "task").write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
        (binv / "task").chmod(0o755)
        return {**os.environ, "PATH": f"{binv}:{os.environ['PATH']}"}

    def _finish(self, repo: Path, exit_code: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(repo / "scripts" / "release.py"), "finish", "--version", "1.1.0"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
            env=self._stub_task(repo, exit_code),
        )

    def test_the_tag_lands_on_the_release_commit(self, repo: Path):
        """The invariant this whole command exists for.

        Tagging before committing names the *parent* — which is how the retired VERSION
        manifest came to record the sha of the commit before the one it shipped in.
        """
        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 0
        res = self._finish(repo, 0)
        assert res.returncode == 0, res.stdout + res.stderr

        assert _git(repo, "rev-parse", "v1.1.0^{commit}") == _git(repo, "rev-parse", "HEAD")
        assert _git(repo, "log", "-1", "--format=%s") == "chore: release 1.1.0"
        assert _git(repo, "status", "--porcelain") == ""

    def test_it_never_pushes(self, repo: Path):
        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 0
        res = self._finish(repo, 0)
        assert "git push --atomic origin" in res.stdout, "it must tell you the push command"
        assert "refs/tags/v1.1.0" in res.stdout, "the tag is pushed by name"
        assert "--tags" not in res.stdout, "`--tags` publishes every local tag, not the release's"
        assert "PUBLIC GitHub Release" in res.stdout, "and say what pushing the tag does"

    def test_a_failed_gate_removes_the_tag_and_keeps_the_commit(self, repo: Path):
        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 0
        res = self._finish(repo, 1)

        assert res.returncode == 1
        assert _git(repo, "tag", "--list", "v1.1.0") == "", "a failed gate must not leave a tag"
        assert _git(repo, "log", "-1", "--format=%s") == "chore: release 1.1.0", "the commit is kept so it can be amended"

    def test_unrelated_changes_are_refused(self, repo: Path):
        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 0
        (repo / "app" / "unrelated.py").write_text("x = 1\n", encoding="utf-8")
        res = self._finish(repo, 0)

        assert res.returncode == 1
        assert "not part of a release" in res.stderr
        assert "app/unrelated.py" in res.stderr

    def test_a_disagreeing_declaration_is_refused(self, repo: Path):
        assert _run(repo, "prepare", "--version", "1.1.0").returncode == 0
        (repo / "pyproject.toml").write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
        res = self._finish(repo, 0)

        assert res.returncode == 1
        assert "disagree" in res.stderr


# ── Release hygiene ──────────────────────────────────────────────────────────


class TestTheReleaseShipsExactlyItsOwnFiles:
    """The things around a valid archive with a matching checksum.

    None of them is visible without downloading and unpacking the published release.
    """

    def test_the_archive_excludes_stale_checksum_files(self):
        """A previous build's `.7z.sha256` must not ship INSIDE the archive: excluding stale
        `.7z` files is not enough without their `.sha256` companions."""
        src = (REPO_ROOT / "scripts" / "package.sh").read_text(encoding="utf-8")
        assert "-xr!logstotal-*.7z.sha256" in src, "a previous release's checksum ships inside this one"

    def test_the_checksum_file_is_the_format_the_docs_tell_people_to_use(self):
        """docs/install/prerequisites.md says `sha256sum -c logstotal-<version>.7z.sha256`. A bare
        hash with no filename makes that fail with `no properly formatted SHA checksum
        lines` — the one command an operator runs before trusting a download."""
        for name in ("scripts/package.sh", "scripts/bundle.sh"):
            src = (REPO_ROOT / name).read_text(encoding="utf-8")
            line = next(ln for ln in src.splitlines() if ".sha256" in ln and ">" in ln and "printf" in ln)
            assert "basename" in line, f"{name} writes a checksum with no filename: {line.strip()!r}"

    def test_every_step_declares_the_variables_its_shell_reads(self):
        """A workflow `env:` is PER STEP, never inherited from the step above.

        A staging step that reads `${TAG#v}` while only the step before it declares TAG
        expands the variable to nothing and tries to move `logstotal-.7z` — after the full
        suite has run green, at the last step before publishing, which is the most expensive
        place to find it.
        """
        import yaml

        for name in (".forgejo/workflows/release.yml", ".github/workflows/release.yml"):
            spec = yaml.safe_load((REPO_ROOT / name).read_text(encoding="utf-8"))
            for job in spec["jobs"].values():
                for step in job.get("steps") or []:
                    script = step.get("run") or ""
                    if "$TAG" not in script and "${TAG" not in script:
                        continue
                    declared = step.get("env") or {}
                    assert "TAG" in declared, f"{name}: step {step.get('name')!r} reads TAG and does not declare it; a workflow env is per step"

    def test_neither_release_workflow_globs_the_worktree(self):
        """Both stage into an empty directory precisely so nothing else is published
        alongside the archive — and moving `logstotal-*` would walk past that and upload a
        stale checksum from an earlier build."""
        for name in (".forgejo/workflows/release.yml", ".github/workflows/release.yml"):
            src = (REPO_ROOT / name).read_text(encoding="utf-8")
            assert "mv logstotal-*" not in src, f"{name} moves whatever the worktree happens to hold"
            assert 'mv "logstotal-${version}.7z"' in src, f"{name} must name the version's files"
