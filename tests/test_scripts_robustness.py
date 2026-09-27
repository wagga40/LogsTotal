"""Robustness pins for deployment and build scripts.

These tests lock the current hardened state so future edits cannot silently regress.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from _taskfile import all_raw

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAFFOLD_SCRIPT = REPO_ROOT / "scripts" / "deploy-env-scaffold.sh"
DEPLOY_MULTISERVER = REPO_ROOT / "scripts" / "deploy-multiserver.sh"
# Taskfile.yml is a root plus taskfiles/{dev,ops}.yml, and every scan here goes through
# all_raw() so a guard cannot silently check a four-task root and pass. See tests/_taskfile.py.

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def test_scaffold_uses_grep_never_rg():
    text = SCAFFOLD_SCRIPT.read_text(encoding="utf-8")
    non_comment = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"(?<![A-Za-z0-9_])rg(?![A-Za-z0-9_])", non_comment), "scripts/deploy-env-scaffold.sh must not call ripgrep (rg); use grep."
    assert "grep -E " in text


_HARDENED_TASK_RULES = ("vendor:update", "tailwind:install")


def _taskfile_curl_lines():
    text = all_raw().splitlines()
    curls = []
    current = None
    for line in text:
        m = re.match(r"^  ([a-zA-Z][a-zA-Z0-9:_-]*):\s*$", line)
        if m:
            current = m.group(1)
            continue
        # Comment lines are not downloads. The rule is about what the task RUNS, and a
        # comment that mentions curl was reported as a curl call missing -fsSL.
        if current in _HARDENED_TASK_RULES and "curl " in line and not line.lstrip().startswith("#"):
            curls.append((current, line))
    return curls


def test_taskfile_curl_uses_fsSL_and_carries_error_message():
    lines = _taskfile_curl_lines()
    assert lines, "No curl calls found in vendor:update/tailwind:install"
    weak = []
    unguarded = []
    for rule, line in lines:
        if "curl -fsSL " not in line:
            weak.append(rule + ": " + line.strip())
        if "ERROR: download failed" not in line:
            unguarded.append(rule + ": " + line.strip())
    assert not weak, "curl calls missing -fsSL:\n  " + "\n  ".join(weak)
    assert not unguarded, "curl calls missing ERROR message:\n  " + "\n  ".join(unguarded)


def _extract_task_body(task_name):
    text = all_raw().splitlines()
    marker = "  " + task_name + ":"
    start = next((i for i, ln in enumerate(text) if ln.rstrip() == marker), None)
    assert start is not None, "Taskfile has no " + task_name + ": rule"
    end = start + 1
    while end < len(text) and not re.match(r"^  [a-zA-Z][a-zA-Z0-9:_-]*:\s*$", text[end]):
        end += 1
    return "\n".join(text[start:end])


@pytest.mark.parametrize("task_name", ["setup"])
def test_setup_tasks_guard_missing_pdm(task_name):
    body = _extract_task_body(task_name)
    assert "command -v pdm" in body, "task " + task_name + " is missing a command -v pdm presence guard."
    assert "pdm not found" in body, "task " + task_name + " pdm guard should say pdm not found verbatim."
    assert "exit 1" in body, "task " + task_name + " pdm guard must exit 1."


def _run_deploy(tmp_path, env_overrides):
    env = dict(os.environ)
    for var in (
        "DEPLOY_HOSTS",
        "DEPLOY_STOP",
        "DEPLOY_START",
        "DEPLOY_KEEPENV",
        "DEPLOY_CLEAN",
        "DEPLOY_CLEAN_CONFIRM",
        "DEPLOY_PACKAGE",
        "DEPLOY_ACTION",
        "DEPLOY_ENV_FILE",
        "DEPLOY_DRY_RUN_HEALTH",
        "SSH_IDENTITY",
    ):
        env.pop(var, None)
    env["DEPLOY_DRY_RUN"] = "true"
    env["DEPLOY_ENV_FILE"] = str(tmp_path / "deploy.env.absent")
    env.update(env_overrides)
    return subprocess.run(
        ["bash", str(DEPLOY_MULTISERVER)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_deploy_clean_refuses_without_confirm(tmp_path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_CLEAN": "true",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert result.returncode != 0, "DEPLOY_CLEAN=true without confirmation should abort:\n" + result.stdout + result.stderr
    combined = result.stdout + result.stderr
    assert "DEPLOY_CLEAN_CONFIRM=yes" in combined
    assert "down -v --rmi all" in combined
    assert "stopping stacks" not in result.stdout
    assert "starting stack" not in result.stdout


def test_deploy_clean_with_confirm_proceeds(tmp_path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com",
            "DEPLOY_CLEAN": "true",
            "DEPLOY_CLEAN_CONFIRM": "yes",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert result.returncode == 0, "DEPLOY_CLEAN + CONFIRM=yes should succeed under DRY_RUN:\n" + result.stdout + result.stderr


def test_deploy_without_clean_ignores_confirm_gate(tmp_path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DEPLOY_CLEAN_CONFIRM=yes" not in result.stderr


# ── The release archive must carry the template it tells you to copy ─────────


def test_package_ships_the_env_template():
    """`.env.example` must survive packaging — and `.env` must not.

    `scripts/package.sh` ends by printing `cp .env.example .env`, so excluding that file
    makes the archive's own instructions impossible to follow. A `-xr!.env.*` glob added
    as speculative hardening did exactly that: it matched `.env.example` too, and nothing
    caught it because no test looked inside the archive.
    """
    src = (REPO_ROOT / "scripts" / "package.sh").read_text(encoding="utf-8")

    assert "cp .env.example .env" in src, "the deploy instructions no longer mention the template — update this test with them"
    for glob in ("'-xr!.env.*'", "'-x!.env.*'", "'-xr!.env*'", "'-x!.env*'"):
        assert glob not in src, f"{glob} also excludes .env.example, which the archive must contain"
    assert "'-x!.env'" in src, "the real .env must still be excluded"


def test_package_excludes_every_directory_that_can_hold_a_secret():
    """A gitignored directory never shows up in a diff, so nothing but this catches one.

    A local `testkit/` can hold pre-baked env files with SECRET_KEY, POSTGRES_PASSWORD,
    REDIS_PASSWORD and Garage keys in them; left off the list, every archive built on that
    machine would carry them to every deploy target. The `-x!` excludes are anchored to the
    archive root and are *not* recursive, so `-x!.env` does not cover them.

    Asserted against the script's source rather than a built archive: `task package` needs
    7z and takes minutes on a real tree, and the failure this guards is a missing line.
    """
    src = (REPO_ROOT / "scripts" / "package.sh").read_text(encoding="utf-8")
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")

    for path in ("deploy-envs", "backups", "testkit", "data", "uploads", "logs", "certs"):
        assert f"'-x!{path}'" in src or f"'-xr!{path}'" in src, f"scripts/package.sh would ship {path}/ into the release archive"
        # If it is worth excluding from the archive it is untracked working state, and the
        # two lists drifting is how the next one gets missed.
        ignored = {line.strip().rstrip("/*").rstrip("/") for line in gitignore.splitlines() if line.strip() and not line.startswith("#")}
        assert path in ignored, f"{path}/ is excluded from the package but is not gitignored — one of the two is wrong"


def test_dockerignore_keeps_the_env_template_but_drops_the_real_one():
    """Same trap, same file, other artifact — Docker at least supports a negation."""
    lines = [line.strip() for line in (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()]

    assert ".env" in lines
    assert "!.env.example" in lines, ".env.* excludes the template unless it is negated afterwards"
    assert lines.index(".env.*") < lines.index("!.env.example"), "the negation must come after the pattern it re-includes"
    for secret in ("deploy-envs/", "backups/", "deploy.env"):
        assert secret in lines, f"{secret} must never be copied into the image"


def test_app_version_is_still_parseable_by_sed():
    """Two release-critical shell readers sed this line out of app/config.py.

    `scripts/release.py` rewrites it, and `.github/workflows/release.yml` greps it to check
    the tag against the declared version before publishing. Reword the line and both go
    quiet rather than loud — the workflow would compare the tag against an empty string.
    """
    config = (REPO_ROOT / "app" / "config.py").read_text(encoding="utf-8")
    versions = re.findall(r'app_version: str = "([^"]*)"', config)
    assert versions, 'app/config.py has no `app_version: str = "..."` line — the release gate reads it with sed'
    assert versions[0].strip(), "app_version is empty"


def test_package_refuses_to_build_an_unversioned_archive():
    """`task package` names the archive from VERSION, so an empty read is not survivable.

    A fallback would ship `logstotal-0.0.0.7z` with /health reporting 0.0.0. Packaging only
    READS the manifest, so the guard has to live at the read.
    """
    body = (REPO_ROOT / "scripts" / "package.sh").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    assert "refusing to build logstotal-unknown.7z" in code, "package.sh lost its empty-version guard"
    assert "${ARCHIVE_VERSION:-unknown}" not in code, "package.sh is back to silently defaulting the archive name"
    assert "task version:write" not in code, "packaging must not regenerate the tracked VERSION manifest"


def test_the_archive_ships_no_local_development_notes(tmp_path: Path):
    """The gitignored local development notes never ship in a release archive.

    Asserted against every `CLAUDE*` line in .gitignore rather than two hard-coded names,
    because the notes are a pair and a guard listing one passes while the other ships.
    """
    ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    notes = [line.strip() for line in ignored if line.strip().startswith("CLAUDE")]
    assert notes, ".gitignore no longer names the development notes — has this moved?"

    package = (REPO_ROOT / "scripts" / "package.sh").read_text(encoding="utf-8")
    verify = (REPO_ROOT / "scripts" / "verify-artifacts.sh").read_text(encoding="utf-8")
    for note in notes:
        assert f"'-x!{note}'" in package, f"{note} would be shipped inside the release archive"
        assert note in verify, f"nothing would catch {note} in a built archive"
