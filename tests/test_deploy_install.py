"""The rule that keeps a release from being written over a tree something is reading.

`7z x -aoa` rewrites each target IN PLACE — same inode, new bytes — under whatever file
descriptor is open on it. On a host deploying to itself that is the script bash is
executing, and bash reads a script incrementally, so the run derails somewhere
unpredictable rather than failing.

rsync, without `--inplace`, writes `.name.XXXXXX` in the destination and rename()s it
over the target. rename() unlinks the old directory entry, but the inode survives while
any process holds it open — so the running script reads its original bytes through to the
end. Everything in scripts/lib/install.sh depends on that, and `--inplace` silently
undoes it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "scripts" / "lib" / "install.sh"
COMMON_SH = REPO_ROOT / "scripts" / "lib" / "common.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

#: Every rsync flag that turns the rename back into a truncating write.
_TRUNCATING_FLAGS = ("--inplace", "--append", "--append-verify")


def _shell_sources() -> list[Path]:
    return sorted([*(REPO_ROOT / "scripts").glob("*.sh"), *(REPO_ROOT / "scripts" / "lib").glob("*.sh")])


def _code_only(text: str) -> str:
    """Comments stripped, so the file that DOCUMENTS the forbidden flags does not trip the
    guard against them. Naming a hazard in prose is the opposite of using it."""
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line.split(" #", 1)[0])
    return "\n".join(out)


@pytest.mark.parametrize("flag", _TRUNCATING_FLAGS)
def test_no_rsync_in_the_tree_writes_in_place(flag: str):
    """The single guard that keeps a self-upgrading install safe, forever.

    Nothing about `--inplace` looks dangerous at a call site — it reads like an
    optimisation — and the failure it reintroduces is not an error but a corrupted run.
    So it is refused by name across the whole shell tree rather than reviewed.
    """
    offenders = [p.name for p in _shell_sources() if flag in _code_only(p.read_text(encoding="utf-8"))]
    assert not offenders, f"{flag} rewrites a file under any descriptor already open on it, which is the bug lib/install.sh exists to avoid: {offenders}"


def test_the_fleet_deploy_stages_before_it_overlays():
    """Asserted against the source because the dry-run seam traces `bash -s` and never the
    heredoc piped into it — the extract command itself is invisible to a behavioural test."""
    src = (REPO_ROOT / "scripts" / "deploy-multiserver.sh").read_text(encoding="utf-8")
    body = re.search(r"step \"stage and overlay.*?\nEOS", src, re.S)
    assert body, "the stage-and-overlay step is gone or renamed"
    block = body.group(0)
    assert "7z x -y" in block
    assert "-aoa" not in block, "-aoa overwrites in place, which is the bug"
    assert "rsync -a --delete" in block, "the release is the whole tree; a dropped file must go"
    assert 'rm -rf "' in block, "the staging directory must not survive the run"


def test_the_overlay_keeps_every_piece_of_instance_state():
    """`--delete` plus a missing exclude is how an upgrade eats the database. Each of
    these lives inside the install directory and is not part of any release."""
    excludes = subprocess.run(
        ["bash", "-c", f'. "{COMMON_SH}"; overlay_excludes'],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for path in (".env", "data", "uploads", "backups", "certs", "deploy-envs", "deploy.env", "*.db", "docker-compose.override.yml"):
        assert f"--exclude={path}\n" in excludes, f"an upgrade would delete {path}"


def test_the_staging_directory_is_excluded_from_the_overlay_that_reads_it():
    """rsync --delete would otherwise remove the directory it is copying from, mid-copy."""
    excludes = subprocess.run(
        ["bash", "-c", f'. "{COMMON_SH}"; overlay_excludes'],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "--exclude=.stage\n" in excludes


def test_the_staging_directory_shares_a_filesystem_with_the_install():
    """rename() is only atomic within one filesystem, and the atomic rename is the whole
    mechanism. Putting the staging directory inside the install guarantees it; /tmp does
    not, and on a host with a separate /tmp rsync would fall back to copy-then-unlink."""
    out = subprocess.run(
        ["bash", "-c", f'. "{COMMON_SH}"; stage_dir /opt/logstotal'],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out.startswith("/opt/logstotal/")


def test_a_run_pins_its_own_scripts(tmp_path: Path):
    """rsync's rename keeps the EXECUTING script readable; it does nothing for a sibling
    the same overlay replaced. upgrade.sh dispatches to deploy-smoke.sh at the end of a
    flow whose middle replaced that file."""
    src = tmp_path / "scripts"
    src.mkdir()
    (src / "sibling.sh").write_text("echo original\n")
    script = f'''
      set -eu
      . "{COMMON_SH}"
      SCRIPT_DIR="{src}"
      pin_run_dir
      echo "PINNED=$SCRIPT_DIR"
      # The overlay lands, replacing the original sibling.
      echo "echo replaced" > "{src}/sibling.sh"
      bash "$SCRIPT_DIR/sibling.sh"
      unpin_run_dir
      [ -d "$SCRIPT_DIR" ] && echo "LEAKED" || echo "CLEANED"
    '''
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "original" in result.stdout, "a sibling replaced mid-run was dispatched from the new tree"
    assert "replaced" not in result.stdout
    assert "CLEANED" in result.stdout


def test_install_sh_is_reachable_from_common():
    """Every script sources lib/common.sh and nothing sources lib/install.sh directly, so
    a missing link here is a NameError at the worst moment rather than at parse time."""
    out = subprocess.run(
        ["bash", "-c", f'. "{COMMON_SH}"; type -t stage_dir overlay_exclude_args pin_run_dir'],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["function", "function", "function"]
