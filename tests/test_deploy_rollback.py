"""The rollback path must fail loudly rather than report a restore it did not do.

``remote_snapshot`` and ``do_rollback`` run as heredocs on the remote host, so the
DEPLOY_DRY_RUN seam cannot exercise them (dry-run prints ``ssh host: bash -s`` and
discards stdin). These tests extract the heredoc body and run it locally against a
sandbox directory, with ``rsync`` stubbed to succeed or fail on demand.

What they pin:

* a failed restore must not print "Rollback complete" and exit 0;
* it must not then ``rm -rf`` the snapshot it just failed to restore from, which would
  leave the operator unable to retry and make the next rollback silently skip a generation;
* a failed snapshot must not degrade to a directory holding only VERSION and still print
  "Snapshot saved".
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "deploy-multiserver.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _extract(pattern: str) -> str:
    """Pull a remote heredoc body out of the script and undo the outer shell's escaping."""
    body = re.search(pattern, SCRIPT.read_text(encoding="utf-8"), re.S).group(1)
    return body.replace("\\$", "$")


def _rollback_body() -> str:
    return _extract(r'remote "\$h" bash -s <<EOS\n(.*?)\nEOS\n')


def _snapshot_exclude_args() -> str:
    """The literal string the outer shell interpolates into the heredoc.

    Read from common.sh rather than restated here — a second copy of the exclude list is
    exactly the thing this consolidation removed."""
    return subprocess.run(
        ["bash", "-c", f'. "{REPO_ROOT / "scripts" / "lib" / "common.sh"}"; snapshot_exclude_args'],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _snapshot_root() -> str:
    """Read from common.sh, not restated: one layout means one definition of it."""
    return subprocess.run(
        ["bash", "-c", f'. "{REPO_ROOT / "scripts" / "lib" / "common.sh"}"; printf %s "$SNAPSHOT_ROOT"'],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _run(body: str, *, deploy_dir: Path, stub_bin: Path | None) -> subprocess.CompletedProcess[str]:
    body = (
        body.replace("${DEPLOY_REMOTE_DIR}", str(deploy_dir))
        .replace("${DEPLOY_KEEP_RELEASES}", "3")
        .replace("${h}", "testhost")
        .replace("${SNAP_EXCLUDES}", _snapshot_exclude_args())
        .replace("${SNAPSHOT_ROOT}", _snapshot_root())
    )
    env = {**os.environ}
    if stub_bin is not None:
        env["PATH"] = f"{stub_bin}:{env['PATH']}"
    return subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env, check=False)


def _stub_rsync(tmp_path: Path, *, exit_code: int) -> Path:
    """A PATH shim standing in for rsync, so we can force the failure branch."""
    bin_dir = tmp_path / "stubbin"
    bin_dir.mkdir()
    shim = bin_dir / "rsync"
    shim.write_text(f'#!/usr/bin/env bash\necho "rsync stub: simulated" >&2\nexit {exit_code}\n')
    shim.chmod(0o755)
    return bin_dir


@pytest.fixture()
def deploy_dir(tmp_path: Path) -> Path:
    """A release directory with one snapshot to roll back to."""
    d = tmp_path / "srv"
    (d / "backups" / "releases" / "20260101-000000-0.1.0").mkdir(parents=True)
    (d / "backups" / "releases" / "20260101-000000-0.1.0" / "VERSION").write_text("0.1.0\n")
    (d / "VERSION").write_text("0.2.0\n")
    return d


# ── Restore ──────────────────────────────────────────────────────────────────


def test_failed_restore_exits_nonzero(deploy_dir: Path, tmp_path: Path):
    result = _run(_rollback_body(), deploy_dir=deploy_dir, stub_bin=_stub_rsync(tmp_path, exit_code=1))
    assert result.returncode != 0
    assert "ERROR" in result.stdout + result.stderr


def test_failed_restore_does_not_claim_success(deploy_dir: Path, tmp_path: Path):
    result = _run(_rollback_body(), deploy_dir=deploy_dir, stub_bin=_stub_rsync(tmp_path, exit_code=1))
    assert "Rollback complete" not in result.stdout


def test_failed_restore_keeps_the_snapshot_so_it_can_be_retried(deploy_dir: Path, tmp_path: Path):
    """Deleting it anyway would leave nothing to retry against."""
    _run(_rollback_body(), deploy_dir=deploy_dir, stub_bin=_stub_rsync(tmp_path, exit_code=1))
    assert (deploy_dir / "backups" / "releases" / "20260101-000000-0.1.0").is_dir()


def test_successful_restore_consumes_the_snapshot(deploy_dir: Path, tmp_path: Path):
    result = _run(_rollback_body(), deploy_dir=deploy_dir, stub_bin=_stub_rsync(tmp_path, exit_code=0))
    assert result.returncode == 0
    assert "Rollback complete" in result.stdout
    assert not (deploy_dir / "backups" / "releases" / "20260101-000000-0.1.0").exists()


def test_missing_rsync_fails_before_touching_anything(deploy_dir: Path, tmp_path: Path):
    """A PATH carrying everything the script needs *except* rsync."""
    bin_dir = tmp_path / "norsync"
    bin_dir.mkdir()
    for tool in ("ls", "tail", "rm"):
        (bin_dir / tool).symlink_to(shutil.which(tool))
    body = (
        _rollback_body()
        .replace("${DEPLOY_REMOTE_DIR}", str(deploy_dir))
        .replace("${h}", "testhost")
        .replace("${SNAP_EXCLUDES}", _snapshot_exclude_args())
        .replace("${SNAPSHOT_ROOT}", _snapshot_root())
    )
    result = subprocess.run(
        [shutil.which("bash"), "-c", body],
        capture_output=True,
        text=True,
        env={"PATH": str(bin_dir), "HOME": str(tmp_path)},
        check=False,
    )
    assert result.returncode != 0
    assert "rsync is required" in result.stdout + result.stderr
    assert (deploy_dir / "backups" / "releases" / "20260101-000000-0.1.0").is_dir()


# ── What the restore actually restores (real rsync, no stub) ─────────────────


@pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync not available")
def test_rollback_restores_a_file_whose_size_and_mtime_did_not_change(tmp_path: Path):
    """rsync's default quick check skips a file whose size AND whole-second mtime both
    match. A snapshot preserves the original mtimes with -a, and the deploy that replaced
    them ran moments later — so within one second the two are indistinguishable. VERSION
    is one short line, identical in size across consecutive releases, which makes it the
    likeliest file in the tree to collide and the one the rollback is judged by.
    """
    d = tmp_path / "srv"
    snap = d / "backups" / "releases" / "20260101-000000-0.1.0"
    snap.mkdir(parents=True)
    (snap / "VERSION").write_text("version: 0.1.0\n")
    (d / "VERSION").write_text("version: 0.2.0\n")  # same size, different content
    stamp = (1893456000, 1893456000)
    os.utime(snap / "VERSION", stamp)
    os.utime(d / "VERSION", stamp)

    result = _run(_rollback_body(), deploy_dir=d, stub_bin=None)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (d / "VERSION").read_text() == "version: 0.1.0\n", "the rollback reported success and left the newer VERSION in place"


@pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync not available")
def test_rollback_removes_a_file_the_newer_release_added(tmp_path: Path):
    """A snapshot is the whole release, so restoring it must also undo additions.
    Without --delete the tree ends up as neither version: old content, new extra files —
    and a stale alembic revision there rolls the SCHEMA forward under rolled-back code."""
    d = tmp_path / "srv"
    snap = d / "backups" / "releases" / "20260101-000000-0.1.0"
    (snap / "alembic" / "versions").mkdir(parents=True)
    (snap / "VERSION").write_text("version: 0.1.0\n")
    (d / "alembic" / "versions").mkdir(parents=True)
    (d / "VERSION").write_text("version: 0.2.0\n")
    (d / "alembic" / "versions" / "0002_new.py").write_text("# only in the newer release\n")

    result = _run(_rollback_body(), deploy_dir=d, stub_bin=None)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not (d / "alembic" / "versions" / "0002_new.py").exists()


@pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync not available")
def test_rollback_leaves_live_state_alone(tmp_path: Path):
    """--delete plus a snapshot that never held them is a combination that would wipe
    the instance. The exclude list is what stops it, so assert it from the outside."""
    d = tmp_path / "srv"
    snap = d / "backups" / "releases" / "20260101-000000-0.1.0"
    snap.mkdir(parents=True)
    (snap / "VERSION").write_text("version: 0.1.0\n")
    (d / "VERSION").write_text("version: 0.2.0\n")
    (d / ".env").write_text("SECRET_KEY=live\n")
    for name in ("data", "uploads", "backups", "certs", "deploy-envs"):
        (d / name).mkdir(exist_ok=True)  # backups/ already exists — it holds the snapshot
        (d / name / "keep").write_text("live state\n")

    result = _run(_rollback_body(), deploy_dir=d, stub_bin=None)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (d / ".env").read_text() == "SECRET_KEY=live\n"
    for name in ("data", "uploads", "backups", "certs", "deploy-envs"):
        assert (d / name / "keep").exists(), f"{name}/ was destroyed by the rollback"


# ── Snapshot ─────────────────────────────────────────────────────────────────


def test_snapshot_never_degrades_to_a_version_only_directory(tmp_path: Path):
    """The `|| cp -r VERSION || true` fallback printed 'Snapshot saved' over a stub."""
    source = SCRIPT.read_text(encoding="utf-8")
    snapshot_block = re.search(r"remote_snapshot\(\) \{(.*?)\n\}", source, re.S).group(1)
    assert "cp -r" not in snapshot_block, "snapshot must not fall back to copying VERSION alone"
    assert "2>/dev/null || true" not in snapshot_block, "snapshot must not mask rsync failures"
    assert "command -v rsync" in snapshot_block, "snapshot must require rsync up front"


@pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync not available")
def test_a_snapshot_never_carries_certs_or_generated_env_files(tmp_path: Path):
    """A snapshot keeping certs/ and deploy-envs/ would make every rollback point on a
    control plane a copy of the TLS private key and the fleet's generated env files —
    DEPLOY_KEEP_RELEASES of them, kept indefinitely. The single-host and fleet paths share
    one exclude list."""
    d = tmp_path / "srv"
    d.mkdir()
    (d / "VERSION").write_text("version: 0.2.0\n")
    (d / "app").mkdir()
    (d / "app" / "main.py").write_text("# code\n")
    (d / "certs").mkdir()
    (d / "certs" / "privkey.pem").write_text("-----BEGIN PRIVATE KEY-----\n")
    (d / "deploy-envs").mkdir()
    (d / "deploy-envs" / "cp.example.env").write_text("SECRET_KEY=shared\n")
    (d / ".env").write_text("SECRET_KEY=live\n")

    body = _extract(r'remote_snapshot\(\) \{.*?remote "\$host" bash -s <<EOS\n(.*?)\nEOS\n')
    result = _run(body, deploy_dir=d, stub_bin=None)
    assert result.returncode == 0, result.stdout + result.stderr

    snaps = list((d / "backups" / "releases").iterdir())
    assert len(snaps) == 1, result.stdout
    snap = snaps[0]
    assert (snap / "app" / "main.py").exists(), "the code is what a snapshot is for"
    assert not (snap / "certs").exists()
    assert not (snap / "deploy-envs").exists()
    assert not (snap / ".env").exists()
