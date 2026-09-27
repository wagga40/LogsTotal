"""Tests for scripts/deploy-bootstrap.sh via DEPLOY_DRY_RUN (no SSH, no installs).

The tested-OS verdict is the part worth pinning: it has four outcomes and a real
distro for each is not something a test suite can have, so the script takes an
/etc/os-release body through DEPLOY_DRY_RUN_OS_RELEASE — the DEPLOY_DRY_RUN_HEALTH
idiom. Every outcome must leave the exit code at 0: bootstrap reports an untested
OS, it never refuses one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "deploy-bootstrap.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

UBUNTU = 'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nVERSION_CODENAME=noble\n'
DEBIAN = 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_CODENAME=bookworm\n'
MINT = 'ID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 22"\nUBUNTU_CODENAME=noble\n'
ROCKY = 'ID="rocky"\nID_LIKE="rhel centos fedora"\nPRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\n'


def _run(tmp_path: Path, env_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    env.pop("SSH_IDENTITY", None)
    env["DEPLOY_DRY_RUN"] = "true"
    env["DEPLOY_ENV_FILE"] = str(tmp_path / "deploy.env.absent")
    env.update(env_overrides)
    return subprocess.run(["bash", str(SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)


def test_missing_hosts_fails_with_a_named_fix(tmp_path: Path):
    result = _run(tmp_path, {})
    assert result.returncode != 0
    assert "DEPLOY_HOSTS is required" in result.stderr


def test_hosts_are_bootstrapped_control_plane_first(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example,w2.example"})
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    cp = out.index("cp.example (control-plane): bootstrap")
    w1 = out.index("w1.example (worker): bootstrap")
    w2 = out.index("w2.example (worker): bootstrap")
    assert cp < w1 < w2
    assert "Bootstrap complete on 3 host(s)" in out


def test_a_local_host_is_bootstrapped_without_ssh(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "local,w1.example"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DRY-RUN local:" in result.stdout
    assert "root@local" not in result.stdout
    assert "DRY-RUN ssh root@w1.example" in result.stdout


def test_the_install_directory_and_its_subdirs_are_passed_through(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_REMOTE_DIR": "/srv/lt"})
    assert "LT_DIR='/srv/lt'" in result.stdout


def test_wireguard_is_installed_only_when_the_vpn_step_is_wanted(tmp_path: Path):
    """This script runs BEFORE deploy-vpn.sh and decides from its own resolution of
    DEPLOY_VPN, so the two have to reach the same answer through lib/common.sh::vpn_mode.
    Resolving it separately is how a host gets a tunnel's packages, and a rewritten
    firewall, for a tunnel that is then skipped.
    """
    # Defaulted and single-host: a hub-and-spoke mesh with no spokes protects nothing.
    off = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example"})
    assert "LT_WIREGUARD='no'" in off.stdout
    # Asked for explicitly: honoured even on a degenerate fleet.
    on = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "wireconf"})
    assert "LT_WIREGUARD='yes'" in on.stdout
    # Defaulted and multi-host: the tunnel is the default, so the packages must land.
    default_fleet = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example"})
    assert "LT_WIREGUARD='yes'" in default_fleet.stdout
    # And turned off explicitly, they must not.
    opted_out = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "none"})
    assert "LT_WIREGUARD='no'" in opted_out.stdout


# ── The tested-OS verdict ────────────────────────────────────────────────────


@pytest.mark.parametrize("release", [UBUNTU, DEBIAN])
def test_a_tested_os_is_reported_as_tested(tmp_path: Path, release: str):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_DRY_RUN_OS_RELEASE": release})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "(tested)" in result.stdout
    assert "WARN" not in result.stderr


def test_a_debian_derivative_is_not_warned_about(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_DRY_RUN_OS_RELEASE": MINT})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Linux Mint 22 (Debian-like" in result.stdout
    assert "tested on Ubuntu and Debian only" not in result.stderr


def test_an_untested_os_warns_names_itself_and_continues(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_DRY_RUN_OS_RELEASE": ROCKY})
    assert result.returncode == 0, "an untested OS must never fail the bootstrap"
    assert "Rocky Linux 9.4" in result.stderr
    assert "tested on Ubuntu and Debian only" in result.stderr
    assert "Continuing" in result.stderr
    assert "Bootstrap complete on 1 host(s)" in result.stdout


def test_the_codename_comes_from_either_field(tmp_path: Path):
    """Debian sets VERSION_CODENAME, Ubuntu derivatives often only UBUNTU_CODENAME,
    and the Docker apt repository line needs whichever exists."""
    debian = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_DRY_RUN_OS_RELEASE": DEBIAN})
    assert "LT_CODENAME='bookworm'" in debian.stdout
    mint = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_DRY_RUN_OS_RELEASE": MINT})
    assert "LT_CODENAME='noble'" in mint.stdout


def test_an_untested_distro_still_resolves_a_docker_repo_id(tmp_path: Path):
    """download.docker.com serves ubuntu and debian only, so an unknown ID has to
    resolve to one of them or the repo URL is a guaranteed 404."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_DRY_RUN_OS_RELEASE": ROCKY})
    assert "LT_DIST_ID='debian'" in result.stdout


def test_the_os_probe_is_skipped_under_a_bare_dry_run(tmp_path: Path):
    """Otherwise every dry run emits "could not read /etc/os-release", which is a
    finding about the dry run rather than about the host."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example"})
    assert "OS check skipped (dry-run)" in result.stdout
    assert "could not read /etc/os-release" not in result.stderr


def test_apt_waits_for_the_dpkg_lock():
    """A freshly provisioned Ubuntu box runs unattended-upgrades on boot, and a FIRST
    deploy is by definition aimed at a freshly provisioned box — so the two collide
    routinely. Without a timeout, apt exits immediately with its own raw message ("Could
    not get lock /var/lib/dpkg/lock-frontend. It is held by process N") in the middle of
    bootstrapping a fleet, and the deploy stops.

    It is not a fault and it clears itself. Asserted on every apt-get, not one, because a
    single unguarded call is all it takes to reproduce the failure.
    """
    text = (REPO_ROOT / "scripts" / "deploy-bootstrap.sh").read_text(encoding="utf-8")
    calls = [line.strip() for line in text.splitlines() if "apt-get update" in line or "apt-get install" in line if not line.lstrip().startswith("#")]
    assert calls, "no apt-get calls found — has bootstrap changed shape?"
    unguarded = [c for c in calls if "APT_WAIT" not in c]
    assert not unguarded, f"these die on a held dpkg lock instead of waiting: {unguarded}"
    assert "DPkg::Lock::Timeout" in text, "APT_WAIT must actually set apt's lock timeout"
