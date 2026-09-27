"""Tests for scripts/deploy-vpn.sh — the opt-in Wireconf step.

Two things carry the weight here. The address arithmetic must match Wireconf's own
`wg_allocate_ips` (base = network + 1, index i gets base + i), because the whole
point of computing it rather than parsing `wireconf show` is that the rule is
documented and stable — and `show` regenerates the configs and prints every host's
PrivateKey on the way past. And a VPN that was ASKED FOR and could not be built must
STOP the deploy: falling back to the public addresses is not a smaller version of the
request, it is the opposite of it — Redis, PostgreSQL and Garage end up bound to a
routable interface, which is what the VPN was for. DEPLOY_VPN_OPTIONAL opts back into
best-effort. (A failed *verify* stays a warning: apply has already recorded the
addresses by then, so nothing is exposed.)
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.conftest import path_without

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "deploy-vpn.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _run(tmp_path: Path, env_overrides: dict[str, str], *, dry_run: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_") or key.startswith("WIRECONF"):
            env.pop(key, None)
    env.pop("SSH_IDENTITY", None)
    if dry_run:
        env["DEPLOY_DRY_RUN"] = "true"
    env["DEPLOY_ENV_FILE"] = str(tmp_path / "deploy.env.absent")
    # An isolated HOME: find_wireconf searches $HOME/.local, so without this the suite
    # passes or fails depending on whether the developer has Wireconf installed.
    env["HOME"] = str(tmp_path)
    # HOME alone was not enough. find_wireconf consults `command -v wireconf` BEFORE it
    # walks WIRECONF_PREFIX and $HOME, and deploy-vpn.sh's own installer writes
    # $HOME/.local/bin/wireconf — a directory on PATH. So one real `task deploy:vpn` on
    # this machine turned all three absence tests into presence tests, and even beat an
    # explicitly-passed WIRECONF_PREFIX. Same shape as the ufw shim (see conftest).
    env["PATH"] = path_without("wireconf")
    env.update(env_overrides)
    return subprocess.run(["bash", str(SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)


# ── Opt-in ───────────────────────────────────────────────────────────────────


def test_a_multi_host_fleet_builds_a_tunnel_by_default(tmp_path: Path):
    """The default changed. Without a tunnel, deploy_fleet_env.py binds Redis, PostgreSQL
    and Garage to a routable interface and prints a warning saying so — and a warning in a
    long log is not a default."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example"})
    assert "Wireconf" in result.stdout


def test_an_explicit_none_still_skips(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "none"})
    assert result.returncode == 0
    assert "skipped (DEPLOY_VPN=none)" in result.stdout
    assert "Wireconf" not in result.stdout


def test_a_defaulted_single_host_fleet_is_skipped_with_a_reason(tmp_path: Path):
    """A hub-and-spoke mesh with no spokes protects nothing, and building one would still
    install WireGuard and rewrite the hub's firewall."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example"})
    assert result.returncode == 0
    assert "only one host" in result.stdout
    assert "Wireconf" not in result.stdout


def test_a_defaulted_all_local_fleet_is_skipped_with_a_reason(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "local,localhost"})
    assert result.returncode == 0
    assert "nothing crosses a network" in result.stdout


def test_an_explicit_request_is_honoured_even_on_a_degenerate_fleet(tmp_path: Path):
    """The rules above soften a DEFAULT. Quietly overruling what someone asked for is
    worse than building something pointless — and it is the difference between a
    well-behaved default and a setting that does not work."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "wireconf"})
    assert "only one host" not in result.stdout
    assert "Wireconf" in result.stdout


def test_tailscale_stops_until_it_is_actually_set_up(tmp_path: Path):
    """Tailscale is supported, just not automated — `tailscale up` needs an interactive
    login. But printing that and returning 0 let the composer deploy the whole fleet over
    public addresses while the operator was being told to go and build a private network:
    exactly the exposure they had asked to avoid."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "tailscale"})
    assert result.returncode != 0
    assert "not automated here" in result.stderr
    assert "DEPLOY_CP_ADDRESS" in result.stderr


def test_tailscale_proceeds_once_its_address_is_known(tmp_path: Path):
    """That address is what makes the fleet use the tunnel, so it is the signal that
    Tailscale is genuinely up."""
    result = _run(
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "tailscale", "DEPLOY_CP_ADDRESS": "100.64.0.1"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "100.64.0.1" in result.stdout


@pytest.mark.parametrize("typo", ["wireguard", "Wireconf", "zerotier"])
def test_an_unrecognised_vpn_value_stops_the_deploy(tmp_path: Path, typo: str):
    """A private network was requested in terms the tooling did not understand.
    Continuing means guessing they meant "none" — the one reading that cannot be right,
    and the one that puts Redis, PostgreSQL and Garage on a routable interface."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": typo})
    assert result.returncode != 0
    assert f"Unknown DEPLOY_VPN={typo}" in result.stderr


def test_missing_hosts_is_the_one_hard_failure(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_VPN": "wireconf"})
    assert result.returncode != 0
    assert "DEPLOY_HOSTS is required" in result.stderr


# ── Address allocation ───────────────────────────────────────────────────────


def test_the_hub_is_dot_one_and_peers_follow(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example,w2.example", "DEPLOY_VPN": "wireconf"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Hub: cp.example → 10.200.0.1" in result.stdout
    assert "Peer: w1.example → 10.200.0.2" in result.stdout
    assert "Peer: w2.example → 10.200.0.3" in result.stdout


def test_every_host_reaches_the_inventory(tmp_path: Path):
    """The last entry vanished until the read loop learned that printf leaves the
    final field unterminated, and a dropped host is a host with no tunnel."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example,w2.example", "DEPLOY_VPN": "wireconf"})
    inventory = result.stdout.split("(dry-run) inventory:")[1]
    for host in ("cp.example", "w1.example", "w2.example"):
        assert f"{host} no" in inventory


@pytest.mark.parametrize(
    ("network", "expected_hub"),
    [
        ("10.200.0.0/24", "10.200.0.1"),
        ("10.201.5.0/24", "10.201.5.1"),
        ("192.168.42.0/28", "192.168.42.1"),
        ("10.10.0.0/16", "10.10.0.1"),
        # Not on a network boundary: Wireconf masks down to one, so must this.
        ("10.200.0.37/24", "10.200.0.1"),
    ],
)
def test_the_arithmetic_matches_wireconfs_allocation(tmp_path: Path, network: str, expected_hub: str):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "wireconf", "DEPLOY_VPN_NETWORK": network})
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"Hub: cp.example → {expected_hub}" in result.stdout


def test_a_network_too_small_for_the_fleet_stops_the_deploy(tmp_path: Path):
    result = _run(
        tmp_path,
        {"DEPLOY_HOSTS": "a,b,c,d,e", "DEPLOY_VPN": "wireconf", "DEPLOY_VPN_NETWORK": "10.0.0.0/30"},
    )
    assert result.returncode != 0
    assert "cannot address 5 host(s)" in result.stderr
    assert "Nothing has been deployed" in result.stderr


def test_an_invalid_network_stops_the_deploy(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "wireconf", "DEPLOY_VPN_NETWORK": "nonsense"})
    assert result.returncode != 0
    assert "cannot address" in result.stderr


# ── Inventory shape ──────────────────────────────────────────────────────────


def test_the_local_sentinel_becomes_localhost_in_the_inventory(tmp_path: Path):
    """Wireconf's own local-execution check matches localhost/127.0.0.1/::1; `local`
    is ours, and passing it through would have it try to SSH to a host of that name."""
    result = _run(tmp_path, {"DEPLOY_HOSTS": "local,w1.example", "DEPLOY_VPN": "wireconf"})
    inventory = result.stdout.split("(dry-run) inventory:")[1]
    assert "localhost no" in inventory
    assert "\n    local no" not in inventory


def test_the_hub_endpoint_defaults_to_the_first_host_without_its_user(tmp_path: Path):
    result = _run(tmp_path, {"DEPLOY_HOSTS": "root@cp.example,w1.example", "DEPLOY_VPN": "wireconf"})
    assert "endpoint cp.example" in result.stdout


def test_an_explicit_hub_endpoint_wins(tmp_path: Path):
    result = _run(
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "wireconf", "DEPLOY_VPN_HUB_ENDPOINT": "203.0.113.10"},
    )
    assert "endpoint 203.0.113.10" in result.stdout


# ── Failure modes ────────────────────────────────────────────────────────────


def test_a_missing_wireconf_stops_the_deploy_rather_than_exposing_the_services(tmp_path: Path):
    """Continuing here deploys a fleet with Redis, PostgreSQL and Garage on a routable
    address, which is exactly what DEPLOY_VPN=wireconf was asked to prevent — and the
    only sign would be one warning in a very long log."""
    result = _run(
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "wireconf", "DEPLOY_VPN_INSTALL": "false"},
        dry_run=False,
    )
    assert result.returncode != 0
    assert "Wireconf not found" in result.stderr
    assert "install.sh" in result.stderr
    assert "Nothing has been deployed" in result.stderr


def test_best_effort_is_available_but_has_to_be_asked_for(tmp_path: Path):
    result = _run(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example",
            "DEPLOY_VPN": "wireconf",
            "DEPLOY_VPN_INSTALL": "false",
            "DEPLOY_VPN_OPTIONAL": "true",
        },
        dry_run=False,
    )
    assert result.returncode == 0
    assert "continuing over the public addresses" in result.stderr
    assert "will be reachable there" in result.stderr


def test_the_installer_path_is_searched_where_the_installer_writes(tmp_path: Path):
    """The installer writes ${WIRECONF_PREFIX}/wireconf — the binary, not a directory.
    Searching $HOME/.local/wireconf/wireconf meant a successful install into
    $HOME/.local was reported as "installed but not found", and the VPN step skipped
    itself on every run. Found in a real deployment."""
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    binary = prefix / "wireconf"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    result = _run(
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "wireconf", "WIRECONF_PREFIX": str(prefix)},
    )
    assert f"Using {binary}" in result.stdout


def test_a_dry_run_writes_no_address_map(tmp_path: Path):
    """A map for tunnels that were never built would point every worker at an address
    that does not answer — and deploy:env consumes it without question."""
    _run(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "wireconf"})
    assert not (tmp_path / "deploy-envs" / "vpn.json").exists()


def test_wireconf_bin_is_honoured(tmp_path: Path):
    fake = tmp_path / "wireconf"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    result = _run(
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "wireconf", "WIRECONF_BIN": str(fake)},
    )
    assert f"Using {fake}" in result.stdout


# ── The version pin ──────────────────────────────────────────────────────────
#
# Wireconf below 0.3.8 omits `-T` from its remote commands, so an operator whose ssh
# config requests a TTY gets CRLF back, and its own `^ID="?(debian|ubuntu)"?$` check
# fails on the `$` anchor against `ID=ubuntu\r` — "w0 is not Debian/Ubuntu" on a host
# that plainly is. So an installed wireconf is never reused without checking its version.


def _stub(tmp_path: Path, version: str, *, update_fails: bool = False, update_to: str = "0.3.8") -> Path:
    """A fake wireconf that reports a version and records whether `update` was called."""
    binary = tmp_path / "wireconf-stub"
    state = tmp_path / "stub.version"
    state.write_text(version, encoding="utf-8")
    fail = "exit 1" if update_fails else f'printf %s {update_to} > "{state}"'
    binary.write_text(f'#!/bin/sh\ncase "$1" in\n  -V) printf "wireconf %s\\n" "$(cat {state})" ;;\n  update) : > "{tmp_path}/update-called"; {fail} ;;\n  *) exit 0 ;;\nesac\n')
    binary.chmod(0o755)
    return binary


def _with_stub(tmp_path: Path, binary: Path, extra: dict[str, str] | None = None):
    env = {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "wireconf", "WIRECONF_BIN": str(binary)}
    env.update(extra or {})
    return _run(tmp_path, env)


def test_the_version_in_use_is_always_reported(tmp_path: Path):
    """The failing run never said which wireconf it used, which is most of why the
    cause took a round trip to find."""
    result = _with_stub(tmp_path, _stub(tmp_path, "0.3.8"))
    assert "(wireconf 0.3.8)" in result.stdout


def test_a_current_wireconf_is_not_touched(tmp_path: Path):
    result = _with_stub(tmp_path, _stub(tmp_path, "0.3.8"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "update-called").exists(), "a current binary must not be updated mid-deploy"


def test_a_newer_wireconf_is_not_downgraded(tmp_path: Path):
    result = _with_stub(tmp_path, _stub(tmp_path, "0.4.1"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "update-called").exists()


def test_an_old_wireconf_is_updated_in_place(tmp_path: Path):
    result = _with_stub(tmp_path, _stub(tmp_path, "0.3.7"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "update-called").exists()
    assert "predates 0.3.8" in result.stdout
    assert "wireconf is now 0.3.8" in result.stdout


def test_an_old_wireconf_that_cannot_update_stops_the_deploy(tmp_path: Path):
    """Building a tunnel with a version that misreads /etc/os-release is what produced
    the field report; refusing is the point."""
    result = _with_stub(tmp_path, _stub(tmp_path, "0.3.7", update_fails=True))
    assert result.returncode != 0
    assert "0.3.7 is too old" in result.stderr
    assert "0.3.8" in result.stderr
    assert "update" in result.stderr
    assert "Nothing has been deployed" in result.stderr


def test_an_update_that_lands_on_a_still_old_version_is_refused(tmp_path: Path):
    result = _with_stub(tmp_path, _stub(tmp_path, "0.3.6", update_to="0.3.7"))
    assert result.returncode != 0
    assert "too old" in result.stderr


def test_the_pin_can_be_lowered_deliberately(tmp_path: Path):
    result = _with_stub(tmp_path, _stub(tmp_path, "0.3.7"), {"DEPLOY_VPN_MIN_VERSION": "0.3.0"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "update-called").exists()


def test_an_unreadable_version_warns_rather_than_refusing(tmp_path: Path):
    """A fork, a distro package or a future -V wording. Refusing would break installs
    that are perfectly fine."""
    binary = tmp_path / "silent"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    result = _with_stub(tmp_path, binary)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Could not read a version" in result.stderr


@pytest.mark.parametrize(
    ("older", "newer"),
    [("0.3.7", "0.3.8"), ("0.3.9", "0.3.10"), ("0.3", "0.3.8"), ("0.3.99", "0.4.0")],
)
def test_version_compare_is_numeric_not_lexical(tmp_path: Path, older: str, newer: str):
    """A string compare puts 0.3.10 before 0.3.9, which would wave the broken version
    through exactly once the project reaches 0.3.10."""
    body = (SCRIPT.read_text(encoding="utf-8").split("version_lt() {")[1]).split("\n}")[0]
    script = f'version_lt() {{{body}\n}}\nversion_lt "{older}" "{newer}" && echo OLDER || echo not\nversion_lt "{newer}" "{older}" && echo OLDER2 || echo not2'
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert "OLDER" in res.stdout
    assert "not2" in res.stdout


# ── The env file reaches wireconf without the -e warning ─────────────────────
#
# Through 0.3.8, passing -e once makes wireconf print "Multiple -e/--env-file flags;
# only the first was sourced (ignoring <path>)" on every invocation: its pre-scan loads
# the file and sets WC_ENV_FILE_EXPLICIT=1, then its main parser meets the same flag and
# counts it as a second. The file is loaded — but a warning telling an operator their
# configuration was ignored, on every deploy, is not something to leave in place.


def _recording_stub(tmp_path: Path) -> tuple[Path, Path]:
    """A wireconf that records its argv, cwd, and whether ./wireconf.env was readable."""
    log = tmp_path / "invocations"
    binary = tmp_path / "wireconf-rec"
    binary.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-V" ]; then echo "wireconf 0.3.8"; exit 0; fi\n'
        f'{{ printf "cwd=%s args=%s env_readable=%s\\n" "$(pwd)" "$*" '
        f'"$([ -r ./wireconf.env ] && echo yes || echo no)"; }} >> "{log}"\n'
        "exit 0\n"
    )
    binary.chmod(0o755)
    return binary, log


def _live_vpn(tmp_path: Path, binary: Path):
    """Not dry-run: dry-run exits before wireconf is invoked. `.invalid` hosts fail
    DNS immediately, so the ping nudges cost nothing."""
    return _run(
        tmp_path,
        {
            "DEPLOY_HOSTS": "hub.invalid,peer.invalid",
            "DEPLOY_VPN": "wireconf",
            "WIRECONF_BIN": str(binary),
            "DEPLOY_VPN_RETRIES": "1",
            "DEPLOY_VPN_DELAY": "0",
            "DEPLOY_ENV_DIR": str(tmp_path / "envs"),
        },
        dry_run=False,
    )


def test_the_env_file_is_auto_loaded_rather_than_named_with_a_flag(tmp_path: Path):
    binary, log = _recording_stub(tmp_path)
    _live_vpn(tmp_path, binary)
    invocations = log.read_text(encoding="utf-8")
    assert invocations, "wireconf was never invoked"
    assert "-e" not in invocations, "passing -e makes wireconf warn that it ignored the config"
    assert "env_readable=yes" in invocations, "the config must be readable from wireconf's cwd"


def test_wireconf_runs_from_the_workdir_holding_its_config(tmp_path: Path):
    binary, log = _recording_stub(tmp_path)
    _live_vpn(tmp_path, binary)
    for line in log.read_text(encoding="utf-8").splitlines():
        assert "logstotal-wireconf." in line.split(" args=")[0], line


def test_the_three_phases_run_in_order(tmp_path: Path):
    """plan, then -y apply, then verify — not `wireconf up`, whose single verify cannot
    survive a tunnel that has no handshake until traffic crosses it."""
    binary, log = _recording_stub(tmp_path)
    _live_vpn(tmp_path, binary)
    args = [line.split("args=")[1].split(" env_readable")[0] for line in log.read_text(encoding="utf-8").splitlines()]
    assert any(a.endswith("plan") for a in args)
    assert any("-y apply" in a for a in args)
    assert any(a.endswith("verify") for a in args)


def test_a_relative_wireconf_path_survives_the_directory_change(tmp_path: Path):
    """run_wireconf cds into the workdir, so a relative WIRECONF_BIN would vanish."""
    binary, log = _recording_stub(tmp_path)
    env = {
        "DEPLOY_HOSTS": "hub.invalid,peer.invalid",
        "DEPLOY_VPN": "wireconf",
        "WIRECONF_BIN": f"./{binary.name}",
        "DEPLOY_VPN_RETRIES": "1",
        "DEPLOY_VPN_DELAY": "0",
        "DEPLOY_ENV_DIR": str(tmp_path / "envs"),
    }
    result = _run(tmp_path, env, dry_run=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert log.exists(), "the binary was not found after the cd"


# ── A verify failure is only survivable when the tunnel is actually up ───────
#
# Recording the addresses after a failed verify pointed every worker's DATABASE_URL,
# REDIS_URL and S3_ENDPOINT at a VPN address that did not answer, while the deploy
# reported success — jobs in `pending`, nothing in any log. But failing on the verify
# alone would be wrong too: wireconf verifies by pinging, and hardened hosts drop ICMP
# while carrying traffic fine. So the WireGuard handshake is the signal.


def _failing_verify_stub(tmp_path: Path) -> Path:
    binary = tmp_path / "wireconf-badverify"
    binary.write_text('#!/bin/sh\nif [ "$1" = "-V" ]; then echo "wireconf 0.3.8"; exit 0; fi\nfor a in "$@"; do [ "$a" = "verify" ] && exit 1; done\nexit 0\n')
    binary.chmod(0o755)
    return binary


def _handshake_shim(tmp_path: Path, stamps: str) -> Path:
    """Shadow ssh so `wg show … latest-handshakes` answers with our stamps."""
    d = tmp_path / "sshshim"
    d.mkdir(exist_ok=True)
    ssh = d / "ssh"
    ssh.write_text(f"#!/bin/sh\ncase \"$*\" in\n  *latest-handshakes*) printf '%s' '{stamps}' ;;\nesac\nexit 0\n")
    ssh.chmod(0o755)
    return d


def _verify_run(tmp_path: Path, stamps: str, extra: dict[str, str] | None = None):
    env = {
        "DEPLOY_HOSTS": "hub.invalid,peer.invalid",
        "DEPLOY_VPN": "wireconf",
        "WIRECONF_BIN": str(_failing_verify_stub(tmp_path)),
        "DEPLOY_VPN_RETRIES": "1",
        "DEPLOY_VPN_DELAY": "0",
        "DEPLOY_CP_ADDRESS": "10.200.0.1",
        "DEPLOY_ENV_DIR": str(tmp_path / "envs"),
        "PATH": f"{_handshake_shim(tmp_path, stamps)}{os.pathsep}{path_without('wireconf')}",
    }
    env.update(extra or {})
    return _run(tmp_path, env, dry_run=False)


def test_a_dead_tunnel_stops_the_deploy(tmp_path: Path):
    """No handshake at all: the tunnel carries nothing, so the addresses must not be
    recorded and no worker may be pointed at them."""
    result = _verify_run(tmp_path, "abc=\t0\n")
    assert result.returncode != 0
    assert "0 of 1 peer(s)" in result.stderr
    assert "every job would sit in pending" in result.stderr
    assert not (tmp_path / "envs" / "vpn.json").exists(), "a map for a dead tunnel must not be written"


def test_a_partially_dead_tunnel_stops_the_deploy(tmp_path: Path):
    result = _verify_run(tmp_path, "abc=\t1787000000\ndef=\t0\n")
    assert result.returncode != 0
    assert "1 of 2 peer(s)" in result.stderr


def test_filtered_icmp_with_a_live_tunnel_continues(tmp_path: Path):
    """Verify pings fail, every peer has shaken hands: a firewall dropping ICMP, not a
    broken tunnel. Refusing here would block a working deployment."""
    result = _verify_run(tmp_path, "abc=\t1787000000\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "completed a WireGuard handshake" in result.stderr
    assert "dropped by a firewall" in result.stderr
    assert (tmp_path / "envs" / "vpn.json").exists()


def test_a_dead_tunnel_can_still_be_overridden(tmp_path: Path):
    result = _verify_run(tmp_path, "abc=\t0\n", {"DEPLOY_VPN_OPTIONAL": "true"})
    assert result.returncode == 0
    assert "continuing over the public addresses" in result.stderr


# ── The missing build_ssh_opts ───────────────────────────────────────────────
#
# This script was the only ssh-using deploy script that never called build_ssh_opts,
# and an unset bash array expands to nothing SILENTLY even under `set -u` — so the
# whole VPN step ran with no BatchMode (password prompts block forever), no
# ConnectTimeout (a filtered host stalls at TCP connect inside the retry loop), no
# host-key auto-accept, and SSH_IDENTITY quietly ignored. That was the reported hang.
#
# Asserted against the source rather than behaviour: the defect is an absent call, and
# the dry-run seam returns before any of those options could be observed.


def test_deploy_vpn_builds_ssh_opts_before_its_first_remote_call():
    src = SCRIPT.read_text(encoding="utf-8")
    assert "\nbuild_ssh_opts\n" in src, "deploy-vpn.sh must call build_ssh_opts"
    first_call = min(
        (src.index(tok) for tok in ("host_exec ", "resolve_from ", "host_primary_address ") if tok in src),
        default=-1,
    )
    assert first_call > 0
    assert src.index("\nbuild_ssh_opts\n") < first_call, "build_ssh_opts must run before the first remote call, or SSH_OPTS is empty for it"


def test_wireconf_is_given_ssh_opts_it_will_actually_read():
    """Wireconf sets WC_SSH_OPTS="${SSH_OPTS:-}" and splices it into every ssh/scp it
    runs. It passes -T/BatchMode/ConnectTimeout itself, but not RemoteCommand=none — so
    on a host whose ~/.ssh/config carries RemoteCommand, its own calls die with
    "Cannot execute command-line and remote command." while ours succeed."""
    src = SCRIPT.read_text(encoding="utf-8")
    run_fn = src.split("run_wireconf() {")[1].split("}")[0]
    assert "SSH_OPTS=" in run_fn and "RemoteCommand=none" in run_fn


def test_the_wireguard_port_is_written_into_the_config_not_just_an_error_string():
    """WG_PORT_LABEL only ever appeared in the "check UDP <port>" hint while the written
    config set no port, so the advice could name a port the tunnel was not using."""
    src = SCRIPT.read_text(encoding="utf-8")
    # The name may survive in the comment explaining why it went; what must not survive
    # is any code using it.
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert "WG_PORT_LABEL" not in code
    assert "printf 'WG_PORT=%s\\n'" in src, "WG_PORT is wireconf's key: WC_PORT=${WG_PORT:-51820}"


def test_a_live_tunnel_leaves_the_retry_loop_on_the_first_attempt(tmp_path: Path):
    """verify pings, and a host dropping ICMP fails it while carrying traffic fine. With
    handshakes present the loop must stop immediately instead of always paying
    RETRIES x DELAY — measured against a fleet running ufw's default deny."""
    result = _verify_run(tmp_path, "abc=\t1787000000\n", {"DEPLOY_VPN_RETRIES": "8", "DEPLOY_VPN_DELAY": "3"})
    assert result.returncode == 0, result.stdout + result.stderr
    # stdout, not stderr: the per-attempt line is info(), and checking the wrong stream
    # would make this pass whether or not the retry loop ran.
    assert "retrying in" not in result.stdout, "it paid the retry loop despite a live tunnel"


def test_an_unreadable_peer_table_is_not_reported_as_zero_peers(tmp_path: Path):
    """PEERS_TOTAL=0 means "could not ask the hub", not "no peer has shaken hands".
    Reporting it as "0 of 0 peer(s)" reads like a parse bug and sends the operator to
    the firewall when the hub itself is what did not answer."""
    result = _verify_run(tmp_path, "")
    assert result.returncode != 0
    assert "0 of 0 peer(s)" not in result.stderr
    assert "Could not read the peer table" in result.stderr
