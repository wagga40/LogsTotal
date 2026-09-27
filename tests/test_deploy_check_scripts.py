"""Behavior tests for the extracted deploy check/scaffold scripts.

Covers scripts/deploy-preflight.sh, deploy-smoke.sh, deploy-env-scaffold.sh,
and health-remote.sh. Mirrors tests/test_deploy_multiserver.py and
tests/test_backup_scripts.py: real bash, an isolated tmp_path cwd, a scrubbed
environment, and assertions on stdout/stderr text + return codes.

Each script resolves scripts/lib/common.sh relative to its own location, so
invoking the repo's script from a tmp_path cwd works while keeping all of its
cwd-relative state (deploy-envs/, deploy.env, …) inside the throwaway directory.
Where a script would otherwise make real network/SSH calls, the tests either run
it in DEPLOY_DRY_RUN mode (preflight) or shadow `curl` with a PATH shim.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = {
    "preflight": REPO_ROOT / "scripts" / "deploy-preflight.sh",
    "smoke": REPO_ROOT / "scripts" / "deploy-smoke.sh",
    "env-scaffold": REPO_ROOT / "scripts" / "deploy-env-scaffold.sh",
    "health-remote": REPO_ROOT / "scripts" / "health-remote.sh",
    "env-push": REPO_ROOT / "scripts" / "deploy-env-push.sh",
    "env-fleet": REPO_ROOT / "scripts" / "deploy-env-fleet.sh",
}

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _run(
    script: str,
    tmp_path: Path,
    env_overrides: dict[str, str] | None = None,
    path_prefix: Path | None = None,
    args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one of the deploy-check scripts from an isolated cwd + scrubbed env."""
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_") or key.startswith("BASIC_AUTH_"):
            env.pop(key, None)
    # The prefix rule above misses every input these scripts read under a bare name, and
    # two of those are live hazards rather than theoretical ones. `PROXY_TLS` is a
    # documented .env key and deploy-smoke.sh reads it at HIGHEST precedence (above
    # DEPLOY_PROXY_TLS and deploy.env), while Taskfile.yml declares `dotenv: ['.env']` — so
    # `task test` on a machine whose .env says `PROXY_TLS=off` fails three smoke tests.
    # `FORCE` is the Taskfile's own spelling for restores, and `FORCE=yes` disarms exactly
    # the overwrite refusal that test_env_scaffold_refuses_to_overwrite_existing_files pins.
    for var in ("SSH_IDENTITY", "SMOKE_URL", "DOMAIN", "HEALTH_URL", "PROXY_TLS", "FORCE"):
        env.pop(var, None)
    # Point at an absent deploy.env so a real one can't leak in; tests that want
    # file-provided defaults override DEPLOY_ENV_FILE explicitly.
    env["DEPLOY_ENV_FILE"] = str(tmp_path / "deploy.env.absent")
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env.get('PATH', '')}"
    if env_overrides:
        env.update(env_overrides)
    cmd = ["bash", str(SCRIPTS[script])]
    if args:
        cmd.extend(args)
    return subprocess.run(cmd, cwd=tmp_path, env=env, capture_output=True, text=True, check=False)


def _make_curl_shim(
    tmp_path: Path,
    stdout: str,
    exit_code: int = 0,
    *,
    record: Path | None = None,
    body: str | None = None,
) -> Path:
    """Create a dir with a `curl` shim that ignores its args, prints `stdout`.

    With `record`, it also appends its own argv there — which is the only way to see the
    flags the probes are built with, since the shim's output is fixed.

    `body` splits the two things a smoke run actually asks for: the `-w %{http_code}` probe
    gets `stdout`, and a plain fetch gets `body`. Without it a shim can only express
    code == body, so an HTTP status carrying something that is NOT a health document — a
    proxy's 502 page, a 404, a transfer truncated mid-JSON — was unrepresentable. That blind
    spot is why deploy-smoke.sh could print three confident subsystem failures under an
    `OK /health (200)` line and no test noticed.
    """
    d = tmp_path / "shim"
    d.mkdir(exist_ok=True)
    curl = d / "curl"
    log = f'printf "%s\\n" "$*" >> {shlex.quote(str(record))}\n' if record else ""
    if body is None:
        emit = f"printf '%s' {shlex.quote(stdout)}\n"
    else:
        # Faithful enough to curl to be worth trusting: honour -o /dev/null (deploy-smoke
        # suppresses the body on its code probes) and substitute into whatever -w format was
        # given (health-remote asks for body AND code in one request, via -w '\n%{http_code}').
        emit = (
            'OUT_NULL=no; FMT=""; prev=""\n'
            'for a in "$@"; do\n'
            '  [ "$prev" = "-o" ] && [ "$a" = "/dev/null" ] && OUT_NULL=yes\n'
            '  [ "$prev" = "-w" ] && FMT="$a"\n'
            '  prev="$a"\n'
            "done\n"
            f'[ "$OUT_NULL" = "no" ] && printf \'%s\' {shlex.quote(body)}\n'
            f"[ -n \"$FMT\" ] && printf '%b' \"$(printf '%s' \"$FMT\" | sed 's/%{{http_code}}/{stdout}/g')\"\n"
        )
    curl.write_text(f"#!/bin/sh\n{log}{emit}exit {exit_code}\n")
    curl.chmod(0o755)
    return d


# ── deploy-preflight.sh ─────────────────────────────────────────────────────────


def test_preflight_missing_hosts_fails(tmp_path: Path):
    result = _run("preflight", tmp_path)
    assert result.returncode == 1
    assert "FAIL: DEPLOY_HOSTS is required (comma-separated host list)." in result.stdout


def test_preflight_dry_run_passes_and_traces_ssh(tmp_path: Path):
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_DRY_RUN": "true", "DEPLOY_HOSTS": "cp.example,w1.example"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Per-host headers, control plane first.
    cp = result.stdout.index("=== cp.example (control-plane) ===")
    w1 = result.stdout.index("=== w1.example (worker) ===")
    assert cp < w1
    # NOT "PREFLIGHT PASSED". A dry run connects to nothing, so it measures nothing, so
    # it cannot certify a host as ready — and "all 2 host(s) ready for deployment" after
    # zero connections is the most dangerous line this script could print.
    assert "PREFLIGHT NOT RUN (dry run)" in result.stdout
    assert "PASSED" not in result.stdout
    # The dry-run seam traces to STDERR (so numeric captures on stdout stay empty).
    assert "DRY-RUN ssh root@cp.example" in result.stderr
    assert "DRY-RUN ssh root@w1.example" in result.stderr
    # Nothing leaked into stdout that would break the numeric guards.
    assert "DRY-RUN" not in result.stdout


def test_preflight_deploy_env_file_provides_defaults_but_env_wins(tmp_path: Path):
    deploy_env = tmp_path / "deploy.env"
    deploy_env.write_text("DEPLOY_HOSTS=filehost.example.com\n", encoding="utf-8")
    # From the file:
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_ENV_FILE": str(deploy_env), "DEPLOY_DRY_RUN": "true"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "=== filehost.example.com (control-plane) ===" in result.stdout
    # Caller env overrides the file:
    result = _run(
        "preflight",
        tmp_path,
        {
            "DEPLOY_ENV_FILE": str(deploy_env),
            "DEPLOY_HOSTS": "envhost.example.com",
            "DEPLOY_DRY_RUN": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "=== envhost.example.com (control-plane) ===" in result.stdout
    assert "filehost.example.com" not in result.stdout


# ── deploy-preflight.sh: the firewall probe ─────────────────────────────────
#
# It runs whatever DEPLOY_VPN says. Gating it on the tunnel would be backwards: a fleet with
# no tunnel has Redis, PostgreSQL and Garage on a routable interface, and that is the one
# whose firewall matters most.


def _make_dying_ssh_shim(tmp_path: Path, die_after: int) -> Path:
    """An `ssh` that answers the first `die_after` calls, then fails with 255 forever.

    255 is ssh's own error code — it never comes from the remote command — which is the
    only reliable way to tell "the host said no" from "the host never answered". A session
    that drops partway is the realistic shape: the reachability gate at the top of the host
    loop has already passed by then.
    """
    d = tmp_path / "dyingssh"
    d.mkdir(exist_ok=True)
    counter = d / "calls"
    (d / "ssh").write_text(f"""#!/bin/bash
for arg in "$@"; do
  if [ "$arg" = "-G" ]; then printf 'hostname %s\n' "${{@: -1}}"; exit 0; fi
done
n=$(cat {counter} 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > {counter}
[ "$n" -gt {die_after} ] && exit 255
case "$*" in
  *shell-ok*)      printf 'shell-ok-0\n' ;;
  *"command -v"*)  printf '/usr/bin/thing\n' ;;
  *"df -k"*)       printf '99000000\n' ;;
  *MemAvailable*)  printf '8000000\n' ;;
  *"grep -c ."*)   printf '0\n' ;;
esac
exit 0
""")
    (d / "ssh").chmod(0o755)
    return d


@pytest.mark.parametrize(
    ("die_after", "must_not_say"),
    [
        (2, "did not survive"),
        (6, "not found."),
    ],
)
def test_preflight_reports_a_lost_session_as_a_lost_session(tmp_path, die_after, must_not_say):
    """`_ssh` returns non-zero for two unrelated reasons and every caller conflated them.

    A dropped session made the remote command "fail", so the check that happened to be
    running claimed its own subject was broken: four `<tool> not found` lines with four
    apt-get commands attached, or `a POSIX command did not survive this host's login shell`
    pointing at root's shell and at lib/common.sh::shquote. In both cases the actual fault —
    the session — was named nowhere in the report.
    """
    shim = _make_dying_ssh_shim(tmp_path, die_after)
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example.com", "DEPLOY_REMOTE_DIR": "/opt/logstotal"},
        path_prefix=shim,
    )
    out = result.stdout + result.stderr

    assert "lost the SSH session" in out, out[-1500:]
    assert out.count("lost the SSH session to") == 1, "reported once per host, not per check"
    assert must_not_say not in out, f"blamed the check's own subject for a dead session:\n{out[-1500:]}"
    assert "SKIP remaining checks" in out, "kept asking a host that could not answer"


def test_preflight_plan_does_not_call_an_unreachable_host_a_fresh_install(tmp_path: Path):
    """The worst verdict this can produce.

    Every probe answers "absent" when the session is gone — no VERSION file, no data
    directories — which is indistinguishable from a brand new box. FRESH INSTALL then
    invites a full first-time deploy over a live installation.
    """
    # 14: far enough in that every earlier check passed, so nothing else has already set
    # a BLOCKED reason — the session dies at the classification step itself, which is the
    # only way to reach the FRESH INSTALL branch.
    shim = _make_dying_ssh_shim(tmp_path, 14)
    result = _run(
        "preflight",
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com",
            "DEPLOY_REMOTE_DIR": "/opt/logstotal",
            "DEPLOY_PLAN_ONLY": "true",
        },
        path_prefix=shim,
    )
    out = result.stdout + result.stderr

    assert "FRESH INSTALL" not in out, f"classified a host it could not reach:\n{out[-1500:]}"
    assert "VERDICT: BLOCKED" in out
    assert "1 blocked" in out
    assert result.returncode == 0, "a plan is read-only and always exits 0"


def _make_ssh_shim(tmp_path: Path, *, firewall: str = "ufw-active", allowed: str = "") -> Path:
    """An `ssh` that stands in for a healthy host, and **runs the firewall probes for real**.

    The split is deliberate. Everything unrelated (tool presence, disk, the login-shell
    marker) is answered from a pattern, because simulating it faithfully proves nothing
    about the code under test. The firewall probe is executed against fake `ufw` /
    `firewall-cmd` binaries, because the real probe is `ufw status | grep -cE ...` — and a
    shim that answers the whole pipeline as one string never runs the grep, so a host with
    no rule at all reports the port allowed. That false OK is exactly what this guards.

    Its PATH is **hermetic**, and that is load-bearing rather than tidy. `firewall="none"`
    says "this host has no firewall manager" by deleting the two fakes — but with the host's
    own PATH still trailing, `command -v ufw` would find the *runner's* real /usr/sbin/ufw,
    run it as a non-root user and get an empty answer back — passing on macOS, which has no
    ufw anywhere, and failing on a Linux CI runner, which does. So the probes run
    against `d` alone: a name that is not in it is genuinely absent, on every machine.

    `allowed` is a space-separated list of `port/proto` the fake firewall permits.
    """
    d = tmp_path / "sshshim"
    d.mkdir(exist_ok=True)

    # The userland those probes need, linked in so PATH can be `d` and nothing else.
    # `head`/`grep`/`tr` are the pipe stages — `ufw status | head -1`,
    # `ufw status | grep -cE ...`, `firewall-cmd --list-ports | tr ' ' '\n' | grep -cx ...`.
    # `bash` is there because host_exec sends `ssh <host> bash -c '<snippet>'`, so what
    # arrives here is itself a bash invocation: the snippet is one level further in than it
    # looks. Extend this list if a probe grows another stage — a missing name does not raise,
    # it returns empty, and the script reads that as a host that never answered.
    for util in ("bash", "head", "grep", "tr"):
        real = shutil.which(util)
        assert real is not None, f"the firewall probes pipe through {util}"
        link = d / util
        if not link.exists():
            link.symlink_to(real)

    rules = "\n".join(f"{port:<26}ALLOW       Anywhere" for port in allowed.split())
    ufw_state = "active" if firewall == "ufw-active" else "inactive"
    (d / "ufw").write_text(f"""#!/bin/bash
[ "$1" = "status" ] || exit 0
printf 'Status: {ufw_state}\\n'
[ "{ufw_state}" = "active" ] || exit 0
printf '%s\\n' "{rules}"
""")
    (d / "firewall-cmd").write_text(f"""#!/bin/bash
case "$1" in
  --state) printf 'running\\n' ;;
  --list-ports) printf '%s\\n' "{allowed}" ;;
esac
""")
    if firewall == "none":
        (d / "ufw").unlink()
        (d / "firewall-cmd").unlink()
    elif firewall == "firewalld":
        (d / "ufw").unlink()

    (d / "ssh").write_text(r"""#!/bin/bash
SHIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for arg in "$@"; do
  if [ "$arg" = "-G" ]; then printf 'hostname %s\n' "${@: -1}"; exit 0; fi
done
# ssh JOINS everything after the destination and hands one string to the remote login
# shell — it does not exec argv. Taking only the last argument leaves the command still
# wrapped in the single quotes shquote added, so the remote shell would try to run a
# command literally named "if command -v ufw ...". That is ssh's actual contract, and
# lib/common.sh::shquote exists because of it.
args=("$@")
i=0
while [ "$i" -lt "${#args[@]}" ]; do
  case "${args[$i]}" in
    -o|-i|-p|-F|-l) i=$((i + 2)); continue ;;
    -*) i=$((i + 1)); continue ;;
  esac
  break
done
cmd="${args[*]:$((i + 1))}"
# The firewall probes run for real, against the fakes above — and against NOTHING else:
# PATH is the shim dir alone, so a deleted fake is an absent binary rather than a fall-
# through to the host's own. `bash` is named absolutely because a temporary `PATH=x cmd`
# assignment governs the lookup of `cmd` itself, so the plain spelling would not resolve.
case "$cmd" in
  *ufw*|*firewall-cmd*) PATH="$SHIM_DIR" "$BASH" -c "$cmd"; exit $? ;;
  *"ip link show"*) exit 1 ;;
esac
# Everything else is answered plausibly: these tests are about the firewall, and a host
# that fails ten unrelated probes never reaches it.
case "$cmd" in
  *shell-ok*) printf 'shell-ok-0\n' ;;
  *"df -k"*) printf '99000000\n' ;;
  *MemAvailable*) printf '8000000\n' ;;
  *"date +%s"*) date +%s ;;
  *"docker compose version"*) printf 'Docker Compose version v2.30.0\n' ;;
  *"docker info"*|*"docker version"*) printf 'Server Version: 27.0\n' ;;
  *"id -u"*) printf '0\n' ;;
  *"command -v"*) printf '/usr/bin/stub\n' ;;
  *) printf '\n' ;;
esac
exit 0
""")
    for name in ("ssh", "ufw", "firewall-cmd"):
        f = d / name
        if f.exists():
            f.chmod(0o755)
    return d


def test_the_firewall_is_reported_even_without_a_vpn(tmp_path: Path):
    """The case that had no report at all: no tunnel, so the relays are public."""
    shim = _make_ssh_shim(tmp_path, firewall="ufw-active", allowed="22/tcp")
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "none", "DEPLOY_PLAN_ONLY": "true"},
        path_prefix=shim,
    )
    out = result.stdout
    assert "firewall: ufw, active" in out
    # Redis / PostgreSQL / Garage are named, not left as numbers.
    for port, service in (("6379", "Redis"), ("5432", "PostgreSQL"), ("3900", "Garage")):
        assert port in out and service in out, f"{port} ({service}) missing from:\n{out}"


def test_a_tunnelled_port_is_not_demanded_on_the_public_interface(tmp_path: Path):
    """Telling someone to open 5432 when the VPN exists to keep it closed would teach
    exactly the wrong lesson."""
    shim = _make_ssh_shim(tmp_path, firewall="ufw-active", allowed="22/tcp 51820/udp")
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "wireconf", "DEPLOY_PLAN_ONLY": "true"},
        path_prefix=shim,
    )
    assert "WARN: 5432/tcp has no matching allow rule" not in result.stdout
    assert "WARN: 6379/tcp has no matching allow rule" not in result.stdout


def test_docker_published_ports_are_explained_not_demanded(tmp_path: Path):
    """Measured on a real fleet: ufw active allowing only 22 and 51820, and
    http://cp:8000 answered 200. Docker publishes through nat and FORWARD, never INPUT.

    Reporting those as "no matching allow rule" reads as "your app is unreachable" — which
    is false — and sends the operator to run a command that changes nothing.
    """
    shim = _make_ssh_shim(tmp_path, firewall="ufw-active", allowed="22/tcp")
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "none", "DEPLOY_PLAN_ONLY": "true"},
        path_prefix=shim,
    )
    assert "has no matching allow rule" not in result.stdout
    assert "bypass ufw (Docker writes nat/FORWARD, not INPUT)" in result.stdout
    assert "ufw allow 6379" not in result.stdout, "advice that changes nothing is worse than none"


def test_the_hub_wireguard_port_is_still_checked_because_ufw_governs_it(tmp_path: Path):
    """The one port on this list that is a host service rather than a container."""
    shim = _make_ssh_shim(tmp_path, firewall="ufw-active", allowed="22/tcp 51820/udp")
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "wireconf", "DEPLOY_PLAN_ONLY": "true"},
        path_prefix=shim,
    )
    assert "OK   51820/udp allowed" in result.stdout


def test_a_missing_hub_port_is_information_when_bootstrap_will_open_it(tmp_path: Path):
    """deploy-bootstrap.sh opens it itself under wireconf, which is the default. Reporting
    BLOCKED for something the very next phase fixes stops an operator who had nothing to
    do — the mirror of claiming OK for something unmeasured."""
    shim = _make_ssh_shim(tmp_path, firewall="ufw-active", allowed="22/tcp")
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "wireconf", "DEPLOY_PLAN_ONLY": "true"},
        path_prefix=shim,
    )
    assert "51820/udp not open yet — deploy:bootstrap adds it" in result.stdout
    assert "VERDICT: BLOCKED" not in result.stdout


def test_a_missing_hub_port_is_fatal_when_nothing_will_open_it(tmp_path: Path):
    shim = _make_ssh_shim(tmp_path, firewall="ufw-active", allowed="22/tcp")
    result = _run(
        "preflight",
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example,w1.example",
            "DEPLOY_VPN": "wireconf",
            "DEPLOY_OPEN_WG_PORT": "false",
            "DEPLOY_PLAN_ONLY": "true",
        },
        path_prefix=shim,
    )
    assert "FAIL: ufw is active on the hub and does not allow 51820/udp" in result.stdout
    assert "DEPLOY_OPEN_WG_PORT is off" in result.stdout


def test_no_firewall_manager_says_nothing_is_filtering(tmp_path: Path):
    shim = _make_ssh_shim(tmp_path, firewall="none")
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example", "DEPLOY_VPN": "none", "DEPLOY_PLAN_ONLY": "true"},
        path_prefix=shim,
    )
    assert "no firewall manager detected" in result.stdout


def test_the_probe_cannot_see_the_hosts_own_firewall(tmp_path: Path):
    """The shim says "absent"; the machine running the suite must not get a vote.

    `firewall="none"` deletes the two fakes, and for a long time that was all it did — the
    host's own PATH still trailed the shim's, so on a runner with /usr/sbin/ufw installed
    the probe found the REAL ufw, ran it as a non-root user, and came back empty. The
    script then correctly said it could not determine anything, and this file's neighbour
    test failed. It went unnoticed because it only fails where ufw is installed: green on
    macOS, red on the Linux CI runner, and before the script learned to tell "" from
    "none" it had been passing there for the wrong reason.
    """
    shim = _make_ssh_shim(tmp_path, firewall="none")

    hostbin = tmp_path / "hostbin"
    hostbin.mkdir()
    # A faithful stand-in for /usr/sbin/ufw reached by someone who is not root: the refusal
    # goes to stderr, stdout is empty. That empty answer is the whole trap.
    (hostbin / "ufw").write_text('#!/bin/sh\necho "ERROR: You need to be root to run this script" >&2\nexit 1\n')
    (hostbin / "ufw").chmod(0o755)

    result = _run(
        "preflight",
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example",
            "DEPLOY_VPN": "none",
            "DEPLOY_PLAN_ONLY": "true",
            # Set here rather than via path_prefix= because _run applies env_overrides last:
            # the shim still comes first, and the host's firewall sits behind it exactly as
            # it does on a real machine.
            "PATH": f"{shim}{os.pathsep}{hostbin}{os.pathsep}{os.environ.get('PATH', '')}",
        },
    )

    assert "no firewall manager detected" in result.stdout, result.stdout
    assert "could not determine the firewall" not in result.stdout


def test_a_dry_run_probes_no_firewall_at_all(tmp_path: Path):
    """`_ssh` returns 0 with empty stdout in a dry run, so every probe would 'succeed' and
    the report would describe a host nobody contacted."""
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_VPN": "wireconf", "DEPLOY_DRY_RUN": "true"},
    )
    assert "wg0 already present" not in result.stdout
    assert "firewall" not in result.stdout.lower()


# ── deploy-smoke.sh ─────────────────────────────────────────────────────────────


def test_smoke_all_probes_fail_reports_failure(tmp_path: Path):
    shim = _make_curl_shim(tmp_path, "000")
    result = _run(
        "smoke",
        tmp_path,
        {"SMOKE_URL": "http://smoke.example:9"},
        path_prefix=shim,
    )
    assert result.returncode == 1
    assert "Smoke-testing: http://smoke.example:9" in result.stdout
    assert "  FAIL /health" in result.stdout
    assert "  FAIL / homepage" in result.stdout
    assert "  FAIL /auth/login" in result.stdout
    # The subsystems are SKIPped, not failed: nothing answered, so nothing was measured.
    # The probes above are the measured failures and they are what fails the run.
    assert "  SKIP database subsystem" in result.stdout
    # The count is deliberately not pinned: a probe added to catch a new class of broken
    # fleet should not have to edit this assertion, only the "nothing passed" claim.
    assert "SMOKE FAILED: 0 passed," in result.stdout
    # Three measured failures, not seven invented ones: the worker count comes out of a
    # /health body that never arrived, so it is unmeasured rather than failed.
    assert "SKIP workers" in result.stdout
    assert "FAIL no workers registered" not in result.stdout


@pytest.mark.parametrize(
    ("rc", "expected"),
    [
        (6, "could not resolve the host"),
        (7, "connection refused or no route"),
        (28, "timed out"),
        (60, "no certificate this machine trusts"),
    ],
)
def test_smoke_names_the_transport_failure_behind_a_000(tmp_path: Path, rc, expected):
    """A transport failure has to say which layer failed.

    `000` alone cannot separate "fix your DNS" from "the certificate is not issued yet",
    and both look identical to a 503 the deployment could actually answer. curl's exit
    status is the only thing that distinguishes them, so it is reported.

    This also pins the shape: curl writes `000` itself on failure, so a
    `$(curl -w '%{http_code}' ... || echo "000")` guard appends a SECOND one and prints
    `000000`. A shim that exits 0 never takes that path.
    """
    shim = _make_curl_shim(tmp_path, "000", exit_code=rc)
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://smoke.example"}, path_prefix=shim)

    assert "000000" not in result.stdout, "the 000 guard is double-appending again"
    assert "  FAIL /health (000 — " in result.stdout
    assert expected in result.stdout


@pytest.mark.parametrize(
    ("mode", "expect_insecure"),
    [("acme", False), ("internal", True), ("custom", True), ("off", False)],
)
def test_smoke_verifies_public_certificates_and_looks_past_private_ones(tmp_path: Path, mode, expect_insecure):
    """`internal` and `custom` serve a certificate no public CA vouches for.

    Verifying it makes every probe return 000, which is exactly what a dead deployment
    looks like — so a healthy internal fleet reported SMOKE FAILED with nothing to
    distinguish it from an outage. `acme` keeps full verification, because there an
    unverifiable certificate is a real finding rather than the expected state.
    """
    argv_log = tmp_path / "curl-argv.txt"
    shim = _make_curl_shim(tmp_path, "000", record=argv_log)
    _run(
        "smoke",
        tmp_path,
        {"DOMAIN": "domain.example", "PROXY_TLS": mode, "DEPLOY_HOSTS": "user@cp.example"},
        path_prefix=shim,
    )
    calls = argv_log.read_text(encoding="utf-8").splitlines()
    assert calls, "the smoke test made no curl calls at all"
    for call in calls:
        assert (" -k " in f" {call} ") == expect_insecure, f"{mode}: {call}"


def test_smoke_reads_the_deploy_env_spelling_of_domain(tmp_path: Path):
    """deploy.env spells it DEPLOY_DOMAIN, and only deploy-fleet.sh bridged the two.

    So `task deploy:smoke` on its own — and the smoke step of `task upgrade`,
    which loads only DEPLOY_HOSTS/SSH_IDENTITY/DEPLOY_REMOTE_DIR — did not know the
    deployment had a domain, fell through to http://<control-plane>:8000 and timed out.
    Behind Caddy that address is bound to 127.0.0.1 on purpose, so the packet is dropped
    rather than refused: seven FAILs on a deployment that had just passed an in-container
    doctor run one step earlier.
    """
    shim = _make_curl_shim(tmp_path, "000")
    (tmp_path / "deploy.env").write_text(
        "DEPLOY_HOSTS=cp.example,w1.example\nDEPLOY_DOMAIN=logs.example.com\nDEPLOY_PROXY_TLS=acme\n",
        encoding="utf-8",
    )

    result = _run("smoke", tmp_path, {"DEPLOY_ENV_FILE": str(tmp_path / "deploy.env")}, path_prefix=shim)
    assert "Smoke-testing: https://logs.example.com" in result.stdout
    assert ":8000" not in result.stdout, "fell through to the control-plane address again"


def test_smoke_env_domain_still_beats_the_deploy_env_one(tmp_path: Path):
    """Caller env wins, the precedence every deploy script shares."""
    shim = _make_curl_shim(tmp_path, "000")
    (tmp_path / "deploy.env").write_text("DEPLOY_DOMAIN=from-file.example\n", encoding="utf-8")

    result = _run(
        "smoke",
        tmp_path,
        {"DOMAIN": "from-env.example", "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env")},
        path_prefix=shim,
    )
    assert "Smoke-testing: https://from-env.example" in result.stdout


def test_smoke_authenticates_with_the_deploy_env_basic_auth_user(tmp_path: Path):
    """Basic auth turns every probe into a 401 unless the smoke test can authenticate.

    The username lives in deploy.env under DEPLOY_BASIC_AUTH_USER; here the password
    comes from the environment, which wins over the file.
    """
    argv_log = tmp_path / "curl-argv.txt"
    shim = _make_curl_shim(tmp_path, "000", record=argv_log)
    (tmp_path / "deploy.env").write_text("DEPLOY_DOMAIN=logs.example.com\nDEPLOY_BASIC_AUTH_USER=ops\n", encoding="utf-8")

    _run(
        "smoke",
        tmp_path,
        {
            "DEPLOY_BASIC_AUTH_PASSWORD": "s3cret",
            "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"),
        },
        path_prefix=shim,
    )
    calls = argv_log.read_text(encoding="utf-8").splitlines()
    assert calls, "the smoke test made no curl calls at all"
    assert all("-u ops:s3cret" in call for call in calls), calls


def test_smoke_authenticates_with_a_password_stored_in_deploy_env(tmp_path: Path):
    """deploy.env offers DEPLOY_BASIC_AUTH_PASSWORD, so smoke has to read it.

    deploy-fleet.sh reads it from there, so a smoke test that refused to would test a
    fleet deployed with the password in the file without it, and 401 on every probe."""
    argv_log = tmp_path / "curl-argv.txt"
    shim = _make_curl_shim(tmp_path, "000", record=argv_log)
    (tmp_path / "deploy.env").write_text(
        "DEPLOY_DOMAIN=logs.example.com\nDEPLOY_BASIC_AUTH_USER=admin\nDEPLOY_BASIC_AUTH_PASSWORD=from-the-file\n",
        encoding="utf-8",
    )

    _run("smoke", tmp_path, {"DEPLOY_ENV_FILE": str(tmp_path / "deploy.env")}, path_prefix=shim)
    calls = argv_log.read_text(encoding="utf-8").splitlines()
    assert calls, "the smoke test made no curl calls at all"
    assert all("-u admin:from-the-file" in call for call in calls), calls


def test_an_environment_password_still_beats_the_stored_one(tmp_path: Path):
    """Caller env wins, the precedence every deploy script shares."""
    argv_log = tmp_path / "curl-argv.txt"
    shim = _make_curl_shim(tmp_path, "000", record=argv_log)
    (tmp_path / "deploy.env").write_text(
        "DEPLOY_DOMAIN=logs.example.com\nDEPLOY_BASIC_AUTH_USER=admin\nDEPLOY_BASIC_AUTH_PASSWORD=from-the-file\n",
        encoding="utf-8",
    )

    _run(
        "smoke",
        tmp_path,
        {"DEPLOY_BASIC_AUTH_PASSWORD": "from-the-env", "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env")},
        path_prefix=shim,
    )
    calls = argv_log.read_text(encoding="utf-8").splitlines()
    assert calls, "the smoke test made no curl calls at all"
    assert all("-u admin:from-the-env" in call for call in calls), calls


def test_smoke_does_not_invent_subsystem_failures_behind_an_auth_wall(tmp_path: Path):
    """A 401 says the deployment answered. It says nothing about the database.

    Every subsystem verdict is read out of one /health body. Behind basic auth that body is
    never obtained, so reporting "FAIL database subsystem" is a confident claim about
    something nobody measured — and it sends the operator to debug a healthy component. This
    is the mirror of the rule deploy-preflight.sh already follows the other way round: never
    report OK for something you could not measure.

    Reached whenever neither the environment nor deploy.env carried a password — the usual
    case when the fleet was deployed with one passed for that run alone.
    """
    shim = _make_curl_shim(tmp_path, "401")
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://logs.example.com"}, path_prefix=shim)

    # 0: skipped is not failed. `task deploy:smoke` printing "Failed to run task" for checks
    # that were never attempted reads as "the deployment is broken" when what happened is
    # that nobody supplied a password. The verdict is stated loudly in the output; the exit
    # status is not the place to report it. DEPLOY_SMOKE_STRICT=true is the opt-in for
    # automation that must gate on it.
    assert result.returncode == 0, "skipped checks must not be reported as a failure"
    assert "SMOKE COULD NOT VERIFY" in result.stdout
    assert "DEPLOY_BASIC_AUTH_PASSWORD" in result.stdout
    for claim in ("FAIL database subsystem", "FAIL redis subsystem", "FAIL storage subsystem"):
        assert claim not in result.stdout, f"invented a verdict for an unmeasured subsystem: {claim}"
    assert "FAIL no workers registered" not in result.stdout
    assert "SKIP database subsystem" in result.stdout
    assert "SKIP workers" in result.stdout


def test_smoke_does_not_call_one_401_both_a_failure_and_a_skip(tmp_path: Path):
    """The most prominent line of the run must not contradict every line under it.

    Against a real 401 server, deciding the /health verdict BEFORE the block that
    recognises an auth wall lets the else arm claim the 401 by default: the run opens with
    `FAIL /health (401)` and then says SKIP six times and `SMOKE COULD NOT VERIFY` once —
    one response, two answers, the wrong one first.

    The exit status is 0 either way, so everything that gates on the script agrees, and only
    the human reading it is told the deployment is broken.
    """
    shim = _make_curl_shim(tmp_path, "401")
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://logs.example.com"}, path_prefix=shim)

    assert "SKIP /health (401) — not measured (authentication required)" in result.stdout
    assert "FAIL /health" not in result.stdout, "the 401 is reported as a failure and as a skip at once"

    # The whole run in one vocabulary. Asserted as the exact sequence rather than a set, so
    # this also pins that all seven checks still report something: a check that silently
    # stopped printing would satisfy "no FAIL anywhere" perfectly.
    assert re.findall(r"^  (OK|FAIL|SKIP|INFO|UNKNOWN)\b", result.stdout, re.M) == ["SKIP"] * 7


def test_smoke_403_is_read_as_an_auth_wall_too(tmp_path: Path):
    """403 travels the same path as 401 everywhere else in this script; the /health line was
    the one place it did not."""
    shim = _make_curl_shim(tmp_path, "403")
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://logs.example.com"}, path_prefix=shim)

    assert "SKIP /health (403) — not measured (authentication required)" in result.stdout
    assert "FAIL" not in result.stdout


def test_smoke_still_fails_a_health_code_that_is_not_an_auth_wall(tmp_path: Path):
    """The guard rail on the new arm: only 401/403 earn the SKIP.

    A 502 is a proxy answering for an application that is not up — the deployment really is
    broken, and it must keep reading FAIL and exiting 1.
    """
    shim = _make_curl_shim(tmp_path, "502", body="<html>502 Bad Gateway</html>")
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://logs.example.com"}, path_prefix=shim)

    assert "FAIL /health (502)" in result.stdout
    assert "SKIP /health" not in result.stdout
    assert result.returncode == 1
    assert "SMOKE FAILED" in result.stdout


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not available")
def test_smoke_against_a_real_401_server(tmp_path: Path):
    """The shim above proves the logic; this proves the premise.

    Every other smoke test replaces curl, so all of them would still pass if a real 401 never
    produced the code the script branches on. This one runs the real binary against a real
    server on loopback — which is how the contradiction was found in the first place.
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="restricted"')
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = _run("smoke", tmp_path, {"SMOKE_URL": f"http://127.0.0.1:{port}"})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert "SKIP /health (401) — not measured (authentication required)" in result.stdout
    assert "FAIL" not in result.stdout, result.stdout
    assert "SMOKE COULD NOT VERIFY" in result.stdout
    assert result.returncode == 0


def test_smoke_strict_makes_unverified_a_failure_again(tmp_path: Path):
    """Exiting 0 on skipped is right for an operator at a terminal and wrong for a pipeline
    that gates on this step, so the strict behaviour stays reachable rather than removed."""
    shim = _make_curl_shim(tmp_path, "401")
    result = _run(
        "smoke",
        tmp_path,
        {"SMOKE_URL": "https://logs.example.com", "DEPLOY_SMOKE_STRICT": "true"},
        path_prefix=shim,
    )
    assert result.returncode == 2
    assert "SMOKE COULD NOT VERIFY" in result.stdout


def test_smoke_a_real_failure_is_still_a_failure_however_lenient_the_skip_path_is(tmp_path):
    """The guard rail on the leniency: only the auth wall exits 0."""
    shim = _make_curl_shim(tmp_path, "000", exit_code=7)
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://logs.example.com"}, path_prefix=shim)
    assert result.returncode == 1, "a measured failure must never exit 0"
    assert "SMOKE FAILED" in result.stdout


def test_smoke_separates_rejected_credentials_from_absent_ones(tmp_path: Path):
    """ "Supply a password" is useless advice to someone who just supplied one."""
    shim = _make_curl_shim(tmp_path, "401")
    result = _run(
        "smoke",
        tmp_path,
        {
            "SMOKE_URL": "https://logs.example.com",
            "BASIC_AUTH_USER": "ops",
            "BASIC_AUTH_PASS": "wrong",
        },
        path_prefix=shim,
    )

    # `warn` goes to stderr and the explanation to stdout; the operator reads both.
    output = result.stdout + result.stderr
    assert "credentials supplied were rejected" in output
    assert "BASIC_AUTH_HASH" in output, "should point at the hash the CP was deployed with"
    assert "Re-run with the password" not in result.stdout.split("SMOKE COULD NOT VERIFY")[0], (
        "telling someone who supplied a password to supply one is the advice that wastes the hour"
    )


def test_smoke_auth_wall_softening_does_not_leak_into_a_real_outage(tmp_path: Path):
    """The guard rail on the guard rail.

    Treating "could not measure" as not-a-failure is only safe while it is scoped to the one
    cause that proves the deployment answered. A dead host must still produce hard FAILs.
    """
    shim = _make_curl_shim(tmp_path, "000", exit_code=7)
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://logs.example.com"}, path_prefix=shim)

    assert result.returncode == 1
    assert "SMOKE FAILED" in result.stdout
    assert "COULD NOT VERIFY" not in result.stdout, "a dead host is not an unverifiable one"
    # The measured failures still fail the run and still name their cause...
    assert "FAIL /health (000" in result.stdout
    assert "FAIL / homepage (000" in result.stdout
    # ...while the subsystems, which nothing asked about, are not invented as failures.
    assert "FAIL database subsystem" not in result.stdout
    assert "no workers registered" not in result.stdout


@pytest.mark.parametrize(
    ("code", "body", "label"),
    [
        ("502", "<html>502 Bad Gateway</html>", "proxy up, application container down"),
        ("404", "not found", "wrong path or a proxy answering for nothing"),
        ("200", '{"app":"ok","datab', "transfer truncated mid-body"),
    ],
)
def test_smoke_never_invents_a_subsystem_verdict_from_an_unread_body(tmp_path, code, body, label):
    """Every subsystem verdict is read out of one /health body. When it did not arrive, they
    are not failures — they are unmeasured.

    Gating this on the auth wall alone was too narrow: it cured one cause and left every
    other one inventing three subsystem failures and a worker diagnosis. The truncated-200
    case is the worst of them — `OK /health (200)` printed directly above `FAIL database
    subsystem`, the OK line actively vouching for the component the next line condemns.

    None of these were expressible before `_make_curl_shim` learned to separate the code
    from the body, which is precisely why the class survived.
    """
    shim = _make_curl_shim(tmp_path, code, body=body)
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://logs.example.com"}, path_prefix=shim)

    for invented in ("FAIL database subsystem", "FAIL redis subsystem", "FAIL storage subsystem"):
        assert invented not in result.stdout, f"{label}: invented {invented!r}"
    assert "FAIL no workers registered" not in result.stdout, label
    assert "check each worker: task deploy:logs" not in result.stdout, f"{label}: shipped a remediation for a fault nobody observed"
    assert "SKIP database subsystem" in result.stdout, label
    assert "SKIP workers" in result.stdout, label


def test_smoke_still_reads_a_real_degraded_health_body(tmp_path: Path):
    """The guard rail on the guard rail.

    Suppressing unmeasured verdicts is only correct while a MEASURED one still gets through.
    A 503 that carries a health document is the case this whole script exists to catch, and
    it must still name the one broken subsystem and vouch for the others.
    """
    body = '{"app":"degraded","database":"error","redis":"ok","storage":"ok","workers":2,"workers_ok":true}'
    shim = _make_curl_shim(tmp_path, "503", body=body)
    result = _run("smoke", tmp_path, {"SMOKE_URL": "https://logs.example.com"}, path_prefix=shim)

    assert result.returncode == 1
    assert "FAIL database subsystem" in result.stdout, "a measured failure must still be reported"
    assert "OK   redis subsystem" in result.stdout
    assert "OK   storage subsystem" in result.stdout
    assert "OK   workers registered (2)" in result.stdout
    assert "SKIP" not in result.stdout, "nothing here was unmeasured"


def test_smoke_url_resolution_precedence(tmp_path: Path):
    shim = _make_curl_shim(tmp_path, "000")

    # 1. SMOKE_URL wins over DOMAIN and DEPLOY_HOSTS.
    result = _run(
        "smoke",
        tmp_path,
        {
            "SMOKE_URL": "https://explicit.example",
            "DOMAIN": "domain.example",
            "DEPLOY_HOSTS": "user@cp.example,w1.example",
        },
        path_prefix=shim,
    )
    assert "Smoke-testing: https://explicit.example" in result.stdout

    # 2. DOMAIN wins over DEPLOY_HOSTS.
    result = _run(
        "smoke",
        tmp_path,
        {"DOMAIN": "domain.example", "DEPLOY_HOSTS": "user@cp.example,w1.example"},
        path_prefix=shim,
    )
    assert "Smoke-testing: https://domain.example" in result.stdout

    # 2b. …but the scheme comes from how the proxy actually terminates TLS. With
    # PROXY_TLS=off there is no https listener at all, so probing one is a connection
    # refused reported as a dead deployment.
    result = _run(
        "smoke",
        tmp_path,
        {"DOMAIN": "domain.example", "PROXY_TLS": "off", "DEPLOY_HOSTS": "user@cp.example"},
        path_prefix=shim,
    )
    assert "Smoke-testing: http://domain.example" in result.stdout

    for mode in ("acme", "internal", "custom"):
        result = _run(
            "smoke",
            tmp_path,
            {"DOMAIN": "domain.example", "PROXY_TLS": mode, "DEPLOY_HOSTS": "user@cp.example"},
            path_prefix=shim,
        )
        assert "Smoke-testing: https://domain.example" in result.stdout, mode

    # 3. DEPLOY_HOSTS-derived, first host, user@ prefix stripped.
    result = _run(
        "smoke",
        tmp_path,
        {"DEPLOY_HOSTS": "user@cp.example,w1.example"},
        path_prefix=shim,
    )
    assert "Smoke-testing: http://cp.example:8000" in result.stdout


# ── deploy-env-scaffold.sh ──────────────────────────────────────────────────────


def test_env_scaffold_default_action_generates_files(tmp_path: Path):
    result = _run("env-scaffold", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr

    cp = tmp_path / "deploy-envs" / "control-plane.env"
    worker = tmp_path / "deploy-envs" / "worker.env"
    assert cp.is_file()
    assert worker.is_file()

    # No de-indent sed step — no leftover .bak files.
    assert list((tmp_path / "deploy-envs").glob("*.bak")) == []

    # python3 is present in the test env, so no placeholder secrets survive.
    cp_text = cp.read_text()
    for placeholder in ("CHANGE-ME", "GENERATE-ME", "GENERATE-GK-KEY", "GENERATE-64-HEX"):
        assert placeholder not in cp_text
        assert placeholder not in worker.read_text()
    assert "no placeholder secrets remain in the generated files" in result.stdout

    # Structural fidelity: first line + a representative key.
    assert cp_text.startswith("# LogsTotal control-plane .env (generated by ./logstotal deploy:env-scaffold)\n")
    assert "COMPOSE_PROFILES=postgres,s3,workers\n" in cp_text
    assert "Next steps:" in result.stdout
    # The bundled Garage's own secrets: without them it runs on the published defaults.
    assert re.search(r"^GARAGE_RPC_SECRET=[0-9a-f]{64}$", cp_text, re.M), "Garage needs 32 bytes of hex"
    assert re.search(r"^GARAGE_ADMIN_TOKEN=\S{20,}$", cp_text, re.M)


def test_env_scaffold_keeps_the_garage_secrets_an_env_already_has(tmp_path: Path):
    (tmp_path / ".env").write_text("GARAGE_RPC_SECRET=" + "ab" * 32 + "\nGARAGE_ADMIN_TOKEN=keep-this-token-please\n")
    result = _run("env-scaffold", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    cp_text = (tmp_path / "deploy-envs" / "control-plane.env").read_text()
    assert "GARAGE_RPC_SECRET=" + "ab" * 32 + "\n" in cp_text
    assert "GARAGE_ADMIN_TOKEN=keep-this-token-please\n" in cp_text


def test_env_scaffold_proxy_action_applies_caddy_defaults(tmp_path: Path):
    base = _run("env-scaffold", tmp_path)
    assert base.returncode == 0, base.stdout + base.stderr

    proxy = _run("env-scaffold", tmp_path, args=["proxy"])
    assert proxy.returncode == 0, proxy.stdout + proxy.stderr
    assert "updated deploy-envs/control-plane.env with proxy defaults" in proxy.stdout

    cp_text = (tmp_path / "deploy-envs" / "control-plane.env").read_text()
    assert "COMPOSE_PROFILES=postgres,s3,proxy,workers\n" in cp_text
    assert "DOMAIN=logs.example.com\n" in cp_text
    assert "ACME_EMAIL=admin@example.com\n" in cp_text
    assert "WEB_PORT=127.0.0.1:8000:8000\n" in cp_text
    assert "ENABLE_HSTS=true\n" in cp_text
    # No leftover sed backups.
    assert list((tmp_path / "deploy-envs").glob("*.bak")) == []


def test_env_scaffold_proxy_scaffolds_when_there_is_nothing_yet(tmp_path: Path):
    """`proxy` on a bare directory does the base scaffold itself, so the documented
    one-command HTTPS path works without a separate prior step."""
    proxy = _run("env-scaffold", tmp_path, args=["proxy"])
    assert proxy.returncode == 0, proxy.stdout + proxy.stderr
    cp = tmp_path / "deploy-envs" / "control-plane.env"
    assert cp.exists()
    assert "COMPOSE_PROFILES=postgres,s3,proxy,workers\n" in cp.read_text()


def test_env_scaffold_proxy_is_rerunnable_without_rotating_secrets(tmp_path: Path):
    """`proxy` must not run the base scaffold unconditionally: the base scaffold REFUSES
    over an existing one, so the command the scaffold's own closing line tells you to run
    next would fail on every run after the first. The only escape, FORCE=yes, rotates
    SECRET_KEY/POSTGRES_PASSWORD/S3 keys and logs the fleet out."""
    first = _run("env-scaffold", tmp_path, args=["proxy"])
    assert first.returncode == 0, first.stdout + first.stderr
    cp = tmp_path / "deploy-envs" / "control-plane.env"
    before = cp.read_text()

    second = _run("env-scaffold", tmp_path, args=["proxy"])
    assert second.returncode == 0, second.stdout + second.stderr
    after = cp.read_text()

    def _secret(text: str) -> str:
        return next(ln for ln in text.splitlines() if ln.startswith("SECRET_KEY="))

    assert _secret(before) == _secret(after), "re-running proxy rotated SECRET_KEY"
    assert "COMPOSE_PROFILES=postgres,s3,proxy,workers\n" in after


def test_env_scaffold_unknown_action_prints_usage(tmp_path: Path):
    result = _run("env-scaffold", tmp_path, args=["bogus"])
    assert result.returncode == 1
    assert "Usage: bash scripts/deploy-env-scaffold.sh" in result.stderr


# ── health-remote.sh ────────────────────────────────────────────────────────────


def test_health_remote_missing_url_errors(tmp_path: Path):
    """On stderr, because it goes through common.sh::die. A refusal on stdout is lost
    by any caller redirecting the report to a file, which is what `task health > x` is."""
    result = _run("health-remote", tmp_path)
    assert result.returncode != 0
    assert "ERROR: HEALTH_URL is required (e.g. HEALTH_URL=http://localhost:8000)." in result.stderr


def test_health_remote_healthy_json_reports_ok(tmp_path: Path):
    # Shape mirrors the real /health payload keys the script greps/jq-parses.
    body = '{"app":"ok","version":"1.2.3","database":"ok","redis":"ok","storage":"ok","workers":2}'
    shim = _make_curl_shim(tmp_path, "200", body=body)
    result = _run(
        "health-remote",
        tmp_path,
        {"HEALTH_URL": "http://health.example/"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "  app:      ok" in result.stdout
    assert "  database: ok" in result.stdout
    assert "  workers:  2" in result.stdout
    assert "  OK   all subsystems healthy." in result.stdout


# ── env-scaffold: overwrite protection ───────────────────────────────────────


def test_env_scaffold_refuses_to_overwrite_existing_files(tmp_path: Path):
    """Regenerating rotates SECRET_KEY, POSTGRES_PASSWORD and the S3 keys, which logs
    every session out and leaves workers authenticating with stale credentials."""
    first = _run("env-scaffold", tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    cp = tmp_path / "deploy-envs" / "control-plane.env"
    original = cp.read_text()

    second = _run("env-scaffold", tmp_path)

    assert second.returncode == 1
    assert "refusing to overwrite existing env scaffold" in second.stderr
    assert cp.read_text() == original, "secrets were rotated despite the refusal"


def test_env_scaffold_force_allows_regeneration(tmp_path: Path):
    first = _run("env-scaffold", tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    cp = tmp_path / "deploy-envs" / "control-plane.env"
    original = cp.read_text()

    forced = _run("env-scaffold", tmp_path, {"FORCE": "yes"})

    assert forced.returncode == 0, forced.stdout + forced.stderr
    assert cp.read_text() != original, "FORCE=yes should regenerate the secrets"


# ── SSH identity tilde expansion (scripts/lib/common.sh::build_ssh_opts) ─────
#
# SSH_IDENTITY usually arrives from deploy.env, which is read with grep/cut and never
# sees a shell, so `SSH_IDENTITY=~/.ssh/id_ed25519` stays literal. Tilde expansion is
# applied to an *unquoted* case pattern, so the `~/*` branch that was meant to handle
# this became `$HOME/*` and never matched.


def _build_ssh_opts(identity: str, home: Path) -> subprocess.CompletedProcess[str]:
    common = REPO_ROOT / "scripts" / "lib" / "common.sh"
    script = f'. "{common}"; SSH_IDENTITY={shlex.quote(identity)}; build_ssh_opts; printf "%s\\n" "${{SSH_OPTS[@]}}"'
    return subprocess.run(
        [shutil.which("bash"), "-c", script],
        capture_output=True,
        text=True,
        env={"HOME": str(home), "PATH": os.environ["PATH"]},
        check=False,
    )


def test_build_ssh_opts_expands_a_leading_tilde(tmp_path: Path):
    key = tmp_path / ".ssh" / "id_ed25519"
    key.parent.mkdir(parents=True)
    key.write_text("KEY")

    result = _build_ssh_opts("~/.ssh/id_ed25519", tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert str(key) in result.stdout
    assert "~" not in result.stdout


def test_build_ssh_opts_rejects_a_missing_identity(tmp_path: Path):
    result = _build_ssh_opts("~/.ssh/does_not_exist", tmp_path)
    assert result.returncode != 0
    assert "SSH_IDENTITY is not a file" in result.stderr


def test_build_ssh_opts_without_identity_has_no_i_flag(tmp_path: Path):
    result = _build_ssh_opts("", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "-i" not in result.stdout


# ── deploy:multiserver package gate ──────────────────────────────────────────


def _gate(tmp_path: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run the package gate in the CI/cron shape: no controlling terminal.

    `start_new_session=True` is the part that makes that true, and it is load-bearing.
    The gate prompts by reading `/dev/tty`, deliberately — an operator piping something
    into the deploy should still be asked. `stdin=DEVNULL` therefore models nothing:
    the child inherits pytest's controlling terminal, `/dev/tty` opens, and the prompt
    blocks on the developer's real keyboard forever. It only looked like it worked
    because CI (and any piped runner) has no controlling terminal to inherit, so the
    test passed there for the wrong reason. setsid() is what CI, cron and nohup
    actually have in common.
    """
    script = REPO_ROOT / "scripts" / "deploy-package-gate.sh"
    full = {**os.environ, "PATH": os.environ["PATH"], **(env or {})}
    # VERSION/ARCHIVE/BUNDLE too: each selects the published-release branch instead of the
    # package-staleness one these tests are about. `task release:finish VERSION=X.Y.Z`
    # exports VERSION into everything beneath it, so the suite it gates ran these against
    # the wrong branch — two failures that reproduced nowhere else and looked like flakes.
    for key in ("DEPLOY_PACKAGE", "DEPLOY_DRY_RUN", "DEPLOY_REBUILD", "VERSION", "ARCHIVE", "BUNDLE"):
        if key not in (env or {}):
            full.pop(key, None)
    return subprocess.run(
        ["bash", str(script)],
        cwd=tmp_path,
        env=full,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=120,
    )


def test_package_gate_reads_dry_run_from_deploy_env(tmp_path: Path):
    """deploy-multiserver.sh — which runs immediately after this step — reads
    DEPLOY_DRY_RUN from deploy.env too, so reading it from the process env alone would
    make a dry run configured in deploy.env build a real package."""
    (tmp_path / "deploy.env").write_text("DEPLOY_DRY_RUN=true\n", encoding="utf-8")
    res = _gate(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "dry-run" in res.stdout


def test_package_gate_reads_package_path_from_deploy_env(tmp_path: Path):
    (tmp_path / "deploy.env").write_text("DEPLOY_PACKAGE=/tmp/explicit.7z\n", encoding="utf-8")
    res = _gate(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "/tmp/explicit.7z" in res.stdout


def test_package_gate_says_what_it_is_doing(tmp_path: Path):
    """It rebuilds when it cannot prove the archive is current, and names the reason.
    Reusing a stale archive ships old code silently; a needless rebuild costs minutes."""
    (tmp_path / "logstotal-9.9.9.7z").write_bytes(b"")
    res = _gate(tmp_path)
    assert "rebuilding:" in res.stdout
    assert "no VERSION file" in res.stdout, "it must say WHY, not just that it is rebuilding"
    assert "DEPLOY_REBUILD=false" in res.stdout
    assert "Device not configured" not in res.stderr, "raw /dev/tty error leaked to the operator"


def test_package_gate_never_fails_silently_on_an_unpublished_version(tmp_path: Path):
    """`release_artifact_exists` was called as a plain command under `set -e`, so a non-zero
    return killed the script BEFORE the `case $?` written to handle it. Both arms were
    unreachable: an unpublished VERSION and an unreachable release server each exited 2 with
    nothing on stdout or stderr — from the FIRST command of `task deploy`.

    Asserted against the source, because reproducing it needs either a missing release or a
    missing network, and the shape is what matters: the status has to be captured.
    """
    src = (REPO_ROOT / "scripts" / "deploy-package-gate.sh").read_text(encoding="utf-8")
    call = next(ln for ln in src.splitlines() if "release_artifact_exists" in ln and "#" not in ln)
    assert "||" in call, f"a bare `release_artifact_exists` dies under set -e before its case block: {call.strip()!r}"


def test_package_gate_never_asks_a_question_it_could_answer(tmp_path: Path):
    """A prompt here blocks forever whenever a terminal exists — as the FIRST command of
    `task deploy`, i.e. step 7/8 of a quickstart, immediately before the archive is
    pushed. "It hangs when pushing files" is what that looks like from outside.

    Asserted against the source: with stdin closed a prompting script takes its no-TTY
    branch and looks fine. The staleness of the archive is a fact the script can check,
    not a preference to ask about."""
    src = (REPO_ROOT / "scripts" / "deploy-package-gate.sh").read_text(encoding="utf-8")
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert "/dev/tty" not in code, "the deploy must never block on a terminal read"
    assert "read -r" not in code


def test_package_gate_honours_an_explicit_rebuild_answer(tmp_path: Path):
    (tmp_path / "logstotal-9.9.9.7z").write_bytes(b"")
    res = _gate(tmp_path, {"DEPLOY_REBUILD": "false"})
    assert res.returncode == 0, res.stdout + res.stderr
    assert "using logstotal-9.9.9.7z" in res.stdout


# ── The `local` sentinel ────────────────────────────────────────────────────────
#
# `local` in DEPLOY_HOSTS means this machine, which is what lets the whole deploy run
# from the control plane. Every DEPLOY_HOSTS consumer has to know it — a script that
# does not will quietly try to resolve a host called "local".


def test_preflight_dry_run_traces_a_local_host_without_ssh(tmp_path: Path):
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_DRY_RUN": "true", "DEPLOY_HOSTS": "local,w1.example"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "=== local (control-plane) ===" in result.stdout
    assert "DRY-RUN local: true" in result.stderr
    assert "root@local" not in result.stderr
    # The remote host still goes over SSH.
    assert "DRY-RUN ssh root@w1.example" in result.stderr
    # The stdout contract the numeric captures depend on is unchanged.
    assert "DRY-RUN" not in result.stdout
    assert "PREFLIGHT NOT RUN (dry run)" in result.stdout


def test_preflight_reports_a_local_host_as_local_not_ssh(tmp_path: Path):
    result = _run("preflight", tmp_path, {"DEPLOY_DRY_RUN": "true", "DEPLOY_HOSTS": "local"})
    assert "OK   local (this machine, no SSH)" in result.stdout


def test_smoke_resolves_the_local_sentinel_to_localhost(tmp_path: Path):
    """`http://local:8000` asks DNS for a host called `local` and reports the
    deployment dead — the sentinel is not a hostname."""
    shim = _make_curl_shim(tmp_path, "000")
    result = _run("smoke", tmp_path, {"DEPLOY_HOSTS": "local,w1.example"}, path_prefix=shim)
    assert "Smoke-testing: http://localhost:8000" in result.stdout


# ── deploy-env-push.sh ──────────────────────────────────────────────────────────


def _fleet_env(tmp_path: Path, *slugs: str) -> Path:
    out = tmp_path / "deploy-envs"
    out.mkdir(exist_ok=True)
    for slug in slugs:
        (out / f"{slug}.env").write_text("SECRET_KEY=abc\nSTORAGE_BACKEND=s3\n", encoding="utf-8")
    return out


def test_env_push_requires_hosts(tmp_path: Path):
    result = _run("env-push", tmp_path)
    assert result.returncode != 0
    assert "DEPLOY_HOSTS is required" in result.stderr


def test_env_push_names_the_generator_when_a_file_is_missing(tmp_path: Path):
    result = _run("env-push", tmp_path, {"DEPLOY_HOSTS": "cp.example", "DEPLOY_DRY_RUN": "true"})
    assert result.returncode != 0
    assert "./logstotal deploy:env" in result.stderr


def test_env_push_installs_each_hosts_file_at_mode_600(tmp_path: Path):
    """A direct scp to .env leaves it world-readable — holding SECRET_KEY and the
    database password — for as long as the transfer takes."""
    _fleet_env(tmp_path, "cp.example", "w1.example")
    result = _run(
        "env-push",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_DRY_RUN": "true"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "install -m 600" in result.stdout
    assert "DRY-RUN scp deploy-envs/cp.example.env -> root@cp.example:/tmp/" in result.stdout
    assert "Pushed 2 file(s)." in result.stdout


def test_env_push_matches_the_generators_filenames_including_a_user_prefix(tmp_path: Path):
    _fleet_env(tmp_path, "cp.example")
    result = _run("env-push", tmp_path, {"DEPLOY_HOSTS": "deploy@cp.example", "DEPLOY_DRY_RUN": "true"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "deploy-envs/cp.example.env" in result.stdout


def test_env_push_uses_no_ssh_for_a_local_host(tmp_path: Path):
    _fleet_env(tmp_path, "local")
    result = _run("env-push", tmp_path, {"DEPLOY_HOSTS": "local", "DEPLOY_DRY_RUN": "true"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DRY-RUN local:" in result.stdout
    assert "root@local" not in result.stdout


# ── deploy-smoke.sh basic auth ──────────────────────────────────────────────────


def test_smoke_sends_basic_auth_credentials_when_both_are_set(tmp_path: Path):
    """Turning Caddy basic auth on made every probe return 401, so a healthy fleet
    reported SMOKE FAILED — a failure this script invented rather than detected."""
    shim = tmp_path / "shim"
    shim.mkdir()
    curl = shim / "curl"
    curl.write_text('#!/bin/sh\nprintf "%s" "$*" >> "$SEEN"\nprintf 200\n')
    curl.chmod(0o755)
    seen = tmp_path / "seen.txt"
    _run(
        "smoke",
        tmp_path,
        {
            "SMOKE_URL": "http://smoke.example",
            "BASIC_AUTH_USER": "ops",
            "BASIC_AUTH_PASS": "hunter2",
            "SEEN": str(seen),
        },
        path_prefix=shim,
    )
    assert "-u ops:hunter2" in seen.read_text(encoding="utf-8")


def test_smoke_sends_no_credentials_when_only_the_user_is_set(tmp_path: Path):
    shim = tmp_path / "shim"
    shim.mkdir()
    curl = shim / "curl"
    curl.write_text('#!/bin/sh\nprintf "%s" "$*" >> "$SEEN"\nprintf 200\n')
    curl.chmod(0o755)
    seen = tmp_path / "seen.txt"
    _run(
        "smoke",
        tmp_path,
        {"SMOKE_URL": "http://smoke.example", "BASIC_AUTH_USER": "ops", "SEEN": str(seen)},
        path_prefix=shim,
    )
    assert "-u " not in seen.read_text(encoding="utf-8")


# The refuse-to-overwrite guard is the one thing here that has to be exercised for
# real: it protects a hand-tuned production .env, and a dry run cannot see a file.
# The `local` sentinel makes that possible without a second machine.


def _local_push(tmp_path: Path, remote_dir: Path, extra: dict[str, str] | None = None):
    _fleet_env(tmp_path, "local")
    env = {"DEPLOY_HOSTS": "local", "DEPLOY_REMOTE_DIR": str(remote_dir)}
    env.update(extra or {})
    return _run("env-push", tmp_path, env)


def test_env_push_really_installs_the_file_at_mode_600(tmp_path: Path):
    remote = tmp_path / "opt"
    # The staging path is `/tmp/logstotal-env.$$` — a *remote* path for a real host, which
    # is why it cannot honour the local TMPDIR — and the `local` sentinel makes it land
    # here. So this has to look at the shared /tmp, and it does so as a before/after diff:
    # a bare glob asserts on every process on the machine, which under `pytest -n auto`
    # means a sibling worker's in-flight copy fails a test about our own cleanup.
    before = set(Path("/tmp").glob("logstotal-env.*"))
    result = _local_push(tmp_path, remote)
    assert result.returncode == 0, result.stdout + result.stderr
    installed = remote / ".env"
    assert installed.read_text(encoding="utf-8") == "SECRET_KEY=abc\nSTORAGE_BACKEND=s3\n"
    assert installed.stat().st_mode & 0o077 == 0
    left_behind = set(Path("/tmp").glob("logstotal-env.*")) - before
    assert not left_behind, f"the staging copy must not be left behind: {sorted(left_behind)}"


def test_env_push_refuses_to_overwrite_and_names_the_keys_it_would_lose(tmp_path: Path):
    remote = tmp_path / "opt"
    remote.mkdir()
    (remote / ".env").write_text("SECRET_KEY=live\nAI_RATE_LIMIT_PER_MINUTE=30\n", encoding="utf-8")
    result = _local_push(tmp_path, remote)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "already exists — not overwriting" in result.stderr
    assert "AI_RATE_LIMIT_PER_MINUTE" in result.stderr, "the operator has to see what they would lose"
    assert "live" not in result.stderr, "key names only — never values"
    assert (remote / ".env").read_text(encoding="utf-8").startswith("SECRET_KEY=live")
    assert "kept the existing .env on: local" in result.stdout


def test_env_push_refreshes_a_file_it_generated_itself(tmp_path: Path):
    """Refusing to refresh our own output means a first run that pushed a bad value and
    then failed protects that bad value on every retry, with the operator seeing the
    same unrelated error each time."""
    remote = tmp_path / "opt"
    remote.mkdir()
    (remote / ".env").write_text(
        "# ── generated by task deploy:env ──\nSECRET_KEY=stale\nSTORAGE_BACKEND=s3\n",
        encoding="utf-8",
    )
    import hashlib

    (remote / ".env.deploy.sha256").write_text(hashlib.sha256((remote / ".env").read_bytes()).hexdigest())
    result = _local_push(tmp_path, remote)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "refreshing the .env this generated earlier" in result.stdout
    assert (remote / ".env").read_text(encoding="utf-8") == "SECRET_KEY=abc\nSTORAGE_BACKEND=s3\n"


def test_a_generated_file_someone_has_since_edited_is_still_protected(tmp_path: Path):
    remote = tmp_path / "opt"
    remote.mkdir()
    (remote / ".env").write_text(
        "# ── generated by task deploy:env ──\nSECRET_KEY=stale\nSTORAGE_BACKEND=s3\nAI_RATE_LIMIT_PER_MINUTE=30\n",
        encoding="utf-8",
    )
    result = _local_push(tmp_path, remote)
    assert "not overwriting" in result.stderr
    assert "AI_RATE_LIMIT_PER_MINUTE" in result.stderr
    assert "stale" in (remote / ".env").read_text(encoding="utf-8")


def test_env_push_overwrites_when_forced(tmp_path: Path):
    remote = tmp_path / "opt"
    remote.mkdir()
    (remote / ".env").write_text("SECRET_KEY=live\n", encoding="utf-8")
    result = _local_push(tmp_path, remote, {"DEPLOY_ENV_PUSH_FORCE": "yes"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert (remote / ".env").read_text(encoding="utf-8") == "SECRET_KEY=abc\nSTORAGE_BACKEND=s3\n"


def test_the_generator_and_the_push_agree_about_where_env_files_live(tmp_path: Path):
    """DEPLOY_ENV_DIR reached the push but not the generator, so setting it produced
    "No env file for <host>" on a run that had just written one."""
    envs = tmp_path / "elsewhere"
    result = _run(
        "env-fleet",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_ENV_DIR": str(envs), "DEPLOY_CP_ADDRESS": "10.0.0.1"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert {p.name for p in envs.glob("*.env")} == {"cp.example.env", "w1.example.env"}
    assert (envs / "secrets.json").exists(), "the secret state must live beside the files it wrote"

    pushed = _run(
        "env-push",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_ENV_DIR": str(envs), "DEPLOY_DRY_RUN": "true"},
    )
    assert pushed.returncode == 0, pushed.stdout + pushed.stderr
    assert "Pushed 2 file(s)." in pushed.stdout


def test_smoke_resolves_an_ssh_alias_before_probing_it(tmp_path: Path):
    """A DEPLOY_HOSTS entry is an SSH destination, and an SSH destination need not be a
    name DNS knows: `w0` may be an ~/.ssh/config alias for w0.example.org. ssh resolves
    it, curl does not — so a perfectly healthy fleet reported seven FAILs and "000",
    which reads as a dead deployment rather than an unresolvable name. Measured.
    """
    shim = _make_curl_shim(tmp_path, "000")
    # An `ssh` that answers -G the way the real client would for a configured alias.
    (shim / "ssh").write_text(
        '#!/bin/sh\n[ "$1" = "-G" ] && { echo "hostname w0.real.example"; exit 0; }\nexit 0\n',
        encoding="utf-8",
    )
    (shim / "ssh").chmod(0o755)
    result = _run("smoke", tmp_path, {"DEPLOY_HOSTS": "w0,w1"}, path_prefix=shim)
    assert "is an SSH alias for w0.real.example" in result.stdout
    assert "Smoke-testing: http://w0.real.example:8000" in result.stdout


def test_smoke_leaves_a_real_hostname_alone(tmp_path: Path):
    """ssh -G echoes back a name it has no alias for, so the substitution must be a
    no-op there rather than announcing a pointless rewrite."""
    shim = _make_curl_shim(tmp_path, "000")
    (shim / "ssh").write_text(
        '#!/bin/sh\n[ "$1" = "-G" ] && { echo "hostname cp.example"; exit 0; }\nexit 0\n',
        encoding="utf-8",
    )
    (shim / "ssh").chmod(0o755)
    result = _run("smoke", tmp_path, {"DEPLOY_HOSTS": "cp.example"}, path_prefix=shim)
    assert "SSH alias" not in result.stdout
    assert "Smoke-testing: http://cp.example:8000" in result.stdout


def test_package_gate_refuses_to_push_an_older_release_than_it_last_deployed(tmp_path: Path):
    """`./logstotal upgrade` in package mode stages nothing locally — the fleet gets
    the published archive — so the checkout's VERSION still names the release it upgraded
    FROM. A bare `./logstotal deploy` afterwards would package that tree and push it,
    which is a DOWNGRADE of production reported as an ordinary deploy, with a filename that
    looks right because it is named for the tree it was built from.
    """
    (tmp_path / "VERSION").write_text("version: 0.9.13\n", encoding="utf-8")
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / ".last-deployed-release").write_text("0.9.14\n", encoding="utf-8")

    res = _gate(tmp_path)
    assert res.returncode != 0
    # One message, on stderr: DEPLOY_ALLOW_DOWNGRADE turns this from a refusal into a
    # warning, so only the exit differs between the two and the text is written once.
    assert "would push an OLDER release" in res.stderr
    assert "./logstotal upgrade" in res.stderr
    assert "DEPLOY_ALLOW_DOWNGRADE=true" in res.stderr, "it must name the way through"


def test_package_gate_allows_a_deliberate_downgrade(tmp_path: Path):
    """Going back on purpose is a real operation; it just must not be the silent default."""
    (tmp_path / "VERSION").write_text("version: 0.9.13\n", encoding="utf-8")
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / ".last-deployed-release").write_text("0.9.14\n", encoding="utf-8")

    res = _gate(tmp_path, {"DEPLOY_ALLOW_DOWNGRADE": "true", "DEPLOY_PACKAGE": "/tmp/explicit.7z"})
    assert res.returncode == 0, res.stdout + res.stderr
    assert "using DEPLOY_PACKAGE" in res.stdout


def test_package_gate_is_quiet_when_the_tree_is_not_behind(tmp_path: Path):
    """The guard must not fire on the ordinary case, nor on a version sort that treats
    0.9.10 as older than 0.9.2."""
    (tmp_path / "VERSION").write_text("version: 0.9.14\n", encoding="utf-8")
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / ".last-deployed-release").write_text("0.9.2\n", encoding="utf-8")

    res = _gate(tmp_path, {"DEPLOY_PACKAGE": "/tmp/explicit.7z"})
    assert res.returncode == 0, res.stdout + res.stderr
    assert "OLDER release" not in res.stdout


# ── PASS / FAIL / UNKNOWN ────────────────────────────────────────────────────


def _make_probe_shim(tmp_path: Path, *, unmeasurable: tuple[str, ...] = ()) -> Path:
    """An `ssh` shim that answers every preflight probe plausibly, except the ones named
    in `unmeasurable`, which return nothing at all.

    An empty reply is what `host_number` turns into its `?` sentinel — the state a real
    host produces when it is a BSD, a minimal container, or simply slow: `df` that did not
    answer, a box with no /proc/meminfo. This is the exact input that must not fail a whole
    `task deploy` at step 6 of 8 while finding nothing wrong.
    """
    d = tmp_path / "probeshim"
    d.mkdir(exist_ok=True)
    df = "" if "df" in unmeasurable else "99000000"
    mem = "" if "mem" in unmeasurable else "8000000"
    (d / "ssh").write_text(
        f"""#!/bin/bash
for arg in "$@"; do
  if [ "$arg" = "-G" ]; then printf 'hostname %s\n' "${{@: -1}}"; exit 0; fi
done
args=("$@")
i=0
while [ "$i" -lt "${{#args[@]}}" ]; do
  case "${{args[$i]}}" in
    -o|-i|-p|-F|-l) i=$((i + 2)); continue ;;
    -*) i=$((i + 1)); continue ;;
  esac
  break
done
cmd="${{args[*]:$((i + 1))}}"
case "$cmd" in
  *shell-ok*) printf 'shell-ok-0\n' ;;
  *"df -k"*) printf '{df}' ;;
  *MemAvailable*) printf '{mem}' ;;
  *"date +%s"*) date +%s ;;
  *"docker compose version"*) printf 'Docker Compose version v2.30.0\n' ;;
  *"docker info"*|*"docker version"*) printf 'Server Version: 27.0\n' ;;
  *"id -u"*) printf '0\n' ;;
  *"command -v"*) printf '/usr/bin/stub\n' ;;
  *) printf '\n' ;;
esac
exit 0
"""
    )
    (d / "ssh").chmod(0o755)
    return d


def test_a_host_that_answers_everything_passes(tmp_path: Path):
    """The control: with every probe answered, the run is clean and says so — including
    the not-measured count, which is printed on a clean run too."""
    shim = _make_probe_shim(tmp_path)
    result = _run("preflight", tmp_path, {"DEPLOY_HOSTS": "cp.example.com"}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PREFLIGHT PASSED" in result.stdout
    assert "0 not measured" in result.stdout


@pytest.mark.parametrize(
    ("probe", "phrase"),
    [("df", "could not measure free disk"), ("mem", "could not measure available memory")],
)
def test_a_probe_that_could_not_be_measured_does_not_fail_the_run(tmp_path: Path, probe: str, phrase: str):
    """Sent straight to note_fail, `host_number`'s `?` would fail a whole deploy at step 6
    of 8 for a host with no /proc/meminfo — a BSD, a minimal container, macOS as a `local`
    host — having found nothing wrong.

    It must still never print OK for something it did not measure. That is what the `?`
    sentinel is for; it is just not fatal.
    """
    shim = _make_probe_shim(tmp_path, unmeasurable=(probe,))
    result = _run("preflight", tmp_path, {"DEPLOY_HOSTS": "cp.example.com"}, path_prefix=shim)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PREFLIGHT PASSED" in result.stdout
    assert f"UNKNOWN: {phrase}" in result.stdout
    assert f"FAIL: {phrase}" not in result.stdout
    assert "1 not measured" in result.stdout


def test_an_unmeasured_check_is_never_rendered_as_ok(tmp_path: Path):
    """The rule the `?` sentinel exists for, restated as a test: not measured is not
    the same as fine, and must never be printed as though it were."""
    shim = _make_probe_shim(tmp_path, unmeasurable=("df", "mem"))
    result = _run("preflight", tmp_path, {"DEPLOY_HOSTS": "cp.example.com"}, path_prefix=shim)
    assert "OK   disk space" not in result.stdout
    assert "OK   memory" not in result.stdout
    assert "2 not measured" in result.stdout


def test_a_measured_failure_still_fails_the_run(tmp_path: Path):
    """UNKNOWN must not become a place to hide failures. A host that genuinely cannot be
    reached is measured — it stopped answering — and still exits 1."""
    d = tmp_path / "deadshim"
    d.mkdir()
    (d / "ssh").write_text("#!/bin/bash\nexit 255\n")
    (d / "ssh").chmod(0o755)
    result = _run("preflight", tmp_path, {"DEPLOY_HOSTS": "cp.example.com"}, path_prefix=d)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "PREFLIGHT FAILED" in result.stdout


def test_the_plan_verdict_survives_an_unmeasured_check(tmp_path: Path):
    """A host whose free disk could not be read is still FRESH INSTALL: the plan says what
    a deploy WOULD do, and it would do exactly that. Folding an unmeasured probe into
    BLOCKED made `deploy:plan` unusable on any host the checks could not fully reach."""
    shim = _make_probe_shim(tmp_path, unmeasurable=("df", "mem"))
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example.com", "DEPLOY_PLAN_ONLY": "true"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERDICT: BLOCKED" not in result.stdout
    assert "NOT MEASURED:" in result.stdout
    assert "could not be measured" in result.stdout


# ── What the plan compares against ───────────────────────────────────────────


def test_the_plan_says_what_it_is_comparing_against(tmp_path: Path):
    """ "ALREADY CURRENT" is only meaningful next to what it is current WITH, so the plan
    says. It matters most on the control plane, where upgrades run and the answer is easy
    to get wrong."""
    (tmp_path / "VERSION").write_text("version: 0.9.15\n", encoding="utf-8")
    shim = _make_probe_shim(tmp_path)
    result = _run(
        "preflight",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example.com", "DEPLOY_PLAN_ONLY": "true"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Compared against 0.9.15 (this tree)" in result.stdout


def test_an_explicit_package_is_what_the_plan_compares_against(tmp_path: Path):
    """A deploy pushes the archive, not the tree. Reporting against this checkout's VERSION,
    `deploy:plan DEPLOY_PACKAGE=…` would name the wrong release in every UPDATE."""
    (tmp_path / "VERSION").write_text("version: 0.9.15\n", encoding="utf-8")
    (tmp_path / "logstotal-1.2.3.7z").write_bytes(b"")
    shim = _make_probe_shim(tmp_path)
    result = _run(
        "preflight",
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com",
            "DEPLOY_PLAN_ONLY": "true",
            "DEPLOY_PACKAGE": str(tmp_path / "logstotal-1.2.3.7z"),
        },
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Compared against 1.2.3" in result.stdout
    assert "0.9.15" not in result.stdout


def test_the_plan_names_the_tautology_when_the_tree_is_the_install(tmp_path: Path):
    """The case that would make the plan useless on a control plane, which is where upgrades
    run: the current directory IS the install, so its VERSION is the version already
    deployed and every host would read ALREADY CURRENT for ever — a mirror, not a plan.

    It cannot resolve a target it was not given, so it says so and points at the command
    that can."""
    (tmp_path / "VERSION").write_text("version: 0.9.15\n", encoding="utf-8")
    shim = _make_probe_shim(tmp_path)
    result = _run(
        "preflight",
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com",
            "DEPLOY_PLAN_ONLY": "true",
            "DEPLOY_REMOTE_DIR": str(tmp_path),
        },
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "which IS the install" in result.stdout
    assert "tautology" in result.stdout
    assert "./logstotal upgrade:plan" in result.stdout


def test_a_dry_run_plan_invents_no_per_host_verdict(tmp_path: Path):
    """It contacted nothing, so every input to a verdict is an empty capture read as an
    answer: `test -d …/data` "succeeds", the version comes back blank, the container count
    is zero. It reported PARTIAL for every host in the fleet — a claim about machines
    nobody asked — and then printed "measured nothing" underneath."""
    (tmp_path / "VERSION").write_text("version: 0.9.15\n", encoding="utf-8")
    result = _run(
        "preflight",
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_PLAN_ONLY": "true",
            "DEPLOY_DRY_RUN": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERDICT:" not in result.stdout
    assert "PREFLIGHT NOT RUN" in result.stdout
    # It still answers the half it can without connecting.
    assert "Would install 0.9.15" in result.stdout


# ── The address the relays bind to ───────────────────────────────────────────


def test_an_address_the_control_plane_does_not_hold_falls_back_to_every_interface(tmp_path: Path):
    """The generator says "binding every interface instead" — and it has to DO it.

    A branch that prints the line and sets nothing lets deploy_fleet_env.py fall through to
    its own default, which returns the control-plane address verbatim whenever it is an IP
    literal. From there it cannot know the address is not on the host — which is exactly
    the case the shell has just detected and announced.

    The deploy then runs to its final step and dies on a raw Docker error, after
    bootstrapping three machines, building an image and starting five containers:
    `failed to bind host port 203.0.113.22:6379/tcp: cannot assign requested address` — a
    control plane that resolves, from a worker, to an address it does not hold.
    """
    src = (REPO_ROOT / "scripts" / "deploy-env-fleet.sh").read_text(encoding="utf-8")
    marker = "not on an interface of"
    assert marker in src, "the detection is gone or reworded"
    after = src.split(marker, 1)[1].split("\nfi", 1)[0]
    assert "DEPLOY_CP_BIND_ADDRESS=" in after, "the branch announces a fallback it does not apply — the exact bug"
    assert "0.0.0.0" in after


def test_regenerating_secrets_for_a_live_fleet_is_announced(tmp_path: Path):
    """Losing deploy-envs/ and re-running silently rotates the database password.

    PostgreSQL sets that password ONCE, when its data directory is initialised, so a new
    one authenticates against nothing. The deploy reports every step green and then times
    out at the health gate, with `FATAL: password authentication failed for user
    "logstotal"` buried in a container log. SECRET_KEY (every session invalidated) and the
    S3 keys (Garage rejects the worker) fail the same way.

    DEPLOY_ENV_FORCE already warned about exactly this. Losing the file has the same
    effect and said nothing — and it is the likelier route here: the file is gitignored,
    lives on one machine, and nothing on the fleet has a copy.
    """
    shim = tmp_path / "shim"
    shim.mkdir()
    # An ssh reporting an installed release, which is what makes this a live fleet.
    (shim / "ssh").write_text('#!/bin/bash\nbody=$(cat 2>/dev/null || true)\ncase "$*$body" in *VERSION*) printf "0.9.15|6" ;; *) printf "" ;; esac\nexit 0\n')
    (shim / "ssh").chmod(0o755)

    result = _run(
        "env-fleet",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example.com,w1.example.com", "DEPLOY_CP_ADDRESS": "10.0.0.1"},
        path_prefix=shim,
    )
    combined = result.stdout + result.stderr
    assert "already runs 0.9.15" in combined, combined[-1500:]
    assert "password authentication" in combined or "authenticates against nothing" in combined


def test_a_first_deploy_is_not_warned_about(tmp_path: Path):
    """Nothing is installed, so there is nothing for new secrets to disagree with. A
    warning here would fire on every single first deploy and teach people to skip it."""
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "ssh").write_text("#!/bin/bash\ncat >/dev/null 2>&1 || true\nprintf ''\nexit 0\n")
    (shim / "ssh").chmod(0o755)

    result = _run(
        "env-fleet",
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example.com,w1.example.com", "DEPLOY_CP_ADDRESS": "10.0.0.1"},
        path_prefix=shim,
    )
    assert "already runs" not in result.stdout + result.stderr


# ── The fleet record reaches the smoke test ──────────────────────────────────


class TestSmokeReadsTheDeployedInfrastructure:
    """deploy:status and deploy:plan consult the fleet record; deploy:smoke did not.

    Not an oversight worth preserving: this script's resolution chain was last touched the
    day BEFORE the record existed. The consequence was specific — on a control plane, which
    has no deploy.env because that belongs to whoever ran the deploy and package.sh keeps it
    out of the archive, it warned that nothing was configured, fell back to
    http://localhost:8000, and behind Caddy that port is bound to loopback on purpose. A
    healthy fleet reported SMOKE FAILED.
    """

    @staticmethod
    def _control_plane(tmp_path: Path, **options: str) -> Path:
        install = tmp_path / "opt" / "logstotal"
        (install / "fleet").mkdir(parents=True)
        args = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "fleet_manifest.py"),
            "--file",
            str(install / "fleet" / "manifest.json"),
            "intent",
            "--hosts",
            "cp.example.com,w1.example.com",
            "--install-dir",
            str(install),
            "--written-by",
            "0.10.4",
            "--written-at",
            "2026-01-01T00:00:00Z",
            "--option",
            f"remote_dir={install}",
        ]
        for key, value in options.items():
            args += ["--option", f"{key}={value}"]
        subprocess.run(args, check=True, capture_output=True)
        return install

    @staticmethod
    def _smoke(install: Path, **env: str) -> subprocess.CompletedProcess:
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "SMOKE_", "DOMAIN", "PROXY_"))}
        clean.update({"DEPLOY_REMOTE_DIR": str(install), "DEPLOY_DRY_RUN": "true", **env})
        return subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "deploy-smoke.sh")],
            cwd=install,
            env=clean,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_a_recorded_domain_becomes_the_target(self, tmp_path: Path):
        install = self._control_plane(tmp_path, domain="logs.example.com", proxy_tls="acme")
        out = self._smoke(install)
        assert "Smoke-testing: https://logs.example.com" in out.stdout, out.stdout + out.stderr
        assert "falling back to localhost" not in out.stderr

    def test_recorded_proxy_tls_off_makes_it_http(self, tmp_path: Path):
        """PROXY_TLS decides the scheme. Recorded but unread, every internal deployment
        probed https:// against a proxy serving plain HTTP and got a connection refused."""
        install = self._control_plane(tmp_path, domain="logs.example.com", proxy_tls="off")
        out = self._smoke(install)
        assert "Smoke-testing: http://logs.example.com" in out.stdout, out.stdout + out.stderr

    def test_the_host_list_comes_from_the_record_and_is_named(self, tmp_path: Path):
        """With no domain recorded the target is the control plane itself, and the run says
        which fleet it read — an operator told a fleet is unhealthy should not have to guess
        which one was probed."""
        install = self._control_plane(tmp_path)
        out = self._smoke(install)
        assert "from this host's fleet record" in out.stdout, out.stdout + out.stderr
        assert "no SMOKE_URL, DOMAIN or DEPLOY_HOSTS set" not in out.stderr

    def test_an_explicit_url_still_wins(self, tmp_path: Path):
        install = self._control_plane(tmp_path, domain="logs.example.com")
        out = self._smoke(install, SMOKE_URL="https://explicit.example")
        assert "Smoke-testing: https://explicit.example" in out.stdout
        assert "fleet record" not in out.stdout, "an explicit URL must not be annotated with a fallback's provenance"

    def test_deploy_env_still_wins_over_the_record(self, tmp_path: Path):
        install = self._control_plane(tmp_path, domain="from-record.example")
        (install / "deploy.env").write_text("DEPLOY_DOMAIN=from-deploy-env.example\n")
        out = self._smoke(install)
        assert "from-deploy-env.example" in out.stdout, "a record must fill a gap, never override a choice"

    def test_no_record_still_warns_and_falls_back(self, tmp_path: Path):
        """Warning and falling back is still right here: nothing configured anywhere really
        is a localhost dev run, and saying so is the point."""
        empty = tmp_path / "empty"
        empty.mkdir()
        out = self._smoke(empty)
        assert "Smoke-testing: http://localhost:8000" in out.stdout
        assert "falling back to localhost" in out.stderr
        assert "fleet record" in out.stderr, "the warning should name every source it checked"

    def test_the_password_is_read_from_deploy_env_but_the_environment_wins(self):
        """deploy.env offers DEPLOY_BASIC_AUTH_PASSWORD, so smoke reads it from there.

        deploy-fleet.sh reads it from deploy.env, so a smoke test that refused to would test
        a fleet deployed from the file without a password, and 401 on every probe.

        The precedence is what matters and is pinned here structurally: the environment
        is consulted before the file, on one line, as every other key in this script does
        it."""
        src = (REPO_ROOT / "scripts" / "deploy-smoke.sh").read_text(encoding="utf-8")
        reads = [ln.strip() for ln in src.splitlines() if "deploy_env_default DEPLOY_BASIC_AUTH_PASSWORD" in ln.split("#", 1)[0]]
        assert len(reads) == 1, f"expected exactly one file read of the password, got: {reads}"
        line = reads[0]
        assert line.index("${DEPLOY_BASIC_AUTH_PASSWORD:-") < line.index("deploy_env_default"), f"the file is consulted before the environment: {line}"


class TestThePreflightTakesPositionalHosts:
    """`task deploy:plan -- cp w1 w2` is step 3 of the documented four-step flow.

    The script parsed no arguments at all, so those hosts went nowhere and the plan reported
    on whatever deploy.env or the fleet record named. Silently — a plan is a report, and a
    report about a different fleet still looks like one.

    The obvious workaround is worse: go-task never exports a CLI variable to the shell, so
    `task deploy:plan DEPLOY_HOSTS=cp,w1` is ignored outright.
    """

    @staticmethod
    def _plan(tmp_path: Path, *args: str, **env: str) -> subprocess.CompletedProcess:
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "FLEET_"))}
        clean.update({"DEPLOY_DRY_RUN": "true", "DEPLOY_PLAN_ONLY": "true", **env})
        return subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "deploy-preflight.sh"), *args],
            cwd=tmp_path,
            env=clean,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_positional_hosts_are_the_fleet(self, tmp_path: Path):
        out = self._plan(tmp_path, "alpha.example.com", "beta.example.com")
        assert "alpha.example.com" in out.stdout, out.stdout + out.stderr
        assert "beta.example.com" in out.stdout

    def test_they_beat_deploy_env(self, tmp_path: Path):
        """Positionals are the most explicit source there is, so they win — the precedence
        every other deploy verb already follows."""
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=from-file.example.com\n")
        out = self._plan(tmp_path, "alpha.example.com")
        assert "alpha.example.com" in out.stdout
        assert "from-file.example.com" not in out.stdout

    def test_no_positionals_still_reads_deploy_env(self, tmp_path: Path):
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=from-file.example.com\n")
        out = self._plan(tmp_path)
        assert "from-file.example.com" in out.stdout, out.stdout + out.stderr

    def test_a_bad_host_is_refused_not_deployed_to(self, tmp_path: Path):
        """hosts_from_args is reused rather than a second parser written, so a shell
        metacharacter is rejected before it can reach to_target and ssh."""
        out = self._plan(tmp_path, "cp; rm -rf /")
        assert out.returncode != 0
        assert "Not a host" in out.stdout + out.stderr

    def test_both_tasks_forward_them(self):
        """deploy:preflight and deploy:plan are the same script; teaching one and not the
        other is how they come to disagree about what an argument means."""
        import yaml

        tasks = yaml.safe_load((REPO_ROOT / "taskfiles" / "ops.yml").read_text(encoding="utf-8"))["tasks"]
        for name in ("deploy:preflight", "deploy:plan"):
            cmds = " ".join(tasks[name]["cmds"])
            assert "deploy-preflight.sh {{.CLI_ARGS}}" in cmds, f"{name} does not forward its arguments"


# ── The plan says what the fleet IS, not only what state its hosts are in ────
#
# Per-host verdicts alone name no setting, and the network plan reads DEPLOY_DOMAIN only as
# a boolean, to move the app from port 8000 to 80+443 — so without the settings block the
# question a plan is asked most often, *which site is this about*, would have no answer in
# its own output. The block and the findings come from scripts/deploy_config_review.py, which is
# tested as data in tests/test_deploy_config_review.py; these pin the wiring.


class TestThePlanShowsTheFleetsSettings:
    @staticmethod
    def _plan(tmp_path: Path, settings: str, **env: str):
        (tmp_path / "deploy.env").write_text(settings, encoding="utf-8")
        return _run(
            "preflight",
            tmp_path,
            {
                "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"),
                "DEPLOY_PLAN_ONLY": "true",
                "DEPLOY_DRY_RUN": "true",
                **env,
            },
        )

    def test_the_domain_is_named(self, tmp_path: Path):
        out = self._plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=logs.example.com\n").stdout
        assert re.search(r"Domain\s+logs\.example\.com", out), "the plan still does not say which site it is about"

    def test_each_setting_says_where_it_came_from(self, tmp_path: Path):
        """ "The domain is wrong" and "the domain is right and deploy.env is being ignored"
        look identical without it, and the second is the one an operator cannot debug."""
        out = self._plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=logs.example.com\n").stdout
        assert re.search(r"Domain\s+logs\.example\.com\s+from deploy\.env", out)
        assert re.search(r"Install dir\s+/opt/logstotal\s+from a default", out)

    def test_provenance_names_the_file_not_its_path(self, tmp_path: Path):
        """DEPLOY_ENV_FILE is absolute here and on any machine driving more than one
        fleet, and the full path pushed every row off the screen."""
        out = self._plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\n").stdout
        assert str(tmp_path) not in out

    def test_the_environment_wins_and_says_so(self, tmp_path: Path):
        out = self._plan(
            tmp_path,
            "DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=from-file.example\n",
            DEPLOY_DOMAIN="from-env.example",
        ).stdout
        assert re.search(r"Domain\s+from-env\.example\s+from the environment", out)

    def test_a_plain_preflight_gets_no_settings_block(self, tmp_path: Path):
        """It is a host readiness check; ten lines of configuration would push its first
        real result off a short terminal."""
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example.com\n", encoding="utf-8")
        out = _run(
            "preflight",
            tmp_path,
            {"DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"), "DEPLOY_DRY_RUN": "true"},
        ).stdout
        assert "Fleet configuration" not in out


class TestThePlanWarnsWhenSettingsDisagree:
    def _plan(self, tmp_path: Path, settings: str):
        return TestThePlanShowsTheFleetsSettings._plan(tmp_path, settings)

    def test_a_finding_reaches_the_plan(self, tmp_path: Path):
        result = self._plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=a.example\nDOMAIN=b.example\n")
        assert "disagree" in result.stdout

    def test_a_finding_never_changes_the_exit_code(self, tmp_path: Path):
        """A plan is a report. Findings are advisory by construction — several of them are
        legitimate configurations — so none may become a gate."""
        result = self._plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=a.example\nDOMAIN=b.example\nDEPLOY_KEEP_RELEASES=0\n")
        assert result.returncode == 0
        assert "none of them stops a deploy" in result.stdout

    def test_a_finding_never_becomes_a_blocked_verdict(self, tmp_path: Path):
        """BLOCKED is measured host state. Folding a config warning into it would make the
        fleet summary claim a deploy would stop where it would not."""
        result = self._plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\nDEPLOY_KEEP_RELEASES=0\n")
        assert "leaving nothing to roll back to" in result.stdout, "the finding should have fired"
        assert "VERDICT: BLOCKED" not in result.stdout
        assert "BLOCKED" not in result.stdout

    def test_a_healthy_configuration_says_nothing(self, tmp_path: Path):
        result = self._plan(tmp_path, "DEPLOY_HOSTS=cp.example.com,w1.example.com\nDEPLOY_VPN=none\n")
        assert "WARN" not in result.stdout
        assert "none of them stops a deploy" not in result.stdout

    def test_a_dry_run_still_reviews_the_configuration(self, tmp_path: Path):
        """The findings are read off deploy.env, not off a host, so the run that connects
        to nothing can still answer them in full."""
        result = self._plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=a.example\nDOMAIN=b.example\n")
        assert "PREFLIGHT NOT RUN (dry run)" in result.stdout
        assert "disagree" in result.stdout


class TestColourIsGated:
    """Colour is resolved once in common.sh, on a TTY and no NO_COLOR.

    Nothing was gated before, so escapes went into pipes, redirected files and CI logs
    unconditionally. The gate is also what keeps ~500 stdout assertions in this suite
    valid: `capture_output=True` is not a TTY, so every one of them still matches plain
    text.
    """

    def test_captured_output_carries_no_escapes(self, tmp_path: Path):
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=a.example\n", encoding="utf-8")
        result = _run(
            "preflight",
            tmp_path,
            {"DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"), "DEPLOY_PLAN_ONLY": "true", "DEPLOY_DRY_RUN": "true"},
        )
        assert "\033" not in result.stdout, "an escape reached a pipe"
        assert "\033" not in result.stderr

    def test_the_verdict_column_is_unchanged_by_colour(self, tmp_path: Path):
        """`OK` carries three spaces because that is the column operators read. Colour
        wraps the label only; a symbol or a reset inside the padding would move it."""
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example.com\n", encoding="utf-8")
        out = _run(
            "preflight",
            tmp_path,
            {"DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"), "DEPLOY_DRY_RUN": "true"},
        ).stdout
        assert "  OK   docker\n" in out


class TestThePlanCanBeParsed:
    def _json_plan(self, tmp_path: Path, settings: str):
        import json

        (tmp_path / "deploy.env").write_text(settings, encoding="utf-8")
        result = _run(
            "preflight",
            tmp_path,
            {
                "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"),
                "DEPLOY_PLAN_ONLY": "true",
                "DEPLOY_DRY_RUN": "true",
                "DEPLOY_PLAN_FORMAT": "json",
            },
        )
        return result, json.loads(result.stdout)

    def test_stdout_is_one_document_and_the_checks_move_to_stderr(self, tmp_path: Path):
        """Suppressing the checks was the alternative and it is worse: they are how an
        operator sees which host is being contacted. This is the DRY-RUN trace's
        arrangement, which goes to stderr for the same reason."""
        result, payload = self._json_plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=a.example\n")
        assert payload["control_plane"] == "cp.example.com"
        assert "===" not in result.stdout, "a human check line landed in the document"
        assert "=== cp.example.com (control-plane) ===" in result.stderr

    def test_the_document_carries_settings_findings_and_counts(self, tmp_path: Path):
        _, payload = self._json_plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\nDEPLOY_DOMAIN=a.example\nDOMAIN=b.example\n")
        assert any(s["label"] == "Domain" and s["value"] == "a.example" for s in payload["settings"])
        assert payload["counts"]["warnings"] >= 1
        assert payload["plan"]["dry_run"] is True
        assert set(payload["plan"]["counts"]) == {"fresh", "update", "current", "partial", "blocked", "unmeasured"}

    def test_it_still_exits_zero(self, tmp_path: Path):
        result, _ = self._json_plan(tmp_path, "DEPLOY_HOSTS=cp.example.com\n")
        assert result.returncode == 0

    def test_a_bad_format_is_refused_by_name(self, tmp_path: Path):
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example.com\n", encoding="utf-8")
        result = _run(
            "preflight",
            tmp_path,
            {"DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"), "DEPLOY_PLAN_ONLY": "true", "DEPLOY_PLAN_FORMAT": "yaml"},
        )
        assert result.returncode != 0
        assert "must be text or json" in result.stdout

    def test_it_is_ignored_outside_a_plan(self, tmp_path: Path):
        """A preflight has no document to emit, and one that fell silent while writing its
        checks to stderr would read as a broken run."""
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example.com\n", encoding="utf-8")
        result = _run(
            "preflight",
            tmp_path,
            {
                "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"),
                "DEPLOY_DRY_RUN": "true",
                "DEPLOY_PLAN_FORMAT": "json",
            },
        )
        assert "=== cp.example.com (control-plane) ===" in result.stdout
