"""Tests for scripts/deploy-multiserver.sh via DEPLOY_DRY_RUN (no SSH connections)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "deploy-multiserver.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _run_deploy(tmp_path: Path, env_overrides: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    """Run the deploy script in dry-run mode from an isolated cwd."""
    env = {**os.environ}
    for var in (
        "DEPLOY_HOSTS",
        "DEPLOY_STOP",
        "DEPLOY_START",
        "DEPLOY_KEEPENV",
        "DEPLOY_CLEAN",
        "DEPLOY_PACKAGE",
        "DEPLOY_ACTION",
        "DEPLOY_ENV_FILE",
        "DEPLOY_DRY_RUN_HEALTH",
        "DEPLOY_REMOVE_CONFIRM",
        "DEPLOY_REMOVE_KEEP_DATA",
        "DEPLOY_REMOVE_VPN",
        "DEPLOY_REMOTE_DIR",
        "SSH_IDENTITY",
    ):
        env.pop(var, None)
    env["DEPLOY_DRY_RUN"] = "true"
    # Point at an absent deploy.env so a real one in the repo can't leak in.
    env["DEPLOY_ENV_FILE"] = str(tmp_path / "deploy.env.absent")
    env.update(env_overrides)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_dry_run_deploy_phases_are_ordered(tmp_path: Path):
    """Stop workers before CP; stage all; start CP + health gate BEFORE starting workers."""
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com,w2.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout

    # Phase banners present and ordered.
    positions = [out.index(f"Phase {n}/5") for n in (1, 2, 3, 4, 5)]
    assert positions == sorted(positions)

    # Workers stop before the control plane.
    stop_w1 = out.index("w1.example.com (worker): stopping stacks")
    stop_w2 = out.index("w2.example.com (worker): stopping stacks")
    stop_cp = out.index("cp.example.com (control-plane): stopping stacks")
    assert stop_w1 < stop_cp
    assert stop_w2 < stop_cp

    # Control plane starts and passes health BEFORE any worker starts.
    start_cp = out.index("cp.example.com (control-plane): starting stack")
    health_cp = out.index("cp.example.com: /health returned 200")
    start_w1 = out.index("w1.example.com (worker): starting stack")
    assert start_cp < health_cp < start_w1


def test_dry_run_failed_health_gate_fails_deploy_and_skips_workers(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
            "DEPLOY_DRY_RUN_HEALTH": "000",
        },
    )
    assert result.returncode != 0
    assert "workers were NOT started" in result.stderr
    assert "w1.example.com (worker): starting stack" not in result.stdout


def test_user_at_host_entries_are_not_double_prefixed(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "deploy@cp.example.com,w1.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DRY-RUN ssh deploy@cp.example.com" in result.stdout
    assert "root@deploy@" not in result.stdout
    # Bare hosts still default to root.
    assert "DRY-RUN ssh root@w1.example.com" in result.stdout


def test_stop_only_action_stops_workers_first(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_ACTION": "stop-only",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    stop_w1 = result.stdout.index("w1.example.com (worker): stopping stacks")
    stop_cp = result.stdout.index("cp.example.com (control-plane): stopping stacks")
    assert stop_w1 < stop_cp


def test_deploy_without_start_leaves_stacks_stopped(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_STOP": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "stacks left stopped" in result.stdout
    assert "starting stack" not in result.stdout


def test_deploy_env_file_provides_defaults_but_env_wins(tmp_path: Path):
    deploy_env = tmp_path / "deploy.env"
    deploy_env.write_text("DEPLOY_HOSTS=filehost.example.com\n", encoding="utf-8")
    # From the file:
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_ENV_FILE": str(deploy_env), "DEPLOY_ACTION": "stop-only"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "filehost.example.com" in result.stdout
    # Caller env overrides the file:
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_ENV_FILE": str(deploy_env),
            "DEPLOY_HOSTS": "envhost.example.com",
            "DEPLOY_ACTION": "stop-only",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "envhost.example.com" in result.stdout
    assert "filehost.example.com" not in result.stdout


# ── start-only ───────────────────────────────────────────────────────────────
#
# The documented resume path after DEPLOY_START=false. Starting every host in list order
# with no health gate would bring workers up against a control plane that might be
# failing — the exact ordering the deploy path exists to prevent.


def test_start_only_gates_workers_on_control_plane_health(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_ACTION": "start-only",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    start_cp = result.stdout.index("cp.example.com (control-plane): starting stack")
    start_w1 = result.stdout.index("w1.example.com (worker): starting stack")
    assert start_cp < start_w1, "control plane must start before the workers"


def test_start_only_aborts_when_the_control_plane_is_unhealthy(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_ACTION": "start-only",
            "DEPLOY_DRY_RUN_HEALTH": "000",
        },
    )
    assert result.returncode != 0
    assert "workers were NOT started" in result.stderr
    assert "w1.example.com (worker): starting stack" not in result.stdout


# ── The `local` sentinel ─────────────────────────────────────────────────────
#
# A DEPLOY_HOSTS entry of `local` means this machine, so the whole deploy can run
# from the control plane instead of a workstation. The phase ordering and the
# health gate are the same code either way — these pin that the branch changed
# only *how* commands reach a host, not *when*.


def test_a_local_control_plane_never_reaches_for_ssh(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_HOSTS": "local,w1.example.com", "DEPLOY_STOP": "true", "DEPLOY_START": "true"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "DRY-RUN local:" in out
    assert "root@local" not in out
    assert "DRY-RUN ssh local" not in out
    # The worker is still remote.
    assert "DRY-RUN ssh root@w1.example.com" in out


def test_a_local_host_keeps_the_phase_order_and_the_health_gate(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_HOSTS": "local,w1.example.com", "DEPLOY_STOP": "true", "DEPLOY_START": "true"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    positions = [out.index(f"Phase {n}/5") for n in (1, 2, 3, 4, 5)]
    assert positions == sorted(positions)
    stop_w1 = out.index("w1.example.com (worker): stopping stacks")
    stop_cp = out.index("local (control-plane): stopping stacks")
    assert stop_w1 < stop_cp
    start_cp = out.index("local (control-plane): starting stack")
    health_cp = out.index("local: /health returned 200")
    start_w1 = out.index("w1.example.com (worker): starting stack")
    assert start_cp < health_cp < start_w1


def test_an_unhealthy_local_control_plane_still_skips_the_workers(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "local,w1.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
            "DEPLOY_DRY_RUN_HEALTH": "000",
        },
    )
    assert result.returncode != 0
    assert "workers were NOT started" in result.stderr
    assert "w1.example.com (worker): starting stack" not in result.stdout


def test_a_local_host_copies_instead_of_scping(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_HOSTS": "local", "DEPLOY_STOP": "true", "DEPLOY_KEEPENV": "true"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DRY-RUN copy" in result.stdout
    assert "DRY-RUN scp" not in result.stdout


def test_an_install_can_deploy_itself(tmp_path: Path):
    """Deploying with DEPLOY_REMOTE_DIR set to the tree these scripts live in must work.

    `7z x -aoa` rewrites each target IN PLACE, under the file descriptor bash is reading its
    own script from, so extracting there would derail the run somewhere unpredictable
    rather than failing.

    Phase 3 stages beside the install and rsyncs across instead. rsync renames its
    temporary into place, and rename() leaves the old inode readable for anyone holding
    it open, so the running script finishes on the bytes it started with. That is what lets
    the install deploy and upgrade itself — what makes "upgrades run from the control
    plane" possible at all.
    """
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_HOSTS": "local", "DEPLOY_REMOTE_DIR": str(REPO_ROOT)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "would extract over" not in result.stderr


def test_the_release_is_staged_beside_the_install_never_over_it(tmp_path: Path):
    """The mechanism, asserted where the dry-run seam can see it: the archive is unpacked
    into .stage and rsynced across. A `7z x` aimed at DEPLOY_REMOTE_DIR itself is the failure."""
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_HOSTS": "local", "DEPLOY_REMOTE_DIR": "/opt/logstotal", "DEPLOY_PACKAGE": "pkg.7z"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "stage and overlay" in result.stdout


def test_the_same_checkout_is_fine_when_every_host_is_remote(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com",
            "DEPLOY_REMOTE_DIR": str(REPO_ROOT),
            "DEPLOY_ACTION": "stop-only",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ── DEPLOY_ONLY: incremental deploys ─────────────────────────────────────────
#
# Without it, adding a worker to a live fleet re-stages every host, including a perfectly
# healthy control plane — a full outage to gain one machine.


def test_only_the_named_host_is_stopped_staged_and_started(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com,w2.example.com",
            "DEPLOY_ONLY": "w2.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "w2.example.com (worker): stopping stacks" in out
    assert "w2.example.com (worker): starting stack" in out
    assert "w2.example.com (worker): stage new release" in out
    for untouched in ("w1.example.com", "cp.example.com"):
        assert f"{untouched} (worker): stopping stacks" not in out
        assert f"{untouched} (control-plane): stopping stacks" not in out
        assert f"{untouched}: stage new release" not in out


def test_an_untargeted_control_plane_is_health_checked_not_restarted(tmp_path: Path):
    """Not restarting it is the point; its health is still the gate, because a worker
    started against a failing control plane is the ordering phase 4 exists to prevent."""
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_ONLY": "w1.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "cp.example.com (control-plane): starting stack" not in out
    assert "not in DEPLOY_ONLY — checking its health without restarting it" in out
    health = out.index("cp.example.com: /health returned 200")
    start_w1 = out.index("w1.example.com (worker): starting stack")
    assert health < start_w1


def test_an_unhealthy_untargeted_control_plane_still_stops_the_deploy(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_ONLY": "w1.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
            "DEPLOY_DRY_RUN_HEALTH": "000",
        },
    )
    assert result.returncode != 0
    assert "workers were NOT started" in result.stderr


def test_a_running_stack_on_an_untargeted_host_is_not_a_blocker(tmp_path: Path):
    """Its stack running is the expected state — that is why it was left out."""
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example.com,w1.example.com", "DEPLOY_ONLY": "w1.example.com", "DEPLOY_START": "true"},
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_misspelt_target_is_refused_rather_than_deploying_to_nothing(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_HOSTS": "cp.example.com,w1.example.com", "DEPLOY_ONLY": "w3.example.com"},
    )
    assert result.returncode != 0
    assert "not in DEPLOY_HOSTS" in result.stderr


def test_without_deploy_only_every_host_is_still_acted_on(tmp_path: Path):
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert "Targeting" not in result.stdout
    assert "cp.example.com (control-plane): starting stack" in result.stdout
    assert "w1.example.com (worker): starting stack" in result.stdout


def test_the_staging_tmpdir_outlives_the_function_that_makes_it():
    """The EXIT trap fires *after* do_deploy has returned, so the staging directory
    cannot be a function-local: it would be out of scope and `rm -rf "$tmpdir"` would die
    with `tmpdir: unbound variable` under set -u, printing a shell error on top of whatever
    had actually gone wrong. That surfaces only when a remote command fails outright —
    a phase 4 or 5 failure, exactly when the real message matters most — which is why
    this is a source-shape assertion: the dry run cannot make remote_start fail, and a
    behavioural test written against the health gate passes on the broken shape too.
    """
    body = SCRIPT.read_text(encoding="utf-8")
    start = body.index('  header "Phase 3/5')
    end = body.index("  # ── Phase 4/5", start)
    stage = body[start:end]
    assert "local tmpdir" not in stage
    assert "STAGE_TMPDIR=$(mktemp" in stage
    # And the trap must tolerate the variable being unset, since it can fire before the
    # assignment if phase 1 or 2 dies.
    assert '[ -n "${STAGE_TMPDIR:-}" ]' in body


def test_deploy_only_does_not_restart_the_hosts_it_says_it_is_leaving_alone(tmp_path: Path):
    """Phase 5's worker loop was missing the targeting guard that phases 2 and 3 have, so
    the run announced "every other host is left running and untouched" and then ran
    `task docker:worker-up` (a docker build and up -d) on them anyway — killing any job
    in flight. The original test only checked that they were not STOPPED."""
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com,w2.example.com",
            "DEPLOY_ONLY": "w2.example.com",
            "DEPLOY_STOP": "true",
            "DEPLOY_START": "true",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "w2.example.com (worker): starting stack" in out
    for untouched in ("w1.example.com", "cp.example.com"):
        assert f"{untouched} (worker): starting stack" not in out
        assert f"{untouched} (control-plane): starting stack" not in out


# ── DEPLOY_ACTION=remove ─────────────────────────────────────────────────────
#
# The destructive counterpart to a deploy. DEPLOY_CLEAN tears down containers, volumes and
# images but leaves DEPLOY_REMOTE_DIR, so only this lets a run start from scratch rather
# than inherit whatever a half-finished one left behind.
#
# Guarded twice on purpose — a confirm variable AND a Taskfile prompt — matching
# DEPLOY_CLEAN_CONFIRM and deploy:rollback, the two precedents already in this file.


def test_remove_refuses_without_the_confirm_variable(tmp_path: Path):
    result = _run_deploy(tmp_path, {"DEPLOY_HOSTS": "cp.example,w1.example", "DEPLOY_ACTION": "remove"})
    assert result.returncode != 0
    assert "DEPLOY_REMOVE_CONFIRM=yes" in result.stderr
    assert "REMOVE" not in result.stdout, "it must refuse before touching a single host"


@pytest.mark.parametrize("unsafe", ["/", "/opt", "/tmp"])
def test_remove_refuses_an_unsafe_remote_dir(tmp_path: Path, unsafe: str):
    """`rm -rf /` and `rm -rf /opt` would take the host with them. No legitimate
    DEPLOY_REMOTE_DIR has that shape, so refuse rather than interpret."""
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example",
            "DEPLOY_ACTION": "remove",
            "DEPLOY_REMOVE_CONFIRM": "yes",
            "DEPLOY_REMOTE_DIR": unsafe,
        },
    )
    assert result.returncode != 0
    assert "Refusing to remove" in result.stderr


def test_remove_takes_workers_down_before_the_control_plane(tmp_path: Path):
    """Same ordering as stop-only, for the same reason: a worker whose database vanished
    first spends its last moments erroring into nothing."""
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example,w1.example,w2.example",
            "DEPLOY_ACTION": "remove",
            "DEPLOY_REMOVE_CONFIRM": "yes",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    order = [result.stdout.index(f"{h}: REMOVE (containers") for h in ("w1.example", "w2.example", "cp.example")]
    assert order == sorted(order), "the control plane must be removed last"


def test_remove_only_touches_the_vpn_when_asked(tmp_path: Path):
    base = {
        "DEPLOY_HOSTS": "cp.example,w1.example",
        "DEPLOY_ACTION": "remove",
        "DEPLOY_REMOVE_CONFIRM": "yes",
    }
    without = _run_deploy(tmp_path, base)
    assert "REMOVE VPN" not in without.stdout

    with_vpn = _run_deploy(tmp_path, {**base, "DEPLOY_REMOVE_VPN": "yes"})
    assert "REMOVE VPN" in with_vpn.stdout
    # The heredoc BODY is not traced — the dry-run seam prints the command it would run
    # (`bash -s`), not what is piped into it. Same limitation test_deploy_rollback.py
    # works around by extracting the body; here the step line is enough.
    assert with_vpn.stdout.count("REMOVE VPN") == 2, "both hosts should have their tunnel torn down"


def test_a_dry_run_remove_does_not_delete_the_vpn_address_map(tmp_path: Path):
    """The one write in do_remove that is not a `remote` call, and so was not covered by
    the dry-run seam: a LOCAL `rm -f deploy-envs/vpn.json`.

    `DEPLOY_DRY_RUN=true task deploy:remove` really deleted it — and it is the single
    file here that re-running nothing can rebuild, because it records the addresses
    Wireconf allocated. A dry run that destroys state is worse than no dry run.
    """
    env_dir = tmp_path / "deploy-envs"
    env_dir.mkdir()
    vpn_map = env_dir / "vpn.json"
    vpn_map.write_text('{"addresses": {"cp.example": "10.200.0.1"}}\n', encoding="utf-8")

    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example,w1.example",
            "DEPLOY_ACTION": "remove",
            "DEPLOY_REMOVE_CONFIRM": "yes",
            "DEPLOY_REMOVE_VPN": "yes",
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert vpn_map.exists(), "a dry run must not delete the address map"
    assert "DRY-RUN remove" in result.stdout, "and it must say that it would have"


def test_remove_sweeps_the_project_volumes_outside_the_directory_check(tmp_path: Path):
    """Measured on a real fleet: six logstotal_* volumes survived a remove that reported
    success, because `docker compose down -v` needs a compose file and the deploy had
    died before staging one. The sweep must therefore run even when the directory is
    already gone — which is exactly the case it exists for."""
    # Asserted against the source: the dry-run seam traces the command it would run
    # (`bash -s`) and never the heredoc piped into it, so this placement is invisible to
    # a behavioural test — the same reason test_deploy_rollback.py extracts its bodies.
    src = SCRIPT.read_text(encoding="utf-8")
    body = src.split("do_remove()", 1)[1].split("\ndo_stop_only()", 1)[0]
    assert "docker volume ls" in body, "remove must sweep the project's named volumes"
    closes_dir_check = body.index('echo "nothing at')
    assert body.index("docker volume ls") > closes_dir_check, "the volume sweep must run even when the directory is already gone — that is the half-failed state it exists for"


# ── Positional hosts ─────────────────────────────────────────────────────────


def test_positional_hosts_beat_the_deploy_env_file(tmp_path: Path):
    """go-task never exports a CLI variable to the shell, so `task deploy:status
    DEPLOY_HOSTS=cp,w1` does not reach this script — and with a deploy.env present it
    does not abort either, it would act on THE FLEET NAMED IN THAT FILE. Hosts arrive as
    positionals for every deploy verb, deploy:status and deploy:rollback included."""
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=other-fleet.example.com\n", encoding="utf-8")
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_ACTION": "status", "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env")},
        "cp.example.com",
        "w1.example.com",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "other-fleet.example.com" not in result.stdout
    assert "cp.example.com" in result.stdout
    assert "w1.example.com" in result.stdout


def test_the_deploy_env_file_still_answers_when_no_host_is_named(tmp_path: Path):
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=from-file.example.com\n", encoding="utf-8")
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_ACTION": "status", "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env")},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "from-file.example.com" in result.stdout


def test_a_positional_that_is_not_a_host_is_refused_before_anything_runs(tmp_path: Path):
    """These strings end up inside `ssh <target> bash -c ...`. A refusal that names the
    offender, on stderr, with nothing on stdout — not a command someone runs."""
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_ACTION": "status"},
        "cp.example.com; rm -rf /",
    )
    assert result.returncode != 0
    assert "Not a host" in result.stderr
    assert result.stdout == "", "it must refuse before printing the banner"


# ── A skipped verification is not a failed deploy ────────────────────────────


def _worker_shim(tmp_path: Path) -> Path:
    """An `ssh`/`scp` pair that answers a real (non-dry) deploy.

    Everything the deploy sends to a host is a heredoc piped into `bash -s`, so the thing
    to dispatch on arrives on STDIN, not in argv — which is why the other tests in this
    file use DEPLOY_DRY_RUN instead. Here the run has to be real, because
    verify_worker_running short-circuits on a dry run.

    It answers: the control plane is healthy, no stack is running yet, and the worker's
    containers never appear.
    """
    d = tmp_path / "shim"
    d.mkdir()
    (d / "ssh").write_text(
        "#!/bin/bash\n"
        "body=$(cat)\n"
        'case "$body" in\n'
        "  *'docker-compose.worker.yml ps --status running'*) exit 1 ;;\n"
        "  *'/health'*) printf '200' ; exit 0 ;;\n"
        "  *main_running*) exit 1 ;;\n"
        "esac\n"
        "exit 0\n"
    )
    (d / "scp").write_text("#!/bin/bash\nexit 0\n")
    for name in ("ssh", "scp"):
        (d / name).chmod(0o755)
    return d


def _real_deploy(tmp_path: Path, extra: dict[str, str]) -> subprocess.CompletedProcess[str]:
    shim = _worker_shim(tmp_path)
    pkg = tmp_path / "logstotal-9.9.9.7z"
    pkg.write_text("stand-in for an archive; the remote 7z is the shim\n")
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    env.update(
        {
            "PATH": f"{shim}{os.pathsep}{env['PATH']}",
            "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env.absent"),
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_START": "true",
            "DEPLOY_PACKAGE": str(pkg),
            "DEPLOY_HEALTH_ATTEMPTS": "1",
            "DEPLOY_HEALTH_DELAY": "0",
            **extra,
        }
    )
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def test_a_worker_that_cannot_be_confirmed_does_not_fail_the_deploy(tmp_path: Path):
    """verify_worker_running polls for 30s and gives up. What it reports is "I did not see
    running containers in the time I waited" — on a slow host, a cold image pull or a
    machine under load that is a statement about the wait, not about the worker.

    By then the control plane has passed its own health gate, the code is staged, and
    `docker compose up -d` has returned successfully. Killing the deploy there threw away
    a run that had done everything asked of it.
    """
    result = _real_deploy(tmp_path, {})
    both = result.stdout + result.stderr

    assert result.returncode == 0, both
    assert "Deploy complete" in result.stdout
    assert "w1.example.com" in both
    assert "not confirmed running" in both


def test_an_unconfirmed_worker_is_named_in_the_closing_line(tmp_path: Path):
    """An unverified worker nobody looks at is the failure mode this leniency could
    create, so it is repeated where the operator actually stops reading."""
    result = _real_deploy(tmp_path, {})
    closing = [ln for ln in result.stdout.splitlines() if "Deploy complete" in ln]
    assert closing, result.stdout
    assert "not confirmed running" in closing[-1]


def test_strict_mode_restores_the_hard_stop(tmp_path: Path):
    """The leniency must be escapable, or CI cannot tell a converged fleet from a limping
    one."""
    result = _real_deploy(tmp_path, {"DEPLOY_STRICT": "true"})
    assert result.returncode != 0
    assert "DEPLOY_STRICT=true" in result.stderr


def test_a_confirmed_worker_says_nothing_about_confirmation(tmp_path: Path):
    """The control: when the worker does come up, the closing line is unqualified."""
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "ssh").write_text("#!/bin/bash\nbody=$(cat)\ncase \"$body\" in\n  *'/health'*) printf '200' ; exit 0 ;;\n  *main_running*) exit 1 ;;\nesac\nexit 0\n")
    (shim / "scp").write_text("#!/bin/bash\nexit 0\n")
    for name in ("ssh", "scp"):
        (shim / name).chmod(0o755)
    pkg = tmp_path / "logstotal-9.9.9.7z"
    pkg.write_text("x\n")
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    env.update(
        {
            "PATH": f"{shim}{os.pathsep}{env['PATH']}",
            "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env.absent"),
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_START": "true",
            "DEPLOY_PACKAGE": str(pkg),
            "DEPLOY_HEALTH_ATTEMPTS": "1",
            "DEPLOY_HEALTH_DELAY": "0",
        }
    )
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "not confirmed running" not in result.stdout + result.stderr
    assert "worker stack running" in result.stdout


# ── What a removal leaves behind ─────────────────────────────────────────────


def test_remove_names_what_it_deliberately_left(tmp_path: Path):
    """A teardown that reports success while leaving the machines changed is the shape of
    "start from scratch" that does not. Each of these would be wrong to undo automatically
    — docker is shared with everything else on the host; deploy-envs/ is the only surviving
    copy of SECRET_KEY and the database password — so the honest move is to name them."""
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "cp.example,w1.example",
            "DEPLOY_ACTION": "remove",
            "DEPLOY_REMOVE_CONFIRM": "yes",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "Left behind — deliberately" in out
    assert "docker" in out and "go-task" in out
    assert "deploy-envs/" in out
    assert "SECRET_KEY" in out, "it must say WHY the secrets are not deleted for you"


def test_remove_on_a_control_plane_says_what_the_operator_must_finish(tmp_path: Path):
    """The control plane cannot delete the ground it is standing on: rsync's rename keeps
    the running script readable, but `rm -rf` on the current directory leaves the process
    with no cwd. Requirement: on the control plane the admin must be told what is left."""
    install = tmp_path / "opt" / "logstotal"
    install.mkdir(parents=True)
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    env.update(
        {
            "DEPLOY_DRY_RUN": "true",
            "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env.absent"),
            "DEPLOY_HOSTS": "local",
            "DEPLOY_ACTION": "remove",
            "DEPLOY_REMOVE_CONFIRM": "yes",
            "DEPLOY_REMOTE_DIR": str(install),
        }
    )
    result = subprocess.run(["bash", str(SCRIPT)], cwd=install, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "YOU ARE STANDING IN THE DIRECTORY THAT WAS REMOVED" in result.stdout
    assert f"rm -rf {install}" in result.stdout


def test_a_removal_from_elsewhere_does_not_claim_you_are_standing_in_it(tmp_path: Path):
    """The note is only true when it is true."""
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_HOSTS": "local",
            "DEPLOY_ACTION": "remove",
            "DEPLOY_REMOVE_CONFIRM": "yes",
            "DEPLOY_REMOTE_DIR": "/opt/logstotal",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "YOU ARE STANDING IN" not in result.stdout


def test_the_removal_knobs_can_live_in_deploy_env(tmp_path: Path):
    """deploy.env.example documented three of them as settings and deploy_env_load read
    none — so putting them there did nothing, silently. The confirmation is excluded on
    purpose: a confirmation you wrote down once is not one."""
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example,w1.example\nDEPLOY_REMOVE_VPN=yes\n", encoding="utf-8")
    result = _run_deploy(
        tmp_path,
        {
            "DEPLOY_ACTION": "remove",
            "DEPLOY_REMOVE_CONFIRM": "yes",
            "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"),
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("REMOVE VPN") == 2, "DEPLOY_REMOVE_VPN in deploy.env did nothing"


def test_the_confirmation_cannot_be_written_down(tmp_path: Path):
    """It is the gate. Reading it from a file would mean one `yes` disarms every future
    removal from that directory."""
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example\nDEPLOY_REMOVE_CONFIRM=yes\n", encoding="utf-8")
    result = _run_deploy(
        tmp_path,
        {"DEPLOY_ACTION": "remove", "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env")},
    )
    assert result.returncode != 0
    assert "DEPLOY_REMOVE_CONFIRM=yes" in result.stderr


# ── A worker that cannot start is reported, not thrown ───────────────────────


def _start_failing_deploy(tmp_path: Path, extra: dict[str, str] | None = None):
    """A shim whose workers accept everything except `docker compose up`.

    Dispatch is on `ROLE="worker"`, not on the task name: the start heredoc carries BOTH
    branches of its own if-statement, so `docker:up` and `docker:worker-up` are present in
    the body whichever host it is bound for.
    """
    d = tmp_path / "shim"
    d.mkdir()
    (d / "ssh").write_text(
        "#!/bin/bash\n"
        "body=$(cat)\n"
        'case "$body" in\n'
        "  *'docker-compose.worker.yml ps --status running'*) exit 1 ;;\n"
        "  *'/health'*) printf '200' ; exit 0 ;;\n"
        '  *\'ROLE="worker"\'*) echo "ERROR: Cannot connect to the Docker daemon" >&2 ; exit 1 ;;\n'
        "  *main_running*) exit 1 ;;\n"
        "esac\n"
        "exit 0\n"
    )
    (d / "scp").write_text("#!/bin/bash\nexit 0\n")
    for name in ("ssh", "scp"):
        (d / name).chmod(0o755)

    pkg = tmp_path / "logstotal-9.9.9.7z"
    pkg.write_text("stand-in for an archive\n")
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    env.update(
        {
            "PATH": f"{d}{os.pathsep}{env['PATH']}",
            "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env.absent"),
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com,w2.example.com",
            "DEPLOY_START": "true",
            "DEPLOY_PACKAGE": str(pkg),
            "DEPLOY_HEALTH_ATTEMPTS": "1",
            "DEPLOY_HEALTH_DELAY": "0",
            **(extra or {}),
        }
    )
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def test_a_worker_that_cannot_start_does_not_abort_the_other_hosts(tmp_path: Path):
    """`remote_start` was unguarded, so `set -e` killed the whole run at the first host
    whose `docker compose up` returned non-zero.

    Measured on a three-host rig with Docker stopped on the last machine: the control plane
    and the first worker were already up, and the run said nothing about either — it ended
    on go-task's bare `exit status 201`, with no result recorded for any host. The failure
    of one worker is a fact about that worker.
    """
    result = _start_failing_deploy(tmp_path)
    both = result.stdout + result.stderr

    # Both workers were attempted — the second only happens if the loop survived the first.
    assert "w1.example.com" in both
    assert "w2.example.com" in both
    assert "could not start the worker stack" in both
    # And it is honest about the outcome: a worker that cannot start is a measured failure.
    assert result.returncode != 0
    assert "Every other host was still attempted" in both


def test_it_says_where_to_find_what_it_recorded(tmp_path: Path):
    """The point of attempting every host is the record left behind; the message has to
    say so, or the operator re-runs the deploy to find out."""
    result = _start_failing_deploy(tmp_path)
    both = result.stdout + result.stderr
    assert "./logstotal fleet" in both
    assert "./logstotal deploy:logs" in both


# ── The teardown checklist ───────────────────────────────────────────────────


def _remove(tmp_path: Path, extra: dict[str, str] | None = None):
    """A dry-run remove with DEPLOY_ENV_FILE deliberately ABSENT from the environment.

    Every other test in this file sets it, which is exactly why two `set -u` faults on that
    variable shipped: the leftovers checklist below, and the "DEPLOY_HOSTS is required"
    hint that is the first error a new operator ever sees.
    """
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    env.update(
        {
            "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
            "DEPLOY_ACTION": "remove",
            "DEPLOY_DRY_RUN": "true",
            "DEPLOY_REMOVE_CONFIRM": "yes",
            **(extra or {}),
        }
    )
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def test_the_teardown_checklist_finishes(tmp_path: Path):
    """It died mid-sentence on a real control plane, immediately after `On THIS machine:`
    and after successfully removing three hosts — so the run reported failure for a
    teardown that had worked, and withheld the one thing the operator still had to do."""
    result = _remove(tmp_path)
    both = result.stdout + result.stderr
    assert "unbound variable" not in both, both
    assert "Left behind" in both
    assert "Next: ./logstotal deploy:plan" in both, "the checklist stopped early"
    assert result.returncode == 0, both


def test_a_machine_with_no_secrets_is_told_where_they_are(tmp_path: Path):
    """A control plane deployed TO rather than FROM holds neither deploy.env nor
    deploy-envs/. Listing them there sends the operator after files that do not exist and
    says nothing about the machine that does have the leftover work."""
    result = _remove(tmp_path)
    both = result.stdout + result.stderr
    assert "this machine holds no" in both.lower()
    assert "whichever machine ran the deploy" in both


def test_and_a_machine_that_has_them_is_told_to_delete_them(tmp_path: Path):
    (tmp_path / "deploy.env").write_text("DEPLOY_REMOTE_DIR=/opt/logstotal\n")
    (tmp_path / "deploy-envs").mkdir()
    result = _remove(tmp_path)
    both = result.stdout + result.stderr
    assert "the fleet's secrets" in both
    assert "Remove them yourself" in both


def test_the_first_error_a_new_operator_sees_is_a_sentence(tmp_path: Path):
    """With nothing configured anywhere, this printed
    `line 176: DEPLOY_ENV_FILE: unbound variable`."""
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    both = result.stdout + result.stderr
    assert "unbound variable" not in both, both
    assert "DEPLOY_HOSTS" in both
    assert "deploy.env" in both
