"""Behavior tests for scripts/upgrade.sh (the extracted upgrade task family).

Mirrors tests/test_backup_scripts.py and tests/test_deploy_check_scripts.py:
real bash, an isolated tmp_path cwd, a scrubbed environment, and a PATH shim of
`#!/bin/sh` stubs that echo `STUB <name> <args>` so the composed flow's shell-outs
(task backup / upgrade:stage-code / env:diff / docker compose … / health:remote /
doctor:docker) can be observed and ORDER-asserted without running anything real.

The script resolves scripts/lib/common.sh relative to its own location, so
invoking the repo's script from a tmp_path cwd works while keeping all of its
cwd-relative state (backups/, …) inside the throwaway directory.

NO live upgrade is ever run here: every external command is stubbed, and the
destructive/network actions (git checkout, ssh, docker, pdm) never execute for
real. `sleep` is stubbed too, only so the docker flow's `sleep 10` settle-wait
does not slow the suite down (it is irrelevant to the flow ORDER under test).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "upgrade.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

# Every var the dispatchers bridge into env — scrubbed so a real shell/CI env
# cannot leak a REF/ARCHIVE/etc. into the script under test.
_SCRUBBED = (
    "REF",
    "VERSION",
    "ALLOW_UNRELEASED",
    "RELEASE_REPO_URL",
    "SKIP_IF_CURRENT",
    "RESTAGE_IF_CURRENT",
    "ARCHIVE",
    "SKIP_BACKUP",
    "HEALTH_URL",
    "SOURCE",
    "SKIP_SNAPSHOT",
    "RELEASE_API_URL",
    "RELEASE_API_MAX_PAGES",
    "GITHUB_TOKEN",
)

#: Every composed flow resolves a release before it does anything. The stubbed `git`
#: reports no tags, so an unpinned run would correctly refuse ("no network, or nothing
#: published") — pin one instead, which is also the shape an operator uses. The pin is
#: accepted without a network check for exactly this reason: an unreachable server warns
#: and continues, while a server that answers and has no such tag refuses.
_PINNED = {"VERSION": "9.9.9"}

#: Same pin, plus the git arm. `package` is the default for every source, including
#: on a checkout, so any test whose subject is the git checkout path has to ask for it.
_PINNED_GIT = {**_PINNED, "SOURCE": "git"}

# Commands the composed flows shell out to; each becomes a `STUB <name> …` echo.
_STUB_CMDS = ("task", "docker", "git", "pdm", "ssh", "scp", "sleep", "curl")


def _make_stub_dir(tmp_path: Path, names: tuple[str, ...] = _STUB_CMDS) -> Path:
    """Create a dir of `#!/bin/sh; echo "STUB <name> $*"; exit 0` executables.

    `ssh` is the exception. The fleet flow invokes scripts/deploy-multiserver.sh directly,
    not through `task` — an upgrade has by then replaced the tree it is running in, and an
    upgrader that depends on the task names of the version it is installing is one a rename
    can break — so the real five-phase deploy runs here, against this shim.

    That is better coverage, and it needs one thing the plain echo cannot give: the
    control-plane health gate polls until it reads `200`, and would otherwise spend its
    whole 60s budget reading "STUB ssh …" and then fail the upgrade. Everything the deploy
    sends a host is a heredoc piped into `bash -s`, so the probe is identifiable on STDIN;
    every other call still gets the echo the ordering assertions read.
    """
    d = tmp_path / "shim"
    d.mkdir(exist_ok=True)
    for name in names:
        p = d / name
        if name == "ssh":
            p.write_text('#!/bin/sh\nbody=$(cat 2>/dev/null || true)\ncase "$body" in *health*) printf 200; exit 0 ;; esac\necho "STUB ssh $*"\nexit 0\n')
        else:
            p.write_text(f'#!/bin/sh\necho "STUB {name} $*"\nexit 0\n')
        p.chmod(0o755)
    return d


def _healthy_curl(shim: Path) -> None:
    """Drop a `curl` into `shim` that answers every smoke probe as a healthy deployment.

    upgrade:multiserver runs scripts/deploy-smoke.sh directly rather than through
    `task deploy:smoke` — go-task collapses every non-zero exit to 201, and the flow has to
    tell 1 (measured and failed) from 2 (could not measure). So `task` being stubbed no
    longer stubs the smoke step, and a test that drives the flow to the end has to supply the
    HTTP side of it too.
    """
    body = '{"app":"ok","database":"ok","redis":"ok","storage":"ok","workers":1,"workers_ok":true}'
    curl = shim / "curl"
    curl.write_text(f"#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = '%{{http_code}}' ] && {{ printf 200; exit 0; }}; done\nprintf '%s' '{body}'\n")
    curl.chmod(0o755)


def _run(
    args: list[str],
    tmp_path: Path,
    env_overrides: dict[str, str] | None = None,
    path_prefix: Path | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run `bash scripts/upgrade.sh <args…>` from an isolated cwd + scrubbed env."""
    env = {**os.environ}
    for var in _SCRUBBED:
        env.pop(var, None)
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    env.pop("SSH_IDENTITY", None)
    if path_prefix is not None:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env.get('PATH', '')}"
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=cwd or tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        # The ssh shim reads stdin to identify the health probe; a call made without a
        # heredoc would otherwise block on pytest's.
        stdin=subprocess.DEVNULL,
    )


def _assert_ordered(haystack: str, needles: list[str]) -> None:
    """Assert each needle appears, in the given relative order."""
    last = -1
    for needle in needles:
        idx = haystack.find(needle, last + 1)
        assert idx > last, f"out of order or missing: {needle!r}\n--- output ---\n{haystack}"
        last = idx


# ── docker ────────────────────────────────────────────────────────────────────


def test_docker_flow_runs_steps_in_order(tmp_path: Path):
    """Full single-host docker upgrade: every composed step fires, in order."""
    shim = _make_stub_dir(tmp_path)
    result = _run(["docker"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout

    # The banner names the KIND of source, not just the ref: `release` here, `unreleased`
    # behind ALLOW_UNRELEASED, `archive` for ARCHIVE=.
    assert "=== upgrade: this host (package) → v9.9.9 ===" in out
    assert "source: package (the published release archive)" in out, "the decision used to be invisible; every run must say which source it took"
    # The pre-upgrade version snapshot goes to a file; its stdout marker is the
    # "recorded" line — assert it, and that the file was actually written.
    assert "pre-upgrade version recorded: backups/pre-upgrade-version-" in out
    snapshots = list((tmp_path / "backups").glob("pre-upgrade-version-*.txt"))
    assert len(snapshots) == 1

    _assert_ordered(
        out,
        [
            "pre-upgrade version recorded:",
            "STUB task backup",
            "STUB task upgrade:stage-code",
            "STUB task env:diff",
            "STUB docker compose build",
            # The app must be down before the schema moves: an Alembic batch migration
            # rebuilds tables copy→drop→rename, and a live worker writing Finding rows
            # through that window loses them (or dies on "database is locked").
            "STUB docker compose stop web worker",
            "STUB docker compose run --rm --no-deps --pull never web python3 -m app.migrations",
            "STUB docker compose up -d",
            "STUB task health:remote",
            "STUB task doctor:docker",
            "upgrade complete (this host)",
        ],
    )


def test_docker_runs_the_rest_of_the_upgrade_on_the_staged_release_go_task(tmp_path: Path):
    """After staging, nested tasks run on the go-task the NEW release pins.

    The upgrade starts under the installed ./logstotal. Staging replaces the Taskfile, so a
    release that moves its pin ahead of a Taskfile feature would fail its own env:diff,
    health and doctor steps after the migration if they kept the old binary. The staged
    release's ./logstotal names the right one (`--task-path`).
    """
    shim = _make_stub_dir(tmp_path)
    staged = tmp_path / "staged-go-task"
    staged.write_text('#!/bin/sh\necho "STAGED-GO-TASK $*"\n')
    staged.chmod(0o755)
    wrapper = tmp_path / "logstotal"
    wrapper.write_text(f'#!/bin/sh\nif [ "$1" = --task-path ]; then echo "{staged}"; exit 0; fi\necho "STUB logstotal $*"\n')
    wrapper.chmod(0o755)
    result = _run(["docker"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    _assert_ordered(
        result.stdout,
        [
            "STUB logstotal backup",
            "STUB logstotal upgrade:stage-code",
            "STAGED-GO-TASK env:diff",
            "STAGED-GO-TASK health:remote",
            "STAGED-GO-TASK doctor:docker",
        ],
    )
    assert "STUB task " not in result.stdout, "a PATH `task` must not run when the installation has its own runner"


def test_docker_stops_the_app_before_migrating(tmp_path: Path):
    """The one data-loss path in the upgrade flows: DDL against a live SQLite writer."""
    shim = _make_stub_dir(tmp_path)
    result = _run(["docker"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    stop = result.stdout.find("STUB docker compose stop web worker")
    migrate = result.stdout.find("STUB docker compose run --rm --no-deps --pull never web python3 -m app.migrations")
    assert stop != -1, "the app is never stopped before the migration"
    assert stop < migrate, "migrations run while web/worker are still up"


def test_docker_skip_backup_warns_and_omits_backup(tmp_path: Path):
    shim = _make_stub_dir(tmp_path)
    result = _run(["docker"], tmp_path, {**_PINNED, "SKIP_BACKUP": "true"}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    # warn() writes to stderr, unlike a bare echo.
    assert "WARN: SKIP_BACKUP=true — proceeding without a backup." in result.stderr
    # The backup shell-out must NOT have fired…
    assert "STUB task backup" not in out
    # …but the rest of the flow still ran to completion.
    assert "STUB task upgrade:stage-code" in out
    assert "upgrade complete (this host)" in out


# ── multiserver ───────────────────────────────────────────────────────────────


def test_multiserver_requires_deploy_hosts(tmp_path: Path):
    """DEPLOY_HOSTS is validated before any preflight / ssh / task shell-out."""
    shim = _make_stub_dir(tmp_path)
    result = _run(["multiserver"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 1
    assert "ERROR: DEPLOY_HOSTS is required" in result.stderr
    # It aborted before reaching preflight — no downstream step fired.
    assert "STUB task deploy:preflight" not in result.stdout


def test_multiserver_reads_deploy_hosts_from_deploy_env(tmp_path: Path):
    """upgrade:multiserver was the only deploy script that ignored deploy.env — and
    the one the docs call the safe upgrade path, so it aborted on its first check."""
    shim = _make_stub_dir(tmp_path)
    _healthy_curl(shim)
    # A checkout, so this exercises deploy.env precedence rather than the no-git path that
    # downloads the published package (covered separately below).
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example.com,w1.example.com\nDEPLOY_REMOTE_DIR=/srv/logstotal\n")

    result = _run(["multiserver"], tmp_path, {**_PINNED_GIT, "DEPLOY_ENV_FILE": "deploy.env"}, path_prefix=shim)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "STUB task deploy:preflight" in result.stdout, "aborted despite deploy.env supplying DEPLOY_HOSTS"


def test_caller_env_still_wins_over_deploy_env(tmp_path: Path):
    """Same precedence as the sibling scripts: explicit env beats the file."""
    shim = _make_stub_dir(tmp_path)
    _healthy_curl(shim)
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=from-file.example.com\n")

    result = _run(
        ["multiserver"],
        tmp_path,
        {**_PINNED_GIT, "DEPLOY_ENV_FILE": "deploy.env", "DEPLOY_HOSTS": "from-env.example.com"},
        path_prefix=shim,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "from-env.example.com" in result.stdout
    assert "from-file.example.com" not in result.stdout


# ── stage-code ────────────────────────────────────────────────────────────────


def test_stage_code_archive_not_found_errors(tmp_path: Path):
    result = _run(
        ["stage-code"],
        tmp_path,
        {"ARCHIVE": "/nonexistent/file.7z"},
    )
    assert result.returncode == 1
    assert "=== upgrade:stage-code (archive) → /nonexistent/file.7z ===" in result.stdout
    assert "ERROR: archive not found: /nonexistent/file.7z" in result.stderr


def _git_that_rejects_tags(shim: Path, tags: tuple[str, ...] = (), *, other_failure: bool = False) -> None:
    """Replace the `git` stub with one whose `fetch` fails the way a divergent tag makes it.

    Verbatim from a real run: git names the tag and nothing else, and the non-zero exit takes
    the whole upgrade down with it — after preflight has passed and a backup has been taken.
    `other_failure` is the control: a fetch that failed for some other reason must still be
    fatal, or the leniency here would swallow an unreachable server.
    """
    rejects = "".join(f'echo " ! [rejected]          {t}    -> {t}  (would clobber existing tag)" >&2\n' for t in tags)
    if other_failure:
        rejects = 'echo "fatal: unable to access origin: Could not resolve host" >&2\n'
    git = shim / "git"
    # Skip leading `-c key=value` pairs before dispatching, exactly as real git does.
    # Without this the stub keys off `$1` and stops recognising `fetch` the moment the
    # script passes a global flag — which it does, to bound a stalled transfer and
    # refuse a credential prompt. A fake that does not model the real CLI turns a
    # behaviour test into a test of the fake.
    git.write_text(
        f"""#!/bin/sh
while [ "$1" = "-c" ]; do shift 2; done
case "$1" in
  fetch) {rejects}exit 1 ;;
  diff) exit 0 ;;
  *) echo "STUB git $*"; exit 0 ;;
esac
"""
    )
    git.chmod(0o755)


def test_an_unrelated_divergent_tag_does_not_abort_the_upgrade(tmp_path: Path):
    """The whole point: `git fetch --all --tags` fails as a unit.

    One tag disagreeing about some old release stopped a v9.9.9 upgrade that had already
    passed preflight and taken a verified backup — over a tag it never looks at.
    """
    shim = _make_stub_dir(tmp_path)
    _git_that_rejects_tags(shim, ("v0.9.3",))
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here

    result = _run(["stage-code"], tmp_path, _PINNED_GIT, path_prefix=shim)
    out = result.stdout + result.stderr

    assert result.returncode == 0, out
    assert "v0.9.3" in out, "the tag has to be named — the raw git line is the only clue today"
    assert "none of them is v9.9.9" in out
    assert "STUB git checkout" in out, "the upgrade must actually go on to stage the code"


def test_a_divergent_tag_that_IS_the_release_stops_the_upgrade(tmp_path: Path):
    """The one case where continuing would install the wrong tree.

    The local and published v9.9.9 disagree, so checking out the local one deploys something
    that is not the published v9.9.9 — silently, since the checkout itself succeeds.
    """
    shim = _make_stub_dir(tmp_path)
    _git_that_rejects_tags(shim, ("v0.9.3", "v9.9.9"))
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here

    result = _run(["stage-code"], tmp_path, _PINNED_GIT, path_prefix=shim)
    out = result.stdout + result.stderr

    assert result.returncode == 1, out
    assert "v9.9.9 is the release being deployed" in out
    assert "STUB git checkout" not in out, "stopped before staging, not after"


def test_a_fetch_that_failed_for_any_other_reason_is_still_fatal(tmp_path: Path):
    """Leniency scoped to the tag case only — an unreachable server must not sail through."""
    shim = _make_stub_dir(tmp_path)
    _git_that_rejects_tags(shim, other_failure=True)
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here

    result = _run(["stage-code"], tmp_path, _PINNED_GIT, path_prefix=shim)
    out = result.stdout + result.stderr

    assert result.returncode == 1, out
    assert "not over a tag conflict" in out
    assert "STUB git checkout" not in out


@pytest.mark.skipif(shutil.which("task") is None, reason="task (go-task) not available")
def test_stage_code_is_shell_reachable_not_internal():
    """upgrade:stage-code must NOT be `internal: true`.

    The upgrade docker/multiserver flows re-enter it via a
    `task upgrade:stage-code` shell subprocess, and go-task refuses internal
    tasks invoked through the CLI — even from inside another task's cmds
    (`task: Task "..." is internal`, observed on go-task 3.52.0). Re-adding
    `internal: true` would make every composed upgrade flow abort at the
    stage-code step; this test trips before an operator does.
    """
    env = {**os.environ}
    for var in _SCRUBBED:
        env.pop(var, None)
    result = subprocess.run(
        ["task", "--dry", "upgrade:stage-code"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "is internal" not in result.stderr


# ── dispatch ──────────────────────────────────────────────────────────────────


def test_unknown_action_prints_usage(tmp_path: Path):
    result = _run(["bogus"], tmp_path)
    assert result.returncode == 1
    assert "Usage: bash scripts/upgrade.sh {upgrade|plan|rollback|stage-code}" in result.stderr


def test_missing_action_prints_usage(tmp_path: Path):
    result = _run([], tmp_path)
    assert result.returncode == 1
    assert "Usage: bash scripts/upgrade.sh {upgrade|plan|rollback|stage-code}" in result.stderr


# ── archive handling ──────────────────────────────────────────────────────────


def test_a_tar_gz_url_is_recognised(tmp_path: Path):
    """`.tar.gz` over HTTP could not be consumed at all, while the docs advertised it.

    The extension was picked with a leftmost-longest sed, so `.*` was maximised and the
    captured group minimised: a `.tar.gz` URL yielded `.gz`, the file downloaded as
    `download.gz`, and extraction then died on "unsupported archive type".
    """
    shim = _make_stub_dir(tmp_path, ("task", "docker", "git", "pdm", "curl"))
    result = _run(
        ["stage-code"],
        tmp_path,
        {**_PINNED, "ARCHIVE": "https://example.com/logstotal.tar.gz"},
        path_prefix=shim,
    )
    # curl is stubbed, so nothing lands — but the type must be read as .tar.gz, never .gz.
    assert "unsupported archive type" not in result.stdout + result.stderr
    assert "cannot tell the archive type" not in result.stdout + result.stderr


def test_an_extensionless_url_is_refused_rather_than_guessed(tmp_path: Path):
    """Defaulting to `.zip` would build a nonsense local path from the whole URL."""
    shim = _make_stub_dir(tmp_path, ("task", "docker", "git", "pdm", "curl"))
    result = _run(
        ["stage-code"],
        tmp_path,
        {**_PINNED, "ARCHIVE": "https://example.com/download"},
        path_prefix=shim,
    )
    assert result.returncode != 0
    assert "cannot tell the archive type" in result.stdout + result.stderr


def test_multiserver_does_not_fail_when_smoke_only_hit_an_auth_wall(tmp_path: Path):
    """An upgrade that worked must not be reported as failed because nobody re-supplied a
    password.

    deploy.env keeps the basic-auth username and never the plaintext, by design, so a re-run
    reaches the smoke step with no credentials and every probe comes back 401. Nothing behind
    the proxy is measured — but migrations ran, and the control plane passed an in-container
    doctor run at step 8. Exit 2 from deploy-smoke.sh says "could not verify"; only exit 1
    says "measured, and broken".

    Note the flow runs deploy-smoke.sh DIRECTLY rather than through `task deploy:smoke`:
    go-task collapses every non-zero exit to 201, so 1 and 2 are indistinguishable through it.
    """
    shim = _make_stub_dir(tmp_path, (*_STUB_CMDS, "rsync", "7z"))
    (shim / "curl").write_text("#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = '%{http_code}' ] && { printf 401; exit 0; }; done\nprintf 'denied'\n")
    (shim / "curl").chmod(0o755)
    (tmp_path / "pkg.7z").write_bytes(b"")

    result = _run(
        ["multiserver"],
        tmp_path,
        {
            **_PINNED,
            "DEPLOY_HOSTS": "cp.example.com",
            "ARCHIVE": "pkg.7z",
            "SKIP_BACKUP": "true",
            "SMOKE_URL": "https://logs.example.com",
        },
        path_prefix=shim,
    )
    combined = result.stdout + result.stderr

    assert "SMOKE COULD NOT VERIFY" in combined, combined[-2500:]
    assert result.returncode == 0, f"a successful upgrade reported as failed:\n{combined[-2500:]}"
    assert "the upgrade completed; its final verification could not run" in combined
    assert "upgrade complete (fleet)" in combined


def test_multiserver_still_fails_when_smoke_measured_a_real_failure(tmp_path: Path):
    """The guard rail on the guard rail: exit 1 must still stop the upgrade.

    A 503 is a MEASURED failure — the deployment answered, and what it said was that it
    is unwell. Contrast the test below, where nothing answered at all.
    """
    shim = _make_stub_dir(tmp_path, (*_STUB_CMDS, "rsync", "7z"))
    (shim / "curl").write_text("#!/bin/sh\nprintf '503'\nexit 0\n")
    (shim / "curl").chmod(0o755)
    (tmp_path / "pkg.7z").write_bytes(b"")

    result = _run(
        ["multiserver"],
        tmp_path,
        {
            **_PINNED,
            "DEPLOY_HOSTS": "cp.example.com",
            "ARCHIVE": "pkg.7z",
            "SKIP_BACKUP": "true",
            "SMOKE_URL": "https://logs.example.com",
        },
        path_prefix=shim,
    )
    combined = result.stdout + result.stderr
    # Must fail AT the smoke step, not before it — else this passes for the wrong reason.
    assert "SMOKE FAILED" in combined, f"never reached the smoke step:\n{combined[-2500:]}"

    assert result.returncode != 0, f"a measured failure did not stop the upgrade:\n{combined[-2500:]}"
    assert "upgrade complete (fleet)" not in combined


def test_an_endpoint_unreachable_from_here_does_not_fail_a_fleet_upgrade(tmp_path: Path):
    """The complaint this exists for: a fleet upgrade that worked, reported as failed.

    `000` is curl reaching no HTTP response at all. Run on its own, deploy-smoke.sh must
    treat that as a failure — it cannot tell a dead application from an unroutable
    address, and "a dead host is not an unverifiable one" is what keeps its auth-wall
    leniency from swallowing a real outage.

    This caller can tell the difference, because it just watched the control plane report
    healthy from INSIDE its own network, through deploy-multiserver.sh's health gate. And
    the default fleet topology is a WireGuard mesh that publishes nothing to the outside,
    so an unreachable endpoint here is the expected outcome of a perfectly good upgrade.
    """
    shim = _make_stub_dir(tmp_path, (*_STUB_CMDS, "rsync", "7z"))
    (shim / "curl").write_text("#!/bin/sh\nprintf '000'\nexit 7\n")
    (shim / "curl").chmod(0o755)
    (tmp_path / "pkg.7z").write_bytes(b"")

    result = _run(
        ["multiserver"],
        tmp_path,
        {
            **_PINNED,
            "DEPLOY_HOSTS": "cp.example.com",
            "ARCHIVE": "pkg.7z",
            "SKIP_BACKUP": "true",
            "SMOKE_URL": "https://logs.example.com",
        },
        path_prefix=shim,
    )
    combined = result.stdout + result.stderr

    assert "SMOKE COULD NOT VERIFY" in combined, f"never reached the smoke step:\n{combined[-2500:]}"
    assert "SMOKE FAILED" not in combined
    assert result.returncode == 0, f"an upgrade that worked was reported as failed:\n{combined[-2500:]}"
    assert "upgrade complete (fleet)" in combined


def test_multiserver_refuses_a_package_it_cannot_extract_remotely(tmp_path: Path):
    """Each host extracts with `7z`, so only a .7z can be a DEPLOY_PACKAGE.

    upgrade:docker rsyncs a tree over the install dir and accepts any
    supported archive, so this asymmetry is real and worth naming up front rather than
    failing on every host in phase 3.
    """
    shim = _make_stub_dir(tmp_path)
    (tmp_path / "pkg.zip").write_bytes(b"")
    result = _run(
        ["multiserver"],
        tmp_path,
        {**_PINNED, "DEPLOY_HOSTS": "cp.example.com", "ARCHIVE": "pkg.zip"},
        path_prefix=shim,
    )
    assert result.returncode != 0
    assert "needs a .7z package" in result.stdout + result.stderr


def test_a_control_plane_can_upgrade_the_install_it_is_running_from(tmp_path: Path):
    """Upgrades are meant to run FROM the control plane, over the install that is serving.

    Extracting the release over DEPLOY_REMOTE_DIR with `7z x -aoa` would rewrite these
    scripts under the descriptor bash is reading them from. The deploy stages beside the
    install and rsyncs across instead, and rsync renames rather than truncates, so there is
    nothing to refuse. A sibling script replaced by that
    same overlay is a different hazard, handled by pinning this run's scripts to a copy.
    """
    # A real archive and no 7z/rsync stubs: the point is that the overlay really lands on
    # the tree the script is running from, which a stub cannot show.
    #
    # The install directory is a SUBDIRECTORY, and the run stands in it. The shim and the
    # archive stay outside, because the overlay's --delete removes anything the release does
    # not carry — which is correct, and would otherwise eat the test's own tooling.
    shim = _make_stub_dir(tmp_path)
    _healthy_curl(shim)
    # The control-plane health gate runs its probe HERE for a `local` host, through this
    # stub rather than over ssh.
    (shim / "docker").write_text('#!/bin/sh\ncase "$*" in */health*) printf 200 ;; *) echo "STUB docker $*" ;; esac\n')
    (shim / "docker").chmod(0o755)
    archive = _real_package(tmp_path)
    install = tmp_path / "install"
    install.mkdir()
    (install / "VERSION").write_text("version: 0.9.1\n", encoding="utf-8")
    result = _run(
        ["multiserver"],
        tmp_path,
        {
            **_PINNED,
            "DEPLOY_HOSTS": "local,w1.example.com",
            "DEPLOY_REMOTE_DIR": str(install),
            "ARCHIVE": str(archive),
            "SKIP_BACKUP": "true",
            "SMOKE_URL": "https://logs.example.com",
        },
        path_prefix=shim,
        cwd=install,
    )
    combined = result.stdout + result.stderr
    assert "extract over" not in combined
    assert result.returncode == 0, combined[-2500:]
    assert "upgrade complete (fleet)" in combined


def test_a_control_plane_with_no_checkout_uses_the_published_package(tmp_path: Path):
    """The control-plane path needs no git and no `task package`.

    Upgrades are releases-only, so the artifact to deploy already exists and is the one CI
    built. Downloading it beats rebuilding it locally: no Tailwind CLI, no 7z creation, and
    the fleet gets the published bytes rather than a local reproduction of them.
    """
    shim = _make_stub_dir(tmp_path)
    result = _run(
        ["multiserver"],
        tmp_path,
        {**_PINNED, "DEPLOY_HOSTS": "local,w1.example.com", "DEPLOY_REMOTE_DIR": "/opt/logstotal"},
        path_prefix=shim,
    )
    out = result.stdout + result.stderr
    assert "using the published package for v9.9.9" in out
    assert "logstotal-9.9.9.7z" in out
    assert "STUB task package" not in out, "it must not rebuild what has already been published"
    assert "STUB task upgrade:stage-code" not in out, "and must not stage a tree it does not need"


# ── code snapshots / upgrade:rollback ─────────────────────────────────────────
#
# The fleet has had a rollback point since it existed; a single-host install had none, so
# its only documented code rollback was "re-run the upgrade with the older version" — which
# needs the network, needs that release to still be published, and cannot remove a file the
# newer release added.


def _install(tmp_path: Path, version: str = "0.9.14", revisions: tuple[str, ...] = ("0001_a.py",)) -> None:
    """A minimal installed tree: a VERSION, some code, some state, some migrations."""
    (tmp_path / "VERSION").write_text(f"version: {version}\n")
    (tmp_path / ".env").write_text("SECRET_KEY=live\n")
    (tmp_path / "app").mkdir(exist_ok=True)
    (tmp_path / "app" / "main.py").write_text(f"# {version}\n")
    (tmp_path / "alembic" / "versions").mkdir(parents=True, exist_ok=True)
    for rev in revisions:
        (tmp_path / "alembic" / "versions" / rev).write_text("")
    for state in ("data", "uploads"):
        (tmp_path / state).mkdir(exist_ok=True)
        (tmp_path / state / "keep.me").write_text("live state\n")


def _snapshots(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "backups" / "releases").glob("*/"))


def test_the_upgrade_snapshots_the_tree_before_it_stages_over_it(tmp_path: Path):
    """After the backup, before staging — staging is what destroys the thing being kept."""
    _install(tmp_path)
    shim = _make_stub_dir(tmp_path)
    result = _run(["docker"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr

    _assert_ordered(result.stdout, ["STUB task backup", ">>> snapshot:", "STUB task upgrade:stage-code"])
    snaps = _snapshots(tmp_path)
    assert len(snaps) == 1
    assert (snaps[0] / "VERSION").read_text() == "version: 0.9.14\n"


def test_a_snapshot_never_carries_secrets_or_live_state(tmp_path: Path):
    """Wider excludes than the fleet's remote_snapshot, which copies certs/ and
    deploy-envs/ — so on a control plane every rollback point holds the TLS private key and
    the fleet's generated env files. A code snapshot has no reason to carry either."""
    _install(tmp_path)
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "key.pem").write_text("PRIVATE KEY\n")
    (tmp_path / "deploy-envs").mkdir()
    (tmp_path / "deploy-envs" / "secrets.json").write_text('{"SECRET_KEY": "x"}\n')
    shim = _make_stub_dir(tmp_path)
    assert _run(["docker"], tmp_path, _PINNED, path_prefix=shim).returncode == 0

    snap = _snapshots(tmp_path)[0]
    for forbidden in (".env", "certs", "deploy-envs", "data", "uploads", "backups"):
        assert not (snap / forbidden).exists(), f"{forbidden} must not be snapshotted"
    assert (snap / "app" / "main.py").exists(), "the code itself must be"


def test_re_running_a_current_upgrade_keeps_the_real_rollback_point(tmp_path: Path):
    """`upgrade:docker` is also the REPAIR flow — code current, containers down. A second
    run must not snapshot the new release over the old one and quietly turn
    upgrade:rollback into a no-op."""
    _install(tmp_path)
    shim = _make_stub_dir(tmp_path)
    assert _run(["docker"], tmp_path, _PINNED, path_prefix=shim).returncode == 0
    first = _snapshots(tmp_path)
    assert len(first) == 1

    result = _run(["docker"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0
    assert "already holds 0.9.14 — keeping it" in result.stdout
    assert _snapshots(tmp_path) == first


def test_skip_snapshot_says_what_it_costs(tmp_path: Path):
    _install(tmp_path)
    shim = _make_stub_dir(tmp_path)
    result = _run(["docker"], tmp_path, {**_PINNED, "SKIP_SNAPSHOT": "true"}, path_prefix=shim)
    assert result.returncode == 0
    assert "no local rollback point" in result.stdout + result.stderr
    assert not _snapshots(tmp_path)


def test_rollback_restores_removes_and_consumes(tmp_path: Path):
    """--delete is the point: without it a rollback cannot undo a file the newer release
    ADDED, and the tree ends up a mixture of two releases."""
    _install(tmp_path, "0.9.14")
    shim = _make_stub_dir(tmp_path)
    assert _run(["docker"], tmp_path, _PINNED, path_prefix=shim).returncode == 0

    # Now look like the newer release: changed file, added file, same migrations.
    (tmp_path / "VERSION").write_text("version: 0.9.15\n")
    (tmp_path / "app" / "main.py").write_text("# 0.9.15\n")
    (tmp_path / "app" / "added_in_0915.py").write_text("new\n")

    result = _run(["rollback"], tmp_path, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr

    # Rich context on every assertion here: this pair of steps is the one place a silent
    # no-op looks identical to a success, and a bare `assert a == b` in CI says only that
    # the tree was not restored, not what the snapshot held or what the restore printed.
    def _ctx() -> str:
        listing = "\n".join(sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")))
        return f"\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}\n--- tree ---\n{listing}"

    assert (tmp_path / "VERSION").read_text() == "version: 0.9.14\n", _ctx()
    assert (tmp_path / "app" / "main.py").read_text() == "# 0.9.14\n", _ctx()
    assert not (tmp_path / "app" / "added_in_0915.py").exists(), "--delete must remove it" + _ctx()
    assert (tmp_path / ".env").read_text() == "SECRET_KEY=live\n", "never touched" + _ctx()
    assert (tmp_path / "data" / "keep.me").exists() and (tmp_path / "uploads" / "keep.me").exists(), _ctx()
    assert not _snapshots(tmp_path), "the snapshot it restored is consumed" + _ctx()


def test_rollback_rebuilds_and_restarts(tmp_path: Path):
    """No code is bind-mounted, so restoring the tree alone leaves the containers running
    the newer image — and printing success there is the silently-false success the fleet's
    rollback tests exist to stop."""
    _install(tmp_path)
    shim = _make_stub_dir(tmp_path)
    assert _run(["docker"], tmp_path, _PINNED, path_prefix=shim).returncode == 0
    (tmp_path / "VERSION").write_text("version: 0.9.15\n")

    result = _run(["rollback"], tmp_path, path_prefix=shim)
    _assert_ordered(
        result.stdout,
        ["(consumed)", "STUB docker compose build", "STUB docker compose up -d", "STUB task health:remote"],
    )


def test_rollback_refuses_across_a_migration_the_snapshot_lacks(tmp_path: Path):
    """The one case where code rollback alone is genuinely unsafe: the database stays
    stamped at the newer revision, and app/migrations.py will not boot past a revision it
    can no longer find on disk."""
    _install(tmp_path, "0.9.14", revisions=("0001_a.py",))
    shim = _make_stub_dir(tmp_path)
    assert _run(["docker"], tmp_path, _PINNED, path_prefix=shim).returncode == 0

    (tmp_path / "VERSION").write_text("version: 0.9.15\n")
    (tmp_path / "alembic" / "versions" / "0002_b.py").write_text("")

    result = _run(["rollback"], tmp_path, path_prefix=shim)
    assert result.returncode != 0
    assert "0002_b.py" in result.stderr, "it must name the migration"
    assert "restore:sqlite" in result.stderr, "and what to do about it"
    assert _snapshots(tmp_path), "the snapshot is kept so the operator can retry"


def test_rollback_with_nothing_to_restore_says_where_snapshots_come_from(tmp_path: Path):
    _install(tmp_path)
    shim = _make_stub_dir(tmp_path)
    result = _run(["rollback"], tmp_path, path_prefix=shim)
    assert result.returncode != 0
    assert "no snapshot to roll back to" in result.stderr
    assert "./logstotal upgrade VERSION=" in result.stderr


# ── SOURCE: where the code comes from ─────────────────────────────────────────
#
# Explicit and overridable: if `[ -d .git ]` chose silently, an operator who wanted the
# other one would have no way to ask and no way to tell which they had got.


def _release_archive(tmp_path: Path, version: str = "9.9.9", extra: dict[str, str] | None = None) -> Path:
    """A .7z-shaped stand-in: a directory the stage step can rsync from, handed to the
    script as ARCHIVE=. Exercises the overlay without needing 7z in the test environment."""
    src = tmp_path / "release-src"
    (src / "app" / "templates").mkdir(parents=True, exist_ok=True)
    (src / "alembic" / "versions").mkdir(parents=True, exist_ok=True)
    (src / "VERSION").write_text(f"version: {version}\n")
    (src / "Taskfile.yml").write_text("version: '3'\n")
    (src / "app" / "main.py").write_text(f"# {version}\n")
    for path, body in (extra or {}).items():
        target = src / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    archive = tmp_path / f"logstotal-{version}.tar.gz"
    subprocess.run(["tar", "-czf", str(archive), "-C", str(src), "."], check=True)
    return archive


def test_an_unknown_source_is_refused_by_name(tmp_path: Path):
    """SOURCE is a short generic name a caller's shell may already export. Validating it
    turns ambient pollution into a message instead of a silent wrong mode."""
    shim = _make_stub_dir(tmp_path)
    result = _run(["stage-code"], tmp_path, {**_PINNED, "SOURCE": "/usr/local/src"}, path_prefix=shim)
    assert result.returncode != 0
    assert "is not a source" in result.stderr
    for named in ("package", "git", "archive"):
        assert named in result.stderr, "the refusal must name the valid ones"


def test_source_git_without_a_checkout_says_so(tmp_path: Path):
    shim = _make_stub_dir(tmp_path)
    result = _run(["stage-code"], tmp_path, _PINNED_GIT, path_prefix=shim)
    assert result.returncode != 0
    assert "SOURCE=git needs a git checkout" in result.stderr


def test_source_git_and_archive_together_are_refused(tmp_path: Path):
    """They ask for different things; guessing which one the operator meant is worse than
    asking."""
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    shim = _make_stub_dir(tmp_path)
    result = _run(["stage-code"], tmp_path, {"SOURCE": "git", "ARCHIVE": "/tmp/x.7z"}, path_prefix=shim)
    assert result.returncode != 0
    assert "ask for different things" in result.stderr


def test_source_archive_without_an_archive_is_refused(tmp_path: Path):
    shim = _make_stub_dir(tmp_path)
    result = _run(["stage-code"], tmp_path, {**_PINNED, "SOURCE": "archive"}, path_prefix=shim)
    assert result.returncode != 0
    assert "needs ARCHIVE=" in result.stderr


def test_an_unreleased_ref_cannot_be_a_package(tmp_path: Path):
    """The URL would be .../releases/download/main/logstotal-main.7z, which cannot exist.
    Say what is actually wrong rather than 404ing on a nonsense name."""
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    shim = _make_stub_dir(tmp_path)
    result = _run(
        ["stage-code"],
        tmp_path,
        {"REF": "main", "ALLOW_UNRELEASED": "true", "SOURCE": "package"},
        path_prefix=shim,
    )
    assert result.returncode != 0
    assert "SOURCE=package cannot stage REF=main" in result.stderr


def test_an_unreleased_ref_falls_to_git_on_its_own(tmp_path: Path):
    """With SOURCE unset, an unreleased ref picks git rather than refusing — only git can
    stage one, and there is no ambiguity to resolve."""
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    shim = _make_stub_dir(tmp_path)
    result = _run(
        ["stage-code"],
        tmp_path,
        {"REF": "main", "ALLOW_UNRELEASED": "true"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "STUB git checkout" in result.stdout


def test_a_dirty_tree_is_refused_whatever_the_source(tmp_path: Path):
    """Not only in the git arm: `git checkout` refuses to clobber a modified tracked file,
    so git mode is guarded by git itself — but rsync has no such abort.
    """
    archive = _release_archive(tmp_path)
    shim = _make_stub_dir(tmp_path, ("task", "docker", "pdm", "ssh", "scp", "sleep", "curl"))
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    # A real git binary, reporting a dirty tree.
    (shim / "git").write_text('#!/bin/sh\ncase "$*" in *diff*) exit 1 ;; esac\necho "STUB git $*"\n')
    (shim / "git").chmod(0o755)

    result = _run(["stage-code"], tmp_path, {"ARCHIVE": str(archive)}, path_prefix=shim)
    assert result.returncode != 0
    assert "uncommitted changes" in result.stderr
    assert "there is nothing to refuse it" in result.stderr


@pytest.mark.parametrize("checkout", [False, True])
def test_the_overlay_replaces_files_with_matching_size_and_mtime(tmp_path: Path, checkout: bool):
    """Archive staging must compare content even when release metadata collides."""
    archive = _release_archive(tmp_path, version="1.2.3", extra={"alembic/versions/0001_a.py": "# new\n"})
    install = tmp_path / "installed"
    install.mkdir()
    if checkout:
        (install / ".git").mkdir()
    expected = {}
    for name, old in {"VERSION": "version: 0.0.1\n", "app/main.py": "# 0.0.1\n", "alembic/versions/0001_a.py": "# old\n"}.items():
        source = tmp_path / "release-src" / name
        target = install / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(old)
        expected[name] = source.read_text()
        assert target.stat().st_size == source.stat().st_size
        for path in (source, target):
            os.utime(path, (1_777_000_000, 1_777_000_000))
    subprocess.run(["tar", "-czf", str(archive), "-C", str(tmp_path / "release-src"), "."], check=True)
    shim = _make_stub_dir(tmp_path)

    result = _run(["stage-code"], tmp_path, {"ARCHIVE": str(archive)}, path_prefix=shim, cwd=install)
    assert result.returncode == 0, result.stdout + result.stderr
    for name, content in expected.items():
        assert (install / name).read_text() == content, f"staging skipped changed content in {name}"


def test_the_overlay_deletes_stale_migrations_on_a_checkout(tmp_path: Path):
    """Without this, `task upgrade:docker VERSION=<older>` leaves the newer revisions on
    disk, get_head_revision() resolves head to a migration the installed code does not
    contain, and the migrate step rolls the SCHEMA FORWARD while the operator rolls the code
    back. Four shipped migrations are destructive. That is the documented rollback path.
    """
    archive = _release_archive(tmp_path, extra={"alembic/versions/0001_a.py": ""})
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    (tmp_path / "alembic" / "versions").mkdir(parents=True)
    (tmp_path / "alembic" / "versions" / "0001_a.py").write_text("")
    (tmp_path / "alembic" / "versions" / "0002_newer.py").write_text("")
    # Tracked files the release archive never carries: git owns these, not the overlay.
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("keep me\n")
    shim = _make_stub_dir(tmp_path)

    result = _run(["stage-code"], tmp_path, {"ARCHIVE": str(archive)}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr

    assert not (tmp_path / "alembic" / "versions" / "0002_newer.py").exists()
    assert (tmp_path / "alembic" / "versions" / "0001_a.py").exists()
    assert (tmp_path / "tests" / "test_x.py").exists(), "package.sh excludes tests/, so a full --delete on a checkout would wipe tracked files the archive never claimed to carry"


def test_the_overlay_deletes_everything_on_an_archive_install(tmp_path: Path):
    """There, the archive IS the whole tree — so files renamed or removed upstream do not
    remain on disk."""
    archive = _release_archive(tmp_path)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "removed_upstream.py").write_text("gone in the new release\n")
    (tmp_path / ".env").write_text("SECRET_KEY=live\n")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "keep.me").write_text("state\n")
    shim = _make_stub_dir(tmp_path)

    result = _run(["stage-code"], tmp_path, {"ARCHIVE": str(archive)}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr

    assert not (tmp_path / "app" / "removed_upstream.py").exists()
    assert (tmp_path / ".env").read_text() == "SECRET_KEY=live\n"
    assert (tmp_path / "data" / "keep.me").exists()


def test_a_checkout_keeps_its_own_base_html(tmp_path: Path):
    """The archive ships base.html in PRODUCTION mode (package.sh runs css:build, archives,
    then restores dev mode) while HEAD holds the Play-CDN block. Overlaying it leaves the
    tree permanently dirty, so the next SOURCE=git run dies on the dirty guard naming no
    file. It costs nothing to keep: the Dockerfile rebuilds both in its css stage and copies
    them over whatever `COPY . .` laid down.
    """
    archive = _release_archive(tmp_path, extra={"app/templates/base.html": "PROD tailwind-built.css\n"})
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    (tmp_path / "app" / "templates").mkdir(parents=True)
    (tmp_path / "app" / "templates" / "base.html").write_text("DEV vendor/tailwind.js\n")
    shim = _make_stub_dir(tmp_path)

    assert _run(["stage-code"], tmp_path, {"ARCHIVE": str(archive)}, path_prefix=shim).returncode == 0
    assert (tmp_path / "app" / "templates" / "base.html").read_text() == "DEV vendor/tailwind.js\n"


def test_an_archive_install_does_take_the_archives_base_html(tmp_path: Path):
    """The other half: with no checkout there is nothing to keep dirty, and the production
    stylesheet is exactly what the archive is for."""
    archive = _release_archive(tmp_path, extra={"app/templates/base.html": "PROD tailwind-built.css\n"})
    (tmp_path / "app" / "templates").mkdir(parents=True)
    (tmp_path / "app" / "templates" / "base.html").write_text("OLD\n")
    shim = _make_stub_dir(tmp_path)

    assert _run(["stage-code"], tmp_path, {"ARCHIVE": str(archive)}, path_prefix=shim).returncode == 0
    assert (tmp_path / "app" / "templates" / "base.html").read_text() == "PROD tailwind-built.css\n"


def test_the_overlay_never_erases_the_hosts_release_origin(tmp_path: Path):
    """`.release-origin` records the server this deployment upgrades FROM, so --delete
    removing it would silently return the host to the built-in default on its NEXT upgrade
    — and every release built before the stamp existed carries none."""
    archive = _release_archive(tmp_path)  # no .release-origin in it
    (tmp_path / ".release-origin").write_text("url: http://forge.example.com:3000/you/LogsTotal\n")
    shim = _make_stub_dir(tmp_path)

    assert _run(["stage-code"], tmp_path, {"ARCHIVE": str(archive)}, path_prefix=shim).returncode == 0
    assert (tmp_path / ".release-origin").read_text() == "url: http://forge.example.com:3000/you/LogsTotal\n"


def test_an_archive_that_carries_a_release_origin_replaces_it(tmp_path: Path):
    """The other direction: a project that moved forges has to be able to say so."""
    archive = _release_archive(tmp_path, extra={".release-origin": "url: https://new.example.com/you/LogsTotal\n"})
    (tmp_path / ".release-origin").write_text("url: http://old.example.com:3000/you/LogsTotal\n")
    shim = _make_stub_dir(tmp_path)

    assert _run(["stage-code"], tmp_path, {"ARCHIVE": str(archive)}, path_prefix=shim).returncode == 0
    assert (tmp_path / ".release-origin").read_text() == "url: https://new.example.com/you/LogsTotal\n"


# ── fleet hosts as positionals ────────────────────────────────────────────────


def test_positional_hosts_beat_a_deploy_env_naming_another_fleet(tmp_path: Path):
    """Getting this wrong is worse than a missing feature.

    go-task never exports a CLI variable to the shell, so with
    `task upgrade:multiserver DEPLOY_HOSTS="cp,w1"` the script would never see the hosts,
    fall through to deploy.env, and upgrade THE FLEET NAMED THERE. Not an abort: a
    different fleet.
    """
    shim = _make_stub_dir(tmp_path)
    _healthy_curl(shim)
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=other-fleet.example.com\n")

    result = _run(
        ["multiserver", "cp.example.com", "w1.example.com"],
        tmp_path,
        {**_PINNED_GIT, "DEPLOY_ENV_FILE": "deploy.env"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "cp.example.com" in result.stdout
    assert "other-fleet.example.com" not in result.stdout


def test_deploy_env_still_answers_when_no_hosts_are_named(tmp_path: Path):
    """Positionals are an addition, not a replacement — `task deploy:*` with a working
    deploy.env must keep working."""
    shim = _make_stub_dir(tmp_path)
    _healthy_curl(shim)
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=from-file.example.com\n")

    result = _run(["multiserver"], tmp_path, {**_PINNED_GIT, "DEPLOY_ENV_FILE": "deploy.env"}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "from-file.example.com" in result.stdout


def test_a_host_that_is_not_a_host_is_refused(tmp_path: Path):
    shim = _make_stub_dir(tmp_path)
    result = _run(["multiserver", "cp; rm -rf /"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode != 0
    assert "Not a host" in result.stderr


def test_only_the_upgrade_itself_takes_positionals(tmp_path: Path):
    """A host list handed to the wrong action is a typo, and swallowing it silently would
    upgrade this host while the operator believed they had named a fleet."""
    shim = _make_stub_dir(tmp_path)
    result = _run(["plan", "cp.example.com"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode != 0
    assert "takes no arguments" in result.stderr
    assert "./logstotal upgrade -- cp w1 w2" in result.stderr


def test_one_verb_chooses_the_scope_from_the_machine(tmp_path: Path):
    """Choosing between a single-host and a fleet upgrade is not the operator's job: the
    answer is a fact about the machine — is there a fleet to upgrade?

    Getting it wrong would not be a refusal, either. A single-host upgrade run on a control
    plane upgrades the control plane and leaves every worker on the old release, running
    against a freshly migrated database."""
    shim = _make_stub_dir(tmp_path, (*_STUB_CMDS, "rsync", "7z"))
    (tmp_path / "pkg.7z").write_bytes(b"")
    _healthy_curl(shim)

    # No fleet named anywhere → this host alone.
    alone = _run(
        ["upgrade"],
        tmp_path,
        {**_PINNED, "ARCHIVE": "pkg.7z", "SKIP_BACKUP": "true"},
        path_prefix=shim,
    )
    assert "scope: this host alone" in alone.stdout, alone.stdout[-1500:]
    assert "upgrade complete (this host)" in alone.stdout

    # A fleet named as arguments → the fleet path.
    fleet = _run(
        ["upgrade", "cp.example.com", "w1.example.com"],
        tmp_path,
        {**_PINNED, "ARCHIVE": "pkg.7z", "SKIP_BACKUP": "true", "SMOKE_URL": "https://x.example"},
        path_prefix=shim,
    )
    assert "scope: this host alone" not in fleet.stdout
    assert "upgrade complete (fleet)" in fleet.stdout, fleet.stdout[-1500:]


def test_a_fleet_record_alone_is_enough_to_choose_the_fleet_path(tmp_path: Path):
    """The control-plane case: no deploy.env, no arguments, but this host knows what fleet
    it belongs to. That is the whole reason the record exists."""
    install = tmp_path / "opt"
    (install / "fleet").mkdir(parents=True)
    (install / "fleet" / "manifest.json").write_text(
        '{"schema": 1, "hosts": [{"entry": "cp.example.com", "role": "control-plane"}, {"entry": "w1.example.com", "role": "worker"}], "options": {}, "release": {}}',
        encoding="utf-8",
    )
    shim = _make_stub_dir(tmp_path, (*_STUB_CMDS, "rsync", "7z"))
    (tmp_path / "pkg.7z").write_bytes(b"")
    _healthy_curl(shim)
    result = _run(
        ["upgrade"],
        tmp_path,
        {
            **_PINNED,
            "ARCHIVE": "pkg.7z",
            "SKIP_BACKUP": "true",
            "DEPLOY_REMOTE_DIR": str(install),
            "SMOKE_URL": "https://x.example",
        },
        path_prefix=shim,
    )
    assert "scope: this host alone" not in result.stdout
    assert "upgrade complete (fleet)" in result.stdout, result.stdout[-1500:]


# ── SKIP_IF_CURRENT and the pre-upgrade record, for a fleet ───────────────────
#
# Both were documented for every upgrade task and implemented only for docker. They could
# not simply be called here: _report_installed_version reads the LOCAL VERSION, which for a
# fleet describes the workstation and not the deployment — and under the package default the
# local tree is never staged at all.


def _fleet(tmp_path: Path, remote_version: str, running: bool = True) -> Path:
    """A stand-in control plane: a directory with a VERSION, reachable as host `local`."""
    remote = tmp_path / "cpdir"
    remote.mkdir(exist_ok=True)
    (remote / "VERSION").write_text(f"version: {remote_version}\n")
    (tmp_path / ".git").mkdir(exist_ok=True)
    # A real archive in the working directory, because the fleet flow runs the real
    # five-phase deploy rather than a stubbed task — and resolve_package looks exactly
    # here. Nothing has to name it.
    _real_package(tmp_path)
    return remote


def _real_package(tmp_path: Path, version: str = "9.9.9") -> Path:
    """A genuine `logstotal-<version>.7z` carrying a VERSION at its root.

    The fleet flow reaches the real deploy rather than a stubbed task, and phase 3
    extracts what it is given and refuses an archive with no VERSION — correctly, since a
    tree without one is not a LogsTotal release. So these tests supply one, and in doing so
    exercise stage-and-overlay for real instead of asserting around it.
    """
    src = tmp_path / "pkgsrc"
    src.mkdir(exist_ok=True)
    (src / "VERSION").write_text(f"version: {version}\n", encoding="utf-8")
    (src / "Taskfile.yml").write_text("version: '3'\n", encoding="utf-8")
    archive = tmp_path / f"logstotal-{version}.7z"
    archive.unlink(missing_ok=True)
    subprocess.run(["7z", "a", "-mf=off", str(archive), "."], cwd=src, capture_output=True, check=True)
    return archive


def _fleet_shim(tmp_path: Path, running: bool = True) -> Path:
    """Stubs for a local-fleet flow — but NOT for 7z or rsync.

    Phase 3 really extracts and really overlays (see _real_package), and stubbing the
    two tools that do it would assert around the mechanism rather than through it."""
    shim = _make_stub_dir(tmp_path)
    _healthy_curl(shim)
    body = "echo cid1" if running else "true"
    # `/health` answers 200: for a `local` host the control-plane health gate runs the probe
    # right here, through this stub, and would otherwise spend its whole budget reading
    # "STUB docker …" and fail an upgrade that worked.
    (shim / "docker").write_text(f'#!/bin/sh\ncase "$*" in\n  *"ps -q"*) {body} ;;\n  */health*) printf 200 ;;\n  *) echo "STUB docker $*" ;;\nesac\n')
    (shim / "docker").chmod(0o755)
    return shim


def test_the_fleet_survey_reads_each_host_not_the_workstation(tmp_path: Path):
    """Under the package default the local tree is never staged, so its VERSION is often the
    release you are upgrading FROM — or nothing at all."""
    remote = _fleet(tmp_path, "0.9.1")
    (tmp_path / "VERSION").write_text("version: 0.0.0\n")  # the workstation, deliberately wrong
    shim = _fleet_shim(tmp_path)

    result = _run(
        ["multiserver", "local"],
        tmp_path,
        {**_PINNED_GIT, "DEPLOY_REMOTE_DIR": str(remote)},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    survey = result.stdout.split("fleet before this upgrade:")[1].split("recorded:")[0]
    assert "0.9.1" in survey, "it must report the HOST's version"
    assert "0.0.0" not in survey, "not the workstation's"
    # upgrade_done still reports the local tree, and says so — that line is deliberate.
    # "this machine's VERSION", not "this checkout": run from the control plane there is no
    # checkout, because the toolkit that installed it is meant to be deleted.
    assert "(this machine's VERSION;" in result.stdout

    records = list((tmp_path / "backups").glob("pre-upgrade-version-*.txt"))
    assert len(records) == 1, "docs told operators to read this after a fleet upgrade"
    body = records[0].read_text()
    assert "host local: version=0.9.1" in body
    assert "scope: local" in body


def test_skip_if_current_exits_before_the_backup_when_the_scope_is_current(tmp_path: Path):
    """It has to exit BEFORE the control-plane backup — that is the whole point of the cron
    no-op, and a backup is the expensive part."""
    remote = _fleet(tmp_path, "9.9.9")
    shim = _fleet_shim(tmp_path)

    result = _run(
        ["multiserver", "local"],
        tmp_path,
        {**_PINNED_GIT, "DEPLOY_REMOTE_DIR": str(remote), "SKIP_IF_CURRENT": "true"},
        path_prefix=shim,
    )
    assert result.returncode == 0
    assert "nothing to do" in result.stdout
    assert "STUB task backup" not in result.stdout
    assert "STUB task deploy:preflight" not in result.stdout


def test_skip_if_current_does_not_skip_when_a_host_is_behind(tmp_path: Path):
    remote = _fleet(tmp_path, "0.9.1")
    shim = _fleet_shim(tmp_path)

    result = _run(
        ["multiserver", "local"],
        tmp_path,
        {**_PINNED_GIT, "DEPLOY_REMOTE_DIR": str(remote), "SKIP_IF_CURRENT": "true"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "nothing to do" not in result.stdout
    assert "STUB task backup" in result.stdout


def test_a_current_version_with_nothing_running_is_not_current(tmp_path: Path):
    """ "Code current, containers down" is exactly the half-finished upgrade the repair flow
    exists for — skipping it would strand the operator who most needs the run."""
    remote = _fleet(tmp_path, "9.9.9")
    shim = _fleet_shim(tmp_path, running=False)

    result = _run(
        ["multiserver", "local"],
        tmp_path,
        {**_PINNED_GIT, "DEPLOY_REMOTE_DIR": str(remote), "SKIP_IF_CURRENT": "true"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "nothing to do" not in result.stdout


def test_an_unmeasurable_host_is_never_reported_as_current(tmp_path: Path):
    """deploy-preflight.sh's rule: an unreadable value prints `?` and counts as a failure.
    Never report OK for something you could not measure."""
    remote = tmp_path / "cpdir"
    remote.mkdir()  # exists, but holds no VERSION
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)  # the real deploy runs now, and resolve_package looks here
    shim = _fleet_shim(tmp_path)

    result = _run(
        ["multiserver", "local"],
        tmp_path,
        {**_PINNED_GIT, "DEPLOY_REMOTE_DIR": str(remote), "SKIP_IF_CURRENT": "true"},
        path_prefix=shim,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "? (no VERSION readable)" in result.stdout
    assert "nothing to do" not in result.stdout


# ── upgrade:plan ──────────────────────────────────────────────────────────────


def test_plan_answers_the_three_questions(tmp_path: Path):
    _install(tmp_path)
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    (tmp_path / ".release-origin").write_text("url: https://git.example.com/o/r\n")
    shim = _make_stub_dir(tmp_path)

    result = _run(["plan"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0
    out = result.stdout
    assert "installed  0.9.14" in out
    assert "target     v9.9.9" in out
    assert "server     https://git.example.com/o/r   (from .release-origin)" in out
    assert "source     package" in out
    assert "would run  ./logstotal upgrade" in out


def test_plan_always_exits_zero_even_when_nothing_resolves(tmp_path: Path):
    """Its whole contract. A command whose job is to say what would happen is useless if the
    answer can be "it crashed" — task deploy:plan's discipline, and why the Taskfile entry
    carries no preconditions (a failed precondition exits 201)."""
    shim = _make_stub_dir(tmp_path)
    result = _run(["plan"], tmp_path, {"RELEASE_REPO_URL": "https://nope.invalid/o/r"}, path_prefix=shim)
    assert result.returncode == 0
    assert "target     ?" in result.stdout
    assert "could not resolve" in result.stdout


def test_plan_names_a_tag_whose_release_was_never_published(tmp_path: Path):
    """The failure that otherwise surfaces at download, after the backup."""
    shim = _make_stub_dir(tmp_path, ("task", "docker", "git", "pdm", "ssh", "scp", "sleep"))
    # The server answers; the asset does not exist.
    (shim / "curl").write_text('#!/bin/sh\ncase "$*" in *releases/download*) exit 22 ;; *) exit 0 ;; esac\n')
    (shim / "curl").chmod(0o755)
    result = _run(["plan"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0
    assert "NOT PUBLISHED" in result.stdout


def test_plan_reports_the_rollback_point(tmp_path: Path):
    _install(tmp_path)
    shim = _make_stub_dir(tmp_path)
    assert _run(["docker"], tmp_path, _PINNED, path_prefix=shim).returncode == 0

    result = _run(["plan"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0
    assert "rollback   0.9.14 (./logstotal upgrade:rollback)" in result.stdout


def test_plan_never_assumes_a_fleet(tmp_path: Path):
    """A fleet upgrade has a far larger blast radius than this host, so a fleet is
    reported, never acted on."""
    _install(tmp_path)
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example.com,w1.example.com\n")
    shim = _make_stub_dir(tmp_path)

    result = _run(["plan"], tmp_path, {**_PINNED, "DEPLOY_ENV_FILE": "deploy.env"}, path_prefix=shim)
    assert result.returncode == 0
    assert "fleet — 2 hosts" in result.stdout
    assert "would run  ./logstotal upgrade" in result.stdout


def test_the_plan_sees_the_fleet_the_upgrade_would_act_on(tmp_path: Path):
    """Reading deploy.env alone is not enough. On a control plane there is none — it belongs
    to whoever ran the deploy, and package.sh keeps it out of the archive — so the plan
    would say "single host" about a machine where `task upgrade` upgrades three.

    A plan that disagrees with the command it is planning is worse than no plan. Both ask
    the same function."""
    _install(tmp_path)
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    install = tmp_path / "opt"
    (install / "fleet").mkdir(parents=True)
    (install / "fleet" / "manifest.json").write_text(
        '{"schema": 1, "hosts": ['
        '{"entry": "cp.example.com", "role": "control-plane"},'
        '{"entry": "w1.example.com", "role": "worker"},'
        '{"entry": "w2.example.com", "role": "worker"}'
        '], "options": {}, "release": {}}',
        encoding="utf-8",
    )
    shim = _make_stub_dir(tmp_path)

    result = _run(
        ["plan"],
        tmp_path,
        {**_PINNED, "DEPLOY_REMOTE_DIR": str(install), "DEPLOY_ENV_FILE": "deploy.env.absent"},
        path_prefix=shim,
    )
    assert result.returncode == 0
    assert "fleet — 3 hosts" in result.stdout, result.stdout
    assert "own fleet record" in result.stdout
    assert "single host" not in result.stdout


def test_rollback_restores_a_file_whose_size_and_mtime_did_not_change(tmp_path: Path):
    """rsync's default quick check skips a file when size AND whole-second mtime match, and
    a snapshot preserves the original mtimes while the upgrade that replaced them ran
    moments later. Consecutive versions such as `version: 1.2.3` and `version: 1.2.4` are
    the same size, so VERSION is the likeliest file in the tree to collide.

    A fast machine lands both writes in the same second, and the rollback prints "restored
    ... (consumed)" followed by the newer version still running. The mtimes are forced equal
    here so the test does not depend on how quick the machine is.
    """
    _install(tmp_path, "0.9.14")
    shim = _make_stub_dir(tmp_path)
    assert _run(["docker"], tmp_path, _PINNED, path_prefix=shim).returncode == 0

    snapshot_version = _snapshots(tmp_path)[0] / "VERSION"
    live_version = tmp_path / "VERSION"
    live_version.write_text("version: 0.9.15\n")
    assert live_version.stat().st_size == snapshot_version.stat().st_size, "same size is the premise"
    # Same whole second, deterministically — this is what a fast machine produces by chance.
    os.utime(live_version, (1_777_000_000, 1_777_000_000))
    os.utime(snapshot_version, (1_777_000_000, 1_777_000_000))

    result = _run(["rollback"], tmp_path, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    assert live_version.read_text() == "version: 0.9.14\n", f"rsync skipped the file on size+mtime; the restore must compare content\n--- stdout ---\n{result.stdout}"


# ── Snapshot ordering ────────────────────────────────────────────────────────


def test_the_newest_snapshot_is_the_newest_one_across_a_version_boundary(tmp_path: Path):
    """Snapshot names must not lead with the VERSION, which is not an ordering.

    "0.10.0" sorts before "0.9.15", so once a release crosses a 9 → 10 boundary the
    lexical `tail -1` that picks the rollback point would return the OLDER snapshot — and
    `upgrade:rollback` would silently go back two releases. The prune takes from the HEAD of
    the same list, so it would delete the newest snapshots instead of the oldest.

    Neither is visible until that boundary is crossed. Names lead with the timestamp, so
    lexical order is chronological.
    """
    root = tmp_path / "backups" / "releases"
    older = root / "20260201-000000-0.9.15"
    newer = root / "20260301-000000-0.10.0"
    for d, version in ((older, "0.9.15"), (newer, "0.10.0")):
        d.mkdir(parents=True)
        (d / "VERSION").write_text(f"version: {version}\n")

    # Driven through the real CLI: `upgrade:plan` prints the rollback point it would use.
    # (upgrade.sh runs main() when sourced, so the helper cannot be called directly.)
    shim = _make_stub_dir(tmp_path)
    plan = _run(["plan"], tmp_path, _PINNED, path_prefix=shim)
    assert "rollback   0.10.0" in plan.stdout, f"picked the older snapshot as the rollback point:\n{plan.stdout}"


def test_the_rollback_is_one_verb_too(tmp_path: Path):
    """Having `deploy:rollback` and `upgrade:rollback` side by side reinstated exactly the
    decision the upgrade merge removed — and the wrong pick was silent in both directions:
    the single-host one on a control plane rolled back the control plane and left every
    worker on the release it had just been moved off."""
    shim = _make_stub_dir(tmp_path)
    (tmp_path / ".git").mkdir()
    _real_package(tmp_path)
    root = tmp_path / "backups" / "releases" / "20260101-000000-0.9.1"
    root.mkdir(parents=True)
    (root / "VERSION").write_text("version: 0.9.1\n", encoding="utf-8")
    (tmp_path / "VERSION").write_text("version: 0.9.2\n", encoding="utf-8")

    alone = _run(["rollback"], tmp_path, _PINNED, path_prefix=shim)
    assert "scope: this host alone" in alone.stdout, alone.stdout[-1200:]

    fleet = _run(["rollback", "cp.example.com"], tmp_path, _PINNED, path_prefix=shim)
    assert "scope: the fleet" in fleet.stdout, fleet.stdout[-1200:]
    assert "this host alone" not in fleet.stdout


# ── Bounded network calls ────────────────────────────────────────────────────
#
# Every failure guarded here presents identically from outside: a command that has
# printed one line and then says nothing, for minutes or forever. `task upgrade:plan`
# hung on a control plane while working on the workstation that deployed it — the
# workstation has a checkout, so `release_tags` fell through to `git tag --list` and
# answered locally; an archive install has no .git and no fallback.


class TestNoBareReleaseArtifactExists:
    """`case $?` after a bare call reads a status `set -e` never let it reach.

    scripts/upgrade.sh sets `set -e`, so a function returning non-zero aborts the script
    before the `case` runs. Both non-zero arms — "no package published for vX" and "could
    not reach the server, trying anyway" — were therefore dead, and an unreachable release
    server exited silently mid-upgrade, after the backup. Verified: under `set -e`,
    `f(){ return 1; }; f; case $? in 1) echo CAUGHT;; esac` prints nothing.

    deploy-package-gate.sh had this found and fixed once already; the test that pinned it
    read only that one file, so the same shape survived in two other places.
    """

    SOURCES = ("scripts/upgrade.sh", "scripts/lib/common.sh", "scripts/deploy-package-gate.sh")

    def test_no_source_reads_case_of_a_bare_status(self):
        problems: list[str] = []
        for rel in self.SOURCES:
            lines = (REPO_ROOT / rel).read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines[1:], start=1):
                if line.strip() != "case $? in":
                    continue
                previous = lines[i - 1].strip()
                if previous.startswith("#") or not previous:
                    continue
                problems.append(f"{rel}:{i + 1}: `case $? in` reads the status of `{previous}`")
        assert not problems, "under `set -e` these arms are unreachable — capture with `|| rc=$?` and switch on $rc:\n  " + "\n  ".join(problems)

    def test_every_release_artifact_exists_call_captures_its_status(self):
        problems: list[str] = []
        for rel in self.SOURCES:
            for i, line in enumerate((REPO_ROOT / rel).read_text(encoding="utf-8").splitlines(), start=1):
                stripped = line.strip()
                if not stripped.startswith("release_artifact_exists ") or stripped.startswith("#"):
                    continue
                if "|| rc=$?" not in stripped and "|| " not in stripped:
                    problems.append(f"{rel}:{i}: {stripped}")
        assert not problems, "release_artifact_exists returns 0/1/2 and must be called as `... || rc=$?`:\n  " + "\n  ".join(problems)


class TestTheReleaseServerLookupIsBounded:
    """The one network call in lib/common.sh that had no ceiling."""

    def test_git_ls_remote_refuses_every_prompt(self):
        """A private repo asks for a username and waits. No timeout fixes that — the call
        is not slow, it is blocked on a human who is not there. stderr is discarded at the
        call site, so there is not even a prompt to see."""
        src = (REPO_ROOT / "scripts" / "lib" / "common.sh").read_text(encoding="utf-8")
        body = src[src.index("git_ls_remote_tags() {") :]
        body = body[: body.index("\n}\n")]
        for guard in ("GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=", "BatchMode=yes", "credential.helper="):
            assert guard in body, f"git_ls_remote_tags lost its {guard} guard — a private remote will hang"
        assert "run_bounded" in body, "git_ls_remote_tags must go through run_bounded"

    def test_downloads_bound_the_connect_and_the_stall_but_not_the_transfer(self):
        """A release archive is ~400 MB, so `--max-time` would abort a transfer that is
        working. What must be bounded is the connect and a dead-but-open socket."""
        src = (REPO_ROOT / "scripts" / "lib" / "common.sh").read_text(encoding="utf-8")
        line = next(ln for ln in src.splitlines() if ln.startswith("CURL_DOWNLOAD_OPTS="))
        assert "--connect-timeout" in line and "--speed-limit" in line and "--speed-time" in line
        assert "--max-time" not in line, "a total ceiling aborts a slow but healthy 400 MB download"

        # A line that PRINTS `curl -fL …` is an announcement, not a download. Excluding the
        # literal substring "echo" tests a spelling rather than a concept:
        # `info "curl -fL ${ARCHIVE}"` is the same announcement. Name every printing helper
        # instead.
        printers = re.compile(r"^\s*(echo|printf|info|ok|note|warn|die|step|header)\b")
        for rel in ("scripts/upgrade.sh", "scripts/deploy-package-gate.sh"):
            for i, ln in enumerate((REPO_ROOT / rel).read_text(encoding="utf-8").splitlines(), start=1):
                if "curl -fL " in ln and not ln.strip().startswith("#") and not printers.match(ln):
                    assert "CURL_DOWNLOAD_OPTS" in ln, f"{rel}:{i}: unbounded archive download: {ln.strip()}"

    @pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
    def test_an_unroutable_release_server_returns_inside_the_ceiling(self, tmp_path: Path):
        """Wall clock, against 192.0.2.1 — TEST-NET-1, which is guaranteed unroutable.

        A blackhole is the shape that actually hangs: a refused connection fails in a
        second, a DROPPED SYN waits out the kernel's retries. Uncapped, `upgrade:plan` from
        an archive install measured 95s and said nothing about why; the git arm alone is
        capped at RELEASE_NET_TIMEOUT.

        Asserts an upper bound only, so a sandbox that fails the connect instantly (no
        route at all) passes for the right reason.
        """
        import time

        probe = tmp_path / "probe.sh"
        probe.write_text(f'. {REPO_ROOT / "scripts" / "lib" / "common.sh"}\nRELEASE_NET_TIMEOUT=5 git_ls_remote_tags "https://192.0.2.1/x/y" >/dev/null 2>&1\n')
        started = time.monotonic()
        subprocess.run(["bash", str(probe)], check=False, capture_output=True, timeout=60)
        elapsed = time.monotonic() - started
        assert elapsed < 20, f"git_ls_remote_tags took {elapsed:.1f}s against a blackhole — the ceiling is not applied"


# ── already current, and up ───────────────────────────────────────────────────


def _docker_ps(shim: Path, running: bool) -> None:
    """Make the stubbed `docker compose ps -q` answer honestly.

    The plain `_make_stub_dir` docker echoes `STUB docker compose ps -q`, which is one line
    of output and therefore reads as one running container — a stub that models the state
    the guard is about by accident. These tests are exactly about that state, so they say
    which one they mean, the way `_fleet_shim(running=)` already does for the fleet.
    """
    body = "echo cid1" if running else "true"
    (shim / "docker").write_text(f'#!/bin/sh\ncase "$*" in\n  *"ps -q"*) {body} ;;\n  */health*) printf 200 ;;\n  *) echo "STUB docker $*" ;;\nesac\n')
    (shim / "docker").chmod(0o755)


def test_upgrading_to_the_running_release_is_refused(tmp_path: Path):
    """Re-running an upgrade on a healthy host is a rebuild and a restart for no change.

    It must refuse, not print one line and do it anyway."""
    _install(tmp_path, "9.9.9")
    shim = _make_stub_dir(tmp_path)
    _docker_ps(shim, running=True)

    result = _run(["docker"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "STUB task backup" not in result.stdout, "it must refuse BEFORE the backup"
    assert "STUB docker compose build" not in result.stdout
    combined = result.stdout + result.stderr
    assert "RESTAGE_IF_CURRENT=true" in combined, "the refusal must name the way through"
    assert "SKIP_IF_CURRENT=true" in combined
    # One stubbed container, counted once. `docker compose ps` is project-scoped, so the
    # two probes common.sh::compose_running_count_cmd makes list the SAME container — and
    # without the dedupe this line, `deploy:plan`'s verdict and `task fleet` all doubled.
    assert "1 container(s) up" in combined, combined


def test_the_repair_flow_is_never_refused(tmp_path: Path):
    """Code current, nothing running — a half-finished upgrade. Restaging IS the repair, so
    it proceeds with no knob and no question. The refusal exists to protect a healthy
    deployment from a pointless restart, not to lock an operator out of a broken one."""
    _install(tmp_path, "9.9.9")
    shim = _make_stub_dir(tmp_path)
    _docker_ps(shim, running=False)

    result = _run(["docker"], tmp_path, _PINNED, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "but nothing is running" in result.stdout
    assert "STUB task backup" in result.stdout
    assert "RESTAGE_IF_CURRENT" not in result.stdout + result.stderr, "no knob is needed to repair"


def test_restage_if_current_carries_a_running_host_through(tmp_path: Path):
    _install(tmp_path, "9.9.9")
    shim = _make_stub_dir(tmp_path)
    _docker_ps(shim, running=True)

    result = _run(["docker"], tmp_path, {**_PINNED, "RESTAGE_IF_CURRENT": "true"}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESTAGE_IF_CURRENT=true — restaging" in result.stdout
    assert "STUB docker compose build" in result.stdout


def test_skip_if_current_does_not_skip_a_stopped_single_host(tmp_path: Path):
    """The fleet survey has always required containers to be up before calling a scope
    current (test_a_current_version_with_nothing_running_is_not_current). This path did not,
    so a nightly `SKIP_IF_CURRENT=true task upgrade` left a half-finished upgrade
    half-finished forever. docs/runbooks/upgrading.md already described the fleet rule as if it
    applied to both."""
    _install(tmp_path, "9.9.9")
    shim = _make_stub_dir(tmp_path)
    _docker_ps(shim, running=False)

    result = _run(["docker"], tmp_path, {**_PINNED, "SKIP_IF_CURRENT": "true"}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "nothing to do" not in result.stdout
    assert "STUB task backup" in result.stdout


def test_skip_if_current_still_skips_a_running_single_host(tmp_path: Path):
    _install(tmp_path, "9.9.9")
    shim = _make_stub_dir(tmp_path)
    _docker_ps(shim, running=True)

    result = _run(["docker"], tmp_path, {**_PINNED, "SKIP_IF_CURRENT": "true"}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "nothing to do" in result.stdout
    assert "STUB task backup" not in result.stdout


def test_a_docker_that_cannot_be_measured_is_treated_as_the_repair_case(tmp_path: Path):
    """No docker on PATH, no compose file, a dead daemon — all come back empty, and an
    unmeasured value must never BLOCK a repair. The inverse of deploy-preflight.sh's rule,
    because the failure modes are opposite."""
    _install(tmp_path, "9.9.9")
    shim = _make_stub_dir(tmp_path, names=tuple(n for n in _STUB_CMDS if n != "docker"))
    (shim / "docker").write_text("#!/bin/sh\nexit 127\n")
    (shim / "docker").chmod(0o755)

    result = _run(["docker"], tmp_path, _PINNED, path_prefix=shim)
    assert "already current, but nothing is running" in result.stdout


def test_the_fleet_refuses_a_scope_that_is_already_running_the_target(tmp_path: Path):
    """Both scopes must ask the same question — on a fleet the restart is rolling."""
    remote = _fleet(tmp_path, "9.9.9")
    shim = _fleet_shim(tmp_path)

    result = _run(
        ["multiserver", "local"],
        tmp_path,
        {**_PINNED_GIT, "DEPLOY_REMOTE_DIR": str(remote)},
        path_prefix=shim,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "STUB task backup" not in result.stdout, "it must refuse before the control-plane backup"
    combined = result.stdout + result.stderr
    assert "RESTAGE_IF_CURRENT=true" in combined
    assert "every host in scope, one after another" in combined


def test_the_fleet_gate_and_the_single_host_gate_are_one_function(tmp_path: Path):
    """A single-host upgrade and a fleet upgrade asking different questions about the same
    situation is worse than either asking the wrong one, so there is exactly one gate and
    both call it."""
    body = SCRIPT.read_text(encoding="utf-8")
    assert body.count("_gate_already_current() {") == 1
    assert body.count("  _gate_already_current ") + body.count("      _gate_already_current ") >= 2
    assert body.count("RESTAGE_IF_CURRENT") >= 1
    # The override is read inside the gate, not at either call site.
    gate = body.split("_gate_already_current() {")[1].split("\n}")[0]
    assert 'truthy "${RESTAGE_IF_CURRENT:-}"' in gate


def test_the_gate_never_reads_a_terminal(tmp_path: Path):
    """Measured, both ways: with no controlling terminal a `read </dev/tty` fails the
    redirection — a bare one exits 1 under `set -e` mid-flow — and with a controlling
    terminal nobody will type into (ssh -t, or ~/.ssh/config RequestTTY yes, which
    host_installed_release documents as live on this fleet) it BLOCKS FOREVER.
    scripts/deploy-package-gate.sh deleted its own prompt after that hung a fleet deploy."""
    # Comments stripped: the gate's own note explains at length why it does not do this,
    # and a substring check over the whole file would match the explanation.
    code = "\n".join(ln for ln in SCRIPT.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#"))
    assert "/dev/tty" not in code, "the upgrade must never prompt — see deploy-package-gate.sh"
    assert "read -r reply" not in code


def test_the_refusal_is_deterministic_without_a_tty(tmp_path: Path):
    """The whole point of an env var over a prompt: no controlling terminal, no stdin, and
    the answer is still the same one, promptly. This is cron, CI and `ssh host task upgrade`.
    """
    import os as _os

    _install(tmp_path, "9.9.9")
    shim = _make_stub_dir(tmp_path)
    _docker_ps(shim, running=True)

    env = {**os.environ}
    for var in _SCRUBBED:
        env.pop(var, None)
    env["PATH"] = f"{shim}{os.pathsep}{env.get('PATH', '')}"
    env["VERSION"] = "9.9.9"
    result = subprocess.run(
        ["bash", str(SCRIPT), "docker"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
        # No controlling terminal at all — /dev/tty cannot even be opened.
        preexec_fn=_os.setsid,
        timeout=60,
    )
    assert result.returncode != 0
    assert "Device not configured" not in result.stderr, "nothing may reach for a terminal"
    assert "RESTAGE_IF_CURRENT=true" in result.stdout + result.stderr


def test_archive_mode_is_never_gated_on_the_resolved_release(tmp_path: Path):
    """scripts/ci-deploy-smoke.sh runs a real in-place `ARCHIVE=... task upgrade`, and an
    archive's version is not known until it is staged — so the local VERSION says nothing
    about whether this run is a no-op. The gate must not fire on the release REF happens to
    resolve to. (It does not, because REF is empty in archive mode; this pins that.)"""
    _install(tmp_path, "9.9.9")
    archive = _release_archive(tmp_path, "9.9.9")
    shim = _make_stub_dir(tmp_path)
    _docker_ps(shim, running=True)

    result = _run(["docker"], tmp_path, {**_PINNED, "ARCHIVE": str(archive)}, path_prefix=shim)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESTAGE_IF_CURRENT" not in result.stdout + result.stderr
    assert "STUB task backup" in result.stdout
