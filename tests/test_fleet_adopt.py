"""FLEET_FROM — running a deploy verb against a fleet you are not standing on.

`task fleet:pull` already fetched a control plane's record and wrote a deploy.env from it.
This is the same fetch without the file, for the case where you want to run one command
rather than adopt a fleet permanently:

    FLEET_FROM=cp.example.com task upgrade

Everything here guards a way it can go quietly wrong. The two that would do real damage are
covered first: a workstation deploying to ITSELF because the record stored `local`, and a
deploy minting fresh database passwords because the secrets stayed on the other machine.

The `local` sentinel doubles as the test harness: host_copy_from maps it to `cp`, so a
"remote" control plane is a directory and no SSH is involved.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
COMMON_SH = REPO_ROOT / "scripts" / "lib" / "common.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _control_plane(tmp_path: Path, hosts: str, **options: str) -> Path:
    """A directory holding a fleet record, standing in for a control plane."""
    install = tmp_path / "cp"
    (install / "fleet").mkdir(parents=True, exist_ok=True)
    args = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "fleet_manifest.py"),
        "--file",
        str(install / "fleet" / "manifest.json"),
        "intent",
        "--hosts",
        hosts,
        "--install-dir",
        str(install),
        "--written-by",
        "0.10.4",
        "--written-at",
        "2026-01-01T00:00:00Z",
    ]
    for key, value in options.items():
        args += ["--option", f"{key}={value}"]
    subprocess.run(args, check=True, capture_output=True)
    return install


def _sh(body: str, *, cwd: Path, install: Path, **env: str) -> subprocess.CompletedProcess:
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "FLEET_"))}
    clean.update(
        {
            "XDG_CACHE_HOME": str(cwd / ".cache"),
            "DEPLOY_REMOTE_DIR": str(install),
            "DEPLOY_ENV_FILE": "deploy.env",
            **env,
        }
    )
    return subprocess.run(
        ["bash", "-c", f". {COMMON_SH}\n{body}\n"],
        cwd=cwd,
        env=clean,
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestItNeverHandsAWorkstationTheLocalSentinel:
    """The failure that would cost a fleet.

    `local` means "this machine", so it is only ever correct where it was written. A record
    made by deploying FROM the control plane stores it — and fleet_hosts returns stored
    entries verbatim once FLEET_MANIFEST is set, precisely so a workstation reading a pulled
    copy keeps the control plane's real name. Adopt such a record without substituting and
    DEPLOY_HOSTS reads `local,w1`: the workstation deploys the control plane to ITSELF.
    """

    def test_a_recorded_local_becomes_the_recorded_address(self, tmp_path: Path):
        install = _control_plane(tmp_path, "local,w1.example.com", cp_address="10.200.0.1")
        ws = tmp_path / "ws"
        ws.mkdir()
        out = _sh("fleet_adopt >/dev/null 2>&1; fleet_hosts", cwd=ws, install=install, FLEET_FROM="local")
        assert out.stdout.strip() == "10.200.0.1,w1.example.com", out.stdout + out.stderr
        assert "local" not in out.stdout.split(",")[0]

    def test_without_an_address_it_falls_back_to_the_host_you_reached(self, tmp_path: Path):
        """The fallback is reachable by construction: the file came off that host."""
        install = _control_plane(tmp_path, "local,w1.example.com")
        ws = tmp_path / "ws"
        ws.mkdir()
        out = _sh("fleet_adopt >/dev/null 2>&1; fleet_hosts", cwd=ws, install=install, FLEET_FROM="local")
        assert out.stdout.strip() == "local,w1.example.com", (
            "the fallback IS `local` here because that is the host named — which is correct, since a local adoption really is this machine"
        )

    def test_a_named_control_plane_is_left_alone(self, tmp_path: Path):
        install = _control_plane(tmp_path, "cp.example.com,w1.example.com")
        ws = tmp_path / "ws"
        ws.mkdir()
        out = _sh("fleet_adopt >/dev/null 2>&1; fleet_hosts", cwd=ws, install=install, FLEET_FROM="local")
        assert out.stdout.strip() == "cp.example.com,w1.example.com"


class TestItIsExplicitAndNeverInferred:
    def test_nothing_happens_without_fleet_from(self, tmp_path: Path):
        """A positional still means exactly one host, and DEPLOY_ONLY still means a subset.
        Inferring "you named the control plane, so you meant its fleet" would be a coin flip
        on task deploy:remove, which deletes install directories."""
        install = _control_plane(tmp_path, "cp.example.com,w1.example.com")
        ws = tmp_path / "ws"
        ws.mkdir()
        out = _sh('fleet_adopt; echo "adopted=[${FLEET_ADOPTED:-}]"', cwd=ws, install=install)
        assert "adopted=[]" in out.stdout
        assert out.returncode == 0

    def test_it_refuses_a_host_list(self, tmp_path: Path):
        """FLEET_FROM names ONE control plane. hosts_from_args is reused rather than a second
        validator written, and it rejects a comma — so this cannot smuggle a fleet in."""
        install = _control_plane(tmp_path, "cp.example.com")
        ws = tmp_path / "ws"
        ws.mkdir()
        out = _sh("fleet_adopt", cwd=ws, install=install, FLEET_FROM="a,b")
        assert out.returncode != 0
        assert "Not a host" in out.stdout + out.stderr

    def test_it_refuses_shell_metacharacters(self, tmp_path: Path):
        install = _control_plane(tmp_path, "cp.example.com")
        ws = tmp_path / "ws"
        ws.mkdir()
        out = _sh("fleet_adopt", cwd=ws, install=install, FLEET_FROM="cp; rm -rf /")
        assert out.returncode != 0
        assert "Not a host" in out.stdout + out.stderr


class TestTheRemotePathIsNotTheReadablePath:
    """fleet_adopt exports FLEET_MANIFEST so every existing reader follows it. Two scp sites
    in deploy-multiserver.sh name a path ON the control plane and must NOT — otherwise a
    deploy copies the fleet record to and from the workstation's cache path on the remote
    host, silently, because every one of those calls is `|| true`."""

    def test_the_override_moves_one_and_not_the_other(self, tmp_path: Path):
        out = _sh(
            'echo "$(fleet_manifest_path /opt/logstotal)|$(fleet_remote_manifest_path /opt/logstotal)"',
            cwd=tmp_path,
            install=tmp_path,
            FLEET_MANIFEST=str(tmp_path / "cache.json"),
        )
        readable, remote = out.stdout.strip().split("|")
        assert readable == str(tmp_path / "cache.json")
        assert remote == "/opt/logstotal/fleet/manifest.json"

    def test_no_copy_to_a_host_uses_the_overridable_path(self):
        """Every scp that names a path on another machine must use the remote form. The
        override is what a workstation sets to adopt a fleet; a copy that follows it writes
        the control plane's record to a cache path on the control plane."""
        offenders = []
        for rel in ("scripts/deploy-multiserver.sh", "scripts/fleet.sh", "scripts/lib/fleet_record.sh"):
            for i, line in enumerate((REPO_ROOT / rel).read_text(encoding="utf-8").splitlines(), start=1):
                if line.lstrip().startswith("#"):
                    continue
                if "host_copy_" in line and "fleet_manifest_path" in line:
                    offenders.append(f"{rel}:{i}: {line.strip()}")
        assert not offenders, "use fleet_remote_manifest_path for a path on another host:\n  " + "\n  ".join(offenders)

    def test_both_of_the_deploys_manifest_copies_are_converted(self):
        src = (REPO_ROOT / "scripts" / "deploy-multiserver.sh").read_text(encoding="utf-8")
        assert src.count("fleet_remote_manifest_path") == 2, "the pull and the push, both"


class TestSecretsStayWhereTheyWereMade:
    def test_a_deploy_from_an_adopted_record_is_refused(self, tmp_path: Path):
        """deploy_fleet_env.py MINTS a fresh SECRET_KEY, POSTGRES_PASSWORD and REDIS_PASSWORD
        when secrets.json is absent, and deploy-env-push.sh pushes that over a working remote
        .env because it carries the generator marker. PostgreSQL sets its password once, when
        its data directory is created, so the new one authenticates against nothing — the
        fleet looks green and then fails health.

        Refused up front, not at step 5 of 8 after three hosts have been bootstrapped.
        """
        install = _control_plane(tmp_path, "cp.example.com,w1.example.com")
        ws = tmp_path / "ws"
        ws.mkdir()
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "FLEET_"))}
        clean.update(
            {
                "XDG_CACHE_HOME": str(ws / ".cache"),
                "DEPLOY_REMOTE_DIR": str(install),
                "FLEET_FROM": "local",
                "DEPLOY_DRY_RUN": "true",
            }
        )
        out = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "deploy-fleet.sh")],
            cwd=ws,
            env=clean,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert out.returncode != 0, out.stdout + out.stderr
        combined = out.stdout + out.stderr
        assert "needs its secrets" in combined
        assert "./logstotal upgrade" in combined, "a refusal must name what IS possible from here"

    def test_deploy_init_is_still_allowed(self, tmp_path: Path):
        """It writes a local file and contacts nothing, so it has no secrets to be missing."""
        install = _control_plane(tmp_path, "cp.example.com,w1.example.com")
        ws = tmp_path / "ws"
        ws.mkdir()
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("DEPLOY_", "FLEET_"))}
        clean.update({"XDG_CACHE_HOME": str(ws / ".cache"), "DEPLOY_REMOTE_DIR": str(install), "FLEET_FROM": "local"})
        out = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "deploy-fleet.sh"), "init"],
            cwd=ws,
            env=clean,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert out.returncode == 0, out.stdout + out.stderr
        assert (ws / "deploy.env").is_file()


class TestAdoptionHappensBeforeTheFirstRead:
    """_fleet_options memoises the record's options on first read, so adopting afterwards is
    silently HALF applied: hosts from the remote record, settings from this machine. No route
    test can see that — both orders produce a working-looking run."""

    ENTRY_SCRIPTS = (
        "scripts/deploy-multiserver.sh",
        "scripts/deploy-preflight.sh",
        "scripts/deploy-smoke.sh",
        "scripts/deploy-fleet.sh",
        "scripts/fleet.sh",
    )

    @pytest.mark.parametrize("rel", ENTRY_SCRIPTS)
    def test_fleet_adopt_precedes_every_deploy_env_read(self, rel: str):
        lines = (REPO_ROOT / rel).read_text(encoding="utf-8").splitlines()
        code = [(i, ln) for i, ln in enumerate(lines, start=1) if not ln.lstrip().startswith("#")]
        adopt = next((i for i, ln in code if ln.strip() == "fleet_adopt"), None)
        assert adopt, f"{rel} resolves a fleet but never calls fleet_adopt"
        first_read = next((i for i, ln in code if "deploy_env_load" in ln or "deploy_env_default" in ln), None)
        if first_read is not None:
            assert adopt < first_read, f"{rel}: fleet_adopt at line {adopt} runs AFTER the first deploy.env read at {first_read}"

    def test_upgrade_adopts_at_the_top_of_main(self):
        """upgrade.sh dispatches to four flows; adopting inside one of them would leave the
        other three reading this machine's record."""
        src = (REPO_ROOT / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
        body = src[src.index("main() {") :]
        assert "fleet_adopt" in body[: body.index('case "$action" in')]


class TestTheCache:
    def test_a_second_run_does_not_refetch(self, tmp_path: Path):
        """One SSH round trip per task invocation is one too many for a plan-then-deploy
        session."""
        install = _control_plane(tmp_path, "cp.example.com,w1.example.com")
        ws = tmp_path / "ws"
        ws.mkdir()
        _sh("fleet_adopt >/dev/null 2>&1", cwd=ws, install=install, FLEET_FROM="local")
        cache = next((ws / ".cache" / "logstotal" / "fleet").glob("*.json"))
        first = cache.stat().st_mtime_ns
        (install / "fleet" / "manifest.json").unlink()  # the "remote" is now gone
        out = _sh("fleet_adopt >/dev/null 2>&1; fleet_hosts", cwd=ws, install=install, FLEET_FROM="local")
        assert cache.stat().st_mtime_ns == first, "it refetched inside the TTL"
        assert "cp.example.com" in out.stdout, "the cached record was not used"

    def test_an_unreachable_control_plane_with_no_cache_is_fatal(self, tmp_path: Path):
        """Naming a fleet that cannot be reached must stop, not fall through to whatever this
        machine happens to know."""
        ws = tmp_path / "ws"
        ws.mkdir()
        out = _sh("fleet_adopt", cwd=ws, install=tmp_path / "nothing-here", FLEET_FROM="local")
        assert out.returncode != 0
        assert "could not fetch the fleet record" in out.stdout + out.stderr
