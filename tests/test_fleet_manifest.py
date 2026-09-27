"""What the control plane knows about its own fleet.

Without a record, a host's role is only its INDEX in DEPLOY_HOSTS, and every other fact
about the deployment lives in the operator's working directory — in files package.sh
deliberately keeps out of the release archive. So a control plane could not answer the
first question an upgrade has to ask, "which machines am I responsible for", and losing the
laptop would lose the architecture.

These pin the three properties the record has to have.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import fleet_manifest as fm  # noqa: E402

COMMON_SH = REPO_ROOT / "scripts" / "lib" / "common.sh"


def _intent(path: Path, hosts: str = "cp.example.com,w1.example.com", **options: str) -> dict:
    m = fm.load(str(path))
    fm.set_intent(
        m,
        hosts_csv=hosts,
        install_dir="/opt/logstotal",
        written_by="0.10.0",
        written_at="2026-08-27T12:00:00Z",
        options=options,
    )
    fm.save(str(path), m)
    return m


# ── It carries no secrets ────────────────────────────────────────────────────


def test_the_record_is_world_readable_and_therefore_must_hold_nothing_secret(tmp_path: Path):
    """0644 is a decision, not an oversight: this file should be safe to paste into a bug
    report, which is exactly what makes it useful when something is broken. deploy-envs/
    (0600) keeps the secrets, and is excluded from snapshots and from the archive."""
    path = tmp_path / "manifest.json"
    _intent(path)
    assert oct(path.stat().st_mode)[-3:] == "644"


def test_only_named_options_are_carried(tmp_path: Path):
    """A pass-through would eventually carry a password. The allow-list is the guard."""
    path = tmp_path / "manifest.json"
    _intent(path, vpn="wireconf", basic_auth_password="hunter2", api_token="secret")
    data = json.loads(path.read_text())
    assert data["options"] == {"vpn": "wireconf"}


# ── Intent and observation stay apart ────────────────────────────────────────


def test_role_comes_from_the_record_not_from_a_list_index():
    """Index-0-is-the-control-plane was restated in six places. Reordering DEPLOY_HOSTS
    silently re-roled machines, and nothing on a host recorded what it had been."""
    assert fm.role_for(0) == fm.CONTROL_PLANE
    assert fm.role_for(1) == fm.WORKER
    assert fm.role_for(9) == fm.WORKER


def test_a_measurement_survives_a_later_statement_of_intent(tmp_path: Path):
    """DEPLOY_ONLY touches one machine. The versions the others were last seen running are
    still the best answer anyone has for them, so re-recording intent must not blank them."""
    path = tmp_path / "manifest.json"
    m = _intent(path)
    fm.set_result(m, entry="w1.example.com", result="ok", version="0.10.0", containers=3)
    fm.save(str(path), m)

    m = _intent(path)  # a second run, same fleet
    worker = next(h for h in m["hosts"] if h["entry"] == "w1.example.com")
    assert worker["version"] == "0.10.0"
    assert worker["containers"] == 3
    assert worker["result"] == "ok"


def test_a_host_dropped_from_the_fleet_is_dropped_from_the_record(tmp_path: Path):
    """The manifest describes this fleet, not its history. A decommissioned worker left in
    it would be upgraded by the next `task upgrade`."""
    path = tmp_path / "manifest.json"
    _intent(
        path,
    )
    m = _intent(path, hosts="cp.example.com")
    assert [h["entry"] for h in m["hosts"]] == ["cp.example.com"]


def test_unverified_is_a_result_in_its_own_right():
    """It is how the deploy's UNKNOWN verdict outlives the console: a worker whose
    containers were never confirmed is neither claimed healthy nor reported broken."""
    assert "unverified" in fm.RESULTS
    assert "ok" in fm.RESULTS and "failed" in fm.RESULTS


def test_a_result_for_a_host_the_fleet_does_not_contain_is_ignored(tmp_path: Path):
    """Silently growing the record would hide a bug in the caller."""
    path = tmp_path / "manifest.json"
    m = _intent(path)
    fm.set_result(m, entry="ghost.example.com", result="ok")
    assert [h["entry"] for h in m["hosts"]] == ["cp.example.com", "w1.example.com"]


def test_an_unknown_result_is_refused(tmp_path: Path):
    path = tmp_path / "manifest.json"
    m = _intent(path)
    with pytest.raises(ValueError):
        fm.set_result(m, entry="cp.example.com", result="probably-fine")


# ── It never becomes a hard dependency ───────────────────────────────────────


@pytest.mark.parametrize(
    "content",
    ["", "{", "null", "[]", '{"schema": 999}', '{"hosts": "not a list"}'],
)
def test_a_damaged_record_reads_as_an_empty_one(tmp_path: Path, content: str):
    """This is the LAST source consulted for a host list — after positionals, the
    environment and deploy.env — so a damaged one must degrade to "I know nothing" rather
    than to an error. A cosmetic file may not become a hard dependency of the tool that
    writes it."""
    path = tmp_path / "manifest.json"
    path.write_text(content, encoding="utf-8")
    m = fm.load(str(path))
    assert m["hosts"] == []


def test_a_missing_record_reads_as_an_empty_one(tmp_path: Path):
    assert fm.load(str(tmp_path / "nope.json"))["hosts"] == []


def test_the_write_is_atomic(tmp_path: Path):
    """A manifest half-written when a deploy is interrupted is worse than none: `load`
    would fall back to blank and the fleet would appear to be one host."""
    path = tmp_path / "manifest.json"
    _intent(path)
    src = (REPO_ROOT / "scripts" / "fleet_manifest.py").read_text(encoding="utf-8")
    assert "os.replace(" in src, "the write must land by rename, not by truncating in place"
    assert not list(tmp_path.glob(".manifest.*")), "a temp file survived a successful write"


# ── It can be taken somewhere else ───────────────────────────────────────────


def test_the_record_renders_back_as_a_deploy_env(tmp_path: Path):
    """What makes it useful from elsewhere: a workstation that has never seen this fleet
    can pull the record off the control plane and drive every deploy task against it."""
    path = tmp_path / "manifest.json"
    m = _intent(path, vpn="wireconf", domain="logs.example.com", remote_dir="/opt/logstotal")
    rendered = fm.to_deploy_env(m)
    assert "DEPLOY_HOSTS=cp.example.com,w1.example.com" in rendered
    assert "DEPLOY_VPN=wireconf" in rendered
    assert "DEPLOY_DOMAIN=logs.example.com" in rendered
    assert "DEPLOY_REMOTE_DIR=/opt/logstotal" in rendered


def test_the_rendered_deploy_env_parses_the_way_the_scripts_read_one(tmp_path: Path):
    """deploy.env is read by grep and cut, never by a shell: no quotes, no inline
    comments, no indentation, no `export`. A renderer that emitted any of those would
    produce a file every script silently misreads."""
    path = tmp_path / "manifest.json"
    m = _intent(path, vpn="wireconf", domain="logs.example.com")
    (tmp_path / "deploy.env").write_text(fm.to_deploy_env(m), encoding="utf-8")

    out = subprocess.run(
        ["bash", "-c", f'. "{COMMON_SH}"; deploy_env_default DEPLOY_HOSTS; deploy_env_default DEPLOY_VPN'],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "DEPLOY_ENV_FILE": "deploy.env"},
    )
    assert out.stdout.split() == ["cp.example.com,w1.example.com", "wireconf"], out.stderr


def test_no_secret_reaches_the_rendered_deploy_env(tmp_path: Path):
    path = tmp_path / "manifest.json"
    m = _intent(path, basic_auth_user="ops")
    rendered = fm.to_deploy_env(m)
    assert "DEPLOY_BASIC_AUTH_USER=ops" in rendered
    # The KEY lines only: the header comment says the word "secrets", which is the point
    # it is making rather than a leak.
    keys = [ln.split("=", 1)[0] for ln in rendered.splitlines() if "=" in ln and not ln.startswith("#")]
    for key in keys:
        assert "PASSWORD" not in key.upper()
        assert "SECRET_KEY" not in key.upper()
        assert "TOKEN" not in key.upper() or key == "RELEASE_REPO_URL"


# ── The shell face ───────────────────────────────────────────────────────────


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_the_shell_helpers_are_silent_when_there_is_no_record(tmp_path: Path):
    """Every consumer treats "" as "I know nothing", which is the only safe reading."""
    out = subprocess.run(
        [
            "bash",
            "-c",
            f'. "{COMMON_SH}"; fleet_hosts "{tmp_path}/absent"; fleet_option vpn "{tmp_path}/absent"',
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == ""


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_the_record_lives_inside_the_install_it_describes(tmp_path: Path):
    """So a host that is moved, or restored from a snapshot, carries its own architecture
    with it — and so `fleet` can be one entry in the overlay and snapshot exclude lists."""
    out = subprocess.run(
        ["bash", "-c", f'. "{COMMON_SH}"; fleet_manifest_path /opt/logstotal'],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout == "/opt/logstotal/fleet/manifest.json"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_the_record_survives_an_upgrade_and_a_snapshot():
    """`fleet` must be excluded in BOTH lists or the first upgrade --delete's the record,
    and a snapshot would otherwise carry one host's architecture into another's tree."""
    for fn in ("overlay_excludes", "snapshot_excludes"):
        out = subprocess.run(
            ["bash", "-c", f'. "{COMMON_SH}"; {fn}'],
            capture_output=True,
            text=True,
            check=True,
        )
        assert "--exclude=fleet\n" in out.stdout, f"{fn} would destroy the fleet record"


# ── The record answers when nothing else does ────────────────────────────────

DEPLOY_SH = REPO_ROOT / "scripts" / "deploy-multiserver.sh"


def _record(tmp_path: Path, hosts: str = "cp.example.com,w1.example.com") -> Path:
    install = tmp_path / "opt"
    path = install / "fleet" / "manifest.json"
    m = fm.load(str(path))
    fm.set_intent(
        m,
        hosts_csv=hosts,
        install_dir=str(install),
        written_by="0.10.0",
        written_at="2026-08-27T12:00:00Z",
        options={"vpn": "none"},
    )
    fm.save(str(path), m)
    return install


def _deploy(tmp_path: Path, install: str, **env: str) -> subprocess.CompletedProcess[str]:
    base = {k: v for k, v in os.environ.items() if not k.startswith("DEPLOY_")}
    base.update(
        {
            "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env.absent"),
            "DEPLOY_ACTION": "status",
            "DEPLOY_DRY_RUN": "true",
            "DEPLOY_REMOTE_DIR": install,
            **env,
        }
    )
    return subprocess.run(["bash", str(DEPLOY_SH)], cwd=tmp_path, env=base, capture_output=True, text=True, check=False)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_a_bare_command_on_a_control_plane_finds_its_own_fleet(tmp_path: Path):
    """The requirement the record exists for. deploy.env belongs to whoever ran the deploy
    and package.sh keeps it out of the archive, so a control plane has none — and before
    this, every `task deploy:*` run there failed with "DEPLOY_HOSTS is required" on a
    machine that was itself part of a fleet it could describe."""
    install = _record(tmp_path)
    result = _deploy(tmp_path, str(install))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "from this host's own record" in result.stdout
    # The control plane is `local` here, not its name: the record names it as the operator
    # typed it from a workstation, and read back ON that machine the name means "ssh to
    # yourself". See fleet_manifest.py::hosts_line.
    assert "local w1.example.com" in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_explicit_configuration_always_beats_the_record(tmp_path: Path):
    """The record is what answers when there is nothing else — never what overrides
    something. Getting this backwards would mean a stale record silently redirecting a
    deploy at hosts the operator did not name — the go-task variable trap, arriving from a
    different direction."""
    install = _record(tmp_path)
    result = _deploy(tmp_path, str(install), DEPLOY_HOSTS="other.example.com")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "cp.example.com" not in result.stdout
    assert "other.example.com" in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_positional_hosts_also_beat_the_record(tmp_path: Path):
    install = _record(tmp_path)
    base = {k: v for k, v in os.environ.items() if not k.startswith("DEPLOY_")}
    base.update(
        {
            "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env.absent"),
            "DEPLOY_ACTION": "status",
            "DEPLOY_DRY_RUN": "true",
            "DEPLOY_REMOTE_DIR": str(install),
        }
    )
    result = subprocess.run(
        ["bash", str(DEPLOY_SH), "named.example.com"],
        cwd=tmp_path,
        env=base,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "named.example.com" in result.stdout
    assert "cp.example.com" not in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_with_no_record_the_error_says_where_it_looked(tmp_path: Path):
    """ "DEPLOY_HOSTS is required" was true and useless. An operator on a control plane
    needs to know that a record was expected and where."""
    result = _deploy(tmp_path, str(tmp_path / "nowhere"))
    assert result.returncode != 0
    assert "fleet record" in result.stderr
    assert "fleet/manifest.json" in result.stderr


def test_the_table_lines_up_for_a_real_host_name(tmp_path: Path):
    """`root@logstotal-worker-1.example.com` is longer than a fixed-width column, which would
    shift every field after it right on exactly the rows an operator is comparing."""
    path = tmp_path / "manifest.json"
    m = _intent(
        path,
        hosts="root@logstotal-cp.example.com,root@logstotal-worker-1.example.com",
    )
    fm.set_result(m, entry="root@logstotal-cp.example.com", result="ok", version="0.9.15", containers=6)
    fm.set_result(m, entry="root@logstotal-worker-1.example.com", result="ok", version="0.9.15", containers=1)

    rendered = fm.summary(m)
    header = next(ln for ln in rendered.splitlines() if ln.startswith("HOST"))
    rows = [ln for ln in rendered.splitlines() if ln.startswith("root@")]
    assert len(rows) == 2, rendered

    # Where ROLE begins in the header is where every row's role must begin. Searching for
    # the word would find it inside the HOSTNAME, which is the whole difficulty.
    role_at = header.index("ROLE")
    for row in rows:
        assert row[role_at:].startswith(("control-plane", "worker")), f"the ROLE column does not line up with the header:\n{rendered}"


def test_a_recorded_host_says_which_release_it_runs(tmp_path: Path):
    """ "Which release is each host on" is the first question anyone asks of a fleet record.
    Recording only ok/failed left it answering `?`, which is barely a record."""
    path = tmp_path / "manifest.json"
    m = _intent(path)
    fm.set_result(m, entry="cp.example.com", result="ok", version="0.9.15", containers=6)
    rendered = fm.summary(m)
    assert "0.9.15" in rendered
    assert " 6" in rendered


class TestTheControlPlaneRecognisesItself:
    """A fleet deployed from a workstation records its control plane by NAME.

    Read that back on the control plane and the name means "ssh to yourself", so `task upgrade`
    there would fail its preflight on SSH to the one host already answering. Upgrading from the
    control plane is the reason the record exists, so this is the case it has to get right.
    """

    def test_the_control_planes_own_entry_becomes_local(self, tmp_path: Path):
        m = _intent(tmp_path / "manifest.json", hosts="root@cp.example.com,root@w1.example.com")
        assert fm.hosts_line(m, as_control_plane=True) == "local,root@w1.example.com"

    def test_and_stays_a_name_for_everyone_else(self, tmp_path: Path):
        """A workstation reading a pulled copy must keep the name, or it deploys to itself."""
        m = _intent(tmp_path / "manifest.json", hosts="root@cp.example.com,root@w1.example.com")
        assert fm.hosts_line(m) == "root@cp.example.com,root@w1.example.com"
        assert "local" not in fm.to_deploy_env(m)

    def test_a_worker_is_never_localised(self, tmp_path: Path):
        """Only the control plane. Rewriting a worker's entry would run its commands here."""
        m = _intent(tmp_path / "manifest.json", hosts="root@cp.example.com,root@w1.example.com")
        m["control_plane"] = "root@w1.example.com"  # not how it is written; proves the key is read
        assert fm.hosts_line(m, as_control_plane=True) == "root@cp.example.com,local"

    def test_it_survives_a_record_with_no_control_plane(self, tmp_path: Path):
        m = _intent(tmp_path / "manifest.json", hosts="root@cp.example.com")
        m["control_plane"] = ""
        assert fm.hosts_line(m, as_control_plane=True) == "root@cp.example.com"

    @pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
    def test_fleet_hosts_localises_and_FLEET_MANIFEST_does_not(self, tmp_path: Path):
        """The shell half, both branches.

        FLEET_MANIFEST is how a deploy builds the record on the machine RUNNING it before
        pushing it — that machine is not the control plane, so the substitution must be off.
        """
        install = tmp_path / "install"
        (install / "fleet").mkdir(parents=True)
        _intent(install / "fleet" / "manifest.json", hosts="root@cp.example.com,root@w1.example.com")

        def run(env_extra: dict[str, str]) -> str:
            return subprocess.run(
                ["bash", "-c", f'. "{COMMON_SH}"; fleet_hosts "{install}"'],
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
                env={**os.environ, **env_extra},
            ).stdout.strip()

        assert run({}) == "local,root@w1.example.com"
        assert run({"FLEET_MANIFEST": str(install / "fleet" / "manifest.json")}) == "root@cp.example.com,root@w1.example.com"


class TestARunNeverDamagesTheRecord:
    """Three ways a routine run could corrupt the record it is updating.

    In every case the run itself reports success; only reading the manifest afterwards
    shows the damage.
    """

    def test_local_never_reaches_the_record(self, tmp_path: Path):
        """Storing `local` would make the record unportable.

        hosts_line() hands a control plane `local` so it stops trying to ssh to itself; the
        run passes that list straight back to set_intent. Storing it would rewrite both the
        entry and `control_plane`, and a `fleet:pull` from there would tell a workstation to
        deploy the control plane to ITSELF.
        """
        path = tmp_path / "manifest.json"
        m = _intent(path, hosts="root@cp.example.com,root@w1.example.com")
        fm.set_result(m, entry="root@cp.example.com", result="ok", version="0.9.15")

        # What a control plane reads, then writes back after its own run.
        assert fm.hosts_line(m, as_control_plane=True) == "local,root@w1.example.com"
        fm.set_intent(
            m,
            hosts_csv="local,root@w1.example.com",
            install_dir="/opt/logstotal",
            written_by="0.10.0",
            written_at="2026-08-27T13:00:00Z",
            options={},
        )
        assert m["control_plane"] == "root@cp.example.com"
        assert [h["entry"] for h in m["hosts"]] == ["root@cp.example.com", "root@w1.example.com"]
        # And the measurement survived, which only happens if the entry was mapped back
        # BEFORE the previous-hosts lookup.
        assert m["hosts"][0]["version"] == "0.9.15"

    def test_an_upgrade_does_not_erase_the_architecture(self, tmp_path: Path):
        """An upgrade runs with DEPLOY_KEEPENV and carries almost none of the deploy-time
        knobs. Overwriting wholesale erased vpn, vpn_port, domain and proxy_tls from a real
        record — the architecture the control plane exists to be able to follow."""
        path = tmp_path / "manifest.json"
        m = _intent(path, vpn="wireconf", vpn_port="51820", domain="logs.example.com", proxy_tls="acme")
        fm.set_intent(
            m,
            hosts_csv="cp.example.com,w1.example.com",
            install_dir="/opt/logstotal",
            written_by="0.10.0",
            written_at="2026-08-27T13:00:00Z",
            options={"keep_releases": "3"},  # all an upgrade knows
        )
        assert m["options"]["vpn"] == "wireconf"
        assert m["options"]["vpn_port"] == "51820"
        assert m["options"]["domain"] == "logs.example.com"
        assert m["options"]["keep_releases"] == "3"

    def test_an_explicit_value_still_wins(self, tmp_path: Path):
        """Merging must not make an option unchangeable — empty means "not specified now",
        which is not the same as a new value."""
        m = _intent(tmp_path / "manifest.json", domain="old.example.com")
        fm.set_intent(
            m,
            hosts_csv="cp.example.com",
            install_dir="/opt/logstotal",
            written_by="0.10.0",
            written_at="2026-08-27T13:00:00Z",
            options={"domain": "new.example.com"},
        )
        assert m["options"]["domain"] == "new.example.com"

    def test_the_header_never_contradicts_the_table(self, tmp_path: Path):
        """A `release:` header read from the deploying machine's VERSION file BEFORE the
        overlay replaces it contradicts the hosts measured under it. Which release is
        deployed is a measurement, and the VERSION column already answers it; the header
        says where releases come FROM."""
        m = _intent(tmp_path / "manifest.json")
        m["release"] = {"server": "https://github.com/wagga40/LogsTotal", "version": "0.9.15"}
        for entry in ("cp.example.com", "w1.example.com"):
            fm.set_result(m, entry=entry, result="ok", version="0.9.99")
        rendered = fm.summary(m)
        assert "https://github.com/wagga40/LogsTotal" in rendered
        assert "0.9.15" not in rendered, rendered
        assert "0.9.99" in rendered

    def test_a_pulled_record_never_hands_a_workstation_local(self, tmp_path: Path):
        """A deploy run on the control plane records its own entry as `local` because that
        is genuinely what was asked for. Rendering that into another machine's deploy.env
        would point every task at the wrong machine."""
        m = _intent(tmp_path / "manifest.json", hosts="local,root@w1.example.com")
        fm.set_result(m, entry="local", result="ok", address="10.0.0.5")
        rendered = fm.to_deploy_env(m)
        assert "DEPLOY_HOSTS=10.0.0.5,root@w1.example.com" in rendered
        assert "WARNING" not in rendered

    def test_and_says_so_loudly_when_it_cannot(self, tmp_path: Path):
        m = _intent(tmp_path / "manifest.json", hosts="local,root@w1.example.com")
        rendered = fm.to_deploy_env(m)
        assert "DEPLOY_HOSTS=local,root@w1.example.com" in rendered
        assert "WARNING" in rendered


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
class TestTheRecordAnswersWhenNothingElseDoes:
    """The record must be read, not only written.

    Otherwise a control plane with cp_address, vpn and domain all recorded still has to be
    told each of them on the command line — an explicit DEPLOY_CP_ADDRESS on the one machine
    that has it written down. A record nothing reads is a report, not an architecture the
    control plane can follow.
    """

    def _load(self, tmp_path: Path, keys: str, env: dict[str, str] | None = None, *, record: bool = True) -> dict[str, str]:
        install = tmp_path / "install"
        (install / "fleet").mkdir(parents=True)
        if record:
            (install / "fleet" / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "control_plane": "root@cp.example.com",
                        "hosts": [{"entry": "root@cp.example.com", "role": "control-plane"}],
                        "options": {"vpn": "wireconf", "cp_address": "10.0.0.1", "domain": "recorded.example.com"},
                    }
                )
            )
        script = f'. "{COMMON_SH}"; deploy_env_load {keys}; ' + "".join(f'printf "%s=%s\\n" {k} "${{{k}:-}}"; ' for k in keys.split())
        out = subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={
                **os.environ,
                "DEPLOY_ENV_FILE": str(tmp_path / "deploy.env"),
                "DEPLOY_REMOTE_DIR": str(install),
                **(env or {}),
            },
        ).stdout
        return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)

    def test_a_recorded_option_answers_a_deploy_variable(self, tmp_path: Path):
        got = self._load(tmp_path, "DEPLOY_VPN DEPLOY_CP_ADDRESS")
        assert got["DEPLOY_VPN"] == "wireconf"
        assert got["DEPLOY_CP_ADDRESS"] == "10.0.0.1"

    def test_the_environment_beats_it(self, tmp_path: Path):
        got = self._load(tmp_path, "DEPLOY_DOMAIN", env={"DEPLOY_DOMAIN": "explicit.example.com"})
        assert got["DEPLOY_DOMAIN"] == "explicit.example.com"

    def test_deploy_env_beats_it_too(self, tmp_path: Path):
        """The middle rung. A stale record must never redirect a run the operator has been
        specific about — the go-task variable trap, from the other side."""
        (tmp_path / "deploy.env").write_text("DEPLOY_DOMAIN=from-deploy-env.example.com\n")
        got = self._load(tmp_path, "DEPLOY_DOMAIN")
        assert got["DEPLOY_DOMAIN"] == "from-deploy-env.example.com"

    def test_an_unrecorded_key_stays_unset(self, tmp_path: Path):
        got = self._load(tmp_path, "DEPLOY_PROXY_TLS")
        assert got["DEPLOY_PROXY_TLS"] == ""

    def test_no_record_is_not_an_error(self, tmp_path: Path):
        """Every deploy_env_load on a workstation goes through this path."""
        got = self._load(tmp_path, "DEPLOY_VPN", record=False)
        assert got["DEPLOY_VPN"] == ""


class TestTheRecordAgreesWithItself:
    """`hosts[0].address` must come from the merged options, not only the ones passed to
    THIS call. Otherwise a run that does not carry DEPLOY_CP_ADDRESS leaves the address
    empty next to an `options.cp_address` holding it — the record disagreeing with itself
    about one fact, in the same file — and `to_deploy_env` refuses to name the machine,
    printing its `local` warning with the address it needs three lines further down.
    """

    def test_the_control_planes_address_comes_from_the_merged_options(self, tmp_path: Path):
        path = tmp_path / "manifest.json"
        m = _intent(path, cp_address="10.0.0.1")
        assert m["hosts"][0]["address"] == "10.0.0.1"

        # A later run that knows nothing about the address must not blank it.
        fm.set_intent(
            m,
            hosts_csv="cp.example.com,w1.example.com",
            install_dir="/opt/logstotal",
            written_by="0.10.0",
            written_at="2026-08-27T13:00:00Z",
            options={},
        )
        assert m["options"]["cp_address"] == "10.0.0.1"
        assert m["hosts"][0]["address"] == "10.0.0.1"

    def test_a_pull_uses_the_recorded_address_for_a_local_control_plane(self, tmp_path: Path):
        """The record only has to carry the address ONCE for the pulled file to be usable."""
        m = _intent(tmp_path / "manifest.json", hosts="local,root@w1.example.com", cp_address="10.0.0.1")
        m["hosts"][0]["address"] = ""  # an older record that only has it in options
        rendered = fm.to_deploy_env(m)
        assert "DEPLOY_HOSTS=10.0.0.1,root@w1.example.com" in rendered
        assert "WARNING" not in rendered

    def test_and_still_warns_when_neither_knows(self, tmp_path: Path):
        m = _intent(tmp_path / "manifest.json", hosts="local,root@w1.example.com")
        rendered = fm.to_deploy_env(m)
        assert "DEPLOY_HOSTS=local,root@w1.example.com" in rendered
        assert "WARNING" in rendered
