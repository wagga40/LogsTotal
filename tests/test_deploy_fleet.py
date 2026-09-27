"""Tests for scripts/deploy-fleet.sh — the one command.

It composes the other deploy scripts rather than reimplementing them, so what is
worth pinning is the composition: that every step runs, in order, that each optional
one honours its knob, and that the host list reaches the tooling as arguments rather
than through a go-task env bridge (which exports the key even when it resolves empty,
silently defeating the documented deploy.env workflow).

Step 8 shells out to `task deploy`, which these cannot reach: they run
from an isolated cwd where go-task finds no Taskfile. So they assert on steps 1-6 —
everything this script itself decides — and the full chain is exercised on a VM.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "deploy-fleet.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _run(
    tmp_path: Path,
    args: list[str] | None = None,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_") or key.startswith("WIRECONF") or key.startswith("BASIC_AUTH_"):
            env.pop(key, None)
    for var in ("SSH_IDENTITY", "DOMAIN", "FORCE", "SMOKE_URL"):
        env.pop(var, None)
    env["DEPLOY_DRY_RUN"] = "true"
    env["DEPLOY_ENV_FILE"] = "deploy.env"  # relative, so each cwd gets its own
    env.update(env_overrides or {})
    return subprocess.run(
        ["bash", str(SCRIPT), *(args or [])],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


# ── Writing the host list ────────────────────────────────────────────────────


def test_init_writes_the_host_list(tmp_path: Path):
    result = _run(tmp_path, ["init", "cp.example.com", "w1.example.com"])
    assert result.returncode == 0, result.stdout + result.stderr
    written = (tmp_path / "deploy.env").read_text(encoding="utf-8")
    assert "DEPLOY_HOSTS=cp.example.com,w1.example.com" in written
    assert "control plane : cp.example.com" in result.stdout


def test_init_keeps_an_existing_file(tmp_path: Path):
    """It may hold knobs this does not know about — clobbering them silently is worse
    than making the operator ask."""
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=old.example\nDEPLOY_KEEP_RELEASES=9\n", encoding="utf-8")
    result = _run(tmp_path, ["init", "cp.example.com"])
    assert result.returncode == 0
    assert "DEPLOY_KEEP_RELEASES=9" in (tmp_path / "deploy.env").read_text(encoding="utf-8")
    assert "FORCE=yes" in result.stdout


def test_init_overwrites_when_forced(tmp_path: Path):
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=old.example\n", encoding="utf-8")
    result = _run(tmp_path, ["init", "cp.example.com"], {"FORCE": "yes"})
    assert result.returncode == 0
    assert "old.example" not in (tmp_path / "deploy.env").read_text(encoding="utf-8")


def test_init_records_the_domain_under_both_names(tmp_path: Path):
    """deploy-smoke.sh resolves its target from DOMAIN, and once Caddy binds WEB_PORT
    to loopback the http://host:8000 fallback no longer answers."""
    _run(tmp_path, ["init", "cp.example.com"], {"DEPLOY_DOMAIN": "logs.example.com"})
    written = (tmp_path / "deploy.env").read_text(encoding="utf-8")
    assert "DEPLOY_DOMAIN=logs.example.com" in written
    assert "DOMAIN=logs.example.com" in written


def test_a_bad_host_token_is_refused(tmp_path: Path):
    result = _run(tmp_path, ["init", "cp.example.com;rm -rf /"])
    assert result.returncode != 0
    assert "Not a host" in result.stderr


def test_no_hosts_anywhere_names_the_fix(tmp_path: Path):
    result = _run(tmp_path)
    assert result.returncode != 0
    assert "task deploy" in result.stderr


# ── The composition ──────────────────────────────────────────────────────────


def _step_numbers(out: str) -> list[int]:
    return [int(m) for m in re.findall(r"Step (\d)/8:", out)]


def test_the_steps_run_in_order(tmp_path: Path):
    result = _run(tmp_path, ["cp.example.com", "w1.example.com"])
    numbers = _step_numbers(result.stdout)
    assert numbers == sorted(numbers)
    # Steps 1-6 all run here; 7 is the deploy itself, which needs a package.
    assert numbers[:6] == [1, 2, 3, 4, 5, 6]


def test_positional_hosts_are_remembered(tmp_path: Path):
    """Naming them once is what makes every later deploy task run bare."""
    _run(tmp_path, ["cp.example.com", "w1.example.com"])
    assert "DEPLOY_HOSTS=cp.example.com,w1.example.com" in (tmp_path / "deploy.env").read_text(encoding="utf-8")


def test_hosts_come_from_deploy_env_when_no_arguments_are_given(tmp_path: Path):
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=fromfile.example,w9.example\nDEPLOY_VPN=none\n", encoding="utf-8")
    result = _run(tmp_path)
    assert "fromfile.example (control-plane)" in result.stdout


def test_a_deploy_env_that_predates_the_wireconf_default_has_to_choose(tmp_path: Path):
    """A fleet configured when the VPN was opt-in must not be converted behind the
    operator's back: building a tunnel re-addresses every cross-host URL from the public
    address to 10.200.0.x, which on a running fleet is an outage, not an improvement.

    The signal is that deploy.env exists and says nothing about DEPLOY_VPN — which is
    exactly that case. It stops before step 1, because bootstrap installs WireGuard and
    opens the hub's port.
    """
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example,w1.example\n", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode != 0
    assert "set up before private networking became the default" in result.stderr
    assert "DEPLOY_VPN=wireconf ./logstotal deploy" in result.stderr
    assert "DEPLOY_VPN=none ./logstotal deploy" in result.stderr
    assert "Step 1/8" not in result.stdout, "nothing may run before the operator has chosen"


@pytest.mark.parametrize("choice", ["wireconf", "none"])
def test_either_answer_settles_it(tmp_path: Path, choice):
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example,w1.example\n", encoding="utf-8")
    result = _run(tmp_path, None, {"DEPLOY_VPN": choice})
    assert "set up before private networking became the default" not in result.stderr
    assert "Step 1/8" in result.stdout


def test_a_fleet_with_no_deploy_env_is_not_asked(tmp_path: Path):
    """There is no prior configuration to preserve, so the default simply applies."""
    result = _run(tmp_path, ["cp.example.com", "w1.example.com"])
    assert "set up before private networking became the default" not in result.stderr
    assert re.search(r"Private network\s+wireconf", result.stdout)


def test_bootstrap_is_skippable(tmp_path: Path):
    off = _run(tmp_path, ["cp.example.com"], {"DEPLOY_BOOTSTRAP": "false"})
    assert "skipped (DEPLOY_BOOTSTRAP is off)" in off.stdout


def test_a_single_host_fleet_does_not_get_a_pointless_mesh(tmp_path: Path):
    """A hub-and-spoke mesh with no spokes protects nothing, and building one still
    installs WireGuard and rewrites the hub's firewall."""
    off = _run(tmp_path, ["cp.example.com"], {"DEPLOY_BOOTSTRAP": "false"})
    assert "not building one — only one host" in off.stdout
    assert re.search(r"Private network\s+none", off.stdout), "the banner must agree with what actually runs"


def test_the_vpn_runs_when_there_is_something_to_protect(tmp_path: Path):
    on = _run(tmp_path, ["cp.example.com", "w1.example.com"], {"DEPLOY_VPN": "wireconf"})
    assert "Private network (Wireconf)" in on.stdout
    assert "Hub: cp.example.com → 10.200.0.1" in on.stdout


def test_env_files_are_generated_and_pushed(tmp_path: Path):
    result = _run(tmp_path, ["cp.example.com", "w1.example.com"])
    assert "deploy-envs/cp.example.com.env  (control-plane)" in result.stdout
    assert "install -m 600" in result.stdout


def test_a_worker_joining_a_live_fleet_is_announced(tmp_path: Path):
    result = _run(tmp_path, ["cp.example.com", "w1.example.com"], {"DEPLOY_ONLY": "w1.example.com"})
    assert re.search(r"Acting on\s+w1\.example\.com", result.stdout)


# ── Basic auth ───────────────────────────────────────────────────────────────


def test_the_password_is_hashed_on_the_control_plane_not_here(tmp_path: Path):
    """The control plane always has Docker; the operator's laptop may not."""
    result = _run(
        tmp_path,
        ["cp.example.com"],
        {"DEPLOY_DOMAIN": "logs.example.com", "DEPLOY_BASIC_AUTH_USER": "ops", "DEPLOY_BASIC_AUTH_PASSWORD": "hunter2"},
    )
    assert "would hash the basic-auth password on cp.example.com" in result.stdout


def test_the_plaintext_password_never_appears_in_the_output(tmp_path: Path):
    result = _run(
        tmp_path,
        ["cp.example.com"],
        {"DEPLOY_DOMAIN": "logs.example.com", "DEPLOY_BASIC_AUTH_USER": "ops", "DEPLOY_BASIC_AUTH_PASSWORD": "hunter2"},
    )
    assert "hunter2" not in result.stdout
    assert "hunter2" not in result.stderr
    assert "hunter2" not in (tmp_path / "deploy.env").read_text(encoding="utf-8")


def test_the_hashing_command_reads_stdin_rather_than_taking_the_password_as_an_argument(tmp_path: Path):
    """`caddy hash-password --plaintext <pw>` puts the password in the control plane's
    argv, where every user on the box can read it out of ps. The manual docs keep that
    form because a human types it interactively; automation must not."""
    code = "\n".join(line for line in SCRIPT.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#"))
    assert "caddy hash-password" in code
    assert "--plaintext" not in code


def test_basic_auth_is_announced_in_the_banner(tmp_path: Path):
    # Separate directories: the first run writes deploy.env, which the second would
    # otherwise inherit — including DEPLOY_BASIC_AUTH_USER.
    on, off = tmp_path / "on", tmp_path / "off"
    on.mkdir()
    off.mkdir()
    with_auth = _run(on, ["cp.example.com"], {"DEPLOY_DOMAIN": "d.example", "DEPLOY_BASIC_AUTH_USER": "ops"})
    assert re.search(r"Basic auth\s+ops", with_auth.stdout), "the banner names the account, not just that auth is on"
    without = _run(off, ["cp.example.com"])
    assert re.search(r"Basic auth\s+off", without.stdout)


# ── A failed basic-auth hash must stop the deploy ────────────────────────────
#
# Warning and continuing would deploy a control plane the operator believes is behind HTTP
# auth and which is not: the deploy reports success, the smoke check passes, and the only
# sign is one warning in a thousand lines of output.


def _docker_shim(tmp_path: Path, stdout: str, exit_code: int = 0) -> Path:
    d = tmp_path / "shim"
    d.mkdir(exist_ok=True)
    docker = d / "docker"
    docker.write_text(f"#!/bin/sh\ncat >/dev/null\nprintf '%s' {stdout!r}\nexit {exit_code}\n")
    docker.chmod(0o755)
    # Step 2 is a real preflight against `local`, and it asks whether we can elevate:
    # `[ "$(id -u)" = 0 ] || sudo -n true`. On a developer's machine that is a genuine
    # FAIL and would stop the composer before it ever reaches the basic-auth step these
    # tests are about — correctly, for a real deploy. A stub answers it the way a
    # properly-configured host would, the same shape as the `docker` stub above.
    sudo = d / "sudo"
    sudo.write_text("#!/bin/sh\nexit 0\n")
    sudo.chmod(0o755)
    return d


def _auth_run(tmp_path: Path, shim: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_") or key.startswith("BASIC_AUTH_"):
            env.pop(key, None)
    env.update(
        {
            "PATH": f"{shim}{os.pathsep}{env['PATH']}",
            "HOME": str(tmp_path),
            "DEPLOY_ENV_FILE": "deploy.env",
            "DEPLOY_BOOTSTRAP": "false",
            "DEPLOY_REMOTE_DIR": str(tmp_path / "opt"),
            "DEPLOY_CP_ADDRESS": "10.0.0.1",
            "DEPLOY_DOMAIN": "logs.example.com",
            "DEPLOY_BASIC_AUTH_USER": "ops",
            "DEPLOY_BASIC_AUTH_PASSWORD": "hunter2",
        }
    )
    return subprocess.run(
        ["bash", str(SCRIPT), "local"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_failed_hash_stops_the_deploy_instead_of_dropping_the_auth(tmp_path: Path):
    result = _auth_run(tmp_path, _docker_shim(tmp_path, "", exit_code=1))
    assert result.returncode != 0
    assert "Nothing was deployed" in result.stderr
    assert not (tmp_path / "deploy-envs").exists(), "no env files may be written after the refusal"


def test_a_non_bcrypt_answer_is_refused(tmp_path: Path):
    """An empty-ish or error string silently became the BASIC_AUTH_HASH, and Caddy then
    rejected every login with nothing in any log saying why."""
    result = _auth_run(tmp_path, _docker_shim(tmp_path, "Error: no such image\n"))
    assert result.returncode != 0
    assert "is not bcrypt" in result.stderr


def test_the_password_is_absent_from_every_failure_message(tmp_path: Path):
    for shim_out, code in (("", 1), ("garbage\n", 0)):
        result = _auth_run(tmp_path, _docker_shim(tmp_path, shim_out, code))
        assert "hunter2" not in result.stderr
        assert "hunter2" not in result.stdout


def test_a_real_bcrypt_hash_is_accepted(tmp_path: Path):
    shim = _docker_shim(tmp_path, "$2a$14$Ck9tE8VUJx1qk3nL0oPqSePBUXPGwqzQ1pQ0m3rLxYyBqz3Yh0Xy2\n")
    _auth_run(tmp_path, shim)
    written = (tmp_path / "deploy-envs" / "local.env").read_text(encoding="utf-8")
    assert "BASIC_AUTH_USER=ops" in written
    assert "BASIC_AUTH_HASH='$2a$14$" in written
    assert "hunter2" not in written


def test_the_password_is_sent_with_a_trailing_newline(tmp_path: Path):
    """`caddy hash-password` reads a LINE from stdin. Without the newline it hits EOF
    mid-read and exits 1 with "Error: EOF" — which, with stderr discarded, arrived as an
    empty capture and read like "Docker is not running there". Reproduced against a real
    Docker host; caddy strips the newline, so the hash verifies against the password
    itself (checked with bcrypt.checkpw)."""
    shim = tmp_path / "shim"
    shim.mkdir()
    seen = tmp_path / "stdin.bin"
    docker = shim / "docker"
    # Only the hash-password call may consume stdin: preflight runs `docker info` and
    # `docker compose version` through the same shim, and a blanket `cat` there both
    # blocks and overwrites the capture.
    docker.write_text(
        f"#!/bin/sh\ncase \"$*\" in\n  *hash-password*) cat > {seen}; printf '$2a$14$stubstubstubstubstubstubstubstubstubstubstubstubstubstub\\n' ;;\n  *) exit 0 ;;\nesac\n"
    )
    docker.chmod(0o755)
    # Step 2's preflight asks whether we can elevate; see the note in _docker_shim.
    (shim / "sudo").write_text("#!/bin/sh\nexit 0\n")
    (shim / "sudo").chmod(0o755)
    _auth_run(tmp_path, shim)
    assert seen.read_bytes() == b"hunter2\n", "caddy needs the terminating newline or it reports EOF"


# ── The pre-bootstrap gate ───────────────────────────────────────────────────


def test_the_reachability_gate_runs_before_bootstrap(tmp_path: Path):
    """DEPLOY_PREFLIGHT_STAGE=pre existed for exactly this position and NOTHING SET IT,
    so the only preflight that ran was the fatal one at step 6 of 8 — by which point
    packages were installed, a WireGuard mesh was built and an .env had been written to
    every host. That is not a gate; it is a report filed after the fact."""
    result = _run(tmp_path, ["cp.example.com", "w1.example.com"])
    out = result.stdout
    gate = out.index("Step 2/8: reachability and privilege")
    bootstrap = out.index("Step 3/8: bootstrap hosts")
    preflight = out.index("Step 6/8: preflight")
    assert gate < bootstrap < preflight


def test_a_host_that_cannot_be_reached_stops_the_deploy_before_anything_is_installed(tmp_path: Path):
    """The point of the gate. `local` on a machine with no passwordless sudo cannot be
    deployed to, and the run must stop saying so — not install packages first."""
    shim = tmp_path / "nosudo"
    shim.mkdir()
    # A sudo that refuses, which is what a host without NOPASSWD looks like.
    (shim / "sudo").write_text("#!/bin/sh\nexit 1\n")
    (shim / "sudo").chmod(0o755)
    env = {**os.environ}
    for key in list(env):
        if key.startswith("DEPLOY_"):
            env.pop(key, None)
    env.update(
        {
            "PATH": f"{shim}{os.pathsep}{env['PATH']}",
            "HOME": str(tmp_path),
            "DEPLOY_ENV_FILE": "deploy.env",
            "DEPLOY_REMOTE_DIR": str(tmp_path / "opt"),
            "DEPLOY_CP_ADDRESS": "10.0.0.1",
            "DEPLOY_VPN": "none",
        }
    )
    result = subprocess.run(
        ["bash", str(SCRIPT), "local"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "no root and no passwordless sudo" in result.stdout
    assert "Step 3/8: bootstrap hosts" not in result.stdout, "the gate must stop the run before bootstrap installs anything"


# ── deploy.env's VPN choice ──────────────────────────────────────────────────


def test_declining_the_vpn_in_deploy_env_is_honoured(tmp_path: Path):
    """`DEPLOY_VPN=none` in deploy.env built a WireGuard mesh anyway.

    vpn_mode is resolved early, so the banner and the written deploy.env agree with what
    will happen — but only DEPLOY_HOSTS had been loaded from the file by then, so the mode
    resolved as unset and defaulted to wireconf. The second deploy_env_load further down
    DID pick the value up, so the same run then warned "set DEPLOY_VPN=wireconf" about the
    tunnel it was in the middle of building.

    Building one is not a cosmetic difference: it re-addresses every cross-host URL from
    the public address to 10.200.0.x, which on a running fleet is an outage — and a tunnel
    that is asked for and cannot be built STOPS the deploy, so a fleet that wanted none
    could be halted by one it never requested.
    """
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example,w1.example\nDEPLOY_VPN=none\n", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(r"Private network\s+none", result.stdout)
    assert "VPN step skipped" in result.stdout
    assert "apply" not in result.stdout, "it would have built the mesh anyway"


def test_asking_for_the_vpn_in_deploy_env_is_honoured_too(tmp_path: Path):
    """The control: honouring an opt-out must not make `none` the answer to everything."""
    (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=cp.example,w1.example\nDEPLOY_VPN=wireconf\n", encoding="utf-8")
    result = _run(tmp_path)
    assert re.search(r"Private network\s+wireconf", result.stdout)
    assert "VPN step skipped" not in result.stdout


# ── deploy:init writes a file worth editing ──────────────────────────────────


class TestTheGeneratedFileIsATemplate:
    """`deploy:init` is described as "the step that gives you something to EDIT".

    Four bare lines would leave an operator who has never opened deploy.env.example not
    knowing that DEPLOY_DOMAIN, DEPLOY_HUEY_WORKERS or RELEASE_REPO_URL exist. It also emits
    the settings most often tuned on a first deploy, commented, at their documented defaults.
    """

    #: Every key the template offers. Curated on purpose — deploy.env.example documents 49,
    #: and a template nobody reads to the end is the same as no template.
    TEMPLATED = (
        "DEPLOY_REMOTE_DIR",
        "SSH_IDENTITY",
        "DEPLOY_VPN_NETWORK",
        "DEPLOY_VPN_PORT",
        "DEPLOY_CP_ADDRESS",
        "DEPLOY_DOMAIN",
        "DEPLOY_PROXY_TLS",
        "DEPLOY_ACME_EMAIL",
        "DEPLOY_BASIC_AUTH_USER",
        "DEPLOY_BASIC_AUTH_PASSWORD",
        "DEPLOY_BASIC_AUTH_HASH",
        "DEPLOY_HUEY_WORKERS",
        "DEPLOY_KEEP_RELEASES",
        "DEPLOY_ADMIN_EMAIL",
        "RELEASE_REPO_URL",
    )

    def test_every_offered_knob_is_offered(self, tmp_path: Path):
        _run(tmp_path, ["init", "cp.example.com", "w1.example.com"])
        written = (tmp_path / "deploy.env").read_text(encoding="utf-8")
        missing = [k for k in self.TEMPLATED if f"#{k}=" not in written]
        assert not missing, f"the template stopped offering: {missing}"

    def test_no_offered_knob_has_drifted_from_deploy_env_example(self):
        """The anti-drift pin. A key offered here but not real is worse than a sparse
        file: it teaches a setting that does nothing."""
        documented = (REPO_ROOT / "deploy.env.example").read_text(encoding="utf-8")
        missing = [k for k in self.TEMPLATED if f"{k}=" not in documented]
        assert not missing, f"offered by deploy:init but absent from deploy.env.example: {missing}"

    #: Offered at a value that deliberately differs from deploy.env.example's. Only
    #: RELEASE_REPO_URL earns it: the example shows a self-hosted forge on a port,
    #: because illustrating WHEN you would set it is the whole point of that entry,
    #: while the generated file writes the real built-in default from
    #: common.sh::release_repo_url. Anything else here is drift wearing an exemption.
    ILLUSTRATIVE_IN_THE_EXAMPLE = {"RELEASE_REPO_URL"}

    #: A *setting* line: one that `deploy_env_default` (which greps `^KEY=`) would read
    #: once its comment marker came off — a `#`, then at most one space. The indent is
    #: what separates it from a usage example like
    #: `#   DEPLOY_BASIC_AUTH_PASSWORD='a long passphrase' task deploy`, which names the
    #: same key and is a command, not a value. Both files carry both shapes, and reading
    #: the example as a setting made this comparison fail against two identical files.
    #:
    #: Matched line by line rather than with one re.M pattern over the whole text: a
    #: trailing `# comment` group, plus a whitespace class that matches newlines, lets one
    #: match run past its own line and swallow the next key — which reads as "both agree".
    #:
    #: Commented, because both halves of both files are compared here and only the
    #: commented half is a *default*: `DEPLOY_HOSTS` and `DEPLOY_VPN` are written for real
    #: with this fleet's own values, which the reference has no opinion about.
    _OFFERED = re.compile(r"^# ?([A-Z_][A-Z0-9_]*)=(.*)$")

    @classmethod
    def _settings(cls, text: str) -> dict[str, str]:
        """KEY -> offered default, first occurrence winning."""
        found: dict[str, str] = {}
        for line in text.splitlines():
            m = cls._OFFERED.match(line)
            if m:
                found.setdefault(m.group(1), m.group(2).split("  #")[0].strip())
        return found

    def test_the_offered_defaults_are_the_documented_ones(self, tmp_path: Path):
        """deploy.env.example is the reference; deploy:init writes a copy of it.

        Key presence was pinned above and value parity was not, so the template offered
        DEPLOY_HUEY_WORKERS=2 against a real default of 4 (deploy_fleet_env.py's
        --huey-workers) — an operator uncommenting it to "keep the default" would have
        halved their fleet's capacity, and the reference three lines away said 4."""
        _run(tmp_path, ["init", "cp.example.com"])
        offered = self._settings((tmp_path / "deploy.env").read_text(encoding="utf-8"))
        documented = self._settings((REPO_ROOT / "deploy.env.example").read_text(encoding="utf-8"))
        shared = set(self.TEMPLATED) & set(offered) & set(documented) - self.ILLUSTRATIVE_IN_THE_EXAMPLE
        drifted = {key: (offered[key], documented[key]) for key in sorted(shared) if offered[key] != documented[key]}
        assert not drifted, f"deploy:init offers a value deploy.env.example does not (offered, documented): {drifted}"

    def test_the_exemptions_are_real_disagreements(self, tmp_path: Path):
        """The ratchet. An exemption for a key the two files already agree on hides the next
        one that should not have been exempted."""
        _run(tmp_path, ["init", "cp.example.com"])
        offered = self._settings((tmp_path / "deploy.env").read_text(encoding="utf-8"))
        documented = self._settings((REPO_ROOT / "deploy.env.example").read_text(encoding="utf-8"))
        stale = {k for k in self.ILLUSTRATIVE_IN_THE_EXAMPLE if offered.get(k) == documented.get(k)}
        assert not stale, f"exempted but no longer disagreeing: {sorted(stale)}"

    def test_both_basic_auth_credentials_are_offered_in_both_files(self, tmp_path: Path):
        """A key the deploy reads is a key both files offer.

        deploy-fleet.sh reads the password from deploy.env and the reference lists it, so a
        template offering the username alone — the password "is never stored here" — would
        give an operator who set it in the file it is documented in a working deploy and a
        template telling them it cannot work."""
        _run(tmp_path, ["init", "cp.example.com"])
        for name, text in (
            ("deploy.env", (tmp_path / "deploy.env").read_text(encoding="utf-8")),
            ("deploy.env.example", (REPO_ROOT / "deploy.env.example").read_text(encoding="utf-8")),
        ):
            offered = self._settings(text)
            for key in ("DEPLOY_BASIC_AUTH_USER", "DEPLOY_BASIC_AUTH_PASSWORD", "DEPLOY_BASIC_AUTH_HASH"):
                assert key in offered, f"{name} does not offer {key}"

    def test_the_deploy_reads_every_basic_auth_key_the_files_offer(self):
        """The other half: offering a key nothing reads teaches a setting that does nothing.

        deploy-smoke.sh is included deliberately. Refusing the password on the grounds that
        reading it back "would invite storing it" means, once the file offers the line, 401
        against a fleet whose password is sitting in it."""
        for script in ("deploy-fleet.sh", "deploy-smoke.sh"):
            code = (REPO_ROOT / "scripts" / script).read_text(encoding="utf-8")
            body = "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("#"))
            assert "DEPLOY_BASIC_AUTH_PASSWORD" in body, f"{script} never reads the password"

    def test_a_default_account_name_is_admin(self, tmp_path: Path):
        """One name for "the person who runs this", across both files.

        The three surfaces had three: `analyst` from deploy:init, `ops` from the example,
        `admin` from .env.example — for the same Caddy credential."""
        _run(tmp_path, ["init", "cp.example.com"])
        offered = self._settings((tmp_path / "deploy.env").read_text(encoding="utf-8"))
        documented = self._settings((REPO_ROOT / "deploy.env.example").read_text(encoding="utf-8"))
        app_env = self._settings((REPO_ROOT / ".env.example").read_text(encoding="utf-8"))
        assert offered["DEPLOY_BASIC_AUTH_USER"] == "admin"
        assert documented["DEPLOY_BASIC_AUTH_USER"] == "admin"
        assert app_env["BASIC_AUTH_USER"] == "admin"

    def test_the_commented_knobs_are_inert(self, tmp_path: Path):
        """deploy_env_default greps ^KEY=, so a commented line cannot change a deploy.
        This is what makes a template safe to ship rather than a pile of new defaults."""
        _run(tmp_path, ["init", "cp.example.com"])
        common = REPO_ROOT / "scripts" / "lib" / "common.sh"
        reads = subprocess.run(
            [
                "bash",
                "-c",
                f". {common}\n" + "".join(f'printf "%s\\n" "$(deploy_env_default {k})"\n' for k in self.TEMPLATED),
            ],
            cwd=tmp_path,
            env={**os.environ, "DEPLOY_ENV_FILE": "deploy.env"},
            capture_output=True,
            text=True,
        )
        values = reads.stdout.splitlines()
        assert values and not any(v.strip() for v in values), f"a commented knob was read as a value: {values}"

    def test_a_supplied_value_is_written_once_and_uncommented(self, tmp_path: Path):
        """The two halves must not both claim a key: a real DEPLOY_DOMAIN= above and a
        commented one below reads as a contradiction, and an operator uncommenting the
        second would silently change nothing."""
        _run(tmp_path, ["init", "cp.example.com"], {"DEPLOY_DOMAIN": "logs.example.com"})
        written = (tmp_path / "deploy.env").read_text(encoding="utf-8")
        assert "DEPLOY_DOMAIN=logs.example.com" in written
        assert "#DEPLOY_DOMAIN=" not in written, "the key was offered as a template AND written for real"

    def test_the_file_keeps_the_grep_contract(self, tmp_path: Path):
        """deploy.env is read with grep and cut, never sourced — so no quotes, no inline
        comments, no indentation. A generated file has to obey the format it will be read
        back with."""
        _run(tmp_path, ["init", "cp.example.com"], {"DEPLOY_DOMAIN": "logs.example.com"})
        for line in (tmp_path / "deploy.env").read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            assert re.match(r"^[A-Z][A-Z0-9_]*=", line), f"not a bare KEY=VALUE line: {line!r}"
            value = line.split("=", 1)[1]
            assert not value.startswith(("'", '"')), f"a quoted value arrives with its quotes: {line!r}"
            assert " #" not in value, f"an inline comment becomes part of the value: {line!r}"

    def test_it_still_refuses_to_clobber(self, tmp_path: Path):
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=already.example.com\n")
        result = _run(tmp_path, ["init", "cp.example.com"])
        assert "already exists" in result.stdout + result.stderr
        assert (tmp_path / "deploy.env").read_text(encoding="utf-8") == "DEPLOY_HOSTS=already.example.com\n"

    def test_the_overwrite_hint_names_init_not_deploy(self, tmp_path: Path):
        """write_deploy_env is shared with the positional-deploy path. Naming `task deploy`
        unconditionally told you that the way to rewrite one file was to deploy the fleet."""
        (tmp_path / "deploy.env").write_text("DEPLOY_HOSTS=already.example.com\n")
        result = _run(tmp_path, ["init", "cp.example.com"])
        assert "FORCE=yes task deploy:init" in result.stdout + result.stderr
