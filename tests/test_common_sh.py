"""Tests for scripts/lib/common.sh — the shared shell helper library.

Every helper here is sourced into a script that sets its own shell options, and the
two that matter most are exercised under `set -euo pipefail` deliberately:
scripts/deploy-multiserver.sh runs with pipefail on, and a helper whose pipeline can
exit non-zero takes the whole deploy down before it prints anything.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
COMMON_SH = PROJECT_ROOT / "scripts" / "lib" / "common.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _run(body: str, cwd: Path, opts: str = "set -euo pipefail") -> subprocess.CompletedProcess:
    script = f'{opts}\n. "{COMMON_SH}"\n{body}\n'
    return subprocess.run(["bash", "-c", script], cwd=cwd, capture_output=True, text=True)


def _deploy_env(tmp_path: Path, contents: str) -> Path:
    (tmp_path / "deploy.env").write_text(contents, encoding="utf-8")
    return tmp_path


class TestDeployEnvDefault:
    def test_a_missing_key_does_not_kill_a_pipefail_caller(self, tmp_path: Path):
        """What this guards: `grep` exits 1 on no match, pipefail promotes that to the
        pipeline's status, and `v=$(deploy_env_default X)` aborts the script. A caller
        running `set -eu` without pipefail never sees it — deploy-multiserver.sh is the
        one that sets it."""
        _deploy_env(tmp_path, "DEPLOY_HOSTS=a.example.com\n")
        res = _run('v=$(deploy_env_default NOPE); echo "reached:[$v]"', tmp_path)
        assert res.returncode == 0, res.stderr
        assert "reached:[]" in res.stdout

    def test_a_missing_file_does_not_kill_a_pipefail_caller(self, tmp_path: Path):
        res = _run('v=$(deploy_env_default DEPLOY_HOSTS); echo "reached:[$v]"', tmp_path)
        assert res.returncode == 0, res.stderr
        assert "reached:[]" in res.stdout

    def test_a_present_key_returns_its_value(self, tmp_path: Path):
        _deploy_env(tmp_path, "# comment\nDEPLOY_HOSTS=a.example.com,b.example.com\n")
        res = _run('echo "[$(deploy_env_default DEPLOY_HOSTS)]"', tmp_path)
        assert "[a.example.com,b.example.com]" in res.stdout

    def test_a_value_containing_equals_survives_intact(self, tmp_path: Path):
        """`cut -d'=' -f2-`, not `-f2` — a postgres URL is mostly equals signs."""
        _deploy_env(tmp_path, "SMOKE_URL=https://x/?a=1&b=2\n")
        res = _run('echo "[$(deploy_env_default SMOKE_URL)]"', tmp_path)
        assert "[https://x/?a=1&b=2]" in res.stdout


class TestDeployEnvLoad:
    def test_it_exports_keys_from_the_file(self, tmp_path: Path):
        _deploy_env(tmp_path, "DEPLOY_HOSTS=a.example.com\nSSH_IDENTITY=~/.ssh/id_ed25519\n")
        res = _run(
            'deploy_env_load DEPLOY_HOSTS SSH_IDENTITY; echo "[$DEPLOY_HOSTS][$SSH_IDENTITY]"',
            tmp_path,
        )
        assert "[a.example.com][~/.ssh/id_ed25519]" in res.stdout

    def test_caller_env_always_wins(self, tmp_path: Path):
        _deploy_env(tmp_path, "DEPLOY_REMOTE_DIR=/srv/from-file\n")
        res = _run(
            'export DEPLOY_REMOTE_DIR=/opt/from-caller; deploy_env_load DEPLOY_REMOTE_DIR; echo "[$DEPLOY_REMOTE_DIR]"',
            tmp_path,
        )
        assert "[/opt/from-caller]" in res.stdout

    def test_set_but_empty_counts_as_set(self, tmp_path: Path):
        """The `${!key+x}` test: an operator who exported KEY= meant "no value", not
        "read the file"."""
        _deploy_env(tmp_path, "DEPLOY_HOST=from-file\n")
        res = _run(
            'export DEPLOY_HOST=; deploy_env_load DEPLOY_HOST; echo "[${DEPLOY_HOST}]"',
            tmp_path,
        )
        assert "[]" in res.stdout

    def test_a_key_the_file_does_not_have_stays_unset(self, tmp_path: Path):
        _deploy_env(tmp_path, "DEPLOY_HOSTS=a\n")
        res = _run(
            'deploy_env_load DEPLOY_MISSING; echo "[${DEPLOY_MISSING:-<unset>}]"',
            tmp_path,
        )
        assert "[<unset>]" in res.stdout

    def test_only_the_named_keys_are_exported(self, tmp_path: Path):
        """Exporting every line in the file would let a stray PATH= or LD_PRELOAD= in
        deploy.env silently reconfigure the deploy."""
        _deploy_env(tmp_path, "DEPLOY_HOSTS=a\nLD_PRELOAD=/tmp/evil.so\n")
        res = _run(
            'deploy_env_load DEPLOY_HOSTS; echo "[${LD_PRELOAD:-<unset>}]"',
            tmp_path,
        )
        # Whatever the caller had — a CI runner may preload a library of its own — and never
        # the file's value.
        assert f"[{os.environ.get('LD_PRELOAD') or '<unset>'}]" in res.stdout
        assert "/tmp/evil.so" not in res.stdout

    def test_an_indented_key_is_skipped_not_fatal(self, tmp_path: Path):
        """`export "  KEY=v"` is an invalid variable name and would abort a naive loader
        outright, under set -e, before the deploy printed anything."""
        _deploy_env(tmp_path, "  INDENTED=x\nDEPLOY_HOSTS=z\n")
        res = _run('deploy_env_load DEPLOY_HOSTS; echo "survived:[$DEPLOY_HOSTS]"', tmp_path)
        assert res.returncode == 0, res.stderr
        assert "survived:[z]" in res.stdout


class TestLocalHostSentinel:
    """`local` in DEPLOY_HOSTS means this machine — how the deploy runs from the CP."""

    @pytest.mark.parametrize("host", ["local"])
    def test_the_sentinel_matches(self, host: str, tmp_path: Path):
        res = _run(f'is_local_host "{host}" && echo YES || echo no', tmp_path)
        assert "YES" in res.stdout

    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "cp.local", "local.example.com", ""])
    def test_nothing_else_matches(self, host: str, tmp_path: Path):
        """localhost is a legitimate SSH target, and every mDNS name carries a dot."""
        res = _run(f'is_local_host "{host}" && echo YES || echo no', tmp_path)
        assert "no" in res.stdout


class TestHostExec:
    def test_a_local_command_runs_here_without_ssh(self, tmp_path: Path):
        res = _run(f'host_exec local "touch {tmp_path}/made-it"', tmp_path)
        assert res.returncode == 0, res.stderr
        assert (tmp_path / "made-it").exists()

    def test_a_joined_command_string_is_re_parsed_like_ssh_does(self, tmp_path: Path):
        """`bash -c "$*"`, not `"$@"` — the latter execs a binary literally named
        `mkdir -p /opt/logstotal`, which is how the callers pass their commands."""
        res = _run(f'host_exec local "mkdir -p {tmp_path}/a/b/c"', tmp_path)
        assert res.returncode == 0, res.stderr
        assert (tmp_path / "a" / "b" / "c").is_dir()

    def test_a_heredoc_still_reaches_the_inner_shell(self, tmp_path: Path):
        """Three call shapes exist; `host_exec h bash -s <<EOS` is the one every
        multi-line remote block uses, and it only works if stdin is inherited."""
        body = f"host_exec local bash -s <<'EOS'\necho from-the-heredoc > {tmp_path}/out\nEOS"
        res = _run(body, tmp_path)
        assert res.returncode == 0, res.stderr
        assert (tmp_path / "out").read_text().strip() == "from-the-heredoc"

    def test_a_failing_local_command_reports_its_status(self, tmp_path: Path):
        res = _run('host_exec local "exit 7" || echo "status:$?"', tmp_path)
        assert "status:7" in res.stdout

    def test_dry_run_traces_a_local_command_and_never_says_ssh(self, tmp_path: Path):
        res = _run('DEPLOY_DRY_RUN=true host_exec local "true"', tmp_path)
        assert "DRY-RUN local: true" in res.stdout
        assert "ssh" not in res.stdout
        assert "root@local" not in res.stdout

    def test_dry_run_still_traces_ssh_for_a_remote_host(self, tmp_path: Path):
        res = _run('DEPLOY_DRY_RUN=true host_exec w1.example.com "true"', tmp_path)
        assert "DRY-RUN ssh root@w1.example.com: true" in res.stdout


class TestHostCopy:
    def test_copy_to_a_local_host_is_a_plain_copy(self, tmp_path: Path):
        (tmp_path / "src").write_text("payload", encoding="utf-8")
        res = _run(f'host_copy_to "{tmp_path}/src" local "{tmp_path}/dst"', tmp_path)
        assert res.returncode == 0, res.stderr
        assert (tmp_path / "dst").read_text() == "payload"

    def test_copy_from_a_local_host_is_a_plain_copy(self, tmp_path: Path):
        (tmp_path / "remote-side").write_text("payload", encoding="utf-8")
        res = _run(f'host_copy_from local "{tmp_path}/remote-side" "{tmp_path}/here"', tmp_path)
        assert res.returncode == 0, res.stderr
        assert (tmp_path / "here").read_text() == "payload"

    def test_dry_run_copies_are_traced_without_scp(self, tmp_path: Path):
        res = _run("DEPLOY_DRY_RUN=true host_copy_to /a local /b", tmp_path)
        assert "DRY-RUN copy /a -> local:/b" in res.stdout
        assert "scp" not in res.stdout

    def test_dry_run_still_traces_scp_for_a_remote_host(self, tmp_path: Path):
        res = _run("DEPLOY_DRY_RUN=true host_copy_to /a w1.example.com /b", tmp_path)
        assert "DRY-RUN scp /a -> root@w1.example.com:/b" in res.stdout


class TestHelpersDoNotLeak:
    def test_assert_sqlite_artifact_populated_declares_its_locals(self):
        """It was the one helper here with no `local` line, so it published
        artifact/source_db/counts/got/want into scripts/backup.sh."""
        body = COMMON_SH.read_text(encoding="utf-8")
        start = body.index("assert_sqlite_artifact_populated() {")
        end = body.index("\n}", start)
        assert "local artifact source_db counts got want" in body[start:end]

    @pytest.mark.parametrize(
        "helper",
        [
            "deploy_env_default",
            "deploy_env_load",
            "require_cmd",
            "host_exec",
            "host_copy_to",
            "host_copy_from",
        ],
    )
    def test_every_config_helper_declares_locals(self, helper: str):
        body = COMMON_SH.read_text(encoding="utf-8")
        start = body.index(f"{helper}() {{")
        end = body.index("\n}", start)
        assert "local " in body[start:end], f"{helper} sets variables without declaring them local"


class TestOsReleaseVerdict:
    """The shell half of the tested-OS report; app/system_checks.py::check_host_os is
    the other. Both warn and continue — refusing an untested distro turns a
    probably-fine deployment into a support ticket."""

    def test_a_tested_distro_says_tested(self, tmp_path: Path):
        release = 'ID=ubuntu\\nPRETTY_NAME="Ubuntu 24.04.1 LTS"'
        res = _run(f"os_release_verdict host \"$(printf '{release}')\"", tmp_path)
        assert "Ubuntu 24.04.1 LTS (tested)" in res.stdout
        assert res.stderr == ""

    def test_a_debian_derivative_is_not_a_warning(self, tmp_path: Path):
        release = 'ID=linuxmint\\nID_LIKE="ubuntu debian"\\nPRETTY_NAME="Linux Mint 22"'
        res = _run(f"os_release_verdict host \"$(printf '{release}')\"", tmp_path)
        assert "Debian-like" in res.stdout
        assert res.stderr == ""

    def test_an_untested_distro_warns_on_stderr_and_returns_zero(self, tmp_path: Path):
        release = 'ID=rocky\\nID_LIKE="rhel fedora"\\nPRETTY_NAME="Rocky Linux 9.4"'
        res = _run(f'os_release_verdict host "$(printf \'{release}\')"; echo "status:$?"', tmp_path)
        assert "Rocky Linux 9.4" in res.stderr
        assert "status:0" in res.stdout

    def test_an_empty_release_says_it_could_not_confirm(self, tmp_path: Path):
        res = _run('os_release_verdict host ""; echo "status:$?"', tmp_path)
        assert "could not read /etc/os-release" in res.stderr
        assert "status:0" in res.stdout

    def test_a_release_with_no_pretty_name_falls_back_to_name(self, tmp_path: Path):
        release = 'ID=rocky\\nNAME="Rocky Linux"'
        res = _run(f"os_release_verdict host \"$(printf '{release}')\"", tmp_path)
        assert "Rocky Linux" in res.stderr

    def test_fields_are_unquoted_and_a_missing_one_is_empty(self, tmp_path: Path):
        release = 'ID="debian"\\nVERSION_CODENAME=bookworm'
        body = (
            f"r=\"$(printf '{release}')\"; "
            'echo "[$(os_release_field ID "$r")]"; '
            'echo "[$(os_release_field VERSION_CODENAME "$r")]"; '
            'echo "[$(os_release_field UBUNTU_CODENAME "$r")]"'
        )
        res = _run(body, tmp_path)
        assert "[debian]" in res.stdout
        assert "[bookworm]" in res.stdout
        assert "[]" in res.stdout


class TestForcedPtyDoesNotCorruptCapturedValues:
    """An operator whose ~/.ssh/config sets `RequestTTY yes` gets a PTY on every call,
    and a PTY rewrites the remote command's output as CRLF. So `ID=ubuntu` stops matching
    `ubuntu` and Ubuntu reports itself as "unknown Linux" — a supported OS, warned about on
    every host, on every run."""

    def test_ssh_never_asks_for_a_terminal(self, tmp_path: Path):
        res = _run('build_ssh_opts; printf "%s\\n" "${SSH_OPTS[@]}"', tmp_path)
        assert "RequestTTY=no" in res.stdout

    def test_an_identity_still_leads_the_option_list(self, tmp_path: Path):
        key = tmp_path / "id"
        key.write_text("x", encoding="utf-8")
        res = _run(f'SSH_IDENTITY={key}; build_ssh_opts; printf "%s " "${{SSH_OPTS[@]}}"', tmp_path)
        assert res.stdout.startswith(f"-i {key} ")
        assert "RequestTTY=no" in res.stdout

    def test_os_release_fields_survive_crlf(self, tmp_path: Path):
        body = 'ID=ubuntu\\r\\nPRETTY_NAME="Ubuntu 26.04 LTS"\\r\\nVERSION_CODENAME=resolute\\r\\n'
        res = _run(
            f'r=$(printf \'{body}\'); echo "[$(os_release_field ID "$r")]"; echo "[$(os_release_field PRETTY_NAME "$r")]"; echo "[$(os_release_field VERSION_CODENAME "$r")]"',
            tmp_path,
        )
        assert "[ubuntu]" in res.stdout
        assert "[Ubuntu 26.04 LTS]" in res.stdout
        assert "[resolute]" in res.stdout

    def test_a_crlf_release_is_still_recognised_as_tested(self, tmp_path: Path):
        body = 'ID=ubuntu\\r\\nPRETTY_NAME="Ubuntu 26.04 LTS"\\r\\n'
        res = _run(f"os_release_verdict host \"$(printf '{body}')\"", tmp_path)
        assert "(tested)" in res.stdout
        assert "unknown Linux" not in res.stdout
        assert res.stderr == ""

    def test_host_capture_strips_cr_and_takes_one_line(self, tmp_path: Path):
        res = _run(
            'echo "[$(host_capture local "printf \'10.0.0.7\\r\\nsecond\\r\\n\'")]"',
            tmp_path,
        )
        assert "[10.0.0.7]" in res.stdout

    def test_host_capture_is_empty_rather_than_failing(self, tmp_path: Path):
        res = _run('v=$(host_capture local "exit 3"); echo "reached:[$v]"', tmp_path)
        assert res.returncode == 0, res.stderr
        assert "reached:[]" in res.stdout


class TestAddressDiscovery:
    """`REDIS_EXPOSE` needs an address the control plane holds; a worker's DATABASE_URL
    needs one the worker can reach. Both are answerable from the hosts themselves, rather
    than left to the operator to work out."""

    @pytest.mark.parametrize("value", ["10.200.0.1", "192.168.1.5", "0.0.0.0", "255.255.255.255"])
    def test_addresses_are_accepted(self, value: str, tmp_path: Path):
        res = _run(f'is_ipv4 "{value}" && echo YES || echo no', tmp_path)
        assert "YES" in res.stdout

    @pytest.mark.parametrize("value", ["cp.example.com", "", "1.2.3", "1.2.3.4.5", "10.0.0.256", "abc", "10.0.0.1 "])
    def test_everything_else_is_rejected(self, value: str, tmp_path: Path):
        """Docker binds ports by address and refuses a name — a hostname reaching
        REDIS_EXPOSE fails the deploy at `docker compose up` with nothing pointing at
        the env file behind it."""
        res = _run(f'is_ipv4 "{value}" && echo YES || echo no', tmp_path)
        assert "no" in res.stdout

    def test_a_hosts_own_addresses_are_listed_one_per_line(self, tmp_path: Path):
        shim = tmp_path / "bin"
        shim.mkdir()
        ip = shim / "ip"
        ip.write_text("#!/bin/sh\nprintf '1: lo inet 127.0.0.1/8 scope host\\n2: eth0 inet 10.0.0.5/24 scope global\\n'\n")
        ip.chmod(0o755)
        res = _run(f'PATH="{shim}:$PATH"; host_addresses local', tmp_path)
        assert "10.0.0.5" in res.stdout


# ── The remote command reaches bash, not the login shell ─────────────────────
#
# `ssh host CMD` hands CMD to the REMOTE LOGIN SHELL. If only host_exec's local branch
# forces bash, a bash-only construct works against a `local` host and dies against every
# real one — on a host whose root shell is fish, deploy-env-push.sh's `.env` install fails
# and is reported as "Usually this is write permission", which it is not.
#
# The shim below is the seam: a fake `ssh` on PATH that records its argv and, when fish
# is installed, EXECUTES the command the way a fish-shelled host would. That turns a
# defect otherwise reachable only from a real fleet into an ordinary unit test.


def _ssh_shim(tmp_path: Path, shell: str = "bash") -> Path:
    """A fake `ssh` that logs argv, then runs the command under `shell` the way sshd
    would: everything after the target is joined with spaces and handed to the shell."""
    d = tmp_path / "shimbin"
    d.mkdir(exist_ok=True)
    (d / "ssh").write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{tmp_path}/ssh-argv.log"\n'
        'args=(); for a in "$@"; do args+=("$a"); done\n'
        "# drop option words and the target; what remains is the remote command\n"
        "i=0; while [ $i -lt ${#args[@]} ]; do\n"
        '  case "${args[$i]}" in\n'
        "    -o|-i|-p) i=$((i+2)); continue ;;\n"
        "    -*) i=$((i+1)); continue ;;\n"
        "    *) break ;;\n"
        "  esac\n"
        "done\n"
        "i=$((i+1))  # skip the target\n"
        'rest=("${args[@]:$i}")\n'
        f'exec {shell} -c "$(printf "%s " "${{rest[@]}}")"\n',
        encoding="utf-8",
    )
    (d / "ssh").chmod(0o755)
    return d


def _with_shim(body: str, tmp_path: Path, shell: str = "bash") -> subprocess.CompletedProcess:
    shim = _ssh_shim(tmp_path, shell)
    script = f'set -euo pipefail\nexport PATH="{shim}:$PATH"\n. "{COMMON_SH}"\nbuild_ssh_opts\n{body}\n'
    return subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True)


class TestRemoteCommandsRunUnderBash:
    def test_the_remote_branch_wraps_the_command_in_bash(self, tmp_path: Path):
        """Structural, so it runs everywhere including CI where fish is absent."""
        _with_shim('host_exec somehost "echo hi" || true', tmp_path)
        argv = (tmp_path / "ssh-argv.log").read_text(encoding="utf-8")
        assert " bash -c " in argv, f"remote command was not wrapped in bash -c: {argv}"

    @pytest.mark.skipif(shutil.which("fish") is None, reason="fish not installed")
    def test_the_env_push_install_line_survives_a_fish_login_shell(self, tmp_path: Path):
        """Byte-for-byte the construct that fails under a fish login shell. fish rejects a
        bare `rc=$?` outright — "Unsupported use of '='" — and the whole command line is
        refused before anything runs, so the .env is never installed."""
        target = tmp_path / "dest"
        cmd = f"mkdir -p {target} 2>/dev/null && install -m 600 /etc/hosts {target}/.env 2>/dev/null || {{ echo fallback; }}; rc=$?; rm -f /tmp/nothing-here; exit $rc"
        res = _with_shim(f"host_exec somehost {shlex.quote(cmd)}", tmp_path, shell="fish")
        assert res.returncode == 0, res.stdout + res.stderr
        assert "Unsupported use of" not in res.stderr
        assert (target / ".env").exists(), "the .env was not installed under a fish login shell"

    @pytest.mark.skipif(shutil.which("fish") is None, reason="fish not installed")
    def test_an_embedded_apostrophe_survives_the_quoting(self, tmp_path: Path):
        """shquote closes-escapes-reopens; fish reads those same bytes as quote,
        literal-quote, quote. If that ever diverges, this is where it shows."""
        res = _with_shim("""host_exec somehost "printf '%s\\n' \\"it's fine\\"" """, tmp_path, shell="fish")
        assert "it's fine" in res.stdout, res.stdout + res.stderr

    def test_a_heredoc_caller_still_reaches_the_inner_bash(self, tmp_path: Path):
        """The 12 `host_exec h bash -s <<EOS` sites in deploy-multiserver.sh depend on
        stdin reaching the remote command. Wrapping in bash -c must not consume it —
        which is also why neither -n nor </dev/null belongs in SSH_OPTS."""
        res = _with_shim("host_exec somehost bash -s <<'EOS'\necho heredoc-arrived\nEOS", tmp_path)
        assert "heredoc-arrived" in res.stdout, res.stdout + res.stderr

    def test_a_piped_stdin_still_reaches_the_remote_command(self, tmp_path: Path):
        """deploy-fleet.sh pipes the basic-auth password into `caddy hash-password`
        through host_exec. Closing stdin would make it read EOF and the capture come
        back empty, which the caller reports as a different failure entirely."""
        res = _with_shim("printf 'secret\\n' | host_exec somehost 'cat'", tmp_path)
        assert "secret" in res.stdout, res.stdout + res.stderr


class TestSshOptions:
    def test_the_operator_ssh_config_cannot_break_the_deploy(self, tmp_path: Path):
        """Each of these neutralises something a normal ~/.ssh/config may set:
        RemoteCommand makes ssh refuse a command outright, RequestTTY yields CRLF that
        breaks every captured value, and without ServerAlive* a session that connects
        and then stalls waits forever."""
        res = _run('build_ssh_opts; printf "%s\\n" "${SSH_OPTS[@]}"', tmp_path)
        assert res.returncode == 0, res.stderr
        for opt in (
            "BatchMode=yes",
            "RequestTTY=no",
            "RemoteCommand=none",
            "ConnectTimeout=10",
            "ServerAliveInterval=15",
            "StrictHostKeyChecking=accept-new",
        ):
            assert opt in res.stdout, f"{opt} missing from SSH_OPTS"

    def test_the_control_path_stays_inside_the_socket_length_limit(self, tmp_path: Path):
        """A unix socket path is capped near 104 bytes. $TMPDIR on macOS is a ~50-char
        /var/folders/... path, and with the 40-char %C hash ssh then fails EVERY
        connection with "ControlPath too long" — measured, and it took a whole fleet
        offline for one run."""
        res = _run('build_ssh_opts; printf "%s\\n" "${SSH_OPTS[@]}"', tmp_path)
        paths = [ln.split("=", 1)[1] for ln in res.stdout.splitlines() if ln.startswith("ControlPath=")]
        if paths:  # absent is legitimate — that is the documented fallback
            resolved = paths[0].replace("%C", "0" * 40)
            assert len(resolved) < 104, f"ControlPath would overrun the socket limit: {resolved}"


class TestHostNumber:
    def test_an_unmeasurable_value_is_a_question_mark_not_an_empty_string(self, tmp_path: Path):
        """The distinction the preflight depends on. An empty capture skips a
        `[ -n "$v" ] && [ "$v" -lt LIMIT ]` guard entirely, so the disk check would print
        "OK   disk space" for a host it never successfully asked."""
        res = _run('v=$(host_number local "printf \'\'"); echo "[$v]"', tmp_path)
        assert "[?]" in res.stdout, res.stdout + res.stderr

    def test_a_non_numeric_answer_is_also_a_question_mark(self, tmp_path: Path):
        res = _run('v=$(host_number local "echo not-a-number"); echo "[$v]"', tmp_path)
        assert "[?]" in res.stdout

    def test_a_real_number_comes_back_clean(self, tmp_path: Path):
        res = _run('v=$(host_number local "echo 4096"); echo "[$v]"', tmp_path)
        assert "[4096]" in res.stdout


class TestHostsHaveLocal:
    """The `local` sentinel is an ENTRY, never a substring.

    `case "$DEPLOY_HOSTS" in *local*)` matched `mylocalbox.example.com`, so
    deploy-fleet.sh skipped its ssh/scp requirement for a fleet that needed both — and
    the failure then surfaced several steps later as `ssh: command not found`.
    """

    @pytest.mark.parametrize(
        "hosts",
        [
            "local",
            "local,w1.example.com",
            "cp.example.com,local",
            "cp.example.com,local,w2.example.com",
            " local , w1.example.com ",
        ],
    )
    def test_an_entry_that_is_local_is_found(self, hosts: str, tmp_path: Path):
        r = _run(f"hosts_have_local {shlex.quote(hosts)} && echo YES || echo NO", tmp_path)
        assert r.stdout.strip() == "YES", r.stderr

    @pytest.mark.parametrize(
        "hosts",
        [
            "",
            "mylocalbox.example.com",
            "cp.example.com,mylocalbox.example.com",
            "localhost",
            "cp.local",
            "user@local.example.com",
            "notlocal",
            "local.example.com",
        ],
    )
    def test_a_host_merely_containing_local_is_not(self, hosts: str, tmp_path: Path):
        r = _run(f"hosts_have_local {shlex.quote(hosts)} && echo YES || echo NO", tmp_path)
        assert r.stdout.strip() == "NO", r.stderr

    def test_it_agrees_with_is_local_host_on_single_entries(self, tmp_path: Path):
        """One predicate for a list, one for an entry, and they must not disagree —
        deploy-multiserver.sh loops with is_local_host while deploy-fleet.sh asks
        about the whole list."""
        body = 'for h in local localhost mylocalbox notlocal; do\n  a=no; b=no\n  is_local_host "$h" && a=yes\n  hosts_have_local "$h" && b=yes\n  echo "$h $a $b"\ndone'
        r = _run(body, tmp_path)
        assert r.returncode == 0, r.stderr
        for line in r.stdout.strip().splitlines():
            host, entry, in_list = line.split()
            assert entry == in_list, f"{host}: is_local_host={entry} hosts_have_local={in_list}"


class TestLibraryResolutionWithoutBash:
    """`common.sh` pulls in three sibling libraries, and how it finds them matters.

    Not `dirname "${BASH_SOURCE[0]}"`. BASH_SOURCE is a bashism, and go-task runs every
    `cmds:` line under mvdan/sh, which does not provide it — so for the tasks that do
    `. scripts/lib/common.sh` directly it expands to nothing, `dirname ""` gives `.`, and
    verdict.sh / install.sh / fleet_record.sh are looked for in the repo root and not found.

    It fails SILENTLY: a failed `source` does not stop the shell, so `task env:diff` would
    print three "no such file" lines in the middle of a live upgrade and carry on without
    the helpers.
    """

    @pytest.mark.skipif(shutil.which("task") is None, reason="go-task not installed")
    def test_a_task_that_sources_the_library_gets_all_of_it(self, tmp_path: Path):
        """Driven through go-task, because that is where the failure lives.

        Under bash this cannot fail: `unset BASH_SOURCE` is undone the moment a file is
        sourced, since bash repopulates it. mvdan/sh — go-task's built-in shell — never
        sets it at all, which is the whole difference, so the reproduction has to be a real
        task. It is skipped where go-task is absent; the shape assertion below is what
        holds the line unconditionally.
        """
        taskfile = tmp_path / "Taskfile.yml"
        taskfile.write_text(
            "version: '3'\n"
            "tasks:\n"
            "  probe:\n"
            f"    dir: {PROJECT_ROOT}\n"
            "    cmds:\n"
            "      - . scripts/lib/common.sh && for f in v_pass stage_dir fleet_hosts"
            ' snapshot_excludes; do type "$f" >/dev/null 2>&1 && echo "$f ok" ||'
            ' echo "$f MISSING"; done\n',
            encoding="utf-8",
        )
        r = subprocess.run(
            ["task", "--taskfile", str(taskfile), "probe"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "MISSING" not in r.stdout, r.stdout + r.stderr
        assert "no such file" not in r.stderr, "the sibling libraries were looked for in the wrong directory:\n" + r.stderr
        assert r.stdout.count(" ok") == 4, r.stdout + r.stderr

    def test_nothing_in_the_library_resolves_a_path_through_bash_source(self):
        """The shape, because the behavioural test above cannot see a NEW use added later —
        and a new one would fail the same silent way."""
        text = COMMON_SH.read_text(encoding="utf-8")
        code = [line for line in text.splitlines() if not line.lstrip().startswith("#") and "BASH_SOURCE" in line]
        offenders = [line.strip() for line in code if "BASH_SOURCE[0]:-" not in line]
        assert not offenders, f"BASH_SOURCE without a fallback: go-task's shell does not set it, and the failure is a silent one. {offenders}"


class TestArtifactIntegrity:
    """There was none. A release archive was fetched with `curl -fL` and extracted, and the
    only thing between a host and someone else's bytes was TLS to the release server —
    which an operator carrying a file on a USB stick does not have at all.

    What this does and does not prove is worth being exact about, because overstating it is
    worse than having nothing: it catches a truncated or corrupted transfer, and it catches
    tampering ONLY if the checksum reached you by a path the tamperer did not control. A
    `.sha256` beside the archive on the same server proves the download completed. Signing
    is the answer to the other half, and this is not it.
    """

    def test_a_matching_digest_passes(self, tmp_path: Path):
        f = tmp_path / "artifact.7z"
        f.write_bytes(b"the release")
        r = _run(f'd=$(file_sha256 "{f}"); verify_sha256 "{f}" "$d"', tmp_path)
        assert r.returncode == 0, r.stderr
        assert "sha256 OK" in r.stdout

    def test_a_mismatched_digest_fails_and_shows_both(self, tmp_path: Path):
        """An operator has to be able to tell a corrupted download from the wrong file."""
        f = tmp_path / "artifact.7z"
        f.write_bytes(b"the release")
        r = _run(f'verify_sha256 "{f}" deadbeef || echo REJECTED', tmp_path)
        assert "REJECTED" in r.stdout
        assert "MISMATCH" in r.stderr + r.stdout
        assert "expected deadbeef" in r.stdout
        assert "got      " in r.stdout

    def test_a_release_that_publishes_no_checksum_is_not_refused(self, tmp_path: Path):
        """Releases cut before checksums existed have none, and refusing those would break
        every older pin — including the documented way to go back a version. It says the
        download was not checked, which is true, and continues."""
        f = tmp_path / "artifact.7z"
        f.write_bytes(b"the release")
        # A curl that finds no .sha256, which is what an older release looks like.
        shim = tmp_path / "shim"
        shim.mkdir()
        (shim / "curl").write_text("#!/bin/sh\nexit 22\n")
        (shim / "curl").chmod(0o755)
        r = subprocess.run(
            ["bash", "-c", f'export PATH="{shim}:$PATH"; . "{COMMON_SH}"; verify_downloaded_artifact "{f}" https://example/x.7z'],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert "not checked" in r.stdout

    def test_the_digest_helper_has_one_implementation(self):
        """sha256sum on Linux, shasum on macOS. Two copies of that branch is two places to
        get it wrong, and scripts/bundle.sh had the second."""
        for script in sorted((PROJECT_ROOT / "scripts").glob("*.sh")):
            text = script.read_text(encoding="utf-8")
            code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
            assert "shasum -a 256" not in code, f"{script.name} re-implements the digest; use common.sh::file_sha256"


class TestTheColourPalette:
    """One gate, resolved at source time, for every script that prints.

    Inline ANSI in the logging helpers would send escapes into pipes, redirected log files
    and CI transcripts unconditionally. This is where the rule lives — a TTY, no NO_COLOR,
    TERM not dumb — and scripts/cli_color.py
    reads the answer out of LT_COLOR rather than asking isatty() a second time, from a
    subprocess that cannot see the caller's redirection.
    """

    def test_the_palette_is_defined_before_verdict_sh_is_sourced(self):
        """verdict.sh renders with these and every deploy script runs under `set -u`, so
        sourcing it above the palette makes the FIRST verdict line abort the run with
        "unbound variable" — every check, on every host, in one move."""
        text = COMMON_SH.read_text(encoding="utf-8")
        assert text.index("C_GREEN=") < text.index('"${_LT_LIB_DIR}/verdict.sh"'), "the palette must be in scope before verdict.sh uses it"

    def test_nothing_reintroduces_a_raw_escape(self, tmp_path: Path):
        """An inline \\033 is a colour nothing can turn off — which is what the gate exists
        to prevent, arriving one printf at a time."""
        offenders = []
        for script in [*sorted((PROJECT_ROOT / "scripts").glob("*.sh")), *sorted((PROJECT_ROOT / "scripts" / "lib").glob("*.sh"))]:
            for n, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                # The palette itself is the one place the escapes are allowed to appear.
                if "\\033[" in line and not line.lstrip().startswith("C_"):
                    offenders.append(f"{script.name}:{n}")
        assert not offenders, f"raw ANSI outside the palette: {offenders}"

    @pytest.mark.parametrize(
        ("env", "expected"),
        [({}, "never"), ({"NO_COLOR": "1"}, "never"), ({"TERM": "dumb"}, "never")],
    )
    def test_a_pipe_is_never_coloured(self, env, expected):
        """capture_output is a pipe, which is also what the ~500 stdout assertions across
        tests/test_deploy_*.py run under — so this is what keeps them matching plain text."""
        r = subprocess.run(
            ["bash", "-c", f'. "{COMMON_SH}"; printf "%s" "$LT_COLOR"'],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, **env},
        )
        assert r.stdout == expected

    def test_a_terminal_is_coloured(self):
        """The other direction, on a real pty rather than an assumption about one."""
        import pty

        env = {key: value for key, value in os.environ.items() if key != "NO_COLOR"}
        pid, fd = pty.fork()
        if pid == 0:
            os.execve("/bin/bash", ["bash", "-c", f'. "{COMMON_SH}"; printf "%s" "$LT_COLOR"'], {**env, "TERM": "xterm"})
        out = bytearray()
        try:
            while chunk := os.read(fd, 1024):
                out.extend(chunk)
        except OSError:
            pass
        os.waitpid(pid, 0)
        assert b"always" in bytes(out)


class TestTheOutputVocabulary:
    """One set of markers for every script, not one per script.

    `task upgrade` puts several scripts' output in one terminal session, and private
    dialects side by side — bare `echo`, `✓`/`→`, `=== x ===` — read as different tools.
    """

    def _emit(self, body: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", "-c", f'. "{COMMON_SH}"; {body}'],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "NO_COLOR": "1"},
        )

    def test_ok_marks_a_step_that_finished(self):
        """`info` says what is being attempted; `ok` says it worked. In a script that
        prints a dozen lines before it can fail, that is the difference between "this is
        where it hung" and "this is where it got to"."""
        r = self._emit('ok "docker compose build"')
        assert r.stdout == "\u2713 docker compose build\n"

    def test_note_indents_its_continuation_under_the_label(self):
        """package.sh wrote these by hand with six literal spaces per line, which is how
        two of its four advisory blocks ended up at seven."""
        r = self._emit('note "an advisory" "first detail" "second detail"')
        assert r.stdout == "NOTE: an advisory\n      first detail\n      second detail\n"

    def test_a_note_is_not_a_warning_and_stays_on_stdout(self):
        """`warn` goes to stderr and is the thing an operator is trained to act on. An
        advisory printed as WARN teaches people to ignore WARN."""
        r = self._emit('note "nothing is wrong here"')
        assert "nothing is wrong here" in r.stdout
        assert r.stderr == ""

    def test_the_banner_rule_is_one_string(self):
        """Three scripts had their own copy at three widths. The rule is decoration, so
        nothing detects a drift in it — you only notice when two of them are on screen."""
        r = self._emit("banner_open; banner_close")
        lines = r.stdout.split("\n")
        assert lines[0] == "", "the banner opens with a blank line, so it separates from the run above it"
        assert lines[1] == lines[2], "both rules are the same string"
        assert set(lines[1]) == {"\u2550"}

    def test_kv_pads_to_one_width_and_emphasises_the_value(self):
        """The URL and the admin account are the only reason the banner exists; they used
        to print in the same grey as the prose around them."""
        r = self._emit('kv "Admin login" "admin@example.com"')
        assert r.stdout == "  Admin login:           admin@example.com\n"

    def test_the_new_markers_are_coloured_on_a_terminal(self):
        """The palette gate covers them too — asserted on a real pty, not on an assumption
        about one. Plain output above is what the ~500 capture_output assertions read."""
        import pty

        env = {key: value for key, value in os.environ.items() if key != "NO_COLOR"}
        pid, fd = pty.fork()
        if pid == 0:
            body = 'ok "built"; note "advisory"; banner_open; kv "URL" "https://x"; banner_close'
            os.execve("/bin/bash", ["bash", "-c", f'. "{COMMON_SH}"; {body}'], {**env, "TERM": "xterm"})
        out = bytearray()
        try:
            while chunk := os.read(fd, 4096):
                out.extend(chunk)
        except OSError:
            pass
        os.waitpid(pid, 0)
        text = bytes(out).decode()
        assert "\033[32m" in text, "ok is green"
        assert "\033[36m" in text, "note and the banner rule are cyan"
        assert "\033[1mhttps://x\033[0m" in text, "kv puts its value through value()"

    def test_no_script_hand_rolls_a_label_the_library_owns(self):
        """The analogue of the raw-escape guard, and for the same reason: the treatment
        erodes one `echo` at a time. `ERROR:` written by hand also lands on STDOUT, where
        `die` puts it on stderr — so a caller redirecting stdout to a log loses it.

        HEREDOC BODIES ARE EXEMPT, and that exemption is the load-bearing half. Eleven of
        these labels live inside `host_exec "$host" ... bash -s <<'BOOTSTRAP'` blocks in
        deploy-bootstrap.sh and deploy-multiserver.sh, which run on a REMOTE host under a
        bare bash that never sourced common.sh. `warn`/`die` do not exist there, and the
        failure is quiet in the worst way: several of those sites are `|| echo "WARN: …"`
        trailers, so `warn: command not found` would be swallowed by the `||` and the
        bootstrap would report success having skipped the thing it was warning about.

        Only the leading label is matched. A line that mentions ERROR: inside prose, or
        greps for it in a subprocess's output, is not printing one.
        """
        label = re.compile(r"""echo\s+["'](ERROR|WARN|NOTE):""")
        # `<<EOS`, `<<'EOS'`, `<<-EOS` — the delimiter is what closes the body.
        opener = re.compile(r"<<-?\s*'?([A-Za-z_][A-Za-z0-9_]*)'?\s*$")
        offenders = []
        for script in [*sorted((PROJECT_ROOT / "scripts").glob("*.sh")), *sorted((PROJECT_ROOT / "scripts" / "lib").glob("*.sh"))]:
            delimiter = None
            for n, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
                if delimiter is not None:
                    if line.strip() == delimiter:
                        delimiter = None
                    continue
                m = opener.search(line)
                if m:
                    delimiter = m.group(1)
                    continue
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                if label.match(stripped):
                    offenders.append(f"{script.name}:{n}")
        assert not offenders, f"use die/warn/note rather than echoing the label: {offenders}"

    def test_the_heredoc_exemption_is_not_a_hole_in_the_local_scripts(self):
        """The exemption above is scoped by construction: it only ever applies inside a
        heredoc, and every heredoc in this tree that carries one of these labels is piped
        to a remote shell. Assert that, so the exemption cannot quietly start covering a
        local block someone appends to one of these files.
        """
        remote = re.compile(r"(host_exec|remote|cp_exec)\b.*bash -s")
        for name in ("deploy-bootstrap.sh", "deploy-multiserver.sh"):
            lines = (PROJECT_ROOT / "scripts" / name).read_text(encoding="utf-8").splitlines()
            opener = re.compile(r"<<-?\s*'?([A-Za-z_][A-Za-z0-9_]*)'?\s*$")
            delimiter = None
            start = 0
            for n, line in enumerate(lines, 1):
                if delimiter is None:
                    m = opener.search(line)
                    if m:
                        delimiter, start = m.group(1), n
                    continue
                if line.strip() != delimiter:
                    continue
                body = "\n".join(lines[start:n])
                if re.search(r"""echo\s+["'](ERROR|WARN|NOTE):""", body):
                    assert remote.search(lines[start - 1]), f"{name}:{start}: a LOCAL heredoc hand-rolls a label the library owns"
                delimiter = None


def _docker_shim(tmp_path: Path, ids: list[str]) -> Path:
    """A `docker` that answers `ps -q` the way Compose really does.

    `docker compose ps` is scoped to the PROJECT, not to the file it was handed: both
    invocations run in the same directory, resolve the same project name, and list the
    SAME containers. Measured against Compose v5.1.2 — a project with two running services
    answers `2` to `ps -q` through a compose file that declares neither of them. A shim
    that narrowed by file would model a Compose that does not exist and would pass with
    the double-count bug present.
    """
    d = tmp_path / "dockerbin"
    d.mkdir(exist_ok=True)
    emit = "\n".join(f"    echo {cid}" for cid in ids) or "    true"
    (d / "docker").write_text(
        f'#!/usr/bin/env bash\ncase "$*" in\n  *"ps -q"*)\n{emit}\n    ;;\n  *) echo "STUB docker $*" ;;\nesac\n',
        encoding="utf-8",
    )
    (d / "docker").chmod(0o755)
    return d


class TestComposeRunningCount:
    """One pipeline counts a deployment's containers, and it counts each one once.

    Three call sites had their own copy — host_installed_release, deploy-preflight.sh's
    plan verdict, upgrade.sh::_local_running_containers — and all three probed both compose
    files without deduping. Because `ps` is project-scoped, that counted every container
    twice: `task fleet` reported 18 for a nine-container control plane and 2 for a
    one-container worker, and `upgrade:plan` printed the same doubled number.
    """

    def _installed_release(self, tmp_path: Path, ids: list[str]) -> str:
        shim = _docker_shim(tmp_path, ids)
        (tmp_path / "VERSION").write_text("version: 9.9.9\n", encoding="utf-8")
        script = f'set -euo pipefail\nexport PATH="{shim}:$PATH"\n. "{COMMON_SH}"\nhost_installed_release local "{tmp_path}"\n'
        r = subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        return r.stdout

    def test_each_container_is_counted_once(self, tmp_path: Path):
        assert self._installed_release(tmp_path, ["cid1", "cid2", "cid3"]) == "9.9.9|3"

    def test_nothing_running_is_a_single_zero(self, tmp_path: Path):
        """`grep -c .` prints 0 AND exits 1, so a caller that supplies its own fallback
        appends a SECOND zero and the field arrives as "0\\n0" — which is not a number and
        makes every numeric caller read `?`."""
        assert self._installed_release(tmp_path, []) == "9.9.9|0"

    def test_probing_both_compose_files_survives(self, tmp_path: Path):
        """The dedupe must not be achieved by dropping the worker file: `docker compose
        ps -q` alone reads docker-compose.yml, and a worker-only host would then report
        zero containers however healthy it is — which is why the second probe exists."""
        r = subprocess.run(
            ["bash", "-c", f'. "{COMMON_SH}"; compose_running_count_cmd'],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert "docker-compose.worker.yml" in r.stdout, r.stdout + r.stderr
        assert "sort -u" in r.stdout, "the dedupe is what makes probing both files safe"

    def test_no_script_counts_containers_by_hand(self):
        """The one-reader guard. Existence checks (`ps ... | grep -q .`) are a different
        question and stay where they are — this is only about counting."""
        offenders = []
        scripts = [*sorted((PROJECT_ROOT / "scripts").glob("*.sh")), *sorted((PROJECT_ROOT / "scripts" / "lib").glob("*.sh"))]
        for script in scripts:
            in_helper = False
            for n, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
                if line.startswith("compose_running_count_cmd()"):
                    in_helper = True  # its own body is the one place the pipeline is written
                elif in_helper and line.startswith("}"):
                    in_helper = False
                if in_helper or line.lstrip().startswith("#"):
                    continue
                if "docker compose" in line and "ps -q" in line and "grep -c" in line:
                    offenders.append(f"{script.name}:{n}")
        assert not offenders, f"container counting must go through common.sh::compose_running_count_cmd: {offenders}"
