"""`./logstotal` and scripts/lib/task_bin.sh: which go-task runs the Taskfile.

Real bash against a throwaway installation: the wrapper and task_bin.sh are copied into
tmp_path and the pin is rewritten to name fake go-task tarballs built here, so nothing is
downloaded and nothing depends on what go-task the machine running the tests has.

PATH is hermetic, not prefixed: a prefix can shadow a binary but never hide one, so a
developer's Homebrew `task` would answer every "nothing on PATH" case and turn it into a
test of a different branch. The sandbox gets symlinks to exactly the tools the wrapper
needs — bash included, or `#!/usr/bin/env bash` finds nothing.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
WRAPPER = REPO_ROOT / "logstotal"
TASK_BIN = REPO_ROOT / "scripts" / "lib" / "task_bin.sh"

PIN = "3.60.0"
FLOOR = "3.39.0"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

#: Everything the wrapper and task_bin.sh call. `perl` because macOS's shasum is a perl script.
_SYSTEM_TOOLS = [
    "bash",
    "sh",
    "env",
    "uname",
    "tar",
    "gzip",
    "mktemp",
    "mkdir",
    "chmod",
    "mv",
    "rm",
    "cut",
    "dirname",
    "cat",
    "cp",
    "sha256sum",
    "shasum",
    "perl",
    "grep",
    "sed",
    "head",
]


def _platform() -> str:
    os_name = {"Linux": "linux", "Darwin": "darwin"}.get(platform.system())
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if not os_name or not arch:
        pytest.skip(f"no go-task asset naming for {platform.system()} {platform.machine()}")
    return f"{os_name}_{arch}"


def _fake_task(version: str, *, go_task: bool = True) -> str:
    """A `task` that answers like go-task (or like Taskwarrior) and reports how it ran."""
    help_text = "Usage: task [flags...] [task...]\\n  -t, --taskfile string   choose which Taskfile to run" if go_task else "Usage: task <filter> <command>"
    return (
        "#!/usr/bin/env bash\n"
        'case "${1:-}" in\n'
        f"  --help) printf '{help_text}\\n'; exit 0 ;;\n"
        f"  --version) echo {version}; exit 0 ;;\n"
        "esac\n"
        f'echo "FAKE-TASK {version} cwd=$(pwd) args=$*"\n'
    )


def _tarball(path: Path, version: str) -> str:
    """Write an upstream-shaped tarball (a `task` member at the top) and return its sha256."""
    body = _fake_task(version).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("task")
        info.size = len(body)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(body))
        for extra in ("LICENSE", "README.md"):
            info = tarfile.TarInfo(extra)
            info.size = 0
            tar.addfile(info, io.BytesIO(b""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return hashlib.sha256(buf.getvalue()).hexdigest()


class Install:
    """A copy of the wrapper with its pin pointed at fake tarballs, and a sealed PATH."""

    def __init__(self, tmp_path: Path, *, bundled_platforms: tuple[str, ...] | None = None):
        self.tmp = tmp_path
        self.root = tmp_path / "install"
        self.platform = _platform()
        (self.root / "scripts" / "lib").mkdir(parents=True)
        shutil.copy2(WRAPPER, self.root / "logstotal")
        # The artefacts a download would fetch, keyed by upstream file name.
        self.served = tmp_path / "served"
        self.served.mkdir()
        other = "linux_arm64" if self.platform != "linux_arm64" else "linux_amd64"
        self.sums = {p: _tarball(self.served / f"task_{p}.tar.gz", PIN) for p in {self.platform, other}}
        self.bundled = bundled_platforms or (self.platform, other)
        self._write_task_bin()
        self.sysbin = tmp_path / "sysbin"
        self.sysbin.mkdir()
        for tool in _SYSTEM_TOOLS:
            found = shutil.which(tool)
            if found:
                (self.sysbin / tool).symlink_to(found)
        self.extra = tmp_path / "extra"
        self.extra.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()

    def _write_task_bin(self) -> None:
        src = TASK_BIN.read_text(encoding="utf-8")
        src = re.sub(r"^LT_TASK_VERSION=.*$", f"LT_TASK_VERSION={PIN}", src, count=1, flags=re.M)
        src = re.sub(r"^LT_TASK_URL_BASE=.*$", "LT_TASK_URL_BASE=https://example.invalid/go-task", src, count=1, flags=re.M)
        src = re.sub(r"^LT_TASK_BUNDLED_PLATFORMS=.*$", f'LT_TASK_BUNDLED_PLATFORMS="{" ".join(self.bundled)}"', src, count=1, flags=re.M)
        pins = "".join(f"    {p}) echo {s} ;;\n" for p, s in self.sums.items())
        src, n = re.subn(r"(lt_task_sha256_pin\(\) \{\n  case \"\$1\" in\n)(?:    [a-z0-9_]+\) echo [0-9a-f]{64} ;;\n)+", lambda m: m.group(1) + pins, src)
        assert n == 1, "the pin table in task_bin.sh changed shape; update this fixture"
        (self.root / "scripts" / "lib" / "task_bin.sh").write_text(src, encoding="utf-8")

    def bundle(self, *, tamper: bool = False) -> Path:
        """Put this platform's tarball where a release archive carries it."""
        dest = self.root / "tools" / "go-task" / f"task_{self.platform}.tar.gz"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.served / f"task_{self.platform}.tar.gz", dest)
        if tamper:
            with dest.open("ab") as fh:
                fh.write(b"tampered")
        return dest

    def on_path(self, name: str, version: str, *, go_task: bool = True) -> Path:
        tool = self.extra / name
        tool.write_text(_fake_task(version, go_task=go_task))
        tool.chmod(0o755)
        return tool

    def online(self, *, tamper: bool = False) -> None:
        """A `curl` that serves the fake release assets, as `-o DEST URL`."""
        corrupt = 'printf tampered >> "$dest"\n' if tamper else ""
        curl = self.extra / "curl"
        curl.write_text(
            "#!/usr/bin/env bash\n"
            'dest=""; url=""\n'
            'while [ $# -gt 0 ]; do case "$1" in -o) dest=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac; done\n'
            f'echo "$url" >> "{self.tmp}/downloads.log"\n'
            f'src="{self.served}/${{url##*/}}"\n'
            '[ -f "$src" ] || exit 22\n'
            'cp "$src" "$dest"\n' + corrupt
        )
        curl.chmod(0o755)

    def run(self, *args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        full = {
            "PATH": f"{self.extra}{os.pathsep}{self.sysbin}",
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
        }
        full.update(env or {})
        return subprocess.run(
            [str(self.sysbin / "bash"), str(self.root / "logstotal"), *args],
            cwd=cwd or self.root,
            env=full,
            capture_output=True,
            text=True,
            check=False,
        )

    def downloads(self) -> list[str]:
        log = self.tmp / "downloads.log"
        return log.read_text().splitlines() if log.exists() else []


@pytest.fixture()
def install(tmp_path: Path) -> Install:
    return Install(tmp_path)


# ── Where go-task comes from ─────────────────────────────────────────────────


def test_an_archive_install_runs_the_go_task_it_ships_even_offline(install: Install):
    """The offline case: the tarball the archive carries, with no network and no curl."""
    install.bundle()
    r = install.run("backup")
    assert r.returncode == 0, r.stderr
    assert f"FAKE-TASK {PIN}" in r.stdout
    assert (install.root / ".bin" / "task").is_file(), "the extracted copy is cached in .bin/"
    assert install.downloads() == []


def test_the_shipped_copy_wins_over_a_task_on_path(install: Install):
    """An installed release runs the go-task it was tested with, whatever the host has."""
    install.bundle()
    install.on_path("task", "3.99.0")
    r = install.run("version")
    assert f"FAKE-TASK {PIN}" in r.stdout, r.stdout + r.stderr


def test_a_tampered_tarball_is_refused_and_nothing_else_is_tried(install: Install):
    """A checksum mismatch is a reason to stop, never to fall through to PATH or the network."""
    install.bundle(tamper=True)
    install.on_path("task", "3.99.0")
    install.online()
    r = install.run("backup")
    assert r.returncode != 0
    assert "does not match the pinned checksum" in r.stderr
    assert "FAKE-TASK" not in r.stdout
    assert install.downloads() == []
    assert not (install.root / ".bin" / "task").exists()


def test_the_cached_copy_is_reused_and_replaced_when_the_pin_moves(install: Install):
    install.bundle()
    assert install.run("x").returncode == 0
    (install.root / "tools" / "go-task" / f"task_{install.platform}.tar.gz").unlink()
    r = install.run("x")
    assert f"FAKE-TASK {PIN}" in r.stdout, "the cached copy should serve without the tarball"
    stale = install.root / ".bin" / "task"
    stale.write_text(_fake_task("3.40.0"))
    stale.chmod(0o755)
    install.bundle()
    r = install.run("x")
    assert f"FAKE-TASK {PIN}" in r.stdout, "a cached copy of another version is not the pin"


def test_a_checkout_uses_an_installed_go_task(install: Install):
    """No tarball (a git checkout): the developer's own go-task, at or above the floor."""
    install.on_path("task", FLOOR)
    r = install.run("check")
    assert r.returncode == 0, r.stderr
    assert f"FAKE-TASK {FLOOR}" in r.stdout
    assert install.downloads() == []


def test_the_debian_binary_name_is_found(install: Install):
    install.on_path("go-task", "3.45.0")
    assert "FAKE-TASK 3.45.0" in install.run("check").stdout


def test_a_go_task_too_old_for_the_taskfile_is_passed_over(install: Install):
    install.on_path("task", "3.38.9")
    install.online()
    r = install.run("check")
    assert f"FAKE-TASK {PIN}" in r.stdout, r.stdout + r.stderr
    assert install.downloads() == [f"https://example.invalid/go-task/v{PIN}/task_{install.platform}.tar.gz"]


def test_taskwarrior_is_not_mistaken_for_go_task(install: Install):
    """On Debian and Ubuntu, `task` is as likely to be Taskwarrior — whose 3.x would pass a bare version check."""
    install.on_path("task", "3.40.0", go_task=False)
    install.online()
    r = install.run("check")
    assert f"FAKE-TASK {PIN}" in r.stdout, r.stdout + r.stderr


def test_a_download_is_verified_before_it_is_run(install: Install):
    install.online(tamper=True)
    r = install.run("check")
    assert r.returncode != 0
    assert "does not match the pinned checksum" in r.stderr
    assert "FAKE-TASK" not in r.stdout


def test_offline_with_nothing_available_says_what_to_copy_where(install: Install):
    r = install.run("check")
    assert r.returncode != 0
    assert "no curl or wget" in r.stderr
    assert f"tools/go-task/task_{install.platform}.tar.gz" in r.stderr


def test_an_explicit_binary_is_used_but_still_has_to_be_go_task(install: Install):
    good = install.on_path("mytask", "3.50.0")
    r = install.run("check", env={"LOGSTOTAL_TASK": str(good)})
    assert "FAKE-TASK 3.50.0" in r.stdout
    old = install.on_path("oldtask", "3.20.0")
    r = install.run("check", env={"LOGSTOTAL_TASK": str(old)})
    assert r.returncode != 0 and "is not go-task" in r.stderr


# ── How it runs ──────────────────────────────────────────────────────────────


def test_it_runs_from_its_own_directory_so_cron_can_call_it_by_path(install: Install, tmp_path: Path):
    install.bundle()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    r = install.run("backup", "--", "--yes", cwd=elsewhere)
    assert f"cwd={install.root}" in r.stdout, r.stdout + r.stderr
    assert "args=backup -- --yes" in r.stdout


def test_task_path_prints_the_binary_and_runs_nothing(install: Install):
    install.bundle()
    r = install.run("--task-path")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == str(install.root / ".bin" / "task")


def test_a_read_only_installation_caches_per_user(install: Install):
    install.bundle()
    (install.root / ".bin").mkdir()
    (install.root / ".bin").chmod(0o555)
    try:
        r = install.run("--task-path")
    finally:
        (install.root / ".bin").chmod(0o755)
    assert r.stdout.strip() == str(install.home / ".cache" / "logstotal" / "go-task" / "task"), r.stderr


# ── What a release archive carries ───────────────────────────────────────────


def _stage(install: Install) -> subprocess.CompletedProcess[str]:
    script = f'. "{install.root}/scripts/lib/task_bin.sh" && lt_task_stage_bundled "{install.root}"'
    env = {"PATH": f"{install.extra}{os.pathsep}{install.sysbin}", "HOME": str(install.home)}
    return subprocess.run([str(install.sysbin / "bash"), "-c", script], env=env, capture_output=True, text=True, check=False)


def test_packaging_stages_every_linux_tarball_verified(install: Install):
    install.online()
    assert _stage(install).returncode == 0
    staged = sorted(p.name for p in (install.root / "tools" / "go-task").iterdir())
    assert staged == sorted(f"task_{p}.tar.gz" for p in install.bundled)
    assert len(install.downloads()) == 2
    assert _stage(install).returncode == 0
    assert len(install.downloads()) == 2, "tarballs already present and matching are not fetched again"


def test_packaging_refuses_a_tarball_that_does_not_match(install: Install):
    install.online(tamper=True)
    r = _stage(install)
    assert r.returncode != 0
    assert not list((install.root / "tools" / "go-task").glob("*.tar.gz")), "a bad download must not be left where the archive would ship it"


# ── The real pin, and how scripts reach it ───────────────────────────────────


def test_the_shipped_pin_is_well_formed():
    src = TASK_BIN.read_text(encoding="utf-8")
    version = re.search(r"^LT_TASK_VERSION=(\S+)$", src, re.M).group(1)
    floor = re.search(r"^LT_TASK_MIN_VERSION=(\S+)$", src, re.M).group(1)
    as_tuple = lambda v: tuple(int(x) for x in v.split("."))  # noqa: E731
    assert as_tuple(version) >= as_tuple(floor)
    pins = dict(re.findall(r"^    ([a-z0-9_]+)\) echo ([0-9a-f]{64}) ;;$", src, re.M))
    assert set(pins) == {"linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"}
    bundled = re.search(r'^LT_TASK_BUNDLED_PLATFORMS="([^"]+)"$', src, re.M).group(1).split()
    assert set(bundled) <= set(pins)


def test_nested_tasks_run_on_the_go_task_running_their_parent():
    """Taskfile.yml hands its binary down; without it lt_task would reach for a PATH `task`."""
    import yaml

    root = yaml.safe_load((REPO_ROOT / "Taskfile.yml").read_text(encoding="utf-8"))
    assert (root.get("env") or {}).get("LOGSTOTAL_TASK_BIN") == "{{.TASK_EXE}}"


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        ("export LOGSTOTAL_TASK_BIN=./bin-from-parent", "parent"),
        ("printf '#!/bin/sh\\necho wrapper\\n' > logstotal; chmod +x logstotal", "wrapper"),
        ("", "path"),
    ],
    ids=["parent-go-task", "installation-wrapper", "path-task"],
)
def test_lt_task_prefers_the_parent_then_the_wrapper_then_path(tmp_path: Path, setup: str, expected: str):
    (tmp_path / "bin-from-parent").write_text("#!/bin/sh\necho parent\n")
    (tmp_path / "bin-from-parent").chmod(0o755)
    shims = tmp_path / "shims"
    shims.mkdir()
    (shims / "task").write_text("#!/bin/sh\necho path\n")
    (shims / "task").chmod(0o755)
    script = f'{setup}\n. "{REPO_ROOT}/scripts/lib/common.sh"\nlt_task version'
    env = {**os.environ, "PATH": f"{shims}{os.pathsep}{os.environ['PATH']}"}
    env.pop("LOGSTOTAL_TASK_BIN", None)
    r = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)
    assert r.stdout.strip() == expected, r.stderr


def test_no_script_runs_a_bare_task():
    """Under ./logstotal the go-task in use is not on PATH, so a script that runs `task`
    itself fails with 127 on a host without one — CI's first GitHub run found
    `task -y upgrade:rollback` in ci-deploy-smoke.sh, which every other runner forgave
    because it happened to have Task installed. Scripts go through `lt_task`."""
    call = re.compile(r"^\s*(?:[A-Z_][A-Z0-9_]*=\S+\s+)*task\s|[|;&(]\s*task\s|\$\(\s*task\s|\b(?:then|do|else|exec|time)\s+task\s")
    offenders = []
    for path in sorted([*(REPO_ROOT / "scripts").glob("*.sh"), *(REPO_ROOT / "scripts" / "lib").glob("*.sh")]):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            code = line.split(" #", 1)[0]
            if code.lstrip().startswith("#") or not call.search(code):
                continue
            # A remote command string for a host installed before the wrapper existed —
            # its own go-task, on its own PATH — is the one legitimate bare `task`.
            if "./logstotal" in code and "else task" in code:
                continue
            # lt_task's own last resort: the `task` on PATH, for a script run outside go-task.
            if path.name == "common.sh" and code.strip() == 'task "$@"':
                continue
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}")
    assert not offenders, "scripts that run go-task by name instead of lt_task:\n" + "\n".join(offenders)
