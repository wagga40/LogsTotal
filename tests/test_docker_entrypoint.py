"""Tests for Docker entrypoint env handling."""

from __future__ import annotations

import os
import socket
import subprocess
from contextlib import contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_PRINT_URLS = "import os; print(os.environ['DATABASE_URL']); print(os.environ['SYNC_DATABASE_URL'])"

# Env vars the entrypoint's DB auto-detection reads — cleared before every run so
# the developer's shell (or the repo .env, loaded by go-task's dotenv) can't leak
# into the assertions.
_DB_DETECTION_VARS = (
    "DATABASE_URL",
    "SYNC_DATABASE_URL",
    "POSTGRES_PASSWORD",
    "POSTGRES_USER",
    "POSTGRES_DB",
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "COMPOSE_PROFILES",
)


def _make_stub_bin(tmp_path: Path) -> Path:
    """Stub the container-only binaries (gosu & friends) the entrypoint calls."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stubs = {
        "gosu": '#!/bin/sh\nshift\nexec "$@"\n',
        "stat": "#!/bin/sh\necho 0\n",
        "getent": "#!/bin/sh\nexit 1\n",
        "addgroup": "#!/bin/sh\nexit 0\n",
        "adduser": "#!/bin/sh\nexit 0\n",
    }
    for name, content in stubs.items():
        path = bin_dir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
    return bin_dir


def _run_entrypoint(tmp_path: Path, env_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
    bin_dir = _make_stub_bin(tmp_path)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SECRET_KEY": "test-secret-key",
    }
    for var in _DB_DETECTION_VARS:
        env.pop(var, None)
    env.update(env_overrides)
    return subprocess.run(
        ["sh", "docker-entrypoint.sh", "python3", "-c", _PRINT_URLS],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@contextmanager
def _pg_listener():
    """Local TCP listener standing in for PostgreSQL during the reachability probe."""
    srv = socket.socket()
    try:
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        yield srv.getsockname()[1]
    finally:
        srv.close()


def _url_lines(result: subprocess.CompletedProcess[str]) -> tuple[str, str]:
    assert result.returncode == 0, result.stderr
    lines = result.stdout.strip().splitlines()
    return lines[-2], lines[-1]


def test_entrypoint_preserves_explicit_database_urls(tmp_path: Path):
    """Remote workers should keep explicit DATABASE_URL values."""
    result = _run_entrypoint(
        tmp_path,
        {
            "DATABASE_URL": "postgresql+asyncpg://worker:pass@10.0.123.1:5432/logstotal",
            "SYNC_DATABASE_URL": "postgresql+psycopg2://worker:pass@10.0.123.1:5432/logstotal",
        },
    )
    async_url, sync_url = _url_lines(result)
    assert async_url == "postgresql+asyncpg://worker:pass@10.0.123.1:5432/logstotal"
    assert sync_url == "postgresql+psycopg2://worker:pass@10.0.123.1:5432/logstotal"


def test_entrypoint_normalizes_relative_sqlite_to_data_volume(tmp_path: Path):
    """Local-dev sqlite+aiosqlite:///./path must map to /data in Docker (appuser cannot write /app)."""
    result = _run_entrypoint(tmp_path, {"DATABASE_URL": "sqlite+aiosqlite:///./logstotal.db"})
    async_url, sync_url = _url_lines(result)
    assert async_url == "sqlite+aiosqlite:////data/logstotal.db"
    assert sync_url == "sqlite:////data/logstotal.db"


def test_entrypoint_preserves_absolute_sqlite_url(tmp_path: Path):
    result = _run_entrypoint(tmp_path, {"DATABASE_URL": "sqlite+aiosqlite:////data/custom.db"})
    async_url, sync_url = _url_lines(result)
    assert async_url == "sqlite+aiosqlite:////data/custom.db"
    assert sync_url == "sqlite:////data/custom.db"


def test_entrypoint_postgres_password_builds_urls(tmp_path: Path):
    """POSTGRES_PASSWORD alone (no DATABASE_URL) must construct compose PostgreSQL URLs."""
    with _pg_listener() as port:
        result = _run_entrypoint(
            tmp_path,
            {
                "POSTGRES_PASSWORD": "testpw",
                "POSTGRES_HOST": "127.0.0.1",
                "POSTGRES_PORT": str(port),
            },
        )
    async_url, sync_url = _url_lines(result)
    assert async_url == f"postgresql+asyncpg://logstotal:testpw@127.0.0.1:{port}/logstotal"
    assert sync_url == f"postgresql+psycopg2://logstotal:testpw@127.0.0.1:{port}/logstotal"


def test_entrypoint_postgres_password_overrides_legacy_sqlite_default(tmp_path: Path):
    """The shipped template default DATABASE_URL must not defeat an enabled postgres profile.

    Older .env templates shipped DATABASE_URL=sqlite+aiosqlite:///./logstotal.db
    uncommented; operators who enabled COMPOSE_PROFILES=postgres + POSTGRES_PASSWORD
    but kept that line silently ran on (and backed up) the wrong database.
    """
    with _pg_listener() as port:
        result = _run_entrypoint(
            tmp_path,
            {
                "DATABASE_URL": "sqlite+aiosqlite:///./logstotal.db",
                "POSTGRES_PASSWORD": "testpw",
                "POSTGRES_HOST": "127.0.0.1",
                "POSTGRES_PORT": str(port),
            },
        )
    async_url, sync_url = _url_lines(result)
    assert async_url == f"postgresql+asyncpg://logstotal:testpw@127.0.0.1:{port}/logstotal"
    assert sync_url == f"postgresql+psycopg2://logstotal:testpw@127.0.0.1:{port}/logstotal"
    assert "WARNING" in result.stdout
    assert "legacy" in result.stdout


def test_entrypoint_explicit_url_wins_over_postgres_password(tmp_path: Path):
    """Any non-template DATABASE_URL stays authoritative even with POSTGRES_PASSWORD set."""
    result = _run_entrypoint(
        tmp_path,
        {
            "DATABASE_URL": "sqlite+aiosqlite:////data/custom.db",
            "POSTGRES_PASSWORD": "testpw",
        },
    )
    async_url, sync_url = _url_lines(result)
    assert async_url == "sqlite+aiosqlite:////data/custom.db"
    assert sync_url == "sqlite:////data/custom.db"


def test_entrypoint_custom_sync_url_disables_legacy_override(tmp_path: Path):
    """A deliberate custom SYNC_DATABASE_URL means the sqlite pair was a choice — stay on SQLite."""
    result = _run_entrypoint(
        tmp_path,
        {
            "DATABASE_URL": "sqlite+aiosqlite:///./logstotal.db",
            "SYNC_DATABASE_URL": "sqlite:////data/elsewhere.db",
            "POSTGRES_PASSWORD": "testpw",
            "COMPOSE_PROFILES": "postgres",  # gate open, so it's the custom-sync guard that keeps SQLite
        },
    )
    async_url, _sync_url = _url_lines(result)
    assert async_url == "sqlite+aiosqlite:////data/logstotal.db"


# ── PostgreSQL gate: COMPOSE_PROFILES is the reference ────────────────────────
# POSTGRES_PASSWORD alone does not engage PostgreSQL mode — the bundled service
# must be in play (postgres profile) or an external POSTGRES_HOST configured. The
# dry-run seam (LOGSTOTAL_ENTRYPOINT_DRYRUN=1) skips the privileged prelude and
# the postgres reachability wait, so the profile-only branch can be pinned without
# a reachable postgres or a fake listener.


def _run_entrypoint_dryrun(env_overrides: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "SECRET_KEY": "test-secret-key"}
    for var in _DB_DETECTION_VARS:
        env.pop(var, None)
    env.update(env_overrides)
    env["LOGSTOTAL_ENTRYPOINT_DRYRUN"] = "1"
    return subprocess.run(
        ["sh", "docker-entrypoint.sh"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )


def _dryrun_backend(env_overrides: dict[str, str]) -> str:
    out = _run_entrypoint_dryrun(env_overrides).stdout
    for line in out.splitlines():
        if line.startswith("DRYRUN: DATABASE_URL="):
            url = line.split("=", 1)[1]
            if url.startswith("postgresql"):
                return "postgres"
            if url.startswith("sqlite"):
                return "sqlite"
    raise AssertionError(f"no resolvable DRYRUN DATABASE_URL in:\n{out}")


def test_gate_password_with_postgres_profile_selects_postgres():
    assert _dryrun_backend({"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "proxy,postgres"}) == "postgres"


def test_gate_password_without_profile_stays_sqlite():
    """The user-reported crash-loop repro: password + proxy profile → SQLite (no 30s postgres wait)."""
    result = _run_entrypoint_dryrun({"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "proxy"})
    assert _dryrun_backend({"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "proxy"}) == "sqlite"
    assert "POSTGRES_PASSWORD is set but the 'postgres' compose profile is not enabled" in result.stdout


def test_gate_password_with_external_host_selects_postgres():
    assert _dryrun_backend({"POSTGRES_PASSWORD": "pw", "POSTGRES_HOST": "somehost"}) == "postgres"


def test_gate_password_alone_stays_sqlite():
    assert _dryrun_backend({"POSTGRES_PASSWORD": "pw"}) == "sqlite"


def test_gate_password_with_profile_prints_no_gate_warning():
    result = _run_entrypoint_dryrun({"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "postgres"})
    assert "compose profile is not enabled" not in result.stdout


def test_gate_profile_substring_is_not_a_match():
    """A profile literally named 'postgresql' must not satisfy the postgres gate."""
    assert _dryrun_backend({"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "postgresql"}) == "sqlite"


# ── env-only mode: commands run inside an already-running container ──────────


def test_env_only_mode_gives_an_execed_command_the_real_database(tmp_path: Path):
    """`docker compose exec web …` inherits only .env, never the URLs this script derived at
    boot — on a default install that is an empty ./logstotal.db inside the container. Run
    through the entrypoint in env-only mode, the command sees what the app sees."""
    result = _run_entrypoint(tmp_path, {"DATABASE_URL": "sqlite+aiosqlite:///./logstotal.db", "LOGSTOTAL_ENTRYPOINT_ENV_ONLY": "1"})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines() == ["sqlite+aiosqlite:////data/logstotal.db", "sqlite:////data/logstotal.db"], (
        "the command's stdout must carry its own output only: the entrypoint's messages go to stderr in this mode"
    )
    assert "relative path" in result.stderr


def test_env_only_mode_does_not_wait_for_postgres(tmp_path: Path):
    """No listener on the port: a boot would wait 30 s and abort; env-only derives and runs."""
    result = _run_entrypoint(
        tmp_path,
        {"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "postgres", "POSTGRES_HOST": "127.0.0.1", "POSTGRES_PORT": "1", "LOGSTOTAL_ENTRYPOINT_ENV_ONLY": "1"},
    )
    async_url, _sync = _url_lines(result)
    assert async_url == "postgresql+asyncpg://logstotal:pw@127.0.0.1:1/logstotal"
    assert "waiting for" not in result.stderr


def test_every_exec_into_an_app_container_goes_through_the_entrypoint():
    """A guard on the call sites: a `docker compose exec web|worker <cmd>` that skips the
    entrypoint runs against the wrong database, silently, with a healthy-looking result."""
    import re

    sources = [
        *REPO_ROOT.joinpath("scripts").glob("*.sh"),
        *REPO_ROOT.joinpath("taskfiles").glob("*.yml"),
        REPO_ROOT / "app" / "system_checks.py",
        *REPO_ROOT.joinpath("docs").rglob("*.md"),
    ]
    # What loads the app's configuration: Python and alembic, or a shell to type them in.
    # `curl`, `test -S …` and friends never read DATABASE_URL, so they may exec directly.
    pattern = re.compile(r"docker compose exec\b[^\n|;&]*?\s(web|worker)\s+(\S+)")
    app_commands = {"python3", "python", "alembic", "bash", "/bin/bash", "sh", "/bin/sh", "/docker-entrypoint.sh"}
    offenders = []
    for path in sources:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for match in pattern.finditer(line):
                if match.group(2) not in app_commands:
                    continue
                if match.group(2) != "/docker-entrypoint.sh" or "LOGSTOTAL_ENTRYPOINT_ENV_ONLY=1" not in line:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}")
    assert not offenders, "exec into web/worker without the entrypoint's env-only mode:\n" + "\n".join(offenders)
