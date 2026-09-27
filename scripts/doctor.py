#!/usr/bin/env python3
"""
LogsTotal deployment doctor — one-stop preflight for any deployment path.

Runs a series of read-only checks (config, secrets, DB, Redis, storage,
migrations, Docker, disk, ports, hardware, tool binaries) and prints a grouped
PASS / WARN / FAIL report where every failure includes the exact command to
fix it. Exits non-zero if any check FAILs, so it doubles as a CI / pre-start gate.

Usage:
    python3 scripts/doctor.py                 # host preflight (auto-detects Docker checks)
    python3 scripts/doctor.py --docker        # force the Docker checks on
    python3 scripts/doctor.py --no-docker
    python3 scripts/doctor.py --in-container  # run inside the web container (./logstotal doctor:docker)
                                              # skips host-only checks (.env file, port, Docker daemon)

The check logic lives in app/system_checks.py, shared with the admin System
Status card, and reuses app.config.Settings so it stays in sync with the real
startup validation (SECRET_KEY rules, production warnings/errors, placeholders).
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Sibling import, the scripts/deploy_fleet_env.py idiom. doctor.py runs on hosts with no
# venv and inside the web container, so nothing here may reach the application — cli_color
# is stdlib only for that reason.
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from cli_color import colors  # noqa: E402

PASS = "PASS"  # noqa: S105 - status label, not a credential
WARN = "WARN"
FAIL = "FAIL"
INFO = "INFO"

# Default admin bootstrap password shipped in .env.example — flagged wherever found.
DEFAULT_ADMIN_PASSWORD = "changeme123"  # noqa: S105 - sentinel, not a real credential


# Which palette key tints which verdict. The escapes themselves live in cli_color, with
# the shell's — a doctor report is read directly under lines common.sh printed, and two
# greens that do not match is the kind of thing you only notice side by side.
#
# Never ask sys.stdout.isatty() here. That is the wrong question in a
# subprocess: `task doctor | less` reaches here on a pipe, and only the shell — which
# resolved LT_COLOR before spawning anything — saw what the operator actually typed.
_TINTS = {PASS: "green", WARN: "yellow", FAIL: "red", INFO: "cyan"}
_SYMBOLS = {PASS: "✓", WARN: "!", FAIL: "✗", INFO: "·"}


class Report:
    """Collects check results and renders them grouped by section."""

    def __init__(self) -> None:
        self._results: list[tuple[str, str, str, str, str]] = []  # section, level, name, msg, fix

    def add(self, section: str, level: str, name: str, msg: str = "", fix: str = "") -> None:
        self._results.append((section, level, name, msg, fix))

    def add_results(self, results) -> None:
        """Append app.system_checks.CheckResult objects."""
        for r in results:
            self.add(r.section, r.level, r.name, r.message, r.fix)

    @property
    def failed(self) -> bool:
        return any(level == FAIL for _, level, *_ in self._results)

    @property
    def warned(self) -> bool:
        return any(level == WARN for _, level, *_ in self._results)

    def render(self) -> None:
        c = colors()
        last_section = None
        for section, level, name, msg, fix in self._results:
            if section != last_section:
                # Bold-cyan section header, matching shell's `header` accent so a doctor
                # run under `task upgrade` sits visually beside its shell siblings. Plain
                # form is `  {section}` (bold+cyan empty), which is what TestDoctorRendersBothWays
                # asserts as `out.splitlines()[:3][1]`.
                print(f"\n  {c['bold']}{c['cyan']}{section}{c['off']}")
                last_section = section
            sym = _SYMBOLS[level]
            # Switched off, every key is the empty string and this renders byte-identically
            # to plain output — which is what the doctor tests read back.
            tag = f"{c[_TINTS[level]]}{sym} {level}{c['off']}"
            line = f"    {tag}  {name}"
            if msg:
                line += f" — {msg}"
            print(line)
            if fix:
                # Dim so the hint reads as a subordinate to the check line above rather
                # than competing with it. Plain form byte-identical.
                print(f"           {c['dim']}↳ fix: {fix}{c['off']}")

        # Verdict aggregation is shared with the admin dashboard readiness view
        # (app/system_checks.py::summarize) so CLI and UI can never disagree.
        from app.system_checks import CheckResult, summarize

        summary = summarize([CheckResult(*r) for r in self._results])
        # Dim the separator so the eye jumps to the tally, not the ruler.
        print(f"\n  {c['dim']}{'─' * 60}{c['off']}")
        # Colour each count in the tally so pass/warn/fail read at a glance without
        # having to parse the number. The middle-dots stay plain.
        print(f"  {c['green']}{summary['passed']} pass{c['off']} · {c['yellow']}{summary['warned']} warn{c['off']} · {c['red']}{summary['failed']} fail{c['off']}")
        # Result verdict — bold+colour per state. Keeps every literal word tests grep for.
        if summary["status"] == "not_ready":
            print(f"\n  {c['bold']}{c['red']}Result: NOT READY{c['off']} — resolve the FAIL items above, then re-run `./logstotal doctor`.")
        elif summary["status"] == "ready_warn":
            print(f"\n  {c['bold']}{c['yellow']}Result: READY (with warnings){c['off']} — review the WARN items before going to production.")
        else:
            print(f"\n  {c['bold']}{c['green']}Result: READY{c['off']} — all checks passed.")


def _read_env_file(path: Path) -> dict[str, str]:
    """Parse a .env file into a dict (best-effort; ignores comments/blank lines)."""
    out: dict[str, str] = {}
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            out[key.strip()] = val.strip().strip("'\"")
    except OSError:
        pass
    return out


# ── Host-only checks (everything shared lives in app/system_checks.py) ────────


def check_env_and_settings(report: Report, in_container: bool) -> object | None:
    """Verify .env exists and Settings loads (this is where SECRET_KEY rules fire)."""
    section = "Configuration"
    env_path = PROJECT_ROOT / ".env"
    if not in_container:
        if not env_path.exists():
            report.add(section, FAIL, ".env file", "not found", "./logstotal setup  (or: cp .env.example .env && ./logstotal gen-secrets -- --write)")
            return None
        report.add(section, PASS, ".env file", "present")

    # Loading app.config triggers module-level Settings() — it raises on bad config.
    try:
        from app.config import settings

        report.add(section, PASS, "Settings load", f"app v{settings.app_version}, db={'postgresql' if 'postgres' in settings.database_url else 'sqlite'}")
        return settings
    except ModuleNotFoundError as exc:
        report.add(section, FAIL, "Settings load", f"dependency missing ({exc.name})", "run via `./logstotal doctor` (uses the venv), or: pdm install")
        return None
    except Exception as exc:
        first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
        report.add(section, FAIL, "Settings load", first_line, 'edit .env, then re-run. Generate a key: python3 -c "import secrets; print(secrets.token_hex(32))"')
        return None


def _admin_user_exists() -> bool | None:
    """True/False when the DB can be read, None when it cannot (fresh or unreachable).

    Only used to decide how loudly to report the default admin password: with an admin
    already in place the shipped default is inert, but on a database that has none
    `init_db.py` refuses it — and under compose's `restart: unless-stopped` that refusal
    becomes a crash loop that `docker compose up -d` still reports as success.
    """
    try:
        from sqlalchemy import text

        from app.system_checks import _sync_engine

        engine = _sync_engine()
        try:
            with engine.connect() as conn:
                # Unquoted `is_superuser` rather than `= 1`/`= true`: SQLite stores the
                # Boolean as 0/1 and PostgreSQL as a real boolean, and a bare column
                # reference is truthy in both.
                return conn.execute(text('SELECT 1 FROM "user" WHERE is_superuser LIMIT 1')).first() is not None
        finally:
            engine.dispose()
    except Exception:
        return None


def check_admin_password(report: Report) -> None:
    section = "Configuration"
    # Environment first (Docker passes ADMIN_PASSWORD into the container), .env as fallback.
    pw = os.environ.get("ADMIN_PASSWORD") or _read_env_file(PROJECT_ROOT / ".env").get("ADMIN_PASSWORD", "")
    if pw == DEFAULT_ADMIN_PASSWORD:
        # FAIL only when it will actually bite: no admin row yet means the next
        # `init_db.py` refuses to boot. With an admin already created it is inert.
        if _admin_user_exists():
            report.add(
                section,
                WARN,
                "admin password",
                "still the shipped default (changeme123)",
                "inert — the admin already exists, so init no longer reads it; still worth clearing from .env",
            )
        else:
            report.add(
                section,
                FAIL,
                "admin password",
                "still the shipped default (changeme123) and no admin exists yet",
                "init REFUSES this password, and under Docker that becomes a restart loop — set a strong one: ./logstotal gen-secrets -- --write",
            )
    elif pw and len(pw) < 12:
        report.add(section, WARN, "admin password", "shorter than 12 characters", "use a longer ADMIN_PASSWORD in .env")
    elif pw:
        report.add(section, PASS, "admin password", "customised")


def check_docker(report: Report, want_docker: bool) -> None:
    section = "Services"
    if not want_docker:
        return
    if shutil.which("docker") is None:
        report.add(section, FAIL, "Docker", "docker CLI not found", "install Docker: https://docs.docker.com/engine/install/")
        return
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        report.add(section, PASS, "Docker", "daemon reachable")
    except Exception:
        report.add(section, FAIL, "Docker", "daemon not reachable", "start Docker Desktop / the docker service, then re-run")


def check_port(report: Report) -> None:
    section = "Resources"
    raw = os.environ.get("WEB_PORT", "8000")
    # WEB_PORT may be "8000" or "127.0.0.1:8000:8000" (compose port mapping).
    parts = [seg for seg in raw.replace(":", " ").split() if seg.isdigit()]
    port = int(parts[0]) if parts else 8000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        in_use = sock.connect_ex(("127.0.0.1", port)) == 0
    finally:
        sock.close()
    if in_use:
        report.add(section, WARN, f"port {port}", "already in use", f"stop whatever is bound to {port}, or set WEB_PORT to a free port")
    else:
        report.add(section, PASS, f"port {port}", "free")


def _detect_ram_gb() -> float | None:
    try:
        if platform.system() == "Linux":
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / (1024**2)  # kB → GB
        elif platform.system() == "Darwin":
            out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, timeout=5, check=True)
            return int(out.stdout.strip()) / (1024**3)
    except Exception:
        return None
    return None


def check_hardware(report: Report) -> None:
    section = "Resources"
    cores = os.cpu_count() or 1
    ram = _detect_ram_gb()
    ram_str = f", {ram:.1f} GB RAM" if ram else ""
    report.add(section, INFO, "hardware", f"{cores} CPU core(s){ram_str}", "size workers with: ./logstotal recommend-scaling")


def main() -> int:
    parser = argparse.ArgumentParser(description="LogsTotal deployment preflight")
    docker_group = parser.add_mutually_exclusive_group()
    docker_group.add_argument("--docker", action="store_true", help="force Docker checks on")
    docker_group.add_argument("--no-docker", action="store_true", help="skip Docker checks")
    parser.add_argument("--in-container", action="store_true", help="running inside the web container — skip host-only checks")
    args = parser.parse_args()

    # Auto-detect: check Docker if COMPOSE_PROFILES is set or a docker-compose file is present.
    want_docker = not args.in_container and (
        args.docker
        or (not args.no_docker and (bool(os.environ.get("COMPOSE_PROFILES")) or ((PROJECT_ROOT / "docker-compose.yml").exists() and shutil.which("docker") is not None)))
    )

    c = colors()
    print(f"{c['bold']}LogsTotal doctor — deployment preflight{c['off']}" + (" (in-container)" if args.in_container else ""))
    report = Report()
    settings = check_env_and_settings(report, args.in_container)
    check_admin_password(report)

    if settings is not None:
        # Shared checks (also power the admin System Status card). Imported only
        # after Settings loaded cleanly — the module imports settings itself.
        from app import system_checks

        report.add_results(system_checks.check_production_config())
        report.add_results(system_checks.check_proxy_config())
        report.add_results(system_checks.check_multi_server_config())
        report.add_results(system_checks.check_bundled_service_config())
        report.add_results([system_checks.check_default_admin_password()])
        report.add_results([system_checks.check_migration_state()])

        # On a Docker host, Redis/Postgres live inside the compose network and are
        # not reachable from the host — a pre-`docker:up` FAIL here is expected.
        # Point the operator at the in-container run instead of leaving a dead end.
        docker_hint = "Docker deployments: this service runs inside the compose network — a host-side failure before `./logstotal docker:up` is expected; verify with: ./logstotal doctor:docker"
        for result in (system_checks.check_database(), system_checks.check_redis(), system_checks.check_storage()):
            if want_docker and not args.in_container and result.level == FAIL:
                result.fix = f"{result.fix}  |  {docker_hint}" if result.fix else docker_hint
            report.add_results([result])
        report.add_results([system_checks.check_redis_eviction()])
        check_docker(report, want_docker)  # same "Services" section as the checks above
        report.add_results(system_checks.check_workers())
        report.add_results(system_checks.check_concurrency())
        for optional_check in (
            system_checks.check_sqlite_multi_worker(),
            system_checks.check_queue_age(),
            system_checks.check_pg_pool_pressure(),
        ):
            if optional_check is not None:
                report.add_results([optional_check])
        report.add_results([system_checks.check_backup_receipt()])
        report.add_results([system_checks.check_host_os(in_container=args.in_container)])
        report.add_results(system_checks.check_disk())
        if not args.in_container:
            check_port(report)
        check_hardware(report)
        report.add_results(system_checks.check_tool_binaries(PROJECT_ROOT))
        # Wired here AND in system_checks.run_all — doctor enumerates its checks
        # explicitly rather than calling run_all, so a new check must be wired in both.
        report.add_results(system_checks.check_docker_tools(PROJECT_ROOT, in_container=args.in_container))
    else:
        check_docker(report, want_docker)
        if not args.in_container:
            check_port(report)
        check_hardware(report)

    report.render()
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.path.insert(0, str(PROJECT_ROOT))
    sys.exit(main())
