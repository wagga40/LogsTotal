"""Shared deployment/health checks — used by scripts/doctor.py (CLI) and the
admin System Status card (/admin/system-checks-partial).

Pure sync functions, no FastAPI/Huey imports (same isolation rule as
app/similarity/). Async callers must off-load via run_in_threadpool.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from app.config import settings
from app.docs_site import docs_url

PASS = "PASS"  # noqa: S105 - status label, not a credential
WARN = "WARN"
FAIL = "FAIL"
INFO = "INFO"

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Queue depth above which a backlog is flagged (not a Settings field on purpose).
QUEUE_BACKLOG_WARN = 25
# Loopback-only default of TRUSTED_PROXY_CIDRS — useless once a proxy container fronts the app.
DEFAULT_LOOPBACK_CIDRS = "127.0.0.1/32,::1/128"
# The shipped default admin password (init_db.py); flagged if any superuser still uses it.
DEFAULT_ADMIN_PASSWORD = "changeme123"  # noqa: S105 - sentinel to compare against, not a live secret
# Single-sourced remedy for "no workers alive" — reused by check_workers() and the
# admin dashboard health strip / getting-started checklist so the prose never drifts.
WORKER_START_FIX = "start one: ./logstotal worker  (Docker: docker compose up -d worker)"


@dataclass
class CheckResult:
    section: str
    level: str  # PASS | WARN | FAIL | INFO
    name: str
    message: str = ""
    fix: str = ""


def multi_server_config_warnings(
    *,
    compose_profiles: str,
    database_url: str,
    storage_backend: str,
    redis_expose: str | None,
    postgres_expose: str | None = None,
    garage_expose: str | None = None,
) -> list[str]:
    """Warn about multi-worker deployments missing shared DB/storage/relay config.

    Pure (no I/O). Returns an empty list when multi-worker mode is not in play.
    Shared by startup logging and the doctor / System Status card.
    """
    profiles = {part.strip() for part in compose_profiles.split(",") if part.strip()}
    multi_worker_enabled = "workers" in profiles or bool(redis_expose)
    if not multi_worker_enabled:
        return []

    warnings: list[str] = []
    if storage_backend.lower() != "s3":
        warnings.append("Multi-worker deployments require shared object storage. Set STORAGE_BACKEND=s3 on the control plane so remote workers can load uploads.")
    if "sqlite" in database_url.lower():
        warnings.append("Multi-worker deployments require a shared PostgreSQL database. The current runtime DATABASE_URL resolves to SQLite.")
    if "workers" in profiles and not redis_expose:
        warnings.append("COMPOSE_PROFILES includes 'workers' but REDIS_EXPOSE is empty. Remote workers will not be able to reach the bundled Redis relay.")
    if "workers" in profiles and "postgres" in profiles and not postgres_expose:
        warnings.append(
            "COMPOSE_PROFILES includes both 'workers' and 'postgres' but POSTGRES_EXPOSE is empty. Remote workers will not be able to reach the bundled PostgreSQL service."
        )
    if "workers" in profiles and "s3" in profiles and not garage_expose:
        warnings.append("COMPOSE_PROFILES includes both 'workers' and 's3' but GARAGE_EXPOSE is empty. Remote workers will not be able to reach the bundled Garage/S3 service.")
    return warnings


def _sync_engine():
    """Short-lived engine on the current settings sync URL (import-time engines
    would not see monkeypatched/test settings)."""
    is_sqlite = "sqlite" in (settings.sync_database_url or "")
    return create_engine(
        settings.sync_database_url,
        poolclass=NullPool,
        connect_args={"check_same_thread": False} if is_sqlite else {},
    )


def check_database() -> CheckResult:
    kind = "postgresql" if "postgres" in (settings.sync_database_url or "") else "sqlite"
    try:
        engine = _sync_engine()
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        finally:
            engine.dispose()
        return CheckResult("Services", PASS, "database", f"reachable ({kind})")
    except Exception as exc:
        return CheckResult(
            "Services",
            FAIL,
            "database",
            f"unreachable ({str(exc).splitlines()[0]})",
            "check DATABASE_URL / SYNC_DATABASE_URL in .env; for PostgreSQL verify the server is up and credentials match",
        )


def check_redis() -> CheckResult:
    try:
        from app.redis_client import get_redis

        get_redis().ping()
        return CheckResult("Services", PASS, "Redis", "reachable")
    except Exception as exc:
        return CheckResult(
            "Services",
            FAIL,
            "Redis",
            f"unreachable ({str(exc).splitlines()[0]})",
            "start it: ./logstotal redis:bg  (or: ./logstotal redis:docker; Docker install: docker compose up -d redis). Multi-host: check REDIS_URL / firewall.",
        )


def check_redis_eviction() -> CheckResult:
    """Redis under an eviction policy can silently drop queued Huey jobs and
    worker heartbeats when memory fills — a hard-to-diagnose stall. One CONFIG
    GET round-trip; degrades to INFO on managed Redis where CONFIG is blocked."""
    try:
        from app.redis_client import get_redis

        policy = get_redis().config_get("maxmemory-policy")
        value = policy.get("maxmemory-policy") if isinstance(policy, dict) else None
        if not value:
            return CheckResult("Services", INFO, "Redis eviction", "could not read maxmemory-policy (managed Redis?)")
        if value == "noeviction":
            return CheckResult("Services", PASS, "Redis eviction", "maxmemory-policy=noeviction")
        return CheckResult(
            "Services",
            WARN,
            "Redis eviction",
            f"maxmemory-policy={value} — evicted keys can silently drop queued jobs and heartbeats",
            "set noeviction (redis.conf: maxmemory-policy noeviction, or the equivalent managed-provider setting)",
        )
    except Exception:
        return CheckResult("Services", INFO, "Redis eviction", "could not read maxmemory-policy (managed Redis?)")


def check_workers() -> list[CheckResult]:
    """Worker liveness + Huey queue depth. A non-empty queue with zero workers
    means uploads will sit in PENDING forever — the classic silent stall."""
    results: list[CheckResult] = []
    try:
        from app.redis_client import WORKER_ALIVE_PREFIX, get_redis

        worker_count = sum(1 for _ in get_redis().scan_iter(f"{WORKER_ALIVE_PREFIX}*"))
    except Exception as exc:
        results.append(CheckResult("Workers", WARN, "workers", f"could not count ({str(exc).splitlines()[0]})"))
        return results

    queue_size: int | None = None
    try:
        from app.huey_inspect import get_queue_snapshot

        snapshot = get_queue_snapshot(limit=0)
        if snapshot.get("error") is None:
            queue_size = int(snapshot.get("queue_size", 0))
    except Exception:
        queue_size = None

    if worker_count == 0:
        level = FAIL if queue_size else WARN
        stall = f"; {queue_size} queued job(s) will stall" if queue_size else " — new analyses will queue but never run"
        results.append(CheckResult("Workers", level, "workers", f"0 alive{stall}", WORKER_START_FIX))
    else:
        results.append(CheckResult("Workers", PASS, "workers", f"{worker_count} alive"))
    if queue_size is not None:
        if queue_size > QUEUE_BACKLOG_WARN:
            results.append(
                CheckResult(
                    "Workers",
                    WARN,
                    "queue depth",
                    f"{queue_size} pending task(s) — backlog above {QUEUE_BACKLOG_WARN}",
                    "add workers (./logstotal worker / scale the worker service), check worker health, or clear stuck jobs via POST /admin/recover-stuck-jobs",
                )
            )
        else:
            results.append(CheckResult("Workers", INFO, "queue depth", f"{queue_size} pending task(s)"))
    return results


def check_storage() -> CheckResult:
    """Actually exercise the storage backend — a write/read/delete probe for
    local storage (not just 'the setting says local'), head_bucket for S3."""
    if settings.storage_backend == "s3":
        try:
            from app.storage import get_storage

            st = get_storage()
            st._s3.head_bucket(Bucket=st._bucket)
            return CheckResult("Services", PASS, "storage", f"s3 bucket '{st._bucket}' reachable")
        except Exception as exc:
            return CheckResult(
                "Services",
                FAIL,
                "storage",
                f"s3 error ({str(exc).splitlines()[0]})",
                "verify S3_ENDPOINT / S3_BUCKET / S3_ACCESS_KEY / S3_SECRET_KEY and that the bucket exists",
            )
    upload_dir = settings.upload_dir if settings.upload_dir.is_absolute() else PROJECT_ROOT / settings.upload_dir
    probe = upload_dir / f".health-probe-{uuid.uuid4().hex[:8]}"
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)
        probe.write_text("ok", encoding="utf-8")
        content = probe.read_text(encoding="utf-8")
        probe.unlink()
        if content != "ok":
            raise OSError("read-back mismatch")
        return CheckResult("Services", PASS, "storage", f"local, writable ({upload_dir})")
    except Exception as exc:
        probe.unlink(missing_ok=True)
        return CheckResult(
            "Services",
            FAIL,
            "storage",
            f"upload dir not writable ({str(exc).splitlines()[0]})",
            f"fix permissions on {upload_dir} (the app user must be able to create files there)",
        )


def check_migration_state() -> CheckResult:
    from app.migrations import migration_status

    status = migration_status()
    if status.state == "at_head":
        return CheckResult("Database schema", PASS, "migrations", f"at Alembic head ({status.head})")
    if status.state == "fresh":
        return CheckResult("Database schema", INFO, "migrations", "no schema yet — created on first start (./logstotal init / docker:up)")
    if status.state == "behind":
        return CheckResult(
            "Database schema",
            FAIL,
            "migrations",
            f"{status.pending_count} migration(s) pending ({status.current} → {status.head})",
            "restart the app (auto-migrates), or run: python3 -m app.migrations",
        )
    if status.state == "unmanaged":
        return CheckResult(
            "Database schema",
            WARN,
            "migrations",
            "database is not under Alembic management (schema drift blocked automatic adoption)",
            f"reconcile the schema with the models, then: ./logstotal db:stamp -- head  (Docker: docker compose run --rm web python3 -m alembic stamp head) — {docs_url('runbooks/migrations.md')}",
        )
    return CheckResult("Database schema", WARN, "migrations", "state unknown (database unreachable?)")


def check_production_config() -> list[CheckResult]:
    """Settings-level safety: warnings, fail-fast errors, and the plain-HTTP
    login footgun (Secure cookie without an HTTPS path in front)."""
    results = [CheckResult("Configuration", WARN, "production safety", w) for w in settings.production_warnings()]
    results += [CheckResult("Configuration", FAIL, "production safety", e, "the app will REFUSE TO START with this configuration — fix .env") for e in settings.production_errors()]
    # `https_terminated_locally`, not "is the proxy profile on": PROXY_TLS=off puts Caddy in
    # front on plain HTTP, so the profile alone does not imply HTTPS. It also splits
    # COMPOSE_PROFILES on commas, so a profile named `myproxy` does not count.
    if settings.cookie_secure and not settings.https_terminated_locally:
        results.append(
            CheckResult(
                "Configuration",
                WARN,
                "cookies vs HTTP",
                "auth cookies are Secure-only but no HTTPS proxy profile is configured — login will silently fail over plain HTTP",
                "for HTTP-only deployments set COOKIE_INSECURE=true; for HTTPS use COMPOSE_PROFILES=proxy (ignore if TLS is terminated by an external proxy)",
            )
        )
    return results


def check_proxy_config() -> list[CheckResult]:
    """Reverse-proxy footguns behind the `proxy` compose profile: forwarded
    client IPs that all collapse to the proxy, and HSTS that disagrees with how
    the proxy terminates TLS. Emits nothing when no proxy profile is configured
    (avoid noise on single-host setups)."""
    if not settings.proxy_profile_enabled:
        return []

    results: list[CheckResult] = []
    cidrs = (settings.trusted_proxy_cidrs or "").strip()
    loopback_only = cidrs in ("", DEFAULT_LOOPBACK_CIDRS)
    if settings.trust_proxy_headers and loopback_only:
        results.append(
            CheckResult(
                "Configuration",
                WARN,
                "proxy client IP",
                "TRUST_PROXY_HEADERS is on but TRUSTED_PROXY_CIDRS is loopback-only — proxied requests will all appear to come from the proxy",
                "set TRUSTED_PROXY_CIDRS to the compose network CIDR (find it with: docker network inspect logstotal_default --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')",
            )
        )
    # HSTS advice is only advice while the proxy actually serves TLS. Under PROXY_TLS=off
    # Caddy is a plain-HTTP front door, so advising HSTS would mean turning on a header
    # browsers ignore over HTTP — and the genuinely wrong state there is the
    # opposite one, HSTS left on from a previous HTTPS configuration.
    if settings.proxy_tls == "off":
        if settings.enable_hsts:
            results.append(
                CheckResult(
                    "Configuration",
                    WARN,
                    "HSTS",
                    "PROXY_TLS=off serves plain HTTP but ENABLE_HSTS is on — the header is ignored over HTTP, and any browser that saw it over HTTPS will refuse to load this site",
                    "set ENABLE_HSTS=false while PROXY_TLS=off, or terminate TLS here (PROXY_TLS=acme|internal|custom)",
                )
            )
    elif not settings.enable_hsts:
        results.append(
            CheckResult(
                "Configuration",
                WARN,
                "HSTS",
                "proxy profile is enabled but ENABLE_HSTS is off — browsers won't be told to stay on HTTPS",
                "set ENABLE_HSTS=true once HTTPS is confirmed working",
            )
        )
    if not results:
        results.append(CheckResult("Configuration", PASS, "proxy config", "reverse-proxy config looks coherent"))
    return results


def check_multi_server_config() -> list[CheckResult]:
    """Wrap multi_server_config_warnings() as CheckResults. Silent on single-host
    deployments; a single PASS when remote workers are configured coherently."""
    profiles = {p.strip() for p in settings.compose_profiles.split(",") if p.strip()}
    multi_worker_enabled = "workers" in profiles or bool(settings.redis_expose)
    if not multi_worker_enabled:
        return []
    warnings = multi_server_config_warnings(
        compose_profiles=settings.compose_profiles,
        database_url=settings.database_url,
        storage_backend=settings.storage_backend,
        redis_expose=settings.redis_expose,
        postgres_expose=settings.postgres_expose,
        garage_expose=settings.garage_expose,
    )
    if not warnings:
        return [CheckResult("Configuration", PASS, "multi-server", "remote-worker config looks coherent")]
    return [CheckResult("Configuration", WARN, "multi-server", w) for w in warnings]


# The bundled Garage service's in-network S3 endpoint. STORAGE_BACKEND=s3 without
# the 's3' profile AND without an external S3_ENDPOINT means storage can't work.
BUNDLED_S3_ENDPOINT = "http://garage:3900"


def check_bundled_service_config() -> list[CheckResult]:
    """COMPOSE_PROFILES is the reference for whether the BUNDLED postgres/S3
    services are running. Catch the two footguns where a leftover secret or a
    backend setting points the app at a bundled service compose never started:

    * WARN — POSTGRES_PASSWORD is set but the 'postgres' profile is off and no
      external POSTGRES_HOST/DATABASE_URL is configured (the app silently uses
      SQLite and ignores the password). Mirrors the entrypoint's WARNING.
    * FAIL — STORAGE_BACKEND=s3 but the 's3' profile is off and S3_ENDPOINT is
      empty or still the bundled Garage default: object storage genuinely cannot
      work (no bundled Garage running, no external endpoint set).

    Reads POSTGRES_PASSWORD/POSTGRES_HOST from the process env (the same runtime
    view the entrypoint gates on; `./logstotal doctor` loads .env into the environment),
    and COMPOSE_PROFILES / STORAGE_BACKEND / S3_ENDPOINT / DATABASE_URL from
    Settings like the neighbouring profile checks.
    """
    section = "Configuration"
    results: list[CheckResult] = []
    profiles = {p.strip() for p in (settings.compose_profiles or "").split(",") if p.strip()}

    pg_password = (os.environ.get("POSTGRES_PASSWORD") or "").strip()
    pg_host = (os.environ.get("POSTGRES_HOST") or "").strip()
    pg_gate = "postgres" in profiles or bool(pg_host)
    if pg_password and not pg_gate and "postgres" not in (settings.database_url or "").lower():
        results.append(
            CheckResult(
                section,
                WARN,
                "postgres profile",
                "POSTGRES_PASSWORD is set but the 'postgres' compose profile is not enabled and no external POSTGRES_HOST/DATABASE_URL is configured — the app will use SQLite and ignore the password",
                "add 'postgres' to COMPOSE_PROFILES (or set POSTGRES_HOST / DATABASE_URL) to use PostgreSQL",
            )
        )

    if settings.storage_backend.lower() == "s3" and "s3" not in profiles:
        endpoint = (settings.s3_endpoint or "").strip().rstrip("/")
        if not endpoint or endpoint == BUNDLED_S3_ENDPOINT:
            results.append(
                CheckResult(
                    section,
                    FAIL,
                    "s3 storage profile",
                    "STORAGE_BACKEND=s3 but the 's3' compose profile is not enabled and S3_ENDPOINT is empty or the bundled Garage default — object storage cannot work",
                    "add 's3' to COMPOSE_PROFILES to start the bundled Garage, or set S3_ENDPOINT to your external S3 endpoint",
                )
            )
    return results


def check_default_admin_password() -> CheckResult:
    """WARN if any superuser still authenticates with the shipped default password.

    Complements doctor's env-based ADMIN_PASSWORD check by inspecting the DB truth
    (a rotated .env value doesn't re-hash an existing admin row). Uses the same
    PasswordHelper as the admin dashboard banner (routers/admin.py) so the two never
    drift. An Argon2 verify costs ~100ms per hash — a handful of admin rows, fine for
    doctor / System-tab cadence. Never raises: a fresh install with no user table
    degrades to INFO.
    """
    section = "Configuration"
    try:
        from fastapi_users.password import PasswordHelper
        from sqlalchemy import select

        from app.database import get_sync_session
        from app.models import User

        ph = PasswordHelper()
        db = get_sync_session()
        try:
            hashes = db.execute(select(User.hashed_password).where(User.is_superuser.is_(True))).scalars().all()
        finally:
            db.close()
        if any(ph.verify_and_update(DEFAULT_ADMIN_PASSWORD, h)[0] for h in hashes if h):
            return CheckResult(
                section,
                WARN,
                "default admin password",
                f"a superuser still uses the shipped default password ({DEFAULT_ADMIN_PASSWORD})",
                "change it at /admin/users or via the profile menu",
            )
        return CheckResult(section, PASS, "default admin password", "no superuser uses the shipped default password")
    except Exception:
        return CheckResult(section, INFO, "default admin password", "could not check (no user table yet / DB unreachable?)")


def _sqlite_data_dir() -> Path:
    """Where the SQLite database actually lives, or the repo's ``data/`` as a fallback.

    A hardcoded relative ``data`` resolves against PROJECT_ROOT, which inside the container
    is ``/app`` — and the image has no ``/app/data``, so ``shutil.disk_usage`` would fall
    back to the parent and measure the container's overlayfs (the Docker graph driver
    volume) rather than the ``/data`` bind mount the database is on: free space for a
    filesystem nothing writes to. Derived from the URL the app will actually open instead.
    """
    url = settings.sync_database_url or ""
    if url.startswith("sqlite"):
        _, _, path_part = url.partition("///")
        path_part = path_part.split("?", 1)[0]
        if path_part:
            parent = Path("/" + path_part.lstrip("/")).parent if url.startswith("sqlite:////") else Path(path_part).parent
            if str(parent) not in ("", "."):
                return parent
    return Path("data")


def check_disk() -> list[CheckResult]:
    results: list[CheckResult] = []
    paths = {"uploads": settings.upload_dir, "data": _sqlite_data_dir()}
    for label, p in paths.items():
        target = (PROJECT_ROOT / p) if not Path(p).is_absolute() else Path(p)
        probe = target if target.exists() else target.parent
        try:
            usage = shutil.disk_usage(probe)
        except OSError:
            continue
        free_gb = usage.free / (1024**3)
        pct = usage.used / usage.total * 100 if usage.total else 0
        msg = f"{free_gb:.1f} GB free ({pct:.0f}% used) on {label} volume"
        if free_gb < 2:
            results.append(
                CheckResult(
                    "Resources",
                    WARN,
                    f"disk ({label})",
                    msg,
                    "free up space or point UPLOAD_DIR / ./data at a larger volume; set JOB_OUTPUT_RETENTION_DAYS to auto-prune",
                )
            )
        else:
            results.append(CheckResult("Resources", PASS, f"disk ({label})", msg))
    return results


def _arch_key() -> str:
    machine = platform.machine().lower()
    if machine == "arm64":
        machine = "aarch64"
    return f"{machine}-{platform.system().lower()}"


def _workflow_task_sources(project_root: Path) -> list[tuple[str, list[dict]]]:
    """(workflow label, task list) pairs for tool checks.

    Active WorkflowDef rows first — that is what jobs actually execute (the
    filesystem YAMLs are only the seed; admins can edit workflows in the DB).
    Falls back to workflows/*.yml before initialization, and always uses the
    filesystem when inspecting a different project_root (tests, doctor on a
    staged tree).
    """
    sources: list[tuple[str, list[dict]]] = []
    if project_root == PROJECT_ROOT:
        try:
            from sqlalchemy import select

            from app.database import get_sync_session
            from app.detection.workflow_runner import parse_workflow_yaml
            from app.models import WorkflowDef

            db = get_sync_session()
            try:
                rows = db.execute(select(WorkflowDef.name, WorkflowDef.tasks_yaml)).all()
            finally:
                db.close()
            for name, tasks_yaml in rows:
                try:
                    tasks = parse_workflow_yaml(tasks_yaml or "")
                except Exception:
                    continue
                if tasks:
                    sources.append((str(name), tasks))
        except Exception:
            sources = []
        if sources:
            return sources
    wf_dir = project_root / "workflows"
    if not wf_dir.exists():
        return sources
    try:
        from app.yaml_utils import safe_load as yaml_safe_load
    except ImportError:
        return sources
    for wf in sorted(wf_dir.glob("*.yml")):
        try:
            data = yaml_safe_load(wf.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        tasks = data.get("tasks") or []
        if tasks:
            sources.append((wf.name, tasks))
    return sources


def check_tool_binaries(project_root: Path = PROJECT_ROOT) -> list[CheckResult]:
    """Per-arch tool binary presence, from the tool_path maps of the active
    workflows (DB WorkflowDef rows, filesystem fallback pre-init).

    Severity mirrors :func:`check_docker_tools`: **FAIL when the unavailable task is the
    workflow's only one**, WARN when something else in that workflow will still run. On
    `aarch64-darwin`, where ChopChopGo ships no build, `linux_syslog.yml` is guaranteed to
    produce nothing, and `summarize()` must not call that READY.
    """
    section = "Detection tools"
    results: list[CheckResult] = []
    arch = _arch_key()
    seen: set[str] = set()
    for wf_label, tasks in _workflow_task_sources(project_root):
        # A workflow with one task has nothing to fall back on, so an unavailable binary
        # there is fatal to it rather than a degradation.
        blocking = len(tasks) == 1
        level = FAIL if blocking else WARN
        consequence = "; this workflow has no other task and will produce nothing" if blocking else "; this task will be skipped on this host"
        for task in tasks:
            tool = task.get("tool", "?")
            tool_path = task.get("tool_path")
            if isinstance(tool_path, dict):
                resolved = tool_path.get(arch)
                key = f"{tool}:{wf_label}"
                if key in seen:
                    continue
                seen.add(key)
                if resolved is None:
                    results.append(
                        CheckResult(
                            section,
                            level,
                            f"{tool} ({wf_label})",
                            f"no binary for this arch ({arch}){consequence}",
                            "Docker-based tools are unaffected; otherwise add an arch entry to tool_path, or remove this workflow and run `./logstotal sync-workflows` (Docker: `./logstotal docker:up`, which reloads workflows)",
                        )
                    )
                elif not (project_root / resolved).exists():
                    results.append(
                        CheckResult(
                            section,
                            level,
                            f"{tool} ({wf_label})",
                            f"binary missing: {resolved}{consequence}",
                            "place the binary at that path, or remove this workflow and run `./logstotal sync-workflows` (Docker: `./logstotal docker:up`, which reloads workflows)",
                        )
                    )
                elif not os.access(project_root / resolved, os.X_OK):
                    results.append(CheckResult(section, level, f"{tool} ({wf_label})", f"binary present but not executable: {resolved}{consequence}", f"chmod +x {resolved}"))
                else:
                    results.append(CheckResult(section, PASS, f"{tool} ({wf_label})", "binary present"))
    return results


# The platforms LogsTotal is actually exercised on — what `docs/limitations.md`,
# `README.md` and `docs/install/prerequisites.md` mean by "Ubuntu and Debian only".
TESTED_DISTRO_IDS = frozenset({"ubuntu", "debian"})
UNTESTED_OS_FIX = f"Other distributions probably work but are not exercised — if something breaks, report it naming this OS. See {docs_url('limitations.md', 'platform-support')}"


def _os_release() -> dict[str, str]:
    """Parse `/etc/os-release` into a dict. A module-level seam, so the check is testable
    without a distro to run it on. Returns {} when the file is absent or unreadable —
    a container base image built FROM scratch has none, and that is not a finding."""
    values: dict[str, str] = {}
    try:
        raw = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        return values
    for line in raw.splitlines():
        key, sep, value = line.partition("=")
        if not sep or not key.isidentifier():
            continue
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def check_host_os(*, in_container: bool = False) -> CheckResult:
    """Is this a platform LogsTotal is tested on?

    Reported rather than enforced. The deploy scripts make the same call per host and
    also continue: refusing an untested distro would turn a probably-fine deployment
    into a support ticket, while saying nothing is how "it worked on my Fedora box
    until it didn't" happens with no clue in the report.

    macOS is INFO, not WARN, deliberately. `./logstotal doctor` runs on the operator's Mac
    constantly for local development, and `summarize()` counts only FAIL and WARN toward
    the verdict — a WARN here would flip every single local run to "ready with
    warnings" and teach people that warnings are noise. INFO costs nothing.
    """
    system = platform.system()

    if in_container or _running_in_container():
        # /etc/os-release inside the image describes the Dockerfile's base, not the
        # machine. Calling that "a tested platform" would be a lie by construction.
        base = _os_release().get("PRETTY_NAME") or "unknown base image"
        return CheckResult(
            "Resources",
            INFO,
            "host OS",
            f"{base} (container base image — the host OS is not visible from in here)",
            "check the host itself with: ./logstotal doctor",
        )

    if system == "Darwin":
        return CheckResult(
            "Resources",
            INFO,
            "host OS",
            f"macOS {platform.mac_ver()[0] or platform.release()} — supported for local development tooling",
            "Production deployments are tested on Ubuntu and Debian.",
        )

    if system != "Linux":
        return CheckResult("Resources", WARN, "host OS", f"{system or 'unknown'} — tested on Ubuntu and Debian only", UNTESTED_OS_FIX)

    info = _os_release()
    pretty = info.get("PRETTY_NAME") or info.get("NAME") or "unknown Linux"
    distro_id = info.get("ID", "").lower()
    if not info:
        return CheckResult(
            "Resources",
            WARN,
            "host OS",
            "could not read /etc/os-release — cannot confirm a tested platform",
            UNTESTED_OS_FIX,
        )
    if distro_id in TESTED_DISTRO_IDS:
        return CheckResult("Resources", PASS, "host OS", f"{pretty} (tested)")
    if "debian" in info.get("ID_LIKE", "").lower().split():
        return CheckResult(
            "Resources",
            INFO,
            "host OS",
            f"{pretty} (Debian-like — close to the tested set, not exercised)",
            UNTESTED_OS_FIX,
        )
    return CheckResult("Resources", WARN, "host OS", f"{pretty} — tested on Ubuntu and Debian only", UNTESTED_OS_FIX)


def _docker_daemon_reachable() -> bool:
    """`docker info` succeeds. A module-level seam so tests do not need a real daemon."""
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=False).returncode == 0
    except Exception:
        return False


def _running_in_container() -> bool:
    """Are we inside a container? `/.dockerenv` is what Docker itself writes.

    Detected rather than only passed in, because `run_all()` — which backs the admin
    System Status card and its readiness verdict — runs in the web process and has no CLI
    flag to thread through. The web container is exactly where this matters.
    """
    return Path("/.dockerenv").exists()


def _docker_socket_present() -> bool:
    """Is a Docker socket even mounted here? A separate seam from reachability.

    Only the **worker** service mounts `/var/run/docker.sock` (docker-compose.yml), and that
    is deliberate: the web tier holding the Docker socket is a privilege-escalation surface
    that `docs/security.md` calls out by name. So "no daemon" answered from the web
    container is not a finding about the deployment, it is a finding about which container
    was asked.
    """
    return Path("/var/run/docker.sock").exists()


def check_docker_tools(project_root: Path = PROJECT_ROOT, *, in_container: bool = False) -> list[CheckResult]:
    """Can the workflows that need a container actually run one?

    `check_tool_binaries` looks only at `tool_path`, so without this a host with no Docker
    daemon would report **READY** while every Zircolite task on it is guaranteed to fail —
    five of the six shipped workflows use Zircolite, and four declare it as their only task.

    FAIL, not WARN, when a workflow's *only* task needs Docker: there is no partial result
    to salvage. WARN when the workflow has other tasks that will still run.
    """
    section = "Detection tools"
    docker_tasks: dict[str, tuple[int, int]] = {}  # workflow -> (docker task count, total)
    for wf_label, tasks in _workflow_task_sources(project_root):
        needs = sum(1 for t in tasks if t.get("docker_image") or t.get("dockerfile"))
        if needs:
            docker_tasks[wf_label] = (needs, len(tasks))
    if not docker_tasks:
        return []

    if _docker_daemon_reachable():
        return [CheckResult(section, PASS, "Docker daemon", f"reachable — {len(docker_tasks)} workflow(s) need it")]

    # `task doctor:docker` runs inside the **web** container, which mounts no Docker socket
    # by design — the worker is the one that runs containers. A FAIL from there would
    # describe which container was asked, not the deployment: four FAILs for the
    # Zircolite-only workflows, a NOT READY verdict, and an aborted `task quickstart` on a
    # perfectly good host.
    if (in_container or _running_in_container()) and not _docker_socket_present():
        return [
            CheckResult(
                section,
                INFO,
                "Docker daemon",
                f"not visible from this container — {len(docker_tasks)} workflow(s) need one, and only the worker mounts the socket",
                "check from the worker instead: docker compose exec -e LOGSTOTAL_ENTRYPOINT_ENV_ONLY=1 worker /docker-entrypoint.sh python3 scripts/doctor.py --in-container",
            )
        ]

    results = []
    for wf_label, (needs, total) in sorted(docker_tasks.items()):
        blocking = needs == total
        results.append(
            CheckResult(
                section,
                FAIL if blocking else WARN,
                f"Docker ({wf_label})",
                "no reachable Docker daemon"
                + ("; this workflow has no other task and will produce nothing" if blocking else f"; {total - needs} of {total} task(s) will still run"),
                "start Docker on the worker host, or remove the container task from this workflow and run `./logstotal sync-workflows` (Docker: `./logstotal docker:up`, which reloads workflows)",
            )
        )
    return results


def _workflow_limits() -> tuple[int, int]:
    """(max per-tool threads, max tools in one workflow) — DB WorkflowDef rows
    first (what jobs actually run), filesystem workflows/*.yml fallback before
    initialization. Mirrors routers/admin.py::_workflow_limits."""
    max_threads, max_tools = 1, 1
    got_db = False
    try:
        from sqlalchemy import select

        from app.database import get_sync_session
        from app.detection.workflow_runner import parse_workflow_yaml
        from app.models import WorkflowDef

        db = get_sync_session()
        try:
            rows = db.execute(select(WorkflowDef.tasks_yaml)).scalars().all()
        finally:
            db.close()
        for tasks_yaml in rows:
            try:
                tasks = parse_workflow_yaml(tasks_yaml or "")
            except Exception:
                continue
            if not tasks:
                continue
            got_db = True
            max_tools = max(max_tools, len(tasks))
            for t in tasks:
                try:
                    thr = int(t.get("threads", 1) or 1)
                except (TypeError, ValueError):
                    thr = 1
                max_threads = max(max_threads, thr)
    except Exception:
        pass
    if got_db:
        return max_threads, max_tools
    try:
        from app.yaml_utils import safe_load as yaml_safe_load

        for wf in sorted((PROJECT_ROOT / "workflows").glob("*.yml")):
            try:
                data = yaml_safe_load(wf.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            tasks = data.get("tasks") or []
            if tasks:
                max_tools = max(max_tools, len(tasks))
            for t in tasks:
                try:
                    thr = int(t.get("threads", 1) or 1)
                except (TypeError, ValueError):
                    thr = 1
                max_threads = max(max_threads, thr)
    except Exception:
        pass
    return max_threads, max_tools


def _parallel_execution_enabled() -> bool:
    """SiteSettings.parallel_execution via a sync session; False when unknowable."""
    try:
        from sqlalchemy import select

        from app.database import get_sync_session
        from app.models import SiteSettings

        db = get_sync_session()
        try:
            return bool(db.execute(select(SiteSettings.parallel_execution)).scalars().first())
        finally:
            db.close()
    except Exception:
        return False


def check_concurrency() -> list[CheckResult]:
    """CPU/RAM oversubscription per live worker host — the same peak model as
    the admin concurrency card (app/concurrency.py), surfaced as check results.
    Silent when no workers have published metadata."""
    section = "Workers"
    try:
        from app.redis_client import get_worker_concurrency_meta

        meta = get_worker_concurrency_meta()
    except Exception:
        return []
    if not meta:
        return []

    from app.concurrency import RAM_GB_PER_WORKER, compute_concurrency, detect_ram_gb

    max_threads, max_tools = _workflow_limits()
    hosts = compute_concurrency(
        meta,
        tool_max_workers=settings.tool_max_workers,
        parallel_execution=_parallel_execution_enabled(),
        max_tools_per_workflow=max_tools,
        max_workflow_threads=max_threads,
    )
    results: list[CheckResult] = []
    local_host = platform.node()
    local_ram = detect_ram_gb()
    for h in hosts:
        if h.over_provisioned:
            results.append(
                CheckResult(
                    section,
                    WARN,
                    f"CPU budget ({h.hostname})",
                    f"peak concurrency {h.effective_peak} > {h.cpu_count} cores — tools will fight for CPU",
                    f"size the knobs to the host: ./logstotal recommend-scaling -- --apply  — {docs_url('scaling.md')}",
                )
            )
        elif h.cpu_count:
            results.append(CheckResult(section, PASS, f"CPU budget ({h.hostname})", f"peak concurrency {h.effective_peak} within {h.cpu_count} cores"))
        else:
            results.append(CheckResult(section, INFO, f"CPU budget ({h.hostname})", f"peak concurrency {h.effective_peak} (cores unknown)"))
        # RAM is only knowable for THIS host — remote workers don't publish it.
        if h.hostname == local_host and local_ram:
            est_gb = h.huey_workers * RAM_GB_PER_WORKER
            if est_gb > local_ram * 0.9:
                results.append(
                    CheckResult(
                        section,
                        WARN,
                        f"RAM budget ({h.hostname})",
                        f"{h.huey_workers} concurrent job(s) x ~{RAM_GB_PER_WORKER:g} GB ≈ {est_gb:.1f} GB vs {local_ram:.1f} GB total RAM",
                        "lower HUEY_WORKERS or add RAM — ./logstotal recommend-scaling factors both ceilings",
                    )
                )
    return results


def check_sqlite_multi_worker() -> CheckResult | None:
    """SQLite with more than one worker process = write-lock contention (and it
    cannot work cross-host at all). Complements check_multi_server_config, which
    only fires for the remote-worker compose profile."""
    if "sqlite" not in (settings.sync_database_url or ""):
        return None
    try:
        from app.redis_client import get_worker_concurrency_meta

        meta = get_worker_concurrency_meta()
    except Exception:
        return None
    if len(meta) <= 1:
        return None
    hostnames = sorted({str(m.get("hostname") or "?") for m in meta})
    return CheckResult(
        "Workers",
        WARN,
        "SQLite vs workers",
        f"{len(meta)} worker processes ({', '.join(hostnames)}) share one SQLite database — write-lock contention can fail tasks under load",
        "switch to PostgreSQL (COMPOSE_PROFILES=postgres + POSTGRES_PASSWORD) before scaling worker processes",
    )


def check_queue_age() -> CheckResult | None:
    """Oldest PENDING job vs HUEY_QUEUE_EXPIRY. Queued tasks not started within
    the expiry are discarded by Huey — the matching job then sits PENDING
    forever. None when there is no pending backlog to measure."""
    try:
        from datetime import datetime

        from sqlalchemy import select

        from app.database import get_sync_session
        from app.models import AnalysisJob, JobStatus

        db = get_sync_session()
        try:
            oldest = db.execute(select(AnalysisJob.created_at).where(AnalysisJob.status == JobStatus.PENDING).order_by(AnalysisJob.created_at.asc()).limit(1)).scalars().first()
        finally:
            db.close()
    except Exception:
        return None
    if oldest is None:
        return None
    age_s = (datetime.now(UTC).replace(tzinfo=None) - oldest).total_seconds()
    expiry = settings.huey_queue_expiry
    if not expiry or age_s <= expiry * 0.8:
        return None
    age_min = int(age_s // 60)
    if age_s > expiry:
        return CheckResult(
            "Workers",
            WARN,
            "queue age",
            f"oldest PENDING job is {age_min} min old — beyond HUEY_QUEUE_EXPIRY ({expiry}s); its queued task has been discarded",
            "fail it (POST /admin/recover-stuck-jobs) and resubmit, then add workers so tasks start within the expiry",
        )
    return CheckResult(
        "Workers",
        WARN,
        "queue age",
        f"oldest PENDING job is {age_min} min old — approaching HUEY_QUEUE_EXPIRY ({expiry}s)",
        "add workers or raise HUEY_QUEUE_EXPIRY before queued tasks are discarded",
    )


def check_pg_pool_pressure() -> CheckResult | None:
    """PostgreSQL max_connections vs what the configured pools can demand:
    (worker processes + web) x (DB_POOL_SIZE + DB_MAX_OVERFLOW). None on SQLite
    or when PostgreSQL is unreachable (check_database already covers that)."""
    if "postgres" not in (settings.sync_database_url or ""):
        return None
    try:
        engine = _sync_engine()
        try:
            with engine.connect() as conn:
                max_conn = int(conn.execute(text("SHOW max_connections")).scalar() or 0)
        finally:
            engine.dispose()
    except Exception:
        return None
    if not max_conn:
        return None
    processes = 1  # the web process
    try:
        from app.redis_client import get_worker_concurrency_meta

        processes += len(get_worker_concurrency_meta())
    except Exception:
        pass
    demand = processes * (settings.db_pool_size + settings.db_max_overflow)
    if demand > max_conn * 0.8:
        return CheckResult(
            "Services",
            WARN,
            "PostgreSQL connections",
            f"{processes} process(es) x (DB_POOL_SIZE={settings.db_pool_size} + DB_MAX_OVERFLOW={settings.db_max_overflow}) = {demand} potential connections vs max_connections={max_conn}",
            "lower DB_POOL_SIZE / DB_MAX_OVERFLOW, or raise PostgreSQL max_connections",
        )
    return CheckResult("Services", PASS, "PostgreSQL connections", f"potential demand {demand} within max_connections={max_conn}")


# A verified backup older than this many days counts as stale.
BACKUP_RECEIPT_STALE_DAYS = 7


def check_backup_receipt(project_root: Path = PROJECT_ROOT) -> CheckResult:
    """Presence + freshness of the non-secret receipt `./logstotal backup` writes after
    a verified backup (backups/last-verified.json). Never reads backup contents."""
    from datetime import datetime

    section = "Backups"
    backups_dir = project_root / "backups"
    receipt_path = backups_dir / "last-verified.json"
    # "I cannot see backups/" and "there is no receipt in it" are different facts, and
    # reporting the first as the second is a false alarm on a correctly backed-up
    # deployment. The worker container deliberately does not mount backups/ — it runs
    # detection tools over uploaded files, and database dumps are not something to put
    # within its reach — yet check_docker_tools sends operators there to run the doctor,
    # because it is the container with the Docker socket.
    if not backups_dir.is_dir():
        return CheckResult(
            section,
            INFO,
            "verified backup",
            "backups/ is not visible from here, so the receipt cannot be checked",
            "check from the host (./logstotal doctor) or the web container (./logstotal doctor:docker) — the worker does not mount backups/ by design",
        )
    if not receipt_path.exists():
        return CheckResult(
            section,
            WARN,
            "verified backup",
            "no verified-backup receipt found (backups/last-verified.json)",
            "run: ./logstotal backup — it dumps, verifies the exact artifact, and writes the receipt",
        )
    try:
        from app.json_utils import loads

        receipt = loads(receipt_path.read_text(encoding="utf-8"))
        verified_at = datetime.fromisoformat(str(receipt.get("verified_at")))
        if verified_at.tzinfo is None:
            verified_at = verified_at.replace(tzinfo=UTC)
        backend = receipt.get("backend", "?")
        artifact = receipt.get("artifact", "?")
    except Exception:
        return CheckResult(section, WARN, "verified backup", "receipt exists but could not be parsed", "re-run: ./logstotal backup")
    age_days = (datetime.now(UTC) - verified_at).total_seconds() / 86400
    detail = f"{backend} backup '{artifact}' verified {verified_at:%Y-%m-%d %H:%M} UTC"
    if age_days > BACKUP_RECEIPT_STALE_DAYS:
        return CheckResult(
            section,
            WARN,
            "verified backup",
            f"{detail} — {age_days:.0f} days ago",
            f"run ./logstotal backup and schedule it (cron example: {docs_url('runbooks/backup-and-restore.md')})",
        )
    return CheckResult(section, PASS, "verified backup", detail)


def summarize(results: list[CheckResult]) -> dict:
    """Aggregate readiness verdict — shared by scripts/doctor.py and the admin
    dashboard so the CLI and the UI can never disagree on what "ready" means.

    Returns {status, label, passed, warned, failed, info, top_fixes} where
    status is one of ready | ready_warn | not_ready and top_fixes lists the
    highest-priority CheckResults (FAILs first, then WARNs)."""
    counts = {PASS: 0, WARN: 0, FAIL: 0, INFO: 0}
    for r in results:
        counts[r.level] = counts.get(r.level, 0) + 1
    if counts[FAIL]:
        status, label = "not_ready", "Not ready"
    elif counts[WARN]:
        status, label = "ready_warn", "Ready with warnings"
    else:
        status, label = "ready", "Ready"
    fixes = [r for r in results if r.level == FAIL] + [r for r in results if r.level == WARN]
    return {
        "status": status,
        "label": label,
        "passed": counts[PASS],
        "warned": counts[WARN],
        "failed": counts[FAIL],
        "info": counts[INFO],
        "top_fixes": fixes[:3],
    }


def run_all() -> list[CheckResult]:
    """Everything the admin System Status card shows, in display order."""
    results: list[CheckResult] = []
    results.extend(check_production_config())
    results.extend(check_proxy_config())
    results.extend(check_multi_server_config())
    results.extend(check_bundled_service_config())
    results.append(check_default_admin_password())
    results.append(check_migration_state())
    results.append(check_database())
    results.append(check_redis())
    results.append(check_redis_eviction())
    results.append(check_storage())
    results.extend(check_workers())
    results.extend(check_concurrency())
    for optional in (check_sqlite_multi_worker(), check_queue_age(), check_pg_pool_pressure()):
        if optional is not None:
            results.append(optional)
    results.append(check_backup_receipt())
    results.append(check_host_os())
    results.extend(check_disk())
    results.extend(check_tool_binaries())
    results.extend(check_docker_tools())
    return results


# How long a completed suite is reused. Deliberately a module constant, not a Settings
# field: this is UI de-duplication, not deployment policy, and a knob here would owe
# .env.example a line and docs/configuration.md a row for nothing.
#
# Sized for a browsing session, not a page load. The Overview tab's readiness chip runs the
# suite when /admin loads; the System tab's card is behind
# `hx-trigger="loadSystemChecks from:body once"`, so it fires whenever the admin gets round
# to clicking through — and a short window would make that click pay for a second full run
# of a storage probe, an Argon2 verify per superuser and a `docker info` that can block for ten.
#
# Nothing here goes stale silently: the card renders "Checked <n> ago" from `ran_at`, and
# "Re-run checks" sends `?force=1`, which is the only way past this cache.
CHECK_CACHE_TTL_SECONDS = 300.0

_cache_lock = threading.Lock()
_cache: tuple[float, list[CheckResult]] | None = None


def run_all_cached(*, force: bool = False, stale_ok: bool = False) -> tuple[list[CheckResult], float]:
    """`run_all()` plus reuse. Returns (results, ran_at_epoch).

    One `/admin` load asks for this suite twice — the Overview tab's readiness verdict and
    the System tab's card are the same `run_all()` — and the suite is not cheap: a storage
    probe, a `docker info` that can block for ten seconds, and an Argon2 verify per
    superuser. Sharing one result is the difference between one wait and two.

    **`stale_ok` is the rule for anything a click can reach.** Opening the System tab must
    never *start* a run, however old the last one is — that is what the "Re-run checks"
    button is for, and it is right there with the timestamp beside it. A TTL cannot express
    this: whatever the window, browsing past it turns a navigation into a ten-second wait for
    a `docker info`. So the System card passes
    `stale_ok=True` and shows whatever exists; only an empty cache makes it run, and by then
    the Overview readiness chip (`hx-trigger="load"`, every page load) has almost always
    filled it. The TTL still governs that chip — a fresh visit to `/admin` deserves fresh
    checks; a tab switch does not.

    The lock is doing as much work as the TTL. "Re-run checks" is a plain button with no
    debounce, so without it an impatient double-click starts a second full suite while the
    first is still in `docker info`; with it, the second caller waits and takes the first
    caller's answer.

    Process-local on purpose. Under several uvicorn workers each warms its own copy, which
    is fine — the goal is to stop one page load running the suite twice, not to establish a
    single cluster-wide truth. `run_all()` itself stays untouched so `scripts/doctor.py`
    and the parity test that compares the two enumerations are unaffected.
    """
    global _cache
    with _cache_lock:
        if not force and _cache is not None:
            ran_at, results = _cache
            if stale_ok or (time.time() - ran_at) < CHECK_CACHE_TTL_SECONDS:
                return results, ran_at
        results = run_all()
        ran_at = time.time()
        _cache = (ran_at, results)
        return results, ran_at


def reset_check_cache() -> None:
    """Drop the memoised suite. For tests, and for any caller that changes deployment state."""
    global _cache
    with _cache_lock:
        _cache = None
