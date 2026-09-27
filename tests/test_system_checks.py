"""Tests for app/system_checks.py — shared deployment/health checks."""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC
from pathlib import Path

import pytest

from app import system_checks
from app.system_checks import FAIL, INFO, PASS, WARN


@pytest.fixture(autouse=True)
def _leave_the_check_cache_empty():
    """Whoever poisons the shared cache cleans it — on the way OUT, not just in.

    `run_all_cached`'s cache is module-level and process-local, and the tests below fill it
    by monkeypatching `run_all` to return a sentinel like ["r"]. monkeypatch restores the
    function at teardown; it cannot know about the value that function already put in the
    cache. So the sentinel outlived this module.

    That was not theoretical. pytest runs with `-n auto --dist loadfile`, so another test
    FILE shares this worker process, and `/admin/system-checks-partial` passes
    `stale_ok=True` — by design, so opening the System tab never starts a ten-second
    `docker info`. stale_ok serves the cached value at ANY age, which is exactly what made
    the poisoned entry reachable: `summarize(["r"])` raised
    `AttributeError: 'str' object has no attribute 'level'` and the route 500'd.

    It surfaced only when an unrelated commit added tests elsewhere and reshuffled which
    files share a worker — the failure was a property of the pair, not of either file, so
    both passed alone and the suite failed. Reproduced on untouched main with
    `pytest tests/test_system_checks.py tests/test_integration_routes.py`.
    """
    system_checks.reset_check_cache()
    yield
    system_checks.reset_check_cache()


# ── Storage ───────────────────────────────────────────────────────────────────


def test_storage_local_writable(monkeypatch, tmp_path):
    from app.config import settings

    monkeypatch.setattr(settings, "storage_backend", "local")
    monkeypatch.setattr(settings, "upload_dir", tmp_path / "uploads")
    result = system_checks.check_storage()
    assert result.level == PASS
    assert "writable" in result.message
    # The probe must not leave files behind.
    assert list((tmp_path / "uploads").iterdir()) == []


def test_storage_local_unwritable(monkeypatch, tmp_path):
    from app.config import settings

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    upload_dir.chmod(0o500)
    monkeypatch.setattr(settings, "storage_backend", "local")
    monkeypatch.setattr(settings, "upload_dir", upload_dir)
    try:
        result = system_checks.check_storage()
    finally:
        upload_dir.chmod(0o700)
    assert result.level == FAIL
    assert result.fix


def test_storage_s3_error(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "storage_backend", "s3")

    def _boom():
        raise RuntimeError("no bucket for you")

    import app.storage as storage_mod

    monkeypatch.setattr(storage_mod, "get_storage", _boom)
    result = system_checks.check_storage()
    assert result.level == FAIL
    assert "s3" in result.message


# ── Database ─────────────────────────────────────────────────────────────────


def test_database_ok():
    result = system_checks.check_database()
    assert result.level == PASS


def test_database_unreachable(monkeypatch, tmp_path):
    from app.config import settings

    monkeypatch.setattr(settings, "sync_database_url", f"sqlite:///{tmp_path}/no/such/dir/x.db")
    result = system_checks.check_database()
    assert result.level == FAIL
    assert result.fix


# ── Redis / workers ──────────────────────────────────────────────────────────


def test_redis_ok(fake_redis):
    assert system_checks.check_redis().level == PASS


def test_redis_down(monkeypatch):
    import app.redis_client as rc

    def _boom():
        raise ConnectionError("refused")

    monkeypatch.setattr(rc, "get_redis", _boom)
    result = system_checks.check_redis()
    assert result.level == FAIL


def test_workers_none_alive_warns(fake_redis):
    results = system_checks.check_workers()
    worker_result = next(r for r in results if r.name == "workers")
    assert worker_result.level in (WARN, FAIL)
    assert "./logstotal worker" in worker_result.fix


def test_workers_alive(fake_redis):
    from app.redis_client import WORKER_ALIVE_PREFIX

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host1", "1")
    results = system_checks.check_workers()
    worker_result = next(r for r in results if r.name == "workers")
    assert worker_result.level == PASS
    assert "1 alive" in worker_result.message


# ── Migration state ──────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_db(monkeypatch, tmp_path, fake_redis):
    from app.config import settings

    db_path = tmp_path / "checks_test.db"
    monkeypatch.setattr(settings, "sync_database_url", f"sqlite:///{db_path}")
    monkeypatch.setattr(settings, "auto_migrate", True)
    return db_path


def test_migration_state_fresh(tmp_db):
    result = system_checks.check_migration_state()
    assert result.level == INFO
    assert "no schema yet" in result.message


def test_migration_state_at_head(tmp_db):
    from app.migrations import run_auto_migrate

    run_auto_migrate()
    result = system_checks.check_migration_state()
    assert result.level == PASS


def test_migration_state_behind(tmp_db):
    from alembic import command
    from app.migrations import _alembic_config

    command.upgrade(_alembic_config(), "09db4ba71a7c")
    result = system_checks.check_migration_state()
    assert result.level == FAIL
    assert "pending" in result.message
    assert "app.migrations" in result.fix


def test_migration_state_unmanaged(tmp_db):
    """create_all + drift → adoption blocked → unmanaged WARN with remedy."""
    from sqlalchemy import create_engine, text

    import app.models  # noqa: F401
    from app.database import Base
    from app.migrations import run_auto_migrate

    engine = create_engine(f"sqlite:///{tmp_db}")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE stray_leftover (id INTEGER PRIMARY KEY)"))
    engine.dispose()
    run_auto_migrate()

    result = system_checks.check_migration_state()
    assert result.level == WARN
    assert "db:stamp" in result.fix


# ── Production config ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("debug", "cookie_insecure", "profiles", "proxy_tls", "expect_warn"),
    [
        (True, False, "", "acme", False),  # debug → cookies not Secure → no footgun
        (False, True, "", "acme", False),  # operator opted into HTTP cookies
        (False, False, "", "acme", True),  # Secure cookies, no HTTPS proxy → footgun
        (False, False, "proxy", "acme", False),  # HTTPS via Caddy profile
        (False, False, "proxy", "internal", False),  # Caddy's own CA is still TLS
        (False, False, "proxy", "custom", False),  # so is an operator's own certificate
        # The whole reason this check stopped reasoning from the profile alone: with
        # PROXY_TLS=off, Caddy is in front on plain HTTP, so a Secure cookie is dropped
        # exactly as it would be with no proxy at all.
        (False, False, "proxy", "off", True),
        # `proxy` is matched as a comma-separated profile, not a substring — a substring
        # match would read this as "HTTPS is configured".
        (False, False, "myproxy", "acme", True),
    ],
)
def test_cookie_http_footgun_matrix(monkeypatch, debug, cookie_insecure, profiles, proxy_tls, expect_warn):
    from app.config import settings

    monkeypatch.setattr(settings, "debug", debug)
    monkeypatch.setattr(settings, "cookie_insecure", cookie_insecure)
    monkeypatch.setattr(settings, "compose_profiles", profiles)
    monkeypatch.setattr(settings, "proxy_tls", proxy_tls)
    results = system_checks.check_production_config()
    footgun = [r for r in results if r.name == "cookies vs HTTP"]
    assert bool(footgun) == expect_warn


def test_production_errors_reported_as_fail(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "debug", False)
    monkeypatch.setattr(settings, "disable_csp", True)
    monkeypatch.delenv("I_ACCEPT_DISABLE_CSP_IN_PROD", raising=False)
    results = system_checks.check_production_config()
    fails = [r for r in results if r.level == FAIL]
    assert fails, "production_errors() conditions must surface as FAIL"
    assert "REFUSE TO START" in fails[0].fix


# ── Proxy config ─────────────────────────────────────────────────────────────

DEFAULT_LOOPBACK_CIDRS = "127.0.0.1/32,::1/128"


@pytest.mark.parametrize(
    ("trust", "cidrs", "profiles", "expect_cidr_warn"),
    [
        (True, DEFAULT_LOOPBACK_CIDRS, "proxy", True),  # all three conditions → WARN
        (False, DEFAULT_LOOPBACK_CIDRS, "proxy", False),  # headers not trusted → no WARN
        (True, "172.18.0.0/16", "proxy", False),  # real CIDR set → no WARN
        (True, "", "proxy", True),  # empty CIDRs count as loopback-only → WARN
        (True, DEFAULT_LOOPBACK_CIDRS, "", False),  # no proxy profile → silent
    ],
)
def test_proxy_cidr_warn_matrix(monkeypatch, trust, cidrs, profiles, expect_cidr_warn):
    from app.config import settings

    monkeypatch.setattr(settings, "trust_proxy_headers", trust)
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", cidrs)
    monkeypatch.setattr(settings, "compose_profiles", profiles)
    monkeypatch.setattr(settings, "enable_hsts", True)  # isolate the CIDR warning
    results = system_checks.check_proxy_config()
    cidr = [r for r in results if r.name == "proxy client IP"]
    assert bool(cidr) == expect_cidr_warn
    if expect_cidr_warn:
        assert cidr[0].level == WARN
        assert "docker network inspect logstotal_default" in cidr[0].fix


def test_proxy_hsts_off_behind_proxy_warns(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "compose_profiles", "proxy")
    monkeypatch.setattr(settings, "proxy_tls", "acme")
    monkeypatch.setattr(settings, "enable_hsts", False)
    monkeypatch.setattr(settings, "trust_proxy_headers", False)
    results = system_checks.check_proxy_config()
    hsts = [r for r in results if r.name == "HSTS"]
    assert hsts and hsts[0].level == WARN


@pytest.mark.parametrize(("enable_hsts", "expect_warn"), [(False, False), (True, True)])
def test_hsts_advice_inverts_when_the_proxy_serves_plain_http(monkeypatch, enable_hsts, expect_warn):
    """PROXY_TLS=off makes the usual HSTS advice backwards.

    Telling an operator to switch on a header browsers ignore over HTTP is noise; the state
    that actually hurts is HSTS left on from a previous HTTPS configuration, which pins
    every browser that saw it into refusing the site now that it is plain HTTP.
    """
    from app.config import settings

    monkeypatch.setattr(settings, "compose_profiles", "proxy")
    monkeypatch.setattr(settings, "proxy_tls", "off")
    monkeypatch.setattr(settings, "enable_hsts", enable_hsts)
    monkeypatch.setattr(settings, "trust_proxy_headers", False)
    hsts = [r for r in system_checks.check_proxy_config() if r.name == "HSTS"]
    assert bool(hsts) == expect_warn
    if expect_warn:
        assert hsts[0].level == WARN
        assert "PROXY_TLS=off" in hsts[0].message


def test_proxy_no_profile_is_silent(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "compose_profiles", "postgres,s3")
    monkeypatch.setattr(settings, "enable_hsts", False)
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    assert system_checks.check_proxy_config() == []


def test_proxy_coherent_config_passes(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "compose_profiles", "proxy")
    monkeypatch.setattr(settings, "proxy_tls", "acme")
    monkeypatch.setattr(settings, "enable_hsts", True)
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "172.18.0.0/16")
    results = system_checks.check_proxy_config()
    assert len(results) == 1
    assert results[0].level == PASS


# ── Redis eviction policy ────────────────────────────────────────────────────


class _FakeRedisConfig:
    def __init__(self, policy):
        self._policy = policy

    def config_get(self, key):
        return {"maxmemory-policy": self._policy}


def test_redis_eviction_warns_on_lru(monkeypatch):
    import app.redis_client as rc

    monkeypatch.setattr(rc, "get_redis", lambda: _FakeRedisConfig("allkeys-lru"))
    result = system_checks.check_redis_eviction()
    assert result.level == WARN
    assert "allkeys-lru" in result.message
    assert result.fix


def test_redis_eviction_pass_on_noeviction(monkeypatch):
    import app.redis_client as rc

    monkeypatch.setattr(rc, "get_redis", lambda: _FakeRedisConfig("noeviction"))
    assert system_checks.check_redis_eviction().level == PASS


def test_redis_eviction_info_when_config_unavailable(fake_redis):
    # fakeredis has no CONFIG GET support → ResponseError → INFO, never raises.
    result = system_checks.check_redis_eviction()
    assert result.level == INFO


# ── Queue backlog escalation ─────────────────────────────────────────────────


def test_workers_queue_backlog_warns(fake_redis, monkeypatch):
    from app.redis_client import WORKER_ALIVE_PREFIX

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host1", "1")
    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=0: {"queue_size": 26, "items": [], "error": None})
    results = system_checks.check_workers()
    depth = next(r for r in results if r.name == "queue depth")
    assert depth.level == WARN
    assert depth.fix


def test_workers_queue_backlog_below_threshold_is_info(fake_redis, monkeypatch):
    from app.redis_client import WORKER_ALIVE_PREFIX

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host1", "1")
    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=0: {"queue_size": 5, "items": [], "error": None})
    results = system_checks.check_workers()
    depth = next(r for r in results if r.name == "queue depth")
    assert depth.level == INFO


# ── Multi-server config ──────────────────────────────────────────────────────


def test_multi_server_config_wraps_warnings(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "compose_profiles", "postgres,s3,workers")
    monkeypatch.setattr(settings, "database_url", "sqlite+aiosqlite:////data/logstotal.db")
    monkeypatch.setattr(settings, "storage_backend", "local")
    monkeypatch.setattr(settings, "redis_expose", "10.0.0.1:6379")
    monkeypatch.setattr(settings, "postgres_expose", None)
    monkeypatch.setattr(settings, "garage_expose", None)
    results = system_checks.check_multi_server_config()
    assert results
    assert all(r.level == WARN and r.section == "Configuration" for r in results)
    assert any("STORAGE_BACKEND=s3" in r.message for r in results)


def test_multi_server_config_silent_when_single_host(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "compose_profiles", "")
    monkeypatch.setattr(settings, "redis_expose", None)
    assert system_checks.check_multi_server_config() == []


def test_multi_server_config_pass_when_coherent(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "compose_profiles", "postgres,s3,workers")
    monkeypatch.setattr(settings, "database_url", "postgresql+asyncpg://x/y")
    monkeypatch.setattr(settings, "storage_backend", "s3")
    monkeypatch.setattr(settings, "redis_expose", "10.0.0.1:6379")
    monkeypatch.setattr(settings, "postgres_expose", "10.0.0.1:5432")
    monkeypatch.setattr(settings, "garage_expose", "10.0.0.1:3900")
    results = system_checks.check_multi_server_config()
    assert len(results) == 1
    assert results[0].level == PASS


# ── Bundled-service gate (COMPOSE_PROFILES is the reference) ──────────────────


def _setup_bundled(monkeypatch, *, profiles="", database_url="sqlite+aiosqlite:///./logstotal.db", storage_backend="local", s3_endpoint=None, pg_password=None, pg_host=None):
    from app.config import settings

    monkeypatch.setattr(settings, "compose_profiles", profiles)
    monkeypatch.setattr(settings, "database_url", database_url)
    monkeypatch.setattr(settings, "storage_backend", storage_backend)
    monkeypatch.setattr(settings, "s3_endpoint", s3_endpoint)
    for var, val in (("POSTGRES_PASSWORD", pg_password), ("POSTGRES_HOST", pg_host)):
        if val is None:
            monkeypatch.delenv(var, raising=False)
        else:
            monkeypatch.setenv(var, val)


def test_bundled_postgres_password_without_profile_warns(monkeypatch):
    """The user repro: POSTGRES_PASSWORD + proxy profile (no postgres) → WARN."""
    _setup_bundled(monkeypatch, profiles="proxy", pg_password="pw")
    results = system_checks.check_bundled_service_config()
    pg = [r for r in results if r.name == "postgres profile"]
    assert pg and pg[0].level == WARN
    assert "COMPOSE_PROFILES" in pg[0].fix


def test_bundled_postgres_password_with_profile_is_silent(monkeypatch):
    _setup_bundled(monkeypatch, profiles="postgres", pg_password="pw")
    assert [r for r in system_checks.check_bundled_service_config() if r.name == "postgres profile"] == []


def test_bundled_postgres_password_with_external_host_is_silent(monkeypatch):
    _setup_bundled(monkeypatch, profiles="proxy", pg_password="pw", pg_host="db.internal")
    assert [r for r in system_checks.check_bundled_service_config() if r.name == "postgres profile"] == []


def test_bundled_postgres_explicit_url_is_silent(monkeypatch):
    """Explicit postgres DATABASE_URL is the escape hatch — no warning even with a password and no profile."""
    _setup_bundled(monkeypatch, profiles="", database_url="postgresql+asyncpg://u:p@db/x", pg_password="pw")
    assert [r for r in system_checks.check_bundled_service_config() if r.name == "postgres profile"] == []


def test_bundled_no_postgres_password_is_silent(monkeypatch):
    _setup_bundled(monkeypatch, profiles="proxy", pg_password=None)
    assert [r for r in system_checks.check_bundled_service_config() if r.name == "postgres profile"] == []


def test_bundled_s3_without_profile_or_endpoint_fails(monkeypatch):
    _setup_bundled(monkeypatch, profiles="proxy", storage_backend="s3", s3_endpoint=None)
    results = system_checks.check_bundled_service_config()
    s3 = [r for r in results if r.name == "s3 storage profile"]
    assert s3 and s3[0].level == FAIL
    assert s3[0].fix


def test_bundled_s3_with_bundled_default_endpoint_fails(monkeypatch):
    """S3_ENDPOINT still pointing at the in-network Garage default, no s3 profile → FAIL."""
    _setup_bundled(monkeypatch, profiles="proxy", storage_backend="s3", s3_endpoint="http://garage:3900")
    s3 = [r for r in system_checks.check_bundled_service_config() if r.name == "s3 storage profile"]
    assert s3 and s3[0].level == FAIL


def test_bundled_s3_with_profile_is_silent(monkeypatch):
    _setup_bundled(monkeypatch, profiles="s3", storage_backend="s3", s3_endpoint=None)
    assert [r for r in system_checks.check_bundled_service_config() if r.name == "s3 storage profile"] == []


def test_bundled_s3_with_external_endpoint_is_silent(monkeypatch):
    _setup_bundled(monkeypatch, profiles="proxy", storage_backend="s3", s3_endpoint="https://s3.us-east-1.amazonaws.com")
    assert [r for r in system_checks.check_bundled_service_config() if r.name == "s3 storage profile"] == []


def test_bundled_local_storage_is_silent(monkeypatch):
    _setup_bundled(monkeypatch, profiles="proxy", storage_backend="local")
    assert [r for r in system_checks.check_bundled_service_config() if r.name == "s3 storage profile"] == []


# ── Default admin password ───────────────────────────────────────────────────


def _seed_superuser(tmp_path, plaintext):
    from fastapi_users.password import PasswordHelper
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.models  # noqa: F401
    from app.database import Base
    from app.models import User

    engine = create_engine(f"sqlite:///{tmp_path}/pw.db")
    Base.metadata.create_all(engine)
    Session = sessionmaker(engine)
    session = Session()
    session.add(User(email="admin@example.com", hashed_password=PasswordHelper().hash(plaintext), is_superuser=True))
    session.commit()
    session.close()
    return Session


def test_default_admin_password_warns(monkeypatch, tmp_path):
    import app.database as db_mod

    session_factory = _seed_superuser(tmp_path, "changeme123")
    monkeypatch.setattr(db_mod, "get_sync_session", lambda: session_factory())
    result = system_checks.check_default_admin_password()
    assert result.level == WARN
    assert result.fix


def test_default_admin_password_strong_passes(monkeypatch, tmp_path):
    import app.database as db_mod

    session_factory = _seed_superuser(tmp_path, "a-very-strong-unique-passphrase")
    monkeypatch.setattr(db_mod, "get_sync_session", lambda: session_factory())
    result = system_checks.check_default_admin_password()
    assert result.level == PASS


def test_default_admin_password_db_error_is_info(monkeypatch):
    import app.database as db_mod

    def _boom():
        raise RuntimeError("no such table: user")

    monkeypatch.setattr(db_mod, "get_sync_session", _boom)
    result = system_checks.check_default_admin_password()
    assert result.level == INFO


# ── Tool binary executability ────────────────────────────────────────────────


def _write_tool_workflow(tmp_path, mode):
    from app.system_checks import _arch_key

    (tmp_path / "workflows").mkdir()
    binp = tmp_path / "tools" / "mytool" / "bin"
    binp.parent.mkdir(parents=True)
    binp.write_text("#!/bin/sh\necho hi\n")
    binp.chmod(mode)
    (tmp_path / "workflows" / "wf.yml").write_text(f"tasks:\n  - tool: mytool\n    tool_path:\n      {_arch_key()}: tools/mytool/bin\n")


def _write_two_task_workflow(tmp_path, mode):
    """A workflow where one task's binary is broken but another task can still run."""
    from app.system_checks import _arch_key

    (tmp_path / "workflows").mkdir()
    binp = tmp_path / "tools" / "mytool" / "bin"
    binp.parent.mkdir(parents=True)
    binp.write_text("#!/bin/sh\necho hi\n")
    binp.chmod(mode)
    (tmp_path / "workflows" / "wf.yml").write_text(
        f"tasks:\n  - tool: mytool\n    tool_path:\n      {_arch_key()}: tools/mytool/bin\n  - tool: other\n    docker_image: example:latest\n"
    )


def test_a_broken_binary_in_a_single_task_workflow_fails(tmp_path):
    """Symmetric with `check_docker_tools`: sole task unavailable means the workflow is dead.

    The two checks must agree. If a missing *container* blocks but a missing *binary* only
    warns, then on `aarch64-darwin` `linux_syslog.yml` (ChopChopGo, no macOS build, one
    task) produces nothing while the verdict still reads READY.
    """
    _write_tool_workflow(tmp_path, 0o644)
    results = system_checks.check_tool_binaries(project_root=tmp_path)
    r = next(r for r in results if r.name == "mytool (wf.yml)")
    assert r.level == FAIL, "a workflow whose only task cannot run must not pass preflight"
    assert "not executable" in r.message
    assert "produce nothing" in r.message
    assert "chmod +x" in r.fix


def test_a_broken_binary_beside_another_task_only_warns(tmp_path):
    """Degradation, not failure — the other task still produces findings."""
    _write_two_task_workflow(tmp_path, 0o644)
    results = system_checks.check_tool_binaries(project_root=tmp_path)
    r = next(r for r in results if r.name == "mytool (wf.yml)")
    assert r.level == WARN
    assert "skipped on this host" in r.message


def test_tool_binary_executable_passes(tmp_path):
    _write_tool_workflow(tmp_path, 0o755)
    results = system_checks.check_tool_binaries(project_root=tmp_path)
    r = next(r for r in results if r.name == "mytool (wf.yml)")
    assert r.level == PASS


# ── run_all / doctor wiring ──────────────────────────────────────────────────


def test_run_all_returns_results(fake_redis, monkeypatch, tmp_path):
    from app.config import settings

    monkeypatch.setattr(settings, "upload_dir", tmp_path / "uploads")
    monkeypatch.setattr(settings, "sync_database_url", f"sqlite:///{tmp_path}/run_all.db")
    results = system_checks.run_all()
    assert results
    sections = {r.section for r in results}
    assert {"Database schema", "Services", "Workers"} <= sections
    assert all(r.level in (PASS, WARN, FAIL, INFO) for r in results)


def test_doctor_cli_help_includes_in_container():
    """The doctor script parses --in-container (wiring smoke test, no env needed)."""
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "doctor.py"), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "--in-container" in proc.stdout


# ── Concurrency / capacity checks ────────────────────────────────────────────


def _patch_worker_meta(monkeypatch, meta):
    import app.redis_client as redis_client

    monkeypatch.setattr(redis_client, "get_worker_concurrency_meta", lambda: meta)


def test_concurrency_no_workers_is_silent(monkeypatch):
    _patch_worker_meta(monkeypatch, [])
    assert system_checks.check_concurrency() == []


def test_concurrency_overprovision_warns(monkeypatch):
    _patch_worker_meta(monkeypatch, [{"hostname": "box", "huey_workers": "8", "cpu_count": "4"}])
    monkeypatch.setattr(system_checks, "_workflow_limits", lambda: (2, 3))
    monkeypatch.setattr(system_checks, "_parallel_execution_enabled", lambda: False)
    results = system_checks.check_concurrency()
    cpu = [r for r in results if r.name.startswith("CPU budget")]
    assert cpu and cpu[0].level == WARN
    assert "recommend-scaling" in cpu[0].fix


def test_concurrency_within_budget_passes(monkeypatch):
    _patch_worker_meta(monkeypatch, [{"hostname": "box", "huey_workers": "2", "cpu_count": "8"}])
    monkeypatch.setattr(system_checks, "_workflow_limits", lambda: (2, 3))
    monkeypatch.setattr(system_checks, "_parallel_execution_enabled", lambda: False)
    results = system_checks.check_concurrency()
    assert any(r.level == PASS and r.name.startswith("CPU budget") for r in results)


def test_sqlite_multi_worker_warns(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "sync_database_url", "sqlite:///./x.db")
    _patch_worker_meta(monkeypatch, [{"hostname": "a"}, {"hostname": "b"}])
    result = system_checks.check_sqlite_multi_worker()
    assert result is not None and result.level == WARN
    assert "PostgreSQL" in result.fix


def test_sqlite_single_worker_is_silent(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "sync_database_url", "sqlite:///./x.db")
    _patch_worker_meta(monkeypatch, [{"hostname": "a"}])
    assert system_checks.check_sqlite_multi_worker() is None


def test_postgres_multi_worker_is_silent(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "sync_database_url", "postgresql+psycopg2://u:p@h/db")
    assert system_checks.check_sqlite_multi_worker() is None


class _FakeScalarResult:
    def __init__(self, value):
        self._value = value

    def scalars(self):
        return self

    def first(self):
        return self._value


class _FakeSession:
    def __init__(self, value):
        self._value = value

    def execute(self, *_args, **_kwargs):
        return _FakeScalarResult(self._value)

    def close(self):
        pass


def test_queue_age_beyond_expiry_warns(monkeypatch):
    from datetime import datetime, timedelta

    import app.database as database
    from app.config import settings

    stale = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=2)
    monkeypatch.setattr(database, "get_sync_session", lambda: _FakeSession(stale))
    monkeypatch.setattr(settings, "huey_queue_expiry", 1800)
    result = system_checks.check_queue_age()
    assert result is not None and result.level == WARN
    assert "discarded" in result.message


def test_queue_age_no_pending_is_silent(monkeypatch):
    import app.database as database

    monkeypatch.setattr(database, "get_sync_session", lambda: _FakeSession(None))
    assert system_checks.check_queue_age() is None


def test_queue_age_fresh_pending_is_silent(monkeypatch):
    from datetime import datetime

    import app.database as database
    from app.config import settings

    fresh = datetime.now(UTC).replace(tzinfo=None)
    monkeypatch.setattr(database, "get_sync_session", lambda: _FakeSession(fresh))
    monkeypatch.setattr(settings, "huey_queue_expiry", 1800)
    assert system_checks.check_queue_age() is None


# ── Backup receipt + readiness summary ───────────────────────────────────────


def test_backup_receipt_missing_warns(tmp_path):
    (tmp_path / "backups").mkdir()
    result = system_checks.check_backup_receipt(project_root=tmp_path)
    assert result.level == WARN
    assert "./logstotal backup" in result.fix


def test_backups_not_visible_is_information_not_a_warning(tmp_path):
    """ "I cannot see backups/" and "there is no receipt in it" are different facts.

    The worker container deliberately does not mount backups/ — it runs detection tools
    over uploaded files, and database dumps are not something to put within its reach —
    yet check_docker_tools sends operators to run the doctor there, because it is the
    container holding the Docker socket. Reporting the first as the second made a
    correctly backed-up deployment look unprotected whenever anyone followed that advice.
    """
    result = system_checks.check_backup_receipt(project_root=tmp_path)
    assert result.level == INFO
    assert "not visible from here" in result.message
    assert "./logstotal doctor:docker" in result.fix


def test_backup_receipt_fresh_passes(tmp_path):
    from datetime import UTC, datetime

    backups = tmp_path / "backups"
    backups.mkdir()
    now = datetime.now(UTC).isoformat(timespec="seconds")
    (backups / "last-verified.json").write_text(
        f'{{"backend": "sqlite", "artifact": "x.db", "verified_at": "{now}"}}',
        encoding="utf-8",
    )
    result = system_checks.check_backup_receipt(project_root=tmp_path)
    assert result.level == PASS
    assert "x.db" in result.message


def test_backup_receipt_stale_warns(tmp_path):
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / "last-verified.json").write_text(
        '{"backend": "postgres", "artifact": "y.sql.gz", "verified_at": "2020-01-01T00:00:00+00:00"}',
        encoding="utf-8",
    )
    result = system_checks.check_backup_receipt(project_root=tmp_path)
    assert result.level == WARN
    assert "2020-01-01" in result.message


def test_backup_receipt_unparseable_warns(tmp_path):
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / "last-verified.json").write_text("not json", encoding="utf-8")
    result = system_checks.check_backup_receipt(project_root=tmp_path)
    assert result.level == WARN


def _cr(level):
    return system_checks.CheckResult("S", level, "n", "m", "f")


def test_summarize_ready():
    summary = system_checks.summarize([_cr(PASS), _cr(INFO)])
    assert summary["status"] == "ready"
    assert summary["passed"] == 1 and summary["failed"] == 0
    assert summary["top_fixes"] == []


def test_summarize_ready_with_warnings():
    summary = system_checks.summarize([_cr(PASS), _cr(WARN)])
    assert summary["status"] == "ready_warn"
    assert summary["warned"] == 1
    assert len(summary["top_fixes"]) == 1


def test_summarize_not_ready_puts_fails_first():
    summary = system_checks.summarize([_cr(WARN), _cr(FAIL), _cr(WARN), _cr(WARN)])
    assert summary["status"] == "not_ready"
    assert summary["top_fixes"][0].level == FAIL
    assert len(summary["top_fixes"]) == 3


# ── doctor and run_all must stay wired together ─────────────────────────────


def test_doctor_runs_every_check_that_run_all_runs():
    """`scripts/doctor.py` enumerates checks explicitly instead of calling `run_all()`.

    That is deliberate (doctor adds host-only checks and orders output for a human), but
    it means a check added to `run_all` and not to doctor silently never runs for the
    operator who types `task doctor` — and vice versa for `/admin/system-checks-partial`.
    """
    import inspect
    import re
    from pathlib import Path

    from app import system_checks

    root = Path(__file__).resolve().parent.parent
    in_run_all = set(re.findall(r"\b(check_\w+)\(", inspect.getsource(system_checks.run_all)))
    in_doctor = set(re.findall(r"system_checks\.(check_\w+)", (root / "scripts" / "doctor.py").read_text(encoding="utf-8")))

    assert in_run_all, "could not parse any checks out of run_all()"
    missing_from_doctor = sorted(in_run_all - in_doctor)
    missing_from_run_all = sorted(in_doctor - in_run_all)

    assert not missing_from_doctor, f"run_all() runs these but `task doctor` does not: {missing_from_doctor}"
    assert not missing_from_run_all, f"doctor runs these but run_all() does not (so /admin never shows them): {missing_from_run_all}"


# ── Docker-dependent workflows ──────────────────────────────────────────────


def _wf_dir(tmp_path, **files):
    root = tmp_path / "proj"
    (root / "workflows").mkdir(parents=True)
    for name, body in files.items():
        (root / "workflows" / name).write_text(body, encoding="utf-8")
    return root


ZIRCOLITE_ONLY = """
name: Windows
log_types: [evtx]
tasks:
  - tool: zircolite
    docker_image: wagga40/zircolite:3.8.1
    rules_path: tools/zircolite/rules
"""

MIXED = """
name: Mixed
log_types: [evtx]
tasks:
  - tool: zircolite
    docker_image: wagga40/zircolite:3.8.1
    rules_path: tools/zircolite/rules
  - tool: hayabusa
    tool_path: tools/hayabusa/hayabusa-intel-lin
    rules_path: tools/hayabusa/rules
"""

NO_DOCKER = """
name: Local only
log_types: [syslog]
tasks:
  - tool: chopchopgo
    tool_path: tools/chopchopgo/chopchopgo-intel-lin
    rules_path: tools/chopchopgo/rules
"""


def test_a_workflow_whose_only_task_needs_docker_fails_without_a_daemon(tmp_path, monkeypatch):
    """`task doctor` reported READY on a host where the default workflow was *guaranteed*
    to produce nothing. Five of five shipped workflows use Zircolite; four have no other
    task."""
    from app import system_checks

    root = _wf_dir(tmp_path, **{"a.yml": ZIRCOLITE_ONLY})
    monkeypatch.setattr(system_checks, "_docker_daemon_reachable", lambda: False)
    results = system_checks.check_docker_tools(root)
    assert results
    assert all(r.level == system_checks.FAIL for r in results)


def test_a_workflow_with_other_tasks_only_warns(tmp_path, monkeypatch):
    from app import system_checks

    root = _wf_dir(tmp_path, **{"a.yml": MIXED})
    monkeypatch.setattr(system_checks, "_docker_daemon_reachable", lambda: False)
    results = system_checks.check_docker_tools(root)
    assert [r.level for r in results] == [system_checks.WARN]


def test_no_container_task_means_no_check_at_all(tmp_path):
    from app import system_checks

    assert system_checks.check_docker_tools(_wf_dir(tmp_path, **{"a.yml": NO_DOCKER})) == []


def test_a_reachable_daemon_passes(tmp_path, monkeypatch):
    from app import system_checks

    root = _wf_dir(tmp_path, **{"a.yml": ZIRCOLITE_ONLY})
    monkeypatch.setattr(system_checks, "_docker_daemon_reachable", lambda: True)
    results = system_checks.check_docker_tools(root)
    assert [r.level for r in results] == [system_checks.PASS]


def test_the_check_is_wired_into_both_run_all_and_doctor():
    """doctor enumerates its checks explicitly instead of calling run_all, so a new check
    added to only one of the two silently never runs there."""
    from pathlib import Path as _P

    assert "check_docker_tools" in (_P(__file__).resolve().parent.parent / "scripts" / "doctor.py").read_text(encoding="utf-8")
    assert "check_docker_tools" in (_P(__file__).resolve().parent.parent / "app" / "system_checks.py").read_text(encoding="utf-8")


# ── Docker tools: which container is being asked ─────────────────────────────


def _docker_workflow(tmp_path):
    (tmp_path / "workflows").mkdir()
    (tmp_path / "workflows" / "wf.yml").write_text("tasks:\n  - tool: zircolite\n    docker_image: example:latest\n")


def test_no_docker_daemon_on_a_host_is_still_a_failure(tmp_path, monkeypatch):
    """The original finding stands where it applies: a real host with no daemon."""
    _docker_workflow(tmp_path)
    monkeypatch.setattr(system_checks, "_docker_daemon_reachable", lambda: False)
    monkeypatch.setattr(system_checks, "_running_in_container", lambda: False)
    results = system_checks.check_docker_tools(project_root=tmp_path)
    assert [r.level for r in results] == [FAIL]


def test_no_docker_socket_inside_a_container_is_informational(tmp_path, monkeypatch):
    """`task doctor:docker` runs in the **web** container, which mounts no socket.

    Only the worker does, deliberately — the web tier holding the Docker socket is a
    privilege-escalation surface `docs/security.md` names. Reporting FAIL from there would
    be a statement about which container was asked, not about the deployment: with four
    Zircolite-only workflows it would produce four FAILs, a NOT READY verdict, and an
    aborted `task quickstart` on a working host.
    """
    _docker_workflow(tmp_path)
    monkeypatch.setattr(system_checks, "_docker_daemon_reachable", lambda: False)
    monkeypatch.setattr(system_checks, "_running_in_container", lambda: True)
    monkeypatch.setattr(system_checks, "_docker_socket_present", lambda: False)
    results = system_checks.check_docker_tools(project_root=tmp_path)
    assert [r.level for r in results] == [INFO], "an unmounted socket in the web container must not fail the deploy verdict"
    assert "only the worker mounts the socket" in results[0].message
    assert "worker" in (results[0].fix or "")


def test_a_mounted_socket_with_no_daemon_still_fails(tmp_path, monkeypatch):
    """A worker that *does* mount the socket but cannot reach a daemon is genuinely broken."""
    _docker_workflow(tmp_path)
    monkeypatch.setattr(system_checks, "_docker_daemon_reachable", lambda: False)
    monkeypatch.setattr(system_checks, "_running_in_container", lambda: True)
    monkeypatch.setattr(system_checks, "_docker_socket_present", lambda: True)
    results = system_checks.check_docker_tools(project_root=tmp_path)
    assert [r.level for r in results] == [FAIL]


# ── Host OS: is this a platform LogsTotal is tested on? ──────────────────────
#
# Reported, never enforced. The deploy scripts make the same call per host and also
# continue — refusing an untested distro turns a probably-fine deployment into a
# support ticket, while saying nothing is how "it worked on my Fedora box until it
# didn't" happens with no clue in the report.


def _os(monkeypatch, system="Linux", release=None):
    monkeypatch.setattr(system_checks.platform, "system", lambda: system)
    monkeypatch.setattr(system_checks, "_running_in_container", lambda: False)
    monkeypatch.setattr(system_checks, "_os_release", lambda: release if release is not None else {})


@pytest.mark.parametrize("distro_id", ["ubuntu", "debian"])
def test_a_tested_distro_passes(monkeypatch, distro_id):
    _os(monkeypatch, release={"ID": distro_id, "PRETTY_NAME": f"{distro_id.title()} 24.04"})
    result = system_checks.check_host_os()
    assert result.level == PASS
    assert "(tested)" in result.message


def test_a_debian_derivative_is_informational_not_a_warning(monkeypatch):
    _os(monkeypatch, release={"ID": "linuxmint", "ID_LIKE": "ubuntu debian", "PRETTY_NAME": "Linux Mint 22"})
    result = system_checks.check_host_os()
    assert result.level == INFO
    assert "Debian-like" in result.message


def test_an_untested_distro_warns_and_names_itself(monkeypatch):
    _os(monkeypatch, release={"ID": "rocky", "ID_LIKE": "rhel centos fedora", "PRETTY_NAME": "Rocky Linux 9.4"})
    result = system_checks.check_host_os()
    assert result.level == WARN
    assert "Rocky Linux 9.4" in result.message
    assert "limitations/#platform-support" in result.fix


def test_an_unreadable_os_release_warns_rather_than_claiming_a_tested_platform(monkeypatch):
    _os(monkeypatch, release={})
    result = system_checks.check_host_os()
    assert result.level == WARN
    assert "/etc/os-release" in result.message


def test_macos_is_informational_so_every_local_doctor_run_stays_green(monkeypatch):
    """summarize() counts only FAIL and WARN toward the verdict. A WARN here would flip
    every `task doctor` on the developer's own Mac to "ready with warnings", which is
    exactly how a report teaches people that warnings are noise."""
    _os(monkeypatch, system="Darwin")
    result = system_checks.check_host_os()
    assert result.level == INFO
    assert system_checks.summarize([result])["status"] == "ready"


def test_a_container_reports_its_base_image_and_says_so(monkeypatch):
    """/etc/os-release inside the image describes the Dockerfile's base, not the machine —
    calling that "a tested platform" would be a lie by construction."""
    monkeypatch.setattr(system_checks.platform, "system", lambda: "Linux")
    monkeypatch.setattr(system_checks, "_running_in_container", lambda: True)
    monkeypatch.setattr(system_checks, "_os_release", lambda: {"ID": "debian", "PRETTY_NAME": "Debian GNU/Linux 12"})
    result = system_checks.check_host_os()
    assert result.level == INFO
    assert "container base image" in result.message
    assert "./logstotal doctor" in result.fix


def test_the_in_container_flag_works_without_dockerenv(monkeypatch):
    """doctor.py passes --in-container explicitly; /.dockerenv detection is the fallback
    for run_all(), which has no CLI flag to thread through."""
    monkeypatch.setattr(system_checks.platform, "system", lambda: "Linux")
    monkeypatch.setattr(system_checks, "_running_in_container", lambda: False)
    monkeypatch.setattr(system_checks, "_os_release", lambda: {"ID": "debian", "PRETTY_NAME": "Debian GNU/Linux 12"})
    assert system_checks.check_host_os(in_container=True).level == INFO


def test_os_release_parsing_ignores_comments_and_strips_quotes(tmp_path, monkeypatch):
    written = "# a comment\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nVERSION_ID='24.04'\nnot a key\n"
    target = tmp_path / "os-release"
    target.write_text(written, encoding="utf-8")
    monkeypatch.setattr(system_checks, "Path", lambda _p: target)
    parsed = system_checks._os_release()
    assert parsed == {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 24.04.1 LTS", "VERSION_ID": "24.04"}


def test_a_missing_os_release_file_is_not_an_exception(monkeypatch, tmp_path):
    monkeypatch.setattr(system_checks, "Path", lambda _p: tmp_path / "absent")
    assert system_checks._os_release() == {}


# ── the shared suite cache ───────────────────────────────────────────────────
#
# One `/admin` load asks for this suite twice: the Overview readiness verdict and the
# System tab card are the same `run_all()`, so they share one run. The lock matters as
# much as the TTL — "Re-run checks" has no debounce, so without it an impatient double
# click starts a second full suite while the first is still inside `docker info`.


def test_a_second_caller_reuses_the_first_run(monkeypatch):
    from app import system_checks

    system_checks.reset_check_cache()
    calls = []
    monkeypatch.setattr(system_checks, "run_all", lambda: calls.append(1) or ["r"])

    first, ran_at = system_checks.run_all_cached()
    second, ran_at_again = system_checks.run_all_cached()

    assert calls == [1], "the second caller ran the suite again"
    assert first == second == ["r"]
    assert ran_at == ran_at_again, "a cache hit must report when the run actually happened"


def test_force_is_the_only_way_past_the_cache(monkeypatch):
    """`?force=1` is what the Re-run button sends; the label has to stay true."""
    from app import system_checks

    system_checks.reset_check_cache()
    calls = []
    monkeypatch.setattr(system_checks, "run_all", lambda: calls.append(1) or ["r"])

    system_checks.run_all_cached()
    system_checks.run_all_cached()
    system_checks.run_all_cached(force=True)

    assert len(calls) == 2


def test_the_cache_expires(monkeypatch):
    from app import system_checks

    system_checks.reset_check_cache()
    calls = []
    monkeypatch.setattr(system_checks, "run_all", lambda: calls.append(1) or ["r"])
    monkeypatch.setattr(system_checks, "CHECK_CACHE_TTL_SECONDS", -1.0)

    system_checks.run_all_cached()
    system_checks.run_all_cached()

    assert len(calls) == 2, "a stale result must not be served forever"


def test_concurrent_callers_do_not_stack_full_suites(monkeypatch):
    """Four threads, one suite. This is the double-click the lock exists for."""
    import threading
    import time as _time

    from app import system_checks

    system_checks.reset_check_cache()
    calls = []

    def slow():
        calls.append(1)
        _time.sleep(0.05)
        return ["r"]

    monkeypatch.setattr(system_checks, "run_all", slow)
    threads = [threading.Thread(target=system_checks.run_all_cached) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(calls) == 1, f"{len(calls)} concurrent suites ran where one should have"


# ── Reaching a page must not run the suite ────────────────────────────────────


def test_stale_ok_serves_any_cached_result_however_old(monkeypatch):
    """The System tab must never *start* a run — that is what Re-run checks is for.

    A TTL cannot express this. Whatever window you pick, browsing past it turns opening a
    tab into a wait for a storage probe, an Argon2 verify per superuser and a `docker info`
    that can block for ten seconds. That was the complaint, and raising the window only
    moved it.
    """
    from app import system_checks

    system_checks.reset_check_cache()
    calls = []
    monkeypatch.setattr(system_checks, "run_all", lambda: calls.append(1) or ["r"])
    monkeypatch.setattr(system_checks, "CHECK_CACHE_TTL_SECONDS", -1.0)  # everything is stale

    system_checks.run_all_cached()  # the readiness chip, at page load
    for _ in range(5):
        system_checks.run_all_cached(stale_ok=True)  # opening the tab, repeatedly

    assert len(calls) == 1, "opening the System tab re-ran the suite"


def test_stale_ok_still_runs_when_nothing_is_cached(monkeypatch):
    """A cold process has nothing to show. Someone has to pay once."""
    from app import system_checks

    system_checks.reset_check_cache()
    calls = []
    monkeypatch.setattr(system_checks, "run_all", lambda: calls.append(1) or ["r"])

    system_checks.run_all_cached(stale_ok=True)
    assert len(calls) == 1


def test_force_still_beats_stale_ok(monkeypatch):
    """Re-run checks is the one thing that must always mean what it says."""
    from app import system_checks

    system_checks.reset_check_cache()
    calls = []
    monkeypatch.setattr(system_checks, "run_all", lambda: calls.append(1) or ["r"])

    system_checks.run_all_cached()
    system_checks.run_all_cached(force=True, stale_ok=True)
    assert len(calls) == 2


def test_the_system_checks_route_never_runs_the_suite_without_force():
    """Asserted on the source: the failure is a missing keyword, and it is invisible in a
    route test because the response looks identical either way — it just took ten seconds."""
    import inspect

    from app.routers import admin as admin_module

    src = inspect.getsource(admin_module.system_checks_partial)
    assert "stale_ok=True" in src, "opening the System tab must reuse whatever the readiness card computed"

    readiness = inspect.getsource(admin_module.readiness_partial)
    assert "stale_ok" not in readiness, "a fresh /admin visit does deserve fresh checks — the TTL governs this one"
