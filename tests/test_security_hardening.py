"""Security regression tests for submitter-driven injection and abuse paths."""

from __future__ import annotations

import re

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.config import Settings
from app.models import AnalysisJob, Entity, EntityJobLink, JobStatus, LogFile, LogType, User, WorkflowDef


async def _create_user(async_db, *, email: str, password: str, is_superuser: bool = False, role: str | None = None) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    effective_role = role or ("admin" if is_superuser else "user")
    return await manager.create(
        UserCreate(
            email=email,
            password=password,
            is_superuser=is_superuser,
            is_active=True,
            role=effective_role,
        )
    )


async def _login(client, *, email: str, password: str) -> None:
    resp = await client.post(
        "/auth/cookie/login",
        data={"username": email, "password": password},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 204, 303), resp.text


@pytest.fixture()
async def seeded_security_data(async_db):
    wf = WorkflowDef(
        name="Security Workflow",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks:\n  - tool: zircolite\n    tool_path: tools/zircolite/zircolite.py\n    rules_path: tools/zircolite/rules\n",
        is_default=True,
    )
    async_db.add(wf)
    await async_db.flush()

    lf = LogFile(
        original_filename="seed.evtx",
        stored_filename="seed_seed.evtx",
        sha256="c" * 64,
        size_bytes=2048,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()

    owner = await _create_user(async_db, email="owner@test.example.com", password="pass123456", role="member")
    other = await _create_user(async_db, email="other@test.example.com", password="pass123456")

    job = AnalysisJob(
        submitted_filename=lf.original_filename,
        effective_log_type=lf.log_type,
        file_id=lf.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
    )
    async_db.add(job)
    await async_db.flush()

    payload = "x');alert(1);//"
    entity = Entity(value=payload, entity_type="domain", job_count=1)
    async_db.add(entity)
    await async_db.flush()
    async_db.add(EntityJobLink(entity_id=entity.id, job_id=job.id, occurrence_count=1))

    await async_db.commit()
    await async_db.refresh(entity)
    await async_db.refresh(job)
    await async_db.refresh(wf)
    return {"workflow": wf, "log_file": lf, "owner": owner, "other": other, "job": job, "entity": entity}


async def test_entity_clipboard_avoids_js_interpolation(test_client, seeded_security_data):
    """The copy button reads the value out of the DOM; the value never reaches a script.

    The button comes from `partials/_copy_button.html` and names its source with
    `data-copy-from`, but the property under test is independent of the macro: an
    entity value is attacker-supplied, HTML-escaping does not make it safe inside a
    `<script>`, and the fixture's payload (`x\');alert(1);//`) is chosen to close a JS
    string literal. Asserted against the *rendered page* rather than the template, so it
    holds however the button is spelled — and it covers `job.html`'s SHA256 and
    `_similar_files.html`'s TLSH the same way.
    """
    await _login(test_client, email="owner@test.example.com", password="pass123456")
    entity = seeded_security_data["entity"]
    # This entity appears in exactly one job, so the page redirects to that scope before
    # rendering; the assertion here is about the rendered markup either way.
    resp = await test_client.get(f"/intel/entities/{entity.id}", follow_redirects=True)
    assert resp.status_code == 200

    body = resp.text
    assert 'data-copy-from="span"' in body, "the value is copied out of the DOM, not carried in JS"

    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", body, re.S)
    assert scripts, "the page does have scripts — an empty list would make this vacuous"
    handlers = re.findall(r'(?:\bon[a-z]+|@[a-z.]+|x-data|x-init)="([^"]*)"', body)
    assert handlers, "...and inline handlers, likewise"
    for chunk in scripts + handlers:
        assert "alert(1)" not in chunk, f"entity value reached executable context: {chunk[:120]!r}"


async def test_resubmit_requires_authentication(test_client, seeded_security_data, monkeypatch):
    monkeypatch.setattr("app.workers.tasks.run_analysis", lambda job_id: None)
    wf = seeded_security_data["workflow"]
    lf = seeded_security_data["log_file"]
    resp = await test_client.post(
        "/jobs/resubmit",
        data={"file_id": str(lf.id), "workflow_id": str(wf.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 401


async def test_resubmit_rejects_non_owner(test_client, seeded_security_data, monkeypatch):
    monkeypatch.setattr("app.workers.tasks.run_analysis", lambda job_id: None)
    await _login(test_client, email="other@test.example.com", password="pass123456")
    wf = seeded_security_data["workflow"]
    lf = seeded_security_data["log_file"]
    resp = await test_client.post(
        "/jobs/resubmit",
        data={"file_id": str(lf.id), "workflow_id": str(wf.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_resubmit_allows_owner(test_client, seeded_security_data, monkeypatch):
    monkeypatch.setattr("app.workers.tasks.run_analysis", lambda job_id: None)
    await _login(test_client, email="owner@test.example.com", password="pass123456")
    wf = seeded_security_data["workflow"]
    lf = seeded_security_data["log_file"]
    resp = await test_client.post(
        "/jobs/resubmit",
        data={"file_id": str(lf.id), "workflow_id": str(wf.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/jobs/" in resp.headers.get("location", "")


async def test_upload_rejects_invalid_log_type_override(test_client, seeded_security_data):
    wf = seeded_security_data["workflow"]
    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(wf.id), "log_type_override": "bad-type"},
        files={"file": ("test.evtx", b"ElfFile\x00" + b"\x00" * 100, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "Invalid log type override." in resp.text


async def test_upload_records_authenticated_submitter(test_client, seeded_security_data, async_db, monkeypatch):
    monkeypatch.setattr("app.workers.tasks.run_analysis", lambda job_id: None)
    owner = seeded_security_data["owner"]
    wf = seeded_security_data["workflow"]
    await _login(test_client, email=owner.email, password="pass123456")

    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(wf.id), "log_type_override": "auto"},
        files={"file": ("fresh.evtx", b"ElfFile\x00" + b"\x01" * 128, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/jobs/" in resp.headers.get("location", "")

    latest_job = await async_db.scalar(select(AnalysisJob).order_by(AnalysisJob.id.desc()).limit(1))
    assert latest_job is not None
    assert latest_job.submitted_by_user_id == owner.id


async def test_duplicate_upload_creates_attributed_job_for_authenticated_user(test_client, seeded_security_data, async_db, monkeypatch):
    monkeypatch.setattr("app.workers.tasks.run_analysis", lambda job_id: None)
    wf = seeded_security_data["workflow"]
    owner = seeded_security_data["owner"]
    file_content = b"ElfFile\x00" + b"\x03" * 96

    # First duplicate baseline is anonymous.
    first = await test_client.post(
        "/upload",
        data={"workflow_id": str(wf.id), "log_type_override": "auto"},
        files={"file": ("dup.evtx", file_content, "application/octet-stream")},
        follow_redirects=False,
    )
    assert first.status_code == 303
    first_job_id = int(first.headers["location"].rstrip("/").split("/")[-1].split("?")[0])

    # Logged-in duplicate should get an attributed job, not anonymous redirect.
    await _login(test_client, email=owner.email, password="pass123456")
    second = await test_client.post(
        "/upload",
        data={"workflow_id": str(wf.id), "log_type_override": "auto"},
        files={"file": ("dup.evtx", file_content, "application/octet-stream")},
        follow_redirects=False,
    )
    assert second.status_code == 303
    second_job_id = int(second.headers["location"].rstrip("/").split("/")[-1].split("?")[0])
    assert second_job_id != first_job_id

    second_job = await async_db.get(AnalysisJob, second_job_id)
    assert second_job is not None
    assert second_job.submitted_by_user_id == owner.id


async def test_submitter_relationship_resolves_for_uuid_fk(async_db, seeded_security_data):
    job_id = seeded_security_data["job"].id
    stmt = select(AnalysisJob).where(AnalysisJob.id == job_id).options(selectinload(AnalysisJob.submitter))
    loaded = await async_db.scalar(stmt)
    assert loaded is not None
    assert loaded.submitter is not None
    assert loaded.submitter.email == seeded_security_data["owner"].email


# ── Privilege-escalation regression tests ───────────────────────────────────


async def test_patch_me_cannot_escalate_role(test_client, async_db):
    """A basic user must not be able to self-promote via PATCH /api/users/me."""
    await _create_user(async_db, email="lowpriv@test.example.com", password="pass123456", role="user")
    await _login(test_client, email="lowpriv@test.example.com", password="pass123456")

    # Intel is member-gated: confirm the user is locked out before the attempt.
    before = await test_client.get("/intel", follow_redirects=False)
    assert before.status_code == 403

    resp = await test_client.patch("/api/users/me", json={"role": "admin"})
    assert resp.status_code == 200, resp.text
    # The response must never report an escalated role.
    assert resp.json().get("role") == "user"

    updated = await async_db.scalar(select(User).where(User.email == "lowpriv@test.example.com"))
    assert updated is not None
    assert updated.role == "user"
    assert updated.is_superuser is False

    # And the Intel boundary still holds after the attempt.
    after = await test_client.get("/intel", follow_redirects=False)
    assert after.status_code == 403


@pytest.mark.parametrize("method", ["GET", "PATCH", "DELETE"])
async def test_the_users_api_offers_no_per_id_routes(admin_client, admin_user, method):
    """fastapi-users' superuser routes on `/api/users/{id}` bypassed everything /admin/users
    enforces: an admin could DELETE their own account (no superuser left), DELETE a user who
    owns jobs (a foreign-key 500 on PostgreSQL, dangling rows on SQLite, no cleanup and no
    audit row), or PATCH `is_superuser` without `role`. Nothing in the UI or the docs used
    them; only `/me` stays."""
    resp = await admin_client.request(method, f"/api/users/{admin_user.id}", json={"is_superuser": False} if method == "PATCH" else None)
    assert resp.status_code in (404, 405), resp.status_code


async def test_me_is_still_served(admin_client):
    resp = await admin_client.get("/api/users/me")
    assert resp.status_code == 200
    assert resp.json()["email"] == "admin@test.example.com"


async def test_patch_me_still_allows_display_name(test_client, async_db):
    """The self-service update must keep working for legitimate fields."""
    await _create_user(async_db, email="profile@test.example.com", password="pass123456", role="user")
    await _login(test_client, email="profile@test.example.com", password="pass123456")

    resp = await test_client.patch("/api/users/me", json={"display_name": "Renamed"})
    assert resp.status_code == 200, resp.text
    assert resp.json().get("display_name") == "Renamed"


async def test_patch_me_refuses_a_display_name_longer_than_the_column(test_client, async_db):
    """`user.display_name` is `String(100)`. SQLite stores anything, PostgreSQL raises on
    commit — so without a schema cap the same request is a silent 5,000-character author
    name on one backend and a 500 on the other."""
    await _create_user(async_db, email="longname@test.example.com", password="pass123456", role="user")
    await _login(test_client, email="longname@test.example.com", password="pass123456")

    resp = await test_client.patch("/api/users/me", json={"display_name": "x" * 101})
    assert resp.status_code == 422, resp.text
    stored = await async_db.scalar(select(User.display_name).where(User.email == "longname@test.example.com"))
    assert stored is None


# ── XSS regression tests ─────────────────────────────────────────────────────


async def test_cases_filter_bar_escapes_alpine_state(test_client, async_db):
    """The cases filter `q` must not break out of the Alpine x-data literal."""
    await _create_user(async_db, email="casexss@test.example.com", password="pass123456", role="member")
    await _login(test_client, email="casexss@test.example.com", password="pass123456")

    payload = "');alert(document.domain);//<script>x</script>"
    resp = await test_client.get("/intel/cases", params={"q": payload})
    assert resp.status_code == 200
    # No raw breakout sequence and no unescaped script tag anywhere in the page.
    assert "');alert(document.domain)" not in resp.text
    assert "<script>x</script>" not in resp.text
    # The value is still present, but JSON/HTML-escaped.
    assert "\\u0027" in resp.text


async def test_entity_add_to_case_uses_dom_option_builder(test_client, seeded_security_data):
    """The shared add-to-case macro must build <option>s via textContent, not innerHTML concat."""
    await _login(test_client, email="owner@test.example.com", password="pass123456")
    entity = seeded_security_data["entity"]
    # Single-job entity: the page redirects to that scope first (see test_intel_job_scope).
    resp = await test_client.get(f"/intel/entities/{entity.id}", follow_redirects=True)
    assert resp.status_code == 200
    assert "opt.textContent" in resp.text
    assert "createElement('option')" in resp.text
    assert "'<option value=\"' + c.id" not in resp.text


async def test_job_add_to_case_dialog_uses_dom_option_builder(test_client, seeded_security_data):
    """Same shared macro on the job page — must not regress to string-built <option>s."""
    await _login(test_client, email="owner@test.example.com", password="pass123456")
    job = seeded_security_data["job"]
    resp = await test_client.get(f"/jobs/{job.id}")
    assert resp.status_code == 200
    assert "opt.textContent" in resp.text
    assert "createElement('option')" in resp.text
    assert "'<option value=\"' + c.id" not in resp.text


async def test_case_detail_pickers_use_dom_building(test_client, async_db, seeded_security_data):
    """The case-detail entity/job search pickers must build result rows via the DOM, not innerHTML concat."""
    from app.models import InvestigationCase

    await _login(test_client, email="owner@test.example.com", password="pass123456")
    case = InvestigationCase(name="XSS Check Case", created_by_user_id=seeded_security_data["owner"].id)
    async_db.add(case)
    await async_db.commit()
    await async_db.refresh(case)

    resp = await test_client.get(f"/intel/cases/{case.id}")
    assert resp.status_code == 200
    assert "createElement('button')" in resp.text
    assert "valueSpan.textContent" in resp.text
    assert "nameSpan.textContent" in resp.text
    # Result rows must never be string-concatenated from picker JSON fields.
    assert "' + item.value" not in resp.text
    assert "' + item.filename" not in resp.text


async def test_a_stale_theme_cookie_is_simply_ignored(test_client, async_db):
    """There is one theme and no `data-theme` attribute, so the cookie an older release set
    reaches nothing at all.

    Kept as a *security* test rather than deleted: the cookie is still out there in real
    browsers, and "the value is not interpolated anywhere" is the property that matters.
    """
    await _create_user(async_db, email="themexss@test.example.com", password="pass123456", role="user")
    await _login(test_client, email="themexss@test.example.com", password="pass123456")

    test_client.cookies.set("logstotal_theme", '"><script>alert(1)</script>')
    resp = await test_client.get("/jobs")
    assert resp.status_code == 200
    assert "data-theme" not in resp.text
    assert "<script>alert(1)</script>" not in resp.text


# ── Security header tests ────────────────────────────────────────────────────


async def test_security_headers_present(test_client):
    resp = await test_client.get("/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "SAMEORIGIN"
    assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in resp.headers.get("permissions-policy", "")


async def test_csp_includes_frame_ancestors(test_client):
    resp = await test_client.get("/health")
    csp = resp.headers.get("content-security-policy", "")
    assert "frame-ancestors 'self'" in csp


# ── Production safety config warnings ────────────────────────────────────────


def _make_settings(**overrides) -> Settings:
    """Build a Settings instance from these kwargs alone.

    `_env_file=None` is the point: `Settings` declares `env_file=".env"`, so without it
    every one of these assertions also read the developer's real deployment config — a
    machine with `ENABLE_HSTS=true` in `.env` would silently pass a test meant to prove
    the warning fires when it is off, and CI would disagree with local runs.
    """
    base = {
        "secret_key": "a" * 64,
        "debug": False,
        "cookie_insecure": False,
        "disable_csp": False,
        "upload_rate_limit_per_minute": 30,
        "login_rate_limit_per_minute": 20,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_production_warnings_debug_true():
    s = _make_settings(debug=True)
    warnings = s.production_warnings()
    assert any("DEBUG=true" in w for w in warnings)


def test_production_warnings_csp_disabled():
    s = _make_settings(disable_csp=True)
    warnings = s.production_warnings()
    assert any("DISABLE_CSP" in w for w in warnings)


def test_production_warnings_cookie_insecure_without_debug():
    s = _make_settings(cookie_insecure=True)
    warnings = s.production_warnings()
    assert any("COOKIE_INSECURE" in w for w in warnings)


def test_production_warnings_wildcard_proxy_cidrs():
    s = _make_settings(trust_proxy_headers=True, trusted_proxy_cidrs="*")
    warnings = s.production_warnings()
    assert any("TRUSTED_PROXY_CIDRS=*" in w for w in warnings)


def test_production_warnings_short_secret():
    s = _make_settings(secret_key="a" * 16)
    warnings = s.production_warnings()
    assert any("shorter than 32" in w for w in warnings)


def test_production_warnings_upload_rate_disabled():
    s = _make_settings(upload_rate_limit_per_minute=0)
    warnings = s.production_warnings()
    assert any("UPLOAD_RATE_LIMIT" in w for w in warnings)


def test_production_warnings_login_rate_disabled():
    s = _make_settings(login_rate_limit_per_minute=0)
    warnings = s.production_warnings()
    assert any("LOGIN_RATE_LIMIT" in w for w in warnings)


def test_production_warnings_clean_config():
    s = _make_settings()
    assert s.production_warnings() == []


# ── Redis exposure fail-fast (production_errors) ─────────────────────────────


def test_production_errors_redis_exposed_without_password():
    s = _make_settings(redis_expose="10.0.0.1:6379", redis_password="", redis_url=None)
    assert any("REDIS_PASSWORD" in e for e in s.production_errors())


def test_production_errors_redis_wildcard_bind_requires_password():
    s = _make_settings(redis_expose="0.0.0.0:6379", redis_password="", redis_url=None)
    assert any("REDIS_PASSWORD" in e for e in s.production_errors())


def test_production_errors_redis_exposed_with_password_ok():
    s = _make_settings(redis_expose="10.0.0.1:6379", redis_password="a-strong-redis-secret", redis_url=None)
    assert not any("REDIS_PASSWORD" in e for e in s.production_errors())


def test_production_errors_redis_loopback_expose_ok():
    s = _make_settings(redis_expose="127.0.0.1:6379", redis_password="", redis_url=None)
    assert not any("REDIS_PASSWORD" in e for e in s.production_errors())


def test_production_errors_redis_url_credentials_ok():
    s = _make_settings(redis_expose="10.0.0.1:6379", redis_password="", redis_url="redis://:pw@10.0.0.1:6379/0")
    assert not any("REDIS_PASSWORD" in e for e in s.production_errors())


# ── Password policy (UserManager.validate_password) ──────────────────────────


async def test_validate_password_rejects_default_and_weak():
    from fastapi_users.exceptions import InvalidPasswordException

    manager = UserManager(None)
    for pw in ("changeme123", "Password", "short7!"):
        with pytest.raises(InvalidPasswordException):
            await manager.validate_password(pw, None)


async def test_validate_password_rejects_email_containment():
    from types import SimpleNamespace

    from fastapi_users.exceptions import InvalidPasswordException

    manager = UserManager(None)
    with pytest.raises(InvalidPasswordException):
        await manager.validate_password("xx-Admin@Example.com-yy", SimpleNamespace(email="admin@example.com"))


async def test_validate_password_accepts_strong():
    from types import SimpleNamespace

    manager = UserManager(None)
    await manager.validate_password("correct-horse-battery", SimpleNamespace(email="admin@example.com"))


async def test_admin_create_user_weak_password_redirects_with_error(admin_client, async_db):
    resp = await admin_client.post(
        "/admin/users/create",
        data={"email": "weakpw@example.com", "password": "changeme123", "role": "user"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]
    created = await async_db.scalar(select(User).where(User.email == "weakpw@example.com"))
    assert created is None


@pytest.mark.parametrize("email", ["analyst@corp.local", "a@b", "x@localhost"])
async def test_admin_create_user_with_an_address_the_schema_refuses_redirects_with_error(admin_client, async_db, email):
    """The form's `type=email` accepts these; the pydantic schema does not (special-use and
    single-label domains). That refusal is the admin's to read, not a 500."""
    resp = await admin_client.post(
        "/admin/users/create",
        data={"email": email, "password": "a-long-enough-passphrase", "role": "user"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]
    assert await async_db.scalar(select(User).where(User.email == email)) is None


async def test_admin_create_user_refuses_a_display_name_longer_than_the_column(admin_client, async_db):
    resp = await admin_client.post(
        "/admin/users/create",
        data={"email": "longname@example.com", "password": "a-long-enough-passphrase", "role": "user", "display_name": "x" * 101},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]
    assert await async_db.scalar(select(User).where(User.email == "longname@example.com")) is None


async def test_admin_set_password_weak_redirects_with_error(admin_client, admin_user):
    resp = await admin_client.post(
        f"/admin/users/{admin_user.id}/set-password",
        data={"password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]
