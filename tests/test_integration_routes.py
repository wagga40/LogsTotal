"""Integration tests for route access control, cache-busting, and core endpoints.

Covers the auth-boundary matrix (admin / member / user / anonymous) across
routers, verifies cache-busting query strings, and exercises key HTMX/JSON
endpoints end-to-end against the in-memory test DB.
"""

from __future__ import annotations

import os

import pytest

from app.models import (
    AnalysisJob,
    JobStatus,
    LogFile,
    LogType,
    WorkflowDef,
)

# ── Seed data ────────────────────────────────────────────────────────────────


@pytest.fixture()
async def seed_data(async_db):
    """Minimal seed: one workflow, one file, one completed job."""
    wf = WorkflowDef(
        name="Test Workflow",
        description="Integration test workflow",
        log_types='["evtx"]',
        tasks_yaml="tasks:\n  - tool: zircolite\n    tool_path: tools/zircolite/zircolite.py\n    rules_path: tools/zircolite/rules\n",
        is_default=True,
    )
    async_db.add(wf)
    await async_db.flush()

    lf = LogFile(
        original_filename="integration.evtx",
        stored_filename="int_integration.evtx",
        sha256="a" * 64,
        size_bytes=4096,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()

    job = AnalysisJob(
        submitted_filename=lf.original_filename,
        effective_log_type=lf.log_type,
        file_id=lf.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        score_ratio="1/1",
        total_findings=0,
    )
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(wf)
    await async_db.refresh(lf)
    await async_db.refresh(job)
    return {"workflow": wf, "log_file": lf, "job": job}


# ── Cache-busting ────────────────────────────────────────────────────────────


async def test_static_assets_have_version_query_string(test_client):
    """base.html should include ?v=<version> on every /static/ reference."""
    resp = await test_client.get("/")
    assert resp.status_code == 200
    body = resp.text
    assert "?v=" in body
    assert "/static/vendor/htmx.min.js?v=" in body
    assert "/static/app.js?v=" in body


async def test_docs_mermaid_has_version_query_string(test_client):
    resp = await test_client.get("/docs")
    assert resp.status_code == 200
    assert "/static/vendor/mermaid.min.js?v=" in resp.text


# ── Public pages (anonymous) ────────────────────────────────────────────────


async def test_homepage_anonymous(test_client, seed_data):
    resp = await test_client.get("/")
    assert resp.status_code == 200
    assert "LogsTotal" in resp.text


async def test_jobs_list_anonymous(test_client, seed_data):
    resp = await test_client.get("/jobs")
    assert resp.status_code == 200


async def test_job_detail_anonymous(test_client, seed_data):
    job = seed_data["job"]
    resp = await test_client.get(f"/jobs/{job.id}")
    assert resp.status_code == 200
    assert "integration.evtx" in resp.text


async def test_docs_page_anonymous(test_client):
    resp = await test_client.get("/docs")
    assert resp.status_code == 200
    assert "What is LogsTotal?" in resp.text


async def test_health_endpoint(test_client):
    """A healthy stack must return 200 — `in (200, 503)` asserted nothing.

    Under the test fixtures every subsystem the endpoint probes is up: SQLite in memory,
    fakeredis (autouse), and a writable tmp upload dir. `workers_ok` is False because no
    Huey consumer is running, which by design does not make the app unhealthy.
    """
    resp = await test_client.get("/health")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["app"] == "ok"
    assert data["database"] == "ok"
    assert data["redis"] == "ok"
    assert data["storage"].startswith("ok")
    assert data["version"]
    assert data["workers_ok"] is False
    # Admin-only: the exact schema revision, and the storage backend's name.
    assert "migrations" not in data
    assert data["storage"] == "ok"


async def test_health_shows_the_schema_revision_to_an_admin(admin_client):
    """The fields anonymous callers do not get are still there for the operator.

    Neither `deploy:smoke` nor `health:remote` reads them, so gating them costs no tooling.
    """
    data = (await admin_client.get("/health")).json()
    assert data["migrations"]
    assert data["storage"].startswith("ok (")


async def test_html_responses_are_not_cacheable_and_vary_on_the_session(test_client):
    """A shared cache must never serve one viewer's page to the next.

    Vary must *merge*, not replace: GZipMiddleware sets `Vary: Accept-Encoding`, and
    dropping that breaks compression negotiation for every downstream cache.
    """
    resp = await test_client.get("/")
    assert resp.headers["cache-control"] == "no-store, private"
    vary = {v.strip().lower() for v in resp.headers["vary"].split(",")}
    assert {"cookie", "hx-request"} <= vary


async def test_json_and_downloads_are_not_cacheable_either(admin_client, async_db):
    """Only text/html carried `no-store`. A private job's `findings.json` and the admin's
    download of the original upload went out with no Cache-Control and a Last-Modified —
    heuristically cacheable by the same shared proxy the HTML rule exists to defend against,
    and kept in the browser after logout."""
    from app.models import AnalysisJob, JobStatus, LogFile, WorkflowDef

    wf = WorkflowDef(name="w", tasks_yaml="tasks: []", log_types="[]")
    lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1)
    async_db.add_all([wf, lf])
    await async_db.flush()
    job = AnalysisJob(submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, is_private=True)
    async_db.add(job)
    await async_db.commit()

    for path in (f"/jobs/{job.id}/findings.json", "/health"):
        resp = await admin_client.get(path)
        assert resp.headers.get("cache-control") == "no-store, private", path
        assert "cookie" in resp.headers.get("vary", "").lower(), path


async def test_static_assets_are_still_cacheable(test_client):
    """The no-store rule is scoped to text/html, or every vendored bundle refetches."""
    resp = await test_client.get("/static/app.js")
    assert resp.status_code == 200
    assert "no-store" not in resp.headers.get("cache-control", "")


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="chmod does not restrict root, so the probe would still succeed")
async def test_health_storage_probe_failure_flips_503(test_client, monkeypatch, tmp_path):
    """Local storage is actually probed — an unwritable upload dir turns /health red."""
    from app.config import settings

    upload_dir = tmp_path / "ro-uploads"
    upload_dir.mkdir()
    upload_dir.chmod(0o500)
    monkeypatch.setattr(settings, "storage_backend", "local")
    monkeypatch.setattr(settings, "upload_dir", upload_dir)
    try:
        resp = await test_client.get("/health")
    finally:
        upload_dir.chmod(0o700)
    assert resp.status_code == 503
    assert resp.json()["storage"] == "error"


# ── Intel access (member-or-above gating) ────────────────────────────────────


async def test_intel_denied_to_anonymous(test_client):
    resp = await test_client.get("/intel", follow_redirects=False)
    assert resp.status_code == 401


async def test_intel_denied_to_basic_user(user_client):
    resp = await user_client.get("/intel", follow_redirects=False)
    assert resp.status_code == 403


async def test_intel_accessible_to_member(member_client):
    resp = await member_client.get("/intel")
    assert resp.status_code == 200


async def test_intel_accessible_to_admin(admin_client):
    resp = await admin_client.get("/intel")
    assert resp.status_code == 200


async def test_mitre_layer_denied_to_anonymous(test_client):
    resp = await test_client.get("/intel/mitre-layer", follow_redirects=False)
    assert resp.status_code == 401


async def test_ioc_feed_denied_to_basic_user(user_client):
    resp = await user_client.get("/intel/ioc-feed", follow_redirects=False)
    assert resp.status_code == 403


async def test_ioc_feed_json_for_member(member_client):
    resp = await member_client.get("/intel/ioc-feed?format=json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")


# ── Workflows (admin-only) ──────────────────────────────────────────────────


async def test_workflows_denied_to_anonymous(test_client):
    resp = await test_client.get("/workflows", follow_redirects=False)
    assert resp.status_code == 401


async def test_workflows_denied_to_member(member_client):
    resp = await member_client.get("/workflows", follow_redirects=False)
    assert resp.status_code == 403


async def test_workflows_accessible_to_admin(admin_client, seed_data):
    resp = await admin_client.get("/workflows")
    assert resp.status_code == 200
    assert "Test Workflow" in resp.text


async def test_workflow_create_admin(admin_client):
    valid_yaml = "tasks:\n  - tool: zircolite\n    tool_path: t\n    rules_path: r\n"
    resp = await admin_client.post(
        "/workflows/new",
        data={
            "name": "Created-via-test",
            "description": "test desc",
            "tasks_yaml": valid_yaml,
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/workflows" in resp.headers.get("location", "")


# ── Admin pages (admin-only) ────────────────────────────────────────────────


async def test_admin_dashboard_denied_to_anonymous(test_client):
    resp = await test_client.get("/admin", follow_redirects=False)
    assert resp.status_code == 401


async def test_admin_dashboard_denied_to_member(member_client):
    resp = await member_client.get("/admin", follow_redirects=False)
    assert resp.status_code == 403


async def test_admin_dashboard_accessible_to_admin(admin_client):
    resp = await admin_client.get("/admin")
    assert resp.status_code == 200
    # System Status card is lazy-loaded via HTMX
    assert "/admin/system-checks-partial" in resp.text


async def test_system_checks_partial_denied_to_anonymous(test_client):
    resp = await test_client.get("/admin/system-checks-partial", follow_redirects=False)
    assert resp.status_code == 401


async def test_system_checks_partial_denied_to_member(member_client):
    resp = await member_client.get("/admin/system-checks-partial", follow_redirects=False)
    assert resp.status_code == 403


async def test_system_checks_partial_renders_for_admin(admin_client):
    resp = await admin_client.get("/admin/system-checks-partial")
    assert resp.status_code == 200
    assert "migrations" in resp.text
    assert "Version" in resp.text


async def test_admin_dashboard_has_tabs_and_maintenance_rows(admin_client):
    from app.routers.admin import MAINTENANCE_ACTIONS

    resp = await admin_client.get("/admin")
    assert resp.status_code == 200
    for label in ("Overview", "System", "Maintenance"):
        assert label in resp.text
    for action in MAINTENANCE_ACTIONS:
        assert action["url"] in resp.text
        assert f"task-status-{action['key']}" in resp.text


async def test_admin_can_set_password_for_other_user(admin_client, regular_user):
    resp = await admin_client.post(
        f"/admin/users/{regular_user.id}/set-password",
        data={"password": "rotated-pass-9"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/users"
    # old password rejected, new one accepted
    bad = await admin_client.post(
        "/auth/cookie/login",
        data={"username": "user@test.example.com", "password": "testpass123"},
    )
    assert bad.status_code == 400
    good = await admin_client.post(
        "/auth/cookie/login",
        data={"username": "user@test.example.com", "password": "rotated-pass-9"},
    )
    assert good.status_code in (200, 204)


async def test_admin_can_set_own_password(admin_client, admin_user):
    """The admin fixing the default-password warning is usually the default admin itself."""
    resp = await admin_client.post(
        f"/admin/users/{admin_user.id}/set-password",
        data={"password": "rotated-pass-9"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    good = await admin_client.post(
        "/auth/cookie/login",
        data={"username": "admin@test.example.com", "password": "rotated-pass-9"},
    )
    assert good.status_code in (200, 204)


async def test_set_password_rejects_short_password(admin_client, regular_user):
    resp = await admin_client.post(
        f"/admin/users/{regular_user.id}/set-password",
        data={"password": "short"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]
    # password unchanged
    ok = await admin_client.post(
        "/auth/cookie/login",
        data={"username": "user@test.example.com", "password": "testpass123"},
    )
    assert ok.status_code in (200, 204)


async def test_set_password_denied_to_non_admin(user_client, regular_user):
    resp = await user_client.post(
        f"/admin/users/{regular_user.id}/set-password",
        data={"password": "whatever-pass-9"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_set_password_unknown_user_404(admin_client):
    import uuid

    resp = await admin_client.post(
        f"/admin/users/{uuid.uuid4()}/set-password",
        data={"password": "whatever-pass-9"},
        follow_redirects=False,
    )
    assert resp.status_code == 404


async def test_default_password_warning_clears_after_set_password(admin_client, async_db):
    """The dashboard banner points at User Management — changing the password there must clear it."""
    # Simulate a legacy deployment: an admin row hashed from the shipped default.
    # validate_password refuses "changeme123" at create time, so write the row
    # directly — exactly what an older database can contain.
    from fastapi_users.password import PasswordHelper

    from app.models import User as UserModel

    legacy = UserModel(
        email="legacy-admin@test.example.com",
        hashed_password=PasswordHelper().hash("changeme123"),
        is_superuser=True,
        is_active=True,
        role="admin",
    )
    async_db.add(legacy)
    await async_db.commit()
    dash = await admin_client.get("/admin")
    assert "Default admin password in use" in dash.text

    from sqlalchemy import select as sa_select

    from app.models import User

    uid = (await async_db.execute(sa_select(User.id).where(User.email == "legacy-admin@test.example.com"))).scalar_one()
    resp = await admin_client.post(
        f"/admin/users/{uid}/set-password",
        data={"password": "rotated-pass-9"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    dash = await admin_client.get("/admin")
    assert "Default admin password in use" not in dash.text


async def test_users_page_has_set_password_form(admin_client, admin_user):
    resp = await admin_client.get("/admin/users")
    assert resp.status_code == 200
    assert f"/admin/users/{admin_user.id}/set-password" in resp.text


async def test_backfill_htmx_returns_live_status_chip(admin_client, monkeypatch):
    import app.workers.tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "backfill_similarity", lambda task_id: None)
    resp = await admin_client.post("/admin/backfill-similarity", headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert "/admin/background-tasks/" in resp.text
    assert "every 3s" in resp.text  # pending chip self-polls


async def test_backfill_plain_post_still_redirects(admin_client, monkeypatch):
    import app.workers.tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "backfill_similarity", lambda task_id: None)
    resp = await admin_client.post("/admin/backfill-similarity", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/admin?backfill=started")


async def test_background_task_status_partial_denied_to_anonymous(test_client):
    resp = await test_client.get("/admin/background-tasks/1/status-partial", follow_redirects=False)
    assert resp.status_code == 401


async def test_background_task_status_partial_denied_to_member(member_client):
    resp = await member_client.get("/admin/background-tasks/1/status-partial", follow_redirects=False)
    assert resp.status_code == 403


async def test_background_task_status_partial_terminal_stops_polling(admin_client, async_db):
    from app.models import BackgroundTask, BackgroundTaskStatus

    bt = BackgroundTask(name="Test Task", status=BackgroundTaskStatus.COMPLETED)
    async_db.add(bt)
    await async_db.commit()
    await async_db.refresh(bt)

    resp = await admin_client.get(f"/admin/background-tasks/{bt.id}/status-partial")
    assert resp.status_code == 200
    assert "Completed" in resp.text
    assert "every 3s" not in resp.text  # terminal chip must not poll


async def test_background_task_status_partial_missing_404(admin_client):
    resp = await admin_client.get("/admin/background-tasks/999999/status-partial")
    assert resp.status_code == 404


# ── Jobs JSON / HTMX endpoints ──────────────────────────────────────────────


async def test_job_status_partial(test_client, seed_data):
    job = seed_data["job"]
    resp = await test_client.get(f"/jobs/{job.id}/status-partial")
    # 286 is HTMX's "stop polling" signal for terminal jobs (completed/failed/partial)
    assert resp.status_code in (200, 286)


async def test_jobs_table_partial(test_client, seed_data):
    resp = await test_client.get("/jobs/table-partial")
    assert resp.status_code == 200


async def test_job_findings_json(test_client, seed_data):
    job = seed_data["job"]
    resp = await test_client.get(f"/jobs/{job.id}/findings.json")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


async def test_one_admin_visit_runs_the_check_suite_once(admin_client, monkeypatch):
    """The readiness verdict and the System card are the same `run_all()`. Opening /admin
    and then the System tab must not pay for it twice, back to back, with the slowest check
    being a `docker info` that can block for ten seconds."""
    from app import system_checks

    system_checks.reset_check_cache()
    calls = []
    monkeypatch.setattr(system_checks, "run_all", lambda: calls.append(1) or [])

    assert (await admin_client.get("/admin/readiness-partial")).status_code == 200
    assert (await admin_client.get("/admin/system-checks-partial")).status_code == 200

    assert len(calls) == 1, f"the suite ran {len(calls)} times for one page visit"

    # The Re-run button is the escape hatch, and it still works.
    assert (await admin_client.get("/admin/system-checks-partial?force=1")).status_code == 200
    assert len(calls) == 2


async def test_the_checks_card_says_when_it_last_ran(admin_client):
    """Results that never expire and never announce their age read as live when they are not."""
    from app import system_checks

    system_checks.reset_check_cache()
    resp = await admin_client.get("/admin/system-checks-partial")
    assert "Checked" in resp.text
    assert "just now" in resp.text


async def test_the_rerun_button_cannot_stack_clicks(admin_client):
    """No indicator and no disabled state is what made the button read as inert, which is
    what got it clicked repeatedly — each click a full server-side suite."""
    resp = await admin_client.get("/admin/system-checks-partial")
    assert 'hx-disabled-elt="this"' in resp.text
    assert "htmx-indicator" in resp.text
    assert "/admin/system-checks-partial?force=1" in resp.text
