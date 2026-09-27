"""`/admin/storage` — access, the retention override, and the reclaim actions."""

from __future__ import annotations

import pytest

from app.models import BackgroundTask, SiteSettings

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
def _clear_storage_cache():
    from app import storage_usage

    storage_usage.reset_cache()
    yield
    storage_usage.reset_cache()


# ── Access ────────────────────────────────────────────────────────────────────


async def test_the_page_requires_an_admin(member_client):
    assert (await member_client.get("/admin/storage")).status_code in (403, 404)


async def test_the_page_renders(admin_client):
    resp = await admin_client.get("/admin/storage")
    assert resp.status_code == 200
    for marker in ("Uploaded logs", "Tool output", "Unowned data", "Retention"):
        assert marker in resp.text


async def test_the_page_names_what_the_dashboard_total_leaves_out(admin_client):
    """The dashboard has always shown SUM(LogFile.size_bytes) alone, which excludes every
    byte under uploads/job_*/ — usually most of the growth."""
    resp = await admin_client.get("/admin/storage")
    assert "not counted by the dashboard total" in resp.text


async def test_the_database_footprint_loads_separately(admin_client):
    """Lazy because on SQLite it opens a connection and reads dbstat, which does not belong
    on the critical path of a page opened to check free space."""
    resp = await admin_client.get("/admin/storage/db-footprint-partial")
    assert resp.status_code == 200
    assert "Total" in resp.text


# ── Retention override ────────────────────────────────────────────────────────


async def test_setting_an_override_records_it(admin_client, async_db):
    resp = await admin_client.post("/admin/storage/retention", data={"job_output_retention_days": "14"}, follow_redirects=False)
    assert resp.status_code == 303
    row = await async_db.get(SiteSettings, 1)
    assert row.job_output_retention_days_override == 14


async def test_an_empty_field_clears_the_override(admin_client, async_db):
    """How an operator gets back to "whatever .env says" without remembering what it was."""
    await admin_client.post("/admin/storage/retention", data={"job_output_retention_days": "14"}, follow_redirects=False)
    await admin_client.post("/admin/storage/retention", data={"job_output_retention_days": ""}, follow_redirects=False)
    row = await async_db.get(SiteSettings, 1)
    assert row.job_output_retention_days_override is None


async def test_a_non_numeric_override_is_refused(admin_client):
    assert (await admin_client.post("/admin/storage/retention", data={"job_output_retention_days": "soon"}, follow_redirects=False)).status_code == 400


async def test_zero_is_a_valid_override_meaning_keep_forever(admin_client, async_db):
    await admin_client.post("/admin/storage/retention", data={"job_output_retention_days": "0"}, follow_redirects=False)
    row = await async_db.get(SiteSettings, 1)
    assert row.job_output_retention_days_override == 0


async def test_the_settings_page_never_touches_the_override(admin_client, async_db):
    """It is not on that form, and if it ever were added with a default it would silently
    reset from a page that does not show it."""
    await admin_client.post("/admin/storage/retention", data={"job_output_retention_days": "7"}, follow_redirects=False)
    await admin_client.post("/admin/settings", data={"max_finding_details": "10"}, follow_redirects=False)
    row = await async_db.get(SiteSettings, 1)
    assert row.job_output_retention_days_override == 7


def test_the_resolver_reports_where_the_value_came_from():
    from app.config import settings
    from app.models import SiteSettings as SS
    from app.retention import effective_retention

    plain = SS(id=1)
    resolved = effective_retention("job_output_retention_days", plain)
    assert resolved.days == settings.job_output_retention_days
    assert resolved.source == "JOB_OUTPUT_RETENTION_DAYS"

    overridden = SS(id=1, job_output_retention_days_override=5)
    resolved = effective_retention("job_output_retention_days", overridden)
    assert resolved.days == 5
    assert resolved.overridden is True


def test_only_the_output_window_is_overridable():
    """The other windows stay env-only, consistent with the five that came before. This is
    the one anyone actually turns."""
    from app.retention import OVERRIDABLE

    assert OVERRIDABLE == ("job_output_retention_days",)


def test_the_sweep_and_the_page_share_one_resolver():
    """Two readers of the same pair would drift within two releases."""
    import inspect

    from app.workers import tasks as worker_tasks

    assert "effective_retention" in inspect.getsource(worker_tasks.cleanup_old_job_outputs.func)


# ── Reclaim actions ───────────────────────────────────────────────────────────


async def test_purging_orphans_queues_a_task(admin_client, async_db, monkeypatch):
    """Queued, not inline: it is a delete loop over storage and belongs on /admin/tasks
    with the rest of the work, including its cancel button."""
    from sqlalchemy import select

    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "purge_orphaned_storage", lambda *a, **k: None)
    resp = await admin_client.post("/admin/storage/purge-orphans", follow_redirects=False)
    assert resp.status_code == 303

    rows = (await async_db.execute(select(BackgroundTask))).scalars().all()
    assert [r.kind for r in rows] == ["purge_orphaned_storage"]


async def test_running_retention_now_queues_the_same_task_the_sweep_uses(admin_client, async_db, monkeypatch):
    from sqlalchemy import select

    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "cleanup_old_job_outputs", lambda *a, **k: None)
    resp = await admin_client.post("/admin/storage/run-retention", follow_redirects=False)
    assert resp.status_code == 303

    rows = (await async_db.execute(select(BackgroundTask))).scalars().all()
    assert [r.kind for r in rows] == ["cleanup_old_job_outputs"]


async def test_vacuum_queues_on_sqlite(admin_client, async_db, monkeypatch):
    from sqlalchemy import select

    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "vacuum_database", lambda *a, **k: None)
    resp = await admin_client.post("/admin/storage/vacuum", follow_redirects=False)
    assert resp.status_code == 303

    rows = (await async_db.execute(select(BackgroundTask))).scalars().all()
    assert [r.kind for r in rows] == ["vacuum_database"]


@pytest.mark.parametrize("path, task", [("/admin/storage/purge-orphans", "purge_orphaned_storage"), ("/admin/storage/vacuum", "vacuum_database")])
async def test_a_second_click_does_not_queue_a_second_run(admin_client, async_db, monkeypatch, path, task):
    """Two purges walk and delete the same objects; two VACUUMs take SQLite's exclusive lock
    twice. Run-retention already refused a duplicate; these two did not."""
    from sqlalchemy import select

    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, task, lambda *a, **k: None)
    await admin_client.post(path, follow_redirects=False)
    second = await admin_client.post(path, follow_redirects=False)

    assert "queued=already" in second.headers["location"]
    assert len((await async_db.execute(select(BackgroundTask))).scalars().all()) == 1


@pytest.mark.parametrize(
    "path, task",
    [("/admin/storage/purge-orphans", "purge_orphaned_storage"), ("/admin/storage/run-retention", "cleanup_old_job_outputs"), ("/admin/storage/vacuum", "vacuum_database")],
)
async def test_a_storage_action_the_queue_refuses_is_failed_not_left_pending(admin_client, async_db, monkeypatch, path, task):
    from sqlalchemy import select

    from app.models import BackgroundTaskStatus
    from app.workers import tasks as worker_tasks

    def _unreachable(*a, **k):
        raise ConnectionError("Error 111 connecting to localhost:6379")

    monkeypatch.setattr(worker_tasks, task, _unreachable)
    resp = await admin_client.post(path, follow_redirects=False)
    assert resp.status_code == 303
    assert "queued=unreachable" in resp.headers["location"]
    row = (await async_db.execute(select(BackgroundTask))).scalars().one()
    assert row.status == BackgroundTaskStatus.FAILED


async def test_vacuum_is_refused_on_postgresql(admin_client, monkeypatch):
    """PostgreSQL autovacuums; offering the button there implies a problem that does not
    exist."""
    from app.config import settings

    monkeypatch.setattr(settings, "database_url", "postgresql+asyncpg://u:p@localhost/db")
    assert (await admin_client.post("/admin/storage/vacuum", follow_redirects=False)).status_code == 400


async def test_reclaim_actions_require_an_admin(member_client):
    for path in ("/admin/storage/purge-orphans", "/admin/storage/run-retention", "/admin/storage/vacuum", "/admin/storage/retention"):
        assert (await member_client.post(path, follow_redirects=False)).status_code in (403, 404)


# ── The shared byte formatter ─────────────────────────────────────────────────


@pytest.mark.parametrize("value,expected", [(0, "0 B"), (512, "512 B"), (2048, "2.0 KB"), (1_073_741_824, "1.0 GB"), (None, "0 B"), ("nope", "—")])
def test_humanbytes(value, expected):
    """One implementation. The dashboard and the job page each carried their own ladder,
    which is how they came to disagree about the boundary."""
    from app.templates_config import templates

    assert templates.env.filters["humanbytes"](value) == expected
