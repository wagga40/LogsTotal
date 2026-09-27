"""Integration tests for the admin dashboard and settings."""

from __future__ import annotations

import pytest


async def test_admin_dashboard_requires_auth(test_client):
    """GET /admin without auth should return 401 or redirect to login."""
    resp = await test_client.get("/admin", follow_redirects=False)
    assert resp.status_code in (401, 403)


async def test_admin_dashboard_loads(admin_client):
    """GET /admin as superuser should return 200 and render the getting-started card."""
    resp = await admin_client.get("/admin")
    assert resp.status_code == 200
    assert "Getting started" in resp.text


async def test_concurrency_partial_requires_auth(test_client):
    """GET /admin/concurrency-partial without auth should be rejected."""
    resp = await test_client.get("/admin/concurrency-partial", follow_redirects=False)
    assert resp.status_code in (401, 403)


async def test_concurrency_partial_empty_state(admin_client):
    """With no workers alive (fake Redis empty), the card shows the empty state."""
    resp = await admin_client.get("/admin/concurrency-partial")
    assert resp.status_code == 200
    assert "Start a worker to see live capacity" in resp.text


async def test_concurrency_partial_lists_live_worker(admin_client, fake_redis):
    """A published worker-info hash surfaces as a per-host capacity row."""
    fake_redis.hset(
        "logstotal:worker:info:hostX:100",
        mapping={"hostname": "hostX", "huey_workers": "2", "cpu_count": "8"},
    )
    resp = await admin_client.get("/admin/concurrency-partial")
    assert resp.status_code == 200
    assert "hostX" in resp.text
    assert "Start a worker to see live capacity" not in resp.text


async def test_admin_settings_page_loads(admin_client):
    """GET /admin/settings should render the settings form."""
    resp = await admin_client.get("/admin/settings")
    assert resp.status_code == 200
    assert "settings" in resp.text.lower() or "Settings" in resp.text


async def test_admin_settings_save(admin_client):
    """POST /admin/settings should persist and redirect."""
    resp = await admin_client.post(
        "/admin/settings",
        data={
            "parallel_execution": "on",
            "max_finding_details": "20",
            "show_mitre_heatmap": "on",
            "show_event_timeline": "on",
            "show_entities": "on",
            "show_threat_detection": "on",
            "demo_mode": "",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "saved=1" in resp.headers.get("location", "")


async def test_upload_selection_limit_persists_and_reaches_the_homepage(admin_client, async_db):
    from app.models import SiteSettings

    response = await admin_client.post("/admin/settings", data={"max_upload_files": "125"}, follow_redirects=False)
    assert response.status_code == 303
    assert (await async_db.get(SiteSettings, 1)).max_upload_files == 125
    page = await admin_client.get("/")
    assert 'data-max-files="125"' in page.text
    assert "up to 125 files" in page.text.lower()
    settings = await admin_client.get("/admin/settings")
    assert 'name="max_upload_files"' in settings.text and 'value="125"' in settings.text
    # A saved form from before the field existed must not reset the new limit.
    await admin_client.post("/admin/settings", data={"max_finding_details": "20"})
    assert (await async_db.get(SiteSettings, 1)).max_upload_files == 125


@pytest.mark.parametrize("value", ["0", "-1", "501", "1.5", "invalid"])
async def test_upload_selection_limit_rejects_invalid_values(admin_client, async_db, value):
    from app.site_settings import get_site_settings

    settings = await get_site_settings(async_db)
    response = await admin_client.post("/admin/settings", data={"max_upload_files": value}, follow_redirects=False)
    assert response.status_code == 422
    await async_db.refresh(settings)
    assert settings.max_upload_files == 50


async def test_only_admins_can_change_upload_selection_limit(user_client):
    response = await user_client.post("/admin/settings", data={"max_upload_files": "125"})
    assert response.status_code in (401, 403)


# `/health` is covered in tests/test_integration_routes.py.


async def test_the_two_timelines_have_independent_switches(admin_client, async_db):
    """Two switches, not one: gated together, the two timelines read as one redundant feature.

    The histogram answers "when was there activity, and of what tactic" and preserves each
    tool's own offset; the events timeline answers "what happened, in what order" in UTC
    and survives raw-output cleanup. Keeping one while dropping the other has to be possible.
    """
    from sqlalchemy import select

    from app.models import SiteSettings

    resp = await admin_client.post(
        "/admin/settings",
        data={
            "max_finding_details": "10",
            "show_event_timeline": "on",  # histogram on
            # show_alert_timeline omitted -> off
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    async_db.expire_all()
    s = (await async_db.execute(select(SiteSettings))).scalars().first()
    assert s.show_event_timeline is True
    assert s.show_alert_timeline is False


async def test_each_switch_hides_only_its_own_panel(admin_client, async_db):
    """The gates are separate in the templates too, not just in the model."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "app" / "templates"
    analytics = (root / "partials" / "_analytics.html").read_text()
    case_tl = (root / "intel" / "partials" / "_case_timeline.html").read_text()

    # The histogram card is gated on show_event_timeline...
    hist = re.search(r"analytics\.timeline and \(not site_settings or site_settings\.(\w+)\)", analytics)
    assert hist and hist.group(1) == "show_event_timeline"

    # ...and every events-timeline include on show_alert_timeline.
    for name, text in (("_analytics.html", analytics), ("_case_timeline.html", case_tl)):
        idx = text.index("_events_timeline.html")
        gate = text.rfind("site_settings.show_", 0, idx)
        assert text[gate:].startswith("site_settings.show_alert_timeline"), f"{name} gates the events timeline on the wrong flag"
