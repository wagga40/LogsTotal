"""`/admin/activity` and the call sites that feed it.

The end-to-end assertions here are the ones that matter: an action taken through a real
route must land as a row, and deleting the actor must leave that row readable. Both are
things unit tests of `activity.py` cannot see.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import ActivityEvent, SiteSettings

pytestmark = pytest.mark.anyio


async def _enable(db) -> None:
    row = await db.get(SiteSettings, 1)
    if row is None:
        row = SiteSettings(id=1)
        db.add(row)
    row.activity_log_enabled = True
    await db.commit()


async def _events(db, action: str | None = None):
    stmt = select(ActivityEvent).order_by(ActivityEvent.id)
    if action:
        stmt = stmt.where(ActivityEvent.action == action)
    return list((await db.execute(stmt)).scalars().all())


# ── Access ────────────────────────────────────────────────────────────────────


async def test_activity_page_requires_an_admin(member_client):
    assert (await member_client.get("/admin/activity")).status_code in (403, 404)


async def test_activity_page_is_reachable_by_an_admin(admin_client):
    resp = await admin_client.get("/admin/activity")
    assert resp.status_code == 200
    assert "Activity" in resp.text


async def test_the_page_says_so_when_capture_is_off(admin_client):
    """An empty audit page with no explanation reads as broken."""
    resp = await admin_client.get("/admin/activity")
    assert "Capture is off" in resp.text


async def test_reading_is_not_gated_by_the_capture_switch(admin_client, async_db):
    """The whole point of the divergence from `show_ai_prompt`: an operator who turns
    capture off must still be able to read what was already captured."""
    from app import activity

    await _enable(async_db)
    await activity.record("admin.settings.changed", summary="something happened")
    row = await async_db.get(SiteSettings, 1)
    row.activity_log_enabled = False
    await async_db.commit()

    resp = await admin_client.get("/admin/activity")
    assert resp.status_code == 200
    assert "something happened" in resp.text


# ── The write path, through real routes ───────────────────────────────────────


async def test_a_settings_save_records_the_fields_that_changed(admin_client, async_db):
    """ "settings were saved" is nearly worthless next to "someone turned demo_mode on"."""
    await _enable(async_db)
    resp = await admin_client.post(
        "/admin/settings",
        data={"activity_log_enabled": "true", "demo_mode": "true", "max_finding_details": "10"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    rows = await _events(async_db, "admin.settings.changed")
    assert rows, "a settings change must be recorded"
    assert "demo_mode" in rows[-1].summary


async def test_switching_the_activity_log_off_is_the_last_thing_it_records(admin_client, async_db):
    """The diff was computed, the settings committed, and only then `record()` read the
    now-off switch and dropped the row — so the one change that stops the audit trail left
    no trace of who made it, or when."""
    await _enable(async_db)
    resp = await admin_client.post("/admin/settings", data={"max_finding_details": "10"}, follow_redirects=False)  # box unticked
    assert resp.status_code == 303

    rows = await _events(async_db, "admin.settings.changed")
    assert rows, "turning capture off must be recorded"
    assert "activity_log_enabled" in rows[-1].summary


async def test_dropping_the_admin_category_is_recorded_too(admin_client, async_db):
    await _enable(async_db)
    data = {"activity_log_enabled": "true", "max_finding_details": "10", "activity_categories": ["auth", "job"]}
    await admin_client.post("/admin/settings", data=data, follow_redirects=False)
    rows = await _events(async_db, "admin.settings.changed")
    assert rows and "activity_categories" in rows[-1].summary


async def test_a_change_made_while_capture_is_off_is_still_not_recorded(admin_client, async_db):
    """The exception is only for the write that changes the policy itself."""
    await admin_client.post("/admin/settings", data={"max_finding_details": "10", "demo_mode": "true"}, follow_redirects=False)
    assert await _events(async_db, "admin.settings.changed") == []


async def test_an_unchanged_settings_save_records_nothing(admin_client, async_db):
    await _enable(async_db)
    # Post the current state back: `activity_log_enabled` on, everything else default-off.
    await admin_client.post("/admin/settings", data={"activity_log_enabled": "true", "max_finding_details": "10"}, follow_redirects=False)
    before = len(await _events(async_db, "admin.settings.changed"))
    await admin_client.post("/admin/settings", data={"activity_log_enabled": "true", "max_finding_details": "10"}, follow_redirects=False)
    assert len(await _events(async_db, "admin.settings.changed")) == before


async def test_a_failed_login_is_recorded_with_the_attempted_account(test_client, async_db, admin_user):
    """The identity attempted is the entire value of a failed-login row — which is why
    this hooks `UserManager.authenticate` rather than sniffing the response status."""
    await _enable(async_db)
    resp = await test_client.post("/auth/cookie/login", data={"username": "nobody@example.com", "password": "wrongpass123"})
    assert resp.status_code in (400, 401, 422)
    rows = await _events(async_db, "auth.login_failed")
    assert rows, "a failed sign-in must be recorded"
    assert rows[-1].summary == "nobody@example.com"
    assert rows[-1].outcome == "failure"


async def test_the_password_is_never_recorded(test_client, async_db, admin_user):
    await _enable(async_db)
    await test_client.post("/auth/cookie/login", data={"username": "nobody@example.com", "password": "hunter2-secret"})
    for row in await _events(async_db):
        blob = " ".join(str(v) for v in (row.summary, row.metadata_json, row.actor_label) if v)
        assert "hunter2-secret" not in blob


async def test_a_successful_login_is_recorded(test_client, async_db, admin_user):
    await _enable(async_db)
    resp = await test_client.post("/auth/cookie/login", data={"username": "admin@test.example.com", "password": "testpass123"})
    assert resp.status_code in (200, 204, 303)
    rows = await _events(async_db, "auth.login")
    assert rows and rows[-1].actor_label == "admin@test.example.com"


async def test_an_ioc_feed_read_is_recorded(admin_client, async_db):
    """The only record that observables left this instance."""
    await _enable(async_db)
    resp = await admin_client.get("/intel/ioc-feed?format=json")
    assert resp.status_code == 200
    rows = await _events(async_db, "export.ioc_feed")
    assert rows, "an IOC feed read must be recorded"
    assert rows[-1].category == "export"


@pytest.mark.parametrize("path", ["/intel/ioc-feed?format=json", "/intel/cases/{case}/stix", "/intel/cases/{case}/misp", "/intel/cases/{case}/ioc-pack"])
async def test_a_token_export_names_the_token_not_just_its_creator(test_client, async_db, admin_user, path):
    """A token delegates its creator's access, so the row belongs to the creator — but an
    incident review has to tell "the admin exported this" from "a token did", and which
    token to revoke. The cookie row and the token row used to be identical."""
    from app.auth.api_tokens import generate_token
    from app.json_utils import dumps as json_dumps
    from app.models import ApiToken, InvestigationCase

    await _enable(async_db)
    case = InvestigationCase(name="c", created_by_user_id=admin_user.id)
    plaintext, digest, prefix = generate_token()
    async_db.add_all(
        [case, ApiToken(name="integration", token_hash=digest, prefix=prefix, scopes_json=json_dumps(["ioc_feed:read", "case:read"]), created_by_user_id=admin_user.id)]
    )
    await async_db.commit()

    resp = await test_client.get(path.format(case=case.id), headers={"Authorization": f"Bearer {plaintext}"})
    assert resp.status_code == 200, resp.text

    row = (await _events(async_db))[-1]
    assert row.actor_user_id == admin_user.id, "the creator still owns the row"
    assert prefix in (row.actor_label or ""), row.actor_label


async def test_the_actor_ip_is_captured(admin_client, async_db):
    await _enable(async_db)
    await admin_client.get("/intel/ioc-feed?format=json")
    assert (await _events(async_db, "export.ioc_feed"))[-1].actor_ip


# ── Survival ──────────────────────────────────────────────────────────────────


async def test_rows_survive_the_deletion_of_their_actor(admin_client, async_db, member_user):
    """An audit log a user can erase by deleting their own account is not an audit log."""
    from app import activity

    await _enable(async_db)
    await activity.record("auth.login", actor_user_id=member_user.id, actor_label=member_user.email)

    resp = await admin_client.post(f"/admin/users/{member_user.id}/delete", follow_redirects=False)
    assert resp.status_code == 303

    rows = await _events(async_db, "auth.login")
    assert rows, "the row must not be deleted with the user"
    assert rows[-1].actor_user_id is None, "the FK must be nulled"
    assert rows[-1].actor_label == "member@test.example.com", "the snapshot must keep it legible"


# ── CSV + prune ───────────────────────────────────────────────────────────────


async def test_csv_export_returns_a_download(admin_client, async_db):
    from app import activity

    await _enable(async_db)
    await activity.record("auth.login", actor_label="someone@example.com")
    resp = await admin_client.get("/admin/activity/export.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]
    assert "someone@example.com" in resp.text


async def test_csv_export_honours_the_active_filter(admin_client, async_db):
    from app import activity

    await _enable(async_db)
    await activity.record("auth.login", actor_label="in-scope@example.com")
    await activity.record("export.ioc_feed", actor_label="out-of-scope@example.com")
    resp = await admin_client.get("/admin/activity/export.csv?category=auth")
    assert "in-scope@example.com" in resp.text
    assert "out-of-scope@example.com" not in resp.text


async def test_prune_refuses_a_non_positive_window(admin_client):
    assert (await admin_client.post("/admin/activity/prune", data={"days": "0"}, follow_redirects=False)).status_code == 400


async def test_the_filter_narrows_the_table(admin_client, async_db):
    from app import activity

    await _enable(async_db)
    await activity.record("auth.login", actor_label="alice@example.com")
    await activity.record("export.ioc_feed", actor_label="bob@example.com")

    resp = await admin_client.get("/admin/activity/partial?category=auth")
    assert "alice@example.com" in resp.text
    assert "bob@example.com" not in resp.text


@pytest.fixture()
async def commentable_job(async_db):
    """One public, completed job — the only thing the discussion tests need.

    Local rather than imported from `test_comments.py`: that fixture builds four users,
    two cases and an entity for its own visibility matrix, and depending on it would couple
    these tests to a shape they do not care about.
    """
    from app.models import AnalysisJob, JobStatus, LogFile, WorkflowDef

    async_db.add_all(
        [
            LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10),
            WorkflowDef(id=1, name="wf"),
        ]
    )
    await async_db.commit()
    job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)
    return job


# ── Discussions ───────────────────────────────────────────────────────────────


async def test_posting_a_comment_is_recorded(admin_client, async_db, commentable_job):
    """Discussions are their own category, not split between `job` and `intel` by target —
    one thread partial serves all three, so splitting would put one feature in two filters."""
    await _enable(async_db)
    resp = await admin_client.post(f"/comments/job/{commentable_job.id}", data={"body": "looks like a false positive"})
    assert resp.status_code == 200

    rows = await _events(async_db, "discussion.comment")
    assert rows, "posting a comment must be recorded"
    assert rows[-1].category == "discussion"
    assert rows[-1].target_type == "job"


async def test_the_comment_text_is_never_recorded(admin_client, async_db, commentable_job):
    """An audit log that duplicated every analyst's prose would be a second, unmanaged copy
    of the thing `Comment`'s soft delete exists to remove properly."""
    secret = "the CFO clicked the link on purpose"
    await _enable(async_db)
    await admin_client.post(f"/comments/job/{commentable_job.id}", data={"body": secret})

    for row in await _events(async_db):
        blob = " ".join(str(v) for v in (row.summary, row.metadata_json) if v)
        assert secret not in blob


async def test_deleting_someone_elses_comment_says_so(admin_client, async_db, commentable_job, member_user):
    """An admin or case owner removing a colleague's words is the case this record is for."""
    from app.models import Comment

    await _enable(async_db)
    comment = Comment(job_id=commentable_job.id, author_user_id=member_user.id, body="mine")
    async_db.add(comment)
    await async_db.commit()
    await async_db.refresh(comment)

    resp = await admin_client.post(f"/comments/{comment.id}/delete")
    assert resp.status_code == 200
    rows = await _events(async_db, "discussion.delete")
    assert rows and "another author's" in rows[-1].summary


async def test_an_empty_comment_records_nothing(admin_client, async_db, commentable_job):
    """A blank submit is a no-op re-render, not an event."""
    await _enable(async_db)
    await admin_client.post(f"/comments/job/{commentable_job.id}", data={"body": "   "})
    assert await _events(async_db, "discussion.comment") == []


async def test_the_discussion_category_can_be_suppressed_on_its_own(admin_client, async_db, commentable_job):
    """The reason it has its own switch: comment metadata is the most sensitive thing here,
    and suppressing it must not cost you the admin trail."""
    from app.models import SiteSettings

    await _enable(async_db)
    row = await async_db.get(SiteSettings, 1)
    row.activity_categories = "auth,admin"
    await async_db.commit()

    await admin_client.post(f"/comments/job/{commentable_job.id}", data={"body": "hello"})
    assert await _events(async_db, "discussion.comment") == []


# ── JSON export ───────────────────────────────────────────────────────────────


async def test_json_export_returns_a_download(admin_client, async_db):
    from app import activity

    await _enable(async_db)
    await activity.record("auth.login", actor_label="someone@example.com")
    resp = await admin_client.get("/admin/activity/export.json")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]

    payload = resp.json()
    assert payload["count"] == len(payload["events"]) >= 1
    assert payload["truncated"] is False
    assert payload["events"][0]["actor"]["label"] == "someone@example.com"


async def test_json_export_keeps_metadata_structured(admin_client, async_db):
    """The whole reason for a second format: CSV flattens metadata_json into a string, so
    the changed-field diff on a settings save survives the export only here."""
    from app import activity

    await _enable(async_db)
    await activity.record("admin.settings.changed", meta={"changed": {"demo_mode": {"from": False, "to": True}}})
    payload = (await admin_client.get("/admin/activity/export.json")).json()
    event = next(e for e in payload["events"] if e["action"] == "admin.settings.changed")
    assert event["metadata"]["changed"]["demo_mode"]["to"] is True


async def test_json_export_honours_the_active_filter(admin_client, async_db):
    from app import activity

    await _enable(async_db)
    await activity.record("auth.login", actor_label="in-scope@example.com")
    await activity.record("export.ioc_feed", actor_label="out-of-scope@example.com")
    payload = (await admin_client.get("/admin/activity/export.json?category=auth")).json()
    actors = {e["actor"]["label"] for e in payload["events"]}
    assert "in-scope@example.com" in actors
    assert "out-of-scope@example.com" not in actors


async def test_both_exports_agree_about_what_a_filter_means(admin_client, async_db):
    """They share `_filtered_query` and `_filters_from` so a filter that narrows one cannot
    silently widen the other."""
    from app import activity

    await _enable(async_db)
    for label in ("a@example.com", "b@example.com"):
        await activity.record("auth.login", actor_label=label)
    await activity.record("export.ioc_feed", actor_label="c@example.com")

    csv_text = (await admin_client.get("/admin/activity/export.csv?category=auth")).text
    json_rows = (await admin_client.get("/admin/activity/export.json?category=auth")).json()["events"]
    assert len(csv_text.strip().splitlines()) - 1 == len(json_rows)


async def test_the_page_offers_both_formats(admin_client):
    page = (await admin_client.get("/admin/activity")).text
    assert "/admin/activity/export.csv" in page
    assert "/admin/activity/export.json" in page


# ── Tags ──────────────────────────────────────────────────────────────────────


@pytest.fixture()
async def taggable_entities(async_db):
    from app.models import Entity

    rows = [Entity(value=f"10.0.0.{i}", entity_type="ip_address", job_count=1) for i in range(1, 4)]
    async_db.add_all(rows)
    await async_db.commit()
    for row in rows:
        await async_db.refresh(row)
    return rows


async def test_tagging_an_entity_is_recorded(admin_client, async_db, taggable_entities):
    await _enable(async_db)
    entity = taggable_entities[0]
    resp = await admin_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "c2", "color": "red"})
    assert resp.status_code == 200

    rows = await _events(async_db, "intel.tag.add")
    assert rows and "c2" in rows[-1].summary
    assert rows[-1].target_type == "entity"


async def test_re_adding_an_existing_tag_records_nothing(admin_client, async_db, taggable_entities):
    """Re-adding to apply a colour is a recolour, not a tagging — recording it would make
    the log claim work that did not happen."""
    await _enable(async_db)
    entity = taggable_entities[0]
    await admin_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "c2", "color": "red"})
    before = len(await _events(async_db, "intel.tag.add"))
    await admin_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "c2", "color": "blue"})
    assert len(await _events(async_db, "intel.tag.add")) == before


async def test_untagging_an_entity_is_recorded(admin_client, async_db, taggable_entities):
    await _enable(async_db)
    entity = taggable_entities[0]
    await admin_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "c2", "color": "red"})
    resp = await admin_client.post(f"/intel/entities/{entity.id}/tags/remove", data={"tag": "c2"})
    assert resp.status_code == 200
    assert await _events(async_db, "intel.tag.remove")


async def test_a_bulk_tag_records_one_row_with_the_count(admin_client, async_db, taggable_entities):
    """One row per bulk operation, not per entity: a 200-entity tag that buried everything
    else under it would be the fastest way to make this log unreadable."""
    await _enable(async_db)
    ids = ",".join(str(e.id) for e in taggable_entities)
    resp = await admin_client.post("/intel/entities/bulk-tag", data={"entity_ids": ids, "tag": "sweep", "color": "amber"})
    assert resp.status_code == 200

    rows = await _events(async_db, "intel.tag.add")
    assert len(rows) == 1, "a bulk operation must be one row"
    assert "3 entities" in rows[-1].summary


async def test_a_bulk_tag_that_changed_nothing_records_nothing(admin_client, async_db, taggable_entities):
    await _enable(async_db)
    ids = ",".join(str(e.id) for e in taggable_entities)
    await admin_client.post("/intel/entities/bulk-tag", data={"entity_ids": ids, "tag": "sweep"})
    before = len(await _events(async_db, "intel.tag.add"))
    await admin_client.post("/intel/entities/bulk-tag", data={"entity_ids": ids, "tag": "sweep"})
    assert len(await _events(async_db, "intel.tag.add")) == before


async def test_renaming_a_tag_records_both_names(admin_client, async_db):
    await _enable(async_db)
    await admin_client.post("/intel/tags", data={"tag": "old-name", "color": "gray"})
    resp = await admin_client.post("/intel/tags/rename", data={"tag": "old-name", "new_tag": "new-name"})
    assert resp.status_code == 200

    rows = await _events(async_db, "intel.tag.rename")
    assert rows and "old-name" in rows[-1].summary and "new-name" in rows[-1].summary


async def test_merging_and_recolouring_are_recorded(admin_client, async_db):
    await _enable(async_db)
    await admin_client.post("/intel/tags", data={"tag": "alpha"})
    await admin_client.post("/intel/tags", data={"tag": "beta"})
    await admin_client.post("/intel/tags/merge", data={"tag": "alpha", "into": "beta"})
    await admin_client.post("/intel/tags/recolor", data={"tag": "beta", "color": "teal"})

    assert await _events(async_db, "intel.tag.merge")
    assert await _events(async_db, "intel.tag.recolor")
    assert len(await _events(async_db, "intel.tag.create")) == 2


# ── Watch rules ───────────────────────────────────────────────────────────────


async def _make_rule(client, name="test rule", **extra):
    data = {"name": name, "query": "10.0.0.1", "entity_types": "", **extra}
    return await client.post("/intel/rules", data=data)


async def test_creating_editing_and_toggling_a_rule_are_recorded(admin_client, async_db):
    """A watch rule POSTs to a URL its owner chose whenever it matches, so every change to
    one is a change to outbound traffic."""
    from sqlalchemy import select

    from app.models import IntelRule

    await _enable(async_db)
    assert (await _make_rule(admin_client)).status_code == 200
    rule = (await async_db.execute(select(IntelRule))).scalars().first()
    assert rule is not None

    await admin_client.post(f"/intel/rules/{rule.id}/edit", data={"name": "renamed rule", "query": "10.0.0.2", "entity_types": ""})
    await admin_client.post(f"/intel/rules/{rule.id}/toggle")

    assert await _events(async_db, "intel.watch_rule.create")
    assert await _events(async_db, "intel.watch_rule.edit")
    toggled = await _events(async_db, "intel.watch_rule.toggle")
    assert toggled and ("enabled" in toggled[-1].summary or "disabled" in toggled[-1].summary)


async def test_acknowledging_alerts_is_recorded_once_per_sweep(admin_client, async_db):
    """Ack-all is one row carrying the count, like a bulk tag — and the bell and the Watch
    page share the write, so they share the record too."""
    await _enable(async_db)
    resp = await admin_client.post("/intel/rules/alerts/ack-all")
    assert resp.status_code == 200

    rows = await _events(async_db, "intel.watch_alert.ack")
    assert len(rows) == 1
    assert "alert(s) acknowledged" in rows[-1].summary


async def test_the_ack_count_is_reported_not_discarded(async_db, member_user):
    """`ack_all_visible_alerts` returns how many it touched: "12 alerts acknowledged" is a
    different statement from "acknowledged"."""
    from app.routers.intel_rules import ack_all_visible_alerts

    assert await ack_all_visible_alerts(async_db, member_user) == 0


async def test_tag_and_watch_events_are_filterable_as_intel(admin_client, async_db, taggable_entities):
    await _enable(async_db)
    await admin_client.post(f"/intel/entities/{taggable_entities[0].id}/tags", data={"tag": "c2"})
    await _make_rule(admin_client)

    page = (await admin_client.get("/admin/activity?category=intel")).text
    assert "Tag applied" in page
    assert "Watch rule created" in page


# ── One bad row must not hide the whole log ───────────────────────────────────


#: Every `meta` shape a call site in this codebase actually writes, plus the two that broke
#: it. `changed` is typed as `{field: {from, to}}` and the table calls `.items()` on it — so
#: a bare count or a list of names under that key raised inside the row loop and took out the
#: *entire* page and partial, for every admin, until the row aged out.
_META_SHAPES = [
    None,
    {},
    {"changed": {"demo_mode": {"from": True, "to": False}}},  # admin.settings.changed
    {"fields": ["description", "tasks_yaml"]},  # admin.workflow.update
    {"hosts": 2},  # admin.worker.priority
    {"changed": 2},  # legacy row: a count under `changed`
    {"changed": ["a", "b"]},  # legacy row: a list of names under `changed`
    {"changed": "everything"},
    {"changed": {"x": "not-a-mapping"}},
]


@pytest.mark.parametrize("meta", _META_SHAPES, ids=lambda m: str(m)[:34])
async def test_the_activity_table_renders_every_metadata_shape(admin_client, async_db, meta):
    """A malformed audit row is a rendering problem, never an availability one.

    This is asserted per shape rather than in one row, because the failure is a raise inside
    the `{% for %}` over rows: with them all in one fixture a single tolerated shape could
    mask the rest.
    """
    from app.json_utils import dumps as json_dumps

    await _enable(async_db)
    async_db.add(
        ActivityEvent(
            action="admin.settings.changed",
            category="admin",
            actor_label="admin@test.example.com",
            summary="probe",
            metadata_json=None if meta is None else json_dumps(meta),
            outcome="success",
        )
    )
    await async_db.commit()

    for url in ("/admin/activity", "/admin/activity/partial"):
        resp = await admin_client.get(url)
        assert resp.status_code == 200, f"{url} broke on meta={meta!r}"
        assert "probe" in resp.text


async def test_no_call_site_writes_a_non_mapping_under_the_changed_key():
    """`changed` has one meaning. Two call sites reused the name for a count and for a list
    of field names, and neither was visible until an admin opened the log."""
    import ast
    from pathlib import Path

    offenders = []
    for path in sorted((Path(__file__).resolve().parent.parent / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values, strict=False):
                if not (isinstance(key, ast.Constant) and key.value == "changed"):
                    continue
                # A Name resolves at runtime, so only flag literals we can judge here.
                if isinstance(value, ast.List | ast.Tuple | ast.Set) or (isinstance(value, ast.Constant) and not isinstance(value.value, dict)):
                    offenders.append(f"{path.name}:{key.lineno}")
    assert not offenders, f'meta["changed"] must be a {{field: {{from, to}}}} mapping — see {offenders}'


# ── The pager ─────────────────────────────────────────────────────────────────


async def test_the_pager_moves_past_the_second_page_and_keeps_the_filter(admin_client, async_db):
    """The pager's links carried the request's whole query string, `page` included, so
    from page 2 on every link read `?page=3&page=2` — the last `page` wins — and the log
    was stuck on page 2 whatever was clicked. The link has to name one page and the filter."""
    import re
    from urllib.parse import parse_qs, urlsplit

    from app.activity import _build

    async_db.add_all(_build("auth.login", actor_label=f"user{i}@example.com", summary=f"event {i}") for i in range(130))
    await async_db.commit()

    resp = await admin_client.get("/admin/activity/partial?page=2&category=auth")
    assert resp.status_code == 200
    next_url = re.search(r'aria-label="Next page"[^>]*hx-get="([^"]+)"', resp.text)
    assert next_url, "no Next button on page 2 of 3"
    url = next_url.group(1).replace("&amp;", "&")
    params = parse_qs(urlsplit(url).query)
    assert params.get("page") == ["3"], f"the Next link must name page 3 and only page 3: {url}"
    assert params.get("category") == ["auth"], f"the filter must travel with the pager: {url}"

    page3 = await admin_client.get(url)
    assert page3.status_code == 200
    assert re.search(r'aria-current="page"[^>]*>\s*3\s*<', page3.text), "following Next from page 2 did not land on page 3"
