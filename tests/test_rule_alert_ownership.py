"""Whose alert is it? One answer for showing an alert and for acknowledging it.

Rule *visibility* and alert *ownership* are different questions. A member may read every
shared rule — it is the vocabulary behind tags they see daily — but an alert raised by a
shared rule an admin switched "alert me" on is the admin's. The bell counted alerts by
ownership and acknowledged them by visibility, so a member's "Acknowledge all" (its badge
showing 0) cleared the admin's alert before the admin ever saw it. And the Rules page listed
alerts from personal rules only, so the admin could not find that alert there either.
"""

from __future__ import annotations

import uuid

import pytest

from app.models import AnalysisJob, Entity, IntelRule, IntelRuleMatch, JobStatus, LogFile, LogType, WorkflowDef

pytestmark = pytest.mark.anyio


async def _login(client, email):
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "testpass123"})
    assert resp.status_code in (200, 204, 303)


@pytest.fixture()
async def shared_alert(async_db, admin_user, member_user):
    wf = WorkflowDef(name="W", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    lf = LogFile(original_filename="a.evtx", stored_filename=f"{uuid.uuid4()}.evtx", sha256="c" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([wf, lf])
    await async_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, is_private=False)
    entity = Entity(value="mshta.exe", entity_type="executable")
    rule = IntelRule(name="LOLBin", owner_user_id=None, is_builtin=True, builtin_key="lolbin", scope="entity", query="mshta", entity_types="[]", action_notify=True, enabled=True)
    async_db.add_all([job, entity, rule])
    await async_db.flush()
    match = IntelRuleMatch(rule_id=rule.id, entity_id=entity.id, job_id=job.id)
    async_db.add(match)
    await async_db.commit()
    return match


async def test_a_members_acknowledge_all_leaves_a_shared_rule_alert_alone(test_client, async_db, shared_alert):
    await _login(test_client, "member@test.example.com")
    assert (await test_client.get("/intel/watchlist-events-partial?count_only=1")).text.strip() in ("", "0"), "precondition: not the member's"

    await test_client.post("/intel/watchlist-events/ack-all")
    await test_client.post("/intel/rules/alerts/ack-all")

    await async_db.refresh(shared_alert)
    assert shared_alert.acknowledged_at is None


async def test_a_member_cannot_acknowledge_a_shared_rule_alert_by_id(test_client, async_db, shared_alert):
    await _login(test_client, "member@test.example.com")
    for path in (f"/intel/watchlist-events/{shared_alert.id}/ack", f"/intel/rules/alerts/{shared_alert.id}/ack"):
        assert (await test_client.post(path)).status_code == 404, path
    await async_db.refresh(shared_alert)
    assert shared_alert.acknowledged_at is None


async def test_the_admin_finds_a_shared_rule_alert_on_the_rules_page(test_client, async_db, shared_alert):
    await _login(test_client, "admin@test.example.com")
    body = (await test_client.get("/intel/rules")).text
    assert f"/intel/rules/alerts/{shared_alert.id}/ack" in body
