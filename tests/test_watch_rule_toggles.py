"""An unticked checkbox has to actually turn the thing off.

HTML omits an unchecked checkbox from the form body entirely. Both watch-rule toggles —
"Raise an alert for every match" (`action_notify`) and "Send deliveries for this rule"
(`webhook_enabled`) — were declared `Form(1)`, so the absent field fell back to the
default and the setting came back on: the box unticked, the form saved, and nothing
changed. There is no error to notice, which is what made it survive.

These go through the real routes rather than calling `_apply_rule_fields`, because the
defect lives in the signature the framework fills in, not in the body of the function.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import IntelRule, User

pytestmark = pytest.mark.anyio


async def _member(async_db) -> User:
    manager = UserManager(SQLAlchemyUserDatabase(async_db, User))
    return await manager.create(UserCreate(email="rules@example.com", password="pass123456", is_superuser=False, is_active=True, role="member"))


async def _login(client) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": "rules@example.com", "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


@pytest.fixture()
async def logged_in(test_client, async_db):
    await _member(async_db)
    await _login(test_client)
    return test_client


async def _only_rule(async_db) -> IntelRule:
    async_db.expire_all()
    return (await async_db.execute(select(IntelRule))).scalars().one()


async def test_creating_a_rule_with_both_boxes_ticked(logged_in, async_db):
    """The happy path, so "always off" cannot pass."""
    resp = await logged_in.post(
        "/intel/rules",
        data={"name": "on", "query": "evil", "action_notify": "1", "webhook_url": "https://hooks.example/x", "webhook_enabled": "1"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 303), resp.text
    rule = await _only_rule(async_db)
    assert rule.action_notify is True
    assert rule.webhook_enabled is True


async def test_creating_a_rule_with_the_boxes_unticked(logged_in, async_db):
    """Unticked means absent from the body — the exact shape a browser sends."""
    resp = await logged_in.post(
        "/intel/rules",
        data={"name": "off", "query": "evil", "webhook_url": "https://hooks.example/x"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 303), resp.text
    rule = await _only_rule(async_db)
    assert rule.action_notify is False, "'Raise an alert for every match' could not be turned off"
    assert rule.webhook_enabled is False, "'Send deliveries for this rule' could not be turned off"


async def test_editing_a_rule_can_turn_both_off_again(logged_in, async_db):
    await logged_in.post(
        "/intel/rules",
        data={"name": "r", "query": "evil", "action_notify": "1", "webhook_url": "https://hooks.example/x", "webhook_enabled": "1"},
        follow_redirects=False,
    )
    rule = await _only_rule(async_db)
    assert (rule.action_notify, rule.webhook_enabled) == (True, True)

    resp = await logged_in.post(
        f"/intel/rules/{rule.id}/edit",
        data={"name": "r", "query": "evil", "webhook_url": "https://hooks.example/x"},
        follow_redirects=False,
    )
    assert resp.status_code in (200, 303), resp.text
    rule = await _only_rule(async_db)
    assert rule.action_notify is False
    assert rule.webhook_enabled is False


async def test_the_preview_agrees_with_the_rule_about_entity_types(logged_in):
    """ "executable, domain" — with the space a person types — must not drop `domain`.

    The preview kept the unstripped token while the save path stripped it, so the number
    shown while typing contradicted the rule that got saved.
    """
    spaced = await logged_in.get("/intel/rules/preview?query=&entity_types=executable,%20domain")
    tight = await logged_in.get("/intel/rules/preview?query=&entity_types=executable,domain")
    assert spaced.status_code == 200
    assert spaced.text == tight.text
