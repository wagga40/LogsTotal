"""Editing a watch rule, and the webhook fields that came with it.

Two behaviours here are easy to get wrong in ways that fail silently:

* **A blank secret on edit means "leave it alone."** The form cannot echo a secret back, so
  treating blank as "clear" would silently unsign every future delivery the first time
  someone renamed a rule.
* **Custom headers must not be able to override ours.** A rule owner naming
  `X-LogsTotal-Signature` in their extra headers would otherwise forge the signature their
  own receiver validates.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.intel.webhooks import delivery_headers
from app.json_utils import dumps as json_dumps
from app.models import IntelRule


@pytest.fixture()
async def rule(async_db, member_user):
    r = IntelRule(name="Original", owner_user_id=member_user.id, query="label:lolbin", entity_types='["executable"]')
    async_db.add(r)
    await async_db.commit()
    await async_db.refresh(r)
    return r


async def _reload(async_db, rule_id):
    return (await async_db.execute(select(IntelRule).where(IntelRule.id == rule_id))).scalar_one()


def _form(**over):
    base = {"name": "Original", "query": "label:lolbin", "entity_types": "executable", "webhook_method": "POST", "webhook_enabled": "1", "action_notify": "1"}
    base.update(over)
    return base


class TestEdit:
    async def test_edits_criteria_and_name(self, member_client, async_db, rule):
        resp = await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(name="Renamed", query="label:dga"))
        assert resp.status_code == 200
        r = await _reload(async_db, rule.id)
        assert (r.name, r.query) == ("Renamed", "label:dga")

    async def test_a_basic_user_cannot_edit_a_rule(self, user_client, rule):
        """`user_client` and `member_client` are the SAME client object — requesting both
        in one test logs in twice and the last one wins, so this asks for only one."""
        assert (await user_client.post(f"/intel/rules/{rule.id}/edit", data=_form())).status_code == 403

    async def test_missing_rule_is_a_404(self, member_client, rule):
        assert (await member_client.post("/intel/rules/999999/edit", data=_form())).status_code == 404

    async def test_empty_name_is_refused(self, member_client, async_db, rule):
        assert (await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(name="   "))).status_code == 400
        assert (await _reload(async_db, rule.id)).name == "Original"


class TestWebhookFields:
    async def test_method_is_validated(self, member_client, async_db, rule):
        assert (await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_method="DELETE"))).status_code == 400

    async def test_headers_must_be_a_json_object(self, member_client, rule):
        assert (await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_headers="[1,2]"))).status_code == 400
        assert (await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_headers="not json"))).status_code == 400

    async def test_header_names_with_newlines_are_refused(self, member_client, rule):
        """A newline in a value would inject a second header — or a second request."""
        resp = await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_headers='{"X-A": "a\\r\\nX-Evil: b"}'))
        assert resp.status_code == 400

    async def test_reserved_headers_are_refused(self, member_client, rule):
        for name in ("Host", "content-length", "Content-Type"):
            resp = await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_headers=json_dumps({name: "x"})))
            assert resp.status_code == 400, name

    async def test_valid_headers_are_stored_canonically(self, member_client, async_db, rule):
        await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_url="https://example.test/h", webhook_headers='{"X-Auth-Token": "abc"}'))
        r = await _reload(async_db, rule.id)
        assert '"X-Auth-Token"' in r.webhook_headers_json

    async def test_webhook_is_disabled_without_a_url(self, member_client, async_db, rule):
        await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_url="", webhook_enabled="1"))
        assert (await _reload(async_db, rule.id)).webhook_enabled is False


class TestSecretHandling:
    async def test_blank_secret_on_edit_keeps_the_existing_one(self, member_client, async_db, rule):
        """Otherwise renaming a rule silently unsigns every future delivery."""
        await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_url="https://example.test/h", webhook_secret="s3cr3t"))
        before = (await _reload(async_db, rule.id)).webhook_secret_encrypted
        assert before

        await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(name="Renamed", webhook_url="https://example.test/h", webhook_secret=""))
        assert (await _reload(async_db, rule.id)).webhook_secret_encrypted == before

    async def test_clear_secret_removes_it(self, member_client, async_db, rule):
        await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_url="https://example.test/h", webhook_secret="s3cr3t"))
        await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_url="https://example.test/h", clear_secret="1"))
        assert (await _reload(async_db, rule.id)).webhook_secret_encrypted is None

    async def test_secret_is_encrypted_at_rest(self, member_client, async_db, rule):
        await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_url="https://example.test/h", webhook_secret="s3cr3t"))
        assert "s3cr3t" not in ((await _reload(async_db, rule.id)).webhook_secret_encrypted or "")


class TestHeaderPrecedence:
    def test_our_headers_win_over_custom_ones(self):
        """A rule owner must not be able to forge the signature their receiver checks."""
        h = delivery_headers(7, "1700000000", "sha256=real", {"X-LogsTotal-Signature": "sha256=forged", "X-Auth": "keep"})
        assert h["X-LogsTotal-Signature"] == "sha256=real"
        assert h["X-LogsTotal-Timestamp"] == "1700000000"
        assert h["Content-Type"] == "application/json"
        assert h["X-Auth"] == "keep"


class TestTestDelivery:
    async def test_test_requires_a_webhook_url(self, member_client, rule):
        assert (await member_client.post(f"/intel/rules/{rule.id}/test")).status_code == 400

    async def test_test_is_accepted_when_configured(self, member_client, async_db, rule, fake_redis):
        await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(webhook_url="https://example.test/h"))
        assert (await member_client.post(f"/intel/rules/{rule.id}/test")).status_code == 200
