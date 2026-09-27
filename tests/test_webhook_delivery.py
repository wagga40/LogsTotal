"""The worker half of a webhook: `deliver_webhook` itself, run in-process.

`tests/test_watch_webhook.py` covers the pure pieces (payload, signing, URL policy, send);
this runs the task body against a real session with the network faked at `webhooks.send`,
so what it pins is the decision the task makes before and after a request goes out.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import WebhookDelivery
from tests.test_watch_rules import _job, _rule, _user


@pytest.fixture(autouse=True)
def _worker_session(sync_db, monkeypatch):
    from app.workers import tasks as tasks_mod

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(sync_db, "close", lambda: None)


@pytest.fixture()
def sent(monkeypatch):
    """Every request `deliver_webhook` would have made, as the pinned address it used."""
    from app.intel import webhooks

    calls: list[str | None] = []

    def fake_send(url, body, headers, *, timeout=5.0, method="POST", pin_ip=None):
        calls.append(pin_ip)
        return 200, None

    monkeypatch.setattr(webhooks.socket, "getaddrinfo", lambda h, p, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr(webhooks, "send", fake_send)
    return calls


def test_a_queued_delivery_is_dropped_once_its_owner_is_deactivated(sync_db, sent):
    """A delivery (or its retry) is queued before the account is switched off and runs after.
    Evaluation already refuses the owner; the send has to agree, or the backoff window is a
    grace period for exactly the account an admin just offboarded."""
    from app.workers import tasks

    owner = _user(sync_db, "o@x.test")
    job = _job(sync_db, owner=owner)
    rule = _rule(sync_db, owner, query="x", webhook_enabled=True, webhook_url="https://hooks.example/x")
    owner.is_active = False
    sync_db.commit()

    tasks.deliver_webhook.call_local(rule.id, job.id, [], 2)

    assert sent == []
    assert sync_db.execute(select(WebhookDelivery)).scalars().all() == []


def _two_family_resolver(monkeypatch):
    from app.intel import webhooks

    monkeypatch.setattr(webhooks.socket, "getaddrinfo", lambda h, p, *a, **k: [(10, 1, 6, "", ("::1", 0, 0, 0)), (2, 1, 6, "", ("127.0.0.1", 0))])


def test_a_receiver_listening_on_one_address_family_is_still_reached(sync_db, monkeypatch):
    """`localhost` resolves to `::1` and `127.0.0.1`. Pinning the first alone made every
    delivery to an IPv4-only receiver (a local n8n, most dev servers) fail with "connection
    refused", retries included — while the rule-list fetch and the AI client, on the same
    guard, already fell through to the next address."""
    from app.intel import webhooks
    from app.workers import tasks

    _two_family_resolver(monkeypatch)
    pins: list[str | None] = []

    def fake_send(url, body, headers, *, timeout=5.0, method="POST", pin_ip=None):
        pins.append(pin_ip)
        return (200, None) if pin_ip == "127.0.0.1" else (None, "ConnectError: connection refused")

    monkeypatch.setattr(webhooks, "send", fake_send)
    owner = _user(sync_db, "o@x.test")
    job = _job(sync_db, owner=owner)
    rule = _rule(sync_db, owner, query="x", webhook_enabled=True, webhook_url="http://localhost:9000/hook")
    sync_db.commit()

    tasks.deliver_webhook.call_local(rule.id, job.id, [], 1)

    assert pins == ["::1", "127.0.0.1"]
    rows = sync_db.execute(select(WebhookDelivery)).scalars().all()
    assert [(r.ok, r.status_code) for r in rows] == [(True, 200)], "one attempt, one row, however many addresses it took"


def test_an_http_answer_is_final_for_the_attempt(sync_db, monkeypatch):
    """A 500 from the first address is the receiver's answer; the other address is the same
    receiver, and asking it again would double-deliver."""
    from app.intel import webhooks
    from app.workers import tasks

    _two_family_resolver(monkeypatch)
    pins: list[str | None] = []
    monkeypatch.setattr(webhooks, "send", lambda url, body, headers, **k: pins.append(k.get("pin_ip")) or (500, None))
    monkeypatch.setattr(tasks.deliver_webhook, "schedule", lambda *a, **k: None)
    owner = _user(sync_db, "o@x.test")
    job = _job(sync_db, owner=owner)
    rule = _rule(sync_db, owner, query="x", webhook_enabled=True, webhook_url="http://localhost:9000/hook")
    sync_db.commit()

    tasks.deliver_webhook.call_local(rule.id, job.id, [], 1)

    assert pins == ["::1"]


def test_zero_retries_means_the_first_attempt_is_the_last(sync_db, monkeypatch, sent):
    from app.config import settings
    from app.intel import webhooks
    from app.workers import tasks

    monkeypatch.setattr(settings, "webhook_max_retries", 0)
    monkeypatch.setattr(webhooks, "send", lambda *a, **k: (503, None))
    scheduled: list[dict] = []
    monkeypatch.setattr(tasks.deliver_webhook, "schedule", lambda *a, **k: scheduled.append(k))
    owner = _user(sync_db, "o@x.test")
    job = _job(sync_db, owner=owner)
    rule = _rule(sync_db, owner, query="x", webhook_enabled=True, webhook_url="https://hooks.example/x")
    sync_db.commit()

    tasks.deliver_webhook.call_local(rule.id, job.id, [7], 1)

    assert scheduled == []


def test_address_fallback_shares_one_deadline(sync_db, monkeypatch):
    from app.config import settings
    from app.intel import webhooks
    from app.workers import tasks

    _two_family_resolver(monkeypatch)
    budgets = []
    # Keep the test deterministic: time advances inside the first connection attempt.
    clock = [100.0]
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    monkeypatch.setattr(settings, "webhook_timeout_seconds", 5)

    def fake_send(*args, timeout, **kwargs):
        budgets.append(timeout)
        clock[0] += 3
        return None, "ConnectError: refused"

    monkeypatch.setattr(webhooks, "send", fake_send)
    owner = _user(sync_db, "budget@x.test")
    rule = _rule(sync_db, owner, query="x", webhook_enabled=True, webhook_url="http://localhost:9000/hook")
    sync_db.commit()
    tasks.deliver_webhook.call_local(rule.id, None, [], 1)
    assert budgets == [5, 2]


def test_read_failures_do_not_redeliver_to_another_address(sync_db, monkeypatch):
    from app.intel import webhooks
    from app.workers import tasks

    _two_family_resolver(monkeypatch)
    calls = []
    monkeypatch.setattr(webhooks, "send", lambda *args, **kwargs: calls.append(kwargs["pin_ip"]) or (None, "timed out"))
    owner = _user(sync_db, "timeout@x.test")
    rule = _rule(sync_db, owner, query="x", webhook_enabled=True, webhook_url="http://localhost:9000/hook")
    sync_db.commit()
    tasks.deliver_webhook.call_local(rule.id, None, [], 1)
    assert calls == ["::1"]
