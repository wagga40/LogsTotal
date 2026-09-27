"""Tests for trusted-proxy client IP resolution."""

from __future__ import annotations

from sqlalchemy import select

from app.models import AnalysisJob, LogFile, WorkflowDef
from app.network.client_ip import get_client_ip_from_scope


def test_get_client_ip_from_scope_uses_peer_when_proxy_trust_disabled(monkeypatch):
    monkeypatch.setattr("app.config.settings.trust_proxy_headers", False)
    scope = {
        "type": "http",
        "client": ("127.0.0.1", 12345),
        "headers": [(b"x-forwarded-for", b"198.51.100.10")],
    }
    assert get_client_ip_from_scope(scope) == "127.0.0.1"


def test_get_client_ip_from_scope_uses_forwarded_for_from_trusted_proxy(monkeypatch):
    monkeypatch.setattr("app.config.settings.trust_proxy_headers", True)
    monkeypatch.setattr("app.config.settings.trusted_proxy_cidrs", "127.0.0.1/32")
    scope = {
        "type": "http",
        "client": ("127.0.0.1", 12345),
        "headers": [(b"x-forwarded-for", b"198.51.100.10")],
    }
    assert get_client_ip_from_scope(scope) == "198.51.100.10"


def test_forwarded_for_is_read_from_the_right(monkeypatch):
    """The leftmost entry is client-supplied; the rightmost was written by our proxy.

    A chain is built by appending, so with `X-Forwarded-For: <a>, <b>` the final proxy
    wrote `b` and `a` is whatever the caller chose to send. Reading from the left let
    anyone pick their own IP, and since every rate limit buckets per IP, rotating the
    header gave a fresh bucket each time — login, upload and resubmit limits all became
    unenforceable behind the reverse proxy the project ships.

    Here 10.0.0.2 is an undeclared hop, so it is the closest address we did not take on
    faith. Declaring it (below) is what makes the client address reachable again.
    """
    monkeypatch.setattr("app.config.settings.trust_proxy_headers", True)
    monkeypatch.setattr("app.config.settings.trusted_proxy_cidrs", "127.0.0.1/32")
    scope = {
        "type": "http",
        "client": ("127.0.0.1", 12345),
        "headers": [(b"x-forwarded-for", b"198.51.100.10, 10.0.0.2")],
    }
    assert get_client_ip_from_scope(scope) == "10.0.0.2"


def test_declaring_every_hop_recovers_the_real_client(monkeypatch):
    """Multi-hop deployments must list all their proxies — the standard contract."""
    monkeypatch.setattr("app.config.settings.trust_proxy_headers", True)
    monkeypatch.setattr("app.config.settings.trusted_proxy_cidrs", "127.0.0.1/32, 10.0.0.0/8")
    scope = {
        "type": "http",
        "client": ("127.0.0.1", 12345),
        "headers": [(b"x-forwarded-for", b"198.51.100.10, 10.0.0.2")],
    }
    assert get_client_ip_from_scope(scope) == "198.51.100.10"


def test_a_forged_prefix_cannot_displace_the_appended_peer(monkeypatch):
    """The attack shape: junk on the left, the proxy's own observation on the right."""
    monkeypatch.setattr("app.config.settings.trust_proxy_headers", True)
    monkeypatch.setattr("app.config.settings.trusted_proxy_cidrs", "127.0.0.1/32")
    scope = {
        "type": "http",
        "client": ("127.0.0.1", 12345),
        "headers": [(b"x-forwarded-for", b"1.1.1.1, 2.2.2.2, 203.0.113.9")],
    }
    assert get_client_ip_from_scope(scope) == "203.0.113.9"


def test_an_all_trusted_chain_still_resolves_to_an_address(monkeypatch):
    """An internal probe through the proxy should not fall through to the peer."""
    monkeypatch.setattr("app.config.settings.trust_proxy_headers", True)
    monkeypatch.setattr("app.config.settings.trusted_proxy_cidrs", "10.0.0.0/8")
    scope = {
        "type": "http",
        "client": ("10.0.0.1", 12345),
        "headers": [(b"x-forwarded-for", b"10.0.0.5, 10.0.0.2")],
    }
    assert get_client_ip_from_scope(scope) == "10.0.0.5"


def test_get_client_ip_from_scope_ignores_spoofed_forwarded_for(monkeypatch):
    monkeypatch.setattr("app.config.settings.trust_proxy_headers", True)
    monkeypatch.setattr("app.config.settings.trusted_proxy_cidrs", "127.0.0.1/32")
    scope = {
        "type": "http",
        "client": ("203.0.113.9", 23456),
        "headers": [(b"x-forwarded-for", b"198.51.100.10")],
    }
    assert get_client_ip_from_scope(scope) == "203.0.113.9"


async def test_upload_persists_forwarded_ip_when_trusted(test_client, async_db, monkeypatch):
    monkeypatch.setattr("app.config.settings.trust_proxy_headers", True)
    monkeypatch.setattr("app.config.settings.trusted_proxy_cidrs", "*")

    wf = WorkflowDef(
        name="IP Workflow",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks:\n  - tool: zircolite\n    tool_path: tools/zircolite/zircolite.py\n    rules_path: tools/zircolite/rules\n",
        is_default=True,
    )
    async_db.add(wf)
    await async_db.commit()
    await async_db.refresh(wf)

    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(wf.id), "log_type_override": "auto"},
        files={"file": ("ip.evtx", b"ElfFile\x00" + b"\x02" * 64, "application/octet-stream")},
        headers={"X-Forwarded-For": "198.51.100.77"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    job = await async_db.scalar(select(AnalysisJob).order_by(AnalysisJob.id.desc()).limit(1))
    assert job is not None
    assert job.submitter_ip == "198.51.100.77"

    log_file = await async_db.scalar(select(LogFile).where(LogFile.id == job.file_id))
    assert log_file is not None
    assert log_file.uploader_ip == "198.51.100.77"
