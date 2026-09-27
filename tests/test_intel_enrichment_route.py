"""Integration tests for the live-enrichment routes."""

from __future__ import annotations

import httpx
import pytest


class _FakeResp:
    """Streamed-response double — fetch_enrichment reads the body in chunks and stops
    at MAX_RESPONSE_BYTES rather than buffering it all and measuring afterwards."""

    def __init__(self, status_code, text):
        self.status_code = status_code
        self._text = text
        self.encoding = "utf-8"

    async def aiter_bytes(self):
        yield self._text.encode()


def _fake_client(resp):
    class _Stream:
        async def __aenter__(self):
            return resp

        async def __aexit__(self, *a):
            return False

    class _C:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, headers=None, extensions=None):
            return _Stream()

    return _C


async def _seed(async_db):
    from app.models import EnrichmentService, Entity

    e = Entity(value="44d88612fea8a8f36de82e1278abb02f", entity_type="hash", job_count=1)
    svc = EnrichmentService(
        name="VT", provider_key="virustotal", entity_types='["hash"]', api_template="https://www.virustotal.com/api/v3/files/{value}", enabled=True, cache_ttl_seconds=86400
    )
    async_db.add_all([e, svc])
    await async_db.commit()
    return e, svc


@pytest.mark.asyncio
async def test_enrichment_partial_lists_service(member_client, async_db):
    e, _svc = await _seed(async_db)
    resp = await member_client.get(f"/intel/entities/{e.id}/enrichment-partial")
    assert resp.status_code == 200
    assert "Live Enrichment" in resp.text
    assert "VT" in resp.text
    assert "Fetch" in resp.text


@pytest.mark.asyncio
async def test_enrich_post_fetches_and_renders_summary(member_client, async_db, fake_redis, monkeypatch):
    e, svc = await _seed(async_db)
    body = '{"data":{"attributes":{"last_analysis_stats":{"malicious":4,"harmless":60,"undetected":6}}}}'
    # Patch httpx, and stub DNS: the URL host is www.virustotal.com, which the allowlist
    # accepts and which must not actually be looked up. This patch was inert until the
    # resolver stopped being bound as a parameter default (a default is evaluated once at
    # import, so it captured the original function), and the route passes no `resolver=` —
    # so this test quietly made a real getaddrinfo call and was the only one in the suite
    # that did. It failed on any runner without outbound DNS.
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client(_FakeResp(200, body)))
    monkeypatch.setattr("app.intel.live_enrichment._default_resolver", lambda host: ["8.8.8.8"])

    resp = await member_client.post(f"/intel/entities/{e.id}/enrich/{svc.id}")
    assert resp.status_code == 200
    assert "4 / 70" in resp.text  # rendered summary
    assert "Refresh" in resp.text  # now cached -> button flips to Refresh


@pytest.mark.asyncio
async def test_enrich_requires_member(user_client, async_db):
    e, svc = await _seed(async_db)
    resp = await user_client.post(f"/intel/entities/{e.id}/enrich/{svc.id}")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_a_service_is_not_sent_a_type_it_was_not_configured_for(member_client, async_db, fake_redis, monkeypatch):
    """An admin scopes VirusTotal to hashes so internal usernames never leave the instance.
    The panel only offered matching services, but the POST took any pair of ids — and sent
    `CORP\\alice` to VirusTotal with the organisation's key."""
    from app.models import Entity

    _e, svc = await _seed(async_db)
    user_entity = Entity(value="CORP\\alice", entity_type="user", job_count=1)
    async_db.add(user_entity)
    await async_db.commit()
    sent: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _recording_client(sent))
    monkeypatch.setattr("app.intel.live_enrichment._default_resolver", lambda host: ["8.8.8.8"])

    resp = await member_client.post(f"/intel/entities/{user_entity.id}/enrich/{svc.id}")
    assert resp.status_code == 404
    assert sent == []


def _recording_client(sent):
    class _Stream:
        async def __aenter__(self):
            return _FakeResp(200, "{}")

        async def __aexit__(self, *a):
            return False

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, headers=None, extensions=None):
            sent.append(url)
            return _Stream()

    return _Client


@pytest.mark.asyncio
async def test_an_unexpected_lookup_error_is_recorded_not_a_500(member_client, async_db, fake_redis, monkeypatch):
    """httpx raises UnicodeEncodeError, not an HTTPError, for a non-ASCII header value. The
    route rolled back — expiring the entity and service — then read their attributes and
    500'd with MissingGreenlet, and the failure it meant to record was lost."""
    e, svc = await _seed(async_db)
    svc.api_headers_json = '{"X-Note": "café"}'
    await async_db.commit()

    async def _boom(*a, **k):
        raise UnicodeEncodeError("ascii", "café", 3, 4, "ordinal not in range(128)")

    monkeypatch.setattr("app.intel.live_enrichment.fetch_enrichment", _boom)

    resp = await member_client.post(f"/intel/entities/{e.id}/enrich/{svc.id}")
    assert resp.status_code == 200
    assert "lookup failed (UnicodeEncodeError)" in resp.text
