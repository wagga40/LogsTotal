"""Tier-2 tests for fetch_enrichment with an injected resolver and a fake httpx client."""

from __future__ import annotations

import httpx
import pytest

from app.intel.live_enrichment import fetch_enrichment


def _public_resolver(host):
    return ["8.8.8.8"]


class _FakeResp:
    """Stands in for a streamed httpx response.

    ``chunk_size`` splits the body so a test can prove the cap stops the read partway
    instead of measuring an already-buffered ``.content``; ``chunks_read`` records how
    much was actually pulled off the wire.
    """

    def __init__(self, status_code: int, text: str, *, chunk_size: int | None = None):
        self.status_code = status_code
        self._text = text
        self.encoding = "utf-8"
        self._chunk_size = chunk_size or max(len(text), 1)
        self.chunks_read = 0

    async def aiter_bytes(self):
        raw = self._text.encode("utf-8")
        for i in range(0, len(raw), self._chunk_size):
            self.chunks_read += 1
            yield raw[i : i + self._chunk_size]


def _fake_client_factory(resp: _FakeResp, calls: list):
    class _FakeStream:
        async def __aenter__(self):
            return resp

        async def __aexit__(self, *a):
            return False

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, headers=None, extensions=None):
            calls.append((method, url, headers, extensions))
            return _FakeStream()

    return _FakeClient


async def _seed(async_db, *, provider="virustotal", template="https://www.virustotal.com/api/v3/files/{value}"):
    from app.models import EnrichmentService, Entity

    e = Entity(value="44d88612fea8a8f36de82e1278abb02f", entity_type="hash", job_count=1)
    svc = EnrichmentService(name="VT", provider_key=provider, entity_types='["hash"]', api_template=template, api_method="GET", enabled=True, cache_ttl_seconds=86400)
    async_db.add_all([e, svc])
    await async_db.commit()
    return e, svc


@pytest.mark.asyncio
async def test_successful_fetch_stores_summary(async_db, fake_redis, monkeypatch):
    e, svc = await _seed(async_db)
    body = '{"data":{"attributes":{"last_analysis_stats":{"malicious":3,"harmless":60,"undetected":7}}}}'
    calls: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(_FakeResp(200, body), calls))

    row = await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)
    await async_db.commit()

    assert row.ok is True
    assert len(calls) == 1
    import json

    summary = json.loads(row.summary_json)
    assert summary["detections"] == "3 / 70"
    assert row.expires_at is not None


@pytest.mark.asyncio
async def test_fetch_pins_connection_to_validated_ip(async_db, fake_redis, monkeypatch):
    e, svc = await _seed(async_db)
    calls: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(_FakeResp(200, "{}"), calls))

    await fetch_enrichment(async_db, e, svc, resolver=lambda host: ["8.8.8.8"])

    assert len(calls) == 1
    _method, url, headers, extensions = calls[0]
    # Connection targets the pinned IP, not the hostname (rebinding-safe).
    assert "8.8.8.8" in url
    assert "virustotal.com" not in url
    # Host + SNI keep the real hostname for routing and cert verification.
    assert headers.get("Host") == "www.virustotal.com"
    assert extensions == {"sni_hostname": "www.virustotal.com"}


@pytest.mark.asyncio
async def test_ssrf_block_does_not_call_httpx(async_db, fake_redis, monkeypatch):
    e, svc = await _seed(async_db, provider=None, template="http://169.254.169.254/latest/{value}")
    calls: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(_FakeResp(200, "{}"), calls))

    row = await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)

    assert row.ok is False
    assert "SSRF" in (row.error_message or "")
    assert calls == []  # never hit the network


@pytest.mark.asyncio
async def test_allowlist_blocks_wrong_host_for_known_provider(async_db, fake_redis, monkeypatch):
    # provider=virustotal but template points elsewhere -> allowlist rejects
    e, svc = await _seed(async_db, provider="virustotal", template="https://evil.example.com/{value}")
    calls: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(_FakeResp(200, "{}"), calls))

    row = await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)
    assert row.ok is False
    assert calls == []


@pytest.mark.asyncio
async def test_http_error_status_recorded(async_db, fake_redis, monkeypatch):
    e, svc = await _seed(async_db)
    calls: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(_FakeResp(404, "not found"), calls))

    row = await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)
    assert row.ok is False
    assert "404" in (row.error_message or "")


@pytest.mark.asyncio
async def test_fresh_cache_hit_skips_network(async_db, fake_redis, monkeypatch):
    e, svc = await _seed(async_db)
    body = '{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"harmless":9}}}}'
    calls: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(_FakeResp(200, body), calls))

    first = await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)
    await async_db.commit()
    assert len(calls) == 1
    # second call within TTL -> served from cache, no new request
    second = await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)
    assert len(calls) == 1
    assert second.id == first.id


@pytest.mark.asyncio
async def test_force_refetches_even_when_cached(async_db, fake_redis, monkeypatch):
    e, svc = await _seed(async_db)
    body = '{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"harmless":9}}}}'
    calls: list = []
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(_FakeResp(200, body), calls))

    await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)
    await async_db.commit()
    await fetch_enrichment(async_db, e, svc, force=True, resolver=_public_resolver)
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_oversized_response_stops_reading_at_the_cap(async_db, fake_redis, monkeypatch):
    """Checked against `.content`, which only exists once httpx has buffered the entire
    body, the 64 KB limit would let an enormous response be fully held in the web process
    before being rejected. It must stop pulling instead."""
    from app.intel.live_enrichment import MAX_RESPONSE_BYTES

    e, svc = await _seed(async_db)
    chunk = 8 * 1024
    huge = "x" * (MAX_RESPONSE_BYTES * 8)
    resp = _FakeResp(200, huge, chunk_size=chunk)
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(resp, []))

    row = await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)
    await async_db.commit()

    assert row.ok is False
    assert row.error_message == "response too large"
    # Enough chunks to pass the cap, and then it stopped — not the whole 512 KB.
    max_expected = MAX_RESPONSE_BYTES // chunk + 1
    assert resp.chunks_read <= max_expected, f"read {resp.chunks_read} chunks; should have stopped by {max_expected}"


@pytest.mark.asyncio
async def test_response_exactly_at_the_cap_is_accepted(async_db, fake_redis, monkeypatch):
    from app.intel.live_enrichment import MAX_RESPONSE_BYTES

    e, svc = await _seed(async_db)
    body = '{"data":' + '"' + "y" * (MAX_RESPONSE_BYTES - 20) + '"}'
    assert len(body.encode()) <= MAX_RESPONSE_BYTES
    monkeypatch.setattr(httpx, "AsyncClient", _fake_client_factory(_FakeResp(200, body), []))

    row = await fetch_enrichment(async_db, e, svc, resolver=_public_resolver)
    await async_db.commit()

    assert row.error_message != "response too large"


@pytest.mark.asyncio
async def test_a_stub_listening_on_one_address_family_is_still_reached(async_db, fake_redis, monkeypatch):
    """With ENRICHMENT_REQUIRE_PUBLIC_HOST=false a service can be a local stub, and
    `localhost` resolves to `::1` and `127.0.0.1`. Pinning only the first recorded "network
    error" against a stub listening on IPv4. The webhook, AI and rule-list clients fall
    through to the next validated address; this one now does too."""
    from app.config import settings

    monkeypatch.setattr(settings, "enrichment_require_public_host", False)
    e, svc = await _seed(async_db, provider="custom", template="http://localhost:8951/{value}")
    calls: list = []
    ok_resp = _FakeResp(200, '{"ok": true}')

    class _Stream:
        def __init__(self, url):
            self.url = url

        async def __aenter__(self):
            if "[::1]" in self.url:
                raise httpx.ConnectError("connection refused")
            return ok_resp

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
            calls.append(url)
            return _Stream(url)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    row = await fetch_enrichment(async_db, e, svc, resolver=lambda host: ["::1", "127.0.0.1"])

    assert row.ok is True, row.error_message
    assert len(calls) == 2 and "127.0.0.1" in calls[1]
