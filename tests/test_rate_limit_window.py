"""Rate-limit window semantics for both production middlewares.

`tests/conftest.py` sets `UPLOAD_RATE_LIMIT_PER_MINUTE=0` so the app-level suite never
produces a 429; these tests drive the middlewares directly against synthetic ASGI scopes
so the limiting logic itself is covered.

What they pin: `INCR` followed by an *unconditional* `EXPIRE` re-anchors the window to the
most recent hit rather than the first. A caller who keeps requesting faster than the window
never lets the key expire, so the counter grows without bound and they stay 429'd forever —
an IOC-feed client polling every 30s under a 120/min limit would lock itself out
permanently after its 120th request.
"""

from __future__ import annotations

import pytest

from app.middleware.production import AuthRateLimitMiddleware, UploadRateLimitMiddleware


async def _inner_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def _drive(mw, scope) -> int:
    messages: list = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await mw(scope, receive, send)
    return next(m for m in messages if m["type"] == "http.response.start")["status"]


def _upload_scope(ip: str = "203.0.113.7"):
    # A real upload always declares its length — a browser form and `fetch` with FormData
    # both do — and POST /upload refuses one that doesn't (411), so a scope with no
    # content-length would never reach the rate limiter these tests are about.
    return {"type": "http", "method": "POST", "path": "/upload", "headers": [(b"content-length", b"64")], "client": (ip, 5000)}


def _feed_scope(token: str = "tok-abc"):
    return {
        "type": "http",
        "method": "GET",
        "path": "/intel/ioc-feed",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "client": ("203.0.113.9", 5000),
    }


# ── The window must actually roll over ───────────────────────────────────────


async def test_ttl_is_anchored_to_the_first_hit_not_the_last(fake_redis):
    """The key's TTL must not be pushed forward by later hits in the same window."""
    mw = UploadRateLimitMiddleware(_inner_app, max_requests=3, window_seconds=60, max_upload_bytes=0)

    assert await _drive(mw, _upload_scope()) == 200
    key = next(iter(fake_redis.scan_iter("logstotal:ratelimit:upload:*")))
    fake_redis.expire(key, 5)  # simulate 55s of the window having elapsed

    await _drive(mw, _upload_scope())
    assert fake_redis.ttl(key) <= 5, "a later request re-armed the window's TTL"


async def test_caller_is_served_again_once_the_window_lapses(fake_redis):
    """Contract test, not the anchoring guard.

    Expiry is simulated by deleting the key, which resets the counter under a re-anchoring
    window too — `test_ttl_is_anchored_to_the_first_hit_not_the_last` above is what catches
    that. This one pins the behaviour operators rely on.
    """
    mw = AuthRateLimitMiddleware(_inner_app, login_max=0, resubmit_max=0, window_seconds=60, ioc_feed_max=2)

    assert await _drive(mw, _feed_scope()) == 200
    assert await _drive(mw, _feed_scope()) == 200
    assert await _drive(mw, _feed_scope()) == 429

    for key in list(fake_redis.scan_iter("logstotal:ratelimit:ioc_feed:*")):
        fake_redis.delete(key)  # the window elapsed

    assert await _drive(mw, _feed_scope()) == 200, "counter did not reset when the window lapsed"


# ── The limit still applies ──────────────────────────────────────────────────


async def test_upload_limit_returns_429_past_the_cap(fake_redis):
    mw = UploadRateLimitMiddleware(_inner_app, max_requests=2, window_seconds=60, max_upload_bytes=0)
    assert [await _drive(mw, _upload_scope()) for _ in range(4)] == [200, 200, 429, 429]


async def test_separate_ips_get_separate_buckets(fake_redis):
    mw = UploadRateLimitMiddleware(_inner_app, max_requests=1, window_seconds=60, max_upload_bytes=0)
    assert await _drive(mw, _upload_scope("198.51.100.1")) == 200
    assert await _drive(mw, _upload_scope("198.51.100.1")) == 429
    assert await _drive(mw, _upload_scope("198.51.100.2")) == 200


async def test_ioc_feed_buckets_by_token_not_ip(fake_redis):
    """Two tokens from one IP must not share a quota — that is the point of the hash key."""
    mw = AuthRateLimitMiddleware(_inner_app, login_max=0, resubmit_max=0, window_seconds=60, ioc_feed_max=1)
    assert await _drive(mw, _feed_scope("token-one")) == 200
    assert await _drive(mw, _feed_scope("token-one")) == 429
    assert await _drive(mw, _feed_scope("token-two")) == 200


async def test_zero_limit_disables_the_check(fake_redis):
    mw = UploadRateLimitMiddleware(_inner_app, max_requests=0, window_seconds=60, max_upload_bytes=0)
    assert [await _drive(mw, _upload_scope()) for _ in range(5)] == [200] * 5


# ── Redis-down fallback ──────────────────────────────────────────────────────


@pytest.fixture()
def broken_redis(monkeypatch):
    import app.redis_client as rc

    def _boom():
        raise ConnectionError("redis is down")

    monkeypatch.setattr(rc, "get_redis", _boom)


async def test_fallback_limits_per_process_when_redis_is_down(broken_redis):
    mw = UploadRateLimitMiddleware(_inner_app, max_requests=2, window_seconds=60, max_upload_bytes=0)
    assert [await _drive(mw, _upload_scope()) for _ in range(4)] == [200, 200, 429, 429]


async def test_fallback_sweeps_stale_buckets(broken_redis):
    """The fallback dict is keyed by client IP and must not grow for the life of an outage."""
    from app.middleware.production import _FALLBACK_SWEEP_AT, _memory_window_limited

    hits: dict[str, list[float]] = {f"stale:{i}": [] for i in range(_FALLBACK_SWEEP_AT + 1)}
    _memory_window_limited(hits, "fresh", limit=5, window_seconds=60)

    assert "fresh" in hits
    assert len(hits) == 1, "expired buckets were never reclaimed"
