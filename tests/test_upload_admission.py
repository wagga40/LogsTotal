"""Admission is shared, bounded, and happens before multipart spooling."""

import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.config import settings
from app.middleware.upload_admission import _BYTES, _LEASES, UploadAdmissionMiddleware, release_upload, renew_upload, reserve_upload


@pytest.fixture()
def space(monkeypatch):
    monkeypatch.setattr("app.storage.free_bytes_for_uploads", lambda: 2 * 1024**3)
    monkeypatch.setattr("app.middleware.upload_admission.shutil.disk_usage", lambda _: SimpleNamespace(free=2 * 1024**3))


def test_concurrent_slot_limit_and_release(fake_redis, monkeypatch, space):
    monkeypatch.setattr(settings, "upload_max_concurrent", 2)
    reserve_upload("one", 100)
    reserve_upload("two", 100)
    with pytest.raises(HTTPException) as exc:
        reserve_upload("three", 100)
    assert exc.value.status_code == 429
    release_upload("one")
    reserve_upload("three", 100)
    assert fake_redis.hlen(_BYTES) == 2
    assert renew_upload("three")


def test_storage_reservation_counts_other_uploads(fake_redis, space):
    reserve_upload("one", 700 * 1024**2)
    with pytest.raises(HTTPException) as exc:
        reserve_upload("two", 400 * 1024**2)
    assert exc.value.status_code == 507


def test_dead_lease_is_reclaimed(fake_redis, space, monkeypatch):
    monkeypatch.setattr(settings, "upload_max_concurrent", 1)
    reserve_upload("dead", 100)
    fake_redis.zadd(_LEASES, {"dead": time.time() - 1})
    reserve_upload("new", 100)
    assert fake_redis.hgetall(_BYTES) == {"new": "100"}


async def test_authentication_failure_does_not_read_body(fake_redis):
    touched = []

    async def inner(scope, receive, send):
        touched.append("inner")

    async def receive():
        touched.append("body")
        return {"type": "http.request", "body": b"data"}

    messages = []

    async def send(message):
        messages.append(message)

    await UploadAdmissionMiddleware(inner)({"type": "http", "method": "POST", "path": "/api/v1/jobs", "headers": [(b"content-length", b"4")], "query_string": b""}, receive, send)
    assert touched == []
    assert messages[0]["status"] == 401


async def test_failure_releases_reservation(fake_redis, space):
    async def inner(scope, receive, send):
        raise RuntimeError("parse failure")

    async def unused(*args):
        pass

    with pytest.raises(RuntimeError):
        await UploadAdmissionMiddleware(inner)({"type": "http", "method": "POST", "path": "/upload", "headers": [(b"content-length", b"4")], "query_string": b""}, unused, unused)
    assert fake_redis.hlen(_BYTES) == fake_redis.zcard(_LEASES) == 0


async def test_busy_slot_uses_a_short_retry_instead_of_the_quota_delay(fake_redis, space, monkeypatch):
    monkeypatch.setattr(settings, "upload_max_concurrent", 1)
    reserve_upload("occupied", 100)
    messages = []

    async def inner(*args):
        pytest.fail("Busy uploads must be rejected before parsing")

    async def send(message):
        messages.append(message)

    await UploadAdmissionMiddleware(inner)({"type": "http", "method": "POST", "path": "/upload", "headers": [(b"content-length", b"4")], "query_string": b""}, inner, send)
    assert messages[0]["status"] == 429
    assert dict(messages[0]["headers"])[b"retry-after"] == b"5"


async def test_lost_lease_closes_partial_multipart_with_a_503(fake_redis, space):
    """A reservation that disappeared must not permit more spool writes."""
    from starlette.requests import Request
    from starlette.responses import Response

    messages = []

    async def inner(scope, receive, send):
        scope.setdefault("state", {})["upload_lease_lost"] = True
        try:
            await Request(scope, receive).form()
        except Exception:
            await Response(status_code=400)(scope, receive, send)

    async def receive():
        return {"type": "http.request", "body": b"--test--\r\n", "more_body": False}

    async def send(message):
        messages.append(message)

    await UploadAdmissionMiddleware(inner)(
        {
            "type": "http",
            "method": "POST",
            "path": "/upload",
            "query_string": b"",
            "headers": [(b"content-length", b"10"), (b"content-type", b"multipart/form-data; boundary=test")],
        },
        receive,
        send,
    )
    assert messages[0]["status"] == 503
    assert sum(m["type"] == "http.response.start" for m in messages) == 1
    assert fake_redis.hlen(_BYTES) == 0


async def test_forged_small_length_cannot_exceed_reserved_space():
    from starlette.requests import Request
    from starlette.responses import Response

    from app.middleware.production import RequestBodyLimitMiddleware

    messages = []

    async def inner(scope, receive, send):
        await Request(scope, receive).body()
        await Response(status_code=200)(scope, receive, send)

    async def receive():
        return {"type": "http.request", "body": b"more than declared", "more_body": False}

    async def send(message):
        messages.append(message)

    await RequestBodyLimitMiddleware(inner, max_upload_bytes=1024)(
        {"type": "http", "method": "POST", "path": "/api/v1/jobs", "state": {"upload_reserved": True}, "headers": [(b"content-length", b"1")]}, receive, send
    )
    assert messages[0]["status"] == 413
