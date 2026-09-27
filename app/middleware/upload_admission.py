"""Reserve bounded temporary storage before FastAPI parses multipart uploads."""

import asyncio
import contextlib
import shutil
import tempfile
import time
import uuid

from fastapi import HTTPException
from redis.exceptions import WatchError
from starlette.concurrency import run_in_threadpool
from starlette.formparsers import MultiPartException
from starlette.requests import Request

from app.config import settings
from app.middleware.production import _error_response, _redis_window_hits
from app.redis_client import get_redis

_LEASES = "logstotal:uploads:leases"
_BYTES = "logstotal:uploads:bytes"
_LEASE_SECONDS = 120
_HEADROOM = 1024 * 1024 * 1024


def require_upload_lease(request):
    if request.scope.get("state", {}).get("upload_lease_lost"):
        raise HTTPException(503, "Upload coordination was interrupted. Check the submission receipt before retrying.")


def reserve_upload(owner, size):
    """WATCH makes admission atomic across web processes; dead leases self-expire.

    Reserve both the parser spool and the storage spool. Using the smaller free
    volume is conservative when /tmp and uploads are on different filesystems.
    """
    from app.storage import free_bytes_for_uploads

    free = free_bytes_for_uploads()
    if free is None:
        raise HTTPException(507, "Cannot determine available upload storage")
    free = min(free, shutil.disk_usage(tempfile.gettempdir()).free)
    r = get_redis()
    for _ in range(10):
        with r.pipeline() as pipe:
            try:
                pipe.watch(_LEASES, _BYTES)
                stale = pipe.zrangebyscore(_LEASES, "-inf", time.time())
                allocations = pipe.hgetall(_BYTES)
                active = {key: int(value) for key, value in allocations.items() if key not in stale}
                if len(active) >= max(1, settings.upload_max_concurrent):
                    raise HTTPException(429, "Upload capacity is busy. Waiting for a slot.", headers={"Retry-After": "5"})
                if free - sum(active.values()) - size < _HEADROOM:
                    raise HTTPException(507, "The server is low on temporary storage. Try again later.")
                pipe.multi()
                if stale:
                    pipe.zrem(_LEASES, *stale)
                    pipe.hdel(_BYTES, *stale)
                pipe.zadd(_LEASES, {owner: time.time() + _LEASE_SECONDS})
                pipe.hset(_BYTES, owner, size)
                pipe.expire(_LEASES, _LEASE_SECONDS * 2)
                pipe.expire(_BYTES, _LEASE_SECONDS * 2)
                pipe.execute()
                return
            except WatchError:
                continue
    raise HTTPException(429, "Upload capacity is busy. Try again shortly.", headers={"Retry-After": "5"})


def release_upload(owner):
    with get_redis().pipeline(transaction=True) as pipe:
        pipe.zrem(_LEASES, owner)
        pipe.hdel(_BYTES, owner)
        pipe.execute()


def renew_upload(owner):
    with get_redis().pipeline(transaction=True) as pipe:
        pipe.zadd(_LEASES, {owner: time.time() + _LEASE_SECONDS}, xx=True)
        pipe.expire(_LEASES, _LEASE_SECONDS * 2)
        pipe.expire(_BYTES, _LEASE_SECONDS * 2)
        pipe.execute()
    # ZADD without CH counts new members only; presence is checked separately.
    return get_redis().zscore(_LEASES, owner) is not None


async def upload_identity(scope):
    """Authenticate before parsing; route dependencies still enforce all scopes."""
    from app import database
    from app.auth.api_tokens import _bearer_attempted, _extract_bearer, _has_scope, _lookup_token
    from app.auth.users import user_for_error_page

    request = Request(scope)
    if _bearer_attempted(request):
        raw = _extract_bearer(request)
        async with database.async_session_maker() as db:
            token = await _lookup_token(db, raw) if raw else None
            if token is None or token.created_by_user_id is None:
                raise HTTPException(401, "Invalid bearer token")
            if not _has_scope(token, "job:submit"):
                raise HTTPException(403, "Token missing required scope: job:submit")
            return str(token.created_by_user_id)
    user = await user_for_error_page(request)
    if user is None and scope["path"] == "/api/v1/jobs":
        raise HTTPException(401, "Cookie session or bearer token required")
    return str(user.id) if user else None


class UploadAdmissionMiddleware:
    PATHS = frozenset({"/upload", "/api/v1/jobs"})

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST" or scope.get("path") not in self.PATHS:
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        declared = headers.get(b"content-length", b"")
        if not declared.isdigit() or len(declared) > 20:
            return await _error_response(scope, 411, "Upload requires a Content-Length header.")(scope, receive, send)
        size = int(declared)
        if size > settings.max_upload_bytes + 1024 * 1024:
            return await _error_response(scope, 413, "Upload too large.")(scope, receive, send)
        owner = uuid.uuid4().hex
        try:
            identity = await upload_identity(scope)
            if identity:
                scope.setdefault("state", {})["upload_authenticated"] = True
                limit = settings.authenticated_upload_rate_limit_per_minute
                if limit > 0 and await run_in_threadpool(_redis_window_hits, f"logstotal:ratelimit:upload-user:{identity}", 60) > limit:
                    raise HTTPException(429, "Too many uploads. Waiting for the upload quota.")
            await run_in_threadpool(reserve_upload, owner, 2 * size)
            scope.setdefault("state", {})["upload_reserved"] = True
        except HTTPException as exc:
            response = _error_response(scope, exc.status_code, exc.detail)
            response.headers.update(exc.headers or {})
            return await response(scope, receive, send)
        except Exception:
            return await _error_response(scope, 503, "Upload admission is unavailable. Try again shortly.")(scope, receive, send)

        async def heartbeat():
            while True:
                await asyncio.sleep(30)
                try:
                    if await run_in_threadpool(renew_upload, owner):
                        continue
                except Exception:
                    pass
                scope.setdefault("state", {})["upload_lease_lost"] = True
                return

        async def guarded_receive():
            message = await receive()
            if scope.get("state", {}).get("upload_lease_lost"):
                # MultiPartException makes Starlette close every partial spool file.
                raise MultiPartException("Upload coordination was interrupted")
            return message

        response_started = False

        async def guarded_send(message):
            nonlocal response_started
            if not response_started and scope.get("state", {}).get("upload_lease_lost"):
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        task = asyncio.create_task(heartbeat())
        try:
            await self.app(scope, guarded_receive, guarded_send)
            if not response_started and scope.get("state", {}).get("upload_lease_lost"):
                await _error_response(scope, 503, "Upload coordination was interrupted. Check the submission receipt before retrying.")(scope, receive, send)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            with contextlib.suppress(Exception):
                await run_in_threadpool(release_upload, owner)
