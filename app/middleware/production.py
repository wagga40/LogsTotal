"""Production-oriented ASGI middleware (security headers, upload rate limiting)."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from urllib.parse import urlparse

from starlette.formparsers import MultiPartException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.network.client_ip import get_client_ip_from_scope

logger = logging.getLogger(__name__)


def _error_response(scope: Scope, status_code: int, detail: str) -> Response:
    """The middleware twin of ``app.main``'s HTTPException handler.

    Middleware returns its rejections directly, so they never reach FastAPI's exception
    handlers or that handler's content negotiation — without this, a browser submitting the
    upload form would see raw JSON for a CSRF failure, an oversized file, or a rate limit.
    Same ``error.html``, same rule: HTML for anything that asked for HTML, JSON otherwise
    (XHR endpoints and Bearer-token clients keep the machine-readable body).
    """
    accept = dict(scope.get("headers", [])).get(b"accept", b"").decode("latin-1")
    headers = {"Retry-After": "60"} if status_code == 429 else None
    if "text/html" in accept:
        from app.templates_config import templates

        return templates.TemplateResponse(
            Request(scope),
            "error.html",
            {"user": None, "status_code": status_code, "detail": detail},
            status_code=status_code,
            headers=headers,
        )
    return JSONResponse({"detail": detail}, status_code=status_code, headers=headers)


# Above this many distinct buckets, the in-memory fallback sweeps expired ones. Only
# reachable while Redis is down, but a long outage on a busy public instance would
# otherwise retain one list per client IP for the life of the process.
_FALLBACK_SWEEP_AT = 10_000


def _bearer_token(scope: Scope) -> str | None:
    """The plaintext of an ``Authorization: Bearer`` header, or None.

    Reads the raw ASGI header list. Header names are already lowercase per the ASGI spec,
    and a `dict(headers)` would collapse duplicates to the last value.
    """
    for raw_key, raw_val in scope.get("headers", []):
        if raw_key.lower() != b"authorization":
            continue
        try:
            parts = raw_val.decode("latin1").strip().split(None, 1)
        except Exception:
            return None
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()
        return None
    return None


def _redis_window_hits(key: str, window_seconds: int) -> int:
    """Hits recorded so far in the current fixed window. Raises if Redis is unreachable.

    ``SET key 0 EX w NX`` + ``INCR``, *not* ``INCR`` + unconditional ``EXPIRE``: refreshing
    the TTL on every request anchors the window to the last hit instead of the first, so the
    counter never rolls over for a steadily-active caller — an IOC-feed client polling every
    30s under a 120/min limit would be locked out permanently after its 120th request. With
    ``NX`` the expiry is set once, by whoever opens the window.
    """
    from app.redis_client import get_redis

    with get_redis().pipeline(transaction=True) as pipe:
        pipe.set(key, 0, ex=window_seconds, nx=True)
        pipe.incr(key)
        _set, current = pipe.execute()
    return int(current)


def _memory_window_limited(hits: dict[str, list[float]], bucket: str, limit: int, window_seconds: int) -> bool:
    """Per-process sliding window — the fallback used only when Redis is unreachable."""
    now = time.monotonic()
    cutoff = now - window_seconds
    if len(hits) > _FALLBACK_SWEEP_AT:
        for stale in [k for k, v in hits.items() if not v or v[-1] <= cutoff]:
            del hits[stale]
    window = hits.setdefault(bucket, [])
    window[:] = [t for t in window if t > cutoff]
    if len(window) >= limit:
        return True
    window.append(now)
    return False


class SecurityHeadersMiddleware:
    """Adds common security headers to HTTP responses."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        disable_csp: bool = False,
        enable_hsts: bool = False,
        hsts_max_age: int = 63072000,
    ):
        self.app = app
        self.disable_csp = disable_csp
        self.enable_hsts = enable_hsts
        self.hsts_max_age = hsts_max_age

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"x-frame-options", b"SAMEORIGIN"))
                headers.append((b"referrer-policy", b"strict-origin-when-cross-origin"))

                # Every response outside /static is rendered for a specific viewer: what a
                # job page, a findings.json, an upload download or anything under /intel
                # contains depends on the session cookie. Without `Vary: Cookie` a shared
                # cache — a corporate proxy, or a misconfigured CDN in front of the reverse
                # proxy — may serve one analyst's private-job data to the next visitor, and
                # without `no-store` it survives in the browser cache after logout. This was
                # once limited to text/html, which left the JSON exports and file downloads
                # (FileResponse sends Last-Modified, so they are heuristically cacheable)
                # outside it. /static keeps caching normally.
                if not scope["path"].startswith("/static/"):
                    # Merge into any existing Vary rather than replacing it — GZipMiddleware
                    # sets `Vary: Accept-Encoding`, and dropping that breaks compression
                    # negotiation for every downstream cache.
                    varies: list[bytes] = []
                    for key, value in headers:
                        if key.lower() == b"vary":
                            varies.extend(part.strip() for part in value.split(b",") if part.strip())
                    for wanted in (b"Cookie", b"HX-Request"):
                        if not any(v.lower() == wanted.lower() for v in varies):
                            varies.append(wanted)
                    headers = [(k, v) for k, v in headers if k.lower() not in (b"cache-control", b"vary")] + [
                        (b"cache-control", b"no-store, private"),
                        (b"vary", b", ".join(varies)),
                    ]
                headers.append(
                    (
                        b"permissions-policy",
                        b"camera=(), microphone=(), geolocation=(), payment=()",
                    )
                )
                if self.enable_hsts:
                    headers.append(
                        (
                            b"strict-transport-security",
                            f"max-age={self.hsts_max_age}; includeSubDomains".encode(),
                        )
                    )
                if not self.disable_csp:
                    # base-uri, form-action and object-src do NOT inherit default-src.
                    # Without them the policy reads as protection it does not give: an
                    # injected <base> rewrites every relative URL on the page (including
                    # the vendored scripts), and an injected <form action> posts a
                    # cookie-authed write off-site. All three are free here — LogsTotal
                    # sets no <base>, posts only to itself, and embeds no plugins.
                    #
                    # 'unsafe-eval' stays: Alpine evaluates its expressions with the
                    # Function constructor, and removing it needs Alpine's CSP build plus
                    # a rewrite of every inline x-data. docs/security.md says so rather
                    # than letting the header imply otherwise.
                    csp = (
                        b"default-src 'self'; "
                        b"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                        b"style-src 'self' 'unsafe-inline'; "
                        b"img-src 'self' data:; "
                        b"font-src 'self'; "
                        b"base-uri 'none'; "
                        b"form-action 'self'; "
                        b"object-src 'none'; "
                        b"frame-ancestors 'self'"
                    )
                    headers.append((b"content-security-policy", csp))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class CsrfMiddleware:
    """Origin/Referer CSRF defense for state-changing requests.

    Only enforced when the fastapi-users auth cookie is present — anonymous
    requests (including /upload, login, and public GETs) are unaffected.
    For authenticated POST/PUT/PATCH/DELETE, the Origin or Referer header
    must match the request's Host. Modern browsers set Origin on all
    cross-origin state-changing requests, so a missing/mismatched Origin
    indicates a cross-site request and is rejected.
    """

    SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
    AUTH_COOKIE_NAME = "logstotal_auth"
    # Logout: anonymous-safe (no-op when not logged in) and some browsers strip
    # Origin on redirects; exempting it keeps logout working across contexts.
    EXEMPT_PATHS = frozenset({"/auth/cookie/logout"})

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "").upper()
        if method in self.SAFE_METHODS:
            await self.app(scope, receive, send)
            return

        if scope.get("path", "") in self.EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        # Raw headers, not a dict. A dict comprehension keeps the *last* value for a
        # repeated name, and HTTP permits repeats: a request with
        # `Cookie: logstotal_auth=…` followed by a second, junk `Cookie:` header would
        # collapse to the junk one, this check would conclude the request is not
        # cookie-authed, and it would sail past — while Starlette joins the two and the
        # route authenticates normally. Defence-in-depth: Uvicorn behind the Caddy this
        # project ships does not produce that shape, but the check must not depend on
        # which server is in front of it.
        headers: dict[str, list[str]] = {}
        for raw_key, raw_val in scope.get("headers", []):
            headers.setdefault(raw_key.decode("latin-1").lower(), []).append(raw_val.decode("latin-1"))

        # Cookies join the same way a client would have sent them in one header.
        cookie_header = "; ".join(headers.get("cookie", []))
        if f"{self.AUTH_COOKIE_NAME}=" not in cookie_header:
            await self.app(scope, receive, send)
            return

        # A repeated Host/Origin/Referer on a cookie-authed write has no legitimate
        # source and makes "which one did the app see?" unanswerable. Fail closed.
        if any(len(headers.get(name, [])) > 1 for name in ("host", "origin", "referer")):
            response = _error_response(scope, 403, "CSRF validation failed: duplicate Host/Origin/Referer header.")
            await response(scope, receive, send)
            return

        host = next(iter(headers.get("host", [])), "")
        origin = next(iter(headers.get("origin", [])), "")
        referer = next(iter(headers.get("referer", [])), "")
        source = origin or referer
        if not source or not self._origin_matches_host(source, host):
            response = _error_response(scope, 403, "CSRF validation failed: Origin/Referer does not match host.")
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    def _origin_matches_host(source: str, host: str) -> bool:
        if not host:
            return False
        try:
            parsed = urlparse(source)
        except ValueError:
            return False
        src_host = parsed.netloc or parsed.path
        if not src_host:
            return False
        return src_host.lower() == host.lower()


class _RequestBodyTooLarge(MultiPartException):
    """Interrupt parsing so Starlette closes partial multipart files."""


class RequestBodyLimitMiddleware:
    """Enforce byte limits before parsers consume data, including chunked bodies."""

    def __init__(self, app: ASGIApp, max_upload_bytes: int, max_body_bytes: int = 1024 * 1024):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.max_upload_bytes = max_upload_bytes + 1024 * 1024

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.max_body_bytes
        if scope.get("method") == "POST":
            if scope.get("path") in ("/upload", "/api/v1/jobs"):
                limit = self.max_upload_bytes
            elif scope.get("path") == "/detect-preview":
                limit = 256 * 1024
        for key, value in scope.get("headers", []):
            if key == b"content-length" and value.isdigit() and (len(value.lstrip(b"0")) > 20 or int(value.lstrip(b"0") or b"0") > limit):
                await _error_response(scope, 413, "Request body too large.")(scope, receive, send)
                return
            if key == b"content-length" and value.isdigit() and scope.get("state", {}).get("upload_reserved"):
                # Admission reserved against this declaration. A forged small length
                # must not consume unreserved disk even below the per-file maximum.
                limit = min(limit, int(value.lstrip(b"0") or b"0"))

        received = 0
        exceeded = False
        response_started = False

        async def limited_receive():
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    raise _RequestBodyTooLarge("Request body too large.")
            return message

        async def limited_send(message):
            nonlocal response_started
            # FastAPI may translate the parsing exception into a 400. The limit owns
            # that response, after the parser has unwound and closed its files.
            if not exceeded:
                response_started |= message["type"] == "http.response.start"
                await send(message)

        try:
            await self.app(scope, limited_receive, limited_send)
        except Exception:
            if not exceeded or response_started:
                raise
        if exceeded and not response_started:
            await _error_response(scope, 413, "Request body too large.")(scope, receive, send)


class UploadRateLimitMiddleware:
    """Redis-backed fixed-window rate limit for POST /upload per client IP.

    Works correctly across multiple web processes and Docker replicas.
    Falls back to in-memory limiting if Redis is unavailable.

    Also enforces a ``Content-Length`` precheck for POST /upload: a declared body
    larger than ``max_upload_bytes`` is rejected with 413 *before* Starlette spools
    the multipart body to disk, so an oversized upload can't exhaust temp storage.
    (Rate limiting is skipped when ``max_requests <= 0``; the size precheck always
    runs.)

    Upload and preview retain their Content-Length requirement. The independent
    RequestBodyLimitMiddleware also counts actual received bytes on every route,
    including requests with a forged declaration and chunked requests elsewhere.

    POST /detect-preview gets the same treatment with its own Redis bucket and a
    fixed small body cap — the form only ever sends the first 64 KB of a file.
    """

    _PREVIEW_BODY_CAP = 256 * 1024  # 64 KB slice + generous multipart overhead

    def __init__(self, app: ASGIApp, max_requests: int, window_seconds: int, max_upload_bytes: int = 0, preview_requests: int | None = None):
        self.app = app
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_upload_bytes = max_upload_bytes
        self.preview_requests = max_requests if preview_requests is None else preview_requests
        self._fallback_hits: dict[str, list[float]] = defaultdict(list)
        self._fallback_warned = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")
        if method == "POST" and path in ("/upload", "/api/v1/jobs"):
            declared = self._declared_length(scope)
            if declared is None:
                response = _error_response(scope, 411, "Upload requires a Content-Length header.")
                await response(scope, receive, send)
                return
            if self.max_upload_bytes > 0 and declared > self.max_upload_bytes:
                response = _error_response(scope, 413, "Upload too large.")
                await response(scope, receive, send)
                return
            if self.max_requests > 0 and not scope.get("state", {}).get("upload_authenticated"):
                ip = get_client_ip_from_scope(scope) or "unknown"
                if self._is_rate_limited(ip, "upload"):
                    response = _error_response(scope, 429, "Too many uploads. Try again later.")
                    await response(scope, receive, send)
                    return

        if method == "POST" and path == "/detect-preview":
            declared = self._declared_length(scope)
            if declared is None:
                response = JSONResponse({"detail": "Content-Length required."}, status_code=411)
                await response(scope, receive, send)
                return
            if declared > self._PREVIEW_BODY_CAP:
                response = JSONResponse(
                    {"detail": "Preview too large."},
                    status_code=413,
                )
                await response(scope, receive, send)
                return
            if self.preview_requests > 0:
                ip = get_client_ip_from_scope(scope) or "unknown"
                if self._is_rate_limited(ip, "detect"):
                    response = JSONResponse(
                        {"detail": "Too many requests. Try again later."},
                        status_code=429,
                        headers={"Retry-After": str(self.window_seconds)},
                    )
                    await response(scope, receive, send)
                    return

        await self.app(scope, receive, send)

    def _declared_length(self, scope: Scope) -> int | None:
        """The declared body size, or ``None`` when there isn't a usable one.

        ``None`` covers both "no header" and "header we cannot parse" — an unparseable
        length is no more checkable than a missing one, and treating it as "fits" would be
        the same hole with extra steps.
        """
        for key, value in scope.get("headers", []):
            if key == b"content-length":
                try:
                    length = int(value)
                except (ValueError, TypeError):
                    return None
                return length if length >= 0 else None
        return None

    def _is_rate_limited(self, ip: str, kind: str) -> bool:
        limit = self.preview_requests if kind == "detect" else self.max_requests
        try:
            return _redis_window_hits(f"logstotal:ratelimit:{kind}:{ip}", self.window_seconds) > limit
        except Exception:
            if not self._fallback_warned:
                logger.warning("UploadRateLimit falling back to in-memory counters (per-process, not shared across workers). Check Redis connectivity.")
                self._fallback_warned = True
            return _memory_window_limited(self._fallback_hits, f"{kind}:{ip}", limit, self.window_seconds)


class AuthRateLimitMiddleware:
    """Rate-limits auth-sensitive endpoints (login, resubmit) per client IP.

    For token-authenticated endpoints (IOC feed, TAXII), the bucket key derives from the
    Bearer token hash so each token gets its own quota; falls back to IP when no token.

    Uses Redis when available, falls back to in-memory counters.
    """

    _RATE_LIMITS: list[tuple[str, str, str]] = [
        ("POST", "/auth/cookie/login", "login"),
        ("POST", "/jobs/resubmit", "resubmit"),
    ]

    # (method, path-prefix, kind, bearer_only) — prefix match (path startswith). Used for
    # endpoints that should be rate-limited per-token when an Authorization: Bearer is
    # present.
    #
    # Every route behind `current_user_or_api_token` must match one of these, or that
    # token scope is unthrottled — and `case:read` fronts the deliberately-unpaginated
    # case aggregations, each also forcing a `last_used_at` write.
    # `tests/test_api_token_auth.py` fails if a new token-reachable path appears with no
    # prefix here.
    #
    # `bearer_only=True` for the case prefix: it also fronts the browser's case pages,
    # whose tabs lazy-load half a dozen partials each. Throttling those per-IP would
    # punish a shared NAT for using the UI, and the reason this entry exists is the token
    # surface. The other two prefixes are API-only and stay limited either way.
    _RATE_LIMITS_PREFIX: list[tuple[str, str, str, bool]] = [
        ("GET", "/api/v1/", "ioc_feed", False),
        ("POST", "/api/v1/cases", "ioc_feed", False),
        ("GET", "/intel/ioc-feed", "ioc_feed", False),
        ("GET", "/taxii2/", "ioc_feed", False),
        ("GET", "/intel/cases/", "ioc_feed", True),
    ]

    def __init__(
        self,
        app: ASGIApp,
        login_max: int,
        resubmit_max: int,
        window_seconds: int = 60,
        ioc_feed_max: int = 120,
    ):
        self.app = app
        self.window_seconds = window_seconds
        self._limits = {"login": login_max, "resubmit": resubmit_max, "ioc_feed": ioc_feed_max}
        self._fallback_hits: dict[str, list[float]] = defaultdict(list)
        self._fallback_warned = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "")
        matched_kind: str | None = None
        for m, p, kind in self._RATE_LIMITS:
            if method == m and path == p:
                matched_kind = kind
                break
        if matched_kind is None:
            for m, p, kind, bearer_only in self._RATE_LIMITS_PREFIX:
                if method == m and path.startswith(p) and (not bearer_only or _bearer_token(scope)):
                    matched_kind = kind
                    break

        if matched_kind is not None:
            limit = self._limits.get(matched_kind, 0)
            if limit > 0:
                bucket_id = self._bucket_id(scope, matched_kind)
                if self._is_rate_limited(bucket_id, matched_kind, limit):
                    # Covers both the browser login form and Bearer-token API clients —
                    # the Accept header decides which body each of them gets.
                    response = _error_response(scope, 429, "Too many requests. Try again later.")
                    await response(scope, receive, send)
                    return

        await self.app(scope, receive, send)

    def _bucket_id(self, scope: Scope, kind: str) -> str:
        """For token-bucketed kinds, hash the Bearer plaintext; otherwise fall back to client IP."""
        if kind == "ioc_feed":
            token = _bearer_token(scope)
            if token:
                import hashlib

                return "token:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
        return "ip:" + (get_client_ip_from_scope(scope) or "unknown")

    def _is_rate_limited(self, bucket_id: str, kind: str, limit: int) -> bool:
        try:
            return _redis_window_hits(f"logstotal:ratelimit:{kind}:{bucket_id}", self.window_seconds) > limit
        except Exception:
            if not self._fallback_warned:
                logger.warning("AuthRateLimit falling back to in-memory counters (per-process, not shared across workers). Check Redis connectivity.")
                self._fallback_warned = True
            return _memory_window_limited(self._fallback_hits, f"{kind}:{bucket_id}", limit, self.window_seconds)
