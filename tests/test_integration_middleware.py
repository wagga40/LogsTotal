"""Integration tests for production middleware stack.

Covers security headers, HSTS, CSP, rate limiting (fallback path),
and static-asset Cache-Control behaviour through the full ASGI pipeline.
"""

from __future__ import annotations

import pytest

from app.models import WorkflowDef


@pytest.fixture()
async def seed_workflow(async_db):
    wf = WorkflowDef(
        name="MW Test Workflow",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks:\n  - tool: zircolite\n    tool_path: t\n    rules_path: r\n",
        is_default=True,
    )
    async_db.add(wf)
    await async_db.commit()
    await async_db.refresh(wf)
    return wf


# ── Security headers on every response ──────────────────────────────────────


async def test_security_headers_on_html_page(test_client):
    resp = await test_client.get("/")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "SAMEORIGIN"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in resp.headers.get("permissions-policy", "")


async def test_security_headers_on_json_endpoint(test_client):
    resp = await test_client.get("/health")
    assert resp.headers["x-content-type-options"] == "nosniff"


async def test_csp_present_by_default(test_client):
    resp = await test_client.get("/")
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'self'" in csp


# ── Rate limiting (in-memory fallback — fakeredis triggers Redis path) ───────


async def test_upload_rate_limit_not_triggered_on_get(test_client):
    """GET / should never be rate-limited even if upload rate limiting is active."""
    for _ in range(5):
        resp = await test_client.get("/")
        assert resp.status_code == 200


async def test_login_rate_limit_allows_normal_attempts(test_client):
    """A few failed login attempts should not trigger rate limiting."""
    for _ in range(3):
        resp = await test_client.post(
            "/auth/cookie/login",
            data={"username": "nobody@example.com", "password": "wrong"},
        )
        assert resp.status_code != 429


# ── Upload Content-Length precheck ───────────────────────────────────────────


async def _drive_upload_mw(*, max_upload_bytes: int, content_length: bytes | None, accept: bytes | None = None):
    """Run UploadRateLimitMiddleware against a synthetic POST /upload scope."""
    from app.middleware.production import UploadRateLimitMiddleware

    called = {"app": False}

    async def inner_app(scope, receive, send):
        called["app"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = UploadRateLimitMiddleware(inner_app, max_requests=0, window_seconds=60, max_upload_bytes=max_upload_bytes)
    headers = [(b"content-length", content_length)] if content_length is not None else []
    if accept is not None:
        headers.append((b"accept", accept))
    scope = {"type": "http", "method": "POST", "path": "/upload", "headers": headers}

    messages: list = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await mw(scope, receive, send)
    start = next(m for m in messages if m["type"] == "http.response.start")
    _drive_upload_mw.last_headers = {k.decode(): v.decode() for k, v in start["headers"]}
    return called["app"], start["status"]


async def test_upload_precheck_rejects_oversized_content_length():
    app_called, status = await _drive_upload_mw(max_upload_bytes=100, content_length=b"200")
    assert status == 413
    assert app_called is False  # rejected before the body is spooled


async def test_upload_precheck_allows_within_limit():
    app_called, status = await _drive_upload_mw(max_upload_bytes=1000, content_length=b"200")
    assert status == 200
    assert app_called is True


async def test_upload_precheck_refuses_a_body_with_no_declared_length():
    """No Content-Length means no precheck is possible, so the request is refused.

    Passing it through to "the handler's streaming cap" would be wrong: there is no
    streaming cap — FastAPI parses the entire multipart body before the endpoint runs — so
    `Transfer-Encoding: chunked` would be an unauthenticated way to spool an unbounded body
    to disk and skip the 413 entirely. Both real callers are ordinary multipart POSTs that
    always declare a length.
    """
    app_called, status = await _drive_upload_mw(max_upload_bytes=100, content_length=None)
    assert status == 411
    assert app_called is False


async def test_upload_precheck_refuses_an_unparseable_length():
    """A length that isn't a number is exactly as uncheckable as a missing one."""
    app_called, status = await _drive_upload_mw(max_upload_bytes=100, content_length=b"not-a-number")
    assert status == 411
    assert app_called is False


# ── Middleware rejections honour Accept ──────────────────────────────────────
#
# Middleware returns its rejections directly, so they never reach the HTTPException
# handler in app/main.py and never got its content negotiation: a browser submitting
# the upload form saw raw JSON for a CSRF failure, an oversized file, or a rate limit.


async def test_oversized_upload_returns_html_to_a_browser():
    _, status = await _drive_upload_mw(max_upload_bytes=100, content_length=b"200", accept=b"text/html,application/xhtml+xml")
    assert status == 413
    assert _drive_upload_mw.last_headers["content-type"].startswith("text/html")


async def test_oversized_upload_returns_json_to_an_api_client():
    _, status = await _drive_upload_mw(max_upload_bytes=100, content_length=b"200", accept=b"application/json")
    assert status == 413
    assert _drive_upload_mw.last_headers["content-type"].startswith("application/json")


async def test_oversized_upload_defaults_to_json_without_an_accept_header():
    _, status = await _drive_upload_mw(max_upload_bytes=100, content_length=b"200")
    assert status == 413
    assert _drive_upload_mw.last_headers["content-type"].startswith("application/json")


async def test_csrf_rejection_returns_html_to_a_browser(admin_client):
    """The cookie-authed form POST is exactly the case that must not render raw JSON."""
    resp = await admin_client.post(
        "/admin/recover-stuck-jobs",
        headers={"origin": "https://evil.example.com", "accept": "text/html"},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert resp.headers["content-type"].startswith("text/html")
    assert "CSRF" in resp.text


async def test_csrf_rejection_returns_json_to_an_api_client(admin_client):
    resp = await admin_client.post(
        "/admin/recover-stuck-jobs",
        headers={"origin": "https://evil.example.com", "accept": "application/json"},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert "detail" in resp.json()


# ── Static file Cache-Control ────────────────────────────────────────────────


async def test_static_cache_control_header(test_client):
    resp = await test_client.get("/static/app.js")
    if resp.status_code == 200:
        cc = resp.headers.get("cache-control", "")
        assert "public" in cc
        assert "max-age" in cc


# ── Error handler responses ─────────────────────────────────────────────────


async def test_404_html_response(test_client):
    resp = await test_client.get("/nonexistent-page", headers={"accept": "text/html"})
    assert resp.status_code == 404


async def test_404_json_response(test_client):
    resp = await test_client.get("/nonexistent-page", headers={"accept": "application/json"})
    assert resp.status_code == 404
    assert "detail" in resp.json()


# ── Request correlation ─────────────────────────────────────────────────────


async def test_every_response_carries_a_request_id(test_client):
    """The id is set unconditionally, not only when REQUEST_LOG_ENABLED is on — it is
    what makes an unhandled-exception traceback traceable back to the user who reported
    it, which is exactly the case where you cannot go back and turn logging on first."""
    resp = await test_client.get("/", headers={"accept": "text/html"})
    assert resp.headers.get("x-request-id")


async def test_a_well_formed_client_request_id_is_echoed(test_client):
    resp = await test_client.get("/", headers={"x-request-id": "trace-abc_1.2"})
    assert resp.headers["x-request-id"] == "trace-abc_1.2"


async def test_a_hostile_client_request_id_is_replaced(test_client):
    """Echoed into a structured log field, so a newline would forge a second line."""
    resp = await test_client.get("/", headers={"x-request-id": "bad value"})
    assert resp.headers["x-request-id"] != "bad value"
    assert " " not in resp.headers["x-request-id"]


async def test_health_and_static_get_no_request_id(test_client):
    """Both are polled constantly; an outermost middleware would log a dozen lines per
    page view and one per healthcheck tick."""
    assert "x-request-id" not in (await test_client.get("/health")).headers
    static = await test_client.get("/static/app.js")
    if static.status_code == 200:
        assert "x-request-id" not in static.headers


def test_request_context_middleware_is_outermost():
    """It must sit outside the guards so it sees the 411/413/429/403 they return before
    routing — the responses a user reports and nothing else records."""
    from app.main import app
    from app.middleware.observability import RequestContextMiddleware

    assert app.user_middleware[0].cls is RequestContextMiddleware


async def test_an_error_page_keeps_a_signed_in_users_nav(admin_client):
    """Both handlers rendered `error.html` with `user: None`, so any 404 or 400 page showed
    a signed-in admin "Login" and no Intel/Admin links — which reads as a lost session."""
    resp = await admin_client.get("/jobs/999999", headers={"accept": "text/html"})

    assert resp.status_code == 404
    assert "Logout" in resp.text


async def test_an_error_page_for_a_stale_cookie_still_renders(test_client):
    """The lookup must never be what fails the error page."""
    test_client.cookies.set("logstotal_auth", "not-a-jwt")
    resp = await test_client.get("/jobs/999999", headers={"accept": "text/html"})

    assert resp.status_code == 404
    assert "Login" in resp.text
