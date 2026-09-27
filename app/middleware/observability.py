"""Request correlation: one id per request, carried into every log line it produces.

Separate from ``production.py`` because that module is about *hardening* — this one only
observes. It is registered last in ``app/main.py``, which makes it outermost, so it also
sees the 411/413/429/403 the upload, rate-limit and CSRF middlewares return before routing
ever happens.

Pure ASGI, like every other middleware here. That is not only about the thread-pool
overhead ``BaseHTTPMiddleware`` adds: a contextvar set inside ``__call__`` is visible to the
endpoint (same task) *and* survives ``run_in_threadpool``, because anyio copies the context
into the worker thread. A ``BaseHTTPMiddleware`` dispatch runs in its own task and the bind
would not reliably reach either.
"""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.logging_config import bind as bind_log_context
from app.logging_config import request_id_var
from app.network.client_ip import get_client_ip_from_scope

_access_log = logging.getLogger("logstotal.access")

#: A client-supplied id is echoed into a structured log field, so it is untrusted input.
#: Anything outside this alphabet could inject a newline (splitting one line into two
#: forged ones) or JSON punctuation into any downstream parser. Non-matching values are
#: not sanitised, they are replaced — a caller sending a bad id gets a working request and
#: a server-chosen id.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

REQUEST_ID_HEADER = "x-request-id"

#: Never worth a line each. `/static/` is a dozen assets per page load behind an outermost
#: middleware, and `/health` is polled by the compose healthcheck, any load balancer,
#: `task health:remote` and `task deploy:smoke`.
_SKIP_PREFIXES = ("/static/",)
_SKIP_EXACT = ("/health",)


def sanitize_request_id(raw: str | None) -> str:
    """Return *raw* if it is a safe correlation id, else a fresh one."""
    if raw and _SAFE_REQUEST_ID.match(raw):
        return raw
    return uuid.uuid4().hex


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value.decode("latin-1", "replace")
    return None


def _is_skipped(path: str) -> bool:
    return path in _SKIP_EXACT or path.startswith(_SKIP_PREFIXES)


class RequestContextMiddleware:
    """Bind a request id for the duration of the request, and optionally log the request.

    *access_log* only gates the log line. The correlation id is bound unconditionally,
    because it is what makes an unhandled-exception traceback traceable back to the user
    who reported it — the case where you cannot go back and turn logging on first.
    """

    def __init__(self, app: ASGIApp, *, access_log: bool = False) -> None:
        self.app = app
        self.access_log = access_log

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if _is_skipped(path):
            await self.app(scope, receive, send)
            return

        request_id = sanitize_request_id(_header(scope, b"x-request-id"))
        token = request_id_var.set(request_id)
        # `scope` is how a route reaches the id without importing the contextvar.
        scope["request_id"] = request_id
        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = message.setdefault("headers", [])
                headers.append((REQUEST_ID_HEADER.encode("latin-1"), request_id.encode("latin-1")))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            if self.access_log:
                duration_ms = int((time.perf_counter() - started) * 1000)
                try:
                    client_ip = get_client_ip_from_scope(scope)
                except Exception:  # pragma: no cover — resolution must never break a response
                    client_ip = None
                # `extra=` is what the JSON formatter emits as top-level fields; in text
                # mode it is simply unused, which is why the message repeats the essentials.
                _access_log.info(
                    "%s %s %s %dms",
                    scope.get("method", "?"),
                    path,
                    status_code,
                    duration_ms,
                    extra={
                        "http_method": scope.get("method", "?"),
                        "http_path": path,
                        "http_status": status_code,
                        "duration_ms": duration_ms,
                        "client_ip": client_ip,
                    },
                )
            request_id_var.reset(token)
            bind_log_context(actor=None)
