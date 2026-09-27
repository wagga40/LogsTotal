"""FastAPI application factory — mounts routers, middleware, and lifespan hooks."""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.schemas import UserRead, UserUpdate
from app.auth.users import auth_backend, current_user_optional, fastapi_users, user_for_error_page
from app.config import settings
from app.database import async_session_maker, parse_row_id
from app.logging_config import configure_logging
from app.middleware.observability import RequestContextMiddleware
from app.middleware.production import AuthRateLimitMiddleware, CsrfMiddleware, RequestBodyLimitMiddleware, SecurityHeadersMiddleware, UploadRateLimitMiddleware
from app.middleware.upload_admission import UploadAdmissionMiddleware
from app.migrations import run_auto_migrate
from app.models import User
from app.routers import (
    activity_admin,
    admin,
    ai,
    ai_admin,
    api_tokens_admin,
    case_ai,
    cases,
    comments,
    docs,
    enrichment_admin,
    intel,
    intel_rules,
    intel_tags,
    jobs,
    storage_admin,
    submission_api,
    upload,
    workflows,
)
from app.system_checks import multi_server_config_warnings
from app.templates_config import templates

logger = logging.getLogger(__name__)


def _warn_multi_server_config() -> None:
    for warning in multi_server_config_warnings(
        compose_profiles=settings.compose_profiles,
        database_url=settings.database_url,
        storage_backend=settings.storage_backend,
        redis_expose=settings.redis_expose,
        postgres_expose=settings.postgres_expose,
        garage_expose=settings.garage_expose,
    ):
        logger.warning(warning)

    if os.environ.get("COMPOSE_PROFILES") and settings.compose_profiles != os.environ.get("COMPOSE_PROFILES"):
        logger.warning(
            "COMPOSE_PROFILES from the environment did not propagate into application settings as expected: %s",
            os.environ.get("COMPOSE_PROFILES"),
        )


async def _warn_missing_tool_paths():
    """On startup, warn about tool_path entries that don't exist on disk."""
    from sqlalchemy import select

    from app.models import WorkflowDef
    from app.tools.base import resolve_tool_path
    from app.yaml_utils import safe_load as yaml_safe_load

    try:
        async with async_session_maker() as session:
            result = await session.execute(select(WorkflowDef))
            wf_defs = result.scalars().all()

        for wf in wf_defs:
            try:
                data = yaml_safe_load(wf.tasks_yaml) or {}
            except Exception:
                continue
            for task in data.get("tasks", []):
                raw = task.get("tool_path")
                if not raw:
                    continue
                resolved, skip_reason = resolve_tool_path(raw)
                if skip_reason:
                    logger.warning("Workflow '%s': %s", wf.name, skip_reason)
                    continue
                if resolved and not Path(resolved).exists():
                    logger.warning(
                        "Workflow '%s': tool_path '%s' does not exist on disk.",
                        wf.name,
                        resolved,
                    )
    except Exception as exc:
        logger.warning("Could not validate tool paths at startup: %s", exc)


def _warn_proxy_ip_config() -> None:
    if settings.trust_proxy_headers:
        logger.warning(
            "TRUST_PROXY_HEADERS is enabled. Forwarded headers will be trusted only from: %s",
            settings.trusted_proxy_cidrs,
        )


def _warn_production_safety() -> None:
    for warning in settings.production_warnings():
        logger.warning("PRODUCTION SAFETY: %s", warning)


def _enforce_production_errors() -> None:
    errors = settings.production_errors()
    if not errors:
        return
    for err in errors:
        logger.error("STARTUP REFUSED: %s", err)
    raise RuntimeError("Refusing to start: " + "; ".join(errors))


async def _recover_stale_jobs():
    """Fail jobs no worker will finish: RUNNING with a dead heartbeat, or PENDING past expiry."""
    from app.constants import RECOVERY_MSG_STARTUP
    from app.recovery import recover_stale_jobs
    from app.redis_client import get_redis

    try:
        async with async_session_maker() as db:
            recovered = await recover_stale_jobs(db, get_redis(), message=RECOVERY_MSG_STARTUP)
        if recovered:
            logger.info("Recovered %d stranded job(s) on startup.", recovered)
    except Exception as exc:
        logger.warning("Stale job recovery failed: %s", exc)


async def _sync_builtin_rules() -> None:
    """Seed the shared rules and their lists from rules/, after migrations and before serving.

    Here as well as in `init_db.py` because an upgrade must not need a manual step to get
    the rules a release adds: `init_db.py` runs in the Docker entrypoint but not on a bare
    `./logstotal dev`, and a member landing on `/intel/rules` to find an empty Built-in section
    would reasonably conclude the feature had not shipped.

    Idempotent and cheap — one parse of `rules/*.yml` and one indexed SELECT of their keys
    when there is nothing to do.
    Swallowed, because a seed is not worth refusing to boot over: migrations are, this is
    not, and `./logstotal sync-rules` puts it right.
    """
    try:
        from app.intel.rules_yaml import rules_dir, sync_rules_from_dir

        async with async_session_maker() as session:
            result = await sync_rules_from_dir(session, rules_dir())
            await session.commit()
        for err in result.errors:
            logger.warning("Shared rule not loaded: %s", err)
        if result.created or result.updated or result.lists_created or result.lists_updated:
            logger.info("Shared rules from %s — %s", rules_dir(), result.summary())
    except Exception as exc:
        logger.warning("Could not sync built-in label rules: %s — run `./logstotal sync-rules`", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs here rather than at import because
    # uvicorn configures its own loggers in `Server.run()` *before* the lifespan, so a
    # later call is the one that wins — which is why no start command needs a log flag.
    configure_logging()
    # Bring the schema to Alembic head (serialized across replicas via Redis lock).
    # Raises on failure — refusing to boot beats serving on a half-migrated schema.
    await asyncio.to_thread(run_auto_migrate)
    await _sync_builtin_rules()
    _warn_multi_server_config()
    await _recover_stale_jobs()
    await _warn_missing_tool_paths()
    _warn_proxy_ip_config()
    _warn_production_safety()
    _enforce_production_errors()
    yield


# Past any page a listing could have; `?page=` above it is refused like an unbindable id.
PAGE_NUMBER_MAX = 1_000_000


async def refuse_unbindable_numbers(request: Request) -> None:
    """404 for an `{..._id}` path segment or `?page=` no row could have, before a route binds it.

    FastAPI accepts any Python int for an `int` parameter. SQLite refuses one past int8 and
    PostgreSQL one past int4 — both as a 500, anonymous routes such as `/jobs/{job_id}`
    included. One app-wide dependency rather than a bound on every signature, and keyed on
    the `_id` suffix so a numeric-looking `{tag}` is left alone.
    """
    for name, value in request.path_params.items():
        if not name.endswith("_id") or not isinstance(value, str):
            continue
        # Pydantic accepts signs and integer-valued decimals such as "123.0". Bound
        # their magnitude too; leave syntax validation and UUIDs to the route itself.
        digits = value.strip().lstrip("+-").partition(".")[0]
        if digits.isdigit() and parse_row_id(digits) is None:
            raise HTTPException(404)
    digits = request.query_params.get("page", "").strip().lstrip("+-").partition(".")[0]
    if digits.isdigit():
        magnitude = parse_row_id(digits)
        if magnitude is None or magnitude > PAGE_NUMBER_MAX:
            raise HTTPException(404)


# All three move together, because `docs_url` alone is not a gate: with `openapi_url` and
# `redoc_url` at their defaults, a production instance would answer `GET /openapi.json`
# with a machine-readable inventory of every route, /admin included, and render it at
# /redoc. Nothing in front gates either: the rate
# limiters match named paths, CsrfMiddleware only guards unsafe methods, and the bundled
# Caddy proxies everything. Swagger cannot render without a reachable schema document,
# which is why the schema moves under /api/ rather than switching off in debug too.
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url="/api/redoc" if settings.debug else None,
    openapi_url="/api/openapi.json" if settings.debug else None,
    dependencies=[Depends(refuse_unbindable_numbers)],
)

app.add_middleware(GZipMiddleware, minimum_size=500)

# Always registered: the Content-Length size precheck runs regardless of the
# rate-limit setting (max_requests=0 simply disables the per-IP rate limiting).
app.add_middleware(
    UploadRateLimitMiddleware,
    max_requests=settings.upload_rate_limit_per_minute,
    window_seconds=60,
    max_upload_bytes=settings.max_upload_bytes + 1024 * 1024,
    preview_requests=settings.preview_rate_limit_per_minute,
)
app.add_middleware(RequestBodyLimitMiddleware, max_upload_bytes=settings.max_upload_bytes)
app.add_middleware(UploadAdmissionMiddleware)

# The API-token limit is part of this condition, or zeroing the three IP-based limits would
# silently take the per-token quota on /intel/ioc-feed and /taxii2/* down with them. The
# middleware already no-ops per kind (`if limit > 0` in __call__),
# so a registered-but-fully-disabled instance is harmless.
if settings.login_rate_limit_per_minute > 0 or settings.resubmit_rate_limit_per_minute > 0 or settings.api_token_rate_limit_per_minute > 0:
    app.add_middleware(
        AuthRateLimitMiddleware,
        login_max=settings.login_rate_limit_per_minute,
        resubmit_max=settings.resubmit_rate_limit_per_minute,
        window_seconds=60,
        ioc_feed_max=settings.api_token_rate_limit_per_minute,
    )

app.add_middleware(CsrfMiddleware)

app.add_middleware(
    SecurityHeadersMiddleware,
    disable_csp=settings.disable_csp,
    enable_hsts=settings.enable_hsts,
    hsts_max_age=settings.hsts_max_age,
)


class StaticCacheMiddleware:
    """Pure ASGI middleware — injects Cache-Control for /static/ responses
    without the thread-pool overhead of BaseHTTPMiddleware."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http" or not scope["path"].startswith("/static/"):
            await self.app(scope, receive, send)
            return

        async def send_with_cache(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"cache-control", b"public, max-age=3600"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_cache)


app.add_middleware(StaticCacheMiddleware)

# Added last, so it is outermost: `add_middleware` inserts at index 0. That position is the
# point — it sees the 411/413/429/403 the guards above return before routing, which are
# exactly the responses a user reports and nothing else records.
app.add_middleware(RequestContextMiddleware, access_log=settings.request_log_enabled)

# ── Static files ─────────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# ── Auth routes ─────────────────────────────────────────────────────────────────
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/cookie",
    tags=["auth"],
)
# `/me` only. fastapi-users also mounts superuser `GET/PATCH/DELETE /{id}`, which bypass
# everything /admin/users enforces — the self-delete and last-admin checks, the reference
# cleanup a user delete needs (a foreign-key 500 on PostgreSQL), the audit row, and keeping
# `role` and `is_superuser` in step. Nothing used them; /admin/users is the way to manage
# accounts.
_users_router = fastapi_users.get_users_router(UserRead, UserUpdate)
_users_router.routes = [route for route in _users_router.routes if "{id}" not in getattr(route, "path", "")]
app.include_router(
    _users_router,
    prefix="/api/users",
    tags=["users"],
)

# ── App routes ──────────────────────────────────────────────────────────────────
app.include_router(upload.router)
app.include_router(submission_api.router)
app.include_router(jobs.router)
# Shares jobs' /jobs prefix, like intel_rules below shares /intel. Registered after
# jobs.router so its literal second segments keep precedence;
# nothing in jobs.py is a /{job_id}/{anything} catch-all, so there is nothing for
# /{job_id}/ai-analysis to be swallowed by, and a test pins that.
app.include_router(ai.router)
app.include_router(intel.router)
# Registered after intel so intel's literal paths stay first — /intel/tags.json is matched
# before /intel/tags. Both share intel's /intel prefix, and
# tests/test_route_table_is_stable.py pins the resulting table.
app.include_router(intel_rules.router)
app.include_router(intel_tags.router)
app.include_router(cases.router)
app.include_router(case_ai.router)
app.include_router(comments.router)
app.include_router(workflows.router)
app.include_router(admin.router)
app.include_router(enrichment_admin.router)
app.include_router(ai_admin.router)
app.include_router(api_tokens_admin.router)
app.include_router(activity_admin.router)
app.include_router(storage_admin.router)
app.include_router(docs.router)

if settings.taxii_enabled:
    from app.routers import taxii as taxii_module

    app.include_router(taxii_module.router)
    logger.info("TAXII 2.1 read-only server enabled at /taxii2/")

# ── Error pages ──────────────────────────────────────────────────────────────────


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if _wants_html(request):
        return templates.TemplateResponse(
            request,
            "error.html",
            {"user": await user_for_error_page(request), "status_code": exc.status_code, "detail": exc.detail, "request_id": request.scope.get("request_id")},
            status_code=exc.status_code,
        )
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # The correlation id rides in via the ContextFilter, so this line and the reference
    # shown on the error page are the same string.
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    if _wants_html(request):
        # No user lookup here, unlike the 4xx handler: a 500 is often the database being
        # unreachable, and a lookup would make the error page wait out the same timeout.
        return templates.TemplateResponse(
            request,
            "error.html",
            {"user": None, "status_code": 500, "detail": "An internal error occurred.", "request_id": request.scope.get("request_id")},
            status_code=500,
        )
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


# ── Health check ─────────────────────────────────────────────────────────────────


@app.get("/health", include_in_schema=False)
async def health(user: User | None = Depends(current_user_optional)):
    """Liveness + subsystem status. Unauthenticated by design — a load balancer and
    `docker compose` healthcheck must be able to read it.

    Two fields are therefore admin-only. The **migration revision** names the exact schema
    an instance is on, and the **storage backend** names the infrastructure behind it;
    neither is needed by `deploy:smoke` or `health:remote`, and both narrow an attacker's
    search. `version` stays public deliberately: it is rendered in the page footer for
    everyone, and SECURITY.md tells reporters to identify their instance by exactly that.
    """
    from sqlalchemy import text

    from app.redis_client import WORKER_ALIVE_PREFIX, get_redis

    detailed = bool(user and user.is_superuser)
    checks: dict = {"app": "ok", "version": settings.app_version}
    all_ok = True
    try:
        async with async_session_maker() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"
        all_ok = False

    # `app/redis_client.py` ships a *synchronous* client, so every call here blocks the
    # event loop. That matters more on this route than anywhere else: `/health` is
    # unauthenticated and polled on a short interval by the compose healthcheck, any load
    # balancer in front of it, `task health:remote` and `task deploy:smoke`. An unreachable
    # Redis then stalls the loop for the socket timeout on every probe, so the one endpoint
    # whose job is to report trouble is also what makes it worse. `check_storage` two blocks
    # down is threadpooled for the same reason.
    from fastapi.concurrency import run_in_threadpool

    r = None
    try:
        r = get_redis()
        await run_in_threadpool(r.ping)
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "error"
        all_ok = False

    # Storage backend check — a real probe (local: write/read/delete; s3: head_bucket)
    try:
        from app import system_checks

        storage_result = await run_in_threadpool(system_checks.check_storage)
        if storage_result.level == system_checks.PASS:
            # Scripts grep for the "ok" prefix, so the backend name is additive.
            checks["storage"] = f"ok ({settings.storage_backend})" if detailed else "ok"
        else:
            checks["storage"] = "error"
            all_ok = False
    except Exception:
        checks["storage"] = "error"
        all_ok = False

    # Migration state — informational (does not gate the 503), admin-only.
    if detailed:
        try:
            from app.migrations import migration_status

            checks["migrations"] = (await run_in_threadpool(migration_status)).summary
        except Exception:
            checks["migrations"] = "unknown"

    # Active worker count — informational: the web tier must not go unhealthy just
    # because workers scaled to zero. Alert on workers_ok instead.
    try:
        if r:
            # A full keyspace walk, so it is the most expensive thing on the route — and it
            # runs on every probe. Threadpooled for the same reason as the ping above.
            worker_count = await run_in_threadpool(lambda: sum(1 for _ in r.scan_iter(f"{WORKER_ALIVE_PREFIX}*")))
            checks["workers"] = worker_count
            checks["workers_ok"] = worker_count > 0
    except Exception:
        checks["workers"] = "unknown"

    return JSONResponse(checks, status_code=200 if all_ok else 503)


# ── Login page (browser) ─────────────────────────────────────────────────────────


@app.get("/auth/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "auth/login.html", {"user": None})
