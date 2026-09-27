"""The generated API schema is a production surface, not just a dev nicety.

Left ungated with `DEBUG=false`, `GET /openapi.json` answers 200 with ~184 KB of JSON
describing every path — dozens of them under `/admin`, including
`/admin/users/{user_id}/delete` and `/admin/api-tokens/{token_id}/revoke` — plus the
request-body schemas, to anyone who asks, and `GET /redoc` renders it. Nothing else gates
either: `UploadRateLimitMiddleware`/`AuthRateLimitMiddleware` match named paths and a few
prefixes, `CsrfMiddleware` only guards unsafe methods, and the bundled Caddy
reverse-proxies with no path matcher.

The routes stay authorization-gated, so this is disclosure rather than access — but a
public instance that accepts anonymous uploads would be publishing a precise
machine-readable inventory of itself. It is easy to miss: with only `docs_url` gated on
DEBUG, Swagger being absent reads as "the API surface is off".
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

MAIN_PY = Path(__file__).resolve().parents[1] / "app" / "main.py"

# Where FastAPI would serve the trio by default, and where debug mode puts it. `/docs` is
# absent from the first list on purpose: that path is the app's own public documentation
# page (`routers/docs.py`), which is why Swagger lives elsewhere.
DEFAULT_PATHS = ("/openapi.json", "/redoc")
DEBUG_PATHS = ("/api/openapi.json", "/api/docs", "/api/redoc")


def _client_for(monkeypatch: pytest.MonkeyPatch, *, debug: bool) -> AsyncClient:
    """Re-execute `app/main.py` under a throwaway module name with DEBUG pinned.

    The FastAPI instance is built at import time from `settings.debug`, and the suite runs
    with `DEBUG=true` (conftest sets it so the auth cookie is not Secure over
    http://test), so the production surface can only be reached by building a second app.
    Loading under a private name leaves `sys.modules["app.main"]` — and with it every
    other test's client — untouched.
    """
    from app.config import settings

    monkeypatch.setattr(settings, "debug", debug)
    spec = importlib.util.spec_from_file_location(f"app_main_debug_{debug}", MAIN_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return AsyncClient(transport=ASGITransport(app=module.app), base_url="http://test")


@pytest.mark.parametrize("path", DEFAULT_PATHS + DEBUG_PATHS)
async def test_nothing_serves_the_schema_in_production(path: str, monkeypatch: pytest.MonkeyPatch):
    """With DEBUG=false there is no schema document and nothing that renders one."""
    async with _client_for(monkeypatch, debug=False) as client:
        assert (await client.get(path)).status_code == 404, f"{path} is reachable with DEBUG=false"


@pytest.mark.parametrize("path", DEBUG_PATHS)
async def test_debug_serves_the_whole_trio_under_api(path: str, monkeypatch: pytest.MonkeyPatch):
    """Swagger cannot render without a reachable schema, so all three move together."""
    async with _client_for(monkeypatch, debug=True) as client:
        assert (await client.get(path)).status_code == 200, f"{path} is unreachable with DEBUG=true"


async def test_swagger_fetches_the_schema_from_where_it_is_actually_served(monkeypatch: pytest.MonkeyPatch):
    """The URL baked into the Swagger page must be the one the app mounted.

    A schema moved without its UI is the same outage as a missing one, and that page is
    generated HTML — only the rendered document proves the two agree.
    """
    async with _client_for(monkeypatch, debug=True) as client:
        assert "/api/openapi.json" in (await client.get("/api/docs")).text


@pytest.mark.parametrize("path", DEFAULT_PATHS)
async def test_debug_leaves_the_default_paths_empty(path: str, monkeypatch: pytest.MonkeyPatch):
    """One place to reason about: everything documentation-shaped lives under `/api/`."""
    async with _client_for(monkeypatch, debug=True) as client:
        assert (await client.get(path)).status_code == 404, f"{path} is served outside /api/ with DEBUG=true"
