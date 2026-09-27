"""End-to-end tests for Bearer API-token authentication.

`tests/test_api_tokens.py` covers the pure helpers (generate/hash/encrypt); this exercises
the dependency that actually guards the endpoints. A scoped Bearer token is the *only*
authentication the TAXII server has, so a regression in revocation, expiry, or scope
checking must fail here.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.auth.api_tokens import generate_token
from app.database import utc_now_naive
from app.json_utils import dumps as json_dumps
from app.models import ApiToken

FEED = "/intel/ioc-feed"


async def _make_token(async_db, *, scopes: list[str], revoked: bool = False, expires_in: timedelta | None = None, creator=None) -> str:
    plaintext, digest, prefix = generate_token()
    async_db.add(
        ApiToken(
            name=f"t-{prefix}",
            token_hash=digest,
            prefix=prefix,
            scopes_json=json_dumps(scopes),
            revoked_at=utc_now_naive() if revoked else None,
            expires_at=(utc_now_naive() + expires_in) if expires_in else None,
            created_by_user_id=creator.id if creator is not None else None,
        )
    )
    await async_db.commit()
    return plaintext


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── /intel/ioc-feed (cookie OR token) ───────────────────────────────────────


async def test_valid_token_is_accepted(test_client, async_db):
    token = await _make_token(async_db, scopes=["ioc_feed:read"])
    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 200


async def test_no_credentials_is_401(test_client):
    assert (await test_client.get(FEED)).status_code == 401


async def test_unknown_token_is_401(test_client, async_db):
    await _make_token(async_db, scopes=["ioc_feed:read"])
    assert (await test_client.get(FEED, headers=_auth("lgt_not-a-real-token"))).status_code == 401


async def test_revoked_token_is_rejected(test_client, async_db):
    token = await _make_token(async_db, scopes=["ioc_feed:read"], revoked=True)
    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 401


async def test_expired_token_is_rejected(test_client, async_db):
    token = await _make_token(async_db, scopes=["ioc_feed:read"], expires_in=timedelta(seconds=-60))
    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 401


async def test_token_valid_until_tomorrow_is_accepted(test_client, async_db):
    token = await _make_token(async_db, scopes=["ioc_feed:read"], expires_in=timedelta(days=1))
    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 200


async def test_wrong_scope_is_403_not_401(test_client, async_db):
    """403 distinguishes "authenticated but not permitted" from "not authenticated"."""
    token = await _make_token(async_db, scopes=["taxii:read"])
    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 403


async def test_successful_use_stamps_last_used_at(test_client, async_db):
    from sqlalchemy import select

    token = await _make_token(async_db, scopes=["ioc_feed:read"])
    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 200

    row = (await async_db.execute(select(ApiToken))).scalars().first()
    await async_db.refresh(row)
    assert row.last_used_at is not None


async def test_a_token_whose_creator_is_active_is_accepted(test_client, async_db, admin_user):
    token = await _make_token(async_db, scopes=["ioc_feed:read"], creator=admin_user)
    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 200


async def test_a_deactivated_creators_token_stops_working(test_client, async_db, admin_user):
    """Deactivating an account is how an admin offboards someone without erasing their
    history. A token delegates its creator's access, so it must stop when the account does —
    otherwise it keeps a departed admin's view of every private job and unshared case."""
    token = await _make_token(async_db, scopes=["ioc_feed:read", "case:read"], creator=admin_user)
    admin_user.is_active = False
    await async_db.commit()

    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 401
    assert (await test_client.get("/intel/cases/list.json", headers=_auth(token))).status_code == 401


async def test_a_creator_demoted_below_member_loses_the_token(test_client, async_db, admin_user):
    """`role=user` has no Intel access by cookie, so a token they minted earlier cannot keep it."""
    token = await _make_token(async_db, scopes=["ioc_feed:read"], creator=admin_user)
    admin_user.role = "user"
    admin_user.is_superuser = False
    await async_db.commit()

    assert (await test_client.get(FEED, headers=_auth(token))).status_code == 401


async def test_basic_user_cookie_cannot_reach_the_feed(user_client):
    """`role=user` is below member, so the cookie branch must refuse."""
    assert (await user_client.get(FEED)).status_code == 403


async def test_member_cookie_is_accepted_without_a_token(member_client):
    assert (await member_client.get(FEED)).status_code == 200


# ── TAXII (token only, and only when enabled) ───────────────────────────────


@pytest.fixture()
async def taxii_client(async_db, fake_redis):
    """A client whose app has the TAXII router mounted (it is opt-in via settings)."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.database import get_async_session
    from app.routers import taxii as taxii_router

    app = FastAPI()
    app.include_router(taxii_router.router)

    async def _override_session():
        yield async_db

    app.dependency_overrides[get_async_session] = _override_session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()


async def test_taxii_discovery_requires_a_token(taxii_client):
    assert (await taxii_client.get("/taxii2/")).status_code == 401


async def test_taxii_rejects_a_token_scoped_only_for_the_feed(taxii_client, async_db):
    token = await _make_token(async_db, scopes=["ioc_feed:read"])
    assert (await taxii_client.get("/taxii2/", headers=_auth(token))).status_code == 403


async def test_taxii_accepts_a_taxii_scoped_token(taxii_client, async_db):
    token = await _make_token(async_db, scopes=["taxii:read"])
    assert (await taxii_client.get("/taxii2/", headers=_auth(token))).status_code == 200


async def test_taxii_rejects_a_revoked_token(taxii_client, async_db):
    token = await _make_token(async_db, scopes=["taxii:read"], revoked=True)
    assert (await taxii_client.get("/taxii2/", headers=_auth(token))).status_code == 401


async def test_taxii_rejects_a_deactivated_creators_token(taxii_client, async_db, admin_user):
    token = await _make_token(async_db, scopes=["taxii:read"], creator=admin_user)
    admin_user.is_active = False
    await async_db.commit()
    assert (await taxii_client.get("/taxii2/", headers=_auth(token))).status_code == 401


# ── every token-reachable route must be rate-limited ────────────────────────


def _token_reachable_paths() -> set[tuple[str, str]]:
    """(method, path) for every route whose dependency tree includes an API-token scope.

    Built from the live app rather than a grep, so a new token-authed route is caught the
    moment it is registered.
    """
    from starlette.routing import Mount

    from app.auth.api_tokens import current_user_or_api_token, submission_access
    from app.main import app

    markers = (current_user_or_api_token.__name__, submission_access.__name__)
    found: set[tuple[str, str]] = set()

    def uses_token(route) -> bool:
        stack = [getattr(route, "dependant", None)]
        while stack:
            dep = stack.pop()
            if dep is None:
                continue
            call = getattr(dep, "call", None)
            # current_user_or_api_token returns a closure defined inside it.
            if call is not None and getattr(call, "__qualname__", "").startswith(markers):
                return True
            stack.extend(dep.dependencies)
        return False

    def walk(routes, prefix: str) -> None:
        for r in routes:
            # FastAPI wraps `include_router` results; unwrap to reach the real routes.
            if type(r).__name__ == "_IncludedRouter":
                walk(r.original_router.routes, prefix + getattr(r.include_context, "prefix", ""))
            elif isinstance(r, Mount):
                walk(r.routes, prefix + r.path)
            elif hasattr(r, "path") and uses_token(r):
                for method in getattr(r, "methods", None) or []:
                    found.add((method, prefix + r.path))

    walk(app.router.routes, "")
    return found


def test_every_token_reachable_route_is_rate_limited():
    """An unthrottled token scope is an unmetered read of the whole instance.

    `case:read` was exactly that: six endpoints, several of them the deliberately
    unpaginated case aggregations, each also forcing a `last_used_at` write.
    """
    from app.middleware.production import AuthRateLimitMiddleware as M
    from app.middleware.upload_admission import UploadAdmissionMiddleware

    reachable = _token_reachable_paths()
    assert reachable, "no token-authed routes found — the introspection above has drifted"

    unlimited = []
    for method, path in sorted(reachable):
        exact = any(method == m and path == p for m, p, _ in M._RATE_LIMITS)
        prefixed = any(method == m and path.startswith(p) for m, p, _, _ in M._RATE_LIMITS_PREFIX)
        ingestion = method == "POST" and path in UploadAdmissionMiddleware.PATHS
        if not (exact or prefixed or ingestion):
            unlimited.append(f"{method} {path}")

    assert not unlimited, "token-reachable routes with no rate limit:\n  " + "\n  ".join(unlimited)
