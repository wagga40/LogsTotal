"""TAXII objects paging: `more=true` has to come with a way to reach the rest.

The endpoint answered `more: true, next: ""` and ignored `next` and `added_after`, so a
paging client (taxii2-client's `as_pages`) looped on page one forever or stopped there, and
an incremental poll re-ingested the same newest objects and never saw older ones.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.auth.api_tokens import generate_token
from app.json_utils import dumps as json_dumps
from app.models import ApiToken, Entity

pytestmark = pytest.mark.anyio

URL = "/taxii2/logstotal/collections/{cid}/objects/"


@pytest.fixture()
async def taxii(async_db, fake_redis):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.database import get_async_session
    from app.intel.taxii import COLLECTIONS
    from app.routers import taxii as taxii_router

    plaintext, digest, prefix = generate_token()
    async_db.add(ApiToken(name="t", token_hash=digest, prefix=prefix, scopes_json=json_dumps(["taxii:read"])))
    for i in range(5):
        # Two share a timestamp, so the cursor has to break the tie on id.
        seen = datetime(2026, 1, 1 + min(i, 3), 12, 0)
        async_db.add(Entity(value=f"10.0.0.{i}", entity_type="ip_address", job_count=1, last_seen_at=seen, first_seen_at=seen))
    await async_db.commit()

    app = FastAPI()
    app.include_router(taxii_router.router)

    async def _session():
        yield async_db

    app.dependency_overrides[get_async_session] = _session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers={"Authorization": f"Bearer {plaintext}"}) as client:
        yield client, URL.format(cid=COLLECTIONS[0]["id"])


def _values(env):
    return [o["name"] for o in env["objects"] if o["type"] == "indicator"]


async def test_following_next_reaches_every_object_exactly_once(taxii):
    client, url = taxii
    seen: list[str] = []
    params = {"limit": 2}
    for _ in range(5):
        env = (await client.get(url, params=params)).json()
        seen.extend(_values(env))
        if not env["more"]:
            break
        assert env["next"], "more=true must carry a cursor"
        params = {"limit": 2, "next": env["next"]}
    assert sorted(seen) == [f"10.0.0.{i}" for i in range(5)]
    assert len(seen) == 5


async def test_added_after_returns_only_newer_objects(taxii):
    client, url = taxii
    env = (await client.get(url, params={"added_after": "2026-01-02T12:00:00Z"})).json()
    assert sorted(_values(env)) == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]


async def test_a_malformed_cursor_is_a_400_not_page_one(taxii):
    client, url = taxii
    assert (await client.get(url, params={"next": "not-a-cursor"})).status_code == 400


async def test_discovery_advertises_https_when_the_app_is_served_over_https(taxii, monkeypatch):
    """Behind the bundled Caddy the app sees plain HTTP from the proxy, so `request.base_url`
    said `http://`, and a client following `api_roots` sent its Bearer token over plaintext
    before the proxy's redirect. `COOKIE_INSECURE` unset is the deployment saying it is served
    over HTTPS — the Secure login cookie would not work otherwise."""
    from app.config import settings

    client, _url = taxii
    monkeypatch.setattr(settings, "debug", False)
    monkeypatch.setattr(settings, "cookie_insecure", False)
    assert (await client.get("/taxii2/")).json()["api_roots"] == ["https://test/taxii2/logstotal/"]

    monkeypatch.setattr(settings, "cookie_insecure", True)
    assert (await client.get("/taxii2/")).json()["api_roots"] == ["http://test/taxii2/logstotal/"]


async def test_a_crafted_cursor_is_a_400_not_a_server_error(taxii):
    """`next` is opaque but it is client-held. An id no integer column can hold raised on
    the bind (SQLite: OverflowError; PostgreSQL: out of range), and an offset timestamp is a
    timezone-aware bind asyncpg refuses — both 500s from a single query parameter."""
    import base64

    client, url = taxii

    def crafted(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    assert (await client.get(url, params={"next": crafted("2026-01-02T12:00:00|99999999999999999999")})).status_code == 400
    offset = await client.get(url, params={"next": crafted("2026-01-02T14:00:00+02:00|3"), "limit": 10})
    assert offset.status_code == 200
