"""The IOC feed's filters narrow, or say why they cannot — they never silently widen.

The feed is read by integrations, not people, so a filter that quietly stops filtering is
worse than an error: the consumer ingests the wrong set and nothing looks broken.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from app.models import Entity

pytestmark = pytest.mark.anyio


@pytest.fixture()
async def two_types(async_db):
    async_db.add_all(
        [
            Entity(value="1.2.3.4", entity_type="ip_address", job_count=1, last_seen_at=datetime(2026, 1, 1, 1, 0)),
            Entity(value="alice", entity_type="user", job_count=1, last_seen_at=datetime(2026, 1, 1, 1, 0)),
        ]
    )
    await async_db.commit()


def _values(resp):
    return sorted(row["value"] for row in resp.json()) if resp.status_code == 200 else None


async def test_a_type_alias_the_search_box_accepts_is_accepted_here(member_client, two_types):
    """`ip` is what the dashboard grammar calls an IP address; the feed returned everything."""
    resp = await member_client.get("/intel/ioc-feed?format=json&types=ip")
    assert _values(resp) == ["1.2.3.4"]


async def test_an_unknown_type_is_refused_not_ignored(member_client, two_types):
    resp = await member_client.get("/intel/ioc-feed?format=json&types=ipv4")
    assert resp.status_code == 400
    assert "ipv4" in resp.text


async def test_since_with_a_utc_offset_means_that_instant(member_client, two_types):
    """`2026-01-01T02:00:00+02:00` is midnight UTC, so an entity last seen at 01:00 UTC is
    inside the window. The offset was dropped and the value compared as 02:00 — excluding it
    on SQLite, and on PostgreSQL an aware datetime cannot bind to the column at all."""
    resp = await member_client.get("/intel/ioc-feed?format=json&since=2026-01-01T02:00:00%2B02:00")
    assert _values(resp) == ["1.2.3.4", "alice"]
    resp = await member_client.get("/intel/ioc-feed?format=json&since=2026-01-01T01:30:00Z")
    assert _values(resp) == []
