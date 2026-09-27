"""Tier-1 tests for the TAXII 2.1 envelope builders."""

from __future__ import annotations

from datetime import UTC, datetime

from app.intel.taxii import (
    COLLECTIONS,
    DEFAULT_API_ROOT,
    api_root,
    collection_by_id,
    collection_envelope,
    collections_envelope,
    discovery,
    objects_envelope,
)
from app.models import Entity


def _e(eid, value="1.2.3.4", etype="ip_address"):
    return Entity(id=eid, value=value, entity_type=etype, first_seen_at=datetime(2026, 1, 1, tzinfo=UTC), last_seen_at=datetime(2026, 1, 2, tzinfo=UTC))


class TestDiscovery:
    def test_discovery_lists_default_api_root(self):
        d = discovery("http://example.com")
        assert DEFAULT_API_ROOT in d["default"]
        assert d["api_roots"][0].endswith(f"/taxii2/{DEFAULT_API_ROOT}/")

    def test_discovery_strips_trailing_slash_in_base(self):
        a = discovery("http://example.com/")
        b = discovery("http://example.com")
        assert a == b


class TestApiRoot:
    def test_api_root_versions(self):
        r = api_root()
        assert "application/taxii+json;version=2.1" in r["versions"]


class TestCollections:
    def test_collections_envelope_has_known_collection(self):
        env = collections_envelope()
        ids = [c["id"] for c in env["collections"]]
        assert ids == [c["id"] for c in COLLECTIONS]
        for c in env["collections"]:
            assert c["can_read"] is True
            assert c["can_write"] is False

    def test_collection_envelope_returns_none_for_unknown(self):
        assert collection_envelope("nonexistent") is None

    def test_collection_by_id_lookup(self):
        cid = COLLECTIONS[0]["id"]
        assert collection_by_id(cid)["title"] == COLLECTIONS[0]["title"]


class TestObjectsEnvelope:
    def test_objects_includes_identity_plus_indicators(self):
        env = objects_envelope([_e(1), _e(2, "5.6.7.8")])
        types = [o["type"] for o in env["objects"]]
        assert types.count("identity") == 1
        assert types.count("indicator") == 2
        assert env["more"] is False
        assert env["next"] == ""

    def test_more_flag_propagates(self):
        env = objects_envelope([_e(1)], more=True, next_cursor="abc123")
        assert env["more"] is True
        assert env["next"] == "abc123"

    def test_empty_objects_still_includes_identity(self):
        env = objects_envelope([])
        assert len(env["objects"]) == 1
        assert env["objects"][0]["type"] == "identity"
