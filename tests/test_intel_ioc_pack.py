"""Tier-1 tests for the IOC pack builders."""

from __future__ import annotations

from datetime import UTC, datetime

from app.intel.ioc_pack import build_case_ioc_pack, build_entity_ioc_pack
from app.models import Entity, EntityTag


def _e(eid, value="1.2.3.4", etype="ip_address", job_count=3):
    return Entity(
        id=eid,
        value=value,
        entity_type=etype,
        first_seen_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_seen_at=datetime(2026, 1, 2, tzinfo=UTC),
        job_count=job_count,
    )


class TestBuildEntityIocPack:
    def test_minimal_pack_has_focal_indicator(self):
        pack = build_entity_ioc_pack(_e(1))
        assert pack["scope"] == "entity"
        assert pack["focal"] == "1.2.3.4"
        assert len(pack["indicators"]) == 1
        assert pack["indicators"][0]["value"] == "1.2.3.4"
        assert pack["indicators"][0]["type"] == "ip_address"
        assert pack["indicators"][0]["sightings"] == 3

    def test_with_neighbors(self):
        pack = build_entity_ioc_pack(_e(1), [_e(2, "5.6.7.8"), _e(3, "evil.example", etype="domain")])
        assert len(pack["indicators"]) == 3

    def test_focal_threat_metadata_propagates(self):
        pack = build_entity_ioc_pack(
            _e(1),
            focal_threat_categories=["lolbin_usage", "credential_access"],
            focal_severity="high",
        )
        focal = pack["indicators"][0]
        assert focal["severity"] == "high"
        assert focal["threat_categories"] == ["credential_access", "lolbin_usage"]

    def test_focal_tags_sorted_alphabetically(self):
        tags = [EntityTag(tag="reviewed", color="green"), EntityTag(tag="apt28", color="red")]
        pack = build_entity_ioc_pack(_e(1), focal_tags=tags)
        assert pack["indicators"][0]["tags"] == ["apt28", "reviewed"]

    def test_stix_pattern_for_ip(self):
        pack = build_entity_ioc_pack(_e(1))
        assert pack["indicators"][0]["stix_pattern"] == "[ipv4-addr:value = '1.2.3.4']"

    def test_stix_pattern_escapes_quotes(self):
        pack = build_entity_ioc_pack(_e(1, "a'b", etype="user"))
        assert "a\\'b" in pack["indicators"][0]["stix_pattern"]


class TestBuildCaseIocPack:
    def test_case_pack_lists_all_entities(self):
        entities = [_e(1, "1.2.3.4"), _e(2, "evil.example", etype="domain")]
        pack = build_case_ioc_pack("My case", entities)
        assert pack["scope"] == "case"
        assert pack["case"] == "My case"
        assert len(pack["indicators"]) == 2

    def test_case_pack_uses_explicit_sighting_count(self):
        entities = [_e(1, "1.2.3.4", job_count=2)]
        pack = build_case_ioc_pack("X", entities, sighting_counts={1: 99})
        assert pack["indicators"][0]["sightings"] == 99

    def test_case_pack_metadata_per_entity(self):
        entities = [_e(1, "1.2.3.4"), _e(2, "5.6.7.8")]
        pack = build_case_ioc_pack(
            "X",
            entities,
            threat_categories_by_entity={1: ["lolbin_usage"]},
            severity_by_entity={2: "critical"},
        )
        assert pack["indicators"][0]["threat_categories"] == ["lolbin_usage"]
        assert pack["indicators"][1]["severity"] == "critical"
