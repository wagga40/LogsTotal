"""Tier-1 tests for the MISP Event builder."""

from __future__ import annotations

from datetime import UTC, datetime

from app.intel.misp import (
    build_misp_event,
    sighting_counts_from_links,
    threat_level_for_entities,
)
from app.models import Entity, EntityJobLink


def _e(eid, value, etype="ip_address"):
    return Entity(
        id=eid,
        value=value,
        entity_type=etype,
        first_seen_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_seen_at=datetime(2026, 1, 2, tzinfo=UTC),
    )


class TestBuildMispEvent:
    def test_minimal_event_shape(self):
        ev = build_misp_event("Test", [])
        assert "Event" in ev
        e = ev["Event"]
        assert e["info"] == "Test"
        assert e["Attribute"] == []
        assert e["published"] is False
        assert "uuid" in e

    def test_ip_attribute(self):
        ev = build_misp_event("IPs", [_e(1, "1.2.3.4")])
        attrs = ev["Event"]["Attribute"]
        assert len(attrs) == 1
        assert attrs[0]["type"] == "ip-dst"
        assert attrs[0]["value"] == "1.2.3.4"
        assert attrs[0]["category"] == "Network activity"

    def test_domain_attribute(self):
        ev = build_misp_event("Domains", [_e(2, "evil.example", etype="domain")])
        assert ev["Event"]["Attribute"][0]["type"] == "domain"

    def test_sha256_hash_attribute(self):
        h = "a" * 64
        ev = build_misp_event("Hashes", [_e(3, h, etype="hash")])
        assert ev["Event"]["Attribute"][0]["type"] == "sha256"

    def test_sha1_hash_attribute(self):
        h = "b" * 40
        ev = build_misp_event("Hashes", [_e(4, h, etype="hash")])
        assert ev["Event"]["Attribute"][0]["type"] == "sha1"

    def test_md5_hash_attribute(self):
        h = "c" * 32
        ev = build_misp_event("Hashes", [_e(5, h, etype="hash")])
        assert ev["Event"]["Attribute"][0]["type"] == "md5"

    def test_unknown_hash_format_skipped(self):
        ev = build_misp_event("Hashes", [_e(6, "shorthash", etype="hash")])
        assert ev["Event"]["Attribute"] == []

    def test_sighting_count_in_comment(self):
        ev = build_misp_event("X", [_e(1, "1.2.3.4")], sighting_counts={1: 7})
        assert "7" in ev["Event"]["Attribute"][0]["comment"]

    def test_event_uuid_deterministic_per_day(self):
        a = build_misp_event("Same", [])["Event"]["uuid"]
        b = build_misp_event("Same", [])["Event"]["uuid"]
        assert a == b

    def test_tags_included(self):
        ev = build_misp_event("X", [], tags=("tlp:red", "logstotal:export"))
        names = [t["name"] for t in ev["Event"]["Tag"]]
        assert "tlp:red" in names
        assert "logstotal:export" in names


class TestThreatLevelForEntities:
    def test_default_undefined(self):
        assert threat_level_for_entities([_e(1, "x")]) == 4

    def test_worst_severity_wins(self):
        ents = [_e(1, "a"), _e(2, "b")]
        sev = {1: "low", 2: "critical"}
        assert threat_level_for_entities(ents, sev) == 1

    def test_medium_maps_to_2(self):
        ents = [_e(1, "a")]
        sev = {1: "medium"}
        assert threat_level_for_entities(ents, sev) == 2


class TestSightingCountsFromLinks:
    def test_counts_links_per_entity(self):
        jl1 = EntityJobLink(entity_id=1, job_id=1)
        jl2 = EntityJobLink(entity_id=1, job_id=2)
        jl3 = EntityJobLink(entity_id=2, job_id=1)
        result = sighting_counts_from_links({1: [jl1, jl2], 2: [jl3]})
        assert result == {1: 2, 2: 1}


class TestCaseScopedIdentifiers:
    """MISP matches events and attributes by UUID, instance-wide.

    Two cases named "Phishing" exported the same event UUID, so the second import was merged
    into the first; and an attribute's UUID depended only on the entity, so an entity in two
    cases was refused as a duplicate when the second event was imported — its indicator
    silently missing there. Exporting the same case twice must still produce the same UUIDs,
    or every re-import duplicates the event.
    """

    def test_same_named_cases_are_different_events(self):
        a = build_misp_event("LogsTotal Case: Phishing", [], case_id=1)["Event"]["uuid"]
        b = build_misp_event("LogsTotal Case: Phishing", [], case_id=2)["Event"]["uuid"]
        assert a != b

    def test_one_entity_in_two_cases_has_two_attribute_uuids(self):
        a = build_misp_event("A", [_e(1, "1.2.3.4")], case_id=1)["Event"]["Attribute"][0]["uuid"]
        b = build_misp_event("B", [_e(1, "1.2.3.4")], case_id=2)["Event"]["Attribute"][0]["uuid"]
        assert a != b

    def test_a_case_re_exported_keeps_its_identifiers(self):
        first = build_misp_event("A", [_e(1, "1.2.3.4")], case_id=1)["Event"]
        again = build_misp_event("Renamed", [_e(1, "1.2.3.4")], case_id=1)["Event"]
        assert first["uuid"] == again["uuid"], "a rename is the same case"
        assert first["Attribute"][0]["uuid"] == again["Attribute"][0]["uuid"]


def test_the_stix_case_note_is_the_case_not_its_name():
    from app.intel.cases import build_case_stix_bundle

    def note_id(bundle):
        return next(o["id"] for o in bundle["objects"] if o["type"] == "note")

    one = build_case_stix_bundle("Phishing", [], {}, case_id=1)
    two = build_case_stix_bundle("Phishing", [], {}, case_id=2)
    renamed = build_case_stix_bundle("Phishing (closed)", [], {}, case_id=1)
    assert note_id(one) != note_id(two), "same name, different cases"
    assert note_id(one) == note_id(renamed), "a rename must not orphan the note"
