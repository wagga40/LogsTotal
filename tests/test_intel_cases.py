"""Tier-1 tests for the STIX 2.1 bundle builders in app.intel.cases."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.intel.cases import (
    LOGSTOTAL_IDENTITY_ID,
    build_case_list_rows,
    build_case_stix_bundle,
    build_entity_stix_bundle,
    build_findings_rollup,
    build_similar_pivot_rows,
    make_identity,
    make_indicator,
    make_relationship,
    make_sighting,
    merge_correlated_hit,
    rank_correlated_pivot_rows,
    suggest_case_severity,
    wrap_bundle,
)
from app.models import AnalysisJob, Entity, EntityJobLink, InvestigationCase
from app.similarity.hasher import SimilarFile


def _entity(eid, value="10.0.0.1", etype="ip_address"):
    return Entity(
        id=eid,
        value=value,
        entity_type=etype,
        first_seen_at=datetime(2026, 1, 1, tzinfo=UTC),
        last_seen_at=datetime(2026, 1, 2, tzinfo=UTC),
    )


def _job(jid):
    return AnalysisJob(id=jid, created_at=datetime(2026, 1, 3, tzinfo=UTC))


class TestPrimitives:
    def test_identity_is_stable(self):
        a = make_identity()
        b = make_identity()
        assert a["id"] == b["id"] == LOGSTOTAL_IDENTITY_ID

    def test_indicator_pattern_for_ip(self):
        ind = make_indicator(_entity(1, "1.2.3.4"))
        assert ind["type"] == "indicator"
        assert ind["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
        assert ind["labels"] == ["ip_address"]

    def test_indicator_pattern_for_domain(self):
        ind = make_indicator(_entity(2, "evil.example", etype="domain"))
        assert ind["pattern"] == "[domain-name:value = 'evil.example']"

    def test_indicator_pattern_for_unknown_type_uses_fallback(self):
        ind = make_indicator(_entity(3, "anything", etype="x-custom"))
        assert ind["pattern"] == "[x-logstotal:value = 'anything']"

    @pytest.mark.parametrize(
        "value, etype, pattern",
        [
            ("D41D8CD98F00B204E9800998ECF8427E", "hash", "[file:hashes.'MD5' = 'D41D8CD98F00B204E9800998ECF8427E']"),
            ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "hash", "[file:hashes.'SHA-1' = 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709']"),
            (
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                "hash",
                "[file:hashes.'SHA-256' = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855']",
            ),
            ("fe80::1", "ip_address", "[ipv6-addr:value = 'fe80::1']"),
            ("\\Microsoft\\Windows\\Foo\\", "task", "[x-logstotal-task:name = '\\\\Microsoft\\\\Windows\\\\Foo\\\\']"),
            ("CORP\\o'brien", "user", "[user-account:account_login = 'CORP\\\\o\\'brien']"),
        ],
    )
    def test_the_pattern_names_what_the_value_is_and_escapes_it(self, value, etype, pattern):
        """Every hash was labelled SHA-256 and every IP ipv4-addr, so an MD5 was matched against
        SHA-256 values downstream and never hit. And a STIX string literal allows `\\` and `\'`
        as escapes: a trailing backslash (every task path) escaped the closing quote and the
        TIP rejected the indicator, or the whole bundle."""
        from app.intel.ioc_pack import build_entity_ioc_pack

        assert make_indicator(_entity(1, value, etype=etype))["pattern"] == pattern
        assert build_entity_ioc_pack(_entity(1, value, etype=etype))["indicators"][0]["stix_pattern"] == pattern

    def test_indicator_id_deterministic(self):
        a = make_indicator(_entity(7))
        b = make_indicator(_entity(7))
        assert a["id"] == b["id"]

    def test_indicator_escapes_single_quote(self):
        ind = make_indicator(_entity(4, "a'b", etype="ip_address"))
        assert "a\\'b" in ind["pattern"]

    def test_relationship_includes_refs(self):
        rel = make_relationship("indicator--A", "indicator--B")
        assert rel["type"] == "relationship"
        assert rel["source_ref"] == "indicator--A"
        assert rel["target_ref"] == "indicator--B"
        assert rel["relationship_type"] == "related-to"

    def test_sighting_count_min_1(self):
        s = make_sighting("indicator--A", _job(42), count=0)
        assert s["count"] == 1

    def test_wrap_bundle_shape(self):
        b = wrap_bundle([{"x": 1}])
        assert b["type"] == "bundle"
        assert b["id"].startswith("bundle--")
        assert b["objects"] == [{"x": 1}]


class TestBuildEntityStixBundle:
    def test_minimal_no_neighbors_no_sightings(self):
        b = build_entity_stix_bundle(_entity(1), [], [])
        types = [o["type"] for o in b["objects"]]
        assert types == ["identity", "indicator"]

    def test_with_neighbors_and_sightings(self):
        focal = _entity(1, "10.0.0.1")
        neighbors = [_entity(2, "10.0.0.2"), _entity(3, "10.0.0.3")]
        job_links = [EntityJobLink(entity_id=1, job_id=42, occurrence_count=3, job=_job(42))]
        b = build_entity_stix_bundle(focal, neighbors, job_links)
        types = [o["type"] for o in b["objects"]]
        # identity + focal indicator + 2 neighbor indicators + 2 relationships + 1 sighting
        assert types.count("indicator") == 3
        assert types.count("relationship") == 2
        assert types.count("sighting") == 1

    def test_drops_sighting_when_job_missing(self):
        focal = _entity(1)
        job_links = [EntityJobLink(entity_id=1, job_id=42, occurrence_count=1, job=None)]
        b = build_entity_stix_bundle(focal, [], job_links)
        assert "sighting" not in [o["type"] for o in b["objects"]]


class TestBuildCaseStixBundle:
    def test_case_bundle_with_note_and_sightings(self):
        entities = [_entity(10, "10.0.0.1"), _entity(11, "evil.example", etype="domain")]
        job_links = {
            10: [EntityJobLink(entity_id=10, job_id=42, occurrence_count=2, job=_job(42))],
            11: [EntityJobLink(entity_id=11, job_id=43, occurrence_count=1, job=_job(43))],
        }
        b = build_case_stix_bundle("My case", entities, job_links)
        types = [o["type"] for o in b["objects"]]
        # identity + note + 2 indicators + 2 sightings
        assert types.count("identity") == 1
        assert types.count("note") == 1
        assert types.count("indicator") == 2
        assert types.count("sighting") == 2
        # Note must reference both indicators
        note = next(o for o in b["objects"] if o["type"] == "note")
        assert len(note["object_refs"]) == 2

    def test_case_bundle_skips_entity_without_links(self):
        entities = [_entity(10)]
        b = build_case_stix_bundle("Empty", entities, {})
        assert "sighting" not in [o["type"] for o in b["objects"]]


class TestSuggestCaseSeverity:
    def test_empty_dict_returns_none(self):
        assert suggest_case_severity({}) is None

    def test_all_zero_counts_returns_none(self):
        assert suggest_case_severity({"critical": 0, "high": 0, "low": 0}) is None

    def test_informational_only_returns_informational(self):
        assert suggest_case_severity({"informational": 3}) == "informational"

    def test_worst_of_mixed_severities_wins(self):
        assert suggest_case_severity({"low": 5, "critical": 1}) == "critical"

    def test_unknown_severity_keys_are_ignored(self):
        assert suggest_case_severity({"bogus": 100}) is None
        assert suggest_case_severity({"bogus": 100, "medium": 1}) == "medium"


class TestBuildFindingsRollup:
    def test_empty_inputs_yield_empty_rollup(self):
        rollup = build_findings_rollup([], [], {})
        assert rollup == {
            "severities": [],
            "total_findings": 0,
            "total_events": 0,
            "suggested_severity": None,
            "top_rules": [],
            "tactics": [],
        }

    def test_severities_ordered_by_severity_order_and_zero_filtered(self):
        # Out-of-order input, plus a defensively-zero row that must be dropped.
        severity_rows = [("low", 2, 4), ("critical", 1, 1), ("medium", 0, 0)]
        rollup = build_findings_rollup(severity_rows, [], {})
        assert [s["severity"] for s in rollup["severities"]] == ["critical", "low"]
        assert rollup["severities"][0] == {"severity": "critical", "findings": 1, "events": 1}
        assert rollup["severities"][1] == {"severity": "low", "findings": 2, "events": 4}
        assert rollup["total_findings"] == 3
        assert rollup["total_events"] == 5

    def test_unknown_severity_row_is_dropped(self):
        rollup = build_findings_rollup([("bogus", 5, 5)], [], {})
        assert rollup["severities"] == []
        assert rollup["total_findings"] == 0

    def test_suggested_severity_matches_worst_present(self):
        severity_rows = [("low", 2, 4), ("critical", 1, 1)]
        rollup = build_findings_rollup(severity_rows, [], {})
        assert rollup["suggested_severity"] == "critical"

    def test_top_rules_passed_through_in_given_order(self):
        rule_rows = [("Rule A", "critical", 5), ("Rule B", "high", 2)]
        rollup = build_findings_rollup([], rule_rows, {})
        assert rollup["top_rules"] == [
            {"rule_name": "Rule A", "severity": "critical", "events": 5},
            {"rule_name": "Rule B", "severity": "high", "events": 2},
        ]

    def test_tactics_ordered_canonically_with_color_attached(self):
        # impact appears after execution in the canonical kill-chain order.
        tactic_counts = {"impact": 3, "execution": 5}
        rollup = build_findings_rollup([], [], tactic_counts)
        assert [t["tactic"] for t in rollup["tactics"]] == ["execution", "impact"]
        assert rollup["tactics"][0]["count"] == 5
        assert all(t["color"].startswith("#") for t in rollup["tactics"])

    def test_tactics_zero_count_excluded(self):
        rollup = build_findings_rollup([], [], {"execution": 0})
        assert rollup["tactics"] == []


class TestBuildCaseListRows:
    """Tier-1 tests for the cases-list triage builder — findings/derived-severity
    assembly, last-activity fallback, and every sort branch (incl. None-handling)."""

    def _case(self, cid, *, name="Case", updated_at=None):
        return InvestigationCase(id=cid, name=name, updated_at=updated_at or datetime(2026, 1, 1, 12, 0))

    def test_findings_total_and_derived_severity_from_counts(self):
        case = self._case(1)
        rows = build_case_list_rows([case], {1: {"critical": 1, "low": 3}}, {}, {}, "updated")
        assert rows[0]["findings_total"] == 4
        assert rows[0]["derived_severity"] == "critical"

    def test_empty_case_has_no_derived_severity_and_zero_findings(self):
        case = self._case(2)
        rows = build_case_list_rows([case], {}, {}, {}, "updated")
        assert rows[0]["findings_total"] == 0
        assert rows[0]["derived_severity"] is None

    def test_last_activity_prefers_max_of_job_entity_case_updated(self):
        case = self._case(3, updated_at=datetime(2026, 1, 1))
        job_activity = {3: datetime(2026, 1, 5)}
        entity_activity = {3: datetime(2026, 1, 3)}
        rows = build_case_list_rows([case], {}, job_activity, entity_activity, "updated")
        assert rows[0]["last_activity"] == datetime(2026, 1, 5)

    def test_last_activity_falls_back_to_case_updated_when_no_links(self):
        case = self._case(4, updated_at=datetime(2026, 1, 2))
        rows = build_case_list_rows([case], {}, {}, {}, "updated")
        assert rows[0]["last_activity"] == datetime(2026, 1, 2)

    def test_sort_updated_or_invalid_keeps_input_order(self):
        case_a = self._case(1, name="B")
        case_b = self._case(2, name="A")
        rows_default = build_case_list_rows([case_a, case_b], {}, {}, {}, "updated")
        assert [r["case"].id for r in rows_default] == [1, 2]
        rows_bogus = build_case_list_rows([case_a, case_b], {}, {}, {}, "not-a-real-sort")
        assert [r["case"].id for r in rows_bogus] == [1, 2]

    def test_sort_activity_orders_desc_with_none_last(self):
        case_old = self._case(1, name="Old", updated_at=datetime(2020, 1, 1))
        case_new = self._case(2, name="New", updated_at=datetime(2026, 1, 1))
        rows = build_case_list_rows([case_old, case_new], {}, {}, {}, "activity")
        assert [r["case"].id for r in rows] == [2, 1]

    def test_sort_findings_orders_desc(self):
        case_low = self._case(1, name="Low")
        case_high = self._case(2, name="High")
        rows = build_case_list_rows([case_low, case_high], {1: {"low": 1}, 2: {"critical": 3}}, {}, {}, "findings")
        assert [r["case"].id for r in rows] == [2, 1]

    def test_sort_name_case_insensitive(self):
        case_b = self._case(1, name="banana")
        case_a = self._case(2, name="Apple")
        case_c = self._case(3, name="cherry")
        rows = build_case_list_rows([case_b, case_a, case_c], {}, {}, {}, "name")
        assert [r["case"].name for r in rows] == ["Apple", "banana", "cherry"]

    def test_sort_severity_worst_first_no_severity_last_tie_break_by_updated_desc(self):
        case_none_older = self._case(1, name="NoneOlder", updated_at=datetime(2026, 1, 1))
        case_none_newer = self._case(2, name="NoneNewer", updated_at=datetime(2026, 1, 5))
        case_low = self._case(3, name="Low", updated_at=datetime(2026, 1, 2))
        case_critical = self._case(4, name="Critical", updated_at=datetime(2026, 1, 1))
        severity_counts = {3: {"low": 1}, 4: {"critical": 1}}
        rows = build_case_list_rows([case_none_older, case_none_newer, case_low, case_critical], severity_counts, {}, {}, "severity")
        # critical first, then low, then the two no-derived-severity cases — newer updated_at first among ties.
        assert [r["case"].id for r in rows] == [4, 3, 2, 1]


# ── Pivot suggestions ─────────────────────────────────────────────────────────────


def _sf(job_id, distance, filename="f.evtx", log_file_id=1):
    return SimilarFile(log_file_id=log_file_id, original_filename=filename, tlsh_hash="X" * 70, distance=distance, job_id=job_id, job_status="completed")


class TestBuildSimilarPivotRows:
    def test_drops_candidate_with_no_job(self):
        candidates = [(1, _sf(None, 10))]
        assert build_similar_pivot_rows(candidates, set()) == []

    def test_drops_candidate_whose_job_is_already_a_member(self):
        candidates = [(1, _sf(2, 10))]
        assert build_similar_pivot_rows(candidates, {2}) == []

    def test_dedupes_keeping_lowest_distance_and_its_source(self):
        candidates = [(1, _sf(5, 40, filename="dup.evtx")), (2, _sf(5, 10, filename="dup.evtx"))]
        rows = build_similar_pivot_rows(candidates, set())
        assert len(rows) == 1
        assert rows[0] == {"filename": "dup.evtx", "distance": 10, "source_job_id": 2, "target_job_id": 5}

    def test_sorts_by_distance_ascending_and_caps(self):
        candidates = [(1, _sf(jid, dist, filename=f"f{jid}.evtx")) for jid, dist in [(10, 50), (11, 5), (12, 30)]]
        rows = build_similar_pivot_rows(candidates, set(), cap=2)
        assert [r["target_job_id"] for r in rows] == [11, 12]


class TestCorrelatedPivotRows:
    def test_merge_same_signature_counts_once_not_per_row(self):
        """Duplicate rule_signature hits on the same job (e.g. duplicate Finding rows)
        must not inflate the "N rules" count — count tracks distinct signatures."""
        rows_by_job: dict[int, dict] = {}
        merge_correlated_hit(rows_by_job, 1, "a.evtx", "low", "rule-a:low")
        merge_correlated_hit(rows_by_job, 1, "a.evtx", "critical", "rule-a:low")
        merge_correlated_hit(rows_by_job, 1, "a.evtx", "medium", "rule-a:low")
        assert rows_by_job[1]["count"] == 1
        assert rows_by_job[1]["worst_severity"] == "critical"

    def test_merge_distinct_signatures_count_separately(self):
        rows_by_job: dict[int, dict] = {}
        merge_correlated_hit(rows_by_job, 1, "a.evtx", "low", "rule-a:low")
        merge_correlated_hit(rows_by_job, 1, "a.evtx", "high", "rule-b:high")
        assert rows_by_job[1]["count"] == 2
        assert rows_by_job[1]["worst_severity"] == "high"

    def test_rank_orders_worst_severity_first_then_count_desc(self):
        rows_by_job = {
            1: {"job_id": 1, "filename": "low.evtx", "count": 5, "worst_severity": "low"},
            2: {"job_id": 2, "filename": "crit_a.evtx", "count": 1, "worst_severity": "critical"},
            3: {"job_id": 3, "filename": "crit_b.evtx", "count": 9, "worst_severity": "critical"},
        }
        ranked = rank_correlated_pivot_rows(rows_by_job)
        assert [r["job_id"] for r in ranked] == [3, 2, 1]

    def test_rank_caps_results(self):
        rows_by_job = {i: {"job_id": i, "filename": f"{i}.evtx", "count": 1, "worst_severity": "low"} for i in range(15)}
        ranked = rank_correlated_pivot_rows(rows_by_job, cap=10)
        assert len(ranked) == 10
