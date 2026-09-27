"""Tests for tool adapter normalize() methods and shared _normalize_severity."""

from __future__ import annotations

import pytest

from app.tools.base import ToolAdapter
from app.tools.chainsaw import ChainsawAdapter
from app.tools.hayabusa import HayabusaAdapter
from app.tools.zircolite import ZircoliteAdapter

# ── _normalize_severity (shared) ─────────────────────────────────────────────


class TestNormalizeSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("informational", "informational"),
        ],
    )
    def test_canonical_values(self, raw, expected):
        assert ToolAdapter._normalize_severity(raw) == expected

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("med", "medium"),
            ("info", "informational"),
            ("notice", "informational"),
        ],
    )
    def test_aliases(self, raw, expected):
        assert ToolAdapter._normalize_severity(raw) == expected

    def test_case_insensitive(self):
        assert ToolAdapter._normalize_severity("HIGH") == "high"
        assert ToolAdapter._normalize_severity("Critical") == "critical"

    def test_unknown_defaults_to_informational(self):
        assert ToolAdapter._normalize_severity("banana") == "informational"
        assert ToolAdapter._normalize_severity("") == "informational"


# ── Zircolite normalize ─────────────────────────────────────────────────────


def _zirc(config=None):
    return ZircoliteAdapter(config or {"tool_path": "/fake", "rules_path": "/fake"})


class TestZircoliteNormalize:
    def test_empty_input(self):
        assert _zirc().normalize([]) == []

    def test_non_list_input(self):
        assert _zirc().normalize(None) == []
        assert _zirc().normalize({}) == []

    def test_single_finding(self):
        raw = [
            {
                "title": "Suspicious Process",
                "id": "abc-123",
                "rule_level": "high",
                "count": 3,
                "tags": ["attack.execution"],
                "matches": [{"EventID": 1}],
                "sigma": ["rule: content"],
            }
        ]
        findings = _zirc().normalize(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_name == "Suspicious Process"
        assert f.severity == "high"
        assert f.count == 3
        assert f.rule_id == "abc-123"
        assert f.tags == ["attack.execution"]
        assert f.details == [{"EventID": 1}]
        assert f.rule_content == "rule: content"

    def test_severity_mapping(self):
        raw = [{"title": "T", "rule_level": "med", "matches": []}]
        assert _zirc().normalize(raw)[0].severity == "medium"

    def test_details_truncation(self):
        adapter = ZircoliteAdapter({"tool_path": "/f", "rules_path": "/f", "max_finding_details": 2})
        matches = [{"e": i} for i in range(5)]
        raw = [{"title": "T", "rule_level": "low", "matches": matches, "count": 5}]
        f = adapter.normalize(raw)[0]
        assert len(f.details) == 2

    def test_sigma_as_list(self):
        raw = [{"title": "T", "rule_level": "low", "matches": [], "sigma": ["r1", "r2"]}]
        f = _zirc().normalize(raw)[0]
        assert "---" in f.rule_content

    def test_sigma_as_string(self):
        raw = [{"title": "T", "rule_level": "low", "matches": [], "sigma": "single rule"}]
        f = _zirc().normalize(raw)[0]
        assert f.rule_content == "single rule"

    def test_missing_fields_default(self):
        raw = [{}]
        f = _zirc().normalize(raw)[0]
        assert f.rule_name == "Unknown Rule"
        assert f.severity == "informational"


# ── Chainsaw normalize ───────────────────────────────────────────────────────


def _chain(config=None):
    return ChainsawAdapter(config or {"tool_path": "/fake", "rules_path": "/fake"})


class TestChainsawNormalize:
    def test_empty_input(self):
        assert _chain().normalize([]) == []

    def test_non_list_input(self):
        assert _chain().normalize(None) == []

    def test_grouping_by_rule_name(self):
        raw = [
            {"name": "Rule A", "level": "high", "id": "r1", "tags": [], "document": {"data": {"k": 1}}},
            {"name": "Rule A", "level": "high", "id": "r1", "tags": [], "document": {"data": {"k": 2}}},
            {"name": "Rule B", "level": "low", "id": "r2", "tags": [], "document": {"data": {"k": 3}}},
        ]
        findings = _chain().normalize(raw)
        assert len(findings) == 2
        a = next(f for f in findings if f.rule_name == "Rule A")
        assert a.count == 2
        assert len(a.details) == 2

    def test_details_limit(self):
        adapter = ChainsawAdapter({"tool_path": "/f", "rules_path": "/f", "max_finding_details": 1})
        raw = [{"name": "R", "level": "low", "document": {"data": {"k": i}}} for i in range(5)]
        f = adapter.normalize(raw)[0]
        assert f.count == 5
        assert len(f.details) == 1

    def test_document_data_extraction(self):
        raw = [{"name": "R", "level": "low", "document": {"data": {"EventID": 1}}}]
        f = _chain().normalize(raw)[0]
        assert f.details[0] == {"EventID": 1}


# ── Hayabusa normalize ──────────────────────────────────────────────────────


def _haya(config=None):
    return HayabusaAdapter(config or {"tool_path": "/fake", "rules_path": "/fake"})


class TestHayabusaNormalize:
    def test_empty_input(self):
        assert _haya().normalize([]) == []

    def test_non_list_input(self):
        assert _haya().normalize("not a list") == []

    def test_grouping_by_rule_title(self):
        raw = [
            {"RuleTitle": "Alert A", "Level": "high", "RuleID": "r1", "MitreTags": "T1059"},
            {"RuleTitle": "Alert A", "Level": "high", "RuleID": "r1", "MitreTags": "T1059"},
        ]
        findings = _haya().normalize(raw)
        assert len(findings) == 1
        assert findings[0].count == 2

    def test_mitre_tags_as_list(self):
        raw = [{"RuleTitle": "A", "Level": "low", "MitreTags": ["T1059", "T1053"]}]
        f = _haya().normalize(raw)[0]
        assert set(f.tags) == {"T1059", "T1053"}

    def test_mitre_tags_as_csv(self):
        raw = [{"RuleTitle": "A", "Level": "low", "MitreTags": "T1059, T1053"}]
        f = _haya().normalize(raw)[0]
        assert set(f.tags) == {"T1059", "T1053"}

    def test_mitre_tags_empty(self):
        raw = [{"RuleTitle": "A", "Level": "low", "MitreTags": ""}]
        f = _haya().normalize(raw)[0]
        assert f.tags == []

    def test_detail_structure(self):
        raw = [
            {
                "RuleTitle": "A",
                "Level": "low",
                "Timestamp": "2024-01-01T00:00:00",
                "Computer": "DC01",
                "EventID": 1,
                "Details": {"key": "val"},
            }
        ]
        f = _haya().normalize(raw)[0]
        d = f.details[0]
        assert d["Timestamp"] == "2024-01-01T00:00:00"
        assert d["Computer"] == "DC01"
        assert d["EventID"] == 1
        assert d["Details"] == {"key": "val"}
