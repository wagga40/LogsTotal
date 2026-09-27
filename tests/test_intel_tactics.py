"""Tier-1 tests pinning MITRE tactic resolution in app.intel.tactics."""

from __future__ import annotations

import importlib
from types import SimpleNamespace


def _module():
    """Return whichever module currently owns the tactic helpers — jobs.py before refactor,
    intel/tactics.py after. Tests don't care which.
    """
    try:
        return importlib.import_module("app.intel.tactics")
    except ImportError:
        return importlib.import_module("app.routers.jobs")


class TestTacticsConstants:
    def test_mitre_tactics_list_canonical_order(self):
        mod = _module()
        assert mod._MITRE_TACTICS[0] == "reconnaissance"
        assert mod._MITRE_TACTICS[-1] == "impact"
        assert "execution" in mod._MITRE_TACTICS
        assert len(mod._MITRE_TACTICS) == 14

    def test_other_tactic_sentinel(self):
        mod = _module()
        assert mod._OTHER_TACTIC == "_other"

    def test_hayabusa_abbrev_mapping(self):
        mod = _module()
        assert mod._HAYABUSA_TACTIC_ABBREV["evas"] == "defense_evasion"
        assert mod._HAYABUSA_TACTIC_ABBREV["c2"] == "command_and_control"
        assert mod._HAYABUSA_TACTIC_ABBREV["recon"] == "reconnaissance"

    def test_color_map_covers_all_tactics(self):
        mod = _module()
        for t in mod._MITRE_TACTICS:
            assert t in mod._MITRE_TACTIC_COLORS

    def test_hex_to_rgb_format(self):
        mod = _module()
        assert mod._hex_to_rgb("#ff0040") == "255,0,64"
        assert mod._hex_to_rgb("ff0040") == "255,0,64"


class TestResolveTacticFromEvent:
    def _setup(self):
        return {
            "Some Rule": "execution",
            "Mimikatz": "credential_access",
        }, {
            "t1003": "credential_access",
            "t1059": "execution",
        }

    def test_rule_name_match_wins(self):
        mod = _module()
        rt, tt = self._setup()
        result = mod._resolve_tactic_from_event(
            {"MitreTactics": "Evas"},
            rt,
            tt,
            "Some Rule",
        )
        assert result == "execution"

    def test_hayabusa_mitretactics_abbrev_string(self):
        mod = _module()
        result = mod._resolve_tactic_from_event(
            {"MitreTactics": "Evas"},
            {},
            {},
            "Unknown Rule",
        )
        assert result == "defense_evasion"

    def test_hayabusa_mitretactics_list(self):
        mod = _module()
        result = mod._resolve_tactic_from_event(
            {"MitreTactics": ["c2", "exec"]},
            {},
            {},
            "Unknown Rule",
        )
        # First match wins
        assert result == "command_and_control"

    def test_technique_id_in_mitretags(self):
        mod = _module()
        rt, tt = self._setup()
        result = mod._resolve_tactic_from_event(
            {"MitreTags": "t1003"},
            rt,
            tt,
            "Unknown Rule",
        )
        assert result == "credential_access"

    def test_technique_id_in_othertags(self):
        mod = _module()
        rt, tt = self._setup()
        result = mod._resolve_tactic_from_event(
            {"OtherTags": ["t1059"]},
            rt,
            tt,
            "Unknown Rule",
        )
        assert result == "execution"

    def test_no_match_falls_to_other(self):
        mod = _module()
        result = mod._resolve_tactic_from_event(
            {"some_other": "value"},
            {},
            {},
            "Unknown Rule",
        )
        assert result == "_other"

    def test_rule_name_overrides_mitretactics_field(self):
        """Strategy ordering: rule_name takes priority over event's MitreTactics."""
        mod = _module()
        rt = {"Critical Rule": "impact"}
        result = mod._resolve_tactic_from_event(
            {"MitreTactics": "Recon"},
            rt,
            {},
            "Critical Rule",
        )
        assert result == "impact"


class TestBuildFindingsIndexNonListTagsGuard:
    """A corrupt Finding.tags value that decodes to something other than a JSON array
    (e.g. a bare number) must be skipped, not raise and 500 the job analytics /
    case-timeline paths that call `_build_findings_index`. Mirrors the guard added to
    `app.routers.cases._tactic_counts_from_tag_rows` for the same underlying hazard."""

    def _job(self, findings):
        tr = SimpleNamespace(findings=findings)
        return SimpleNamespace(task_results=[tr])

    def test_non_list_tags_json_is_skipped_not_raised(self):
        mod = _module()
        bad = SimpleNamespace(tags="42", rule_name="Corrupt Rule", count=5)  # decodes to int, not a list
        good = SimpleNamespace(tags='["attack.initial_access"]', rule_name="Good Rule", count=2)
        job = self._job([bad, good])

        rule_tactic, _technique_tactic, tactic_counts = mod._build_findings_index(job)

        assert "Corrupt Rule" not in rule_tactic
        assert rule_tactic["Good Rule"] == "initial_access"
        assert tactic_counts["initial_access"] == 2

    def test_dict_tags_json_is_skipped(self):
        mod = _module()
        bad = SimpleNamespace(tags='{"not": "a list"}', rule_name="Dict Rule", count=3)
        job = self._job([bad])

        rule_tactic, _technique_tactic, tactic_counts = mod._build_findings_index(job)

        assert "Dict Rule" not in rule_tactic
        assert all(c == 0 for c in tactic_counts.values())


class TestPrimaryTacticFromTags:
    """Extracted from `_build_findings_index` so the graph's per-node tactic and the job
    analytics' per-rule tactic cannot disagree about which tactic 'wins' a tag list."""

    def _mod(self):
        import app.intel.tactics as mod

        return mod

    def test_kill_chain_order_wins_not_tag_order(self):
        mod = self._mod()
        assert mod.primary_tactic_from_tags(["attack.impact", "attack.execution"]) == "execution"

    def test_prefix_dash_and_space_forms_all_normalise(self):
        mod = self._mod()
        for tag in ("attack.defense-evasion", "defense_evasion", "Defense Evasion", "ATTACK.DEFENSE_EVASION"):
            assert mod.primary_tactic_from_tags([tag]) == "defense_evasion", tag

    def test_techniques_and_junk_yield_none(self):
        mod = self._mod()
        assert mod.primary_tactic_from_tags(["attack.t1055", "cve-2021-1234"]) is None
        assert mod.primary_tactic_from_tags([]) is None
        assert mod.primary_tactic_from_tags(None) is None
        assert mod.primary_tactic_from_tags({"not": "a list"}) is None

    def test_a_csv_string_is_accepted(self):
        mod = self._mod()
        assert mod.primary_tactic_from_tags("attack.persistence,attack.discovery") == "persistence"

    def test_normalize_tactic_tag_rejects_techniques(self):
        mod = self._mod()
        assert mod.normalize_tactic_tag("attack.execution") == "execution"
        assert mod.normalize_tactic_tag("attack.t1059") is None

    def test_public_aliases_match_the_private_lists(self):
        mod = self._mod()
        assert tuple(mod._MITRE_TACTICS) == mod.MITRE_TACTICS
        assert mod.OTHER_TACTIC == mod._OTHER_TACTIC
        assert set(mod.TACTIC_COLORS) == set(mod._MITRE_TACTIC_COLORS) | {mod._OTHER_TACTIC}
