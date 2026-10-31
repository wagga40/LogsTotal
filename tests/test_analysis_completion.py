"""An engine finishing is distinct from every record being analysed."""

from __future__ import annotations

import pytest

from app.tools.chainsaw import ChainsawAdapter
from app.tools.hayabusa import HayabusaAdapter
from app.tools.zircolite import ZircoliteAdapter


@pytest.mark.parametrize("adapter_cls", [ChainsawAdapter, HayabusaAdapter, ZircoliteAdapter])
def test_missing_output_is_not_a_zero_detection_run(tmp_path, monkeypatch, adapter_cls):
    adapter = adapter_cls({"rules_path": str(tmp_path), "tool_path": "/unused"})
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (0, "", ""))
    result = adapter._execute_and_parse(["unused"], tmp_path / "missing.json")
    assert not result.success
    assert "output" in result.error.lower()


def test_truncated_output_retains_findings_as_partial(tmp_path, monkeypatch):
    adapter = HayabusaAdapter({"rules_path": str(tmp_path), "tool_path": "/unused"})
    output = tmp_path / "result.jsonl"
    output.write_text('{"RuleTitle":"Alert","RuleID":"r1","Level":"high"}\n{"RuleTitle":')
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (0, "", ""))
    result = adapter._execute_and_parse(["unused"], output)
    assert result.success
    assert [(f.rule_id, f.count) for f in result.findings] == [("r1", 1)]
    assert result.diagnostics.completion == "incomplete"
    assert result.diagnostics.records_skipped == 1


@pytest.mark.parametrize("payload", ["not json", "null\n42\n"])
def test_wholly_unusable_output_fails(tmp_path, monkeypatch, payload):
    adapter = HayabusaAdapter({"rules_path": str(tmp_path), "tool_path": "/unused"})
    output = tmp_path / "result.jsonl"
    output.write_text(payload)
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (0, "", ""))
    assert not adapter._execute_and_parse(["unused"], output).success


def test_empty_output_does_not_invent_processed_counts(tmp_path, monkeypatch):
    adapter = ZircoliteAdapter({"rules_path": str(tmp_path), "tool_path": "/unused"})
    output = tmp_path / "result.json"
    output.write_text("[]")
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (0, "", ""))
    result = adapter._execute_and_parse(["unused"], output)
    assert result.success
    assert result.diagnostics.completion == "unknown"
    assert result.diagnostics.processed_events is None


# End-of-run lines exactly as the pinned engines print them (ANSI and Rich borders included).
_FINISHED = {
    ChainsawAdapter: "[+] Loading detection rules from: rules/\n\x1b[38;5;11m[!] Loaded 3630 detection rules (296 not loaded)\x1b[0m\n[+] 0 Detections found on 0 documents\n",
    HayabusaAdapter: "Total detection rules: 4674\nEvents with hits / Total events: 0 / 1 (Data reduction: 1 events (100.00%))\n",
    ZircoliteAdapter: "[+] 4527 rules loaded\n[+] Total events processed: 1 (0 filtered out by log source)\n│    🎯 Detections       None                                     │\n",
}


@pytest.mark.parametrize("adapter_cls", list(_FINISHED))
def test_an_engine_that_prints_its_summary_is_complete(tmp_path, monkeypatch, adapter_cls):
    adapter = adapter_cls({"rules_path": str(tmp_path)})
    output = tmp_path / "result.json"
    output.write_text("[]" if adapter_cls is ZircoliteAdapter else "")
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (0, _FINISHED[adapter_cls], ""))
    result = adapter._execute_and_parse(["unused"], output)
    assert result.success
    assert result.diagnostics.completion == "complete"
    assert result.diagnostics.warnings == []


def test_chainsaw_unloadable_rules_are_counted_not_a_gap(tmp_path, monkeypatch):
    """The shipped Sigma set always has rules Chainsaw cannot load; every Windows job was PARTIAL."""
    adapter = ChainsawAdapter({"rules_path": str(tmp_path)})
    output = tmp_path / "result.json"
    output.write_text("")
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (0, _FINISHED[ChainsawAdapter], ""))
    result = adapter._execute_and_parse(["unused"], output)
    assert result.diagnostics.completion == "complete"
    assert result.diagnostics.rules_loaded == 3630
    assert result.diagnostics.rules_skipped == 296


@pytest.mark.parametrize("adapter_cls", [ChainsawAdapter, HayabusaAdapter])
def test_an_incomplete_run_that_found_nothing_fails(tmp_path, monkeypatch, adapter_cls):
    adapter = adapter_cls({"rules_path": str(tmp_path)})
    output = tmp_path / "result.json"
    output.write_text("")
    summary = "Loaded 0 detection rules" if adapter_cls is ChainsawAdapter else "Total detection rules: 0"
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (0, summary, ""))
    result = adapter._execute_and_parse(["unused"], output)
    assert not result.success
    assert result.error.startswith("Incomplete analysis")
    assert "no detection rules" in result.error


def test_failed_process_preserves_usable_evidence(tmp_path, monkeypatch):
    adapter = HayabusaAdapter({"rules_path": str(tmp_path)})
    output = tmp_path / "result.jsonl"
    output.write_text('{"RuleTitle":"Alert","RuleID":"r1","Level":"high"}\n')
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (1, "", "engine failed"))
    result = adapter._execute_and_parse(["unused"], output)
    assert result.success
    assert result.diagnostics.completion == "incomplete"
    assert result.findings[0].rule_id == "r1"


def test_invalid_rule_block_does_not_hide_later_analytics_events(tmp_path):
    import json

    adapter = ZircoliteAdapter({"rules_path": str(tmp_path)})
    output = tmp_path / "results_zircolite.json"
    output.write_text(
        json.dumps(
            [
                {"title": "Before", "matches": [{"Computer": "first"}]},
                {"title": "Corrupt", "matches": None},
                {"title": "After", "matches": [{"Computer": "last"}]},
            ]
        )
    )
    result = adapter._parse_output(output, "", "", 0)
    assert result.success
    assert result.diagnostics.completion == "incomplete"
    assert result.diagnostics.records_skipped == 1
    assert [f.rule_name for f in result.findings] == ["Before", "After"]
    assert [m.rule_name for m in adapter.iter_raw_matches(output)] == ["Before", "After"]
