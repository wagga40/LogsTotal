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


def test_rule_load_gaps_are_visible_even_with_valid_empty_output(tmp_path, monkeypatch):
    adapter = ChainsawAdapter({"rules_path": str(tmp_path)})
    output = tmp_path / "result.json"
    output.write_text("")
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (0, "", "[!] Loaded 10 detection rules (2 not loaded)"))
    result = adapter._execute_and_parse(["unused"], output)
    assert result.success
    assert result.diagnostics.completion == "incomplete"
    assert result.diagnostics.rules_loaded == 10
    assert result.diagnostics.rules_skipped == 2


def test_failed_process_preserves_usable_evidence(tmp_path, monkeypatch):
    adapter = HayabusaAdapter({"rules_path": str(tmp_path)})
    output = tmp_path / "result.jsonl"
    output.write_text('{"RuleTitle":"Alert","RuleID":"r1","Level":"high"}\n')
    monkeypatch.setattr(adapter, "_exec", lambda *a, **kw: (1, "", "engine failed"))
    result = adapter._execute_and_parse(["unused"], output)
    assert result.success
    assert result.diagnostics.completion == "incomplete"
    assert result.findings[0].rule_id == "r1"
