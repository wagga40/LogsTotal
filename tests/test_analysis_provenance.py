"""Execution records describe the worker's assets, never today's installation."""

from __future__ import annotations

import json

from app.tools.hayabusa import HayabusaAdapter


def test_worker_snapshot_fingerprints_custom_assets_without_exposing_paths(tmp_path):
    from app.analysis_confidence import capture_tool_snapshot

    binary = tmp_path / "private-engine"
    binary.write_bytes(b"engine version one")
    rules = tmp_path / "private-rules"
    rules.mkdir()
    rule = rules / "rule.yml"
    rule.write_text("id: r1\nlevel: high\n")
    adapter = HayabusaAdapter({"tool_path": str(binary), "rules_path": str(rules), "options": {"password": "private-password"}})
    old = capture_tool_snapshot(adapter)
    rule.write_text("id: r1\nlevel: critical\n")
    new = capture_tool_snapshot(adapter)
    assert old["rules_sha256"] != new["rules_sha256"]
    assert old["runtime_sha256"] == new["runtime_sha256"]
    assert old["engine_version"] is None
    assert str(tmp_path) not in json.dumps(old)
    assert "private-password" not in json.dumps(old)


def test_snapshot_detects_changed_executable_even_with_same_declared_version(tmp_path):
    from app.analysis_confidence import capture_tool_snapshot

    binary = tmp_path / "engine"
    binary.write_bytes(b"first")
    adapter = HayabusaAdapter({"tool_path": str(binary), "rules_path": str(tmp_path / "missing")})
    first = capture_tool_snapshot(adapter)
    binary.write_bytes(b"second")
    second = capture_tool_snapshot(adapter)
    assert first["runtime_sha256"] != second["runtime_sha256"]
    assert second["rules_sha256"] is None


def test_job_snapshot_is_a_value_and_records_effective_workflow():
    from app.analysis_confidence import capture_job_snapshot

    configs = [{"tool": "hayabusa", "rules_path": "/private/rules", "extra_args": ["--secret", "private-token"]}]
    snapshot = capture_job_snapshot("a" * 64, "evtx", "Windows", configs, "1.2.0")
    configs[0]["tool"] = "changed"
    assert snapshot["tools"] == ["hayabusa"]
    assert snapshot["input_sha256"] == "a" * 64
    assert snapshot["logstotal_version"] == "1.2.0"
    assert "private-token" not in json.dumps(snapshot)
    assert "/private/rules" not in json.dumps(snapshot)


def test_assets_changed_during_execution_make_result_incomplete(tmp_path):
    from app.tools.base import ToolOutput

    binary = tmp_path / "engine"
    binary.write_bytes(b"first")
    adapter = HayabusaAdapter({"tool_path": str(binary), "rules_path": str(tmp_path / "missing")})

    def execute():
        binary.write_bytes(b"second")
        return ToolOutput(success=True)

    result = adapter._run_recorded(execute)
    assert result.diagnostics.completion == "incomplete"
    assert result.execution_snapshot["runtime_sha256"]
