"""Execution records describe the worker's assets, never today's installation."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from app.tools.hayabusa import HayabusaAdapter


@pytest.mark.parametrize(
    "output,expected",
    [
        ("-= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-\n                              v4.2.0\n", "4.2.0"),
        ("\x1b[36m-= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-\x1b[0m\n\x1b[32m v4.7.0\x1b[0m\n", "4.7.0"),
        ("Rule title: Zircolite v9.9.9\n v8.8.8\n", None),
        ("-= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-\nv4.7.0 unexpected text\n", None),
        ("", None),
    ],
)
def test_zircolite_records_version_reported_by_the_engine(tmp_path, output, expected):
    from app.tools.base import ToolOutput
    from app.tools.zircolite import ZircoliteAdapter

    adapter = ZircoliteAdapter({"docker_image": "custom/zircolite:latest", "rules_path": str(tmp_path / "missing")})
    result = adapter._run_recorded(lambda: ToolOutput(success=True, stdout=output))

    assert result.execution_snapshot["engine_version"] == expected


@pytest.mark.parametrize("stored_version", [None, "4.1.0"])
def test_historical_version_uses_only_the_runs_saved_banner(stored_version):
    from app.analysis_confidence import task_metadata
    from app.models import TaskResult, TaskStatus

    snapshot = json.dumps({"schema_version": 1, "engine_version": stored_version, "execution_mode": "docker"})
    task = TaskResult(
        tool_name="zircolite",
        status=TaskStatus.COMPLETED,
        execution_snapshot=snapshot,
        log_output="=== stdout ===\n-= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-\n v4.2.0\nPRIVATE_LOG_DATA",
    )

    metadata = task_metadata(task)

    assert metadata["provenance"]["engine_version"] == (stored_version or "4.2.0")
    assert task.execution_snapshot == snapshot
    assert "PRIVATE_LOG_DATA" not in json.dumps(metadata)


@pytest.mark.parametrize("custom_image", [False, True])
def test_docker_engine_version_is_independent_of_rules_release(tmp_path, monkeypatch, custom_image):
    import app.analysis_confidence as provenance
    from app.tools.catalog import TOOLS
    from app.tools.digests import tree_digest
    from app.tools.zircolite import ZircoliteAdapter

    tool_dir = tmp_path / "tools" / "zircolite"
    rules = tool_dir / "rules"
    rules.mkdir(parents=True)
    (rules / "rules.json").write_text("[]")
    (tool_dir / "upstream.json").write_text(
        json.dumps(
            {
                "version": "v4.7.0",
                "binaries": {},
                "rules": {"repo": "wagga40/Zircolite", "commit": "new-rules-revision", "trees": {"rules": tree_digest(rules)}},
            }
        )
    )
    image = "wagga40/zircolite:4.6.0@sha256:" + "a" * 64
    monkeypatch.setitem(TOOLS, "zircolite", replace(TOOLS["zircolite"], docker_image=image))
    monkeypatch.setattr(provenance, "_ROOT", tmp_path)
    adapter = ZircoliteAdapter({"docker_image": "custom/zircolite:latest" if custom_image else image, "rules_path": str(rules / "rules.json")})

    snapshot = provenance.capture_tool_snapshot(adapter)

    assert snapshot["engine_version"] == (None if custom_image else "4.6.0")
    assert snapshot["rules_revision"] == "new-rules-revision"


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


def test_chainsaw_default_native_rules_are_fingerprinted(tmp_path, monkeypatch):
    from app.analysis_confidence import capture_tool_snapshot
    from app.tools.chainsaw import ChainsawAdapter

    rules = tmp_path / "native"
    rules.mkdir()
    rule = rules / "rule.yml"
    rule.write_text("before")
    sigma = tmp_path / "sigma"
    sigma.mkdir()
    monkeypatch.setattr(ChainsawAdapter, "_DEFAULT_CHAINSAW_RULES", str(rules))
    a = ChainsawAdapter({"rules_path": str(sigma)})
    before = capture_tool_snapshot(a)
    rule.write_text("after")
    assert capture_tool_snapshot(a)["rules_sha256"] != before["rules_sha256"]


def test_custom_chopchopgo_default_mapping_is_fingerprinted(tmp_path):
    from app.analysis_confidence import capture_tool_snapshot
    from app.tools.chopchopgo import ChopChopGoAdapter

    binary = tmp_path / "chopchopgo"
    binary.write_text("executable")
    mapping = tmp_path / "mappings" / "syslog.yml"
    mapping.parent.mkdir()
    mapping.write_text("before")
    a = ChopChopGoAdapter({"tool_path": str(binary), "rules_path": str(tmp_path / "rules")})
    before = capture_tool_snapshot(a)
    mapping.write_text("after")
    assert capture_tool_snapshot(a)["mapping_sha256"] != before["mapping_sha256"]
