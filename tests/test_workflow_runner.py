"""Tests for app.detection.workflow_runner — YAML parsing and workflow filtering."""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from app.detection.workflow_runner import get_compatible_workflows, parse_workflow_yaml


def _rules_paths_of(task: dict) -> list[str]:
    """`rules_path` is a string or a list of strings — see `ToolAdapter.__init__`."""
    rules = task.get("rules_path")
    if not rules:
        return []
    return [rules] if isinstance(rules, str) else list(rules)


# ── parse_workflow_yaml ──────────────────────────────────────────────────────


class TestParseWorkflowYaml:
    def test_valid_yaml(self):
        yaml_str = """
tasks:
  - tool: zircolite
    rules_path: /rules
    timeout: 300
  - tool: chainsaw
    tool_path: /bin/chainsaw
"""
        tasks = parse_workflow_yaml(yaml_str)
        assert len(tasks) == 2
        assert tasks[0]["tool"] == "zircolite"
        assert tasks[1]["tool"] == "chainsaw"

    def test_empty_string(self):
        assert parse_workflow_yaml("") == []

    def test_missing_tasks_key(self):
        assert parse_workflow_yaml("other_key: value") == []

    def test_none_yaml(self):
        assert parse_workflow_yaml("null") == []

    def test_timeout_normalized_to_int(self):
        yaml_str = """
tasks:
  - tool: zircolite
    rules_path: /rules
    timeout: "600"
"""
        tasks = parse_workflow_yaml(yaml_str)
        assert len(tasks) == 1
        assert tasks[0]["timeout"] == 600

    def test_timeout_clamped_to_range(self):
        yaml_str = """
tasks:
  - tool: zircolite
    rules_path: /rules
    timeout: 0
  - tool: chainsaw
    tool_path: /bin/chainsaw
    timeout: 999999
"""
        tasks = parse_workflow_yaml(yaml_str)
        assert tasks[0]["timeout"] == 1
        assert tasks[1]["timeout"] == 86400

    def test_timeout_invalid_becomes_300(self):
        yaml_str = """
tasks:
  - tool: zircolite
    rules_path: /rules
    timeout: not_a_number
"""
        tasks = parse_workflow_yaml(yaml_str)
        assert tasks[0]["timeout"] == 300

    def test_invalid_extra_args_type_rejected(self):
        yaml_str = """
tasks:
  - tool: zircolite
    extra_args: "--bad"
"""
        with pytest.raises(ValueError, match="extra_args"):
            parse_workflow_yaml(yaml_str)

    def test_invalid_docker_options_type_rejected(self):
        yaml_str = """
tasks:
  - tool: zircolite
    docker_options:
      - /host:/container
      - 42
"""
        with pytest.raises(ValueError, match="docker_options"):
            parse_workflow_yaml(yaml_str)

    def test_invalid_tool_path_type_rejected(self):
        yaml_str = """
tasks:
  - tool: zircolite
    tool_path:
      x86_64-linux: /bin/tool
      bad: 123
"""
        with pytest.raises(ValueError, match="tool_path"):
            parse_workflow_yaml(yaml_str)


# ── get_compatible_workflows ─────────────────────────────────────────────────


@dataclass
class FakeWorkflow:
    name: str
    log_types: str  # JSON string


class TestGetCompatibleWorkflows:
    def test_match(self):
        wf = FakeWorkflow("w1", json.dumps(["evtx", "syslog"]))
        result = get_compatible_workflows([wf], "evtx")
        assert result == [wf]

    def test_no_match(self):
        wf = FakeWorkflow("w1", json.dumps(["evtx"]))
        result = get_compatible_workflows([wf], "syslog")
        assert result == []

    def test_empty_log_types_matches_everything(self):
        wf = FakeWorkflow("w1", json.dumps([]))
        result = get_compatible_workflows([wf], "anything")
        assert result == [wf]

    def test_null_log_types_matches_everything(self):
        wf = FakeWorkflow("w1", "null")
        result = get_compatible_workflows([wf], "anything")
        assert result == [wf]

    def test_none_attribute(self):
        """log_types=None should be treated as 'all types'."""
        wf = FakeWorkflow("w1", None)
        result = get_compatible_workflows([wf], "evtx")
        assert result == [wf]

    def test_multiple_workflows(self):
        w1 = FakeWorkflow("evtx-only", json.dumps(["evtx"]))
        w2 = FakeWorkflow("all", json.dumps([]))
        w3 = FakeWorkflow("syslog-only", json.dumps(["syslog"]))
        result = get_compatible_workflows([w1, w2, w3], "evtx")
        assert w1 in result
        assert w2 in result
        assert w3 not in result


# ── shipped workflow YAML files ──────────────────────────────────────────────


class TestShippedWorkflows:
    """Guards over workflows/*.yml: they must parse and reference valid values."""

    @staticmethod
    def _shipped():
        import pathlib

        import yaml

        root = pathlib.Path(__file__).resolve().parents[1]
        files = sorted((root / "workflows").glob("*.yml"))
        assert files, "no shipped workflow YAMLs found"
        return root, [(f, yaml.safe_load(f.read_text())) for f in files]

    def test_all_parse_and_declare_valid_log_types(self):
        from app.models import LogType

        valid = {t.value for t in LogType}
        _, shipped = self._shipped()
        for path, data in shipped:
            assert data.get("name"), f"{path.name}: missing name"
            parse_workflow_yaml(path.read_text())  # raises on invalid tasks
            for lt in data.get("log_types", []):
                assert lt in valid, f"{path.name}: unknown log_type {lt!r}"

    def test_all_tools_registered(self):
        from app.tools.registry import _REGISTRY

        _, shipped = self._shipped()
        for path, data in shipped:
            for task in data.get("tasks", []):
                assert task["tool"] in _REGISTRY, f"{path.name}: unregistered tool {task['tool']!r}"

    def test_rules_paths_exist(self):
        root, shipped = self._shipped()
        for path, data in shipped:
            for task in data.get("tasks", []):
                for rules in _rules_paths_of(task):
                    assert (root / rules).exists(), f"{path.name}: rules_path missing on disk: {rules}"

    def test_no_workflow_loads_a_non_rule_directory(self):
        """Rule paths must not resolve to trees SigmaHQ ships but does not want executed.

        Pointing `rules_path` at the SigmaHQ repo *root* — Chainsaw's `--sigma` loads
        recursively — sweeps in 167 `deprecated/` and 87 `unsupported/` rules, 17
        `rules-placeholder/` files with unexpanded `%placeholder%` values, and 170
        `regression_data/` files that carry no `detection:` block at all.

        Measured against the vendored binary and `samples/windows/bitsadmin.evtx`: the repo
        root loads **3,735 rules with 1,014 rejected**; the three curated directories load
        **3,505 with 378 rejected**. The 230-rule difference is withdrawn and unsupported
        rules that would be live and could fire, which on a detection platform is a
        correctness failure — a finding attributed to a rule SigmaHQ has retired.

        (The rejected files do *not* flood `TaskResult.log_output`: Chainsaw reports one
        summary line, and total tool output is ~1.5 KB either way, far under
        `MAX_LOG_OUTPUT_BYTES`. The case rests on the 230 rules.)

        Checked by containment rather than by name, because the failure is a *parent*
        directory silently including these, not anyone naming one.
        """
        root, shipped = self._shipped()
        forbidden = ("deprecated", "unsupported", "rules-placeholder", "regression_data")
        for path, data in shipped:
            for task in data.get("tasks", []):
                for rules in _rules_paths_of(task):
                    resolved = (root / rules).resolve()
                    if not resolved.is_dir():
                        continue
                    for name in forbidden:
                        offender = resolved / name
                        assert not offender.is_dir(), (
                            f"{path.name}: rules_path {rules!r} contains {name}/, so a recursive rule load "
                            f"picks it up. Name the curated rule directories individually — `rules_path` "
                            f"accepts a list."
                        )
