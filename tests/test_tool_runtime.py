"""Runtime profiles must preserve every shipped command and legacy task behavior."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from app.detection.workflow_runner import parse_workflow_yaml
from app.tools.registry import get_adapter_class

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/tool_runtime/shipped_legacy.json"


def command_snapshot(task, log_types):
    """Build real CLI args without executing platform-specific binaries."""
    snapshot = {}
    adapter_class = get_adapter_class(task["tool"])
    for log_type in log_types:
        adapter = adapter_class(copy.deepcopy(task))
        adapter._log_type = log_type
        if log_type not in adapter.SUPPORTED_TYPES:
            result = adapter.run(Path("/case/input.log"), Path("/out"), log_type=log_type)
            snapshot[log_type] = {"error": result.error}
            continue
        if task.get("docker_image"):
            rules = "/rules/" + Path(task["rules_path"]).name
            snapshot[log_type] = {"docker_args": adapter._docker_tool_args("/case/input.log", rules, "/out/result.json")}
        else:
            commands = {}
            for arch, binary in task["tool_path"].items():
                # Binary validation is external to command construction and rejects
                # binaries for architectures other than this test host.
                adapter._check_binary_executable = lambda _path: None
                cmd, error = adapter._build_local_cmd(Path(binary), Path("/case/input.log"), Path("/out/result.json"))
                assert not error, error
                commands[arch] = [part.replace(str(ROOT), "<ROOT>") for part in cmd]
            snapshot[log_type] = {"local_commands": commands}
    return snapshot


def test_shipped_tasks_and_commands_match_frozen_legacy_snapshot():
    frozen = json.loads(FIXTURE.read_text())
    actual = {}
    for workflow in sorted((ROOT / "workflows").glob("*.yml")):
        data = yaml.safe_load(workflow.read_text())
        tasks = parse_workflow_yaml(workflow.read_text())
        actual[workflow.name] = {"tasks": tasks, "commands": [command_snapshot(task, data["log_types"]) for task in tasks]}
    assert actual == frozen


def test_unprofiled_tasks_keep_all_legacy_values_and_are_not_mutated():
    from app.tools.runtime import resolve_task_config

    task = {"tool": "custom", "tool_path": {"arch": "/custom"}, "options": {"nested": [1]}, "extra_args": ["--flag"]}
    original = copy.deepcopy(task)
    resolved = resolve_task_config(task)
    assert resolved == original
    resolved["options"]["nested"].append(2)
    resolved["tool_path"]["arch"] = "/other"
    assert task == original


def test_profile_merges_options_replaces_lists_and_does_not_mutate():
    from app.tools.runtime import resolve_task_config

    task = {"tool": "zircolite", "profile": "journald", "options": {"min_level": "high"}, "extra_args": ["--flag"], "docker_options": ["--network=none"], "timeout": 123}
    original = copy.deepcopy(task)
    result = resolve_task_config(task)
    assert result["options"] == {"config": "zircolite_journald.yaml", "min_level": "high"}
    assert result["extra_args"] == ["--flag"]
    assert result["docker_options"] == ["--network=none"]
    assert result["timeout"] == 123
    assert result["docker_image"].startswith("wagga40/zircolite:4.7.0@sha256:")
    result["options"]["config"] = "other"
    assert task == original
    assert resolve_task_config({"tool": "zircolite", "profile": "journald"})["options"] == {"config": "zircolite_journald.yaml"}


@pytest.mark.parametrize("override", [{"tool_path": "/custom/script"}, {"dockerfile": "Dockerfile.custom"}, {"docker_image": "custom:1"}, {"tool_path": None}])
def test_explicit_runner_overrides_replace_profile_runner(override):
    from app.tools.runtime import resolve_task_config

    result = resolve_task_config({"tool": "zircolite", "profile": "windows", **override})
    assert {key: result[key] for key in ("tool_path", "docker_image", "dockerfile") if key in result} == override


def test_profile_override_does_not_keep_default_local_runner():
    from app.tools.runtime import resolve_task_config

    result = resolve_task_config({"tool": "hayabusa", "profile": "default", "docker_image": "custom:1", "rules_path": ["custom/rules"], "threads": 4})
    assert "tool_path" not in result
    assert result["rules_path"] == ["custom/rules"]
    assert result["threads"] == 4


@pytest.mark.parametrize(
    "task",
    [
        {"tool": "zircolite", "profile": "unknown"},
        {"tool": "unknown", "profile": "default"},
        {"tool": "chainsaw", "profile": 42},
        {"tool": "chainsaw", "profile": "default", "options": []},
    ],
)
def test_invalid_profile_configs_raise_actionable_error(task):
    from app.tools.runtime import resolve_task_config

    with pytest.raises(ValueError, match=r"profile|options"):
        resolve_task_config(task)


def test_parser_and_direct_registry_instantiation_resolve_same_profile():
    from app.tools.registry import get_adapter

    parsed = parse_workflow_yaml("tasks:\n  - tool: hayabusa\n    profile: default\n")[0]
    adapter = get_adapter("HAYABUSA", {"profile": "default"})
    assert adapter.rules_path == parsed["rules_path"] == "tools/hayabusa/rules/"
    assert adapter._threads == 1
    assert "threads" not in parsed
    assert adapter.config["tool_path"] == parsed["tool_path"]


def test_runtime_modules_import_without_application_dependencies():
    result = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            "from app.tools.runtime import resolve_task_config; assert resolve_task_config({'tool': 'chainsaw', 'profile': 'default'})['rules_path'][0] == 'tools/chainsaw/sigma/rules'",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_profile_images_and_custom_overrides_are_available_before_install(tmp_path):
    workflow_dir = tmp_path / "workflows"
    workflow_dir.mkdir()
    (workflow_dir / "profiles.yml").write_text("tasks:\n  - tool: zircolite\n    profile: windows\n  - tool: custom\n    docker_image: 'registry.example/tool:2' # custom runner\n")
    result = subprocess.run([sys.executable, "-S", str(ROOT / "scripts/tool_runtime_inventory.py"), "--images", str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == {
        "registry.example/tool:2",
        "wagga40/zircolite:4.7.0@sha256:6dba9ac590a699d6d622ad9a7ecd2c7b2e0874decff3bc310d452b33ad45a28f",
    }


def test_profiles_leave_resource_limits_to_workflows():
    from app.tools.runtime import resolve_task_config

    result = resolve_task_config({"tool": "hayabusa", "profile": "default"})
    assert "threads" not in result
    assert "timeout" not in result
    overridden = resolve_task_config({"tool": "hayabusa", "profile": "default", "threads": 4, "timeout": 120})
    assert overridden["threads"] == 4
    assert overridden["timeout"] == 120
