"""
Parse workflow YAML and filter workflows by log-type compatibility.
Used by Huey workers (sync context) and the upload router.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TypeVar

import yaml

from app.json_utils import loads as json_loads
from app.yaml_utils import safe_load as yaml_safe_load

_log = logging.getLogger(__name__)

T = TypeVar("T")


def _normalize_task_timeout(cfg: dict[str, Any]) -> None:
    """Normalize task timeout to int in [1, 86400]; invalid values become 300. Mutates cfg."""
    val = cfg.get("timeout", 300)
    try:
        sec = int(val) if val is not None else 300
    except (TypeError, ValueError):
        sec = 300
    cfg["timeout"] = max(1, min(86400, sec))


def _validate_string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ValueError(f"Workflow field '{field_name}' must be a list of strings.")
    return value


def _validate_tool_path(value: Any) -> str | dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        return value
    raise ValueError("Workflow field 'tool_path' must be a string or {arch: path} object.")


def _validate_task_config(task: dict[str, Any]) -> None:
    _validate_tool_path(task.get("tool_path"))
    task["extra_args"] = _validate_string_list(task.get("extra_args"), "extra_args")
    task["docker_options"] = _validate_string_list(task.get("docker_options"), "docker_options")


def parse_workflow_yaml(tasks_yaml: str) -> list[dict[str, Any]]:
    """
    Parse the tasks section of a workflow YAML.

    Expected YAML structure::

        tasks:
          - tool: zircolite
            docker_image: wagga40/zircolite:3.8.1@sha256:41b0683343c591069b94b17ed6c16a3edced15f905c7dce73a41cfa715e0f39b   # or dockerfile: path/to/Dockerfile
            rules_path: sigma_rules/windows
            timeout: 300
          - tool: chainsaw
            tool_path: tools/chainsaw/chainsaw-mac   # string or arch-keyed dict
            rules_path:                              # string or list of directories
              - tools/chainsaw/sigma/rules
              - tools/chainsaw/sigma/rules-emerging-threats
            threads: 2                               # optional CPU thread limit
            extra_args: ["--full"]                    # optional raw CLI flags
            timeout: 300

    ``tool_path`` may be a plain string *or* a dict mapping
    ``{machine}-{system}`` keys to binary paths (resolved at runtime).

    ``rules_path`` may be a plain string *or* a list of paths.  Chainsaw emits one
    ``--sigma`` per entry; the Docker runner binds a single path and rejects a list
    rather than running against only the first.
    """
    data = yaml_safe_load(tasks_yaml) or {}
    tasks = data.get("tasks", [])
    if not isinstance(tasks, list):
        raise ValueError("Workflow 'tasks' must be a list.")
    for task in tasks:
        if not isinstance(task, dict):
            raise ValueError("Each workflow task must be an object.")
        _normalize_task_timeout(task)
        _validate_task_config(task)
    return tasks


def get_compatible_workflows(
    workflows: Sequence[T],
    detected_type: str,
) -> list[T]:
    """Filter workflows to those compatible with *detected_type*.

    A workflow is compatible when its ``log_types`` JSON list is empty
    (meaning "all types") or explicitly contains the detected type value.

    Works with any object that has a ``log_types`` attribute storing a
    JSON-encoded list of type strings (e.g. ``WorkflowDef``).
    """
    compatible: list[T] = []
    for wf in workflows:
        raw = getattr(wf, "log_types", "[]") or "[]"
        wf_types: list[str] = json_loads(raw) if isinstance(raw, str) else raw
        if not wf_types or detected_type in wf_types:
            compatible.append(wf)
    return compatible


async def sync_workflows_from_dir(session, workflows_dir: Path) -> tuple[int, int, list[str]]:
    """Upsert every ``workflows/*.yml`` into ``WorkflowDef``, keyed by name.

    Returns ``(added, updated, errors)``. Shared by `init_db.py` (bootstrap) and
    `sync_workflows.py` (`./logstotal sync-workflows`), so a malformed workflow behaves the same
    whichever command runs.

    A file that fails to parse is reported and skipped; the rest still load. The caller
    owns the commit.
    """
    import json

    from sqlalchemy import select, update

    from app.models import WorkflowDef

    added = updated = 0
    errors: list[str] = []
    default_names: list[str] = []

    for yaml_file in sorted(workflows_dir.glob("*.yml")):
        try:
            data = yaml_safe_load(yaml_file.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                raise ValueError("workflow file is not a YAML mapping")
        except Exception as exc:
            errors.append(f"{yaml_file.name}: {exc}")
            continue

        name = data.get("name", yaml_file.stem)
        tasks_yaml = yaml.dump({"tasks": data.get("tasks", [])}, default_flow_style=False)
        fields = {
            "description": data.get("description", ""),
            "log_types": json.dumps(data.get("log_types", [])),
            "tasks_yaml": tasks_yaml,
            "is_default": bool(data.get("is_default", False)),
        }

        existing = await session.scalar(select(WorkflowDef).where(WorkflowDef.name == name))
        if existing:
            for key, value in fields.items():
                setattr(existing, key, value)
            updated += 1
        else:
            session.add(WorkflowDef(name=name, **fields))
            added += 1
        if fields["is_default"]:
            default_names.append(name)

    # `is_default` is single-valued. The admin CRUD path enforces it
    # (`routers/workflows.py::_demote_other_defaults`); here, two shipped YAMLs both claiming
    # it — or one claiming it while an admin-created workflow holds it — would leave two rows
    # set, and the upload form pre-selects with `find(wf => wf.is_default)` over a
    # name-ordered list, so the winner would be decided alphabetically and silently.
    #
    # Not an entry in `errors`: that list makes `task sync-workflows` exit 1, and a second
    # default is a resolvable ambiguity rather than a file that failed to load. The
    # directory wins over whatever the table held, and the first name in sorted-filename
    # order wins within the directory — deterministic, and logged so it is not a surprise.
    if default_names:
        keeper = default_names[0]
        if len(default_names) > 1:
            _log.warning("workflows: %d files claim is_default (%s); keeping %r", len(default_names), ", ".join(default_names), keeper)
        await session.flush()
        await session.execute(update(WorkflowDef).where(WorkflowDef.is_default.is_(True), WorkflowDef.name != keeper).values(is_default=False))

    return added, updated, errors
