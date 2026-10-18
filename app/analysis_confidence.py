"""Immutable execution fingerprints and public, stored analysis metadata."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.tools.catalog import TOOLS

_ROOT = Path(__file__).resolve().parent.parent
_SECRET = re.compile(r"password|passwd|secret|token|credential|authorization|api[-_]?key", re.I)
_JOB_FIELDS = frozenset({"schema_version", "captured_at", "input_sha256", "log_type", "workflow", "workflow_sha256", "tools", "logstotal_version"})
_TOOL_FIELDS = frozenset(
    {
        "schema_version",
        "captured_at",
        "tool",
        "execution_mode",
        "engine_version",
        "runtime_sha256",
        "image_id",
        "rules_sha256",
        "rules_revision",
        "rules_repository",
        "mapping_sha256",
        "configuration_sha256",
    }
)
_DIAGNOSTIC_FIELDS = frozenset({"schema_version", "completion", "processed_events", "rules_loaded", "rules_skipped", "records_skipped", "warnings"})


def _configuration(value: Any) -> Any:
    """Credentials do not participate in a public configuration fingerprint."""
    if isinstance(value, dict):
        return {str(k): "[redacted]" if _SECRET.search(str(k)) else _configuration(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        result, redact_next = [], False
        for item in value:
            sensitive = isinstance(item, str) and bool(_SECRET.search(item))
            result.append("[redacted]" if redact_next or sensitive else _configuration(item))
            redact_next = sensitive and "=" not in item
        return result
    return value


def configuration_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(_configuration(value), sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tree_digest(path: Path) -> str:
    """Same filename/content framing as the vendored upstream manifests."""
    digest = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(str(file.relative_to(path)).encode())
        digest.update(b"\0")
        digest.update(file_digest(file).encode())
        digest.update(b"\n")
    return digest.hexdigest()


def _asset_digest(path: Path) -> str | None:
    try:
        return tree_digest(path) if path.is_dir() else file_digest(path)
    except OSError:
        return None


def read_snapshot(value: str | None) -> dict:
    try:
        data = json.loads(value or "null")
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) and data.get("schema_version") == 1 else {}


def capture_job_snapshot(input_sha256: str, log_type: str | None, workflow: str, tasks: list[dict], version: str) -> dict:
    return {
        "schema_version": 1,
        "captured_at": datetime.now(UTC).isoformat(),
        "input_sha256": input_sha256,
        "log_type": log_type,
        "workflow": workflow,
        "workflow_sha256": configuration_digest(tasks),
        "tools": [task.get("tool", "") for task in tasks],
        "logstotal_version": version,
    }


def capture_tool_snapshot(adapter) -> dict:
    config = adapter.config
    tool_dir = _ROOT / "tools" / adapter.name
    try:
        manifest = json.loads((tool_dir / "upstream.json").read_text())
    except (OSError, ValueError):
        manifest = {}
    binary = Path(config["tool_path"]) if isinstance(config.get("tool_path"), str) else None
    runtime_hash = _asset_digest(binary) if binary else None
    spec = TOOLS.get(adapter.name)
    version = None
    verified_binary = binary and binary.resolve().parent == tool_dir.resolve() and runtime_hash and manifest.get("binaries", {}).get(binary.name) == runtime_hash
    verified_image = not binary and spec and spec.docker_image and config.get("docker_image") == spec.docker_image
    if verified_binary or verified_image:
        version = manifest.get("version")
    rule_hashes = [_asset_digest(Path(p)) for p in adapter.rules_paths]
    # Include adapter-owned mapping/configuration defaults, not just workflow overrides.
    ancillary = []
    for key in ("mapping_path", "chainsaw_rules_path"):
        if config.get(key):
            ancillary.append(Path(config[key]))
    for name in ("mappings", "config"):
        if (tool_dir / name).is_dir():
            ancillary.append(tool_dir / name)
    options = config.get("options") or {}
    if isinstance(options.get("config"), str):
        ancillary.append(Path(adapter.rules_path).parent / options["config"])
    verified_rules = bool(manifest.get("rules", {}).get("trees"))
    for name, expected in manifest.get("rules", {}).get("trees", {}).items():
        if _asset_digest(tool_dir / name) != expected:
            verified_rules = False
    bundled_paths = all(Path(p).resolve().is_relative_to(tool_dir.resolve()) for p in adapter.rules_paths)
    rules = manifest.get("rules", {}) if verified_rules and bundled_paths else {}
    return {
        "schema_version": 1,
        "captured_at": datetime.now(UTC).isoformat(),
        "tool": adapter.name,
        "execution_mode": "local" if binary else "docker",
        "engine_version": version,
        "runtime_sha256": runtime_hash,
        "image_id": None,
        "rules_sha256": configuration_digest(rule_hashes) if rule_hashes and all(rule_hashes) else None,
        "rules_revision": rules.get("commit"),
        "rules_repository": rules.get("repo"),
        "mapping_sha256": configuration_digest([_asset_digest(p) for p in ancillary]) if ancillary else None,
        "configuration_sha256": configuration_digest(config),
    }


def task_metadata(task) -> dict:
    from app.models import enum_val

    return {
        "task_id": task.id,
        "tool": task.tool_name,
        "status": enum_val(task.status),
        "provenance": _public(task.execution_snapshot, _TOOL_FIELDS),
        "diagnostics": _public(task.diagnostics_json, _DIAGNOSTIC_FIELDS),
    }


def _public(value: str | None, fields: frozenset[str]) -> dict | None:
    return {key: value for key, value in read_snapshot(value).items() if key in fields} or None


def job_provenance(job) -> dict | None:
    return _public(job.execution_snapshot, _JOB_FIELDS)
