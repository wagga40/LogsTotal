"""Immutable execution fingerprints and public, stored analysis metadata."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.tools.catalog import TOOLS
from app.tools.diagnostics import reported_engine_version
from app.tools.digests import file_digest, stat_fingerprint, tree_digest

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


# {resolved path: (stat fingerprint, digest)}, per process. Every run captures a
# snapshot before and after; re-reading ~5,000 rule files each time cost seconds per job.
_DIGESTS: dict[str, tuple[tuple, str]] = {}


def _asset_digest(path: Path) -> str | None:
    key = str(path.resolve())
    stamp = stat_fingerprint(path)
    if stamp is None:
        return None
    cached = _DIGESTS.get(key)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    try:
        digest = tree_digest(path) if path.is_dir() else file_digest(path)
    except OSError:
        return None
    _DIGESTS[key] = (stamp, digest)
    return digest


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
    if verified_binary:
        version = manifest.get("version")
    elif verified_image:
        # Rules can be refreshed independently of the digest-pinned engine image.
        image_tag = spec.docker_image.split("@", 1)[0].rsplit(":", 1)[-1]
        if re.fullmatch(r"v?\d+\.\d+\.\d+", image_tag):
            version = image_tag
    rule_paths = [Path(p) for p in adapter.rules_paths]
    if adapter.name == "chainsaw":
        rule_paths.append(Path(config.get("chainsaw_rules_path", adapter._DEFAULT_CHAINSAW_RULES)))
    rule_hashes = [_asset_digest(p) for p in rule_paths]
    # Include adapter-owned mapping/configuration defaults, not just workflow overrides.
    ancillary = []
    for key in ("mapping_path",):
        if config.get(key):
            ancillary.append(Path(config[key]))
    if adapter.name == "chopchopgo" and binary and not config.get("mapping_path"):
        if default_mapping := adapter._default_mapping(binary):
            ancillary.append(default_mapping)
    for name in ("mappings", "config"):
        if adapter.name != "chopchopgo" and (tool_dir / name).is_dir():
            ancillary.append(tool_dir / name)
    options = config.get("options") or {}
    if isinstance(options.get("config"), str):
        ancillary.append(Path(adapter.rules_path).parent / options["config"])
    verified_rules = bool(manifest.get("rules", {}).get("trees"))
    for name, expected in manifest.get("rules", {}).get("trees", {}).items():
        if _asset_digest(tool_dir / name) != expected:
            verified_rules = False
    bundled_paths = all(Path(p).resolve().is_relative_to(tool_dir.resolve()) for p in rule_paths)
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

    provenance = _public(task.execution_snapshot, _TOOL_FIELDS)
    if provenance and not provenance.get("engine_version"):
        # Recover only evidence saved with this run; never consult today's assets
        # or change the original snapshot when rendering a historical report.
        provenance["engine_version"] = reported_engine_version(task.tool_name, task.log_output or "")
    return {
        "task_id": task.id,
        "tool": task.tool_name,
        "status": enum_val(task.status),
        "provenance": provenance,
        "diagnostics": _public(task.diagnostics_json, _DIAGNOSTIC_FIELDS),
    }


def _public(value: str | None, fields: frozenset[str]) -> dict | None:
    return {key: value for key, value in read_snapshot(value).items() if key in fields} or None


def job_provenance(job) -> dict | None:
    return _public(job.execution_snapshot, _JOB_FIELDS)
