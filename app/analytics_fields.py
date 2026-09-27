"""
Load analytics field-name config from YAML for the entity extraction in app/analytics.py.
Config is cached after first load; path is taken from settings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import settings
from app.yaml_utils import safe_load as yaml_safe_load

_REQUIRED_KEYS = (
    "ip_keys",
    "hash_keys",
    "image_keys",
    "domain_keys",
    "cmdline_keys",
    "user_keys",
    "noise_users",
    "cmdline_exts",
)


@dataclass(frozen=True)
class AnalyticsFieldConfig:
    """Field names and lists used by ``_compute_analytics_data`` in ``app/analytics.py``."""

    ip_keys: frozenset[str]
    hash_keys: frozenset[str]
    image_keys: frozenset[str]
    domain_keys: frozenset[str]
    cmdline_keys: frozenset[str]
    user_keys: frozenset[str]
    service_keys: frozenset[str]
    task_keys: frozenset[str]
    hostname_keys: frozenset[str]
    noise_users: frozenset[str]
    cmdline_exts: frozenset[str]


def _to_set(raw: Any, lower: bool = False) -> frozenset[str]:
    if raw is None:
        return frozenset()
    if isinstance(raw, (list, tuple)):
        items = (str(x).lower() if lower else str(x) for x in raw)
        return frozenset(items)
    s = str(raw)
    return frozenset((s.lower(),) if lower else (s,))


def load_analytics_fields(path: Path | None = None) -> AnalyticsFieldConfig:
    """Load and parse analytics field config from YAML. Raises if file missing or invalid."""
    p = path or settings.analytics_fields_path
    if not p.is_absolute():
        # Resolve relative to cwd so default config/analytics_fields.yaml works
        p = Path.cwd() / p
    if not p.exists():
        raise FileNotFoundError(f"Analytics fields config not found: {p}")
    text = p.read_text(encoding="utf-8")
    data = yaml_safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Analytics fields YAML must be a mapping")
    missing = [k for k in _REQUIRED_KEYS if k not in data]
    if missing:
        raise ValueError(f"Analytics fields YAML missing required keys: {missing}")

    return AnalyticsFieldConfig(
        ip_keys=_to_set(data["ip_keys"]),
        hash_keys=_to_set(data["hash_keys"]),
        image_keys=_to_set(data["image_keys"]),
        domain_keys=_to_set(data["domain_keys"]),
        cmdline_keys=_to_set(data["cmdline_keys"]),
        user_keys=_to_set(data["user_keys"]),
        service_keys=_to_set(data.get("service_keys", [])),
        task_keys=_to_set(data.get("task_keys", [])),
        hostname_keys=_to_set(data.get("hostname_keys", [])),
        noise_users=_to_set(data["noise_users"], lower=True),
        cmdline_exts=_to_set(data["cmdline_exts"]),
    )


_cached: AnalyticsFieldConfig | None = None


def get_analytics_fields() -> AnalyticsFieldConfig:
    """Return cached analytics field config, loading from YAML on first call."""
    global _cached
    if _cached is None:
        _cached = load_analytics_fields()
    return _cached
