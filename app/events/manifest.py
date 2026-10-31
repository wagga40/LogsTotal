"""The store's manifest: what the builder writes last and every reader checks first. Stdlib only.

The worker validates it before publishing a store, so a crashed or partial build is never
served: the files must exist with the exact sizes the manifest records, and an unknown
format version is refused rather than guessed at.
"""

from __future__ import annotations

import json
from pathlib import Path

FORMAT = "logstotal-events"
FORMAT_VERSION = 1
#: Bumped whenever the builder's output changes meaning, so stores built before are rebuilt.
BUILDER_VERSION = 1
MANIFEST = "manifest.json"
REQUIRED_FILES = ("events.parquet", "order.parquet")
_TYPES = {"BIGINT", "DOUBLE", "VARCHAR"}
MAX_COLUMNS = 10_000


class ManifestError(ValueError):
    pass


def validate_manifest(directory: Path) -> dict:
    """The parsed manifest of a complete store in *directory*, or ManifestError."""
    path = directory / MANIFEST
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestError(f"unreadable manifest: {exc}") from exc
    if manifest.get("format") != FORMAT or manifest.get("format_version") != FORMAT_VERSION:
        raise ManifestError(f"unsupported store format {manifest.get('format')!r} v{manifest.get('format_version')!r}")
    if manifest.get("status") != "complete":
        raise ManifestError(f"store status is {manifest.get('status')!r}")
    files = {f.get("name"): f for f in manifest.get("files") or [] if isinstance(f, dict)}
    for name in REQUIRED_FILES:
        if name not in files:
            raise ManifestError(f"manifest lists no {name}")
    for name, entry in files.items():
        if not isinstance(name, str) or "/" in name or name.startswith("."):
            raise ManifestError(f"bad file name {name!r}")
        actual = directory / name
        if not actual.is_file() or actual.stat().st_size != entry.get("bytes"):
            raise ManifestError(f"{name} is missing or not the size the manifest records")
    columns = manifest.get("columns") or []
    if len(columns) > MAX_COLUMNS:
        raise ManifestError("too many columns")
    names = [c.get("name") for c in columns]
    if len({n.lower() for n in names if isinstance(n, str)}) != len(names) or any(c.get("type") not in _TYPES for c in columns):
        raise ManifestError("column names must be unique and typed BIGINT, DOUBLE or VARCHAR")
    return manifest
