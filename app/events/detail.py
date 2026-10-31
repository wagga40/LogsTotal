"""One event for the drawer: its fields grouped by where they came from, and as JSON. Pure.

The store holds flattened columns; the manifest records each column's original path
(`EventData/CommandLine`), so the drawer can group by the path's first segment and rebuild
the nested shape for "Copy JSON" without the original record. Fields past the column cap
live in `_lt_extra` (a JSON object keyed by path) and are folded back in the same way.
"""

from __future__ import annotations

import json
from datetime import datetime

from app.events.state import FIXED_LABELS

#: Fixed columns shown in the drawer's first group, in this order.
_FIXED_SHOWN = ("_lt_time", "_lt_host", "_lt_channel", "_lt_eid", "_lt_rid", "_lt_seq", "_lt_line")


def _display(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _paths(manifest: dict) -> dict[str, str]:
    return {c["name"]: str(c.get("path") or c["name"]) for c in manifest.get("columns") or []}


def _extra(fields: dict) -> dict[str, object]:
    raw = fields.get("_lt_extra")
    if not raw:
        return {}
    try:
        extra = json.loads(raw)
    except ValueError:
        return {}
    return extra if isinstance(extra, dict) else {}


def group_fields(fields: dict, manifest: dict) -> list[tuple[str, list[tuple[str, str, str]]]]:
    """`[(group, [(label, field name for a query term, display value)])]`, Event group first."""
    paths = _paths(manifest)
    groups: dict[str, list[tuple[str, str, str]]] = {"Event": []}
    for name in _FIXED_SHOWN:
        if fields.get(name) is not None:
            groups["Event"].append((FIXED_LABELS.get(name, name), name, _display(fields[name])))
    for name, value in fields.items():
        if name.startswith("_lt_") or value is None:
            continue
        path = paths.get(name, name)
        group = path.split("/", 1)[0] if "/" in path else "Fields"
        groups.setdefault(group, []).append((name, name, _display(value)))
    for path, value in _extra(fields).items():
        group = path.split("/", 1)[0] if "/" in path else "Fields"
        groups.setdefault(group, []).append((path, "", _display(value)))
    return [(group, sorted(rows, key=lambda r: r[0].lower()) if group != "Event" else rows) for group, rows in groups.items() if rows]


def rebuild_json(fields: dict, manifest: dict) -> dict:
    """The event as a nested object, from its columns' original paths."""
    paths = _paths(manifest)
    out: dict = {}

    def put(path: str, value: object) -> None:
        node = out
        parts = path.split("/")
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = node[part] = {}
            node = child
        node[parts[-1]] = value.isoformat() if isinstance(value, datetime) else value

    for name, value in fields.items():
        if not name.startswith("_lt_") and value is not None:
            put(paths.get(name, name), value)
    for path, value in _extra(fields).items():
        put(path, value)
    return out
