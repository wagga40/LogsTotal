"""Nested events to flat `{path: scalar}` maps, and the column names those paths get.

Rules, borrowed from Zircolite's measured design but not its code:

- An iterative walk: `#attributes` segments vanish from the path (`Provider/#attributes/Name`
  becomes `Provider/Name`) and `#text` folds into its parent (`EventID/#text` is `EventID`).
- Lists become JSON text (not Python's `str()`), booleans `"true"`/`"false"`, and null or empty
  values are dropped: a missing field and an empty one read the same downstream.
- `xmlns` attributes are dropped; they are the schema's, not the event's.

Paths are compared case-insensitively — EVTX writers disagree on case, and the store's engine
treats column names that way — so `EventData/User` and `EventData/user` are one column, shown
in the spelling seen first.

**Names are decided over the whole file, never per event.** Zircolite names a column after its
leaf and lets two paths with the same leaf overwrite each other silently. Here the bare leaf
goes to the most-populated path; every other path with that leaf gets the shortest parent
suffix that makes it unique (`UserData_Data`). Windows System fields have fixed names, so a
store's `EventID` or `Computer` is the same column in every file.
"""

from __future__ import annotations

import re

import orjson

Path = tuple[str, ...]

#: Fixed names for the EVTX System block, after the `Event` root is dropped. Keeps the system
#: fields apart from EventData fields of the same leaf: `Execution/ProcessID` (the logging
#: process) is not Sysmon's `EventData/ProcessId` (the process the event is about).
SYSTEM_NAMES: dict[Path, str] = {
    ("system", "provider", "name"): "Provider_Name",
    ("system", "provider", "guid"): "Provider_Guid",
    ("system", "provider", "eventsourcename"): "Provider_EventSourceName",
    ("system", "eventid"): "EventID",
    ("system", "eventid", "qualifiers"): "EventID_Qualifiers",
    ("system", "version"): "Version",
    ("system", "level"): "Level",
    ("system", "task"): "Task",
    ("system", "opcode"): "Opcode",
    ("system", "keywords"): "Keywords",
    ("system", "timecreated", "systemtime"): "SystemTime",
    ("system", "eventrecordid"): "EventRecordID",
    ("system", "correlation", "activityid"): "Correlation_ActivityID",
    ("system", "correlation", "relatedactivityid"): "Correlation_RelatedActivityID",
    ("system", "execution", "processid"): "Execution_ProcessID",
    ("system", "execution", "threadid"): "Execution_ThreadID",
    ("system", "channel"): "Channel",
    ("system", "computer"): "Computer",
    ("system", "security", "userid"): "Security_UserID",
}

_DROP_LEAVES = {"xmlns"}
_UNSAFE = re.compile(r"[^0-9A-Za-z_]+")


#: (lower-cased parent path, key) -> lower-cased path. Keys repeat across the events of a
#: file, so lowering and tuple-building happen once per distinct path, not once per value:
#: measured, that was the largest single cost of the parse.
_LPATHS: dict[tuple, Path] = {}


def flatten(event: dict, *, root: str | None = "Event", spellings: dict[Path, Path] | None = None) -> dict[Path, object]:
    """`{lower-cased path: scalar}`; the `root` wrapper (EVTX's `Event`) is skipped.

    *spellings*, when given, records each lower-cased path's first original-case spelling.
    """
    if root and len(event) == 1 and type(event.get(root)) is dict:
        event = event[root]
    out: dict[Path, object] = {}
    lpaths = _LPATHS
    stack: list[tuple[dict, Path, Path]] = [(event, (), ())]
    while stack:
        node, prefix, lprefix = stack.pop()
        for key, value in node.items():
            if key in {"#attributes", "#text"}:
                path, lpath = prefix, lprefix
            else:
                cache_key = (lprefix, key)
                lpath = lpaths.get(cache_key)
                if lpath is None:
                    lpath = lpaths[cache_key] = (*lprefix, str(key).lower())
                path = None  # the original spelling is built only for a path not seen yet
            kind = type(value)
            if kind is dict:
                stack.append((value, path if path is not None else (*prefix, str(key)), lpath))
                continue
            if kind is str:
                if not value:
                    continue
            elif value is None:
                continue
            elif kind is list:
                if not value:
                    continue
                value = orjson.dumps(value).decode()
            elif kind is bool:
                value = "true" if value else "false"
            elif kind is not int and kind is not float:
                value = str(value)
            if not lpath or lpath[-1] in _DROP_LEAVES:
                continue
            out[lpath] = value
            if spellings is not None and lpath not in spellings:
                spellings[lpath] = path if path is not None else (*prefix, str(key))
    return out


def assign_names(counts: dict[Path, int], spellings: dict[Path, Path]) -> dict[Path, str]:
    """Column name per (lower-cased) path. Pure; deterministic for a given census.

    *counts* is each path's non-null count, *spellings* the first-seen original-case path.
    """
    names: dict[Path, str] = {}
    taken: set[str] = set()
    for path, name in SYSTEM_NAMES.items():
        if path in counts:
            names[path] = name
            taken.add(name.lower())
    by_leaf: dict[str, list[Path]] = {}
    for path in counts:
        if path not in names:
            by_leaf.setdefault(_safe(spellings[path][-1]).lower(), []).append(path)
    for _leaf, paths in sorted(by_leaf.items()):
        # The most-populated path keeps the bare leaf; ties break on the path itself.
        ordered = sorted(paths, key=lambda p: (-counts[p], p))
        for path in ordered:
            name = _shortest_unique(spellings[path], taken)
            names[path] = name
            taken.add(name.lower())
    return names


def _safe(segment: str) -> str:
    return _UNSAFE.sub("_", segment).strip("_") or "field"


def _shortest_unique(spelled: Path, taken: set[str]) -> str:
    segments = [_safe(s) for s in spelled]
    for width in range(1, len(segments) + 1):
        candidate = "_".join(segments[-width:])
        if candidate.lower() not in taken and not candidate.lower().startswith("_lt_"):
            return candidate
    base, n = "_".join(segments), 2
    while f"{base}_{n}".lower() in taken:
        n += 1
    return f"{base}_{n}"
