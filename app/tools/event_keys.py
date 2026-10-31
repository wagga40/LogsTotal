"""Identity of the source event behind each detection, for joining tool output to the event store.

Pure. Every tool reports the event it matched in its own shape, and some keep more of its
identity than others (measured on real outputs):

- Zircolite, Chainsaw, rsigma: full `Computer`, `Channel`, `EventRecordID` — an exact key.
- Hayabusa: `Computer` and `RecordID`, but the channel abbreviated (`Sysmon`), resolved here
  through the reverse of its own `channel_abbreviations.txt`; unresolvable, the key falls
  back to (host, event id, record id).
- Linux text logs: no record id. Zircolite auditd keeps a converted time, ChopChopGo only a
  timestamp and the message. These get *hints* (time, cursor, audit serial, pid, message
  hash) rather than a key: the overlay decides how to join them, unique matches only.

The normalisers below are shared with the event-store builder, so both sides of the join
lower-case and type the same way. Changing one without the other unlinks every detection.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

WINDOWS = "w"  # (WINDOWS, host, channel, record_id)
WINDOWS_BY_EVENT_ID = "we"  # (WINDOWS_BY_EVENT_ID, host, event_id, record_id)
HINTS = "h"  # (HINTS, epoch_second | None, cursor | None, audit_seq | None, pid | None, message_sha | None)

_ABBREVIATIONS = Path(__file__).resolve().parents[2] / "tools" / "hayabusa" / "rules" / "config" / "channel_abbreviations.txt"


def norm_host(value: object) -> str | None:
    text = str(value).strip().lower() if value not in (None, "") else ""
    return text or None


def norm_channel(value: object) -> str | None:
    return norm_host(value)


def norm_int(value: object) -> int | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def message_sha(message: object) -> str | None:
    if not isinstance(message, str) or not message.strip():
        return None
    return hashlib.sha1(message.strip().encode("utf-8"), usedforsecurity=False).hexdigest()[:16]


_AMBIGUOUS = ""


@lru_cache(maxsize=1)
def _hayabusa_channels() -> dict[str, str]:
    """Abbreviation -> full channel name, lower-cased; empty if the file is absent.

    Three abbreviations name several channels each (AppLocker, SecMitig, UserProfileSvc in
    Hayabusa 4.2's table); they map to `_AMBIGUOUS`, and such a key falls back to the event id.
    """
    mapping: dict[str, str] = {}
    try:
        lines = _ABBREVIATIONS.read_text(encoding="utf-8").splitlines()
    except OSError:
        return mapping
    for line in lines[1:]:
        channel, _, abbreviation = line.rpartition(",")
        abbreviation, channel = abbreviation.strip().lower(), channel.strip().lower()
        if channel and abbreviation:
            mapping[abbreviation] = _AMBIGUOUS if mapping.get(abbreviation, channel) != channel else channel
    return mapping


def _system(event: dict) -> dict:
    """The EVTX System block wherever a tool kept it, or {}."""
    for path in (("Event", "System"), ("document", "data", "Event", "System")):
        node = event
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if isinstance(node, dict):
            return node
    return {}


def link_key(event: dict, *, epoch_second: int | None = None) -> tuple | None:
    """The identity tuple for one matched event, or None when nothing identifies it.

    *epoch_second* is the caller's already-normalised event time (the timeline parse has it),
    used only for the hints form.
    """
    if not isinstance(event, dict):
        return None
    system = _system(event)
    host = norm_host(system.get("Computer") or event.get("Computer") or event.get("computer"))
    record_id = norm_int(system.get("EventRecordID") or event.get("EventRecordID") or event.get("RecordID"))
    if host and record_id is not None:
        channel = norm_channel(system.get("Channel") or event.get("Channel"))
        # Hayabusa abbreviates (`Sysmon`, `Sec`); no full channel name is also an abbreviation.
        channel = _hayabusa_channels().get(channel, channel) if channel else None
        if channel:
            return (WINDOWS, host, channel, record_id)
        event_id = norm_int(system.get("EventID") or event.get("EventID"))
        if event_id is not None:
            return (WINDOWS_BY_EVENT_ID, host, event_id, record_id)
    cursor = event.get("__CURSOR") or event.get("CURSOR") or event.get("cursor")
    seq = norm_int(event.get("_lt_seq") or event.get("serial") or event.get("audit_serial"))
    pid = norm_int(event.get("pid") or event.get("PID") or event.get("_PID"))
    sha = message_sha(event.get("Message") or event.get("MESSAGE") or event.get("message"))
    hints = (HINTS, epoch_second, str(cursor) if cursor else None, seq, pid, sha)
    return hints if any(v is not None for v in hints[1:]) else None


#: Links kept per job, like the timeline parse's MAX_PARSE_EVENTS; past it `truncated` says so.
MAX_LINKS = 250_000


class LinkAccumulator:
    """Every (rule, source-event key) pair of one job, columnar for storage.

    One per worker thread, merged in path order like `MarkerAccumulator`, so it needs no lock
    and the merged order is deterministic. `unkeyed` counts matches that carried no identity
    at all: the overlay reports them as unlinked rather than pretending they matched nothing.
    """

    def __init__(self, cap: int = MAX_LINKS):
        self.cap = cap
        self.rules: dict[tuple, int] = {}
        self.links: list[list] = []
        self.unkeyed = 0
        self.truncated = False

    def add(self, tool: str, rule_id: object, rule_name: object, severity: object, event: dict, ts: object = None) -> None:
        key = link_key(event)
        if key is not None and key[0] == HINTS and ts:
            from app.intel.event_markers import event_epoch_seconds

            key = (HINTS, event_epoch_seconds(ts), *key[2:])
        if key is None:
            self.unkeyed += 1
            return
        self._append((tool or "", str(rule_id or ""), str(rule_name or ""), str(severity or "")), list(key))

    def _append(self, rule: tuple, key: list) -> None:
        if len(self.links) >= self.cap:
            self.truncated = True
            return
        ix = self.rules.setdefault(rule, len(self.rules))
        self.links.append([ix, *key])

    def merge(self, other: LinkAccumulator) -> None:
        order = list(other.rules)
        for link in other.links:
            self._append(order[link[0]], link[1:])
        self.unkeyed += other.unkeyed
        self.truncated = self.truncated or other.truncated

    def result(self) -> dict:
        return {"v": 1, "rules": [list(rule) for rule in self.rules], "links": self.links, "unkeyed": self.unkeyed, "truncated": self.truncated}
