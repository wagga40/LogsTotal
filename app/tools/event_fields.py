"""Pure event field views over native evidence and declared source layouts.

Legacy sources intentionally differ by consumer: analytics scans all sources,
relationships merge them, lineage adds defaults, and marker hosts see the document
wrapper. Keeping those policies here preserves existing extraction omissions.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

FieldPath = tuple[str, ...]
FallbackPaths = tuple[FieldPath, ...]
_MISSING = object()

HAYABUSA_TACTIC_ABBREV = {
    "recon": "reconnaissance",
    "resdev": "resource_development",
    "initaccess": "initial_access",
    "exec": "execution",
    "persis": "persistence",
    "privesc": "privilege_escalation",
    "evas": "defense_evasion",
    "credaccess": "credential_access",
    "disc": "discovery",
    "latmov": "lateral_movement",
    "collect": "collection",
    "c2": "command_and_control",
    "exfil": "exfiltration",
    "impact": "impact",
}


@dataclass(frozen=True)
class EventField:
    """Canonical alias with ordered fallbacks relative to its native source.

    By default only missing/null values fall through, retaining zero and False.
    ``missing`` preserves explicit null; ``truthy`` skips all falsey values.
    Metadata host/timestamp policies separately retain their legacy truthiness.
    """

    name: str
    paths: FallbackPaths
    fallback: Literal["non_null", "missing", "truthy"] = "non_null"


@dataclass(frozen=True)
class EventSource:
    """Native mapping, optionally projected to canonical fields without mutation."""

    path: FieldPath = ()
    fields: tuple[EventField, ...] = ()
    skip_empty: bool = False


# Named native sources make the historic consumer policies explicit.
ROOT = EventSource()
DETAILS = EventSource(("Details",))
EVTX_DATA = EventSource(("Event", "EventData"), skip_empty=True)
EVTX_SYSTEM = EventSource(("Event", "System"))
EXTRA_FIELDS = EventSource(("ExtraFieldInfo",))


@dataclass(frozen=True)
class EventProjection:
    """Declarative source and fallback policy; defaults preserve legacy extraction.

    Timestamp and host paths are groups: choose the first truthy value within a
    group, validate it, then try the next group. A malformed truthy Timestamp thus
    still masks lowercase timestamp before the EVTX fallback, as it did before.
    """

    analytics_sources: tuple[EventSource, ...] = (ROOT, DETAILS, EVTX_DATA)
    relationship_sources: tuple[EventSource, ...] = (EVTX_SYSTEM, EVTX_DATA, DETAILS, ROOT)
    lineage_defaults: tuple[EventSource, ...] = (EXTRA_FIELDS,)
    excluded_fields: tuple[str, ...] = ("Event", "Details", "EventData", "System")
    timestamp_paths: tuple[FallbackPaths, ...] = (
        (("Timestamp",), ("timestamp",)),
        # Zircolite flattens TimeCreated to a root SystemTime and writes no Timestamp.
        (("SystemTime",),),
        (("Event", "System", "TimeCreated_attributes", "SystemTime"),),
    )
    host_paths: tuple[FallbackPaths, ...] = (
        (("Computer",), ("computer",)),
        (("Event", "System", "Computer"),),
        (("document", "data", "Event", "System", "Computer"),),
    )
    analytics_host_paths: FallbackPaths = (("Computer",), ("Event", "System", "Computer"))
    tactic_paths: tuple[FieldPath, ...] = (("MitreTactics",),)
    tactic_aliases: tuple[tuple[str, str], ...] = tuple(HAYABUSA_TACTIC_ABBREV.items())
    technique_paths: tuple[FieldPath, ...] = (("MitreTags",), ("OtherTags",), ("tags",))
    metadata_source: EventSource | None = None

    @classmethod
    def canonical(cls, source: EventSource) -> EventProjection:
        """Use one canonical field declaration for every downstream consumer.

        Declare Timestamp, Computer and other fields once in ``source``. Their
        native paths also supply metadata reads, without changing raw evidence.
        """
        return cls(
            analytics_sources=(source,),
            relationship_sources=(source,),
            lineage_defaults=(),
            metadata_source=source,
        )


LEGACY_PROJECTION = EventProjection()


class EventRecord(dict):
    """Native JSON-equivalent evidence with transient field-source metadata."""

    def __init__(self, event: dict, *, projection: EventProjection):
        super().__init__(event)
        self.projection = projection


def _at(mapping: dict, path: FieldPath, default: object = None) -> object:
    value: object = mapping
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def _first_value(mapping: dict, paths: FallbackPaths, fallback: Literal["non_null", "missing", "truthy"] = "truthy") -> object:
    for path in paths:
        value = _at(mapping, path, _MISSING)
        if value is _MISSING:
            continue
        if fallback == "missing" or (fallback == "non_null" and value is not None) or (fallback == "truthy" and value):
            return value
    return None


def _items(value: object) -> list:
    return value if isinstance(value, list) else [item.strip() for item in str(value).split(",")]


class EventView:
    """Read-only field access shared by analytics, timelines and process lineage."""

    def __init__(self, event: dict, projection: EventProjection | None = None):
        self.event = event
        self.projection = projection if projection is not None else getattr(event, "projection", LEGACY_PROJECTION)
        self._metadata = event
        if self.projection.metadata_source is not None:
            self._metadata = next(self._sources((self.projection.metadata_source,)), {})

    def _sources(self, sources: tuple[EventSource, ...]) -> Iterator[dict]:
        for source in sources:
            if source is self.projection.metadata_source and self._metadata is not self.event:
                yield self._metadata
                continue
            native = _at(self.event, source.path)
            if not isinstance(native, dict) or (source.skip_empty and not native):
                continue
            if source.fields:
                # Only declared fields are canonical; raw evidence is always retained.
                yield {field.name: _first_value(native, field.paths, field.fallback) for field in source.fields}
            else:
                yield native

    @property
    def analytics_sources(self) -> list[dict]:
        return list(self._sources(self.projection.analytics_sources))

    @property
    def analytics_computer(self) -> object:
        return _first_value(self._metadata, self.projection.analytics_host_paths)

    @property
    def relationship_fields(self) -> dict:
        merged: dict = {}
        for source in self._sources(self.projection.relationship_sources):
            merged.update({key: value for key, value in source.items() if key not in self.projection.excluded_fields})
        return merged

    @property
    def lineage_fields(self) -> dict:
        merged = self.relationship_fields
        for source in self._sources(self.projection.lineage_defaults):
            for key, value in source.items():
                merged.setdefault(key, value)
        return merged

    @property
    def timestamp(self) -> str | None:
        for paths in self.projection.timestamp_paths:
            value = _first_value(self._metadata, paths)
            if isinstance(value, str) and len(value) >= 13:
                return value
        return None

    @property
    def computer(self) -> str | None:
        for paths in self.projection.host_paths:
            value = _first_value(self._metadata, paths)
            if isinstance(value, str) and value:
                return value
        return None

    def tactic_hints(self) -> Iterator[str]:
        aliases = dict(self.projection.tactic_aliases)
        for path in self.projection.tactic_paths:
            raw = _at(self._metadata, path)
            if raw:
                for value in _items(raw):
                    tactic = aliases.get(value.lower())
                    if tactic:
                        yield tactic

    def technique_hints(self) -> Iterator[object]:
        for path in self.projection.technique_paths:
            raw = _at(self._metadata, path)
            if raw:
                yield from _items(raw)
