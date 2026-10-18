"""Typed output declarations and the shared detection/evidence decoder.

Paths name literal dictionary keys. Fallbacks and transforms are Python values,
never expressions evaluated from tool output or workflow configuration.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from app.json_utils import load_file, loads
from app.tools.diagnostics import CompletionDiagnostics
from app.tools.output import RawMatch, event_timestamp

_MISSING = object()
_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Selector:
    paths: tuple[tuple[str, ...], ...] = ()
    default: Any = None
    fallback: Literal["truthy", "missing"] = "truthy"
    transforms: tuple[Callable[[Any], Any], ...] = ()

    def read(self, record: dict) -> Any:
        value = self.default
        for path in self.paths:
            candidate: Any = record
            for key in path:
                if not isinstance(candidate, dict) or key not in candidate:
                    candidate = _MISSING
                    break
                candidate = candidate[key]
            if candidate is not _MISSING and (self.fallback == "missing" or candidate):
                value = candidate
                break
        for transform in self.transforms:
            value = transform(value)
        return value


@dataclass(frozen=True)
class MetadataMapping:
    rule_name: Selector = field(default_factory=lambda: Selector(default=""))
    rule_id: Selector = field(default_factory=lambda: Selector(default=""))
    severity: Selector = field(default_factory=Selector)
    tags: Selector = field(default_factory=lambda: Selector(default=[]))
    rule_content: Selector = field(default_factory=lambda: Selector(default=""))


@dataclass(frozen=True)
class OutputMapping:
    finding: MetadataMapping
    # Named exceptions to finding metadata preserve historical reader semantics.
    raw_overrides: Mapping[str, Selector] = field(default_factory=dict)
    format: Literal["json", "jsonl"] = "json"
    events: Selector | None = None  # None means the record itself is evidence.
    raw_events: Selector | None = None
    reported_count: Selector | None = None
    grouping: Literal["name", "identity", "blocks"] = "name"
    detail_projection: Callable[[Any], Any] | None = None
    event_transform: Callable[[dict], dict] | None = None
    # Future analytics projections travel beside evidence; they never replace it.
    event_projection: Callable[[dict], dict] | None = None
    timestamp: Callable[[dict], Any] = event_timestamp
    validate: Callable[[Any], None] | None = None
    strict: bool = False
    iterable_input: bool = False
    lookup_rule: bool = True
    lookup_empty_id: bool = False
    rule_metadata: Callable[[Any, str], tuple[str, str]] | None = None
    record_label: str = "event(s)"


@dataclass
class DecodedDetection:
    rule_name: Any
    rule_id: Any
    severity: Any
    tags: list
    rule_content: Any
    reported_count: int
    events: Any
    event_projection: Callable[[dict], dict] | None = None


@dataclass
class RecordStream:
    """A file-backed stream accepted by the otherwise list-only legacy adapters."""

    records: Iterable[Any]

    def __iter__(self):
        return iter(self.records)


def file_records(path: Path, *, format: Literal["json", "jsonl"], strict: bool = False, diagnostics: CompletionDiagnostics | None = None) -> Iterator[Any]:
    if format == "json":
        raw = load_file(path)
        if not isinstance(raw, list):
            if strict or diagnostics is not None:
                raise ValueError("Invalid detection output: expected a JSON list")
            return
        for item in raw:
            if isinstance(item, dict):
                yield item
            elif strict:
                raise ValueError("Invalid detection record: expected an object")
            elif diagnostics is not None:
                diagnostics.skip_record()
        return
    with path.open("rb") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                item = loads(line)
            except (ValueError, KeyError):
                if strict:
                    raise
                if diagnostics is not None:
                    diagnostics.skip_record()
                continue
            if strict or isinstance(item, dict):
                yield item
            elif diagnostics is not None:
                diagnostics.skip_record()


def _decode(record: dict, mapping: OutputMapping, purpose: Literal["finding", "raw"]) -> DecodedDetection:
    if mapping.validate is not None:
        mapping.validate(record)
    if not isinstance(record, dict):
        raise ValueError("Invalid detection record: expected an object")
    metadata = {}
    for name in ("rule_name", "rule_id", "severity", "tags", "rule_content"):
        selector = mapping.raw_overrides.get(name, getattr(mapping.finding, name)) if purpose == "raw" else getattr(mapping.finding, name)
        metadata[name] = selector.read(record)
    selector = mapping.raw_events if purpose == "raw" and mapping.raw_events is not None else mapping.events
    events = selector.read(record) if selector is not None else [record]
    if mapping.event_transform is not None:
        events = [mapping.event_transform(event) for event in events]
    count = mapping.reported_count.read(record) if mapping.reported_count is not None and purpose == "finding" else None
    if not isinstance(count, int):
        count = len(events) if purpose == "finding" else 0
    return DecodedDetection(**metadata, reported_count=count, events=events, event_projection=mapping.event_projection)


def decode_records(
    records: Iterable[Any], mapping: OutputMapping, *, purpose: Literal["finding", "raw"] = "finding", tool_name: str = "tool", diagnostics: CompletionDiagnostics | None = None
) -> Iterator[DecodedDetection]:
    skipped = 0
    for record in records:
        if not isinstance(record, dict) and not mapping.strict:
            if diagnostics is not None:
                diagnostics.skip_record()
            continue
        try:
            detection = _decode(record, mapping, purpose)
        except Exception:
            if mapping.strict or purpose == "raw":
                raise
            skipped += 1
            if diagnostics is not None:
                diagnostics.skip_record()
            continue
        yield detection
    if skipped:
        _log.warning("%s: skipped %d unparseable %s", tool_name, skipped, mapping.record_label)


def iter_raw_matches(path: Path, mapping: OutputMapping) -> Iterator[RawMatch]:
    for detection in decode_records(file_records(path, format=mapping.format, strict=mapping.strict), mapping, purpose="raw"):
        for event in detection.events:
            if isinstance(event, dict):
                if detection.event_projection is not None:
                    event = detection.event_projection(event)
                yield RawMatch(event, detection.rule_name, detection.rule_id, detection.severity, detection.tags, mapping.timestamp(event))


def normalize(adapter: Any, raw: Any) -> list:
    # Import locally to keep the mapping usable by the base adapter itself.
    from app.tools.base import NormalizedFinding

    mapping = adapter.output_mapping
    if mapping.iterable_input or isinstance(raw, RecordStream):
        records = raw
    elif mapping.strict:
        if not isinstance(raw, list):
            raise ValueError("Invalid detection output: expected a list")
        records = raw
    else:
        records = adapter._dict_records(raw)
    grouped = {}
    findings = []
    rule_cache = {}
    skipped = 0
    for detection in decode_records(records, mapping, tool_name=adapter.name, diagnostics=adapter._diagnostics):
        try:
            key = detection.rule_id or detection.rule_name if mapping.grouping == "identity" else detection.rule_name
            finding = None if mapping.grouping == "blocks" else grouped.get(key)
            if finding is None:
                severity = adapter._normalize_severity(detection.severity)
                content = detection.rule_content
                if mapping.rule_metadata is not None:
                    if detection.rule_id not in rule_cache:
                        rule_cache[detection.rule_id] = mapping.rule_metadata(adapter, detection.rule_id)
                    severity, content = rule_cache[detection.rule_id]
                elif mapping.lookup_rule and (detection.rule_id or mapping.lookup_empty_id):
                    content = adapter._lookup_rule_yaml(detection.rule_id)
                finding = NormalizedFinding(detection.rule_name, severity, 0, detection.rule_id, detection.tags, rule_content=content)
                findings.append(finding)
                if mapping.grouping != "blocks":
                    grouped[key] = finding
            if mapping.grouping == "blocks":
                finding.count = detection.reported_count
                # Slicing retains historical negative limits and non-dict samples.
                finding.details = detection.events[: adapter.max_details]
            else:
                finding.count += detection.reported_count
                for event in detection.events:
                    if len(finding.details) < adapter.max_details:
                        finding.details.append(mapping.detail_projection(event) if mapping.detail_projection is not None else event)
        except Exception:
            if mapping.strict:
                raise
            skipped += 1
            adapter._diagnostics.skip_record()
    if skipped:
        _log.warning("%s: skipped %d unparseable %s", adapter.name, skipped, mapping.record_label)
    return findings


def list_tags(value: Any) -> list:
    return value if isinstance(value, list) else [str(value)]


def csv_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(tag).strip() for tag in value if tag]
    return [tag.strip() for tag in str(value).split(",") if tag.strip()] if value else []


def list_events(value: Any) -> list:
    return value if isinstance(value, list) else []


def sigma_content(value: Any) -> Any:
    if isinstance(value, list) and value:
        return value[0] if len(value) == 1 else "\n---\n".join(str(rule) for rule in value)
    return value if isinstance(value, str) and value else ""
