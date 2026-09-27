"""IOC pack builder — compact JSON suitable for pasting into tickets, Slack, or emails.

Pure-Python helpers that take already-loaded entities + metadata; no DB calls inside.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from app.intel.cases import stix_pattern
from app.models import Entity, EntityTag


def _stix_pattern_for(entity: Entity) -> str:
    return stix_pattern(entity.entity_type, entity.value)


def _iso(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def _indicator_row(
    entity: Entity,
    *,
    sighting_count: int = 0,
    threat_categories: list[str] | None = None,
    severity: str | None = None,
    tag_strings: list[str] | None = None,
) -> dict:
    return {
        "value": entity.value,
        "type": entity.entity_type,
        "first_seen": _iso(entity.first_seen_at),
        "last_seen": _iso(entity.last_seen_at),
        "sightings": int(sighting_count or 0),
        "threat_categories": sorted(threat_categories or []),
        "severity": severity or "",
        "stix_pattern": _stix_pattern_for(entity),
        "tags": sorted(tag_strings or []),
    }


def build_entity_ioc_pack(
    focal: Entity,
    neighbors: Iterable[Entity] = (),
    *,
    focal_threat_categories: list[str] | None = None,
    focal_severity: str | None = None,
    focal_tags: Iterable[EntityTag] = (),
) -> dict:
    """Build an IOC pack for a single entity + its top neighbors (optional)."""
    indicators = [
        _indicator_row(
            focal,
            sighting_count=focal.job_count or 0,
            threat_categories=focal_threat_categories,
            severity=focal_severity,
            tag_strings=[t.tag for t in focal_tags],
        )
    ]
    for n in neighbors:
        indicators.append(_indicator_row(n, sighting_count=n.job_count or 0))
    return {
        "version": "1.0",
        "generated_at": _iso(datetime.now(UTC)),
        "source": "LogsTotal",
        "scope": "entity",
        "focal": focal.value,
        "indicators": indicators,
    }


def build_case_ioc_pack(
    case_name: str,
    entities: Iterable[Entity],
    *,
    sighting_counts: dict[int, int] | None = None,
    threat_categories_by_entity: dict[int, list[str]] | None = None,
    severity_by_entity: dict[int, str] | None = None,
) -> dict:
    """Build an IOC pack for an investigation case."""
    sighting_counts = sighting_counts or {}
    threat_categories_by_entity = threat_categories_by_entity or {}
    severity_by_entity = severity_by_entity or {}
    indicators = []
    for e in entities:
        indicators.append(
            _indicator_row(
                e,
                sighting_count=sighting_counts.get(e.id, e.job_count or 0),
                threat_categories=threat_categories_by_entity.get(e.id),
                severity=severity_by_entity.get(e.id),
            )
        )
    return {
        "version": "1.0",
        "generated_at": _iso(datetime.now(UTC)),
        "source": "LogsTotal",
        "scope": "case",
        "case": case_name,
        "indicators": indicators,
    }
