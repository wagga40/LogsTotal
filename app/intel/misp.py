"""MISP Event JSON builder — dict-based, no pymisp dependency.

Produces a single MISP Event wrapping a set of indicators as Attributes. Suitable for
import into MISP via the `/events/add` REST API or the CLI tools.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime

from app.models import Entity, EntityJobLink

# LogsTotal entity_type → MISP Attribute type
_ENTITY_TO_MISP_TYPE: dict[str, str] = {
    "ip_address": "ip-dst",
    "domain": "domain",
    "user": "target-user",
    "computer": "target-machine",
    "executable": "filename",
    "cmdline_file": "filename",
    "service": "comment",
    "task": "comment",
}

# Severity → MISP threat_level_id (1=high, 2=medium, 3=low, 4=undefined)
_SEVERITY_TO_THREAT_LEVEL = {
    "critical": 1,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}

_HASH_RES = (
    (re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE), "sha256"),
    (re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE), "sha1"),
    (re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE), "md5"),
)


def _misp_type_for(entity: Entity) -> str | None:
    if entity.entity_type == "hash":
        for rx, t in _HASH_RES:
            if rx.match(entity.value or ""):
                return t
        return None  # unknown hash format → skip
    return _ENTITY_TO_MISP_TYPE.get(entity.entity_type)


def _category_for(misp_type: str) -> str:
    if misp_type in ("ip-dst", "ip-src", "domain", "hostname", "url"):
        return "Network activity"
    if misp_type in ("md5", "sha1", "sha256", "filename"):
        return "Payload delivery"
    if misp_type.startswith("target-"):
        return "Targeting data"
    return "External analysis"


def _stable_uuid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"logstotal:misp:{seed}"))


def _attribute_for(entity: Entity, sighting_count: int = 0, *, scope: str = "") -> dict | None:
    misp_type = _misp_type_for(entity)
    if not misp_type:
        return None
    return {
        # Scoped to the event: MISP refuses an attribute UUID that already exists in another
        # event, so an entity in two cases lost its indicator from the second import.
        "uuid": _stable_uuid(f"{scope}attr:{entity.id}:{misp_type}"),
        "type": misp_type,
        "category": _category_for(misp_type),
        "value": entity.value,
        "to_ids": True,
        "comment": f"Observed in {sighting_count} LogsTotal job(s)" if sighting_count else "",
    }


def build_misp_event(
    info: str,
    entities: Iterable[Entity],
    *,
    sighting_counts: dict[int, int] | None = None,
    threat_level: int | None = None,
    tags: Iterable[str] = ("tlp:amber",),
    published: bool = False,
    case_id: int | None = None,
) -> dict:
    """Build a MISP Event wrapping `entities` as Attributes.

    `sighting_counts` maps Entity.id → number of jobs the entity was sighted in (drives the comment).

    `case_id` makes the event *that case*: its UUID is derived from the case id, so a re-export
    (or a rename) updates the same MISP event, and two cases that share a name stay two
    events. Without it — the IOC feed — the event is the day's feed, keyed on `info` and date.
    """
    sighting_counts = sighting_counts or {}
    scope = f"case:{case_id}:" if case_id is not None else f"event:{info}:{datetime.now(UTC).strftime('%Y-%m-%d')}:"
    attributes: list[dict] = []
    for e in entities:
        attr = _attribute_for(e, sighting_count=sighting_counts.get(e.id, 0), scope=scope)
        if attr is not None:
            attributes.append(attr)

    event_uuid = _stable_uuid(scope.rstrip(":"))
    return {
        "Event": {
            "uuid": event_uuid,
            "info": info,
            "distribution": "0",  # your-org only
            "threat_level_id": str(threat_level or 4),
            "analysis": "2",  # complete
            "date": datetime.now(UTC).strftime("%Y-%m-%d"),
            "published": published,
            "Attribute": attributes,
            "Tag": [{"name": t} for t in tags],
        }
    }


def threat_level_for_entities(entities: Iterable[Entity], severity_by_entity: dict[int, str] | None = None) -> int:
    """Return the worst (lowest threat_level_id) across the given entities. Defaults to undefined."""
    severity_by_entity = severity_by_entity or {}
    best = 4
    for e in entities:
        sev = severity_by_entity.get(e.id) or "informational"
        best = min(best, _SEVERITY_TO_THREAT_LEVEL.get(sev, 4))
    return best


def sighting_counts_from_links(job_links_by_entity: dict[int, list[EntityJobLink]]) -> dict[int, int]:
    """Convenience: convert {entity_id: [EntityJobLink,...]} → {entity_id: count}."""
    return {eid: len(links) for eid, links in job_links_by_entity.items()}
