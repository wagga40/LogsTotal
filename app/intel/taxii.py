"""TAXII 2.1 envelope builders. Pure-Python; reuses app.intel.cases for STIX primitives.

Implements the read-only subset of TAXII 2.1:
  - Discovery, API Root, Collections, Collection objects.
  - No write endpoints (POST returns 405 at the router level).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from app.intel.cases import make_identity, make_indicator
from app.models import Entity

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

DEFAULT_API_ROOT = "logstotal"

# A single collection. Add entries here to publish more.
COLLECTIONS: list[dict[str, str]] = [
    {
        "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "title": "live-iocs",
        "description": "All current LogsTotal entities with threat context, refreshed on read.",
    },
]


def collection_by_id(cid: str) -> dict[str, str] | None:
    for c in COLLECTIONS:
        if c["id"] == cid:
            return c
    return None


def discovery(base_url: str) -> dict[str, Any]:
    return {
        "title": "LogsTotal TAXII 2.1 server",
        "description": "Read-only feed of threat indicators extracted from log analysis.",
        "contact": "see /docs",
        "default": f"{base_url.rstrip('/')}/taxii2/{DEFAULT_API_ROOT}/",
        "api_roots": [f"{base_url.rstrip('/')}/taxii2/{DEFAULT_API_ROOT}/"],
    }


def api_root() -> dict[str, Any]:
    return {
        "title": "LogsTotal",
        "description": "Default API root.",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 1048576,
    }


def collections_envelope() -> dict[str, Any]:
    return {
        "collections": [
            {
                "id": c["id"],
                "title": c["title"],
                "description": c["description"],
                "can_read": True,
                "can_write": False,
                "media_types": [STIX_MEDIA_TYPE],
            }
            for c in COLLECTIONS
        ]
    }


def collection_envelope(cid: str) -> dict[str, Any] | None:
    c = collection_by_id(cid)
    if not c:
        return None
    return {
        "id": c["id"],
        "title": c["title"],
        "description": c["description"],
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_MEDIA_TYPE],
    }


def objects_envelope(entities: Iterable[Entity], *, more: bool = False, next_cursor: str | None = None) -> dict[str, Any]:
    """Build a TAXII Objects envelope wrapping STIX 2.1 indicator objects."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    identity = make_identity(now)
    objects = [identity]
    for e in entities:
        objects.append(make_indicator(e, now))
    return {
        "objects": objects,
        "more": more,
        "next": next_cursor or "",
    }
