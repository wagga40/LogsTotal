"""DB-driven enrichment helpers — the lookup links shown on the entity page.

No FastAPI or Huey imports. `get_enrichment_links` is the only public loader: it
returns a list of `{name, url}` dicts ready for the entity page template.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.json_utils import loads as json_loads
from app.models import EnrichmentService

_log = logging.getLogger(__name__)


def _decode_types(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        v = json_loads(raw)
        return [t for t in v if isinstance(t, str)] if isinstance(v, list) else []
    except (ValueError, TypeError):
        return []


def _format_link(template: str | None, value: str, entity_type: str) -> str | None:
    if not template:
        return None
    # MalwareBazaar wants lowercase hashes.
    link_value = value.lower() if entity_type == "hash" and "bazaar.abuse.ch" in template else value
    try:
        return template.format(value=link_value)
    except (KeyError, IndexError) as exc:
        _log.warning("enrichment template format failed: %s — template=%r value=%r", exc, template, value)
        return None


def _rows_to_links(rows: Iterable[EnrichmentService], entity_type: str, value: str) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        if not row.enabled:
            continue
        types = _decode_types(row.entity_types)
        if entity_type not in types:
            continue
        url = _format_link(row.link_template, value, entity_type)
        if not url:
            continue
        out.append({"name": row.name, "url": url})
    return out


async def get_enrichment_links(db: AsyncSession, entity_type: str, value: str) -> list[dict]:
    """Enabled services for this entity type, as `{name, url}` link dicts."""
    rows = (
        (await db.execute(select(EnrichmentService).where(EnrichmentService.enabled.is_(True)).order_by(EnrichmentService.display_order, EnrichmentService.name))).scalars().all()
    )
    return _rows_to_links(rows, entity_type, value)
