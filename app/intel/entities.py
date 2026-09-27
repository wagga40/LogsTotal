"""Entity persistence — extract entities from analytics data and store independently."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import delete, func, or_, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

_log = logging.getLogger(__name__)

if TYPE_CHECKING:
    pass

_UPSERT_BATCH = 200

ENTITY_TYPE_KEYS = {
    "users": "user",
    "computers": "computer",
    "ip_addresses": "ip_address",
    "hashes": "hash",
    "executables": "executable",
    "domains": "domain",
    "cmdline_files": "cmdline_file",
    "services": "service",
    "tasks": "task",
}


def persist_entities_from_analytics(db: Session, job_id: int, analytics_data: dict) -> int:
    """Upsert entities from analytics_data and link them to the given job.

    Uses batched operations instead of per-entity round trips:
    1. Bulk INSERT ON CONFLICT DO NOTHING for all entities
    2. Bulk SELECT to fetch all entity rows
    3. Bulk check existing links for this job
    4. Bulk insert new links
    5. Bulk update last_seen_at and job_count

    Returns the number of entity-job links created.
    """
    from app.models import Entity, EntityJobLink

    now = datetime.now(UTC)

    pairs: list[tuple[str, str]] = []
    for analytics_key, entity_type in ENTITY_TYPE_KEYS.items():
        for value in analytics_data.get(analytics_key, []):
            if value and isinstance(value, str):
                pairs.append((value[:500], entity_type))

    if not pairs:
        return 0

    dialect = db.get_bind().dialect.name

    for i in range(0, len(pairs), _UPSERT_BATCH):
        batch = pairs[i : i + _UPSERT_BATCH]
        rows = [{"value": v, "entity_type": et, "first_seen_at": now, "last_seen_at": now, "job_count": 0} for v, et in batch]
        if dialect == "postgresql":
            stmt = pg_insert(Entity).values(rows).on_conflict_do_nothing(index_elements=["value", "entity_type"])
        else:
            stmt = sqlite_insert(Entity).values(rows).on_conflict_do_nothing(index_elements=["value", "entity_type"])
        db.execute(stmt)

    db.flush()

    all_entities = (
        db.execute(
            select(Entity).where(
                tuple_(Entity.value, Entity.entity_type).in_(pairs),
            )
        )
        .scalars()
        .all()
    )

    entity_map: dict[tuple[str, str], Entity] = {(e.value, e.entity_type): e for e in all_entities}

    # Compute per-type attributes for entities missing them (new rows, or older rows
    # that predate this column). Idempotent — recomputed only when absent.
    try:
        from app.intel.attributes import compute_attributes
        from app.json_utils import dumps as _json_dumps

        with db.begin_nested():
            for (v, et), entity in entity_map.items():
                if entity.attributes_json is None:
                    attrs = compute_attributes(v, et)
                    if attrs is not None:
                        entity.attributes_json = _json_dumps(attrs)
    except Exception:
        _log.warning("Job %s: attribute computation failed; entities kept", job_id, exc_info=True)

    entity_ids = [e.id for e in all_entities]
    existing_links: set[int] = set()
    if entity_ids:
        for i in range(0, len(entity_ids), _UPSERT_BATCH):
            batch_ids = entity_ids[i : i + _UPSERT_BATCH]
            rows_result = db.execute(
                select(EntityJobLink.entity_id).where(
                    EntityJobLink.job_id == job_id,
                    EntityJobLink.entity_id.in_(batch_ids),
                )
            )
            existing_links.update(row[0] for row in rows_result)

    new_links = []
    for v, et in pairs:
        entity = entity_map.get((v, et))
        if entity is None:
            continue
        entity.last_seen_at = now
        if entity.id not in existing_links:
            new_links.append({"entity_id": entity.id, "job_id": job_id, "occurrence_count": 1})
            entity.job_count = (entity.job_count or 0) + 1
            existing_links.add(entity.id)

    if new_links:
        for i in range(0, len(new_links), _UPSERT_BATCH):
            batch_links = new_links[i : i + _UPSERT_BATCH]
            if dialect == "postgresql":
                link_stmt = pg_insert(EntityJobLink).values(batch_links).on_conflict_do_nothing(index_elements=["entity_id", "job_id"])
            else:
                link_stmt = sqlite_insert(EntityJobLink).values(batch_links).on_conflict_do_nothing(index_elements=["entity_id", "job_id"])
            db.execute(link_stmt)

    db.flush()

    # Also link entities to findings within this job for reverse lookup.
    try:
        with db.begin_nested():
            link_findings_to_entities_for_job(db, job_id, entity_map)
    except Exception:
        _log.warning("Job %s: finding-entity linking failed; entities kept", job_id, exc_info=True)

    # Persist typed relationships extracted in the same analytics pass.
    # Endpoints are resolved via the entity_map built above; unmatched edges drop.
    try:
        from app.intel.relationships import persist_relationships

        with db.begin_nested():
            persist_relationships(
                db,
                job_id,
                analytics_data.get("relationships") or [],
                entity_map,
                evidence=analytics_data.get("relationship_evidence"),
            )
    except Exception:
        _log.warning("Job %s: relationship persistence failed; entities kept", job_id, exc_info=True)

    return len(new_links)


# ── Finding ↔ Entity linker ───────────────────────────────────────────────

# IP boundary regex cache. Pattern requires the value not to be flanked by
# digits or dots, so "10.0.0.1" does not match inside "10.0.0.10".
_IP_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}


def _ip_pattern(value: str) -> re.Pattern[str]:
    pat = _IP_PATTERN_CACHE.get(value)
    if pat is None:
        pat = re.compile(rf"(?<![\d\.]){re.escape(value)}(?![\d\.])")
        _IP_PATTERN_CACHE[value] = pat
    return pat


def _entity_appears_in_blob(value: str, entity_type: str, blob: str, blob_lower: str) -> bool:
    """Per-type predicate: does this entity value appear in the finding's details/tags?"""
    if not value:
        return False
    if entity_type == "ip_address":
        return bool(_ip_pattern(value).search(blob))
    if entity_type == "hash":
        return value.lower() in blob_lower or value.upper() in blob
    return value.lower() in blob_lower


def link_findings_to_entities_for_job(db: Session, job_id: int, entity_map: dict[tuple[str, str], object]) -> int:
    """Create FindingEntityLink rows by scanning each finding's details/tags for entity values.

    Uses strict-enough substring matching (with IP boundary protection) to keep false
    positives low. Idempotent — re-running for the same job is a no-op (ON CONFLICT DO NOTHING).

    Returns the number of link rows newly inserted (best-effort estimate; conflicts excluded).
    """
    from app.models import Finding, FindingEntityLink, TaskResult

    if not entity_map:
        return 0

    finding_rows = db.execute(select(Finding.id, Finding.details, Finding.tags).join(TaskResult, Finding.task_result_id == TaskResult.id).where(TaskResult.job_id == job_id)).all()

    if not finding_rows:
        return 0

    new_links: list[dict] = []
    seen: set[tuple[int, int]] = set()

    for finding_id, details, tags in finding_rows:
        blob = (details or "") + "\n" + (tags or "")
        if not blob.strip():
            continue
        blob_lower = blob.lower()
        for (value, et), entity in entity_map.items():
            if _entity_appears_in_blob(value, et, blob, blob_lower):
                pair = (finding_id, entity.id)
                if pair in seen:
                    continue
                seen.add(pair)
                new_links.append({"finding_id": finding_id, "entity_id": entity.id})

    if not new_links:
        return 0

    dialect = db.get_bind().dialect.name
    for i in range(0, len(new_links), _UPSERT_BATCH):
        batch = new_links[i : i + _UPSERT_BATCH]
        if dialect == "postgresql":
            stmt = pg_insert(FindingEntityLink).values(batch).on_conflict_do_nothing(index_elements=["finding_id", "entity_id"])
        else:
            stmt = sqlite_insert(FindingEntityLink).values(batch).on_conflict_do_nothing(index_elements=["finding_id", "entity_id"])
        db.execute(stmt)

    db.flush()
    return len(new_links)


def rebuild_finding_entity_links_for_job(db: Session, job_id: int) -> int:
    """Rebuild FindingEntityLink rows for a single job from scratch.

    Used by the admin backfill. Loads the entity map from existing EntityJobLink
    rows for this job, so it works even if analytics_data is not handy.
    """
    from app.models import Entity, EntityJobLink, Finding, FindingEntityLink, TaskResult

    finding_ids_subq = select(Finding.id).join(TaskResult, Finding.task_result_id == TaskResult.id).where(TaskResult.job_id == job_id)
    db.execute(delete(FindingEntityLink).where(FindingEntityLink.finding_id.in_(finding_ids_subq)))

    entities = db.execute(select(Entity).join(EntityJobLink, Entity.id == EntityJobLink.entity_id).where(EntityJobLink.job_id == job_id)).scalars().all()
    entity_map: dict[tuple[str, str], Entity] = {(e.value, e.entity_type): e for e in entities}
    return link_findings_to_entities_for_job(db, job_id, entity_map)


def rebuild_entity_job_counts(db: Session) -> None:
    """Recalculate Entity.job_count from EntityJobLink rows."""
    db.execute(text("UPDATE entity SET job_count = (  SELECT COUNT(*) FROM entity_job_link WHERE entity_job_link.entity_id = entity.id)"))
    db.flush()


def _retally(relationship_ids: list[int]):
    """`occurrence_count` = the sum of an edge's remaining evidence rows, for these edges.

    The derivation `relationships._persist_relationship_evidence` uses, applied after a
    job's evidence is deleted. Shared by both twins below so they cannot disagree.
    """
    from sqlalchemy import update

    from app.models import EntityRelationship, EntityRelationshipEvidence

    total = (
        select(func.coalesce(func.sum(EntityRelationshipEvidence.occurrence_count), 0)).where(EntityRelationshipEvidence.relationship_id == EntityRelationship.id).scalar_subquery()
    )
    return update(EntityRelationship).where(EntityRelationship.id.in_(relationship_ids)).values(occurrence_count=total)


async def remove_entity_links_for_job_async(db: AsyncSession, job_id: int) -> None:
    """Remove intel entity links for a job; drop entities that no longer link any job.

    Call before deleting the AnalysisJob row so FK constraints stay consistent.
    Also removes FindingEntityLink rows whose findings belong to this job, since
    those would be orphaned by the upcoming Finding cascade.
    """
    from app.models import (
        CaseEntityLink,
        Comment,
        Entity,
        EntityEnrichmentResult,
        EntityJobLink,
        EntityRelationship,
        EntityRelationshipEvidence,
        EntityTag,
        Finding,
        FindingEntityLink,
        IntelRule,
        IntelRuleMatch,
        JobRuleMatch,
        TaskResult,
        WebhookDelivery,
    )

    finding_ids_subq = select(Finding.id).join(TaskResult, Finding.task_result_id == TaskResult.id).where(TaskResult.job_id == job_id)
    await db.execute(delete(FindingEntityLink).where(FindingEntityLink.finding_id.in_(finding_ids_subq)))

    # Relationship evidence is keyed by job — drop this job's rows before the job goes away,
    # then re-derive the tally of every edge they fed: `occurrence_count` is the sum of the
    # evidence rows, and nothing else would take this job's share back out of it.
    touched_rel_ids = list((await db.execute(select(EntityRelationshipEvidence.relationship_id).where(EntityRelationshipEvidence.job_id == job_id))).scalars().all())
    await db.execute(delete(EntityRelationshipEvidence).where(EntityRelationshipEvidence.job_id == job_id))
    if touched_rel_ids:
        await db.execute(_retally(touched_rel_ids))

    res = await db.execute(select(EntityJobLink.entity_id).where(EntityJobLink.job_id == job_id))
    entity_ids = {row[0] for row in res.all()}
    if not entity_ids:
        return

    await db.execute(delete(EntityJobLink).where(EntityJobLink.job_id == job_id))

    # One grouped count + one batch fetch instead of a query pair per entity.
    remaining_counts = {
        row[0]: row[1]
        for row in (await db.execute(select(EntityJobLink.entity_id, func.count()).where(EntityJobLink.entity_id.in_(entity_ids)).group_by(EntityJobLink.entity_id))).all()
    }
    entities = (await db.execute(select(Entity).where(Entity.id.in_(entity_ids)))).scalars().all()

    orphan_ids = []
    for entity in entities:
        remaining = remaining_counts.get(entity.id, 0)
        if remaining == 0:
            orphan_ids.append(entity.id)
        else:
            entity.job_count = int(remaining)

    if orphan_ids:
        # No ORM cascade in the async path, so EVERY table referencing Entity must be
        # cleared here or the delete leaves dangling rows (silently on SQLite, which does
        # not enforce foreign keys by default) and raises ForeignKeyViolation on
        # PostgreSQL. Keep this list in lock-step with Entity's relationships in
        # app/models.py: job_links, tags, finding_links, case_links,
        # comments — plus the relationship edges and cached enrichment below.
        orphan_rel_subq = select(EntityRelationship.id).where(or_(EntityRelationship.source_entity_id.in_(orphan_ids), EntityRelationship.target_entity_id.in_(orphan_ids)))
        await db.execute(delete(EntityRelationshipEvidence).where(EntityRelationshipEvidence.relationship_id.in_(orphan_rel_subq)))
        await db.execute(delete(EntityRelationship).where(or_(EntityRelationship.source_entity_id.in_(orphan_ids), EntityRelationship.target_entity_id.in_(orphan_ids))))
        await db.execute(delete(EntityEnrichmentResult).where(EntityEnrichmentResult.entity_id.in_(orphan_ids)))
        await db.execute(delete(Comment).where(Comment.entity_id.in_(orphan_ids)))
        await db.execute(delete(CaseEntityLink).where(CaseEntityLink.entity_id.in_(orphan_ids)))
        await db.execute(delete(EntityTag).where(EntityTag.entity_id.in_(orphan_ids)))
        await db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.entity_id.in_(orphan_ids)))
        orphan_auto_rules = select(IntelRule.id).where(IntelRule.auto_entity_id.in_(orphan_ids))
        await db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.rule_id.in_(orphan_auto_rules)))
        # A starred rule can be switched to job scope, and then its alerts are here instead.
        await db.execute(delete(JobRuleMatch).where(JobRuleMatch.rule_id.in_(orphan_auto_rules)))
        await db.execute(delete(WebhookDelivery).where(WebhookDelivery.rule_id.in_(orphan_auto_rules)))
        await db.execute(delete(IntelRule).where(IntelRule.auto_entity_id.in_(orphan_ids)))
        await db.execute(delete(FindingEntityLink).where(FindingEntityLink.entity_id.in_(orphan_ids)))
        await db.execute(delete(Entity).where(Entity.id.in_(orphan_ids)))


def remove_entity_links_for_job_sync(db: Session, job_id: int) -> None:
    """Sync twin of :func:`remove_entity_links_for_job_async`, for the Huey worker.

    A twin rather than a shared body — the `app/job_watch.py` shape — because the two sit
    on opposite sides of the process boundary: the delete route awaits, and the upload
    retention sweep runs inside a worker, where async SQLAlchemy is not allowed. Keep the
    two in lock-step; `tests/test_fk_cleanup_parity.py` checks both against the schema.
    """
    from app.models import (
        CaseEntityLink,
        Comment,
        Entity,
        EntityEnrichmentResult,
        EntityJobLink,
        EntityRelationship,
        EntityRelationshipEvidence,
        EntityTag,
        Finding,
        FindingEntityLink,
        IntelRule,
        IntelRuleMatch,
        JobRuleMatch,
        TaskResult,
        WebhookDelivery,
    )

    finding_ids_subq = select(Finding.id).join(TaskResult, Finding.task_result_id == TaskResult.id).where(TaskResult.job_id == job_id)
    db.execute(delete(FindingEntityLink).where(FindingEntityLink.finding_id.in_(finding_ids_subq)))

    # Relationship evidence is keyed by job — drop this job's rows and re-derive the tallies
    # they fed, for the reason the async twin gives.
    touched_rel_ids = list(db.execute(select(EntityRelationshipEvidence.relationship_id).where(EntityRelationshipEvidence.job_id == job_id)).scalars().all())
    db.execute(delete(EntityRelationshipEvidence).where(EntityRelationshipEvidence.job_id == job_id))
    if touched_rel_ids:
        db.execute(_retally(touched_rel_ids))

    entity_ids = {row[0] for row in db.execute(select(EntityJobLink.entity_id).where(EntityJobLink.job_id == job_id)).all()}
    if not entity_ids:
        return

    db.execute(delete(EntityJobLink).where(EntityJobLink.job_id == job_id))

    remaining_counts = {
        row[0]: row[1] for row in db.execute(select(EntityJobLink.entity_id, func.count()).where(EntityJobLink.entity_id.in_(entity_ids)).group_by(EntityJobLink.entity_id)).all()
    }
    entities = db.execute(select(Entity).where(Entity.id.in_(entity_ids))).scalars().all()

    orphan_ids = []
    for entity in entities:
        remaining = remaining_counts.get(entity.id, 0)
        if remaining == 0:
            orphan_ids.append(entity.id)
        else:
            entity.job_count = int(remaining)

    if orphan_ids:
        # Every table referencing Entity, for the reason the async twin spells out: a Core
        # delete fires no ORM cascade, so a missed table dangles silently on SQLite and
        # raises ForeignKeyViolation on PostgreSQL.
        orphan_rel_subq = select(EntityRelationship.id).where(or_(EntityRelationship.source_entity_id.in_(orphan_ids), EntityRelationship.target_entity_id.in_(orphan_ids)))
        db.execute(delete(EntityRelationshipEvidence).where(EntityRelationshipEvidence.relationship_id.in_(orphan_rel_subq)))
        db.execute(delete(EntityRelationship).where(or_(EntityRelationship.source_entity_id.in_(orphan_ids), EntityRelationship.target_entity_id.in_(orphan_ids))))
        db.execute(delete(EntityEnrichmentResult).where(EntityEnrichmentResult.entity_id.in_(orphan_ids)))
        db.execute(delete(Comment).where(Comment.entity_id.in_(orphan_ids)))
        db.execute(delete(CaseEntityLink).where(CaseEntityLink.entity_id.in_(orphan_ids)))
        db.execute(delete(EntityTag).where(EntityTag.entity_id.in_(orphan_ids)))
        db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.entity_id.in_(orphan_ids)))
        orphan_auto_rules = select(IntelRule.id).where(IntelRule.auto_entity_id.in_(orphan_ids))
        db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.rule_id.in_(orphan_auto_rules)))
        db.execute(delete(JobRuleMatch).where(JobRuleMatch.rule_id.in_(orphan_auto_rules)))
        db.execute(delete(WebhookDelivery).where(WebhookDelivery.rule_id.in_(orphan_auto_rules)))
        db.execute(delete(IntelRule).where(IntelRule.auto_entity_id.in_(orphan_ids)))
        db.execute(delete(FindingEntityLink).where(FindingEntityLink.entity_id.in_(orphan_ids)))
        db.execute(delete(Entity).where(Entity.id.in_(orphan_ids)))
