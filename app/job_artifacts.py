"""Per-job derived results (`JobArtifact`): write once in the analytics pass, read cheaply.

Pure pack/unpack plus sync writers for the worker and async readers for routes. A reader asks
for a `(kind, version)` pair, and a row of another version counts as absent, so a shape change
only needs the version bumped: old rows fall back to the raw-output path until recalculated.
"""

from __future__ import annotations

from typing import Any

import orjson
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.compression_utils import compress, decompress
from app.models import JobArtifact

#: Hourly MITRE buckets, mergeable across jobs: `{iso_hour: {tactic: count}}`.
TL_BUCKETS = ("tl_buckets", 1)
#: The unfiltered, hit-anchored process forest `lineage.build_process_forest` returns.
#: Version 4 matches the Redis cache key it replaces (`logstotal:proctree:v4`).
PROC_FOREST = ("proc_forest", 4)


def pack(obj: Any) -> bytes:
    return compress(orjson.dumps(obj))


def unpack(payload: bytes) -> Any:
    return orjson.loads(decompress(payload))


def put_sync(db, job_id: int, artifact: tuple[str, int], obj: Any) -> None:
    """Insert or replace one artifact. The caller commits."""
    kind, version = artifact
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    stmt = insert(JobArtifact).values(job_id=job_id, kind=kind, version=version, payload=pack(obj))
    db.execute(stmt.on_conflict_do_update(index_elements=["job_id", "kind"], set_={"version": stmt.excluded.version, "payload": stmt.excluded.payload}))


def get_sync(db, job_id: int, artifact: tuple[str, int]) -> Any | None:
    kind, version = artifact
    payload = db.scalar(select(JobArtifact.payload).where(JobArtifact.job_id == job_id, JobArtifact.kind == kind, JobArtifact.version == version))
    return unpack(payload) if payload is not None else None


async def get_payload(db, job_id: int, artifact: tuple[str, int]) -> bytes | None:
    """The packed bytes, for handing to a threadpool hop without an ORM object."""
    kind, version = artifact
    return await db.scalar(select(JobArtifact.payload).where(JobArtifact.job_id == job_id, JobArtifact.kind == kind, JobArtifact.version == version))


async def get_many(db, job_ids: list[int], artifact: tuple[str, int]) -> dict[int, Any]:
    kind, version = artifact
    if not job_ids:
        return {}
    rows = await db.execute(select(JobArtifact.job_id, JobArtifact.payload).where(JobArtifact.job_id.in_(job_ids), JobArtifact.kind == kind, JobArtifact.version == version))
    return {job_id: unpack(payload) for job_id, payload in rows.all()}
