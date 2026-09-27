"""`GET /intel/relationships/{id}/timespan.json` — when an edge was actually observed.

The graph's edge panel is where an analyst decides whether a typed relationship is worth
believing, so this endpoint is written to refuse three specific lies:

  * `EntityRelationship.first_seen_at`/`last_seen_at` are ``server_default=func.now()`` —
    ingest wall-clock, not event time. They are still reported when nothing better exists,
    but always behind `time_source: "ingest"`.
  * timestamps are parsed as strict UTC (`event_epoch_seconds`), not with the histogram's
    offset-preserving normaliser, or a job mixing `+09:00` and `Z` places one edge hours
    apart from itself.
  * evidence is sampled at `EVIDENCE_CAP` per edge per job, so the window is a sample and
    the response says so.

Plus the usual: evidence rows are filtered to jobs the viewer may see.
"""

from __future__ import annotations

import json

import pytest

from app.models import (
    AnalysisJob,
    Entity,
    EntityRelationship,
    EntityRelationshipEvidence,
    JobStatus,
    LogFile,
    WorkflowDef,
)


@pytest.fixture()
async def edge(async_db):
    """A `domain -resolves_to-> ip` edge with no evidence yet."""
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="x" * 64, size_bytes=1))
    async_db.add(WorkflowDef(id=1, name="wf1"))
    await async_db.commit()
    src = Entity(value="evil.example", entity_type="domain")
    tgt = Entity(value="1.2.3.4", entity_type="ip_address")
    async_db.add_all([src, tgt])
    await async_db.commit()
    rel = EntityRelationship(source_entity_id=src.id, target_entity_id=tgt.id, relationship_type="resolves_to", occurrence_count=7)
    async_db.add(rel)
    await async_db.commit()
    await async_db.refresh(rel)
    return rel


async def _job(async_db, jid, *, private=False, owner=None):
    job = AnalysisJob(id=jid, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=private, submitted_by_user_id=owner)
    async_db.add(job)
    await async_db.commit()
    return job


async def _evidence(async_db, rel, job_id, events, occ=1):
    async_db.add(
        EntityRelationshipEvidence(
            relationship_id=rel.id,
            job_id=job_id,
            occurrence_count=occ,
            sample_events_json=json.dumps(events),
        )
    )
    await async_db.commit()


async def test_event_timestamps_win_over_ingest_time(member_client, async_db, edge):
    await _job(async_db, 1)
    await _evidence(
        async_db,
        edge,
        1,
        [{"UtcTime": "2024-01-05 12:00:00"}, {"UtcTime": "2024-01-05 18:30:00"}],
    )

    body = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    assert body["time_source"] == "event"
    assert body["from"] == 1704456000_000
    assert body["to"] == 1704479400_000
    assert body["sampled"] is True
    assert body["sample_cap"] == 3


async def test_offsets_are_normalised_to_utc_not_preserved(member_client, async_db, edge):
    """A job mixing `+09:00` and `Z` must not place one edge hours apart from itself.

    `normalize_event_time` deliberately preserves the offset verbatim for the histogram;
    this endpoint deliberately does not.
    """
    await _job(async_db, 1)
    await _evidence(async_db, edge, 1, [{"Timestamp": "2024-01-05T21:00:00+09:00"}, {"Timestamp": "2024-01-05T12:00:00Z"}])

    body = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    # Both are the same instant in UTC, so the window has zero width.
    assert body["from"] == body["to"] == 1704456000_000


async def test_falls_back_to_ingest_time_and_labels_it(member_client, async_db, edge):
    """Linux/auditd relationships land here: EVIDENCE_FIELDS is deliberately not widened
    to carry free-form auditd `msg=` bodies, so there is no event timestamp to parse."""
    await _job(async_db, 1)
    await _evidence(async_db, edge, 1, [{"Computer": "host01", "Image": "/usr/bin/curl"}])

    body = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    assert body["time_source"] == "ingest"
    assert body["sampled"] is False
    assert body["from"] is not None


async def test_no_evidence_at_all_still_answers(member_client, async_db, edge):
    body = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    assert body["time_source"] == "ingest"
    assert body["jobs"] == 0
    assert body["occurrence_count"] == 7


async def test_private_job_evidence_is_invisible_to_a_stranger(member_client, async_db, edge, admin_user):
    """Sample-event timestamps and per-job counts from a private job must not leak.

    Precedent: `relationship_evidence_partial` already applies this filter, and the graph
    makes typed edges far more prominent — an arrow, a label, and the only kind a path
    traverses — so someone will read this panel and assume it is scoped.

    `member_client` and `admin_client` are the *same* httpx client, so requesting both
    fixtures would have the second login silently replace the first cookie. The admin half
    logs in explicitly, after the member assertion has run.
    """
    await _job(async_db, 1, private=True, owner=admin_user.id)
    await _evidence(async_db, edge, 1, [{"UtcTime": "2024-01-05 12:00:00"}])

    stranger = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    assert stranger["time_source"] == "ingest", "a private job's event timestamps leaked into the window"
    assert stranger["jobs"] == 0
    assert stranger["evidence_occurrences"] == 0

    await member_client.post("/auth/cookie/login", data={"username": "admin@test.example.com", "password": "testpass123"})
    owner = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    assert owner["time_source"] == "event"


async def test_public_job_evidence_is_visible(member_client, async_db, edge):
    await _job(async_db, 1, private=False)
    await _evidence(async_db, edge, 1, [{"UtcTime": "2024-01-05 12:00:00"}], occ=4)

    body = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    assert body["time_source"] == "event"
    assert body["evidence_occurrences"] == 4


async def test_unknown_relationship_is_404(member_client):
    assert (await member_client.get("/intel/relationships/999999/timespan.json")).status_code == 404


async def test_requires_member_or_above(test_client, edge):
    assert (await test_client.get(f"/intel/relationships/{edge.id}/timespan.json")).status_code in (401, 403)


async def test_malformed_sample_json_is_survivable(member_client, async_db, edge):
    await _job(async_db, 1)
    async_db.add(EntityRelationshipEvidence(relationship_id=edge.id, job_id=1, occurrence_count=1, sample_events_json="{not json"))
    await async_db.commit()

    body = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    assert body["time_source"] == "ingest"


async def test_the_ingest_fallback_is_utc_whatever_the_hosts_timezone(member_client, async_db, edge, monkeypatch):
    """`first_seen_at` is stored as naive UTC. `datetime.timestamp()` on a naive value reads it
    as *local* time, so on a host set to Europe/Paris the window came back an hour early."""
    import time
    from datetime import datetime

    monkeypatch.setenv("TZ", "Asia/Tokyo")
    time.tzset()
    try:
        edge.first_seen_at = datetime(2026, 3, 14, 3, 7)
        edge.last_seen_at = datetime(2026, 3, 14, 3, 7)
        await async_db.commit()
        body = (await member_client.get(f"/intel/relationships/{edge.id}/timespan.json")).json()
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()
    assert body["time_source"] == "ingest"
    assert body["from"] == body["to"] == 1773457620_000  # 2026-03-14T03:07:00Z
