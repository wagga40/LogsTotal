"""Integration test: the relationships-partial endpoint renders for a member."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_relationships_partial_renders(member_client, async_db):
    from app.models import Entity, EntityRelationship

    exe = Entity(value="powershell.exe", entity_type="executable", job_count=1)
    h = Entity(value="A" * 64, entity_type="hash", job_count=1)
    async_db.add_all([exe, h])
    await async_db.commit()
    async_db.add(EntityRelationship(source_entity_id=exe.id, target_entity_id=h.id, relationship_type="hashes_to", occurrence_count=2))
    await async_db.commit()

    resp = await member_client.get(f"/intel/entities/{exe.id}/relationships-partial")
    assert resp.status_code == 200
    body = resp.text
    assert "hashes to" in body  # human label
    assert "A" * 64 in body  # the linked hash entity value
    assert "outgoing" in body


@pytest.mark.asyncio
async def test_relationships_partial_empty_state(member_client, async_db):
    from app.models import Entity

    e = Entity(value="lonely.exe", entity_type="executable", job_count=1)
    async_db.add(e)
    await async_db.commit()

    resp = await member_client.get(f"/intel/entities/{e.id}/relationships-partial")
    assert resp.status_code == 200
    assert "No typed relationships" in resp.text


@pytest.mark.asyncio
async def test_relationships_partial_requires_member(user_client, async_db):
    from app.models import Entity

    e = Entity(value="x.exe", entity_type="executable", job_count=1)
    async_db.add(e)
    await async_db.commit()

    resp = await user_client.get(f"/intel/entities/{e.id}/relationships-partial")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_relationship_evidence_partial_renders_jobs_and_events(member_client, async_db):
    from app.json_utils import dumps as json_dumps
    from app.models import (
        AnalysisJob,
        Entity,
        EntityJobLink,
        EntityRelationship,
        EntityRelationshipEvidence,
        JobStatus,
        LogFile,
        WorkflowDef,
    )

    exe = Entity(value="evil.exe", entity_type="executable", job_count=1)
    host = Entity(value="WS01", entity_type="computer", job_count=1)
    async_db.add_all([exe, host])
    await async_db.commit()

    rel = EntityRelationship(source_entity_id=exe.id, target_entity_id=host.id, relationship_type="runs_on", occurrence_count=3)
    lf = LogFile(original_filename="eve.evtx", stored_filename="s.evtx", sha256="z" * 64, size_bytes=1)
    wf = WorkflowDef(name="wf")
    async_db.add_all([rel, lf, wf])
    await async_db.commit()

    job = AnalysisJob(submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.commit()

    # Both endpoints co-occur in the job, and an evidence sample exists.
    async_db.add_all(
        [
            EntityJobLink(entity_id=exe.id, job_id=job.id, occurrence_count=1),
            EntityJobLink(entity_id=host.id, job_id=job.id, occurrence_count=1),
            EntityRelationshipEvidence(
                relationship_id=rel.id,
                job_id=job.id,
                occurrence_count=3,
                sample_events_json=json_dumps([{"EventID": 1, "Image": "evil.exe", "Computer": "WS01"}]),
            ),
        ]
    )
    await async_db.commit()

    resp = await member_client.get(f"/intel/relationships/{rel.id}/evidence-partial")
    assert resp.status_code == 200
    body = resp.text
    assert f"/jobs/{job.id}" in body  # job link
    assert "eve.evtx" in body  # filename
    assert "evil.exe" in body  # event sample content


@pytest.mark.asyncio
async def test_relationship_evidence_partial_empty_when_no_cooccurrence(member_client, async_db):
    from app.models import Entity, EntityRelationship

    a = Entity(value="a.exe", entity_type="executable", job_count=0)
    b = Entity(value="b.exe", entity_type="executable", job_count=0)
    async_db.add_all([a, b])
    await async_db.commit()
    rel = EntityRelationship(source_entity_id=a.id, target_entity_id=b.id, relationship_type="parent_of", occurrence_count=1)
    async_db.add(rel)
    await async_db.commit()

    resp = await member_client.get(f"/intel/relationships/{rel.id}/evidence-partial")
    assert resp.status_code == 200
    assert "No jobs found" in resp.text


@pytest.mark.asyncio
async def test_relationship_evidence_partial_404_for_missing(member_client, async_db):
    resp = await member_client.get("/intel/relationships/99999/evidence-partial")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_relationship_evidence_partial_requires_member(user_client, async_db):
    resp = await user_client.get("/intel/relationships/1/evidence-partial")
    assert resp.status_code == 403
