"""Integration tests: the "Associated Entities" card on the entity detail page."""

from __future__ import annotations

import pytest


async def _exe_with_hash(async_db):
    from app.models import Entity, EntityRelationship

    exe = Entity(value="powershell.exe", entity_type="executable", job_count=1)
    h = Entity(value="B" * 64, entity_type="hash", job_count=1)
    async_db.add_all([exe, h])
    await async_db.commit()
    async_db.add(EntityRelationship(source_entity_id=exe.id, target_entity_id=h.id, relationship_type="hashes_to", occurrence_count=2))
    await async_db.commit()
    return exe, h


@pytest.mark.asyncio
async def test_exe_page_shows_hash_association(member_client, async_db):
    exe, h = await _exe_with_hash(async_db)

    resp = await member_client.get(f"/intel/entities/{exe.id}")
    assert resp.status_code == 200
    body = resp.text
    assert "Associated Entities" in body
    assert "Hashes" in body  # group label for hashes_to out
    assert "B" * 64 in body
    assert f"/intel/entities/{h.id}" in body


@pytest.mark.asyncio
async def test_hash_page_shows_filenames_group(member_client, async_db):
    exe, h = await _exe_with_hash(async_db)

    resp = await member_client.get(f"/intel/entities/{h.id}")
    assert resp.status_code == 200
    body = resp.text
    assert "Associated Entities" in body
    assert "Filenames" in body  # group label for hashes_to in
    assert "powershell.exe" in body
    assert f"/intel/entities/{exe.id}" in body


@pytest.mark.asyncio
async def test_card_hidden_without_relationships(member_client, async_db):
    from app.models import Entity

    e = Entity(value="lonely.exe", entity_type="executable", job_count=1)
    async_db.add(e)
    await async_db.commit()

    resp = await member_client.get(f"/intel/entities/{e.id}")
    assert resp.status_code == 200
    assert "Associated Entities" not in resp.text


@pytest.mark.asyncio
async def test_overflow_button_renders(member_client, async_db):
    from app.models import Entity, EntityRelationship

    exe = Entity(value="dropper.exe", entity_type="executable", job_count=1)
    async_db.add(exe)
    await async_db.commit()
    hashes = [Entity(value=f"{i:064X}", entity_type="hash", job_count=1) for i in range(12)]
    async_db.add_all(hashes)
    await async_db.commit()
    async_db.add_all([EntityRelationship(source_entity_id=exe.id, target_entity_id=h.id, relationship_type="hashes_to", occurrence_count=i + 1) for i, h in enumerate(hashes)])
    await async_db.commit()

    resp = await member_client.get(f"/intel/entities/{exe.id}")
    assert resp.status_code == 200
    body = resp.text
    assert "Associated Entities" in body
    assert "+2 more" in body
    # Top-occurrence edges make the cut; the two lowest overflow.
    assert f"{11:064X}" in body
    assert f"{0:064X}" not in body


@pytest.mark.asyncio
async def test_symmetric_connects_to_renders_both_directions(member_client, async_db):
    from app.models import Entity, EntityRelationship

    ip_a = Entity(value="8.8.8.8", entity_type="ip_address", job_count=1)
    ip_b = Entity(value="9.9.9.9", entity_type="ip_address", job_count=1)
    ip_c = Entity(value="1.1.1.1", entity_type="ip_address", job_count=1)
    async_db.add_all([ip_a, ip_b, ip_c])
    await async_db.commit()
    async_db.add_all(
        [
            EntityRelationship(source_entity_id=ip_a.id, target_entity_id=ip_b.id, relationship_type="connects_to", occurrence_count=1),
            EntityRelationship(source_entity_id=ip_c.id, target_entity_id=ip_a.id, relationship_type="connects_to", occurrence_count=1),
        ]
    )
    await async_db.commit()

    resp = await member_client.get(f"/intel/entities/{ip_a.id}")
    assert resp.status_code == 200
    body = resp.text
    assert "Connects to" in body
    assert "Inbound connections" in body
    assert "9.9.9.9" in body
    assert "1.1.1.1" in body
