"""The instance-wide exports must not aggregate other people's private jobs.

`/intel/ioc-feed` and `/intel/mitre-layer` are the two Intel endpoints that summarise
*everything* rather than one entity or one case, and both were built with no viewer at
all — `_build_ioc_data` took no user argument, and `_build_mitre_layer` filtered on job
*status* only. A member therefore received threat categories, severities and ATT&CK
technique scores computed from private jobs belonging to other members, and the same
values flowed into the STIX and MISP renderings of the feed.

The leak is a summary rather than a document, which is what let it survive: nothing in the
output names the job it came from, so it looks like aggregate intelligence until you notice
the aggregate includes rows the viewer cannot open.

Each test asserts on a marker that exists *only* in the private job, so a failure names the
leak instead of a count being off by one.
"""

from __future__ import annotations

import json

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    Finding,
    JobStatus,
    LogFile,
    TaskResult,
    TaskStatus,
    User,
    WorkflowDef,
)

pytestmark = pytest.mark.anyio

# A technique that appears only in the private job.
SECRET_TECHNIQUE = "T1003"
PUBLIC_TECHNIQUE = "T1059"
# A threat category that appears only in the private job's analytics blob.
SECRET_CATEGORY = "credential_dumping"


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    manager = UserManager(SQLAlchemyUserDatabase(async_db, User))
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


def _analytics(category: str) -> str:
    return json.dumps({"threat_detection": {"categories": {category: {"indicators": ["x"], "severity": "critical"}}}})


@pytest.fixture()
async def world(async_db):
    """One public job and one private job owned by somebody else, each with a finding.

    The shared entity is the important part: it is linked to *both* jobs, so the viewer
    legitimately sees the entity and the only question is whether the private job's
    threat context rides along with it.
    """
    async_db.add_all(
        [
            LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10),
            LogFile(id=2, original_filename="b.evtx", stored_filename="f2.evtx", sha256="b" * 64, size_bytes=10),
            WorkflowDef(id=1, name="wf"),
        ]
    )
    await async_db.commit()

    owner = await _create_user(async_db, email="owner@exp.example.com")
    viewer = await _create_user(async_db, email="viewer@exp.example.com")

    public = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False, analytics_json=_analytics("persistence"))
    private = AnalysisJob(
        file_id=2,
        workflow_id=1,
        status=JobStatus.COMPLETED,
        is_private=True,
        submitted_by_user_id=owner.id,
        analytics_json=_analytics(SECRET_CATEGORY),
    )
    shared = Entity(value="8.8.8.8", entity_type="ip_address", job_count=2)
    async_db.add_all([public, private, shared])
    await async_db.commit()
    for obj in (public, private, shared):
        await async_db.refresh(obj)

    async_db.add_all(
        [
            EntityJobLink(entity_id=shared.id, job_id=public.id),
            EntityJobLink(entity_id=shared.id, job_id=private.id),
        ]
    )
    pub_task = TaskResult(job_id=public.id, tool_name="zircolite", status=TaskStatus.COMPLETED)
    priv_task = TaskResult(job_id=private.id, tool_name="zircolite", status=TaskStatus.COMPLETED)
    async_db.add_all([pub_task, priv_task])
    await async_db.commit()
    for obj in (pub_task, priv_task):
        await async_db.refresh(obj)

    async_db.add_all(
        [
            Finding(task_result_id=pub_task.id, rule_id="r1", rule_name="public rule", severity="high", count=1, tags=json.dumps([f"attack.{PUBLIC_TECHNIQUE.lower()}"])),
            Finding(task_result_id=priv_task.id, rule_id="r2", rule_name="private rule", severity="high", count=5, tags=json.dumps([f"attack.{SECRET_TECHNIQUE.lower()}"])),
        ]
    )
    await async_db.commit()
    return {"public": public, "private": private, "owner": owner, "viewer": viewer}


# ── IOC feed ─────────────────────────────────────────────────────────────────


async def test_ioc_feed_hides_threat_context_from_a_private_job(test_client, world):
    await _login(test_client, "viewer@exp.example.com")
    resp = await test_client.get("/intel/ioc-feed")
    assert resp.status_code == 200
    assert SECRET_CATEGORY not in resp.text, "private job's threat categories leaked into the IOC feed"
    # The entity itself is shared intelligence and still appears, with the public context.
    assert "8.8.8.8" in resp.text
    assert "persistence" in resp.text


@pytest.mark.parametrize("fmt", ["csv", "stix", "misp"])
async def test_every_ioc_feed_format_is_scoped(test_client, world, fmt):
    """All four renderings go through one builder, so none can disagree about scope."""
    await _login(test_client, "viewer@exp.example.com")
    resp = await test_client.get(f"/intel/ioc-feed?format={fmt}")
    assert resp.status_code == 200
    assert SECRET_CATEGORY not in resp.text


async def test_the_owner_still_sees_their_own_private_context(test_client, world):
    """Scoping must not blind people to their own data."""
    await _login(test_client, "owner@exp.example.com")
    resp = await test_client.get("/intel/ioc-feed")
    assert SECRET_CATEGORY in resp.text


async def test_an_admin_sees_everything(admin_client, world):
    resp = await admin_client.get("/intel/ioc-feed")
    assert SECRET_CATEGORY in resp.text


# ── MITRE Navigator layer ────────────────────────────────────────────────────


async def test_mitre_layer_excludes_private_jobs(test_client, world):
    await _login(test_client, "viewer@exp.example.com")
    resp = await test_client.get("/intel/mitre-layer")
    assert resp.status_code == 200
    ids = {t["techniqueID"] for t in resp.json()["techniques"]}
    assert SECRET_TECHNIQUE not in ids, "a private job's ATT&CK techniques leaked into the aggregate layer"
    assert PUBLIC_TECHNIQUE in ids


async def test_mitre_layer_includes_your_own_private_jobs(test_client, world):
    await _login(test_client, "owner@exp.example.com")
    resp = await test_client.get("/intel/mitre-layer")
    ids = {t["techniqueID"] for t in resp.json()["techniques"]}
    assert SECRET_TECHNIQUE in ids


async def test_mitre_layer_for_an_admin_covers_the_instance(admin_client, world):
    resp = await admin_client.get("/intel/mitre-layer")
    ids = {t["techniqueID"] for t in resp.json()["techniques"]}
    assert {SECRET_TECHNIQUE, PUBLIC_TECHNIQUE} <= ids
