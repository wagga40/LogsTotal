"""The Intel dashboard stat tiles must count only what the viewer can open.

`/intel` renders six counts above the entity table. Four were viewer-scoped —
`unacked_alerts` goes through `_visible_rules(user)`, and the entity
counts are instance-wide by design because entities are shared intelligence. Two were not:

- **Jobs with entities** counted every `EntityJobLink.job_id`, including jobs a member
  cannot open, so the tile reported other users' private submissions.
- **Open cases** counted every non-closed `InvestigationCase`, ignoring `is_shared`, so a
  member with no visible cases was shown a number and clicked through to an empty list.

A leaked *count* is quieter than a leaked document, which is why it survived: nothing on
the page names the row it came from. It still discloses activity volume — how many private
jobs another member has run — and the empty list on click-through is the tell.

Each test asserts the exact number, not merely "not the leaked one", so an over-correction
that hides the viewer's own rows fails too.
"""

from __future__ import annotations

import re

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    InvestigationCase,
    JobStatus,
    LogFile,
    User,
    WorkflowDef,
)

pytestmark = pytest.mark.anyio


async def _create_user(async_db, *, email: str, role: str = "member", is_superuser: bool = False) -> User:
    manager = UserManager(SQLAlchemyUserDatabase(async_db, User))
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=is_superuser, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


def _tile(html: str, label: str) -> int:
    """Read a stat tile's number out of the rendered dashboard.

    Anchored on the tile's own value/label pair rather than on the label alone: "Cases" also
    appears in the nav, and a bare `find` locates that instead — which is how a first draft
    of this test read a number that was not the one under test.
    """
    match = re.search(
        r'<div class="text-lg font-bold[^"]*">\s*([\d,]+)\s*</div>\s*<div class="text-\[11px\] text-gray-400">\s*' + re.escape(label) + r"\s*</div>",
        html,
    )
    assert match, f"stat tile {label!r} not found on the dashboard"
    return int(match.group(1).replace(",", ""))


@pytest.fixture()
async def world(async_db):
    """Three jobs and three cases, split across two members.

    Viewer can see: the public job, their own private job, their own case, the shared case.
    Viewer must not count: the other member's private job, the other member's unshared case.
    """
    async_db.add_all(
        [
            LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10),
            LogFile(id=2, original_filename="b.evtx", stored_filename="f2.evtx", sha256="b" * 64, size_bytes=10),
            LogFile(id=3, original_filename="c.evtx", stored_filename="f3.evtx", sha256="c" * 64, size_bytes=10),
            WorkflowDef(id=1, name="wf"),
        ]
    )
    await async_db.commit()

    owner = await _create_user(async_db, email="owner@cnt.example.com")
    viewer = await _create_user(async_db, email="viewer@cnt.example.com")
    admin = await _create_user(async_db, email="admin@cnt.example.com", role="admin", is_superuser=True)

    public = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    mine = AnalysisJob(file_id=2, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=viewer.id)
    theirs = AnalysisJob(file_id=3, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner.id)
    entity = Entity(value="8.8.8.8", entity_type="ip_address", job_count=3)
    async_db.add_all([public, mine, theirs, entity])
    await async_db.commit()
    for obj in (public, mine, theirs, entity):
        await async_db.refresh(obj)

    # The entity appears in all three jobs, so "jobs with entities" is exactly the
    # visibility question and nothing else.
    async_db.add_all(
        [
            EntityJobLink(entity_id=entity.id, job_id=public.id),
            EntityJobLink(entity_id=entity.id, job_id=mine.id),
            EntityJobLink(entity_id=entity.id, job_id=theirs.id),
            InvestigationCase(name="mine", status="open", created_by_user_id=viewer.id, is_shared=False),
            InvestigationCase(name="shared", status="open", created_by_user_id=owner.id, is_shared=True),
            InvestigationCase(name="theirs", status="open", created_by_user_id=owner.id, is_shared=False),
            # Closed cases are excluded for everyone — pinned so the visibility fix cannot
            # be mistaken for having changed the status filter.
            InvestigationCase(name="closed-shared", status="closed", created_by_user_id=owner.id, is_shared=True),
        ]
    )
    await async_db.commit()
    return {"viewer": viewer, "owner": owner, "admin": admin}


async def test_jobs_with_entities_excludes_other_users_private_jobs(test_client, world):
    await _login(test_client, "viewer@cnt.example.com")
    resp = await test_client.get("/intel")
    assert resp.status_code == 200
    # Public + the viewer's own private job. Not the third.
    assert _tile(resp.text, "Jobs Analyzed") == 2


async def test_open_cases_excludes_other_users_unshared_cases(test_client, world):
    await _login(test_client, "viewer@cnt.example.com")
    resp = await test_client.get("/intel")
    assert resp.status_code == 200
    # The viewer's own open case + the shared open one. Not the third, not the closed one.
    assert _tile(resp.text, "Cases") == 2


async def test_an_admin_still_sees_everything(test_client, world):
    """`visible_job_filter` / `visible_case_filter` return literal True for a superuser.

    Scoping a count is only correct if it does not also hide rows from the people who are
    meant to see them — an over-correction here reads as data loss on the admin dashboard.
    """
    await _login(test_client, "admin@cnt.example.com")
    resp = await test_client.get("/intel")
    assert resp.status_code == 200
    assert _tile(resp.text, "Jobs Analyzed") == 3
    assert _tile(resp.text, "Cases") == 3
