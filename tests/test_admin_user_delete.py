"""Deleting a user must not orphan or destroy the rows that reference them.

No ``ForeignKey("user.id")`` in app/models.py carries ``ondelete=``, and SQLite runs
with FK enforcement off, so a bare ``db.delete(user)`` "succeeds" locally while leaving
dangling ``submitted_by_user_id`` values — and raises ``ForeignKeyViolation`` on
PostgreSQL. These tests pin the anonymise-don't-orphan contract.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import (
    AnalysisJob,
    ApiToken,
    Comment,
    InvestigationCase,
    JobStatus,
    LogFile,
    LogType,
    User,
    WorkflowDef,
)


@pytest.fixture()
async def user_owned_rows(async_db, regular_user):
    """A job, a private job, a case, a comment and an API token owned by regular_user."""
    wf = WorkflowDef(name="Del WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()

    lf = LogFile(
        original_filename="owned.evtx",
        stored_filename="del_owned.evtx",
        sha256="d" * 64,
        size_bytes=1024,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(lf)
    await async_db.flush()

    public_job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=regular_user.id, is_private=False)
    private_job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=regular_user.id, is_private=True)
    case = InvestigationCase(name="Owned case", status="open", created_by_user_id=regular_user.id, is_shared=True)
    async_db.add_all([public_job, private_job, case])
    await async_db.flush()

    comment = Comment(job_id=public_job.id, author_user_id=regular_user.id, body="a note the team still needs")
    token = ApiToken(name="tok", token_hash="e" * 64, prefix="abcd1234", scopes_json='["ioc_feed:read"]', created_by_user_id=regular_user.id)
    async_db.add_all([comment, token])
    await async_db.commit()
    return {"public_job": public_job.id, "private_job": private_job.id, "case": case.id, "comment": comment.id}


async def test_delete_user_succeeds_and_removes_the_account(admin_client, async_db, regular_user, user_owned_rows):
    resp = await admin_client.post(f"/admin/users/{regular_user.id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert await async_db.get(User, regular_user.id) is None


async def test_delete_user_anonymises_rather_than_orphans(admin_client, async_db, regular_user, user_owned_rows):
    """Jobs, cases and comments survive with a NULL owner — no dangling user id."""
    await admin_client.post(f"/admin/users/{regular_user.id}/delete", follow_redirects=False)
    async_db.expire_all()

    for job_id in (user_owned_rows["public_job"], user_owned_rows["private_job"]):
        job = await async_db.get(AnalysisJob, job_id)
        assert job is not None, "deleting a user must not delete their jobs"
        assert job.submitted_by_user_id is None

    case = await async_db.get(InvestigationCase, user_owned_rows["case"])
    assert case is not None and case.created_by_user_id is None

    comment = await async_db.get(Comment, user_owned_rows["comment"])
    assert comment is not None and comment.author_user_id is None
    assert comment.body == "a note the team still needs"


async def test_delete_user_revokes_their_api_tokens(admin_client, async_db, regular_user, user_owned_rows):
    """A token is a live credential, not authorship — it must not outlive its owner."""
    await admin_client.post(f"/admin/users/{regular_user.id}/delete", follow_redirects=False)
    assert (await async_db.execute(select(ApiToken))).scalars().all() == []


async def test_no_user_reference_is_left_dangling(admin_client, async_db, regular_user, user_owned_rows):
    """Every FK to user.id is covered — the check PostgreSQL would enforce for us."""
    from app.routers.admin import _USER_REFERENCES

    await admin_client.post(f"/admin/users/{regular_user.id}/delete", follow_redirects=False)
    for model, column in _USER_REFERENCES:
        stale = (await async_db.execute(select(model).where(getattr(model, column) == regular_user.id))).scalars().all()
        assert stale == [], f"{model.__name__}.{column} still references the deleted user"
