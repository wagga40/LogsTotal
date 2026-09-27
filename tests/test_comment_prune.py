"""Soft-deleted comment tombstones are hard-deleted after a retention window.

Deleting a comment blanks its body but keeps the row, so the audit trail survives the
text. Those tombstones accumulated forever. This prunes them on the same daily cadence
as the token and enrichment prunes, and — the easy way to get it wrong — compares naive
datetimes, since `Comment.deleted_at` is written naive and an aware comparison raises on
PostgreSQL.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.database import utc_now_naive
from app.models import AnalysisJob, Comment, JobStatus, LogFile, LogType, WorkflowDef
from app.workers.tasks import COMMENT_TOMBSTONE_RETENTION_DAYS


@pytest.fixture()
def commented_job(sync_db):
    wf = WorkflowDef(name="P WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    sync_db.add(wf)
    sync_db.flush()
    lf = LogFile(original_filename="p.evtx", stored_filename="p.evtx", sha256="7" * 64, size_bytes=10, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    sync_db.add(lf)
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    sync_db.add(job)
    sync_db.commit()
    return job


def _comment(job, *, body="hello", deleted_days_ago=None):
    deleted_at = None if deleted_days_ago is None else utc_now_naive() - timedelta(days=deleted_days_ago)
    return Comment(job_id=job.id, body="" if deleted_at else body, deleted_at=deleted_at)


def _run(sync_db, monkeypatch):
    import app.workers.tasks as tasks_mod

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    tasks_mod.prune_deleted_comments_periodic.call_local()
    sync_db.expire_all()
    return sync_db.execute(select(Comment)).scalars().all()


def test_old_tombstones_are_removed(sync_db, commented_job, monkeypatch):
    sync_db.add(_comment(commented_job, deleted_days_ago=COMMENT_TOMBSTONE_RETENTION_DAYS + 10))
    sync_db.commit()
    assert _run(sync_db, monkeypatch) == []


def test_recent_tombstones_are_kept(sync_db, commented_job, monkeypatch):
    """The window is the point — a deletion from last week is still accountable."""
    sync_db.add(_comment(commented_job, deleted_days_ago=7))
    sync_db.commit()
    assert len(_run(sync_db, monkeypatch)) == 1


def test_live_comments_are_never_touched(sync_db, commented_job, monkeypatch):
    """Filtering on a blank body rather than deleted_at would eat a live empty comment."""
    sync_db.add(_comment(commented_job, body=""))
    sync_db.add(_comment(commented_job, body="still here"))
    sync_db.commit()
    remaining = _run(sync_db, monkeypatch)
    assert len(remaining) == 2
    assert all(c.deleted_at is None for c in remaining)


def test_only_the_expired_tombstone_goes(sync_db, commented_job, monkeypatch):
    sync_db.add(_comment(commented_job, body="live"))
    sync_db.add(_comment(commented_job, deleted_days_ago=5))
    sync_db.add(_comment(commented_job, deleted_days_ago=COMMENT_TOMBSTONE_RETENTION_DAYS + 1))
    sync_db.commit()
    remaining = _run(sync_db, monkeypatch)
    assert len(remaining) == 2


def test_prune_is_idempotent_and_safe_on_an_empty_table(sync_db, commented_job, monkeypatch):
    assert _run(sync_db, monkeypatch) == []
    assert _run(sync_db, monkeypatch) == []


def test_retention_is_a_module_constant_not_a_settings_field():
    """A Settings field would force .env.example + docs/configuration.md + the docs-sync
    guards for a value no operator needs to tune."""
    from app.config import settings

    assert isinstance(COMMENT_TOMBSTONE_RETENTION_DAYS, int)
    assert not hasattr(settings, "comment_tombstone_retention_days")
