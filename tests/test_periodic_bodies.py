"""The nightly `_…_periodic_body` sweeps, which nothing covered.

Each periodic task is a thin `_ScheduledRun` wrapper around a plain function so the run's
detail line has somewhere to come from — and not one of those functions had a test. Two
bugs shipped through that gap, and both only bite an operator who moved a default away
from the value the suite runs with:

* the output sweep gated on the environment variable alone, so an instance with
  `JOB_OUTPUT_RETENTION_DAYS=0` and a window set from /admin/storage swept nothing every
  night while the page promised otherwise;
* the upload prune deleted the file before the commit that deletes the row, so a job with
  entity links took an `IntegrityError`, the rollback restored the row, and the upload was
  gone for good — one destroyed log file per run, on the same row, forever.

Both bodies are worker code, so everything here is synchronous.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.database import utc_now_naive


@pytest.fixture()
def fk_db():
    """A synchronous session with `PRAGMA foreign_keys=ON`, the way the worker really runs.

    `tests/helpers.make_sync_engine` deliberately leaves foreign keys off — nine fixtures
    were folded into it and turning them on would have been a behaviour change smuggled in
    with a de-duplication. This module cannot use it: the prune bug *is* an FK violation on
    the commit, so with the pragma off the broken code passes.
    """
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker

    from tests.helpers import schema_ddl

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _enforce_foreign_keys(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    with engine.begin() as conn:
        conn.connection.driver_connection.executescript(schema_ddl())

    session = sessionmaker(engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


class _RecordingStorage:
    """Records what the sweep asked it to delete, and deletes nothing."""

    def __init__(self):
        self.outputs: list[int] = []
        self.files: list[str] = []

    def delete_job_outputs_sync(self, job_id: int) -> bool:
        self.outputs.append(job_id)
        return True

    def delete_sync(self, filename: str) -> None:
        self.files.append(filename)


def _old_upload_with_entity(db):
    """An expired upload whose job produced one entity."""
    from app.models import AnalysisJob, Entity, EntityJobLink, JobStatus, LogFile, LogType, WorkflowDef

    workflow = WorkflowDef(name="wf", log_types="[]", tasks_yaml="tasks: []")
    db.add(workflow)
    db.flush()

    old = utc_now_naive() - timedelta(days=400)
    log_file = LogFile(original_filename="old.log", stored_filename="stored-old.log", sha256="a" * 64, size_bytes=10, log_type=LogType.UNKNOWN, uploaded_at=old)
    db.add(log_file)
    db.flush()

    job = AnalysisJob(file_id=log_file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED, created_at=old, finished_at=old)
    db.add(job)
    db.flush()

    entity = Entity(value="10.0.0.1", entity_type="ip_address", job_count=1)
    db.add(entity)
    db.flush()
    db.add(EntityJobLink(entity_id=entity.id, job_id=job.id, occurrence_count=3))
    db.commit()
    return job.id, log_file.stored_filename


# ── The output sweep ─────────────────────────────────────────────────────────


def test_output_sweep_honours_the_admin_retention_override(monkeypatch, sync_db):
    """env `0` + a 7-day override from /admin/storage must not read as "disabled".

    `app/retention.py` exists precisely so the sweep and the page describing it cannot
    disagree; the wrapper read `settings.job_output_retention_days` instead and answered
    "retention disabled" every night while the page showed 7 days and disk grew.
    """
    from app.config import settings
    from app.models import SiteSettings
    from app.workers import tasks

    sync_db.add(SiteSettings(id=1, job_output_retention_days_override=7))
    sync_db.commit()

    monkeypatch.setattr(settings, "job_output_retention_days", 0)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)

    detail = tasks._cleanup_job_outputs_periodic_body()

    assert detail != "retention disabled"
    # The detail line feeds the Scheduled panel on /admin/tasks, so it has to name the
    # window actually in force rather than the environment default it overrode.
    assert detail == "swept outputs older than 7 days"


def test_output_sweep_is_disabled_when_nothing_sets_a_window(monkeypatch, sync_db):
    """No override and env `0` still means off — the override is the only new input."""
    from app.config import settings
    from app.models import SiteSettings
    from app.workers import tasks

    sync_db.add(SiteSettings(id=1))
    sync_db.commit()

    monkeypatch.setattr(settings, "job_output_retention_days", 0)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)

    assert tasks._cleanup_job_outputs_periodic_body() == "retention disabled"


# ── The upload prune ─────────────────────────────────────────────────────────


def test_prune_removes_a_job_that_produced_entities(monkeypatch, fk_db):
    """The job row must go, links and all — not roll back on an IntegrityError.

    `entity_job_link` carries no `ondelete=` and AnalysisJob declares no relationship to
    it, so `db.delete(job)` alone raises on the commit under the foreign-key pragma the
    app runs with.
    """
    from app.config import settings
    from app.models import AnalysisJob, EntityJobLink, LogFile
    from app.workers import tasks

    job_id, stored_filename = _old_upload_with_entity(fk_db)
    storage = _RecordingStorage()

    monkeypatch.setattr(settings, "upload_retention_days", 30)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: fk_db)
    monkeypatch.setattr("app.storage.get_storage", lambda: storage)

    detail = tasks._prune_old_uploads_periodic_body()

    assert detail == "1 upload(s) removed"
    assert fk_db.query(AnalysisJob).count() == 0
    assert fk_db.query(LogFile).count() == 0
    assert fk_db.query(EntityJobLink).count() == 0
    assert storage.outputs == [job_id]
    assert storage.files == [stored_filename]


def test_prune_forgets_the_redis_keys_of_the_jobs_it_removes(monkeypatch, fk_db, fake_redis):
    """Same reason as the route's delete: the id goes back into circulation."""
    from app.config import settings
    from app.intel.process_tree import _cache_key
    from app.redis_client import TIMELINE_BUCKETS_PREFIX
    from app.workers import tasks

    job_id, _ = _old_upload_with_entity(fk_db)
    fake_redis.set(_cache_key(job_id), "stale")
    fake_redis.set(f"{TIMELINE_BUCKETS_PREFIX}{job_id}", "stale")

    monkeypatch.setattr(settings, "upload_retention_days", 30)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: fk_db)
    monkeypatch.setattr("app.storage.get_storage", lambda: _RecordingStorage())

    tasks._prune_old_uploads_periodic_body()

    assert not fake_redis.exists(_cache_key(job_id))
    assert not fake_redis.exists(f"{TIMELINE_BUCKETS_PREFIX}{job_id}")


class _BrokenSession:
    """A session whose every query raises, the way PostgreSQL does mid-outage."""

    def query(self, *a, **k):
        raise RuntimeError("database unavailable")

    execute = query

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.mark.parametrize(
    "task_name",
    [
        "prune_webhook_deliveries_periodic",
        "prune_expired_api_tokens_periodic",
        "refresh_rule_lists_periodic",
        "prune_enrichment_results_periodic",
        "prune_deleted_comments_periodic",
        "prune_old_uploads_periodic",
        "prune_background_tasks_periodic",
        "cleanup_job_outputs_periodic",
    ],
)
def test_a_sweep_that_fails_is_recorded_as_failed(monkeypatch, fake_redis, sync_db, task_name):
    """The Scheduled panel exists so a task that silently stopped working is visible. A body
    that catches its own exception, logs, and returns None was recorded as outcome "ok" —
    an upload sweep that rolled back every night read as healthy forever."""
    from app.config import settings
    from app.models import SiteSettings
    from app.redis_client import TASK_LAST_RUN_PREFIX
    from app.workers import tasks

    sync_db.add(SiteSettings(id=1, job_output_retention_days_override=30))
    sync_db.commit()
    for knob in ("webhook_delivery_retention_days", "upload_retention_days", "background_task_retention_days", "job_output_retention_days"):
        monkeypatch.setattr(settings, knob, 30)
    broken = _BrokenSession()
    # The output sweep resolves its window on a real session first, then works on another.
    sessions = iter([sync_db] + [broken] * 5) if task_name == "cleanup_job_outputs_periodic" else iter([broken] * 5)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: next(sessions))
    monkeypatch.setattr(sync_db, "close", lambda: None)

    with pytest.raises(RuntimeError):
        getattr(tasks, task_name).call_local()

    assert fake_redis.hgetall(f"{TASK_LAST_RUN_PREFIX}{task_name}").get("outcome") == "error"


def test_prune_keeps_the_upload_when_the_commit_fails(monkeypatch, fk_db):
    """A rollback restores the rows; nothing restores the file, so touch storage last.

    Deleting the file first makes a failed commit permanent rather than merely noisy: the row
    survives still pointing at a file that no longer exists, so every later run picks the
    same row and deletes nothing more.
    """
    from app.config import settings
    from app.models import AnalysisJob, LogFile
    from app.workers import tasks

    _old_upload_with_entity(fk_db)
    storage = _RecordingStorage()

    def _boom():
        raise RuntimeError("commit refused")

    monkeypatch.setattr(settings, "upload_retention_days", 30)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: fk_db)
    monkeypatch.setattr("app.storage.get_storage", lambda: storage)
    monkeypatch.setattr(fk_db, "commit", _boom)

    with pytest.raises(RuntimeError):
        tasks._prune_old_uploads_periodic_body()

    assert storage.outputs == []
    assert storage.files == []
    assert fk_db.query(AnalysisJob).count() == 1
    assert fk_db.query(LogFile).count() == 1


def _add_job(db, file_id: int, created_at):
    from app.models import AnalysisJob, JobStatus, WorkflowDef

    workflow_id = db.query(WorkflowDef.id).scalar()
    job = AnalysisJob(file_id=file_id, workflow_id=workflow_id, status=JobStatus.COMPLETED, created_at=created_at, finished_at=created_at)
    db.add(job)
    db.commit()
    return job.id


def test_prune_keeps_an_old_upload_that_a_recent_job_still_references(monkeypatch, fk_db):
    """Age runs from the newest job on the file, not from the first upload.

    Submitting identical content again reuses the stored LogFile (matched by sha256) and
    `POST /jobs/resubmit` attaches a new job to it, and neither touches `uploaded_at`. The
    sweep keyed on that column alone, so a job created yesterday on a file first uploaded
    before the cutoff was deleted with it the next night: its results, its download, its
    resubmit, gone.
    """
    from app.config import settings
    from app.models import AnalysisJob, LogFile
    from app.workers import tasks

    old_job_id, _ = _old_upload_with_entity(fk_db)
    file_id = fk_db.query(LogFile.id).scalar()
    recent_job_id = _add_job(fk_db, file_id, utc_now_naive() - timedelta(days=1))
    storage = _RecordingStorage()

    monkeypatch.setattr(settings, "upload_retention_days", 30)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: fk_db)
    monkeypatch.setattr("app.storage.get_storage", lambda: storage)

    detail = tasks._prune_old_uploads_periodic_body()

    assert detail == "nothing to remove"
    assert fk_db.query(LogFile).count() == 1
    assert {j for (j,) in fk_db.query(AnalysisJob.id)} == {old_job_id, recent_job_id}
    assert storage.outputs == []
    assert storage.files == []


def test_prune_still_removes_an_upload_whose_every_job_is_old(monkeypatch, fk_db):
    """The guard protects recent references only; a second expired job changes nothing."""
    from app.config import settings
    from app.models import AnalysisJob, LogFile
    from app.workers import tasks

    _, stored_filename = _old_upload_with_entity(fk_db)
    file_id = fk_db.query(LogFile.id).scalar()
    _add_job(fk_db, file_id, utc_now_naive() - timedelta(days=31))
    storage = _RecordingStorage()

    monkeypatch.setattr(settings, "upload_retention_days", 30)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: fk_db)
    monkeypatch.setattr("app.storage.get_storage", lambda: storage)

    assert tasks._prune_old_uploads_periodic_body() == "1 upload(s) removed"
    assert fk_db.query(LogFile).count() == 0
    assert fk_db.query(AnalysisJob).count() == 0
    assert storage.files == [stored_filename]
