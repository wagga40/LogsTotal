"""A terminal job status is final: no status write may overwrite one written by another actor.

Every writer reads the row first and writes it later — the worker across a whole analysis
run — so these tests commit a competing status *between* the read and the write, the way a
recovery sweep, a cancel or a second worker would from another process.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, update

from app.models import AnalysisJob, JobStatus, LogFile, LogType, TaskResult, WorkflowDef
from app.redis_client import CANCEL_PREFIX, HEARTBEAT_PREFIX, cancel_flag_value
from app.tools.base import ToolOutput


@pytest.fixture()
def job_id(sync_db, tmp_path, monkeypatch):
    import app.workers.tasks as tasks_mod

    wf = WorkflowDef(name="Conditional WF", description="", log_types='["evtx"]', tasks_yaml="tasks:\n  - tool: zircolite\n", is_default=True)
    lf = LogFile(original_filename="c.evtx", stored_filename="c.evtx", sha256="c" * 64, size_bytes=264, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    sync_db.add_all([wf, lf])
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PENDING)
    sync_db.add(job)
    sync_db.commit()

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    (upload_dir / "c.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 256)
    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", upload_dir)

    class FakeStorage:
        def exists_sync(self, name):
            return True

        def load_sync(self, name):
            return str(upload_dir / name)

        def release_sync(self, path):
            pass

        def delete_job_outputs_sync(self, job_id):
            pass

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

    class FakeSiteSettings:
        parallel_execution = False
        max_finding_details = 10
        show_mitre_heatmap = show_event_timeline = show_entities = show_threat_detection = True

    monkeypatch.setattr("app.storage.get_storage", lambda: FakeStorage())
    monkeypatch.setattr(tasks_mod, "get_site_settings_sync", lambda db: FakeSiteSettings())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)
    return job.id


def _commit_elsewhere(db, job_id, status):
    """What another process's commit looks like to this session: the row changes, the
    in-memory object this session holds does not."""
    db.execute(update(AnalysisJob).where(AnalysisJob.id == job_id).values(status=status).execution_options(synchronize_session=False))
    db.commit()


def _adapter_calls(monkeypatch):
    import app.workers.tasks as tasks_mod

    calls = []

    class FakeAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            calls.append(file_path)
            return ToolOutput(success=True, findings=[], duration_ms=1, stdout="ok")

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: FakeAdapter())
    return calls


@pytest.mark.parametrize("competing", [JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.RUNNING])
def test_claim_does_not_overwrite_a_status_committed_after_pickup(sync_db, job_id, monkeypatch, competing):
    """The expired-PENDING sweep, a cancel or another worker commits between the pickup read
    and the claim. The claim must lose, and the tools must not run."""
    import app.workers.tasks as tasks_mod

    calls = _adapter_calls(monkeypatch)
    real_flag_value = tasks_mod.cancel_flag_value

    def flag_value_then_compete(job):  # runs between the pickup read and the claim
        _commit_elsewhere(sync_db, job_id, competing)
        return real_flag_value(job)

    monkeypatch.setattr(tasks_mod, "cancel_flag_value", flag_value_then_compete)
    tasks_mod.run_analysis.call_local(job_id)

    sync_db.expire_all()
    assert sync_db.get(AnalysisJob, job_id).status == competing
    assert calls == []


@pytest.mark.parametrize("competing", [JobStatus.FAILED, JobStatus.CANCELLED])
def test_finalize_keeps_a_status_committed_while_the_tools_ran(sync_db, job_id, monkeypatch, competing):
    """The recovery sweep failed the job (its heartbeat lapsed), or the cancel route
    cancelled it, while this worker was still running tools."""
    import app.workers.tasks as tasks_mod

    class CompetingAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            _commit_elsewhere(sync_db, job_id, competing)
            return ToolOutput(success=True, findings=[], duration_ms=1, stdout="ok")

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: CompetingAdapter())
    tasks_mod.run_analysis.call_local(job_id)

    sync_db.expire_all()
    assert sync_db.get(AnalysisJob, job_id).status == competing


def test_a_run_that_loses_the_claim_leaves_the_live_workers_keys(sync_db, job_id, monkeypatch, fake_redis):
    """A duplicate message for a job another worker is running must not delete that
    worker's heartbeat (recovery would then fail a live job) or its cancel flag (the cancel
    would be lost)."""
    import app.workers.tasks as tasks_mod

    calls = _adapter_calls(monkeypatch)
    _commit_elsewhere(sync_db, job_id, JobStatus.RUNNING)
    job = sync_db.get(AnalysisJob, job_id)
    sync_db.refresh(job)
    fake_redis.set(f"{HEARTBEAT_PREFIX}{job_id}", "other-worker")
    # A flag for another job id keeps this run from taking the cancelled-before-pickup
    # branch; the live worker's own flag is what must survive.
    fake_redis.set(f"{CANCEL_PREFIX}{job_id}", "job:0:not-this-one")

    tasks_mod.run_analysis.call_local(job_id)

    assert calls == []
    assert fake_redis.get(f"{HEARTBEAT_PREFIX}{job_id}") == "other-worker"
    assert fake_redis.get(f"{CANCEL_PREFIX}{job_id}") == "job:0:not-this-one"
    assert cancel_flag_value(job) != "job:0:not-this-one"


def test_fail_job_does_not_overwrite_a_terminal_status(sync_db, job_id):
    import app.workers.tasks as tasks_mod

    job = sync_db.get(AnalysisJob, job_id)
    _commit_elsewhere(sync_db, job_id, JobStatus.COMPLETED)
    tasks_mod._fail_job(sync_db, job, "late failure")

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job_id)
    assert job.status == JobStatus.COMPLETED
    assert job.error_message != "late failure"
    assert sync_db.execute(select(TaskResult).where(TaskResult.job_id == job_id)).first() is None
