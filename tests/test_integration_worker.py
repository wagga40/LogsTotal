"""Lightweight worker integration tests.

Exercises the core run_analysis logic end-to-end using a mocked tool adapter
and in-memory SQLite, without actually spawning Huey or subprocesses.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import (
    AnalysisJob,
    JobStatus,
    LogFile,
    LogType,
    TaskResult,
    TaskStatus,
    WorkflowDef,
)
from app.tools.base import NormalizedFinding, ToolOutput


@pytest.fixture()
def worker_job(sync_db, tmp_path):
    """Create a pending job with associated file and workflow in the sync DB."""
    wf = WorkflowDef(
        name="Worker Test WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks:\n  - tool: zircolite\n    tool_path: tools/zircolite/zircolite.py\n    rules_path: tools/zircolite/rules\n",
        is_default=True,
    )
    sync_db.add(wf)
    sync_db.flush()

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    fake_file = upload_dir / "test_worker.evtx"
    fake_file.write_bytes(b"ElfFile\x00" + b"\x00" * 256)

    lf = LogFile(
        original_filename="worker.evtx",
        stored_filename="test_worker.evtx",
        sha256="b" * 64,
        size_bytes=264,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    sync_db.add(lf)
    sync_db.flush()

    job = AnalysisJob(
        file_id=lf.id,
        workflow_id=wf.id,
        status=JobStatus.PENDING,
    )
    sync_db.add(job)
    sync_db.commit()
    sync_db.refresh(job)
    return {"job": job, "workflow": wf, "log_file": lf, "upload_dir": upload_dir}


def _make_tool_output(*, findings: list[NormalizedFinding] | None = None, error: str | None = None) -> ToolOutput:
    if error:
        return ToolOutput(success=False, error=error, findings=[], duration_ms=10)
    return ToolOutput(
        success=True,
        findings=findings or [],
        duration_ms=42,
        stdout="ok",
    )


def test_run_analysis_finalizes_job(sync_db, worker_job, tmp_path, monkeypatch):
    """run_analysis should move a PENDING job to COMPLETED when the tool succeeds."""
    import app.workers.tasks as tasks_mod

    job_id = worker_job["job"].id

    mock_output = _make_tool_output(
        findings=[
            NormalizedFinding(
                rule_id="TEST-001",
                rule_name="Test Rule",
                severity="medium",
                count=1,
                tags=["attack.t1059"],
                details=[{"key": "value"}],
            )
        ]
    )

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", worker_job["upload_dir"])

    class FakeStorage:
        def exists_sync(self, name):
            return True

        def load_sync(self, name):
            return str(worker_job["upload_dir"] / name)

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

    monkeypatch.setattr("app.storage.get_storage", lambda: FakeStorage())

    class FakeAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            return mock_output

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: FakeAdapter())

    class FakeHeartbeat:
        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: FakeHeartbeat())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)

    class FakeSiteSettings:
        parallel_execution = False
        max_finding_details = 10
        show_mitre_heatmap = True
        show_event_timeline = True
        show_entities = True
        show_threat_detection = True

    monkeypatch.setattr(tasks_mod, "get_site_settings_sync", lambda db: FakeSiteSettings())

    run_fn = tasks_mod.run_analysis.call_local
    run_fn(job_id)

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job_id)
    assert job is not None
    assert job.status in (JobStatus.COMPLETED, JobStatus.PARTIAL)
    assert job.finished_at is not None

    task_results = sync_db.execute(select(TaskResult).where(TaskResult.job_id == job_id)).scalars().all()
    tool_results = [tr for tr in task_results if tr.tool_name == "zircolite"]
    assert len(tool_results) == 1
    assert tool_results[0].status == TaskStatus.COMPLETED
    assert tool_results[0].findings_count == 1


def test_run_analysis_marks_failed_on_missing_file(sync_db, worker_job, monkeypatch):
    """run_analysis should FAIL the job if the uploaded file is missing."""
    import app.workers.tasks as tasks_mod

    job_id = worker_job["job"].id

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", worker_job["upload_dir"])

    class MissingStorage:
        def exists_sync(self, name):
            return False

        def load_sync(self, name):
            raise FileNotFoundError(name)

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

    monkeypatch.setattr("app.storage.get_storage", lambda: MissingStorage())

    class FakeHeartbeat:
        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: FakeHeartbeat())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)

    run_fn = tasks_mod.run_analysis.call_local
    run_fn(job_id)

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job_id)
    assert job is not None
    assert job.status == JobStatus.FAILED
    assert "not found" in (job.error_message or "").lower()


def test_no_module_level_tool_executor():
    """The shared module-level ThreadPoolExecutor was replaced by a per-job pool.

    A shared pool multiplexed every worker thread's tools through one FIFO queue,
    breaking the documented per-job TOOL_MAX_WORKERS parallelism. Guard against it
    creeping back.
    """
    import app.workers.tasks as tasks_mod

    assert not hasattr(tasks_mod, "_tool_executor")


def test_parallel_tools_run_concurrently(sync_db, tmp_path, monkeypatch):
    """With parallel_execution ON and TOOL_MAX_WORKERS=2, a job's two tools must run
    at the same time. Both adapters rendezvous on a Barrier(2); if the per-job pool
    only gave one slot the barrier would time out and that tool's result would FAIL."""
    import threading

    import app.workers.tasks as tasks_mod

    wf = WorkflowDef(
        name="Parallel WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml=("tasks:\n  - tool: hayabusa\n    tool_path: t/a\n    rules_path: r\n  - tool: chainsaw\n    tool_path: t/b\n    rules_path: r\n"),
        is_default=False,
    )
    sync_db.add(wf)
    sync_db.flush()

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    (upload_dir / "par.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    lf = LogFile(
        original_filename="par.evtx",
        stored_filename="par.evtx",
        sha256="c" * 64,
        size_bytes=72,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    sync_db.add(lf)
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PENDING)
    sync_db.add(job)
    sync_db.commit()
    sync_db.refresh(job)
    job_id = job.id

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", upload_dir)
    monkeypatch.setattr("app.config.settings.tool_max_workers", 2)

    class FakeStorage:
        def exists_sync(self, name):
            return True

        def load_sync(self, name):
            return str(upload_dir / name)

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

    monkeypatch.setattr("app.storage.get_storage", lambda: FakeStorage())

    barrier = threading.Barrier(2, timeout=5)

    class BarrierAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            # Both tools must reach this point together — proves intra-job parallelism.
            barrier.wait()
            return _make_tool_output(findings=[NormalizedFinding(rule_id="R", rule_name="Rule", severity="low", count=1)])

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: BarrierAdapter())

    class FakeHeartbeat:
        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: FakeHeartbeat())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)

    class FakeSiteSettings:
        parallel_execution = True
        max_finding_details = 10
        show_mitre_heatmap = True
        show_event_timeline = True
        show_entities = True
        show_threat_detection = True

    monkeypatch.setattr(tasks_mod, "get_site_settings_sync", lambda db: FakeSiteSettings())

    tasks_mod.run_analysis.call_local(job_id)

    sync_db.expire_all()
    tool_results = sync_db.execute(select(TaskResult).where(TaskResult.job_id == job_id, TaskResult.tool_name.in_(["hayabusa", "chainsaw"]))).scalars().all()
    assert len(tool_results) == 2
    assert all(tr.status == TaskStatus.COMPLETED for tr in tool_results), "a tool failed — the barrier timed out, so the two tools did not run concurrently"


def test_parallel_execution_survives_tool_max_workers_zero(sync_db, tmp_path, monkeypatch):
    """TOOL_MAX_WORKERS=0 is nonsensical config, but must not crash the job.

    ThreadPoolExecutor(max_workers=0) raises ValueError; the per-job pool guards
    against this with max(1, ...) so a misconfigured 0 degrades to serial-ish
    execution (one slot) instead of failing every job.
    """
    import app.workers.tasks as tasks_mod

    wf = WorkflowDef(
        name="Zero Workers WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml=("tasks:\n  - tool: hayabusa\n    tool_path: t/a\n    rules_path: r\n  - tool: chainsaw\n    tool_path: t/b\n    rules_path: r\n"),
        is_default=False,
    )
    sync_db.add(wf)
    sync_db.flush()

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    (upload_dir / "zero.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    lf = LogFile(
        original_filename="zero.evtx",
        stored_filename="zero.evtx",
        sha256="d" * 64,
        size_bytes=72,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    sync_db.add(lf)
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PENDING)
    sync_db.add(job)
    sync_db.commit()
    sync_db.refresh(job)
    job_id = job.id

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", upload_dir)
    monkeypatch.setattr("app.config.settings.tool_max_workers", 0)

    class FakeStorage:
        def exists_sync(self, name):
            return True

        def load_sync(self, name):
            return str(upload_dir / name)

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

    monkeypatch.setattr("app.storage.get_storage", lambda: FakeStorage())

    class PlainAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            return _make_tool_output(findings=[NormalizedFinding(rule_id="R", rule_name="Rule", severity="low", count=1)])

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: PlainAdapter())

    class FakeHeartbeat:
        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: FakeHeartbeat())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)

    class FakeSiteSettings:
        parallel_execution = True
        max_finding_details = 10
        show_mitre_heatmap = True
        show_event_timeline = True
        show_entities = True
        show_threat_detection = True

    monkeypatch.setattr(tasks_mod, "get_site_settings_sync", lambda db: FakeSiteSettings())

    tasks_mod.run_analysis.call_local(job_id)

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job_id)
    assert job.status == JobStatus.COMPLETED
    tool_results = sync_db.execute(select(TaskResult).where(TaskResult.job_id == job_id, TaskResult.tool_name.in_(["hayabusa", "chainsaw"]))).scalars().all()
    assert len(tool_results) == 2
    assert all(tr.status == TaskStatus.COMPLETED for tr in tool_results)


def test_cleanup_outputs_marks_bg_task_when_retention_disabled(sync_db, monkeypatch):
    """Retention 0 (keep forever) must still close out the BackgroundTask row,
    or the admin dashboard's live status chip would show 'Queued…' forever."""
    import app.workers.tasks as tasks_mod
    from app.models import BackgroundTask, BackgroundTaskStatus

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(tasks_mod.settings, "job_output_retention_days", 0)

    bt = BackgroundTask(name="Output Directory Cleanup", status=BackgroundTaskStatus.PENDING)
    sync_db.add(bt)
    sync_db.commit()

    task_id = bt.id
    tasks_mod.cleanup_old_job_outputs.call_local(task_id)

    # The task closes its session, detaching `bt` — re-fetch instead of refresh.
    sync_db.expire_all()
    fetched = sync_db.get(BackgroundTask, task_id)
    assert fetched is not None
    assert fetched.status == BackgroundTaskStatus.COMPLETED
    assert "Retention disabled" in (fetched.detail or "")


# ── Cancellation ─────────────────────────────────────────────────────────────


class _FakeHeartbeat:
    def start(self):
        pass

    def stop(self):
        pass


class _FakeSiteSettings:
    parallel_execution = False
    max_finding_details = 10
    show_mitre_heatmap = True
    show_event_timeline = True
    show_entities = True
    show_threat_detection = True


def _patch_worker_env(monkeypatch, sync_db, upload_dir, *, parallel=False):
    """Common monkeypatching for run_analysis tests (no Redis, no Huey)."""
    import app.workers.tasks as tasks_mod

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", upload_dir)

    class FakeStorage:
        def exists_sync(self, name):
            return True

        def load_sync(self, name):
            return str(upload_dir / name)

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

    monkeypatch.setattr("app.storage.get_storage", lambda: FakeStorage())
    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: _FakeHeartbeat())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)

    site = _FakeSiteSettings()
    site.parallel_execution = parallel
    monkeypatch.setattr(tasks_mod, "get_site_settings_sync", lambda db: site)
    return tasks_mod


def test_pickup_drops_job_already_cancelled(sync_db, worker_job, monkeypatch):
    """A job cancelled while PENDING must be dropped at pickup, untouched."""
    tasks_mod = _patch_worker_env(monkeypatch, sync_db, worker_job["upload_dir"])

    job = worker_job["job"]
    job.status = JobStatus.CANCELLED
    sync_db.commit()

    tasks_mod.run_analysis.call_local(job.id)

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job.id)
    assert job.status == JobStatus.CANCELLED
    task_results = sync_db.execute(select(TaskResult).where(TaskResult.job_id == job.id)).scalars().all()
    assert task_results == []


def test_pickup_honors_redis_cancel_flag(sync_db, worker_job, monkeypatch):
    """A PENDING job with the Redis cancel flag set ends CANCELLED, no tools run."""
    from app.constants import CANCEL_MSG_USER

    tasks_mod = _patch_worker_env(monkeypatch, sync_db, worker_job["upload_dir"])
    monkeypatch.setattr(tasks_mod, "_cancel_requested", lambda job_id, identity=None: True)

    job_id = worker_job["job"].id
    tasks_mod.run_analysis.call_local(job_id)

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job_id)
    assert job.status == JobStatus.CANCELLED
    assert job.error_message == CANCEL_MSG_USER
    assert job.finished_at is not None
    assert sync_db.execute(select(TaskResult).where(TaskResult.job_id == job_id)).scalars().all() == []


def test_pickup_starts_from_an_empty_output_tree(sync_db, worker_job, monkeypatch):
    """SQLite gives the next job the id of the newest deleted one, and `task db:reset` or a
    restore of an older database leaves `uploads/` behind — so `uploads/job_{id}/` can
    already hold another job's raw output. Everything downstream parses the whole tree, so
    those files were merged into this job's analytics, entities, timeline and export."""
    tasks_mod = _patch_worker_env(monkeypatch, sync_db, worker_job["upload_dir"])
    cleared: list[int] = []
    monkeypatch.setattr("app.storage.get_storage", lambda: _StorageRecordingDeletes(worker_job["upload_dir"], cleared))

    class FakeAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            return _make_tool_output()

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: FakeAdapter())

    job_id = worker_job["job"].id
    stale = worker_job["upload_dir"] / f"job_{job_id}" / "task_999"
    stale.mkdir(parents=True)
    (stale / "old_job_hayabusa.json").write_text('{"Computer": "STALE-HOST"}\n')

    tasks_mod.run_analysis.call_local(job_id)

    assert not stale.exists(), "a previous job's output survived into this one"
    assert cleared == [job_id], "the stored copy (the S3 bucket) must be cleared too"


class _StorageRecordingDeletes:
    def __init__(self, upload_dir, cleared):
        self._dir = upload_dir
        self._cleared = cleared

    def exists_sync(self, name):
        return True

    def load_sync(self, name):
        return str(self._dir / name)

    def delete_job_outputs_sync(self, job_id):
        self._cleared.append(job_id)
        return False

    def sync_job_outputs_from_worker(self, job_id, output_dir):
        pass


def test_a_process_tree_cached_while_the_job_ran_is_dropped_when_it_finishes(sync_db, worker_job, monkeypatch, fake_redis):
    """The entity and case Processes tabs accept a running job, and cache what they find —
    nothing, early on — for five minutes. That empty tree outlived the job's completion."""
    from app.intel.process_tree import _cache_key

    tasks_mod = _patch_worker_env(monkeypatch, sync_db, worker_job["upload_dir"])

    class FakeAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            fake_redis.set(_cache_key(worker_job["job"].id), '{"roots": []}', ex=300)  # a viewer, mid-run
            return _make_tool_output()

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: FakeAdapter())

    tasks_mod.run_analysis.call_local(worker_job["job"].id)

    assert not fake_redis.exists(_cache_key(worker_job["job"].id))


def test_a_cancel_flag_left_for_an_earlier_job_with_this_id_is_ignored(sync_db, worker_job, monkeypatch, fake_redis):
    """Deleting a PENDING job sets its cancel flag for ~26h. If the next upload is given the
    same id, that flag cancelled a job nobody asked to cancel."""
    from app.redis_client import CANCEL_PREFIX

    tasks_mod = _patch_worker_env(monkeypatch, sync_db, worker_job["upload_dir"])

    class FakeAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            return _make_tool_output()

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: FakeAdapter())

    job_id = worker_job["job"].id
    fake_redis.set(f"{CANCEL_PREFIX}{job_id}", f"job:{job_id}:2020-01-01T00:00:00", ex=90000)

    tasks_mod.run_analysis.call_local(job_id)

    sync_db.expire_all()
    assert sync_db.get(AnalysisJob, job_id).status != JobStatus.CANCELLED


@pytest.mark.parametrize("value", ["for-this-job", "legacy"])
def test_a_cancel_flag_set_for_this_job_still_cancels_it(sync_db, worker_job, monkeypatch, fake_redis, value):
    from app.redis_client import CANCEL_PREFIX, cancel_flag_value

    tasks_mod = _patch_worker_env(monkeypatch, sync_db, worker_job["upload_dir"])
    job = worker_job["job"]
    # "legacy": a flag written before flags carried the job's identity, during an upgrade.
    fake_redis.set(f"{CANCEL_PREFIX}{job.id}", cancel_flag_value(job) if value == "for-this-job" else "deleted", ex=90000)

    tasks_mod.run_analysis.call_local(job.id)

    sync_db.expire_all()
    assert sync_db.get(AnalysisJob, job.id).status == JobStatus.CANCELLED


def test_cancel_mid_run_keeps_completed_findings(sync_db, tmp_path, monkeypatch):
    """Cancelling mid-run keeps finished tools' findings; the rest go CANCELLED."""
    from app.constants import CANCEL_MSG_USER, POST_TASK_NAMES

    wf = WorkflowDef(
        name="Cancel WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml=("tasks:\n  - tool: hayabusa\n    tool_path: t/a\n    rules_path: r\n  - tool: chainsaw\n    tool_path: t/b\n    rules_path: r\n"),
        is_default=False,
    )
    sync_db.add(wf)
    sync_db.flush()
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    (upload_dir / "cancel.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    lf = LogFile(
        original_filename="cancel.evtx",
        stored_filename="cancel.evtx",
        sha256="e" * 64,
        size_bytes=72,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    sync_db.add(lf)
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PENDING)
    sync_db.add(job)
    sync_db.commit()
    job_id = job.id

    tasks_mod = _patch_worker_env(monkeypatch, sync_db, upload_dir, parallel=False)

    class CancellingAdapter:
        """First tool: returns findings AND requests cancellation (sets the event)."""

        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, log_type=None, cancel_event=None):
            cancel_event.set()
            return _make_tool_output(findings=[NormalizedFinding(rule_id="R1", rule_name="Rule One", severity="medium", count=1)])

    class NeverRunAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            raise AssertionError("second tool must not run after cancellation")

    adapters = {"hayabusa": CancellingAdapter(), "chainsaw": NeverRunAdapter()}
    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: adapters[name])

    tasks_mod.run_analysis.call_local(job_id)

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job_id)
    assert job.status == JobStatus.CANCELLED
    assert job.error_message == CANCEL_MSG_USER
    assert job.severity_summary  # score/severity still computed from kept findings

    task_results = sync_db.execute(select(TaskResult).where(TaskResult.job_id == job_id)).scalars().all()
    by_name = {tr.tool_name: tr for tr in task_results}
    assert by_name["hayabusa"].status == TaskStatus.COMPLETED
    assert by_name["hayabusa"].findings_count == 1
    assert by_name["chainsaw"].status == TaskStatus.CANCELLED
    assert by_name["chainsaw"].error_message == CANCEL_MSG_USER
    for post_name in POST_TASK_NAMES:
        assert by_name[post_name].status == TaskStatus.CANCELLED


def test_watchdog_finalizes_job_with_hung_tool(sync_db, tmp_path, monkeypatch):
    """A tool that ignores its timeout must not block finalize — the orchestration
    watchdog fails it after the summed timeout budget and the job goes PARTIAL."""
    import time as time_mod

    wf = WorkflowDef(
        name="Watchdog WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml=(
            "tasks:\n  - tool: hayabusa\n    tool_path: t/a\n    rules_path: r\n    timeout: 1\n  - tool: chainsaw\n    tool_path: t/b\n    rules_path: r\n    timeout: 1\n"
        ),
        is_default=False,
    )
    sync_db.add(wf)
    sync_db.flush()
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    (upload_dir / "hang.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    lf = LogFile(
        original_filename="hang.evtx",
        stored_filename="hang.evtx",
        sha256="f" * 64,
        size_bytes=72,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    sync_db.add(lf)
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PENDING)
    sync_db.add(job)
    sync_db.commit()
    job_id = job.id

    tasks_mod = _patch_worker_env(monkeypatch, sync_db, upload_dir, parallel=True)
    monkeypatch.setattr("app.config.settings.tool_max_workers", 2)
    monkeypatch.setattr(tasks_mod, "_WATCHDOG_GRACE_SECONDS", 0.5)

    class HangingAdapter:
        """Pathological tool: ignores both its timeout and the cancel event."""

        SUPPORTED_TYPES = set()
        _timeout_seconds = 1

        def run(self, file_path, output_dir, **kw):
            time_mod.sleep(4)
            return _make_tool_output()

    class QuickAdapter:
        SUPPORTED_TYPES = set()
        _timeout_seconds = 1

        def run(self, file_path, output_dir, **kw):
            return _make_tool_output(findings=[NormalizedFinding(rule_id="R2", rule_name="Rule Two", severity="low", count=1)])

    adapters = {"hayabusa": HangingAdapter(), "chainsaw": QuickAdapter()}
    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: adapters[name])

    t0 = time_mod.monotonic()
    tasks_mod.run_analysis.call_local(job_id)
    elapsed = time_mod.monotonic() - t0
    assert elapsed < 4, f"watchdog did not bound the hung tool (took {elapsed:.1f}s)"

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job_id)
    assert job.status == JobStatus.PARTIAL
    task_results = sync_db.execute(select(TaskResult).where(TaskResult.job_id == job_id)).scalars().all()
    by_name = {tr.tool_name: tr for tr in task_results}
    assert by_name["chainsaw"].status == TaskStatus.COMPLETED
    assert by_name["hayabusa"].status == TaskStatus.FAILED
    assert "Watchdog" in (by_name["hayabusa"].error_message or "")


def test_exception_during_a_cancelled_run_reports_cancelled_not_failed(sync_db, worker_job, monkeypatch):
    """Killing the tools is a plausible source of the exception — don't blame the
    platform for doing what the user asked. The job must end CANCELLED, not FAILED."""
    import app.workers.tasks as tasks_mod

    job_id = worker_job["job"].id

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", worker_job["upload_dir"])

    class ExplodingStorage:
        def exists_sync(self, name):
            return True

        def load_sync(self, name):
            raise RuntimeError("read aborted while the tool was being killed")

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

    monkeypatch.setattr("app.storage.get_storage", lambda: ExplodingStorage())

    class FakeTimer:
        def start(self):
            pass

        def stop(self):
            pass

    class LatchedCancelWatcher(FakeTimer):
        """Stands in for _CancelWatcher with its event already latched."""

        def __init__(self, job_id):
            import threading

            self.event = threading.Event()
            self.event.set()

    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: FakeTimer())
    monkeypatch.setattr(tasks_mod, "_CancelWatcher", LatchedCancelWatcher)
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)
    # Don't let the pickup guard short-circuit before the body runs.
    monkeypatch.setattr(tasks_mod, "_cancel_requested", lambda job_id: False)

    tasks_mod.run_analysis.call_local(job_id)

    sync_db.expire_all()
    job = sync_db.get(AnalysisJob, job_id)
    assert job.status == JobStatus.CANCELLED


def test_pool_is_shut_down_when_persisting_a_result_raises(sync_db, tmp_path, monkeypatch):
    """A commit failure inside the as_completed loop escaped both the TimeoutError
    handler and the else branch, so pool.shutdown() was never reached: the remaining
    tools kept running while the outer handler marked the job FAILED, with nothing left
    to reap them. SQLite is the default backend and its 5s busy_timeout makes an
    OperationalError here entirely ordinary."""
    import app.workers.tasks as tasks_mod

    wf = WorkflowDef(
        name="Pool WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml=("tasks:\n  - tool: hayabusa\n    tool_path: t/a\n    rules_path: r\n  - tool: chainsaw\n    tool_path: t/b\n    rules_path: r\n"),
        is_default=False,
    )
    sync_db.add(wf)
    sync_db.flush()

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    (upload_dir / "pool.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    lf = LogFile(
        original_filename="pool.evtx",
        stored_filename="pool.evtx",
        sha256="9" * 64,
        size_bytes=72,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    sync_db.add(lf)
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PENDING)
    sync_db.add(job)
    sync_db.commit()
    job_id = job.id

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", upload_dir)
    monkeypatch.setattr("app.config.settings.tool_max_workers", 2)

    class FakeStorage:
        def exists_sync(self, name):
            return True

        def load_sync(self, name):
            return str(upload_dir / name)

        def release_sync(self, path):
            pass

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

    monkeypatch.setattr("app.storage.get_storage", lambda: FakeStorage())

    class QuietAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            return _make_tool_output(findings=[])

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: QuietAdapter())

    class FakeHeartbeat:
        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: FakeHeartbeat())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)

    class FakeSiteSettings:
        parallel_execution = True
        max_finding_details = 10
        show_mitre_heatmap = True
        show_event_timeline = True
        show_entities = True
        show_threat_detection = True

    monkeypatch.setattr(tasks_mod, "get_site_settings_sync", lambda db: FakeSiteSettings())

    shutdowns: list[bool] = []
    real_pool = tasks_mod.ThreadPoolExecutor

    class RecordingPool(real_pool):
        def shutdown(self, wait=True, *, cancel_futures=False):
            shutdowns.append(cancel_futures)
            return super().shutdown(wait=False, cancel_futures=True)

    monkeypatch.setattr(tasks_mod, "ThreadPoolExecutor", RecordingPool)

    def _boom(*a, **kw):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(tasks_mod, "_persist_tool_result", _boom)

    tasks_mod.run_analysis.call_local(job_id)

    assert shutdowns, "the tool pool was never shut down after the persist failure"


def test_recalculation_closes_its_background_task_row(sync_db, worker_job, monkeypatch, tmp_path):
    """Both ways out of the task have to close the row it was given — including "nothing to
    do", which is not a failure: the raw output is gone and existing analytics are kept."""
    import app.workers.tasks as tasks_mod
    from app.models import BackgroundTask, BackgroundTaskStatus

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(sync_db, "close", lambda: None)
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path / "no-outputs-here")

    job_id = worker_job["job"].id
    kept = BackgroundTask(name="Recalculate", kind="recalculate_single_analytics", target_id=str(job_id), status=BackgroundTaskStatus.PENDING)
    gone = BackgroundTask(name="Recalculate", kind="recalculate_single_analytics", target_id="999999", status=BackgroundTaskStatus.PENDING)
    sync_db.add_all([kept, gone])
    sync_db.commit()

    tasks_mod.recalculate_single_analytics.call_local(job_id, bg_task_id=kept.id)
    tasks_mod.recalculate_single_analytics.call_local(999999, bg_task_id=gone.id)

    sync_db.expire_all()
    assert sync_db.get(BackgroundTask, kept.id).status == BackgroundTaskStatus.COMPLETED
    assert sync_db.get(BackgroundTask, kept.id).detail
    assert sync_db.get(BackgroundTask, gone.id).status == BackgroundTaskStatus.FAILED


def test_a_disabled_retention_names_the_setting_that_disabled_it(sync_db, monkeypatch):
    """The resolver above the early return honours the /admin/storage override, but the
    detail always blamed `JOB_OUTPUT_RETENTION_DAYS=0` — sending an operator to an .env
    that says 90 to find out why nothing was cleaned."""
    import app.workers.tasks as tasks_mod
    from app.models import BackgroundTask, BackgroundTaskStatus, SiteSettings

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(tasks_mod.settings, "job_output_retention_days", 90)
    sync_db.add(SiteSettings(id=1, job_output_retention_days_override=0))
    bt = BackgroundTask(name="Output Directory Cleanup", status=BackgroundTaskStatus.PENDING)
    sync_db.add(bt)
    sync_db.commit()
    task_id = bt.id

    tasks_mod.cleanup_old_job_outputs.call_local(task_id)

    sync_db.expire_all()
    detail = sync_db.get(BackgroundTask, task_id).detail or ""
    assert "Retention disabled" in detail
    assert "JOB_OUTPUT_RETENTION_DAYS" not in detail and "site setting" in detail, detail


@pytest.mark.parametrize("parallel", [False, True])
def test_worker_uses_submission_type_even_when_shared_file_disagrees(sync_db, worker_job, monkeypatch, parallel):
    tasks_mod = _patch_worker_env(monkeypatch, sync_db, worker_job["upload_dir"], parallel=parallel)
    job = worker_job["job"]
    job.effective_log_type = LogType.EVTX
    worker_job["log_file"].log_type = LogType.SYSLOG
    sync_db.commit()
    seen = []

    class Adapter:
        SUPPORTED_TYPES = {"evtx"}

        def run(self, file_path, output_dir, **kwargs):
            seen.append(kwargs["log_type"])
            return _make_tool_output()

    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, config: Adapter())
    tasks_mod.run_analysis.call_local(job.id)
    assert seen == ["evtx"]
