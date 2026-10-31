"""An analysis with EVENTS_ENABLED on asks for its upload's event store and still completes.

Run on a file database with a fresh session per `get_sync_session()` call, as the worker
has in production: the store request commits on a session of its own, and the shared
session most worker tests use would make that impossible to observe.
"""

from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import AnalysisJob, EventStore, JobStatus, LogFile, LogType, WorkflowDef
from app.tools.base import NormalizedFinding, ToolOutput


def test_an_analysis_requests_the_store_and_completes(tmp_path, monkeypatch):
    import app.workers.tasks as tasks_mod
    from app.config import settings

    engine = create_engine(f"sqlite:///{tmp_path / 'worker.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    (upload_dir / "w.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 256)
    with sessions() as db:
        wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks:\n  - tool: zircolite\n    tool_path: x\n    rules_path: y\n")
        lf = LogFile(original_filename="w.evtx", stored_filename="w.evtx", sha256="c" * 64, size_bytes=264, log_type=LogType.EVTX, detected_type=LogType.EVTX)
        db.add_all([wf, lf])
        db.flush()
        job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PENDING, effective_log_type=LogType.EVTX)
        db.add(job)
        db.commit()
        job_id, log_file_id = job.id, lf.id

    monkeypatch.setattr(settings, "events_enabled", True)
    monkeypatch.setattr(settings, "upload_dir", upload_dir)
    monkeypatch.setattr(tasks_mod, "get_sync_session", sessions)
    enqueued: list[int] = []
    monkeypatch.setattr(tasks_mod, "build_event_store", lambda store_id: enqueued.append(store_id))
    monkeypatch.setattr(tasks_mod, "build_event_overlay", lambda job_id: None)

    class Storage:
        def exists_sync(self, name):
            return True

        def load_sync(self, name):
            return str(upload_dir / name)

        def sync_job_outputs_from_worker(self, job_id, output_dir):
            pass

        def release_sync(self, path):
            pass

    class Adapter:
        SUPPORTED_TYPES: set = set()

        def run(self, file_path, output_dir, **kw):
            return ToolOutput(success=True, findings=[NormalizedFinding(rule_id="R", rule_name="R", severity="low", count=1, tags=[], details=[])], duration_ms=1)

    class Quiet:
        def __init__(self, *a, **kw):
            self.event = type("E", (), {"is_set": staticmethod(lambda: False)})()

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr("app.storage.get_storage", lambda: Storage())
    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: Adapter())
    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", Quiet)
    monkeypatch.setattr(tasks_mod, "_CancelWatcher", Quiet)
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)
    monkeypatch.setattr(tasks_mod, "_acquire_job_slot", lambda _: True)
    monkeypatch.setattr(tasks_mod, "_release_job_slot", lambda: None)

    tasks_mod.run_analysis.call_local(job_id)

    with sessions() as db:
        job = db.get(AnalysisJob, job_id)
        assert job.status in (JobStatus.COMPLETED, JobStatus.PARTIAL), job.error_message
        store = db.scalar(select(EventStore).where(EventStore.log_file_id == log_file_id))
        assert store is not None and store.status == "pending" and store.log_type == "evtx"
    assert enqueued == [store.id]
