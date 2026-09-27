"""Write path for the events-timeline marker index.

Covers the three things that can silently break it: the blob never being written, the blob
riding along on every wholesale job query, and the storage sync racing the analytics pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select

from app.intel.event_markers import pack_index, slice_index, unpack_index
from app.models import (
    AnalysisJob,
    Finding,
    JobStatus,
    LogFile,
    LogType,
    Severity,
    TaskResult,
    TaskStatus,
    WorkflowDef,
)
from app.tools.base import NormalizedFinding, ToolOutput

RULE = "Timeline Test Rule"


def _seed_job(db, upload_dir: Path) -> int:
    wf = WorkflowDef(
        name="Timeline WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks:\n  - tool: hayabusa\n    tool_path: tools/hayabusa/hayabusa\n    rules_path: tools/hayabusa/rules\n",
        is_default=True,
    )
    lf = LogFile(
        original_filename="t.evtx",
        stored_filename="t.evtx",
        sha256="c" * 64,
        size_bytes=10,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    db.add_all([wf, lf])
    db.flush()
    (upload_dir / "t.evtx").write_bytes(b"ElfFile\x00")
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.PENDING)
    db.add(job)
    db.commit()
    return job.id


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


def _run_worker(db, job_id, upload_dir, monkeypatch, storage):
    """Drive run_analysis with a tool that writes a real hayabusa output file."""
    import app.workers.tasks as tasks_mod

    events = [
        {"Timestamp": "2024-01-05T12:00:00Z", "RuleTitle": RULE, "Level": "high", "Computer": "WIN94"},
        {"Timestamp": "2024-01-05T12:00:00Z", "RuleTitle": RULE, "Level": "high", "Computer": "WIN94"},
        {"Timestamp": "2024-01-05T13:30:00Z", "RuleTitle": RULE, "Level": "high", "Computer": "WIN94"},
    ]

    class FakeAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / "res_hayabusa.json").write_text("\n".join(json.dumps(e) for e in events))
            return ToolOutput(
                success=True,
                findings=[
                    NormalizedFinding(
                        rule_id="SIGMA-XYZ",
                        rule_name=RULE,
                        severity="high",
                        count=len(events),
                        tags=["attack.execution"],
                        details=events,
                    )
                ],
                duration_ms=1,
            )

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: db)
    monkeypatch.setattr("app.config.settings.upload_dir", upload_dir)
    monkeypatch.setattr("app.storage.get_storage", lambda: storage)
    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: FakeAdapter())
    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: _FakeHeartbeat())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)
    monkeypatch.setattr(tasks_mod, "get_site_settings_sync", lambda d: _FakeSiteSettings())

    tasks_mod.run_analysis.call_local(job_id)
    db.expire_all()
    return db.get(AnalysisJob, job_id)


class _LocalStorage:
    """Stands in for LocalStorage: the sync is a no-op and outputs stay on disk."""

    def __init__(self, upload_dir):
        self._dir = upload_dir
        self.synced_at = None

    def exists_sync(self, name):
        return True

    def load_sync(self, name):
        return str(self._dir / name)

    def release_sync(self, path):
        pass

    def sync_job_outputs_from_worker(self, job_id, output_dir):
        self.synced_at = "called"


class _S3Storage(_LocalStorage):
    """Stands in for S3Storage, whose sync uploads and then rmtree's the local tree.

    That destructive step is what makes the ordering load-bearing: the analytics pass reads
    ``upload_dir/job_{id}`` straight off the filesystem, bypassing app/storage.py.
    """

    def sync_job_outputs_from_worker(self, job_id, output_dir):
        import shutil

        self.synced_at = "called"
        shutil.rmtree(output_dir, ignore_errors=True)


def test_worker_writes_a_marker_index(sync_db, tmp_path, monkeypatch):
    job_id = _seed_job(sync_db, tmp_path)
    job = _run_worker(sync_db, job_id, tmp_path, monkeypatch, _LocalStorage(tmp_path))

    payload = unpack_index(job.event_markers)
    assert payload is not None, "the analytics pass should have produced an index"
    assert payload["total"] == 3

    out = slice_index(payload, job_id=job_id)
    assert len(out["items"]) == 2, "two timestamps, the pair at 12:00 collapsing into one"
    assert out["items"][0]["label"] == RULE
    assert out["items"][0]["category"] == "high"
    # rule_id comes from the DB Finding via rule_meta, not from the raw event.
    assert out["items"][0]["meta"]["rule_id"] == "SIGMA-XYZ"
    assert out["items"][0]["meta"]["computer"] == "WIN94"
    assert out["items"][0]["meta"]["discarded"] == 1


def test_outputs_are_mirrored_after_analytics_not_before(sync_db, tmp_path, monkeypatch):
    """The S3 sync rmtree's the output tree, so it must run *after* the analytics pass.

    Ordered the other way — which is how it shipped — every S3 deployment silently produced
    empty timelines, entities and threat detection, because the parse found no directory.
    """
    job_id = _seed_job(sync_db, tmp_path)
    storage = _S3Storage(tmp_path)
    job = _run_worker(sync_db, job_id, tmp_path, monkeypatch, storage)

    assert storage.synced_at == "called", "outputs must still be mirrored"
    assert not (tmp_path / f"job_{job_id}").exists(), "the S3 stand-in should have removed the tree"

    payload = unpack_index(job.event_markers)
    assert payload is not None, "analytics ran after the tree was deleted"
    assert payload["total"] == 3

    analytics = json.loads(job.analytics_json)
    assert analytics["computers"] == ["WIN94"], "the whole analytics pass shares this ordering"


def test_marker_index_is_absent_when_there_is_no_raw_output(sync_db, tmp_path, monkeypatch):
    """A job with findings but no parseable output stores NULL, not an empty index —
    the endpoint then reports index_missing rather than an empty axis."""
    import app.workers.tasks as tasks_mod

    job_id = _seed_job(sync_db, tmp_path)

    class NoOutputAdapter:
        SUPPORTED_TYPES = set()

        def run(self, file_path, output_dir, **kw):
            return ToolOutput(success=True, findings=[], duration_ms=1)

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path)
    monkeypatch.setattr("app.storage.get_storage", lambda: _LocalStorage(tmp_path))
    monkeypatch.setattr(tasks_mod, "get_adapter", lambda name, cfg: NoOutputAdapter())
    monkeypatch.setattr(tasks_mod, "_HeartbeatTimer", lambda job_id: _FakeHeartbeat())
    monkeypatch.setattr(tasks_mod, "_register_worker", lambda *a, **kw: None)
    monkeypatch.setattr(tasks_mod, "get_site_settings_sync", lambda d: _FakeSiteSettings())

    tasks_mod.run_analysis.call_local(job_id)
    sync_db.expire_all()
    assert sync_db.get(AnalysisJob, job_id).event_markers is None


def test_pack_index_round_trips_and_compresses():
    from app.intel.event_markers import MarkerAccumulator, build_index

    acc = MarkerAccumulator()
    for i in range(2000):
        acc.add(("r", "Rule", "high", "execution", "H", "hayabusa"), f"2024-01-05T12:{i % 60:02d}:00Z")
    payload = build_index(acc)
    blob = pack_index(payload)
    assert unpack_index(blob) == payload
    assert len(blob) < len(json.dumps(payload)) / 2, "gzip should more than halve it"


def test_pack_index_returns_none_for_an_empty_index():
    assert pack_index(None) is None
    assert pack_index({}) is None
    assert pack_index({"v": 1, "ts": []}) is None


def test_unpack_index_survives_corruption():
    assert unpack_index(b"not gzip") is None
    assert unpack_index(None) is None


def test_backfill_analytics_fills_the_index(sync_db, tmp_path, monkeypatch):
    """Pre-upgrade jobs get their index from the existing backfill — no new task needed."""
    import app.workers.tasks as tasks_mod

    job_id = _seed_job(sync_db, tmp_path)
    job = sync_db.get(AnalysisJob, job_id)
    job.status = JobStatus.COMPLETED
    tr = TaskResult(job_id=job_id, tool_name="hayabusa", status=TaskStatus.COMPLETED, findings_count=1)
    sync_db.add(tr)
    sync_db.flush()
    sync_db.add(
        Finding(
            task_result_id=tr.id,
            rule_id="SIGMA-XYZ",
            rule_name=RULE,
            severity=Severity.HIGH,
            count=1,
            tags='["attack.execution"]',
            details="[]",
        )
    )
    sync_db.commit()

    job_dir = tmp_path / f"job_{job_id}"
    job_dir.mkdir()
    (job_dir / "res_hayabusa.json").write_text(json.dumps({"Timestamp": "2024-01-05T12:00:00Z", "RuleTitle": RULE, "Computer": "WIN94"}))

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path)
    tasks_mod.backfill_analytics.call_local(None)

    sync_db.expire_all()
    payload = unpack_index(sync_db.get(AnalysisJob, job_id).event_markers)
    assert payload is not None
    assert payload["keys"][0][0] == "SIGMA-XYZ"


async def test_jobs_list_does_not_load_the_marker_blob(test_client, async_db):
    """The blob is deferred, and that is load-bearing: ~16 call sites select(AnalysisJob)
    wholesale, including the 100-row jobs list, where an eager blob would cost megabytes
    per render."""
    from sqlalchemy import inspect as sa_inspect

    lf = LogFile(
        original_filename="d.evtx",
        stored_filename="d.evtx",
        sha256="d" * 64,
        size_bytes=1,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    wf = WorkflowDef(name="Deferred WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    async_db.add_all([lf, wf])
    await async_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, event_markers=b"x" * 1000)
    async_db.add(job)
    await async_db.commit()
    async_db.expunge_all()

    loaded = (await async_db.execute(select(AnalysisJob).where(AnalysisJob.id == job.id))).scalar_one()
    assert "event_markers" in sa_inspect(loaded).unloaded, "event_markers must not be eagerly loaded"
    assert "analytics_json" not in sa_inspect(loaded).unloaded, "sanity: ordinary columns still load"
