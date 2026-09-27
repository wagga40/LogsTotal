"""Worker-side recomputation reads raw output through `app/storage.py`, like the web tier.

On `STORAGE_BACKEND=s3` the worker uploads a job's output tree and removes its local copy,
so `upload_dir/job_{id}` is empty on every host. `backfill_analytics`,
`backfill_relationships` and Recalculate analytics built that path themselves, found
nothing, and reported success: every job "skipped", "0 edges", analytics unchanged.

The fake backend here is the S3 shape that matters — `resolve_job_outputs_dir_sync` hands
back a directory that is *not* under `upload_dir`, and `load_sync` a copy that has to be
released — without boto3.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.models import AnalysisJob, BackgroundTask, BackgroundTaskStatus, EntityRelationship, JobStatus, LogFile, LogType, WorkflowDef

_EVENT = {
    "Timestamp": "2026-01-01 10:00:00.000 +00:00",
    "RuleTitle": "r",
    "Computer": "WS01",
    "EventID": 1,
    "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
    "ParentImage": "C:\\\\Windows\\\\explorer.exe",
    "User": "CORP\\\\alice",
}


class _BucketStorage:
    """Outputs live somewhere other than `upload_dir`; uploads are handed out as copies."""

    def __init__(self, remote_root, cache_dir):
        self.remote_root = remote_root
        self.cache_dir = cache_dir
        self.released: list[str] = []
        self.loaded: list[str] = []

    def resolve_job_outputs_dir_sync(self, job_id):
        d = self.remote_root / f"job_{job_id}"
        return (d, False) if d.is_dir() else None

    def exists_sync(self, name):
        return True

    def load_sync(self, name):
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        copy = self.cache_dir / name
        copy.write_bytes(b"ElfFile\x00" + bytes(range(256)) * 64)
        self.loaded.append(str(copy))
        return copy

    async def load(self, name):
        return self.load_sync(name)

    def release_sync(self, path):
        self.released.append(str(path))


@pytest.fixture()
def bucket(sync_db, tmp_path, monkeypatch):
    import app.workers.tasks as tasks_mod
    from app import storage as storage_mod

    upload_dir = tmp_path / "uploads"  # the worker's staging dir: empty, as after an S3 sync
    upload_dir.mkdir()
    remote = tmp_path / "bucket"
    (remote / "job_1" / "task_1").mkdir(parents=True)
    (remote / "job_1" / "task_1" / "x_hayabusa.json").write_text(json.dumps(_EVENT) + "\n")
    store = _BucketStorage(remote, tmp_path / "cache")

    monkeypatch.setattr("app.config.settings.upload_dir", upload_dir)
    monkeypatch.setattr(storage_mod, "_storage", store)
    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(sync_db, "close", lambda: None)

    wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    sync_db.add_all([wf, lf])
    sync_db.flush()
    job = AnalysisJob(
        submitted_filename=lf.original_filename,
        effective_log_type=lf.log_type,
        file_id=lf.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        analytics_json=json.dumps({"computers": []}),
    )
    sync_db.add(job)
    sync_db.commit()
    assert job.id == 1
    return {"store": store, "job": job, "log_file": lf}


def _row(sync_db, kind):
    bt = BackgroundTask(name=kind, kind=kind, status=BackgroundTaskStatus.PENDING)
    sync_db.add(bt)
    sync_db.commit()
    return bt


def test_backfill_analytics_finds_outputs_the_backend_holds(sync_db, bucket):
    import app.workers.tasks as tasks_mod

    bt = _row(sync_db, "backfill_analytics")
    tasks_mod.backfill_analytics.call_local(bt.id)

    sync_db.expire_all()
    assert "skipped" not in (sync_db.get(BackgroundTask, bt.id).detail or "")
    assert "WS01" in sync_db.get(AnalysisJob, 1).analytics_json


def test_backfill_relationships_finds_outputs_the_backend_holds(sync_db, bucket):
    import app.workers.tasks as tasks_mod

    tasks_mod.backfill_analytics.call_local(_row(sync_db, "backfill_analytics").id)  # entities first
    tasks_mod.backfill_relationships.call_local(_row(sync_db, "backfill_relationships").id)

    assert sync_db.execute(select(EntityRelationship)).scalars().all(), "no edge was rebuilt from the stored output"


def test_recalculate_finds_outputs_the_backend_holds(sync_db, bucket):
    import app.workers.tasks as tasks_mod

    bt = _row(sync_db, "recalculate_single_analytics")
    tasks_mod.recalculate_single_analytics.call_local(1, bg_task_id=bt.id)

    sync_db.expire_all()
    assert "WS01" in sync_db.get(AnalysisJob, 1).analytics_json


def test_the_similarity_backfill_releases_every_copy_it_loads(sync_db, bucket):
    """On S3 `load_sync` downloads the whole upload into `.s3_cache`. Nothing prunes that
    directory, so a backfill over 200 GB of uploads left 200 GB on the worker."""
    import app.workers.tasks as tasks_mod

    tasks_mod.backfill_similarity.call_local(_row(sync_db, "backfill_similarity").id)

    store = bucket["store"]
    assert store.loaded, "precondition: the backfill loaded the upload"
    assert store.released == store.loaded


async def test_the_admin_download_releases_its_copy(admin_client, async_db, monkeypatch, tmp_path):
    from app import storage as storage_mod

    store = _BucketStorage(tmp_path / "bucket", tmp_path / "cache")
    monkeypatch.setattr(storage_mod, "_storage", store)
    wf = WorkflowDef(name="WF", log_types='["evtx"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="a.evtx", stored_filename="stored_a.evtx", sha256="b" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([wf, lf])
    await async_db.flush()
    job = AnalysisJob(submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.commit()

    resp = await admin_client.get(f"/jobs/{job.id}/download")
    assert resp.status_code == 200
    assert store.released == store.loaded


def test_purging_orphans_spares_what_was_created_during_the_walk(sync_db, tmp_path, monkeypatch):
    """The purge snapshots the known jobs and uploads, then walks storage. A job picked up
    during the walk (on S3 the walk can take minutes) wrote a directory the snapshot did not
    know — and it was deleted mid-run. An upload saved during the walk went the same way."""
    import app.workers.tasks as tasks_mod
    from app import storage as storage_mod

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr("app.config.settings.upload_dir", upload_dir)
    monkeypatch.setattr(storage_mod, "_storage", None)
    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(sync_db, "close", lambda: None)

    wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    sync_db.add_all([wf, lf])
    sync_db.commit()
    (upload_dir / "a.evtx").write_bytes(b"x")
    (upload_dir / "job_999" / "task_1").mkdir(parents=True)  # a real orphan, for contrast
    (upload_dir / "job_999" / "task_1" / "old_hayabusa.json").write_text("{}\n")

    st = storage_mod.get_storage()
    real_iter = st.iter_objects_sync
    created = {}

    def walk_while_work_arrives(prefix=None):
        job = AnalysisJob(submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
        late = LogFile(original_filename="b.evtx", stored_filename="late_b.evtx", sha256="b" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
        sync_db.add_all([job, late])
        sync_db.commit()
        (upload_dir / f"job_{job.id}" / "task_1").mkdir(parents=True)
        (upload_dir / f"job_{job.id}" / "task_1" / "a_hayabusa.json").write_text("{}\n")
        (upload_dir / "late_b.evtx").write_bytes(b"y")
        created["job"] = job.id
        yield from real_iter(prefix)

    monkeypatch.setattr(st, "iter_objects_sync", walk_while_work_arrives)
    tasks_mod.purge_orphaned_storage.call_local(None)

    assert (upload_dir / f"job_{created['job']}").exists()
    assert (upload_dir / "late_b.evtx").exists()
    assert not (upload_dir / "job_999").exists(), "the real orphan still goes"
