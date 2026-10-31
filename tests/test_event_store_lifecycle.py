"""Event stores: requested at job claim, built in a subprocess, published, deleted with the upload."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from sqlalchemy import select

from app.events.manifest import validate_manifest
from app.models import EventStore, EventStoreStatus, LogFile, LogType

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "linux" / "auditd_sample.log"


@pytest.fixture()
def local_events(tmp_path, monkeypatch, sync_db):
    """Local storage under tmp_path, the store switch on, and one stored upload."""
    from app import storage as storage_mod
    from app.config import settings

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(settings, "upload_dir", upload_dir)
    monkeypatch.setattr(settings, "events_enabled", True)
    monkeypatch.setattr(settings, "events_min_free_disk_mb", 0)
    monkeypatch.setattr(settings, "events_build_memory_mb", 256)
    monkeypatch.setattr(storage_mod, "_storage", None)
    shutil.copy(SAMPLE, upload_dir / "audit.log")
    lf = LogFile(
        original_filename="audit.log", stored_filename="audit.log", sha256="c" * 64, size_bytes=SAMPLE.stat().st_size, log_type=LogType.AUDITD, detected_type=LogType.AUDITD
    )
    sync_db.add(lf)
    sync_db.commit()
    return upload_dir, lf


def test_a_request_creates_one_row_and_a_ready_store_needs_none(sync_db, local_events):
    from app.events.store import request_build_sync

    _, lf = local_events
    first = request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=1)
    sync_db.commit()
    assert first is not None
    assert request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=2) == first, "a pending row is re-requested, not duplicated"
    row = sync_db.get(EventStore, first)
    row.status = EventStoreStatus.READY.value
    sync_db.commit()
    assert request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=3) is None
    assert len(sync_db.scalars(select(EventStore)).all()) == 1


def test_retries_stop_after_three_failures(sync_db, local_events):
    from app.events.store import MAX_ATTEMPTS, request_build_sync

    _, lf = local_events
    sid = request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=1)
    row = sync_db.get(EventStore, sid)
    row.status, row.attempts = EventStoreStatus.FAILED.value, MAX_ATTEMPTS
    sync_db.commit()
    assert request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=2) is None


def test_switched_off_nothing_is_requested(sync_db, local_events, monkeypatch):
    from app.config import settings
    from app.events.store import request_build_sync

    monkeypatch.setattr(settings, "events_enabled", False)
    _, lf = local_events
    assert request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=1) is None


def test_a_real_build_is_published_into_place(sync_db, local_events):
    from app.events.store import request_build_sync, run_build

    upload_dir, lf = local_events
    sid = request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=1)
    sync_db.commit()
    outcome = run_build(sync_db, sid)
    row = sync_db.get(EventStore, sid)
    sync_db.refresh(row)
    assert row.status == EventStoreStatus.READY.value, (outcome, row.error_message)
    assert row.event_count == 35 and row.gen and row.bytes > 0
    store_dir = upload_dir / "events" / lf.sha256 / row.gen
    assert validate_manifest(store_dir)["totals"]["events"] == 35
    assert not any((upload_dir / ".events_build").iterdir()), "staging is reclaimed"


def test_a_failed_build_is_recorded_with_its_reason(sync_db, local_events, monkeypatch):
    import app.procutil as procutil
    from app.events.store import request_build_sync, run_build

    _, lf = local_events
    monkeypatch.setattr(procutil, "run_supervised", lambda *a, **k: (1, "", "Traceback…\nValueError: boom"))
    sid = request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=1)
    sync_db.commit()
    run_build(sync_db, sid)
    row = sync_db.get(EventStore, sid)
    sync_db.refresh(row)
    assert row.status == EventStoreStatus.FAILED.value and "ValueError: boom" in row.error_message


def test_a_store_deleted_while_it_built_leaves_no_files(sync_db, local_events, monkeypatch):
    """The row went (its upload deleted) between publish and the ready UPDATE: the published
    files are nobody's and are removed, not left as an orphan."""
    from app.events import store as store_mod
    from app.storage import get_storage

    upload_dir, lf = local_events
    sid = store_mod.request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=1)
    sync_db.commit()
    st = get_storage()
    real_publish = st.publish_event_store_sync

    def publish_then_vanish(sha, gen, local_dir):
        size = real_publish(sha, gen, local_dir)
        sync_db.query(EventStore).filter(EventStore.id == sid).update({"status": EventStoreStatus.EVICTED.value})
        sync_db.commit()
        return size

    monkeypatch.setattr(st, "publish_event_store_sync", publish_then_vanish)
    assert store_mod.run_build(sync_db, sid) == "superseded while building"
    assert not (upload_dir / "events" / lf.sha256).exists() or not any((upload_dir / "events" / lf.sha256).iterdir())


def test_storage_counts_stores_apart_and_spares_one_mid_publish():
    from app.storage import StoredObject
    from app.storage_usage import classify_objects

    sha = "d" * 64
    objects = [
        StoredObject(key=f"events/{sha}/auditd-b1-0123abcd/events.parquet", size=100, mtime=0.0),
        StoredObject(key=f"events/{sha}/auditd-b1-deadbeef/events.parquet", size=50, mtime=0.0),
        StoredObject(key=".events_build/7-aaaa/spool-00000.ndjson.zst", size=9, mtime=0.0),
    ]
    report = classify_objects(
        objects, known_filenames=set(), known_job_ids=set(), active_job_ids=set(), now=10_000.0, known_event_stores={f"events/{sha}/auditd-b1-0123abcd"}, build_stale_seconds=60
    )
    assert report.event_store_bytes == 150 and report.uploads_count == 0, "never mistaken for unowned uploads"
    assert report.orphan_event_stores == {(sha, "auditd-b1-deadbeef"): 50}
    assert (".events_build/7-aaaa/spool-00000.ndjson.zst", 9) in report.removable


def test_s3_publishes_the_manifest_last(tmp_path):
    from app.storage import S3Storage

    order: list[str] = []

    class _S3:
        def upload_file(self, src, bucket, key):
            order.append(key.rsplit("/", 1)[-1])

    st = S3Storage.__new__(S3Storage)
    st._s3, st._bucket = _S3(), "b"
    staging = tmp_path / "s"
    staging.mkdir()
    for name in ("manifest.json", "events.parquet", "order.parquet", "text.parquet"):
        (staging / name).write_text("x")
    st.publish_event_store_sync("e" * 64, "evtx-b1-0000abcd", staging)
    assert order[-1] == "manifest.json" and set(order[:-1]) == {"events.parquet", "order.parquet", "text.parquet"}
    assert not staging.exists()


def test_a_location_that_is_not_a_store_is_refused():
    from app.storage import event_store_prefix

    for sha, gen in (("../..", "x"), ("e" * 64, "../../job_1"), ("E" * 64, "evtx-b1-0000abcd")):
        with pytest.raises(ValueError):
            event_store_prefix(sha, gen)


def test_the_job_claim_requests_a_store(sync_db, local_events, monkeypatch):
    from app.workers import tasks

    _, lf = local_events
    queued: list[int] = []
    monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(sync_db, "close", lambda: None)
    monkeypatch.setattr(tasks, "build_event_store", queued.append)
    tasks._request_event_store(lf.id, "auditd", 42)
    assert len(queued) == 1
    assert sync_db.get(EventStore, queued[0]).requested_by_job_id == 42


async def test_deleting_the_last_job_removes_the_store_with_the_upload(admin_client, async_db, tmp_path, monkeypatch):
    from app import storage as storage_mod
    from app.config import settings
    from app.models import AnalysisJob, JobStatus, WorkflowDef

    sha = "f" * 64
    store_dir = settings.upload_dir / "events" / sha / "auditd-b1-0123abcd"
    store_dir.mkdir(parents=True)
    (store_dir / "events.parquet").write_text("x")
    (settings.upload_dir / "f.log").write_text("x")
    monkeypatch.setattr(storage_mod, "_storage", None)
    wf = WorkflowDef(name="W", description="", log_types='["auditd"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="f.log", stored_filename="f.log", sha256=sha, size_bytes=1, log_type=LogType.AUDITD, detected_type=LogType.AUDITD)
    async_db.add_all([wf, lf])
    await async_db.flush()
    job = AnalysisJob(submitted_filename="f.log", effective_log_type=LogType.AUDITD, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    async_db.add(EventStore(log_file_id=lf.id, log_type="auditd", builder_version=1, status="ready", gen="auditd-b1-0123abcd", attempts=1, truncated=False))
    await async_db.commit()
    resp = await admin_client.post(f"/jobs/{job.id}/delete", follow_redirects=False)
    assert resp.status_code in (200, 303)
    assert (await async_db.scalars(select(EventStore))).all() == []
    assert not store_dir.exists()


def _store(sync_db, lf, **values):
    row = EventStore(
        log_file_id=lf.id,
        log_type=values.pop("log_type", "auditd"),
        builder_version=values.pop("builder_version", 1),
        attempts=values.pop("attempts", 0),
        truncated=False,
        **values,
    )
    sync_db.add(row)
    sync_db.commit()
    return row


def test_the_sweep_requeues_a_dropped_build_and_fails_a_dead_one(sync_db, local_events):
    from datetime import timedelta

    from app.database import utc_now_naive
    from app.events.store import sweep_sync

    _, lf = local_events
    long_ago = utc_now_naive() - timedelta(days=1)
    dropped = _store(sync_db, lf, status="pending", requested_at=long_ago)
    dead = _store(sync_db, lf, log_type="syslog", status="building", started_at=long_ago, requested_at=long_ago, attempts=1)
    requeue, summary = sweep_sync(sync_db)
    assert dropped.id in requeue
    sync_db.refresh(dead)
    assert dead.status == "failed" and "stopped responding" in dead.error_message
    assert dead.id not in requeue, "a fresh failure waits out its backoff"
    assert "stalled" in summary


def test_the_sweep_evicts_the_least_recently_opened_past_the_cap(sync_db, local_events, monkeypatch):
    from datetime import timedelta

    from app.config import settings
    from app.database import utc_now_naive
    from app.events.store import sweep_sync

    upload_dir, lf = local_events
    monkeypatch.setattr(settings, "events_max_total_mb", 1)
    now = utc_now_naive()
    old = _store(sync_db, lf, status="ready", gen="auditd-b1-0000000a", bytes=900_000, last_accessed_at=now - timedelta(days=3))
    new = _store(sync_db, lf, log_type="syslog", status="ready", gen="syslog-b1-0000000b", bytes=900_000, last_accessed_at=now)
    for row in (old, new):
        d = upload_dir / "events" / lf.sha256 / row.gen
        d.mkdir(parents=True)
        (d / "events.parquet").write_text("x")
    _, summary = sweep_sync(sync_db)
    sync_db.refresh(old)
    sync_db.refresh(new)
    assert (old.status, old.gen) == ("evicted", None) and new.status == "ready"
    assert not (upload_dir / "events" / lf.sha256 / "auditd-b1-0000000a").exists()
    assert (upload_dir / "events" / lf.sha256 / "syslog-b1-0000000b").exists()
    assert "1 evicted" in summary


def test_the_sweep_does_nothing_when_switched_off(sync_db, local_events, monkeypatch):
    from app.config import settings
    from app.events.store import sweep_sync

    monkeypatch.setattr(settings, "events_enabled", False)
    assert sweep_sync(sync_db) == ([], "switched off")
