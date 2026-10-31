"""Uploads stored compressed (UPLOAD_COMPRESSION=zstd): every reader still sees the original.

A compressed upload is stored as `<key>.zst`; `load`/`load_sync` hand back a private plain
copy under `upload_dir/.decompressed/`, and `release_sync` removes it. Tools, downloads, the
event index builder and TLSH all go through those two calls, so none of them changed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from sqlalchemy import select

from app.compression_utils import compress_file, decompress_file, is_zstd_file
from app.models import AnalysisJob, JobStatus, LogFile, LogType, WorkflowDef

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
EVTX = (ROOT / "samples/windows/bitsadmin.evtx").read_bytes()


def test_compress_and_decompress_files_round_trip(tmp_path):
    src = tmp_path / "a.evtx"
    src.write_bytes(EVTX)
    packed = tmp_path / "a.evtx.zst"
    assert compress_file(src, packed) < len(EVTX) and is_zstd_file(packed)
    assert decompress_file(packed, tmp_path / "back") == len(EVTX)
    assert (tmp_path / "back").read_bytes() == EVTX
    assert decompress_file(src, tmp_path / "plain") == len(EVTX), "a plain file reads through unchanged"


@pytest.fixture()
def local(tmp_path, monkeypatch):
    from app import storage as storage_mod
    from app.config import settings

    monkeypatch.setattr(settings, "upload_dir", tmp_path / "uploads")
    (tmp_path / "uploads").mkdir()
    monkeypatch.setattr(storage_mod, "_storage", None)
    return storage_mod.get_storage(), tmp_path / "uploads"


async def test_a_local_compressed_upload_loads_as_a_private_plain_copy(local):
    st, upload_dir = local
    compress_file(_write(upload_dir / "src", EVTX), upload_dir / "x.evtx.zst")
    copy = st.load_sync("x.evtx.zst")
    assert copy.read_bytes() == EVTX and copy.name == "x.evtx"
    assert copy.parent.parent.name == ".decompressed", "under upload_dir, where the Docker-run tool can mount it"
    other = st.load_sync("x.evtx.zst")
    assert other != copy, "two readers never share a copy one of them will release"
    st.release_sync(copy)
    assert not copy.exists() and not copy.parent.exists() and other.exists()
    assert (await st.load("x.evtx.zst")).read_bytes() == EVTX
    _write(upload_dir / "plain.evtx", EVTX)
    plain = st.load_sync("plain.evtx")
    st.release_sync(plain)
    assert plain.exists(), "releasing the stored file itself never deletes it"


def test_an_s3_compressed_upload_downloads_then_decompresses(tmp_path, monkeypatch):
    from app import storage as storage_mod
    from app.config import settings
    from app.storage import S3Storage

    monkeypatch.setattr(settings, "upload_dir", tmp_path / "uploads")
    (tmp_path / "uploads").mkdir()
    packed = tmp_path / "remote.zst"
    compress_file(_write(tmp_path / "remote", EVTX), packed)

    class Bucket:
        def download_file(self, bucket, key, filename):
            Path(filename).write_bytes(packed.read_bytes())

    st = S3Storage.__new__(S3Storage)
    st._s3, st._bucket = Bucket(), "b"
    monkeypatch.setattr(storage_mod, "_storage", st)
    copy = st.load_sync("k.evtx.zst")
    assert copy.read_bytes() == EVTX
    cache = tmp_path / "uploads" / ".s3_cache"
    assert not any(p.is_file() for p in cache.rglob("*")), "the compressed download is released at once"
    st.release_sync(copy)
    assert not copy.exists()


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


@pytest.fixture()
async def evtx_workflow(async_db) -> WorkflowDef:
    wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.commit()
    await async_db.refresh(wf)
    return wf


async def test_an_upload_is_stored_compressed_and_downloads_as_uploaded(admin_client, async_db, evtx_workflow, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "upload_compression", "zstd")
    r = await admin_client.post("/upload", data={"workflow_id": str(evtx_workflow.id)}, files={"file": ("b.evtx", EVTX, "application/octet-stream")}, follow_redirects=False)
    assert r.status_code == 303
    lf = await async_db.scalar(select(LogFile))
    assert lf.stored_filename.endswith(".evtx.zst") and lf.size_bytes == len(EVTX) and lf.sha256 == hashlib.sha256(EVTX).hexdigest()
    stored = Path(settings.upload_dir) / lf.stored_filename
    assert is_zstd_file(stored) and stored.stat().st_size < len(EVTX)
    job = await async_db.scalar(select(AnalysisJob))
    download = await admin_client.get(f"/jobs/{job.id}/download")
    assert download.content == EVTX, "the download is the file as it was uploaded"
    assert not any(p.is_file() for p in (Path(settings.upload_dir) / ".decompressed").rglob("*")), "the download's copy is released"


async def test_off_stores_uploads_as_they_are(admin_client, async_db, evtx_workflow):
    r = await admin_client.post("/upload", data={"workflow_id": str(evtx_workflow.id)}, files={"file": ("b.evtx", EVTX, "application/octet-stream")}, follow_redirects=False)
    assert r.status_code == 303
    assert (await async_db.scalar(select(LogFile))).stored_filename.endswith(".evtx")


def test_the_backfill_compresses_idle_uploads_and_skips_busy_ones(sync_db, local, monkeypatch):
    import app.workers.tasks as tasks

    st, upload_dir = local
    monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
    wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    idle = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=len(EVTX), log_type=LogType.EVTX, detected_type=LogType.EVTX)
    busy = LogFile(original_filename="b.evtx", stored_filename="b.evtx", sha256="b" * 64, size_bytes=len(EVTX), log_type=LogType.EVTX, detected_type=LogType.EVTX)
    sync_db.add_all([wf, idle, busy])
    sync_db.flush()
    sync_db.add_all([AnalysisJob(file_id=idle.id, workflow_id=wf.id, status=JobStatus.COMPLETED), AnalysisJob(file_id=busy.id, workflow_id=wf.id, status=JobStatus.RUNNING)])
    sync_db.commit()
    for name in ("a.evtx", "b.evtx"):
        _write(upload_dir / name, EVTX)
    tasks.backfill_compress_uploads.call_local(None)
    sync_db.expire_all()
    assert sync_db.get(LogFile, idle.id).stored_filename == "a.evtx.zst"
    assert not (upload_dir / "a.evtx").exists() and is_zstd_file(upload_dir / "a.evtx.zst")
    copy = st.load_sync("a.evtx.zst")
    assert copy.read_bytes() == EVTX
    st.release_sync(copy)
    assert sync_db.get(LogFile, busy.id).stored_filename == "b.evtx" and (upload_dir / "b.evtx").exists(), "a running job's input is left alone"


def test_stale_decompressed_copies_are_offered_for_removal():
    from app.storage import StoredObject
    from app.storage_usage import DECOMPRESSED_STALE_SECONDS, classify_objects

    now = 1_700_000_000.0
    objects = [StoredObject(".decompressed/1-a/x.evtx", 10, now - 60), StoredObject(".decompressed/2-b/y.evtx", 20, now - DECOMPRESSED_STALE_SECONDS - 1)]
    report = classify_objects(objects, known_filenames=set(), known_job_ids=set(), active_job_ids=set(), now=now)
    assert report.removable == [(".decompressed/2-b/y.evtx", 20)] and report.uploads_bytes == 0
