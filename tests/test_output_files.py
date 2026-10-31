"""Raw tool outputs at rest: compressed once a job is done, read and exported the same way.

Measured on job 12's real outputs: 276 MB -> 7 MB. The trap these tests guard: a reader that
stops recognising `<name>.zst` makes has_raw_output() false, and _cache_analytics then writes
no analytics, markers or entities for every new job — silently. The output-parity suite runs
every recorded case on compressed copies; these cover the module and the two edges.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.tools.output_files import ZST_SUFFIX, compress_job_outputs, compress_output_file, logical_name, open_output

pytestmark = pytest.mark.anyio

PAYLOAD = "\n".join(json.dumps({"Timestamp": "2026-01-01T00:00:00Z", "RuleTitle": f"r{i}", "Details": {"Cmd": "whoami " * 20}}) for i in range(200))


def test_logical_name_strips_only_the_compression_suffix():
    assert logical_name("abc_hayabusa.json.zst") == "abc_hayabusa.json"
    assert logical_name("abc_hayabusa.json") == "abc_hayabusa.json"
    assert logical_name("ABC_RSIGMA.JSON.ZST") == "ABC_RSIGMA.JSON"


def test_compressing_replaces_the_file_atomically_and_keeps_its_content(tmp_path):
    out = tmp_path / "x_hayabusa.json"
    out.write_text(PAYLOAD)
    saved = compress_output_file(out)
    target = tmp_path / ("x_hayabusa.json" + ZST_SUFFIX)
    assert saved > 0 and not out.exists() and target.is_file()
    assert [p.name for p in tmp_path.iterdir()] == [target.name], "no .part left behind"
    with open_output(target) as stream:
        assert stream.read().decode() == PAYLOAD
    assert compress_output_file(target) == 0, "an already-compressed file is left alone"


def test_a_plain_file_still_reads_through_the_same_opener(tmp_path):
    out = tmp_path / "x_chainsaw.json"
    out.write_text(PAYLOAD)
    with open_output(out) as stream:
        assert stream.read().decode() == PAYLOAD


def test_only_tool_outputs_are_compressed(tmp_path):
    task = tmp_path / "task_1"
    task.mkdir()
    (task / "x_hayabusa.json").write_text(PAYLOAD)
    (task / "notes.txt").write_text(PAYLOAD)
    files, saved = compress_job_outputs(tmp_path)
    assert files == 1 and saved > 0
    assert sorted(p.name for p in task.iterdir()) == ["notes.txt", "x_hayabusa.json.zst"]


def test_a_file_that_cannot_be_compressed_stays_plain_and_nothing_raises(tmp_path, monkeypatch):
    import app.tools.output_files as of

    (tmp_path / "x_hayabusa.json").write_text(PAYLOAD)

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(of, "open_write", boom)
    assert compress_job_outputs(tmp_path) == (0, 0)
    assert (tmp_path / "x_hayabusa.json").read_text() == PAYLOAD
    assert not list(tmp_path.glob("*.part"))


def test_has_raw_output_sees_a_compressed_only_job(tmp_path):
    """The trap: _cache_analytics writes nothing when this is false."""
    from app.intel.event_timeline import has_raw_output

    task = tmp_path / "job_7" / "task_1"
    task.mkdir(parents=True)
    (task / "x_hayabusa.json").write_text(PAYLOAD)
    compress_job_outputs(tmp_path / "job_7")
    assert not (task / "x_hayabusa.json").exists()
    assert has_raw_output(7, job_dir=tmp_path / "job_7")


async def test_the_raw_export_carries_the_files_the_tools_wrote(admin_client, async_db, tmp_path):
    """The archive is for analysts and other tools: original names, original bytes."""
    from app.config import settings
    from app.models import AnalysisJob, JobStatus, LogFile, LogType, WorkflowDef

    wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([wf, lf])
    await async_db.flush()
    job = AnalysisJob(submitted_filename="a.evtx", effective_log_type=LogType.EVTX, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.commit()
    task = settings.upload_dir / f"job_{job.id}" / "task_1"
    task.mkdir(parents=True)
    (task / "x_hayabusa.json").write_text(PAYLOAD)
    (task / "x_chainsaw.json").write_text("plain one")
    compress_output_file(task / "x_hayabusa.json")

    resp = await admin_client.get(f"/jobs/{job.id}/export-raw")
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        assert sorted(zf.namelist()) == ["task_1/x_chainsaw.json", "task_1/x_hayabusa.json"]
        assert zf.read("task_1/x_hayabusa.json").decode() == PAYLOAD
        assert zf.read("task_1/x_chainsaw.json").decode() == "plain one"


def _job(sync_db, status):
    from app.models import AnalysisJob, LogFile, LogType, WorkflowDef

    wf = sync_db.query(WorkflowDef).first()
    if wf is None:
        wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
        lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
        sync_db.add_all([wf, lf])
        sync_db.flush()
    lf = sync_db.query(LogFile).first()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=status)
    sync_db.add(job)
    sync_db.commit()
    return job.id


def test_the_backfill_compresses_finished_jobs_and_skips_running_ones(sync_db, tmp_path, monkeypatch):
    from app import storage as storage_mod
    from app.models import JobStatus
    from app.workers import tasks

    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path)
    monkeypatch.setattr(storage_mod, "_storage", None)
    monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(sync_db, "close", lambda: None)
    done, running = _job(sync_db, JobStatus.COMPLETED), _job(sync_db, JobStatus.RUNNING)
    for jid in (done, running):
        (tmp_path / f"job_{jid}" / "task_1").mkdir(parents=True)
        (tmp_path / f"job_{jid}" / "task_1" / "x_hayabusa.json").write_text(PAYLOAD)

    tasks.backfill_compress_outputs.call_local(None)

    assert (tmp_path / f"job_{done}" / "task_1" / "x_hayabusa.json.zst").is_file()
    assert (tmp_path / f"job_{running}" / "task_1" / "x_hayabusa.json").is_file(), "a running job's tree is still being written"


class _Bucket:
    """In-memory S3 for the compress path: list, download, upload, delete."""

    def __init__(self, objects):
        self.objects = dict(objects)

    def get_paginator(self, _name):
        bucket = self

        class _P:
            def paginate(self, Bucket, Prefix=""):
                yield {"Contents": [{"Key": k, "Size": len(v)} for k, v in sorted(bucket.objects.items()) if k.startswith(Prefix)]}

        return _P()

    def download_file(self, bucket, key, dest):
        from pathlib import Path

        Path(dest).write_bytes(self.objects[key])

    def upload_file(self, src, bucket, key):
        from pathlib import Path

        self.objects[key] = Path(src).read_bytes()

    def delete_object(self, Bucket, Key):
        del self.objects[Key]


def test_s3_outputs_are_rewritten_with_the_plain_key_removed_last(tmp_path, monkeypatch):
    from app.compression_utils import decompress
    from app.storage import S3Storage

    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path)
    st = S3Storage.__new__(S3Storage)
    st._bucket = "b"
    st._s3 = _Bucket({"job_9/task_1/x_hayabusa.json": PAYLOAD.encode(), "job_9/task_1/notes.txt": b"keep", "123_upload.evtx": b"evtx"})
    files, saved = st.compress_job_outputs_sync(9)
    assert files == 1 and saved > 0
    assert sorted(st._s3.objects) == ["123_upload.evtx", "job_9/task_1/notes.txt", "job_9/task_1/x_hayabusa.json.zst"]
    assert decompress(st._s3.objects["job_9/task_1/x_hayabusa.json.zst"]).decode() == PAYLOAD
    assert not list((tmp_path / ".s3_cache").iterdir()), "the work directory is reclaimed"
