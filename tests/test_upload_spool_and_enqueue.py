"""Two ways POST /upload can fail after the bytes are already on disk.

**A long filename must not be an anonymous 500.** New storage keys are opaque UUIDs
with content-derived extensions. Submission filenames remain bounded independently.

**And no such failure may leak its spool file.** A temp file unlinked only on the explicit
rejection branches is left behind for good by anything raised in detection, storage or the
commit: `purge_orphaned_storage` is not a periodic task, it runs when an admin clicks Purge
orphans. The residue accumulates until the free-space guard starts answering 507 to
everyone and uploads stop site-wide.

The enqueue tests cover the fourth wall of the same room: the row is committed *before* the
task is queued, so a queue that refuses it would leave the visitor a 500 and a job that
polls PENDING until `HUEY_QUEUE_EXPIRY` sweeps it. Marking the row FAILED is the
load-bearing half — the 503 is only what the caller sees.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.config import settings
from app.models import (
    AiAnalysisStatus,
    AiProvider,
    AnalysisJob,
    BackgroundTask,
    BackgroundTaskStatus,
    JobAiAnalysis,
    JobStatus,
    LogFile,
    LogType,
    WorkflowDef,
)

_EVTX_BODY = b"ElfFile\x00" + b"\x00" * 100

# 255 bytes is NAME_MAX on ext4, xfs and APFS alike.
_NAME_MAX_BYTES = 255


@pytest.fixture()
async def workflow(async_db) -> WorkflowDef:
    wf = WorkflowDef(
        name="Spool WF",
        description="",
        log_types='["evtx"]',
        tasks_yaml="tasks: []",
        is_default=True,
    )
    async_db.add(wf)
    await async_db.commit()
    await async_db.refresh(wf)
    return wf


def _spooled(tmp_dir) -> list[str]:
    """Whatever `mkstemp(suffix=".upload")` left behind in the upload directory."""
    return sorted(p.name for p in tmp_dir.glob("*.upload"))


async def _upload(client, workflow_id: int, filename: str, body: bytes = _EVTX_BODY):
    return await client.post(
        "/upload",
        data={"workflow_id": str(workflow_id), "log_type_override": "auto"},
        files={"file": (filename, body, "application/octet-stream")},
        follow_redirects=False,
    )


@pytest.mark.parametrize(
    "filename",
    [
        "A" * 300 + ".evtx",
        # 120 CJK characters is 360 bytes: a name that is comfortably under any character
        # count you would think to cap at, and still twice NAME_MAX.
        "日" * 120 + ".evtx",
    ],
    ids=["ascii", "cjk"],
)
async def test_a_filename_past_name_max_uploads_instead_of_500ing(test_client, async_db, workflow, filename):
    resp = await _upload(test_client, workflow.id, filename)
    assert resp.status_code == 303, resp.text
    assert "/jobs/" in resp.headers.get("location", "")

    log_file = await async_db.scalar(select(LogFile))
    assert log_file is not None
    assert len(log_file.stored_filename.encode("utf-8")) <= _NAME_MAX_BYTES
    # Only the on-disk name is capped — what the visitor sent is the record.
    assert log_file.original_filename == filename
    assert _spooled(settings.upload_dir) == []


async def _upload_raw_filename(client, workflow_id: int, filename: bytes, body: bytes = _EVTX_BODY):
    """A multipart body built by hand, because httpx will not put a NUL in a filename."""
    boundary = b"lt-boundary"
    payload = (
        b"--" + boundary + b'\r\nContent-Disposition: form-data; name="workflow_id"\r\n\r\n' + str(workflow_id).encode() + b"\r\n"
        b"--" + boundary + b'\r\nContent-Disposition: form-data; name="file"; filename="' + filename + b'"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n" + body + b"\r\n--" + boundary + b"--\r\n"
    )
    return await client.post("/upload", content=payload, headers={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"}, follow_redirects=False)


async def test_a_control_character_in_the_filename_uploads_instead_of_500ing(test_client, async_db, workflow):
    """`os.replace` raises ValueError, not OSError, on an embedded NUL — past the handler
    that turns a storage failure into something other than an anonymous 500."""
    resp = await _upload_raw_filename(test_client, workflow.id, b"re\x00port\x1b.evtx")
    assert resp.status_code == 303, resp.text

    log_file = await async_db.scalar(select(LogFile))
    assert log_file.original_filename == "report.evtx"
    assert "\x00" not in log_file.stored_filename
    assert _spooled(settings.upload_dir) == []


async def test_an_original_filename_longer_than_its_column_is_cut_to_fit(test_client, async_db, workflow):
    """`original_filename` is String(512). SQLite stores more, PostgreSQL refuses at commit —
    after the bytes were already moved into place, orphaning them."""
    resp = await _upload(test_client, workflow.id, "A" * 600 + ".evtx")
    assert resp.status_code == 303, resp.text

    log_file = await async_db.scalar(select(LogFile))
    assert len(log_file.original_filename) <= 512
    assert log_file.original_filename.endswith(".evtx"), "the extension is the half worth keeping"


async def test_a_commit_that_fails_after_the_file_is_stored_removes_it(test_client, async_db, workflow, monkeypatch):
    """The stored object has no row pointing at it, so nothing would ever find it again
    short of an admin's Purge orphans — and each retry parks another copy."""
    real_commit = async_db.commit

    async def commit():
        if any(isinstance(obj, LogFile) for obj in async_db.identity_map.values()):
            raise RuntimeError("value too long for type character varying(512)")
        await real_commit()

    monkeypatch.setattr(async_db, "commit", commit)

    with pytest.raises(RuntimeError):
        await _upload(test_client, workflow.id, "ordinary.evtx")

    leftovers = [p.name for p in settings.upload_dir.iterdir() if p.is_file()]
    assert leftovers == []


async def test_a_failure_after_spooling_still_drops_the_spool_file(test_client, workflow, monkeypatch):
    """Detection is one of six things between mkstemp and the commit that can raise."""

    def _boom(path):
        raise RuntimeError("detection exploded")

    monkeypatch.setattr("app.routers.upload.detect_log_type", _boom)

    with pytest.raises(RuntimeError):
        await _upload(test_client, workflow.id, "ordinary.evtx")

    assert _spooled(settings.upload_dir) == []


async def test_upload_answers_503_and_fails_the_job_when_the_queue_is_down(test_client, async_db, workflow, monkeypatch):
    """A job nobody will ever run must not be left polling PENDING for half an hour."""

    def _boom(job_id):
        raise ConnectionError("Redis is unreachable")

    monkeypatch.setattr("app.routers.upload.run_analysis", _boom)

    resp = await _upload(test_client, workflow.id, "queued.evtx")
    assert resp.status_code == 503

    job = await async_db.scalar(select(AnalysisJob))
    assert job is not None
    await async_db.refresh(job)
    assert job.status == JobStatus.FAILED
    assert job.error_message
    assert job.finished_at is not None
    assert _spooled(settings.upload_dir) == []


async def test_resubmit_answers_503_and_fails_the_job_when_the_queue_is_down(admin_client, async_db, workflow, monkeypatch):
    log_file = LogFile(
        original_filename="a.evtx",
        stored_filename="stored_a.evtx",
        sha256="a" * 64,
        size_bytes=len(_EVTX_BODY),
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(log_file)
    await async_db.commit()
    await async_db.refresh(log_file)

    def _boom(job_id):
        raise ConnectionError("Redis is unreachable")

    monkeypatch.setattr("app.workers.tasks.run_analysis", _boom)

    resp = await admin_client.post(
        "/jobs/resubmit",
        data={"file_id": str(log_file.id), "workflow_id": str(workflow.id)},
        follow_redirects=False,
    )
    assert resp.status_code == 503

    job = await async_db.scalar(select(AnalysisJob))
    assert job is not None
    await async_db.refresh(job)
    assert job.status == JobStatus.FAILED


async def test_recalculate_answers_503_and_fails_the_task_row_when_the_queue_is_down(admin_client, async_db, workflow, monkeypatch):
    log_file = LogFile(
        original_filename="a.evtx",
        stored_filename="stored_a.evtx",
        sha256="b" * 64,
        size_bytes=len(_EVTX_BODY),
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(log_file)
    await async_db.commit()
    job = AnalysisJob(file_id=log_file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)

    def _boom(job_id):
        raise ConnectionError("Redis is unreachable")

    monkeypatch.setattr("app.workers.tasks.recalculate_single_analytics", _boom)

    resp = await admin_client.post(f"/jobs/{job.id}/recalculate-analytics", follow_redirects=False)
    assert resp.status_code == 503

    bt = await async_db.scalar(select(BackgroundTask))
    assert bt is not None
    await async_db.refresh(bt)
    assert bt.status == BackgroundTaskStatus.FAILED
    assert bt.error_message


async def test_ai_run_answers_503_and_fails_the_run_row_when_the_queue_is_down(member_client, async_db, workflow, monkeypatch):
    log_file = LogFile(
        original_filename="a.evtx",
        stored_filename="stored_a.evtx",
        sha256="c" * 64,
        size_bytes=len(_EVTX_BODY),
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add(log_file)
    provider = AiProvider(name="Local Ollama", kind="openai", base_url="http://127.0.0.1:11434/v1", model="qwen3:8b", enabled=True, is_default=True)
    async_db.add(provider)
    from app.site_settings import get_site_settings

    (await get_site_settings(async_db)).show_ai_analysis = True  # off by default, and it gates starting a run
    await async_db.commit()
    job = AnalysisJob(file_id=log_file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)
    await async_db.refresh(provider)

    def _boom(analysis_id):
        raise ConnectionError("Redis is unreachable")

    monkeypatch.setattr("app.workers.tasks.run_ai_analysis", _boom)

    resp = await member_client.post(f"/jobs/{job.id}/ai-analysis", data={"provider_id": str(provider.id)}, headers={"HX-Request": "true"})
    assert resp.status_code == 503

    run = await async_db.scalar(select(JobAiAnalysis))
    assert run is not None
    await async_db.refresh(run)
    assert run.status == AiAnalysisStatus.FAILED
    assert run.error_message


async def test_storage_initialization_failure_cleans_the_spool(test_client, workflow, monkeypatch):
    def unavailable_storage():
        raise ConnectionError("storage configuration unavailable")

    monkeypatch.setattr("app.storage.get_storage", unavailable_storage)
    with pytest.raises(ConnectionError):
        await _upload(test_client, workflow.id, "storage.evtx")
    assert _spooled(settings.upload_dir) == []
