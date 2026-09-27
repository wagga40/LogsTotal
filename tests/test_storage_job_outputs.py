"""Job output paths on storage backends (RAW ZIP / multi-tier deployments)."""

from __future__ import annotations

import json

import pytest


@pytest.mark.asyncio
async def test_local_resolve_job_outputs_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path)
    from app.storage import LocalStorage

    st = LocalStorage()
    assert await st.resolve_job_outputs_dir(99) is None

    root = tmp_path / "job_42"
    (root / "task_1").mkdir(parents=True)
    (root / "task_1" / "out.txt").write_text("x", encoding="utf-8")

    resolved = await st.resolve_job_outputs_dir(42)
    assert resolved is not None
    path, cleanup = resolved
    assert path == root
    assert cleanup is False
    assert st.delete_job_outputs_sync(42) is True
    assert not root.exists()


@pytest.mark.asyncio
async def test_local_resolve_empty_job_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path)
    from app.storage import LocalStorage

    (tmp_path / "job_7").mkdir()
    st = LocalStorage()
    assert await st.resolve_job_outputs_dir(7) is None


# ── S3 download cache reclamation ────────────────────────────────────────────
#
# Written on every job and pruned by nothing, `.s3_cache` would give a worker a
# permanent local copy of every log it had ever analysed — the exact thing the
# object-store backend exists to avoid.


class _FakeS3:
    """Minimal boto3 client stand-in: download_file just writes a file."""

    def __init__(self):
        self.downloads = 0

    def download_file(self, bucket, key, dest):
        self.downloads += 1
        from pathlib import Path

        Path(dest).write_text("log contents", encoding="utf-8")


@pytest.fixture()
def s3_storage(tmp_path, monkeypatch):
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path)
    from app.storage import S3Storage

    st = S3Storage.__new__(S3Storage)  # bypass __init__'s boto3 session/config
    st._s3 = _FakeS3()
    st._bucket = "test-bucket"
    return st


def test_release_sync_reclaims_the_download_cache(tmp_path, s3_storage):
    path = s3_storage.load_sync("abc_sample.evtx")
    assert path.exists() and ".s3_cache" in str(path)

    s3_storage.release_sync(path)
    assert not path.exists(), "the cached copy must not outlive the job"


def test_release_sync_refuses_paths_outside_the_cache(tmp_path, s3_storage):
    """A mistaken call must never delete a real upload."""
    real_upload = tmp_path / "not_a_cache_entry.evtx"
    real_upload.write_text("precious", encoding="utf-8")

    s3_storage.release_sync(real_upload)

    assert real_upload.exists()


def test_release_sync_is_a_noop_on_local_storage(tmp_path, monkeypatch):
    """LocalStorage hands back the stored file itself — releasing must not delete it."""
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path)
    from app.storage import LocalStorage

    stored = tmp_path / "kept.evtx"
    stored.write_text("x", encoding="utf-8")

    LocalStorage().release_sync(stored)

    assert stored.exists()


@pytest.mark.asyncio
async def test_s3_load_runs_the_blocking_download_off_the_event_loop(s3_storage):
    """`load` is async but boto3 is blocking. Left inline it stalls every other request
    — including the 3s job-status polls and /health — for the whole download.

    Asserting the *thread* is what discriminates: a coroutine with no internal await
    still completes without yielding, so timing or sibling-task tricks pass either way.
    """
    import threading

    main_thread = threading.get_ident()
    seen: list[int] = []
    original = s3_storage._s3.download_file

    def recording(bucket, key, dest):
        seen.append(threading.get_ident())
        return original(bucket, key, dest)

    s3_storage._s3.download_file = recording

    await s3_storage.load("abc_sample.evtx")

    assert seen and seen[0] != main_thread, "boto3 download ran on the event loop thread"


@pytest.mark.asyncio
async def test_s3_resolve_job_outputs_dir_runs_off_the_event_loop(s3_storage):
    """Worse than load(): a paginated list plus one blocking download per output file."""
    import threading

    main_thread = threading.get_ident()
    seen: list[int] = []

    class _Paginator:
        def paginate(self, **kwargs):
            seen.append(threading.get_ident())
            return [{"Contents": [{"Key": "job_7/task_1/out.txt"}]}]

    s3_storage._s3.get_paginator = lambda name: _Paginator()

    resolved = await s3_storage.resolve_job_outputs_dir(7)

    assert resolved is not None
    assert seen and seen[0] != main_thread, "S3 listing ran on the event loop thread"


# ── Every raw-output reader goes through the backend ─────────────────────────


def test_process_tree_reads_through_storage_not_the_upload_dir(tmp_path, monkeypatch, fake_redis):
    """The process tree was blank on every S3 deployment and perfect on local disk.

    On S3 the worker uploads a job's output tree and then removes its local copy, and in a
    multi-server layout the web tier was never the machine that wrote it. Reading
    `settings.upload_dir / f"job_{id}"` directly therefore finds nothing — and because
    "nothing" is indistinguishable from "this job has no processes", the page renders its
    own empty state and nothing anywhere reports a problem.

    This stands in a backend whose output lives somewhere else entirely, which is the one
    thing a local-disk test can never do.
    """
    from app import storage as storage_mod
    from app.intel import process_tree

    # Where the app thinks uploads are — deliberately left empty, as on a real control plane.
    monkeypatch.setattr("app.config.settings.upload_dir", tmp_path / "uploads")

    elsewhere = tmp_path / "somewhere-else" / "job_5"
    (elsewhere / "task_1").mkdir(parents=True)
    # A zircolite-shaped file: the parser reads `matches`, and one Sysmon EID 1 event is
    # all `build_process_forest` needs to produce a root.
    (elsewhere / "task_1" / "sysmon_zircolite.json").write_text(
        json.dumps(
            [
                {
                    "title": "Suspicious process",
                    "id": "r-1",
                    "level": "high",
                    "count": 1,
                    "matches": [
                        {
                            "EventID": 1,
                            "ProcessGuid": "{g-1}",
                            "ProcessId": "10",
                            "Image": r"C:\\evil.exe",
                            "Computer": "WS01",
                            "UtcTime": "2024-01-01 09:00:00",
                        }
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )

    class _Remote:
        """Stands for S3: the tree is not under upload_dir, and it is a disposable copy."""

        def __init__(self):
            self.asked = 0

        def resolve_job_outputs_dir_sync(self, job_id):
            self.asked += 1
            return (elsewhere, False) if job_id == 5 else None

    remote = _Remote()
    monkeypatch.setattr(storage_mod, "get_storage", lambda: remote)

    forest = process_tree.build_job_forest_sync(5)

    assert remote.asked == 1, "the reader never asked the storage backend where the output is"
    assert forest["roots"], "no processes were parsed — the reader looked in upload_dir"


def test_a_temporary_copy_is_always_cleaned_up(tmp_path, monkeypatch):
    """S3 hands back a temp copy of a whole job's output. A parse that raises must not
    leave it behind — on a busy instance that fills the container's disk."""
    from app import storage as storage_mod

    copy = tmp_path / "job_9_raw_abc"
    copy.mkdir()
    (copy / "x.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(storage_mod, "get_storage", lambda: type("S", (), {"resolve_job_outputs_dir_sync": staticmethod(lambda _id: (copy, True))})())

    with pytest.raises(RuntimeError), storage_mod.job_outputs_dir(9):
        raise RuntimeError("the parse blew up")

    assert not copy.exists(), "the temporary copy survived an exception"


def test_a_storage_outage_degrades_to_the_empty_state(tmp_path, monkeypatch):
    """A backend that cannot answer must not turn every process tree into a 500."""
    from app import storage as storage_mod

    def _boom():
        raise RuntimeError("the object store is unreachable")

    monkeypatch.setattr(storage_mod, "get_storage", _boom)
    with storage_mod.job_outputs_dir(1) as job_dir:
        assert job_dir is None


def test_both_readers_accept_the_resolved_directory():
    """`has_raw_output` and `extract_all_from_raw_output` must take the same override, or
    the case-timeline coverage notice and its buckets disagree about the same job."""
    import inspect

    from app.intel import event_timeline

    assert "job_dir" in inspect.signature(event_timeline.has_raw_output).parameters
    assert "job_dir" in inspect.signature(event_timeline.extract_all_from_raw_output).parameters
