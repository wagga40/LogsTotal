"""Recomputing analytics must never blank a job whose raw output is gone.

``extract_all_from_raw_output`` returns ``({}, [])`` for a missing directory, which is
indistinguishable downstream from "this job matched nothing". Persisting that result would
replace good ``analytics_json`` with an all-zero blob and null ``event_markers`` — both
unrecoverable, since the source they were parsed from is what went missing.

It is not a corner case. ``S3Storage.sync_job_outputs_from_worker`` rmtree's the local tree
after the first analytics pass, so on any ``STORAGE_BACKEND=s3`` deployment *every* job is
in this state from the moment it finishes; ``/admin/cleanup-outputs`` puts local
deployments there too. Pressing "Recalculate analytics" would be enough to destroy the job.
"""

from __future__ import annotations

import pytest

from app.workers.tasks import _cache_analytics


class _Job:
    """Minimal stand-in — _cache_analytics only touches these three attributes."""

    def __init__(self, job_id: int):
        self.id = job_id
        self.analytics_json = '{"real": "analytics"}'
        self.event_markers = b"packed-index"


@pytest.fixture
def upload_dir(tmp_path, monkeypatch):
    from app.intel import event_timeline

    monkeypatch.setattr(event_timeline.settings, "upload_dir", str(tmp_path))
    return tmp_path


def test_refuses_to_write_when_the_output_directory_is_gone(upload_dir):
    job = _Job(7)  # no uploads/job_7 directory at all

    assert _cache_analytics(job, {"total_events": 0}) is False
    assert job.analytics_json == '{"real": "analytics"}'
    assert job.event_markers == b"packed-index"


def test_refuses_to_write_when_the_directory_exists_but_is_empty(upload_dir):
    """Cleanup removes the files and can leave the directory — that is still "gone"."""
    (upload_dir / "job_7").mkdir()
    job = _Job(7)

    assert _cache_analytics(job, {"total_events": 0}) is False
    assert job.analytics_json == '{"real": "analytics"}'


def test_writes_normally_when_raw_output_is_present(upload_dir):
    # Real layout: uploads/job_N/task_M/<upload-name>_<tool>.json. The trailing
    # `_<tool>.json` is what _iter_output_files matches on, so a plausible-looking
    # "zircolite.json" would not count as output.
    job_dir = upload_dir / "job_7" / "task_1"
    job_dir.mkdir(parents=True)
    (job_dir / "sysmon_zircolite.json").write_text("[]", encoding="utf-8")
    job = _Job(7)

    assert _cache_analytics(job, {"total_events": 3}) is True
    assert "real" not in job.analytics_json
    # No markers in this payload, so the index is legitimately empty — the point is that
    # the write happened at all, which is what distinguishes it from the guarded case.
    assert job.event_markers is None


def test_recalculate_task_stops_before_the_entity_pass(upload_dir, monkeypatch):
    """The guard has to short-circuit the whole recompute, not just the blob write.

    ``persist_entities_from_analytics`` is where relationship tallies are applied, so
    letting it run with an empty parse would be a second way to damage the job.
    """
    from app.workers import tasks

    called = []
    monkeypatch.setattr("app.intel.entities.persist_entities_from_analytics", lambda *a, **k: called.append(a))

    job = _Job(7)
    monkeypatch.setattr(tasks, "_compute_analytics_data", lambda _job: {"total_events": 0}, raising=False)

    assert _cache_analytics(job, {"total_events": 0}) is False
    assert called == []
