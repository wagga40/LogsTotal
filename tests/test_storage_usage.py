"""Storage classification, and the two windows where a healthy instance looks broken.

Classification is pure, so every orphan kind is exercised here as data rather than by
manufacturing a filesystem. The two false-positive tests are the reason the pure/impure
split exists at all: both describe a moment during normal operation when an object has no
owner *yet*, and getting either wrong means offering to delete live data.
"""

from __future__ import annotations

import time

import pytest

from app.storage import StoredObject
from app.storage_usage import (
    MAX_ENTRIES_SCANNED,
    TMP_SPOOL_STALE_SECONDS,
    classify_objects,
    job_id_of,
)

NOW = 1_700_000_000.0


def obj(key: str, size: int = 100, *, age: float = 0.0) -> StoredObject:
    return StoredObject(key=key, size=size, mtime=NOW - age)


def classify(objects, **kwargs):
    kwargs.setdefault("known_filenames", set())
    kwargs.setdefault("known_job_ids", set())
    kwargs.setdefault("active_job_ids", set())
    kwargs.setdefault("now", NOW)
    return classify_objects(objects, **kwargs)


# ── Key parsing ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("key,expected", [("job_7/task_1/out.json", 7), ("job_42/x", 42), ("job_7", None), ("abc_job_7/x", None), ("upload.evtx", None)])
def test_job_id_is_read_from_the_key(key, expected):
    assert job_id_of(key) == expected


def test_windows_separators_are_handled():
    assert job_id_of("job_9\\task_1\\out.json") == 9


# ── The breakdown ────────────────────────────────────────────────────────────


def test_uploads_and_outputs_are_counted_separately():
    """The dashboard total has always been uploads alone, which excludes what is usually
    most of the growth."""
    report = classify(
        [obj("a.evtx", 1000), obj("b.evtx", 500), obj("job_1/task_1/out.json", 300), obj("job_2/task_1/out.json", 200)],
        known_filenames={"a.evtx", "b.evtx"},
        known_job_ids={1, 2},
    )
    assert report.uploads_bytes == 1500
    assert report.uploads_count == 2
    assert report.outputs_bytes == 500
    assert report.outputs_count == 2
    assert report.total_bytes == 2000


def test_largest_consumers_are_ranked():
    report = classify(
        [obj("small.evtx", 10), obj("huge.evtx", 9000), obj("job_1/a", 5), obj("job_2/a", 700)],
        known_filenames={"small.evtx", "huge.evtx"},
        known_job_ids={1, 2},
    )
    assert report.largest_uploads[0] == ("huge.evtx", 9000)
    assert report.largest_jobs[0] == (2, 700)


def test_output_bytes_are_summed_per_job():
    report = classify([obj("job_3/task_1/a", 100), obj("job_3/task_2/b", 250)], known_job_ids={3})
    assert report.largest_jobs == [(3, 350)]


# ── Orphans ──────────────────────────────────────────────────────────────────


def test_output_for_a_deleted_job_is_an_orphan():
    """The retention sweep walks jobs, so it can never reach these."""
    report = classify([obj("job_99/task_1/out.json", 400)], known_job_ids=set())
    group = next(g for g in report.orphans if g.kind == "orphan_outputs")
    assert group.count == 1
    assert group.bytes == 400
    assert report.orphan_job_ids == {99}


def test_a_stored_file_with_no_row_is_an_orphan():
    report = classify([obj("ghost.evtx", 800)], known_filenames=set())
    group = next(g for g in report.orphans if g.kind == "unowned_upload")
    assert group.count == 1
    assert group.bytes == 800


def test_a_stale_upload_spool_is_an_orphan():
    report = classify([obj("tmpabc123.upload", 50, age=TMP_SPOOL_STALE_SECONDS + 60)])
    group = next(g for g in report.orphans if g.kind == "tmp_spool")
    assert group.count == 1
    assert "tmpabc123.upload" in report.removable_keys


def test_a_fresh_upload_spool_is_left_alone():
    """A 500 MB upload over a slow link is legitimately still in flight."""
    report = classify([obj("tmpabc123.upload", 50, age=10)])
    assert not [g for g in report.orphans if g.kind == "tmp_spool"]
    assert report.removable_keys == []


def test_the_health_probe_is_never_offered_for_removal():
    """The storage check cleans up after itself; a straggler is noise, not an action."""
    report = classify([obj(".health-probe-abc123", 1)])
    assert report.orphans == []
    assert report.other_count == 1


# ── The two false-positive windows ───────────────────────────────────────────


def test_a_running_jobs_output_directory_is_not_an_orphan():
    """On S3 the tree is uploaded AFTER the analytics pass, so mid-job it exists only
    locally and the row is not terminal. Offering to delete it would destroy live work."""
    report = classify([obj("job_5/task_1/out.json", 900)], known_job_ids=set(), active_job_ids={5})
    assert not [g for g in report.orphans if g.kind == "orphan_outputs"]
    assert report.orphan_job_ids == set()


def test_a_recent_s3_cache_entry_belongs_to_a_live_reader():
    """A worker analysing a 400 MB upload holds its private copy for the whole run."""
    report = classify([obj(".s3_cache/123-abc/file.evtx", 400, age=60)], worker_alive_ttl=180)
    assert not [g for g in report.orphans if g.kind == "s3_cache"]


def test_an_old_s3_cache_entry_is_reclaimable():
    report = classify([obj(".s3_cache/123-abc/file.evtx", 400, age=100_000)], worker_alive_ttl=180)
    group = next(g for g in report.orphans if g.kind == "s3_cache")
    assert group.count == 1


# ── Bounds and honesty ───────────────────────────────────────────────────────


def test_a_capped_scan_says_so_rather_than_under_reporting():
    """The `total_edges_is_floor` convention: a truncated total that claims to be complete
    is worse than one that admits it is a floor."""
    objects = (obj(f"file_{i}.evtx", 1) for i in range(MAX_ENTRIES_SCANNED + 10))
    report = classify(objects)
    assert report.truncated is True


def test_an_uncapped_scan_does_not_claim_truncation():
    assert classify([obj("a.evtx")]).truncated is False


def test_reclaimable_bytes_is_the_sum_of_the_reclaimable_groups():
    report = classify([obj("job_99/a", 100), obj("ghost.evtx", 200)])
    assert report.reclaimable_bytes == 300


def test_an_empty_backend_reports_nothing_rather_than_failing():
    report = classify([])
    assert report.total_bytes == 0
    assert report.orphans == []


# ── The cache ────────────────────────────────────────────────────────────────


def test_the_cache_serves_a_second_call_without_rewalking():
    from app import storage_usage

    storage_usage.reset_cache()
    calls = []

    def _gather():
        calls.append(1)
        report = storage_usage.UsageReport()
        report.ran_at = time.time()
        return report

    storage_usage.cached_usage(gather=_gather)
    storage_usage.cached_usage(gather=_gather)
    assert len(calls) == 1
    storage_usage.reset_cache()


def test_force_bypasses_the_cache():
    """Exactly what the Rescan button sends."""
    from app import storage_usage

    storage_usage.reset_cache()
    calls = []

    def _gather():
        calls.append(1)
        report = storage_usage.UsageReport()
        report.ran_at = time.time()
        return report

    storage_usage.cached_usage(gather=_gather)
    storage_usage.cached_usage(gather=_gather, force=True)
    assert len(calls) == 2
    storage_usage.reset_cache()


def test_a_storage_failure_is_reported_not_raised():
    """A storage report must never 500 the page an admin opens to diagnose storage."""
    from app import storage_usage

    class _Broken:
        def iter_objects_sync(self, prefix=None):
            raise RuntimeError("bucket unreachable")

    import app.storage as storage_module

    original = storage_module.get_storage
    storage_usage.get_storage = lambda: _Broken()
    try:
        report = storage_usage.gather_usage_sync(known_filenames=set(), known_job_ids=set(), active_job_ids=set())
        assert report.error and "unreachable" in report.error
    finally:
        storage_usage.get_storage = original


# ── Database footprint ───────────────────────────────────────────────────────


def test_the_footprint_uses_the_databases_own_accounting():
    """Never SUM(LENGTH(col)): on PostgreSQL that detoasts every row of the largest table,
    ignores indexes, and counts characters rather than bytes."""
    # Strip the docstring first: it explains at length *why* SUM(LENGTH(col)) is wrong,
    # so a naive substring check would fail on the explanation rather than the code.
    import ast
    import inspect

    from app import storage_usage

    tree = ast.parse(inspect.getsource(storage_usage.database_footprint_sync))
    func = tree.body[0]
    if isinstance(func.body[0], ast.Expr) and isinstance(func.body[0].value, ast.Constant):
        func.body = func.body[1:]
    body = ast.unparse(func)

    assert "pg_total_relation_size" in body
    assert "length(" not in body.lower()


def test_the_footprint_reports_a_total():
    from app import storage_usage

    result = storage_usage.database_footprint_sync()
    assert result["error"] is None
    assert result["total_bytes"] is not None


def test_the_footprint_admits_what_it_cannot_measure():
    """SQLite's per-table breakdown needs the `dbstat` extension, which most CPython builds
    omit. Saying so beats inventing a number."""
    import inspect

    from app import storage_usage

    source = inspect.getsource(storage_usage.database_footprint_sync)
    assert "dbstat" in source
    assert 'result["note"]' in source
