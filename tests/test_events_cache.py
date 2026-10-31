"""The histogram axis, and stores at a local path for the engine: in place, or fetched from S3."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from app.events import cache as cache_mod
from app.events import histogram
from app.events.manifest import FORMAT, FORMAT_VERSION

SHA = "a" * 64
GEN = "evtx-b1-0000abcd"


# ── histogram axis ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("span", "width_px", "bucket"),
    [(10, 800, 1), (3600, 800, 30), (86_400, 800, 600), (86_400 * 30, 800, 21_600), (86_400 * 365 * 3, 48, 365 * 86_400), (0, 800, 1)],
)
def test_the_bucket_fits_the_span_in_the_bars(span, width_px, bucket):
    start = datetime(2026, 1, 1, 0, 0, 7)
    ax = histogram.axis(start, datetime.fromtimestamp(start.timestamp() + span), width_px)
    assert ax.bucket_seconds == bucket
    assert ax.bins <= histogram.max_bins(width_px), "alignment never adds bars past the cap"
    assert ax.origin <= start < ax.end, "the first event has a bar"


def test_the_axis_is_aligned_and_inclusive():
    ax = histogram.axis(datetime(2026, 1, 1, 10, 7), datetime(2026, 1, 1, 13, 0), 48)
    assert ax.origin == datetime(2026, 1, 1, 10, 0) and ax.bucket_seconds == 1800
    assert ax.end > datetime(2026, 1, 1, 13, 0), "the newest event is inside the last bar, not past it"
    assert histogram.axis(datetime(2026, 1, 2), datetime(2026, 1, 1), 48).origin == datetime(2026, 1, 1), "a reversed range is the same range"


def test_bars_per_pixel():
    assert histogram.max_bins(0) == histogram.MIN_BINS and histogram.max_bins(10_000) == histogram.MAX_BINS and histogram.max_bins(800) == 200


# ── store cache ──────────────────────────────────────────────────────────────


def _store_files(directory: Path) -> dict[str, bytes]:
    directory.mkdir(parents=True)
    files = {"events.parquet": b"E" * 50, "order.parquet": b"O" * 20}
    for name, data in files.items():
        (directory / name).write_bytes(data)
    manifest = {"format": FORMAT, "format_version": FORMAT_VERSION, "status": "complete", "columns": [], "files": [{"name": n, "bytes": len(d)} for n, d in files.items()]}
    (directory / "manifest.json").write_text(json.dumps(manifest))
    return {name: (directory / name).read_bytes() for name in [*files, "manifest.json"]}


class _Bucket:
    """The two calls the S3 backend's fetches make, over a dict of keys."""

    def __init__(self, objects: dict[str, bytes]):
        self.objects, self.downloads = objects, 0

    def download_file(self, bucket, key, filename):
        from botocore.exceptions import ClientError

        if key not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "GetObject")
        self.downloads += 1
        Path(filename).write_bytes(self.objects[key])


@pytest.fixture()
def s3(tmp_path, monkeypatch):
    from app import storage as storage_mod
    from app.config import settings
    from app.storage import S3Storage

    monkeypatch.setattr(settings, "upload_dir", tmp_path / "uploads")
    files = _store_files(tmp_path / "remote")
    objects = {f"events/{SHA}/{GEN}/{name}": data for name, data in files.items()}
    st = S3Storage.__new__(S3Storage)
    st._s3, st._bucket = _Bucket(objects), "b"
    monkeypatch.setattr(storage_mod, "_storage", st)
    return st, objects


def test_a_local_store_is_used_where_it_lies(tmp_path, monkeypatch):
    from app import storage as storage_mod
    from app.config import settings

    monkeypatch.setattr(settings, "upload_dir", tmp_path)
    monkeypatch.setattr(storage_mod, "_storage", None)
    _store_files(tmp_path / "events" / SHA / GEN)
    with cache_mod.store_dir(SHA, GEN) as root:
        assert root == (tmp_path / "events" / SHA / GEN).resolve()
    assert not (tmp_path / ".events_cache" / "stores").exists()
    assert cache_mod.overlay_dir(SHA, GEN, 1, "abc") is None


def test_an_s3_store_is_fetched_once_and_validated(s3, tmp_path):
    st, _objects = s3
    with cache_mod.store_dir(SHA, GEN) as root:
        assert (root / "events.parquet").read_bytes() == b"E" * 50
    with cache_mod.store_dir(SHA, GEN):
        pass
    assert st._s3.downloads == 3, "manifest, events, order — then reused"
    assert not [p for p in root.parent.iterdir() if p.name.endswith(".part")]


def test_a_store_that_arrives_damaged_is_never_used(s3):
    _st, objects = s3
    objects[f"events/{SHA}/{GEN}/events.parquet"] = b"short"
    with pytest.raises(Exception, match="not the size"), cache_mod.store_dir(SHA, GEN):
        pass
    assert not (cache_mod.cache_root() / "stores" / SHA / GEN).exists()


def test_an_overlay_is_cached_by_its_tag(s3):
    _st, objects = s3
    assert cache_mod.overlay_dir(SHA, GEN, 7, "abc") is None, "not built yet"
    for name in cache_mod.OVERLAY_FILES:
        objects[f"events/{SHA}/{GEN}/overlays/job_7/{name}"] = name.encode()
    first = cache_mod.overlay_dir(SHA, GEN, 7, "abc")
    assert first.name == "job_7-abc" and (first / "hits.parquet").read_bytes() == b"hits.parquet"
    rebuilt = cache_mod.overlay_dir(SHA, GEN, 7, "def")
    assert rebuilt.name == "job_7-def" and not first.exists(), "a rebuilt overlay replaces the old copy"
    assert cache_mod.overlay_dir(SHA, GEN, 7, "../x") is None


def test_the_cache_trims_least_recently_opened_first(s3, monkeypatch):
    import os
    import time

    with cache_mod.store_dir(SHA, GEN) as root:
        pass
    old = time.time() - 3600
    os.utime(root / "manifest.json", (old, old))
    assert cache_mod.trim(max_bytes=10_000) == 0, "under the cap nothing goes"
    assert cache_mod.trim(max_bytes=10) > 0 and not root.exists()
    with cache_mod.store_dir(SHA, GEN) as root:
        assert cache_mod.trim(max_bytes=10) == 0 and root.exists(), "a store in use is never trimmed"


def test_deleting_a_store_forgets_its_match_sets_and_counts(tmp_path, monkeypatch, fake_redis):
    from app import storage as storage_mod
    from app.config import settings
    from app.events.store import delete_store_files

    monkeypatch.setattr(settings, "upload_dir", tmp_path)
    monkeypatch.setattr(storage_mod, "_storage", None)
    _store_files(tmp_path / "events" / SHA / GEN)
    matches = tmp_path / ".events_cache" / "matches"
    matches.mkdir(parents=True)
    (matches / f"{GEN}-0-all-time.parquet").write_bytes(b"x")
    (matches / "evtx-b1-1111aaaa-0-all-time.parquet").write_bytes(b"x")
    fake_redis.hset(f"logstotal:events:v1:{GEN}", "0:k", 5)
    delete_store_files([(SHA, GEN)])
    assert not (tmp_path / "events" / SHA / GEN).exists()
    assert [p.name for p in matches.iterdir()] == ["evtx-b1-1111aaaa-0-all-time.parquet"], "another store's match-sets stay"
    assert not fake_redis.exists(f"logstotal:events:v1:{GEN}")
