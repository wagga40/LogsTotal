"""The analytics pass must not materialise a job's events.

Materialising means holding two lists at once: every matched event (up to
`MAX_PARSE_EVENTS`, 250,000) and a second list of each event's scan dicts — the largest
allocation the worker would make. Everything the pass does is a fold, so it streams.

These tests pin the *shape*, not a benchmark: that the consumer path never retains, that
the job-wide cap still holds across parallel files, and that a streamed run produces the
same analytics as the materialising one.
"""

from __future__ import annotations

import json

import pytest

from app.intel.event_timeline import MAX_PARSE_EVENTS, extract_all_from_raw_output, parse_single_output_file


def _write_hayabusa(path, count, *, rule="Streamed Rule"):
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(count):
            fh.write(json.dumps({"Timestamp": f"2026-01-01 0{i % 10}:00:00 +00:00", "RuleTitle": rule, "Level": "high", "Computer": "HOST1"}) + "\n")


def test_consumer_mode_returns_no_events(tmp_path):
    out = tmp_path / "x_hayabusa.json"
    _write_hayabusa(out, 50)

    seen = []
    buckets, events = parse_single_output_file(out, {}, {}, consumer=seen.append)

    assert events == [], "consumer mode must retain nothing"
    assert len(seen) == 50
    assert buckets, "the histogram is still built from the same pass"


def test_materialising_mode_is_unchanged(tmp_path):
    out = tmp_path / "x_hayabusa.json"
    _write_hayabusa(out, 50)

    buckets, events = parse_single_output_file(out, {}, {})
    assert len(events) == 50
    assert buckets


def test_the_cap_still_applies_in_consumer_mode(tmp_path, monkeypatch):
    """`len(events)` was the cap; in consumer mode that list is always empty."""
    monkeypatch.setattr("app.intel.event_timeline.MAX_PARSE_EVENTS", 10)
    out = tmp_path / "x_hayabusa.json"
    _write_hayabusa(out, 40)

    seen = []
    parse_single_output_file(out, {}, {}, consumer=seen.append, max_events=10)
    assert len(seen) == 10


def test_the_cap_is_job_wide_not_per_file(tmp_path, monkeypatch):
    """Four files each streaming the cap would be 4x the documented limit."""
    from app.config import settings

    job_dir = tmp_path / "job_77"
    job_dir.mkdir()
    for name in ("a_hayabusa.json", "b_chainsaw.json"):
        _write_hayabusa(job_dir / name, 40)

    monkeypatch.setattr(settings, "upload_dir", tmp_path)
    monkeypatch.setattr("app.intel.event_timeline.MAX_PARSE_EVENTS", 25)

    seen = []
    extract_all_from_raw_output(77, {}, {}, consumer=seen.append)
    assert len(seen) == 25, "the budget is shared across the job's output files"


def test_streamed_and_materialised_agree(tmp_path, monkeypatch):
    from app.config import settings

    job_dir = tmp_path / "job_78"
    job_dir.mkdir()
    _write_hayabusa(job_dir / "a_hayabusa.json", 30, rule="Alpha")
    _write_hayabusa(job_dir / "b_chainsaw.json", 20, rule="Beta")
    monkeypatch.setattr(settings, "upload_dir", tmp_path)

    streamed = []
    b_stream, e_stream = extract_all_from_raw_output(78, {}, {}, consumer=streamed.append)
    b_mat, e_mat = extract_all_from_raw_output(78, {}, {})

    assert e_stream == []
    assert b_stream == b_mat
    assert len(streamed) == len(e_mat) == 50


@pytest.mark.parametrize("n", [0, 1])
def test_empty_and_single_event_files(tmp_path, n):
    out = tmp_path / "x_hayabusa.json"
    _write_hayabusa(out, n)
    seen = []
    parse_single_output_file(out, {}, {}, consumer=seen.append)
    assert len(seen) == n


def test_max_parse_events_is_operator_configurable():
    """It was a hard-coded module constant; the ceiling it sets is a sizing decision."""
    from app.config import settings

    assert settings.max_parse_events == MAX_PARSE_EVENTS
