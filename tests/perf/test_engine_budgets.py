"""The Explore engine against the plan's p95 budgets, on a 2M x 300 synthetic store.

Each interaction runs once to warm up, then REPEATS times; the budget is checked against the
second-slowest run, so one scheduler hiccup does not fail it but a regression does. "first"
interactions clear the match-set cache before every run, so they measure the cold path.
Run with `./logstotal test:perf` (prints the table with -s).
"""

from __future__ import annotations

import csv
import io
import os
import time
from pathlib import Path

import pytest

from app.events import engine as engine_mod
from app.events.engine import Engine, StoreView
from app.events.query import Schema, compile_query
from tests.perf import synth_store

pytestmark = pytest.mark.perf
ROWS = int(os.environ.get("LOGSTOTAL_PERF_ROWS", "2000000"))
GEN = "evtx-b1-5e5e5e5e"
REPEATS = 7
COLS = ["_lt_time", "_lt_host", "_lt_channel", "_lt_eid", "Image", "CommandLine", "User"]
RESULTS: list[tuple[str, float, float]] = []


@pytest.fixture(scope="module")
def setup(tmp_path_factory):
    root = Path(__file__).parent / ".store" / f"{GEN}-{ROWS}"
    manifest = synth_store.build(root, ROWS)
    eng = Engine(roots=[root.parent], cache_dir=tmp_path_factory.mktemp("events_cache"), threads=2, memory_mb=768, max_concurrent=2, timeout_seconds=60)
    view = StoreView(root=root.resolve(), manifest=manifest, gen=GEN, overlay=(root / "overlay").resolve(), overlay_tag="perf")
    schema = Schema.from_manifest(manifest, overlay=True)
    return eng, view, schema


@pytest.fixture(autouse=True)
def _no_count_cache(monkeypatch):
    monkeypatch.setattr(engine_mod, "_count_get", lambda view, compiled: None)


def _measure(fn, *, cold=None) -> float:
    if cold is None:
        fn()
    samples = []
    for _ in range(REPEATS):
        if cold is not None:
            cold()
        started = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - started)
    return sorted(samples)[-2]


def _cases(eng, view, schema):
    q = lambda text: compile_query(text, schema)  # noqa: E731
    clear = lambda: eng.forget_store(GEN)  # noqa: E731
    return [
        ("unfiltered page", 0.050, lambda: eng.page(view, q(""), offset=100_000, limit=100, columns=COLS), None),
        ("EventID count", 0.100, lambda: eng.count(view, q("EventID:4607")), None),
        ("CommandLine:*x* count", 0.400, lambda: eng.count(view, q("CommandLine:*mimikatz*")), None),
        ("filtered page 1", 0.150, lambda: eng.page(view, q("Image:*powershell*"), limit=100, columns=COLS), None),
        ("deep page (match-set built)", 0.080, lambda: eng.page(view, q("Image:*cmd*"), offset=40_000, limit=100, columns=COLS), None),
        ("column sort, first", 2.5, lambda: eng.page(view, q(""), sort="CommandLine", limit=100, columns=COLS), clear),
        ("column sort, cached", 0.080, lambda: eng.page(view, q(""), sort="CommandLine", limit=100, columns=COLS), None),
        ("facet, low cardinality", 0.150, lambda: eng.facet(view, q(""), "IntegrityLevel"), None),
        ("facet, CommandLine", 0.800, lambda: eng.facet(view, q(""), "CommandLine"), None),
        ("stack, 1 field", 0.300, lambda: eng.stack(view, q(""), ["Image"]), None),
        ("stack, 3 fields", 1.2, lambda: eng.stack(view, q(""), ["Image", "ParentImage", "User"]), None),
        ("histogram, unfiltered", 0.150, lambda: eng.histogram(view, q("")), None),
        ("histogram, filtered", 0.400, lambda: eng.histogram(view, q("Image:*cmd*")), None),
        ("drawer", 0.080, lambda: eng.event(view, ROWS // 2 + 17), None),
        ("bare word, first", 2.5, lambda: eng.page(view, q("mimikatz"), limit=100, columns=COLS), clear),
        ("bare word, cached", 0.150, lambda: eng.page(view, q("mimikatz"), limit=100, columns=COLS), None),
        ("detections only, page 1", 0.150, lambda: eng.page(view, q("level:>=high"), limit=100, columns=COLS), None),
    ]


def test_interactions_stay_inside_their_budgets(setup):
    eng, view, schema = setup
    over = []
    for name, budget, fn, cold in _cases(eng, view, schema):
        took = _measure(fn, cold=cold)
        RESULTS.append((name, took, budget))
        if took > budget:
            over.append(f"{name}: {took * 1000:.0f} ms > {budget * 1000:.0f} ms")
    print("\n" + "\n".join(f"{name:<30} {took * 1000:8.1f} ms   budget {budget * 1000:6.0f} ms" for name, took, budget in RESULTS))
    assert not over, over


def test_csv_export_streams_fast_enough(setup):
    eng, view, schema = setup
    out = io.StringIO()
    writer = csv.writer(out)
    rows = 0
    started = time.perf_counter()
    for batch in eng.export(view, compile_query("", schema), COLS, max_rows=500_000):
        writer.writerows(batch)
        rows += len(batch)
        out.seek(0)
        out.truncate()
    rate = rows / (time.perf_counter() - started)
    print(f"\nCSV export: {rows:,} rows at {rate:,.0f} rows/s")
    assert rows == min(500_000, ROWS) and rate >= 100_000
