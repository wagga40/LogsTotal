"""The web tier's DuckDB engine over a small hand-built store, so every answer is exact.

The store has the builder's shape (fixed `_lt_*` columns, order/text files, a manifest) and
an overlay (hits, levels), written here with DuckDB directly. One test at the end runs the
real builder and overlay on a sample, so the two cannot drift apart unnoticed.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

import duckdb
import pytest

from app.events import engine as engine_mod
from app.events.engine import Engine, EngineBusy, EngineError, EngineTimeout, StoreView
from app.events.query import Rule, Schema, compile_query

ROOT = Path(__file__).resolve().parents[1]
GEN = "evtx-b1-0000abcd"
#      uid  time                   host    channel     eid    Image                         EventID Score
EVENTS = [
    (0, "2026-01-01 10:00:00", "ws1", "sysmon", 1, r"C:\Windows\cmd.exe", 1, 1.0),
    (1, "2026-01-01 10:05:00", "ws1", "sysmon", 1, r"C:\Windows\whoami.exe", 1, 3.0),
    (2, None, "ws2", "security", 4624, None, 4624, None),
    (3, "2026-01-01 09:00:00", "ws2", "sysmon", 1, r"C:\Windows\cmd.exe", 1, 2.0),
    (4, "2026-01-02 10:00:00", "dc1", "security", 4625, None, 4625, 5.0),
    (5, "2026-01-01 10:05:00", "ws1", "sysmon", 3, r"C:\Windows\cmd.exe", 3, None),
]
TIME_ORDER = [3, 0, 1, 5, 4, 2]  # by time, ties by uid, undated last
HITS = [(1, 0), (1, 1), (4, 2)]
LEVELS = [(1, 3, 2, 3), (4, 1, 1, 4)]
RULES = (Rule(0, "hayabusa", "a", "Whoami", "high"), Rule(1, "zircolite", "b", "Recon", "medium"), Rule(2, "chainsaw", "c", "Failed logon", "low"))


def _write_store(root: Path) -> dict:
    root.mkdir(parents=True)
    con = duckdb.connect()
    con.execute(
        "CREATE TABLE e (_lt_uid BIGINT, _lt_time TIMESTAMP, _lt_host VARCHAR, _lt_channel VARCHAR, _lt_eid BIGINT, _lt_rid BIGINT, _lt_seq BIGINT,"
        ' _lt_line BIGINT, _lt_family VARCHAR, _lt_extra VARCHAR, "Image" VARCHAR, "EventID" BIGINT, "Score" DOUBLE)'
    )
    for uid, time, host, channel, eid, image, event_id, score in EVENTS:
        con.execute("INSERT INTO e VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, NULL, ?, ?, ?)", [uid, time, host, channel, eid, uid + 100, f"{channel}|{eid}", image, event_id, score])
    con.execute(f"COPY e TO '{root}/events.parquet' (FORMAT parquet)")
    con.execute(f"COPY (SELECT row_number() OVER (ORDER BY _lt_time NULLS LAST, _lt_uid) - 1 AS _lt_pos, _lt_uid, _lt_time FROM e) TO '{root}/order.parquet' (FORMAT parquet)")
    con.execute(f"COPY (SELECT _lt_uid, lower(concat_ws(chr(31), _lt_host, _lt_channel, \"Image\")) AS _lt_text FROM e) TO '{root}/text.parquet' (FORMAT parquet)")
    overlay = root / "overlays" / "job_1"
    overlay.mkdir(parents=True)
    con.execute("CREATE TABLE h (_lt_uid BIGINT, rule_ix BIGINT)")
    con.executemany("INSERT INTO h VALUES (?, ?)", HITS)
    con.execute(f"COPY h TO '{overlay}/hits.parquet' (FORMAT parquet)")
    con.execute("CREATE TABLE l (_lt_uid BIGINT, level_rank INTEGER, n_rules BIGINT, tools_mask BIGINT)")
    con.executemany("INSERT INTO l VALUES (?, ?, ?, ?)", LEVELS)
    con.execute(f"COPY l TO '{overlay}/levels.parquet' (FORMAT parquet)")
    con.close()
    return {
        "columns": [
            {"name": "Image", "type": "VARCHAR", "path": "EventData/Image"},
            {"name": "EventID", "type": "BIGINT", "path": "System/EventID"},
            {"name": "Score", "type": "DOUBLE", "path": "Score"},
        ],
        "totals": {"events": len(EVENTS)},
        "time": {"min": "2026-01-01T09:00:00", "max": "2026-01-02T10:00:00"},
        "text_index": {"present": True},
    }


@pytest.fixture()
def store(tmp_path):
    root = tmp_path / "events" / "s" / GEN
    manifest = _write_store(root)
    eng = Engine(roots=[tmp_path / "events"], cache_dir=tmp_path / ".events_cache", threads=1, memory_mb=256, max_concurrent=2, timeout_seconds=10)
    view = StoreView(root=root.resolve(), manifest=manifest, gen=GEN, overlay=(root / "overlays" / "job_1").resolve(), overlay_tag="t1")
    schema = Schema.from_manifest(manifest, overlay=True, rules=RULES)
    return eng, view, schema, tmp_path


def _q(schema, text):
    return compile_query(text, schema)


def test_the_engine_reads_only_under_its_roots(store, tmp_path):
    eng, view, _schema, _ = store
    outside = tmp_path / "outside.parquet"
    duckdb.connect().execute(f"COPY (SELECT 1 AS x) TO '{outside}' (FORMAT parquet)")
    with pytest.raises(duckdb.PermissionException):
        eng._run(f"SELECT * FROM read_parquet('{outside}')")
    with pytest.raises(duckdb.Error):
        eng._run("SET GLOBAL enable_external_access = true")
    with pytest.raises(duckdb.Error):
        eng._run("SET threads = 8")
    assert eng._run(f"SELECT count(*) FROM {view.events}") == [(len(EVENTS),)]


def test_counts(store, fake_redis):
    eng, view, schema, _ = store
    assert eng.count(view, _q(schema, "")) == 6
    assert eng.count(view, _q(schema, "Image:*cmd*")) == 3
    assert eng.count(view, _q(schema, "det:yes")) == 2
    assert eng.count(view, _q(schema, "whoami OR dc1")) == 2
    assert fake_redis.hlen(f"logstotal:events:v1:{GEN}") == 3, "the unfiltered count comes from the manifest"
    fake_redis.hset(f"logstotal:events:v1:{GEN}", f"t1:{_q(schema, 'Image:*cmd*').key}", 99)
    assert eng.count(view, _q(schema, "Image:*cmd*")) == 99, "a cached count is served"
    engine_mod.forget_counts(GEN)
    assert eng.count(view, _q(schema, "Image:*cmd*")) == 3


def test_pages_in_time_order_with_their_detections(store):
    eng, view, schema, _ = store
    assert [r["_lt_uid"] for r in eng.page(view, _q(schema, ""), limit=10).rows] == TIME_ORDER
    assert [r["_lt_uid"] for r in eng.page(view, _q(schema, ""), offset=2, limit=2).rows] == TIME_ORDER[2:4]
    rows = eng.page(view, _q(schema, "Image:*"), columns=["_lt_time", "Image", "Score"]).rows
    assert [r["_lt_uid"] for r in rows] == [3, 0, 1, 5]
    assert rows[2] == {"_lt_uid": 1, "_lt_time": datetime(2026, 1, 1, 10, 5), "Image": r"C:\Windows\whoami.exe", "Score": 3.0, "_det": 3, "_rules": 2}
    assert "_det" not in rows[0]


def test_deep_pages_sorts_and_free_text_read_a_match_set(store, monkeypatch):
    eng, view, schema, _ = store
    monkeypatch.setattr(engine_mod, "DEEP_OFFSET", 0)
    assert [r["_lt_uid"] for r in eng.page(view, _q(schema, "sysmon"), offset=1, limit=2).rows] == [0, 1]
    assert len(list(eng.matches_dir.glob(f"{GEN}-*.parquet"))) == 1
    by_score = eng.page(view, _q(schema, ""), sort="Score", limit=10).rows
    assert [r["_lt_uid"] for r in by_score] == [0, 3, 1, 4, 5, 2], "numeric sort, NULLs last, ties in time order"
    assert [r["_lt_uid"] for r in eng.page(view, _q(schema, ""), sort="Score", desc=True, limit=10).rows] == [4, 1, 3, 0, 5, 2]
    assert [r["_lt_uid"] for r in eng.page(view, _q(schema, ""), sort="Image", limit=3).rows] == [3, 0, 5]
    with pytest.raises(EngineError):
        eng.page(view, _q(schema, ""), sort="NoSuchColumn")
    eng.forget_store(GEN)
    assert not list(eng.matches_dir.glob(f"{GEN}-*.parquet"))


def test_a_match_set_answers_later_queries(store):
    eng, view, schema, _ = store
    compiled = _q(schema, "cmd")
    path = eng.match_set(view, compiled)
    where, params = eng._filter(view, compiled)
    assert str(path) in where and params == []
    assert eng.count(view, compiled) == 3 and eng.facet(view, compiled, "_lt_host")["values"] == [("ws1", 2), ("ws2", 1)]


def test_histogram(store):
    eng, view, schema, _ = store
    hist = eng.histogram(view, _q(schema, ""), width_px=48)
    assert hist["bucket_seconds"] == 3 * 3600 and sum(hist["counts"]) == 5, "the undated event has no bar"
    assert sum(hist["detected"]) == 2
    narrow = eng.histogram(view, _q(schema, "sysmon"), start=datetime(2026, 1, 1, 10), end=datetime(2026, 1, 1, 10, 10), width_px=400)
    assert sum(narrow["counts"]) == 3 and narrow["bucket_seconds"] == 10, "600 s in at most 98 bars"
    empty = dict(view.manifest, time={"min": None, "max": None})
    assert eng.histogram(StoreView(view.root, empty, GEN), _q(schema, ""))["counts"] == []


def test_facets_and_stacks(store):
    eng, view, schema, _ = store
    facet = eng.facet(view, _q(schema, ""), "Image")
    assert facet["values"][0] == (r"C:\Windows\cmd.exe", 3) and facet["matched"] == 6 and facet["present"] == 4
    stack = eng.stack(view, _q(schema, ""), ["_lt_host", "_lt_eid"])
    assert stack["rows"][0] == (["dc1", 4625], 1) and stack["rows"][-1] == (["ws1", 1], 2) and stack["groups"] == 5
    with pytest.raises(EngineError):
        eng.stack(view, _q(schema, ""), ["Image", "EventID", "Score", "_lt_host"])


def test_one_event_and_its_rules(store):
    eng, view, _schema, _ = store
    event = eng.event(view, 1)
    assert event["rules"] == [0, 1] and event["fields"]["Image"] == r"C:\Windows\whoami.exe" and "_lt_extra" not in event["fields"]
    assert eng.event(view, 999) is None


def test_exports_stream_and_hold_one_slot(store):
    eng, view, schema, _ = store
    first = eng.export(view, _q(schema, ""), ["_lt_uid", "Image"], max_rows=4)
    assert [r[0] for r in next(first)] == TIME_ORDER[:4]
    with pytest.raises(EngineBusy):
        next(eng.export(view, _q(schema, ""), ["_lt_uid"], max_rows=1))
    first.close()  # a client that disconnects mid-stream frees the slot
    assert [r[0] for batch in eng.export(view, _q(schema, "det:yes"), ["_lt_uid"], max_rows=10) for r in batch] == [1, 4]


def test_busy_and_timeout(store, monkeypatch):
    eng, view, schema, _ = store
    monkeypatch.setattr(engine_mod, "SLOT_WAIT_SECONDS", 0.05)
    for _ in range(2):
        eng._slots.acquire()
    try:
        with pytest.raises(EngineBusy):
            eng.count(view, _q(schema, "Image:*x*"))
    finally:
        for _ in range(2):
            eng._slots.release()
    eng.timeout_seconds = 0.2
    with pytest.raises(EngineTimeout):
        eng._run("SELECT count(*) FROM range(100000000) a, range(1000) b WHERE a.range % 7 = b.range")


def test_concurrent_queries_each_take_a_cursor(store):
    eng, view, schema, _ = store
    results, errors = [], []

    def work():
        try:
            for _ in range(20):
                results.append(eng.count(view, _q(schema, "Score:>1")))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and set(results) == {3}


def test_the_engine_rules_hold_in_the_source():
    """The four DuckDB 2.0 rules in the module docstring, checked on the code itself."""
    source = Path(engine_mod.__file__).read_text()
    tree = ast.parse(source)
    executes = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "execute"]
    on_connection = [n for n in executes if isinstance(n.func.value, ast.Attribute) and n.func.value.attr == "_con"]
    init = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    assert all(init.lineno <= n.lineno <= init.end_lineno for n in on_connection), "outside setup, every query runs on its own cursor"
    sets = re.findall(r'"(SET [^"]*)', source)
    assert sets and all(s.startswith("SET GLOBAL ") for s in sets), sets
    assert source.index("allowed_directories") < source.index("enable_external_access = false") < source.index("lock_configuration = true")
    assert "//" not in "".join(re.findall(r'f?"[^"\n]*"', source.split('"""', 2)[2])), "never integer division in SQL"


def test_the_engine_reads_what_the_builder_writes(tmp_path):
    store_dir = tmp_path / "events" / "x" / "g"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "app.events.build",
            "--input",
            str(ROOT / "samples/windows/sysmon_process_creation.json"),
            "--log-type",
            "json_evtx",
            "--out",
            str(store_dir),
            "--memory-mb",
            "256",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=120,
    )
    manifest = json.loads((store_dir / "manifest.json").read_text())
    eng = Engine(roots=[tmp_path / "events"], cache_dir=tmp_path / ".events_cache", threads=1, memory_mb=256)
    view = StoreView(root=store_dir.resolve(), manifest=manifest, gen="g")
    schema = Schema.from_manifest(manifest)
    assert eng.count(view, _q(schema, "")) == 4
    assert eng.count(view, _q(schema, "EventID:1")) == 2
    assert eng.count(view, _q(schema, "powershell")) == 1
    rows = eng.page(view, _q(schema, "Image:*cmd.exe"), columns=["_lt_time", "_lt_host", "Image"]).rows
    assert len(rows) == 1 and rows[0]["Image"].endswith("cmd.exe")
    assert sum(eng.histogram(view, _q(schema, ""))["counts"]) == manifest["totals"]["events"] - manifest["totals"]["undated"]
    assert eng.event(view, rows[0]["_lt_uid"])["fields"]["Image"] == rows[0]["Image"]


def test_the_drawer_reads_only_its_family_columns(store):
    eng, view, _schema, _ = store
    families = [{"channel": "sysmon", "eid": 1, "columns": ["Image", "EventID", "Gone"]}]
    narrow = StoreView(view.root, dict(view.manifest, families=families), GEN, view.overlay, view.overlay_tag)
    fields = eng.event(narrow, 1)["fields"]
    assert fields["Image"].endswith("whoami.exe") and "Score" not in fields, "Score is not a sysmon|1 column"
    assert "Score" in eng.event(narrow, 4)["fields"], "an event of an unlisted family reads every column"
