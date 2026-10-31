"""The event-store builder's pure half, and one real build per format through DuckDB.

Measured on the 213 MB development EVTX: 183,797 events, 89 columns, built in 6.5 s into an
11.5 MB store (events 4.9 MB, order 1.0 MB, text 5.6 MB).
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from app.events.census import Census
from app.events.flatten import assign_names, flatten
from app.events.manifest import ManifestError, validate_manifest
from app.events.parsers import iter_events
from app.events.timeparse import parse_time

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2024-01-15T10:30:00.000Z", datetime(2024, 1, 15, 10, 30)),
        ("2023-02-06 22:07:30.404066", datetime(2023, 2, 6, 22, 7, 30, 404066)),
        ("2021-11-11T09:31:03.920486000Z", datetime(2021, 11, 11, 9, 31, 3, 920486)),  # 9-digit fraction
        ("2022-09-26 01:56:28.294 +02:00", datetime(2022, 9, 25, 23, 56, 28, 294000)),  # Hayabusa's form
        (1644169369.363, datetime(2022, 2, 6, 17, 42, 49, 363000)),  # auditd epoch
        ("1786713440960220", datetime(2026, 8, 14, 13, 17, 20, 960220)),  # journald microseconds
        ("not a time", None),
        ("", None),
        (True, None),
    ],
)
def test_times_are_utc_or_none(value, expected):
    assert parse_time(value) == expected


def test_flatten_drops_attributes_folds_text_and_lowers_paths():
    spellings: dict = {}
    flat = flatten(
        {
            "Event": {
                "System": {"Provider": {"#attributes": {"Name": "Sysmon"}}, "EventID": {"#text": 1, "#attributes": {"Qualifiers": ""}}},
                "EventData": {"Hashes": ["a", "b"], "Empty": "", "Flag": True, "xmlns": "x"},
            }
        },
        spellings=spellings,
    )
    assert flat == {("system", "provider", "name"): "Sysmon", ("system", "eventid"): 1, ("eventdata", "hashes"): '["a","b"]', ("eventdata", "flag"): "true"}
    assert spellings[("system", "provider", "name")] == ("System", "Provider", "Name")


def test_names_never_collide_and_the_busiest_path_keeps_the_leaf():
    """Zircolite lets two paths with the same leaf overwrite each other; here neither is lost."""
    counts = {("system", "eventid"): 10, ("eventdata", "data"): 9, ("userdata", "x", "data"): 2, ("eventdata", "eventid"): 1}
    spellings = {
        ("system", "eventid"): ("System", "EventID"),
        ("eventdata", "data"): ("EventData", "Data"),
        ("userdata", "x", "data"): ("UserData", "X", "Data"),
        ("eventdata", "eventid"): ("EventData", "EventID"),
    }
    names = assign_names(counts, spellings)
    assert names[("system", "eventid")] == "EventID"
    assert names[("eventdata", "data")] == "Data"
    assert names[("userdata", "x", "data")] == "X_Data"
    assert names[("eventdata", "eventid")] == "EventData_EventID"
    assert len({n.lower() for n in names.values()}) == len(names)


def test_the_census_types_from_every_value():
    census = Census(max_columns=10)
    for path, values in ((("a",), [1, 2]), (("b",), [1, 2.5]), (("c",), [1, "x"]), (("d",), [2**70])):
        cid = census.column(path)
        for v in values:
            census.observe(cid, v)
    assert [census.duck_type(census.ids[(k,)]) for k in "abcd"] == ["BIGINT", "DOUBLE", "VARCHAR", "VARCHAR"]


def test_the_column_cap_sends_new_paths_to_extra():
    census = Census(max_columns=1)
    assert census.column(("a",)) == 0
    assert census.column(("b",)) is None


@pytest.mark.parametrize(
    "sample, kind, events, has_rid",
    [
        ("windows/bitsadmin.evtx", "evtx", 1, True),
        ("windows/sysmon_process_creation.json", "json_evtx", 4, False),
        ("windows/sysmon_winlogbeat.json", "json_winlogbeat", 2, True),
        ("windows/security_events.xml", "xml", 2, True),
        ("linux/sysmon_linux_sample.log", "sysmon_linux", 5, True),
        ("linux/auditd_sample.log", "auditd", 35, False),
        ("linux/journald_sample.json", "journald", 181, False),
        ("linux/syslog_intrusion.log", "syslog", 27, False),
    ],
)
def test_every_parser_reads_its_sample(sample, kind, events, has_rid):
    stats: dict = {}
    parsed = list(iter_events(SAMPLES / sample, kind, stats=stats, spellings={}, reference=datetime(2026, 3, 1)))
    assert len(parsed) == events and stats["errors"] == 0
    assert all(fixed["time"] is not None for _, fixed in parsed), "every sample event is dated"
    assert any(fixed["rid"] is not None for _, fixed in parsed) is has_rid


def test_winlogbeat_lands_on_the_evtx_column_names():
    """The same event gets the same columns whichever way it was exported."""
    (flat, _), *_ = iter_events(SAMPLES / "windows/sysmon_winlogbeat.json", "json_winlogbeat", stats={}, spellings={})
    for path in (("system", "computer"), ("system", "channel"), ("system", "eventid"), ("system", "eventrecordid")):
        assert path in flat, path


def test_xml_declaring_a_dtd_is_refused_unparsed(tmp_path):
    """Uploads are untrusted; every entity attack needs a DTD and EVTX exports never have one."""
    bomb = tmp_path / "bomb.xml"
    bomb.write_text('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><Event><System><EventID>&lol2;</EventID></System></Event>')
    stats: dict = {}
    assert list(iter_events(bomb, "xml", stats=stats, spellings={})) == []
    assert stats["dtd_refused"] is True


def test_rfc3164_years_roll_back_over_new_year(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("Dec 31 23:59:59 h app[1]: last year\nJan  1 00:00:01 h app[1]: this year\n")
    times = [fixed["time"] for _, fixed in iter_events(log, "syslog", stats={}, spellings={}, reference=datetime(2026, 1, 2))]
    assert times == [datetime(2025, 12, 31, 23, 59, 59), datetime(2026, 1, 1, 0, 0, 1)]


def test_a_malformed_line_is_counted_not_fatal(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("type=SYSCALL msg=audit(1644169369.364:91191): pid=1\nnot an audit line\n")
    stats: dict = {}
    assert len(list(iter_events(log, "auditd", stats=stats, spellings={}))) == 1 and stats["errors"] == 1


def _build(tmp_path, sample: str, kind: str) -> tuple[Path, dict]:
    out = tmp_path / kind
    result = subprocess.run(
        [sys.executable, "-m", "app.events.build", "--input", str(SAMPLES / sample), "--log-type", kind, "--out", str(out), "--reference", "2026-03-01", "--memory-mb", "256"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return out, validate_manifest(out)


@pytest.mark.parametrize("sample, kind", [("windows/sysmon_winlogbeat.json", "json_winlogbeat"), ("linux/auditd_sample.log", "auditd"), ("windows/security_events.xml", "xml")])
def test_a_real_build_is_readable_and_consistent(tmp_path, sample, kind):
    import duckdb

    out, manifest = _build(tmp_path, sample, kind)
    con = duckdb.connect()
    n = manifest["totals"]["events"]
    uids = [r[0] for r in con.execute(f"SELECT _lt_uid FROM read_parquet('{out / 'events.parquet'}') ORDER BY _lt_uid").fetchall()]
    assert uids == list(range(n)), "_lt_uid is dense and physical"
    order = con.execute(f"SELECT _lt_time FROM read_parquet('{out / 'order.parquet'}') ORDER BY _lt_pos").fetchall()
    assert [t for (t,) in order] == sorted((t for (t,) in order), key=lambda t: (t is None, t)), "order.parquet is time order"
    names = {c["name"] for c in manifest["columns"]}
    described = {row[0] for row in con.execute(f"DESCRIBE SELECT * FROM read_parquet('{out / 'events.parquet'}')").fetchall()}
    assert names <= described and all(not n.startswith("_lt_") for n in names)
    assert con.execute(f"SELECT count(*) FROM read_parquet('{out / 'text.parquet'}')").fetchone()[0] == n


def test_a_tampered_store_is_refused(tmp_path):
    out, _ = _build(tmp_path, "linux/auditd_sample.log", "auditd")
    with (out / "events.parquet").open("ab") as stream:
        stream.write(b"x")
    with pytest.raises(ManifestError):
        validate_manifest(out)
