"""Source-event identity per tool: the join between detections and the event store.

Measured on job 12's real outputs (183,797-event EVTX): every match of all four Windows tools
got an exact key, and the keys agree across tools: all 17,971 distinct Chainsaw events are in
Hayabusa's set, all 11,212 Zircolite events too, and Zircolite and rsigma share 11,209. The
cases below pin the shapes that agreement rests on.
"""

from __future__ import annotations

from app.tools.event_keys import HINTS, WINDOWS, WINDOWS_BY_EVENT_ID, LinkAccumulator, link_key

SYSTEM = {"Computer": "WIN-1.corp.local", "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "EventRecordID": "4242"}
EXPECTED = (WINDOWS, "win-1.corp.local", "microsoft-windows-sysmon/operational", 4242)


def test_every_windows_tool_shape_gives_the_same_key():
    zircolite = {**SYSTEM, "Image": "cmd.exe"}  # flattened
    chainsaw = {"name": "r", "document": {"kind": "evtx", "data": {"Event": {"System": dict(SYSTEM), "EventData": {}}}}}
    rsigma = {"Event": {"System": dict(SYSTEM)}, "Computer": "WIN-1.corp.local", "EventID": 1}
    hayabusa = {"Computer": "WIN-1.corp.local", "Channel": "Sysmon", "EventID": 1, "RecordID": 4242}
    assert {link_key(e) for e in (zircolite, chainsaw, rsigma, hayabusa)} == {EXPECTED}


def test_record_ids_compare_as_integers_whatever_the_tool_wrote():
    """Zircolite writes the record id as a string on Windows and an int on sysmon_linux."""
    assert link_key({**SYSTEM, "EventRecordID": 4242}) == link_key({**SYSTEM, "EventRecordID": " 4242 "}) == EXPECTED


def test_an_ambiguous_hayabusa_abbreviation_falls_back_to_the_event_id():
    """AppLocker names several channels in Hayabusa's table; guessing one would mislink."""
    assert link_key({"Computer": "WIN-1", "Channel": "AppLocker", "EventID": 8004, "RecordID": 7}) == (WINDOWS_BY_EVENT_ID, "win-1", 8004, 7)


def test_linux_text_logs_get_hints_not_a_key():
    chopchopgo = {"Timestamp": "2026-01-01T00:00:05Z", "Message": "Accepted password for root from 10.0.0.1", "PID": "811"}
    acc = LinkAccumulator()
    acc.add("chopchopgo", "r1", "SSH root login", "high", chopchopgo, chopchopgo["Timestamp"])
    kind, epoch, cursor, seq, pid, sha = acc.result()["links"][0][1:]
    assert (kind, cursor, seq, pid) == (HINTS, None, None, 811)
    assert epoch == 1767225605 and len(sha) == 16


def test_an_event_with_no_identity_is_counted_unkeyed():
    acc = LinkAccumulator()
    acc.add("tool", "r", "rule", "low", {"foo": "bar"})
    assert acc.result()["links"] == [] and acc.result()["unkeyed"] == 1


def test_accumulators_merge_rules_by_identity_in_order():
    a, b = LinkAccumulator(), LinkAccumulator()
    a.add("zircolite", "r1", "Rule 1", "high", {**SYSTEM, "EventRecordID": 1})
    b.add("chainsaw", "r2", "Rule 2", "low", {**SYSTEM, "EventRecordID": 2})
    b.add("zircolite", "r1", "Rule 1", "high", {**SYSTEM, "EventRecordID": 3})
    a.merge(b)
    out = a.result()
    assert out["rules"] == [["zircolite", "r1", "Rule 1", "high"], ["chainsaw", "r2", "Rule 2", "low"]]
    assert [link[0] for link in out["links"]] == [0, 1, 0]
    assert [link[-1] for link in out["links"]] == [1, 2, 3]


def test_the_cap_is_reported_not_silent():
    acc = LinkAccumulator(cap=2)
    for rid in range(5):
        acc.add("zircolite", "r", "R", "low", {**SYSTEM, "EventRecordID": rid})
    out = acc.result()
    assert len(out["links"]) == 2 and out["truncated"] is True
