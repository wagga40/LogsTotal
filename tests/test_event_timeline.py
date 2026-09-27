"""Tier-1 tests for the new pure helpers in app.intel.event_timeline.

These functions are new (not moved) — normalize_event_time and merge_buckets. The
moved functions (extract_timestamp, parse_single_output_file, extract_all_from_raw_output,
format_timeline) keep their existing coverage in tests/test_raw_output_parsing.py.
"""

from __future__ import annotations

from pathlib import Path

from app.intel.event_timeline import build_key_events, has_raw_output, merge_buckets, normalize_event_time


class TestNormalizeEventTime:
    def test_iso_with_t_passthrough_unchanged(self):
        assert normalize_event_time("2024-01-05T12:34:56Z") == "2024-01-05T12:34:56Z"

    def test_space_separated_normalized_to_t(self):
        assert normalize_event_time("2024-01-05 12:34:56") == "2024-01-05T12:34:56"

    def test_auditd_marker_converts_to_utc_iso(self):
        raw = "type=SYSCALL msg=audit(1700000000.123:456):"
        assert normalize_event_time(raw) == "2023-11-14T22:13:20"

    def test_auditd_marker_anywhere_in_string(self):
        raw = "node=host1 type=SYSCALL msg=audit(1700000000.999:1):  arch=c000003e syscall=59"
        assert normalize_event_time(raw) == "2023-11-14T22:13:20"

    def test_none_returns_none(self):
        assert normalize_event_time(None) is None

    def test_non_str_returns_none(self):
        assert normalize_event_time(12345678901234) is None
        assert normalize_event_time({"a": 1}) is None

    def test_too_short_returns_none(self):
        assert normalize_event_time("2024-01-05") is None
        assert normalize_event_time("short") is None

    def test_garbage_string_returns_none(self):
        assert normalize_event_time("not a timestamp at all") is None

    def test_whitespace_stripped_before_length_check(self):
        assert normalize_event_time("   2024-01-05T12:34:56Z   ") == "2024-01-05T12:34:56Z"

    def test_exactly_13_chars_boundary(self):
        # 13 chars is the minimum accepted length; one shorter must be rejected.
        assert normalize_event_time("2024-01-05T12") == "2024-01-05T12"
        assert normalize_event_time("2024-01-05T1") is None

    def test_sortability_auditd_and_iso_interleave_correctly(self):
        # auditd epoch 1700000000 -> 2023-11-14T22:13:20 (before the ISO values below)
        auditd = normalize_event_time("type=SYSCALL msg=audit(1700000000.123:456):")
        iso_before = "2023-06-01T00:00:00"
        iso_after = "2024-01-01T00:00:00"
        values = [iso_after, auditd, iso_before]
        assert sorted(values) == [iso_before, auditd, iso_after]


class TestMergeBuckets:
    def test_empty_iterable_returns_empty_dict(self):
        assert merge_buckets([]) == {}

    def test_disjoint_hours_union(self):
        result = merge_buckets([{"2024-01-05T12": {"execution": 1}}, {"2024-01-05T13": {"discovery": 2}}])
        assert result == {
            "2024-01-05T12": {"execution": 1},
            "2024-01-05T13": {"discovery": 2},
        }

    def test_same_hour_same_tactic_sums_counts(self):
        result = merge_buckets(
            [
                {"2024-01-05T12": {"execution": 1}},
                {"2024-01-05T12": {"execution": 4}},
            ]
        )
        assert result == {"2024-01-05T12": {"execution": 5}}

    def test_same_hour_different_tactics_both_kept(self):
        result = merge_buckets(
            [
                {"2024-01-05T12": {"execution": 1}},
                {"2024-01-05T12": {"discovery": 2}},
            ]
        )
        assert result == {"2024-01-05T12": {"execution": 1, "discovery": 2}}

    def test_inputs_not_mutated(self):
        a = {"2024-01-05T12": {"execution": 1}}
        b = {"2024-01-05T12": {"execution": 4}, "2024-01-05T13": {"discovery": 2}}
        a_copy = {k: dict(v) for k, v in a.items()}
        b_copy = {k: dict(v) for k, v in b.items()}

        merge_buckets([a, b])

        assert a == a_copy
        assert b == b_copy


class TestHasRawOutput:
    def _patch_dir(self, monkeypatch, tmp_path: Path):
        from app.intel import event_timeline

        monkeypatch.setattr(event_timeline.settings, "upload_dir", str(tmp_path))

    def test_true_when_matching_tool_file_present(self, tmp_path: Path, monkeypatch):
        job_dir = tmp_path / "job_5"
        job_dir.mkdir()
        (job_dir / "out_hayabusa.json").write_text("{}")
        self._patch_dir(monkeypatch, tmp_path)
        assert has_raw_output(5) is True

    def test_true_for_each_supported_suffix(self, tmp_path: Path, monkeypatch):
        self._patch_dir(monkeypatch, tmp_path)
        for i, suffix in enumerate(("_hayabusa.json", "_chainsaw.json", "_zircolite.json", "_chopchopgo.json")):
            job_dir = tmp_path / f"job_{100 + i}"
            job_dir.mkdir()
            (job_dir / f"out{suffix}").write_text("[]")
            assert has_raw_output(100 + i) is True

    def test_false_when_dir_missing(self, tmp_path: Path, monkeypatch):
        self._patch_dir(monkeypatch, tmp_path)
        assert has_raw_output(999) is False

    def test_false_when_dir_present_but_no_matching_files(self, tmp_path: Path, monkeypatch):
        job_dir = tmp_path / "job_7"
        job_dir.mkdir()
        (job_dir / "notes.txt").write_text("hi")
        (job_dir / "input.json").write_text("{}")  # plain .json, not a tool suffix
        self._patch_dir(monkeypatch, tmp_path)
        assert has_raw_output(7) is False


class TestBuildKeyEvents:
    def _finding(self, events, **over):
        f = {
            "finding_id": 1,
            "rule_name": "Some Rule",
            "severity": "high",
            "tactic": "execution",
            "job_id": 10,
            "events": events,
        }
        f.update(over)
        return f

    def test_sorts_iso_auditd_and_undated_with_undated_last(self):
        findings = [
            self._finding([{"Timestamp": "2024-03-01T10:00:00Z"}], finding_id=1),  # ISO 2024
            self._finding([{"Timestamp": "type=SYSCALL msg=audit(1700000000.1:1):"}], finding_id=2),  # auditd 2023
            self._finding([{"foo": "bar"}], finding_id=3),  # undated
        ]
        items, total = build_key_events(findings)
        assert total == 3
        # auditd (2023) before ISO (2024); undated grouped at the end.
        assert [it["finding_id"] for it in items] == [2, 1, 3]
        assert items[-1]["ts"] is None

    def test_undated_group_is_stable_in_insertion_order(self):
        findings = [
            self._finding([{"no": "ts"}], finding_id=1),
            self._finding([{"Timestamp": "2024-01-01T00:00:00Z"}], finding_id=2),
            self._finding([{"also": "undated"}], finding_id=3),
        ]
        items, _ = build_key_events(findings)
        # Dated item first, then undated in original order (1 before 3).
        assert [it["finding_id"] for it in items] == [2, 1, 3]

    def test_cap_limits_items_but_total_is_full_precap_count(self):
        events = [{"Timestamp": f"2024-01-01T{h:02d}:00:00Z"} for h in range(10)]
        items, total = build_key_events([self._finding(events)], cap=3)
        assert total == 10
        assert len(items) == 3
        assert [it["ts"] for it in items] == [
            "2024-01-01T00:00:00Z",
            "2024-01-01T01:00:00Z",
            "2024-01-01T02:00:00Z",
        ]

    def test_non_dict_events_and_non_list_events_skipped(self):
        findings = [
            {
                "finding_id": 1,
                "rule_name": "R",
                "severity": "low",
                "tactic": "_other",
                "job_id": 1,
                "events": ["str", 123, None, {"Timestamp": "2024-01-01T00:00:00Z"}],
            },
            {"finding_id": 2, "events": None},  # non-list events
            {"finding_id": 3, "events": "notalist"},  # non-list events
            {"finding_id": 4},  # missing events key entirely
        ]
        items, total = build_key_events(findings)
        assert total == 1
        assert items[0]["finding_id"] == 1
        assert items[0]["computer"] is None
        # Carried finding metadata is preserved on the surviving row.
        assert items[0]["severity"] == "low"
        assert items[0]["tactic"] == "_other"

    def test_computer_from_top_level_and_nested_evtx_shape(self):
        findings = [
            self._finding([{"Timestamp": "2024-01-01T00:00:00Z", "Computer": "HOST-A"}], finding_id=1),
            self._finding([{"Timestamp": "2024-01-01T01:00:00Z", "Event": {"System": {"Computer": "HOST-B"}}}], finding_id=2),
            self._finding([{"Timestamp": "2024-01-01T02:00:00Z", "computer": "host-c"}], finding_id=3),
        ]
        items, _ = build_key_events(findings)
        comps = {it["finding_id"]: it["computer"] for it in items}
        assert comps == {1: "HOST-A", 2: "HOST-B", 3: "host-c"}

    def test_empty_input_returns_empty(self):
        assert build_key_events([]) == ([], 0)


class TestCrossToolHourBuckets:
    """One hour must be one bar, whichever tool reported it.

    Slicing `ts[:13]` off the raw string does not work. Hayabusa writes
    "2021-12-01 09:23:45 +09:00" and Chainsaw "2021-12-01T09:23:45", so the same hour
    would produce the keys "2021-12-01 09" and "2021-12-01T09" and the two tools would never
    share a bar. Because ' ' sorts before 'T', a mixed job would also draw every Hayabusa
    hour to the left of every Chainsaw one regardless of when the events actually happened.
    """

    @staticmethod
    def _write(job_dir, filename, events):
        import json

        path = job_dir / filename
        path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
        return path

    def test_space_and_t_separators_land_in_one_bucket(self, tmp_path):
        from app.intel.event_timeline import parse_single_output_file

        hb = self._write(tmp_path, "o_hayabusa.json", [{"Timestamp": "2021-12-01 09:23:45.123 +00:00", "RuleTitle": "R"}])
        cs = self._write(tmp_path, "o_chainsaw.json", [{"timestamp": "2021-12-01T09:41:02", "name": "R"}])

        hb_buckets, _ = parse_single_output_file(hb, {}, {})
        cs_buckets, _ = parse_single_output_file(cs, {}, {})

        assert list(hb_buckets) == ["2021-12-01T09"], hb_buckets
        assert list(cs_buckets) == ["2021-12-01T09"], cs_buckets

    def test_merged_buckets_sort_chronologically_across_tools(self, tmp_path):
        from app.intel.event_timeline import merge_buckets, parse_single_output_file

        early = self._write(tmp_path, "a_chainsaw.json", [{"timestamp": "2021-12-01T08:00:00", "name": "R"}])
        late = self._write(tmp_path, "b_hayabusa.json", [{"Timestamp": "2021-12-01 22:00:00 +00:00", "RuleTitle": "R"}])

        merged = merge_buckets([parse_single_output_file(early, {}, {})[0], parse_single_output_file(late, {}, {})[0]])
        assert sorted(merged) == ["2021-12-01T08", "2021-12-01T22"]


class TestEventComputerAcrossToolShapes:
    """`_event_computer` has to reach the host in three different nestings.

    Chainsaw wraps the source record one level deeper than the others
    (`document.data.Event.System.Computer`), so a shallower lookup reports no host. Cosmetic
    in the key-events list, but the events-timeline marker key includes the computer — so a
    multi-host Chainsaw job would merge two hosts into one marker.
    """

    def test_top_level_key(self):
        from app.intel.event_timeline import _event_computer

        assert _event_computer({"Computer": "HOST-A"}) == "HOST-A"
        assert _event_computer({"computer": "HOST-A"}) == "HOST-A"

    def test_evtx_nesting(self):
        from app.intel.event_timeline import _event_computer

        assert _event_computer({"Event": {"System": {"Computer": "HOST-B"}}}) == "HOST-B"

    def test_chainsaw_document_wrapper(self):
        from app.intel.event_timeline import _event_computer

        hit = {"name": "Rule", "timestamp": "2024-01-05T12:00:00Z", "document": {"data": {"Event": {"System": {"Computer": "HOST-C"}}}}}
        assert _event_computer(hit) == "HOST-C"

    def test_absent_or_malformed_returns_none(self):
        from app.intel.event_timeline import _event_computer

        assert _event_computer({}) is None
        assert _event_computer({"Computer": ""}) is None
        assert _event_computer({"document": "not a dict"}) is None
        assert _event_computer({"document": {"data": {"Event": "not a dict"}}}) is None
