"""Tier-1 tests for app.intel.event_markers — pure, no DB, no filesystem.

This is where the events-timeline logic lives, so this is where it is pinned: UTC
normalisation, the collapse rule, the resolution ladder, bounded accumulation, bisect
boundaries, and the case-wide merge.
"""

from __future__ import annotations

from app.intel.event_markers import (
    INDEX_VERSION,
    MARKER_ACCUM_CAP,
    RESOLUTION_LADDER,
    MarkerAccumulator,
    build_index,
    event_epoch_seconds,
    merge_sliced,
    normalize_severity,
    slice_index,
)

# (rule_id, rule_name, severity, tactic, computer, tool)
KEY_A = ("rule-a", "Rule A", "high", "execution", "WIN94", "hayabusa")
KEY_B = ("rule-b", "Rule B", "low", "discovery", "WIN94", "hayabusa")
KEY_A_OTHER_HOST = ("rule-a", "Rule A", "high", "execution", "WIN12", "hayabusa")

T0 = "2024-01-05T12:00:00Z"
E0 = 1704456000  # epoch of T0


def _iso(epoch: int) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestEventEpochSeconds:
    def test_utc_z_suffix(self):
        assert event_epoch_seconds("2024-01-05T12:00:00Z") == E0

    def test_space_separator_is_accepted(self):
        assert event_epoch_seconds("2024-01-05 12:00:00Z") == E0

    def test_naive_is_assumed_utc(self):
        assert event_epoch_seconds("2024-01-05T12:00:00") == E0

    def test_offset_and_z_land_on_the_same_instant(self):
        """The whole point of this helper: one absolute instant regardless of spelling."""
        assert event_epoch_seconds("2024-01-05T14:00:00+02:00") == E0
        assert event_epoch_seconds("2024-01-05T12:00:00Z") == E0
        assert event_epoch_seconds("2024-01-05T07:00:00-05:00") == E0

    def test_hayabusa_space_before_offset(self):
        """Hayabusa emits "2024-01-05 21:00:00.123 +09:00" — fromisoformat rejects it raw."""
        assert event_epoch_seconds("2024-01-05 21:00:00.000 +09:00") == E0

    def test_fractional_seconds_truncate_to_the_second(self):
        assert event_epoch_seconds("2024-01-05T12:00:00.987Z") == E0

    def test_auditd_marker_anywhere_in_the_line(self):
        raw = "node=h1 type=SYSCALL msg=audit(1704456000.123:99): arch=c000003e"
        assert event_epoch_seconds(raw) == E0

    def test_rejects_non_timestamps(self):
        assert event_epoch_seconds(None) is None
        assert event_epoch_seconds(12345) is None
        assert event_epoch_seconds("2024-01-05") is None
        assert event_epoch_seconds("not a timestamp at all") is None

    def test_trailing_garbage_falls_back_to_the_fixed_prefix(self):
        assert event_epoch_seconds("2024-01-05T12:00:00 (local)") == E0


class TestNormalizeSeverity:
    def test_hayabusa_abbreviations(self):
        assert normalize_severity("crit") == "critical"
        assert normalize_severity("med") == "medium"
        assert normalize_severity("info") == "informational"

    def test_canonical_values_pass_through(self):
        for value in ("critical", "high", "medium", "low", "informational"):
            assert normalize_severity(value) == value

    def test_unknown_and_non_str(self):
        assert normalize_severity("bogus") == "unknown"
        assert normalize_severity(None) == "unknown"


class TestAccumulatorCollapse:
    def test_same_key_in_one_window_collapses(self):
        acc = MarkerAccumulator()
        for _ in range(12):
            acc.add(KEY_A, T0)
        idx = build_index(acc)
        assert idx["n"] == [12]
        assert idx["total"] == 12

    def test_different_rules_stay_separate(self):
        acc = MarkerAccumulator()
        acc.add(KEY_A, T0)
        acc.add(KEY_B, T0)
        idx = build_index(acc)
        assert len(idx["ts"]) == 2
        assert len(idx["keys"]) == 2

    def test_different_computers_stay_separate(self):
        """Adding computer to the key costs nothing on single-host data and is correct
        on multi-host, where a rule-only key would show one host's name for a merged marker."""
        acc = MarkerAccumulator()
        acc.add(KEY_A, T0)
        acc.add(KEY_A_OTHER_HOST, T0)
        idx = build_index(acc)
        assert len(idx["ts"]) == 2
        assert sorted(idx["computers"]) == ["WIN12", "WIN94"]

    def test_undated_events_are_counted_but_not_placed(self):
        acc = MarkerAccumulator()
        acc.add(KEY_A, T0)
        acc.add(KEY_A, None)
        acc.add(KEY_A, "garbage")
        idx = build_index(acc)
        assert idx["total"] == 3
        assert idx["undated"] == 2
        assert idx["n"] == [1]


class TestResolutionLadder:
    def test_under_cap_keeps_one_second_fidelity(self):
        acc = MarkerAccumulator()
        for i in range(50):
            acc.add(KEY_A, _iso(E0 + i))
        idx = build_index(acc, cap=1000)
        assert idx["res"] == 1
        assert len(idx["ts"]) == 50

    def test_over_cap_coarsens_up_the_ladder(self):
        acc = MarkerAccumulator()
        for i in range(300):
            acc.add(KEY_A, _iso(E0 + i))
        idx = build_index(acc, cap=100)
        assert idx["res"] > 1
        assert idx["res"] in RESOLUTION_LADDER
        assert len(idx["ts"]) <= 100
        assert sum(idx["n"]) == 300, "coarsening must never lose events"

    def test_coarsening_picks_the_finest_step_that_fits(self):
        acc = MarkerAccumulator()
        for i in range(300):
            acc.add(KEY_A, _iso(E0 + i))
        # 300 one-second markers → 60 at 5s, 20 at 15s. A cap of 60 should stop at 5s.
        idx = build_index(acc, cap=60)
        assert idx["res"] == 5
        assert len(idx["ts"]) == 60

    def test_in_flight_coarsening_bounds_the_accumulator(self):
        """MAX_PARSE_EVENTS is per file, so the accumulator must bound itself."""
        acc = MarkerAccumulator(cap=100)
        for i in range(5000):
            acc.add(KEY_A, _iso(E0 + i))
        assert len(acc) <= 100
        assert acc.resolution > 1
        idx = build_index(acc)
        assert sum(idx["n"]) == 5000

    def test_accumulator_cap_default_is_the_documented_constant(self):
        assert MarkerAccumulator()._cap == MARKER_ACCUM_CAP


class TestAccumulatorMerge:
    def test_merge_sums_counts_at_the_same_resolution(self):
        a, b = MarkerAccumulator(), MarkerAccumulator()
        a.add(KEY_A, T0)
        b.add(KEY_A, T0)
        b.add(KEY_B, T0)
        a.merge(b)
        idx = build_index(a)
        assert idx["total"] == 3
        assert sum(idx["n"]) == 3
        assert len(idx["keys"]) == 2

    def test_merge_aligns_to_the_coarser_resolution(self):
        fine = MarkerAccumulator()
        fine.add(KEY_A, _iso(E0))
        coarse = MarkerAccumulator(cap=1)
        for i in range(200):
            coarse.add(KEY_B, _iso(E0 + i))
        assert coarse.resolution > fine.resolution

        fine.merge(coarse)
        assert fine.resolution == coarse.resolution
        assert build_index(fine)["total"] == 201


class TestBuildIndexShape:
    def test_columns_are_parallel_and_timestamps_sorted(self):
        acc = MarkerAccumulator()
        for i in (30, 10, 20, 0):
            acc.add(KEY_A, _iso(E0 + i))
        idx = build_index(acc)
        assert idx["v"] == INDEX_VERSION
        assert len(idx["ts"]) == len(idx["k"]) == len(idx["n"])
        assert idx["ts"] == sorted(idx["ts"]), "bisect requires a sorted ts column"

    def test_dictionaries_deduplicate(self):
        acc = MarkerAccumulator()
        for i in range(10):
            acc.add(KEY_A, _iso(E0 + i))
        idx = build_index(acc)
        assert idx["computers"] == ["WIN94"]
        assert idx["tools"] == ["hayabusa"]
        assert len(idx["keys"]) == 1
        assert set(idx["k"]) == {0}

    def test_key_rows_carry_rule_identity_and_dictionary_indices(self):
        acc = MarkerAccumulator()
        acc.add(KEY_A, T0)
        row = build_index(acc)["keys"][0]
        assert row[:4] == ["rule-a", "Rule A", "high", "execution"]
        assert isinstance(row[4], int) and isinstance(row[5], int)

    def test_empty_accumulator_builds_an_empty_index(self):
        idx = build_index(MarkerAccumulator())
        assert idx["ts"] == [] and idx["keys"] == [] and idx["total"] == 0


def _index(pairs: list[tuple[tuple, int]]) -> dict:
    acc = MarkerAccumulator()
    for key, offset in pairs:
        acc.add(key, _iso(E0 + offset))
    return build_index(acc)


class TestSliceIndex:
    def test_bisect_boundaries_are_inclusive_at_both_ends(self):
        idx = _index([(KEY_A, i) for i in (0, 10, 20, 30)])
        out = slice_index(idx, E0 + 10, E0 + 20)
        assert [it["start"] for it in out["items"]] == [(E0 + 10) * 1000, (E0 + 20) * 1000]

    def test_open_range_returns_everything(self):
        idx = _index([(KEY_A, i) for i in (0, 10, 20)])
        assert len(slice_index(idx)["items"]) == 3

    def test_range_outside_the_data_is_empty_but_still_reports_extent(self):
        idx = _index([(KEY_A, 0)])
        out = slice_index(idx, E0 + 10_000, E0 + 20_000)
        assert out["items"] == []
        assert out["extent"] is not None

    def test_start_is_epoch_millis(self):
        out = slice_index(_index([(KEY_A, 0)]))
        assert out["items"][0]["start"] == E0 * 1000

    def test_discarded_is_collapsed_minus_one(self):
        acc = MarkerAccumulator()
        for _ in range(12):
            acc.add(KEY_A, T0)
        out = slice_index(build_index(acc))
        assert out["items"][0]["meta"]["discarded"] == 11
        assert out["discarded"] == 11

    def test_over_cap_bumps_resolution_and_sets_truncated(self):
        idx = _index([(KEY_A, i) for i in range(300)])
        out = slice_index(idx, cap=10)
        assert out["resolution"] > out["base_resolution"]
        assert len(out["items"]) <= 10

    def test_resolution_cannot_go_finer_than_what_was_stored(self):
        acc = MarkerAccumulator(cap=2)
        for i in range(500):
            acc.add(KEY_A, _iso(E0 + i))
        idx = build_index(acc)
        out = slice_index(idx, resolution=1)
        assert out["resolution"] == idx["res"] > 1

    def test_severity_filter(self):
        idx = _index([(KEY_A, 0), (KEY_B, 10)])
        out = slice_index(idx, severities={"high"})
        assert len(out["items"]) == 1
        assert out["items"][0]["category"] == "high"

    def test_item_meta_carries_provenance(self):
        out = slice_index(_index([(KEY_A, 0)]), job_id=42)
        meta = out["items"][0]["meta"]
        assert meta["rule_id"] == "rule-a"
        assert meta["computer"] == "WIN94"
        assert meta["tool"] == "hayabusa"
        assert meta["job_id"] == 42

    def test_grouping_and_category_map_to_tactic_and_severity(self):
        item = slice_index(_index([(KEY_A, 0)]))["items"][0]
        assert item["grouping"] == "execution"
        assert item["category"] == "high"

    def test_wrong_version_is_treated_as_missing(self):
        idx = _index([(KEY_A, 0)])
        idx["v"] = 999
        assert slice_index(idx)["items"] == []

    def test_garbage_payload_does_not_raise(self):
        assert slice_index({})["items"] == []
        assert slice_index(None)["items"] == []


class TestMergeSliced:
    def test_merges_and_sorts_by_time(self):
        a = slice_index(_index([(KEY_A, 20)]), job_id=1)
        b = slice_index(_index([(KEY_B, 0)]), job_id=2)
        out = merge_sliced([a, b])
        assert [it["meta"]["job_id"] for it in out["items"]] == [2, 1]

    def test_takes_the_coarsest_resolution(self):
        fine = slice_index(_index([(KEY_A, 0)]))
        coarse_acc = MarkerAccumulator(cap=2)
        for i in range(500):
            coarse_acc.add(KEY_B, _iso(E0 + i))
        coarse = slice_index(build_index(coarse_acc))
        out = merge_sliced([fine, coarse])
        assert out["resolution"] == max(fine["resolution"], coarse["resolution"])

    def test_extent_spans_every_input(self):
        a = slice_index(_index([(KEY_A, 0)]))
        b = slice_index(_index([(KEY_B, 3600)]))
        out = merge_sliced([a, b])
        assert out["extent"][0] == E0 * 1000
        assert out["extent"][1] >= (E0 + 3600) * 1000

    def test_global_recap_after_merge(self):
        slices = [slice_index(_index([(KEY_A, i)]), job_id=i) for i in range(20)]
        out = merge_sliced(slices, cap=5)
        assert len(out["items"]) == 5
        assert out["truncated"] is True

    def test_empty_input(self):
        assert merge_sliced([])["items"] == []
        assert merge_sliced([None, {}])["items"] == []


class TestMixedNullableKeyFields:
    """Real jobs mix rules that matched a DB Finding with rules that did not.

    The un-matched ones carry `rule_id=None` and `severity=None`, and sorting the raw key
    tuples then dies with "'<' not supported between instances of 'str' and 'NoneType'" —
    which is exactly how this failed on a 82,658-event job while every test here passed,
    because they all used a fully-populated key.
    """

    def test_build_index_sorts_keys_with_null_fields(self):
        acc = MarkerAccumulator()
        acc.add(("rule-a", "Named", "high", "execution", "H", "hayabusa"), T0)
        acc.add((None, "Unmatched", None, "execution", "H", "hayabusa"), T0)
        acc.add((None, "Another", None, "_other", None, "zircolite"), T0)
        idx = build_index(acc)
        assert len(idx["keys"]) == 3
        assert idx["ts"] == sorted(idx["ts"])

    def test_missing_severity_becomes_unknown_not_null(self):
        acc = MarkerAccumulator()
        acc.add((None, "Unmatched", None, "execution", "H", "hayabusa"), T0)
        assert build_index(acc)["keys"][0][2] == "unknown"

    def test_slice_renders_a_null_keyed_marker(self):
        acc = MarkerAccumulator()
        acc.add((None, "Unmatched", None, "execution", None, None), T0)
        item = slice_index(build_index(acc))["items"][0]
        assert item["label"] == "Unmatched"
        assert item["category"] == "unknown"
        assert item["meta"]["rule_id"] is None
        assert item["meta"]["computer"] is None

    def test_label_falls_back_when_even_the_name_is_missing(self):
        acc = MarkerAccumulator()
        acc.add((None, "", None, "_other", None, None), T0)
        assert slice_index(build_index(acc))["items"][0]["label"] == "Unknown rule"


class TestStableGroupings:
    """Lane identity is a property of the job, not of the viewport.

    Derived from the returned items, a lane disappeared as soon as a zoom excluded its last
    marker — the canvas got shorter, everything below moved up, and the page jumped under
    the cursor mid-gesture. It is also more correct: a capped slice can drop a rare tactic
    that is genuinely in the data.
    """

    def _two_tactics(self):
        acc = MarkerAccumulator()
        acc.add(("r1", "Early Rule", "high", "execution", "H", "hayabusa"), _iso(E0))
        acc.add(("r2", "Late Rule", "low", "exfiltration", "H", "hayabusa"), _iso(E0 + 3600))
        return build_index(acc)

    def test_groupings_cover_the_whole_index(self):
        assert sorted(slice_index(self._two_tactics())["groupings"]) == ["execution", "exfiltration"]

    def test_groupings_survive_a_zoom_that_excludes_a_tactic(self):
        idx = self._two_tactics()
        out = slice_index(idx, E0 - 10, E0 + 10)
        assert [it["grouping"] for it in out["items"]] == ["execution"], "only one tactic is visible"
        assert sorted(out["groupings"]) == ["execution", "exfiltration"], "but both lanes must stay"

    def test_groupings_survive_an_empty_viewport(self):
        """Zooming into a quiet gap must not collapse the panel and re-expand on pan."""
        out = slice_index(self._two_tactics(), E0 + 100_000, E0 + 200_000)
        assert out["items"] == []
        assert sorted(out["groupings"]) == ["execution", "exfiltration"]

    def test_groupings_survive_an_item_cap(self):
        idx = self._two_tactics()
        out = slice_index(idx, cap=1)
        assert len(out["items"]) == 1
        assert sorted(out["groupings"]) == ["execution", "exfiltration"]

    def test_merge_unions_groupings_across_jobs(self):
        a = slice_index(_index([(KEY_A, 0)]), job_id=1)  # execution
        b = slice_index(_index([(KEY_B, 0)]), job_id=2)  # discovery
        assert sorted(merge_sliced([a, b])["groupings"]) == ["discovery", "execution"]

    def test_empty_and_garbage_payloads_report_no_groupings(self):
        assert slice_index({})["groupings"] == []
        assert merge_sliced([])["groupings"] == []


class TestFindingLinkAndCounts:
    """Markers carry enough to deep-link into the per-finding partials and to say how many
    alerts they stand for — the panel had rule name and little else."""

    KEY = ("rule-a", "Rule A", "high", "execution", "WIN94", "hayabusa", 77)

    def test_finding_id_reaches_the_item(self):
        acc = MarkerAccumulator()
        acc.add(self.KEY, T0)
        assert slice_index(build_index(acc))["items"][0]["meta"]["finding_id"] == 77

    def test_events_count_is_the_collapsed_total(self):
        acc = MarkerAccumulator()
        for _ in range(9):
            acc.add(self.KEY, T0)
        meta = slice_index(build_index(acc))["items"][0]["meta"]
        assert meta["events"] == 9, "how many alerts this marker stands for"
        assert meta["discarded"] == 8, "and how many are hidden behind the one drawn"

    def test_six_wide_keys_still_slice(self):
        """An index written before finding_id existed must keep working.

        The field is appended, and the reader indexes rather than unpacks — a fixed-arity
        unpack would drop every marker from an older index and render an empty axis instead
        of reporting itself missing.
        """
        acc = MarkerAccumulator()
        acc.add(KEY_A, T0)  # 6-wide, no finding_id
        payload = build_index(acc)
        payload["keys"] = [row[:6] for row in payload["keys"]]  # simulate the older shape

        out = slice_index(payload)
        assert len(out["items"]) == 1
        assert out["items"][0]["label"] == "Rule A"
        assert out["items"][0]["meta"]["finding_id"] is None

    def test_malformed_key_rows_are_skipped_not_fatal(self):
        acc = MarkerAccumulator()
        acc.add(KEY_A, T0)
        payload = build_index(acc)
        payload["keys"] = [["too", "short"]]
        assert slice_index(payload)["items"] == []


class TestActiveFindingIds:
    """`active_finding_ids` is a *set extractor*, not a display path.

    It must not route through `slice_index`: that caps at MAX_TIMELINE_ITEMS and walks the
    resolution ladder coarser until the window fits, dropping whole marker keys — and
    therefore whole finding ids. On the graph's time link an under-reported set renders a
    genuinely active entity as dimmed, which is a false negative presented as fact.
    """

    def _index(self, rows):
        acc = MarkerAccumulator()
        for key, ts in rows:
            acc.add(key, ts)
        return build_index(acc)

    def test_returns_the_finding_ids_in_the_window(self):
        from app.intel.event_markers import active_finding_ids

        payload = self._index([((*KEY_A, 11), T0), ((*KEY_B, 22), "2024-01-05T13:00:00Z")])
        assert active_finding_ids(payload) == {11, 22}
        assert active_finding_ids(payload, E0, E0 + 60) == {11}
        assert active_finding_ids(payload, E0 + 3600, E0 + 3660) == {22}

    def test_a_window_outside_the_extent_is_empty(self):
        from app.intel.event_markers import active_finding_ids

        payload = self._index([((*KEY_A, 11), T0)])
        assert active_finding_ids(payload, E0 - 7200, E0 - 3600) == set()
        assert active_finding_ids(payload, E0 + 3600, E0 + 7200) == set()

    def test_boundaries_are_inclusive_at_both_ends(self):
        from app.intel.event_markers import active_finding_ids

        payload = self._index([((*KEY_A, 11), T0)])
        bucket = payload["ts"][0]
        assert active_finding_ids(payload, bucket, bucket) == {11}

    def test_no_item_cap_unlike_slice_index(self):
        """A 5,000-key index returns every id; `slice_index` would collapse most away."""
        from app.intel.event_markers import MAX_TIMELINE_ITEMS, active_finding_ids

        n = MAX_TIMELINE_ITEMS + 500
        acc = MarkerAccumulator()
        for i in range(n):
            acc.add((f"rule-{i}", f"Rule {i}", "high", "execution", "WIN94", "hayabusa", i), T0)
        payload = build_index(acc)
        assert len(active_finding_ids(payload)) == n

    def test_legacy_six_wide_rows_contribute_nothing_rather_than_raising(self):
        from app.intel.event_markers import active_finding_ids

        payload = self._index([(KEY_A, T0)])
        payload["keys"] = [row[:6] for row in payload["keys"]]
        assert active_finding_ids(payload) == set()

    def test_junk_input_is_empty(self):
        from app.intel.event_markers import active_finding_ids

        assert active_finding_ids(None) == set()
        assert active_finding_ids({}) == set()
        assert active_finding_ids({"v": 999, "ts": [1], "k": [0], "keys": [[None] * 7]}) == set()
