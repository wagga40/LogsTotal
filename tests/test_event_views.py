"""Field-source compatibility and declarative projections through real consumers."""

import copy
import json
import sys
from types import SimpleNamespace

from app.intel.event_timeline import _event_computer, extract_timestamp
from app.intel.lineage import build_process_forest
from app.intel.relationships import _flatten, extract_relationships, trim_evidence_event
from app.intel.tactics import _resolve_tactic_from_event
from app.tools.event_fields import EventField, EventProjection, EventRecord, EventSource, EventView


def test_canonical_aliases_retain_zero_uid_in_lineage_and_evidence(tmp_path):
    from app.tools.base import ToolAdapter
    from app.tools.mapping import MetadataMapping, OutputMapping, Selector

    projection = EventProjection.canonical(
        EventSource(
            ("native",),
            fields=(
                EventField("exe", (("program",),)),
                EventField("pid", (("process_id",),)),
                EventField("uid", (("user_id",),)),
                EventField("enabled", (("enabled",),)),
            ),
        )
    )

    class LinuxAdapter(ToolAdapter):
        output_mapping = OutputMapping(
            finding=MetadataMapping(rule_name=Selector((("title",),), default="")),
            event_projection=lambda event: EventRecord(event, projection=projection),
        )

    native = {"title": "Root process", "native": {"program": "/bin/bash", "process_id": 123, "user_id": 0, "enabled": False}}
    output = tmp_path / "matches.json"
    output.write_text(json.dumps([native]))
    match = next(LinuxAdapter.iter_raw_matches(output))
    assert EventView(match.event).analytics_sources == [{"exe": "/bin/bash", "pid": 123, "uid": 0, "enabled": False}]
    assert build_process_forest([match.event])["roots"][0]["user"] == "0"
    assert trim_evidence_event(match.event)["uid"] == 0
    assert _flatten(match.event)["uid"] == 0
    assert match.event == native
    assert json.loads(json.dumps(match.event)) == native


def test_canonical_field_fallback_distinguishes_missing_and_null():
    native = {"null": None, "fallback": 7, "zero": 0}
    projection = EventProjection.canonical(
        EventSource(
            fields=(
                EventField("non_null", (("missing",), ("null",), ("fallback",))),
                EventField("present_null", (("missing",), ("null",), ("fallback",)), fallback="missing"),
                EventField("truthy", (("zero",), ("fallback",)), fallback="truthy"),
            )
        )
    )
    assert EventView(native, projection).relationship_fields == {"non_null": 7, "present_null": None, "truthy": 7}


def test_projection_is_used_by_relationship_consumers():
    # A declared native source must reach consumers without a new vendor branch.
    event = EventRecord(
        {"payload": {"program": r"C:\tools\probe.exe", "account": "Analyst"}},
        projection=EventProjection(
            relationship_sources=(
                EventSource(
                    path=("payload",),
                    fields=(
                        EventField(name="Image", paths=(("program",),)),
                        EventField(name="User", paths=(("account",),)),
                    ),
                ),
            ),
            excluded_fields=(),
        ),
    )
    assert ("probe.exe", "executable", "Analyst", "user", "runs_as") in extract_relationships(event)


def test_legacy_merge_precedence_and_lineage_extra_defaults():
    event = {
        "Event": {"System": {"Image": "system.exe", "EventID": 1}, "EventData": {"Image": "data.exe", "User": "Data"}},
        "Details": {"Image": "detail.exe", "User": "Detail", "ProcessId": "5"},
        "Image": "root.exe",
        "ExtraFieldInfo": {"Image": "extra.exe", "ParentImage": "parent.exe", "User": "Extra", "ParentProcessId": "2"},
    }
    original = copy.deepcopy(event)
    fields = _flatten(event)
    assert fields["Image"] == "root.exe"
    assert fields["User"] == "Detail"
    assert "ParentImage" not in fields
    relationships = extract_relationships(event)
    assert ("root.exe", "executable", "Detail", "user", "runs_as") in relationships
    assert not any(edge[-1] == "parent_of" for edge in relationships)
    forest = build_process_forest([event])
    parent = forest["roots"][0]
    assert parent["image"] == "parent.exe"
    assert parent["children"][0]["image"] == "root.exe"
    assert parent["children"][0]["user"] == "Detail"
    assert event == original


def test_document_wrapper_is_only_read_for_marker_host():
    event = {"document": {"data": {"Event": {"System": {"Computer": "WRAPPED", "EventID": 1}, "EventData": {"Image": "wrapped.exe", "ProcessId": "7"}}}}}
    assert _event_computer(event) == "WRAPPED"
    assert extract_relationships(event) == []
    assert build_process_forest([event])["stats"]["hits"] == 0


def test_bad_truthy_timestamp_and_host_preserve_fallback_behavior():
    event = {
        "Timestamp": "short",
        "timestamp": "2024-01-01T01:00:00",
        "Computer": 42,
        "computer": "LOWER",
        "Event": {"System": {"Computer": "NESTED", "TimeCreated_attributes": {"SystemTime": "2024-02-02T02:00:00"}}},
    }
    assert extract_timestamp(event) == "2024-02-02T02:00:00"
    assert _event_computer(event) == "NESTED"


def test_zircolite_root_system_time_is_a_timestamp():
    """Zircolite flattens TimeCreated to a root `SystemTime` and writes no `Timestamp`.

    Reading only `Timestamp` and the nested EVTX path left every Zircolite match
    undated: counted as undated in the event markers and missing from the histogram.
    """
    zircolite = {"SystemTime": "2019-03-19T23:34:25.1234567Z", "Computer": "WIN-1", "EventID": 1, "rule_title": "x"}
    assert EventView(zircolite).timestamp == "2019-03-19T23:34:25.1234567Z"
    assert extract_timestamp(zircolite) == "2019-03-19T23:34:25.1234567Z"
    # An explicit Timestamp still wins over it, and the nested EVTX path still answers last.
    both = {**zircolite, "Timestamp": "2024-01-01T00:00:00Z"}
    assert EventView(both).timestamp == "2024-01-01T00:00:00Z"
    nested = {"Event": {"System": {"TimeCreated_attributes": {"SystemTime": "2024-02-02T02:00:00"}}}}
    assert EventView(nested).timestamp == "2024-02-02T02:00:00"


def test_tactic_priority_and_abbreviation_order_are_preserved():
    event = {"MitreTactics": ["Evas", "Exec"], "MitreTags": ["T1001"], "OtherTags": ["T1002"]}
    assert _resolve_tactic_from_event(event, {"Rule": "impact"}, {"t1001": "discovery"}, "Rule") == "impact"
    assert _resolve_tactic_from_event(event, {}, {"t1001": "discovery"}, "Rule") == "defense_evasion"
    event["MitreTactics"] = "unknown"
    assert _resolve_tactic_from_event(event, {}, {"t1001": "discovery", "t1002": "execution"}, "Rule") == "discovery"


def test_projection_keeps_native_evidence_and_declared_sources_independent():
    native = {"payload": {"account": "Fallback", "program": "native.exe"}, "extra": {"account": "Wrong", "parent": "parent.exe"}}
    source = EventSource(("payload",), (EventField("User", (("missing",), ("account",))), EventField("Image", (("program",),))))
    extra = EventSource(("extra",), (EventField("User", (("account",),)), EventField("ParentImage", (("parent",),))))
    record = EventRecord(native, projection=EventProjection(analytics_sources=(source,), relationship_sources=(source,), lineage_defaults=(extra,)))
    view = EventView(record)
    assert view.analytics_sources == [{"User": "Fallback", "Image": "native.exe"}]
    assert view.relationship_fields == {"User": "Fallback", "Image": "native.exe"}
    assert view.lineage_fields == {"User": "Fallback", "Image": "native.exe", "ParentImage": "parent.exe"}
    assert record == native
    assert json.loads(json.dumps(record)) == native


def test_legacy_analytics_sources_keep_conflicting_values_separate():
    event = {"User": "Root", "Details": {"User": "Details"}, "Event": {"System": {"User": "System"}, "EventData": {"User": "Data"}}, "ExtraFieldInfo": {"User": "Extra"}}
    sources = EventView(event).analytics_sources
    assert [source["User"] for source in sources] == ["Root", "Details", "Data"]
    assert sources[0] is event
    assert sources[1] is event["Details"]
    assert sources[2] is event["Event"]["EventData"]


def test_projected_adapter_events_reach_analytics_markers_and_lineage(tmp_path, monkeypatch):
    from app.analytics import _compute_analytics_data
    from app.intel import event_timeline
    from app.tools.base import ToolAdapter
    from app.tools.catalog import TOOLS, ToolSpec
    from app.tools.mapping import MetadataMapping, OutputMapping, Selector

    source = EventSource(
        ("native",),
        tuple(
            EventField(name, ((key,),))
            for name, key in (
                ("Image", "program"),
                ("User", "account"),
                ("Computer", "machine"),
                ("ProcessId", "pid"),
                ("EventID", "event_code"),
                ("Timestamp", "when"),
                ("MitreTactics", "tactic"),
                ("MitreTags", "technique"),
            )
        ),
    )
    projection = EventProjection.canonical(source)

    class ExampleAdapter(ToolAdapter):
        name = "example"
        output_mapping = OutputMapping(
            finding=MetadataMapping(rule_name=Selector((("title",),), default="")),
            events=Selector((("events",),), default=[]),
            event_projection=lambda event: EventRecord(event, projection=projection),
        )

        def _output_filename(self, file_path):
            return file_path.stem + ".json"

    native = {
        "native": {
            "program": r"C:\bin\agent.exe",
            "account": "Operator",
            "machine": "NEW-HOST",
            "pid": "37",
            "event_code": 1,
            "when": "2026-01-01T07:08:09Z",
            "tactic": "Exec",
            "technique": "T1001",
        }
    }
    records = [{"title": "Example rule", "events": [native]}]
    original = copy.deepcopy(records)
    output = tmp_path / "example_example.json"
    output.write_text(json.dumps(records))
    # Register a real catalog entry and refresh the timeline's import-time suffix cache.
    monkeypatch.setattr(sys.modules[__name__], "_ProjectedTestAdapter", ExampleAdapter, raising=False)
    monkeypatch.setitem(
        TOOLS,
        "example",
        ToolSpec(
            name="example",
            adapter=f"{__name__}:_ProjectedTestAdapter",
            supported_types=frozenset({"json"}),
            execution_modes=frozenset({"local"}),
            output_suffix="_example.json",
            supports_threads=False,
            repo="",
            rule_repo="",
        ),
    )
    monkeypatch.setitem(event_timeline._TOOL_BY_SUFFIX, "_example.json", "example")
    monkeypatch.setattr(event_timeline, "_OUTPUT_SUFFIXES", (*event_timeline._OUTPUT_SUFFIXES, "_example.json"))
    finding = ExampleAdapter({}).normalize(records)[0]
    match = next(ExampleAdapter.iter_raw_matches(output))
    assert finding.details == [native]
    assert match.event == native
    assert json.loads(json.dumps(match.event)) == native
    assert match.timestamp == "2026-01-01T07:08:09Z"
    assert _event_computer(match.event) == "NEW-HOST"
    assert _resolve_tactic_from_event(match.event, {}, {}, "Example rule") == "execution"
    assert _resolve_tactic_from_event(EventRecord(native, projection=EventProjection(technique_paths=(("native", "technique"),))), {}, {"t1001": "discovery"}, "") == "discovery"
    buckets, events = event_timeline.parse_single_output_file(output, {}, {})
    assert buckets == {"2026-01-01T07": {"execution": 1}}
    forest = build_process_forest(events)
    assert forest["stats"]["hits"] == 1
    assert (forest["roots"][0]["image"], forest["roots"][0]["pid"], forest["roots"][0]["computer"]) == ("agent.exe", "37", "NEW-HOST")
    analytics = _compute_analytics_data(SimpleNamespace(id=1, task_results=[]), job_dir=tmp_path)
    assert analytics["users"] == ["Operator"]
    assert analytics["computers"] == ["NEW-HOST"]
    assert analytics["executables"] == ["agent.exe"]
    assert analytics["event_markers"]["computers"] == ["NEW-HOST"]
    assert analytics["event_markers"]["tools"] == ["example"]
    assert analytics["relationships"][("agent.exe", "executable", "Operator", "user", "runs_as")] == 1
    assert analytics["relationships"][("agent.exe", "executable", "NEW-HOST", "computer", "runs_on")] == 1
    assert records == original
    assert json.loads(output.read_text()) == original
