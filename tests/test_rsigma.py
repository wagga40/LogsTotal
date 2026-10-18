"""RSigma must preserve evidence and never turn broken evaluation into a clean job."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from app.tools.registry import get_adapter


def adapter(**config):
    return get_adapter("rsigma", {"rules_path": "tools/rsigma/rules", **config})


def detection(**overrides):
    result = {
        "rule_title": "Alert",
        "rule_id": "r1",
        "level": "high",
        "tags": ["attack.execution"],
        "event": {
            "Event": {
                "System": {"EventID": 1, "Computer": "PC", "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T01:00:00Z"}}},
                "EventData": {"Image": "evil.exe", "ProcessId": 42},
            }
        },
    }
    result.update(overrides)
    return result


def test_normalization_groups_by_id_and_caps_evidence(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "one.yml").write_text("title: Alert\nid: r1\nauthor: Example Analyst\n")
    findings = adapter(rules_path=str(rules), max_finding_details=1).normalize([detection(), detection(), detection(rule_id="r2")])
    assert [f.count for f in findings] == [2, 1]
    assert findings[0].severity == "high"
    assert len(findings[0].details) == 1
    assert "author: Example Analyst" in findings[0].rule_content
    assert findings[0].details[0]["Computer"] == "PC"
    assert findings[0].details[0]["Image"] == "evil.exe"


def test_raw_reader_and_timeline_keep_identity_and_timestamp(tmp_path):
    from app.intel.event_timeline import extract_all_from_raw_output

    out = tmp_path / "x_rsigma.json"
    out.write_text(json.dumps(detection()) + "\n")
    buckets, events = extract_all_from_raw_output(1, job_dir=tmp_path)
    assert buckets == {"2026-01-01T01": {"execution": 1}}
    assert events[0]["ProcessId"] == 42
    assert events[0]["Event"]["EventData"]["Image"] == "evil.exe"


def test_winlogbeat_evidence_extracts_ecs_fields():
    event = {
        "@timestamp": "2026-01-01T01:00:00Z",
        "host": {"name": "PC"},
        "winlog": {"event_id": 1, "event_data": {"User": "domain\\alice"}},
        "process": {"executable": "evil.exe", "command_line": "evil -arg", "pid": 42, "parent": {"pid": 9}},
        "destination": {"ip": "192.0.2.7"},
    }
    detail = adapter().normalize([detection(event=event)])[0].details[0]
    assert (detail["Computer"], detail["Image"], detail["CommandLine"], detail["DestinationIp"], detail["ParentProcessId"]) == ("PC", "evil.exe", "evil -arg", "192.0.2.7", 9)


@pytest.mark.parametrize("config", [{"rules_path": ["one", "two"]}, {"docker_image": "image"}, {"threads": 2}])
def test_invalid_execution_config_is_rejected(config):
    with pytest.raises(ValueError):
        adapter(**config)


@pytest.mark.parametrize("record", [None, {"rule_title": "broken"}, detection(correlation_type="event_count")])
def test_invalid_or_unsupported_output_fails(record):
    with pytest.raises(ValueError):
        adapter().normalize([record])


@pytest.mark.parametrize(
    "payload,stderr,code,success",
    [
        ("", "Processed 2 events, 0 matches.", 0, True),
        ("not json", "", 0, False),
        (json.dumps(detection()), "Error parsing JSON on line 1: bad", 0, True),
        (json.dumps(detection()), "failure", 1, True),
        (json.dumps(detection()), "Processed 1 events, 1 matches.", 0, True),
    ],
)
def test_execution_publishes_usable_output(tmp_path, monkeypatch, payload, stderr, code, success):
    a = adapter()

    def execute(cmd, timeout, cancel_event, *, stdout_path, env):
        stdout_path.write_text(payload)
        return code, "", stderr

    monkeypatch.setattr(a, "_exec", execute)
    out = tmp_path / "events_rsigma.json"
    result = a._execute_and_parse(["unused"], out)
    assert result.success is success
    assert out.exists() is success
    assert result.stdout == ""


def test_command_sets_input_and_evidence_without_thread_flag():
    a = adapter()
    a._log_type = "evtx"
    cmd, error = a._build_local_cmd(Path(sys.executable), Path("/tmp/evidence.evtx"), Path("/tmp/out"))
    # The actual vendored binary is verified separately; this test only builds argv.
    assert not error
    assert cmd[1:3] == ["engine", "eval"]
    assert "@" + str(Path("/tmp/evidence.evtx").resolve()) in cmd
    assert "--include-event" in cmd
    assert "--threads" not in cmd
    assert cmd[cmd.index("--output-format") + 1] == "ndjson"


@pytest.fixture
def real_adapter(tmp_path):
    from app.tools.base import resolve_tool_path
    from app.tools.catalog import TOOLS

    spec = TOOLS["rsigma"]
    binary, reason = resolve_tool_path({asset.target: str(Path("tools/rsigma") / asset.installed) for asset in spec.assets})
    if reason:
        pytest.skip(reason)
    assert binary and Path(binary).is_file(), "vendored RSigma binary missing"
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "process.yml").write_text(
        "title: Process marker\nid: test-process\nauthor: Test Analyst\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: evil.exe\n  condition: selection\nlevel: high\ntags: [attack.execution]\n"
    )
    return adapter(tool_path=binary, rules_path=str(rules))


@pytest.mark.parametrize(
    "log_type,event,expected",
    [
        ("json_evtx", {"Event": {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}, "EventData": {"Image": "evil.exe"}}}, 1),
        ("json_evtx", {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}, "EventData": {"Image": "evil.exe"}}, 1),
        ("json_evtx", {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "evil.exe"}, 1),
        ("json_evtx", {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3, "Image": "evil.exe"}, 0),
        ("json_evtx", {"Channel": "Security", "EventID": 1, "Image": "evil.exe"}, 0),
        ("json_evtx", {"Channel": "Security", "EventID": 4688, "NewProcessName": "evil.exe"}, 1),
        (
            "json_evtx",
            {
                "Event": {
                    "System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Provider": {"#attributes": {"Name": "Unrelated"}}},
                    "EventData": {"Image": "evil.exe"},
                }
            },
            0,
        ),
        ("json_winlogbeat", {"winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "1"}, "process": {"executable": "evil.exe"}}, 1),
        ("json_winlogbeat", {"winlog": {"channel": "Security", "event_id": 4688, "event_data": {"NewProcessName": "evil.exe"}}}, 1),
    ],
)
def test_real_engine_windows_mapping_and_source_boundaries(real_adapter, tmp_path, log_type, event, expected):
    source = tmp_path / "event.json"
    source.write_text(json.dumps(event) + "\n")
    result = real_adapter.run(source, tmp_path / "out", log_type=log_type)
    assert result.success, result.error
    assert sum(f.count for f in result.findings) == expected
    assert "Processed 1 events" in result.stderr


def test_corrupt_json_is_not_a_successful_clean_scan(real_adapter, tmp_path):
    source = tmp_path / "corrupt.json"
    source.write_text("{not JSON}\n")
    result = real_adapter.run(source, tmp_path / "out", log_type="json_evtx")
    assert not result.success
    assert "Invalid" in result.error


@pytest.mark.parametrize("log_type", ["json_evtx", "json_winlogbeat"])
def test_utf8_bom_preserves_all_events_and_source_bytes(real_adapter, tmp_path, monkeypatch, log_type):
    from app.detection.detector import detect_log_type

    if log_type == "json_evtx":
        event = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "evil.exe"}
    else:
        event = {"winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1}, "process": {"executable": "evil.exe"}}
    payload = b"\xef\xbb\xbf" + (json.dumps(event) + "\n\n" + json.dumps(event) + "\n").encode()
    source = tmp_path / "event.json"
    source.write_bytes(payload)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(scratch))
    assert detect_log_type(source).value == log_type

    result = real_adapter.run(source, tmp_path / "out", log_type=log_type)

    assert result.success, result.error
    assert sum(f.count for f in result.findings) == 2
    assert source.read_bytes() == payload
    assert not list(scratch.iterdir())
    assert (tmp_path / "out" / "event_rsigma.json").is_file()


@pytest.mark.parametrize("failure", ["malformed", "cancelled", "timeout"])
def test_bom_temporary_input_is_removed_on_failure(real_adapter, tmp_path, monkeypatch, failure):
    import threading

    import app.tools.rsigma as module

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(scratch))
    source = tmp_path / "event.json"
    payload = b"\xef\xbb\xbf" + (b"{bad JSON}" if failure == "malformed" else b"{}")
    source.write_bytes(payload)
    cancel = threading.Event()
    check_budget = real_adapter._check_budget
    monotonic = module.time.monotonic

    def check_copy_budget(deadline):
        if list(scratch.iterdir()):
            if failure == "cancelled":
                cancel.set()
            elif failure == "timeout":
                monkeypatch.setattr(module.time, "monotonic", lambda: max(monotonic(), deadline + 1))
        check_budget(deadline)

    monkeypatch.setattr(real_adapter, "_check_budget", check_copy_budget)

    result = real_adapter.run(source, tmp_path / "out", log_type="json_evtx", cancel_event=cancel)

    assert not result.success
    assert {"malformed": "Invalid", "cancelled": "cancelled", "timeout": "timed out"}[failure] in result.error
    assert not list(scratch.iterdir())
    assert source.read_bytes() == payload
    assert not list((tmp_path / "out").glob("*_rsigma.json"))


@pytest.mark.parametrize(
    "sample,log_type,event_count,rule_id",
    [
        ("bitsadmin.evtx", "evtx", 1, "d059842b-6b9d-4ed1-b5c3-5b89143c6ede"),
        ("sysmon_process_creation.json", "json_evtx", 4, "fb843269-508c-4b76-8b8d-88679db22ce7"),
        ("sysmon_winlogbeat.json", "json_winlogbeat", 2, None),
    ],
)
def test_shipped_sample_coverage(real_adapter, tmp_path, sample, log_type, event_count, rule_id):
    real_adapter.rules_path = "tools/rsigma/rules"
    real_adapter.rules_paths = ["tools/rsigma/rules"]
    result = real_adapter.run(Path("samples/windows") / sample, tmp_path / "out", log_type=log_type)
    assert result.success, result.error
    assert f"Processed {event_count} " in result.stderr
    if rule_id:
        assert any(f.rule_id == rule_id and f.details and f.rule_content for f in result.findings), [(f.rule_id, f.rule_name) for f in result.findings]


def test_evidence_preserves_evaluated_process_aliases():
    event = {"ProcessId": "new-pid", "Event": {"EventData": {"ProcessId": "creator-pid"}}}
    assert adapter().normalize([detection(event=event)])[0].details[0]["ProcessId"] == "new-pid"


def test_ambient_rsigma_settings_do_not_change_batch_contract(real_adapter, tmp_path, monkeypatch):
    monkeypatch.setenv("RSIGMA_EVAL__FAIL_ON_DETECTION", "true")
    source = tmp_path / "event.json"
    source.write_text(json.dumps({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": "evil.exe"}))
    result = real_adapter.run(source, tmp_path / "out", log_type="json_evtx")
    assert result.success, result.error
    assert len(result.findings) == 1


def test_unmapped_rule_logsource_cannot_match_every_event(real_adapter, tmp_path):
    rule = Path(real_adapter.rules_path) / "process.yml"
    rule.write_text(rule.read_text().replace("process_creation", "unsupported_category"))
    source = tmp_path / "event.json"
    source.write_text(json.dumps({"EventID": 1, "Image": "evil.exe"}))
    result = real_adapter.run(source, tmp_path / "out", log_type="json_evtx")
    assert not result.success
    assert "logsource" in result.error


def test_json_input_validation_is_inside_task_timeout(real_adapter, tmp_path, monkeypatch):
    import app.tools.rsigma as module

    source = tmp_path / "events.json"
    source.write_text("{}\n{}\n")
    times = iter([0, 301, 301, 301, 301])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times, 301))
    result = real_adapter.run(source, tmp_path / "out", log_type="json_evtx")
    assert not result.success
    assert "timed out" in result.error


def test_malformed_rules_do_not_become_empty_success(real_adapter, tmp_path):
    (Path(real_adapter.rules_path) / "process.yml").write_text("invalid: [")
    source = tmp_path / "events.json"
    source.write_text("{}\n")
    result = real_adapter.run(source, tmp_path / "out", log_type="json_evtx")
    assert not result.success


@pytest.mark.parametrize(
    "event",
    [
        {"Event": {"System": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": {"#text": 1}}, "EventData": {"Data": [{"@Name": "Image", "#text": "evil.exe"}]}}},
        {"winlog.channel": "Microsoft-Windows-Sysmon/Operational", "winlog.event_id": "1", "process.executable": "evil.exe"},
    ],
)
def test_exported_event_field_layouts(real_adapter, tmp_path, event):
    source = tmp_path / "event.json"
    source.write_text(json.dumps(event))
    log_type = "json_winlogbeat" if "winlog.channel" in event else "json_evtx"
    result = real_adapter.run(source, tmp_path / "out", log_type=log_type)
    assert result.success, result.error
    assert len(result.findings) == 1
    assert result.findings[0].details[0]["Image"] == "evil.exe"


def test_category_without_windows_product_is_rejected(real_adapter, tmp_path):
    rule = Path(real_adapter.rules_path) / "process.yml"
    rule.write_text(rule.read_text().replace("  product: windows\n", ""))
    source = tmp_path / "event.json"
    source.write_text(json.dumps({"Channel": "Security", "EventID": 1, "Image": "evil.exe"}))
    result = real_adapter.run(source, tmp_path / "out", log_type="json_evtx")
    assert not result.success
    assert "logsource" in result.error


def test_security_process_tree_preserves_creator_pid(real_adapter, tmp_path):
    from app.intel.event_timeline import extract_all_from_raw_output
    from app.intel.lineage import build_process_forest

    source = tmp_path / "security.json"
    events = [
        {"Channel": "Security", "EventID": 4688, "Computer": "PC", "NewProcessId": str(pid), "ProcessId": str(parent), "NewProcessName": "evil.exe"}
        for pid, parent in [(100, 4), (200, 100)]
    ]
    source.write_text("\n".join(json.dumps(e) for e in events))
    out = tmp_path / "out"
    result = real_adapter.run(source, out, log_type="json_evtx")
    assert result.success, result.error
    _, raw = extract_all_from_raw_output(1, job_dir=out)
    forest = build_process_forest(raw)
    assert len(forest["roots"]) == 1
    assert forest["roots"][0]["pid"] == "100"
    assert forest["roots"][0]["children"][0]["pid"] == "200"


@pytest.mark.parametrize(
    "log_type,event",
    [
        ("json_evtx", {"Event": {"System": {"EventID": 1}, "EventData": "broken"}}),
        ("json_winlogbeat", {"winlog": 3}),
    ],
)
def test_event_filter_errors_are_failures(real_adapter, tmp_path, log_type, event):
    source = tmp_path / "bad.json"
    source.write_text(json.dumps(event))
    result = real_adapter.run(source, tmp_path / "out", log_type=log_type)
    assert not result.success
    assert not list((tmp_path / "out").glob("*_rsigma.json"))


@pytest.mark.parametrize(
    "channel,eid,data,rule_id",
    [
        ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21, {"Address": "16777216"}, "64d51a51-32a6-49f0-9f3d-17e34d640272"),
        ("Microsoft-Windows-LSA/Operational", 300, {"TargetUserSid": "S-1-5-21-123-456-789-1001", "SidList": "S-1-5-32-544"}, "7ac407cc-0f48-4328-aede-de1d2e6fef41"),
        ("Microsoft-Windows-DNS Client Events/Operational", 3008, {"QueryName": "example.onion"}, "8384bd26-bde6-4da9-8e5d-4174a7a47ca2"),
    ],
)
@pytest.mark.parametrize("log_type", ["json_evtx", "json_winlogbeat"])
def test_shipped_service_rules_with_provider_userdata(real_adapter, tmp_path, channel, eid, data, rule_id, log_type):
    if log_type == "json_evtx":
        event = {"Event": {"System": {"Channel": channel, "EventID": eid}, "UserData": {"EventXML": data}}}
    else:
        event = {"winlog": {"channel": channel, "event_id": eid, "user_data": {"EventXML": data}}}
    real_adapter.rules_path = "tools/rsigma/rules"
    real_adapter.rules_paths = [real_adapter.rules_path]
    source = tmp_path / "events.json"
    source.write_text(json.dumps(event))
    result = real_adapter.run(source, tmp_path / "out", log_type=log_type)
    assert result.success, result.error
    assert rule_id in {f.rule_id for f in result.findings}


def test_source_channel_does_not_overwrite_cleared_channel(real_adapter, tmp_path):
    # Service belongs to System, but the rule's Channel describes the cleared log.
    event = {
        "Event": {
            "System": {"Channel": "System", "EventID": 104, "Provider": {"#attributes": {"Name": "Microsoft-Windows-Eventlog"}}},
            "UserData": {"LogFileCleared": {"Channel": "Application"}},
        }
    }
    real_adapter.rules_path = "tools/rsigma/rules"
    real_adapter.rules_paths = [real_adapter.rules_path]
    source = tmp_path / "events.json"
    source.write_text(json.dumps(event))
    result = real_adapter.run(source, tmp_path / "out", log_type="json_evtx")
    assert result.success, result.error
    ids = {f.rule_id for f in result.findings}
    assert "a62b37e0-45d3-48d9-a517-90c1a1b0186b" in ids
    assert "100ef69e-3327-481c-8e5c-6d80d9507556" not in ids


@pytest.mark.parametrize("aborted", ["cancelled", "timeout"])
def test_cancellation_discards_output_but_timeout_retains_evidence(tmp_path, monkeypatch, aborted):
    import threading

    import app.tools.rsigma as module

    a = adapter()
    a._cancel_event = threading.Event()
    now = [0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])

    def execute(cmd, timeout, cancel_event, *, stdout_path, env):
        stdout_path.write_text(json.dumps(detection()))
        if aborted == "cancelled":
            a._cancel_event.set()
        else:
            now[0] = 301
        return 0, "", "Processed 1 events, 1 matches."

    monkeypatch.setattr(a, "_exec", execute)
    out = tmp_path / "event_rsigma.json"
    result = a._execute_and_parse(["unused"], out)
    if aborted == "cancelled":
        assert not result.success
        assert not out.exists()
    else:
        assert result.success
        assert result.diagnostics.completion == "incomplete"
        assert out.exists()


def test_incomplete_execution_retains_valid_records_and_cleans_artifact(tmp_path, monkeypatch):
    a = adapter()

    def execute(cmd, **kw):
        kw["stdout_path"].write_text(json.dumps(detection()) + '\n{"truncated":\n')
        return 0, "", "Warning: skipped event\nProcessed 2 events, 2 matches."

    monkeypatch.setattr(a, "_exec", execute)
    output = tmp_path / "out_rsigma.json"
    result = a._execute_and_parse(["unused"], output)
    assert result.success
    assert result.diagnostics.completion == "incomplete"
    assert result.diagnostics.records_skipped == 1
    assert sum(f.count for f in result.findings) == 1
    assert len(list(a._records(output))) == 1


def test_timeout_preserves_valid_rsigma_evidence(tmp_path, monkeypatch):
    now = [0.0]
    monkeypatch.setattr("app.tools.rsigma.time.monotonic", lambda: now[0])
    a = adapter(timeout=1)

    def execute(cmd, **kw):
        kw["stdout_path"].write_text(json.dumps(detection()) + "\n")
        now[0] = 10.0
        return -1, "", "Command timed out"

    monkeypatch.setattr(a, "_exec", execute)
    result = a._execute_and_parse(["unused"], tmp_path / "out_rsigma.json")
    assert result.success
    assert result.diagnostics.completion == "incomplete"
    assert result.findings[0].count == 1
