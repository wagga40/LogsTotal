"""Tests for app.detection.detector.detect_log_type — pure file-based detection."""

from __future__ import annotations

import json

import pytest

from app.detection.detector import detect_log_type
from app.models import LogType

# ── EVTX (magic bytes) ──────────────────────────────────────────────────────


def test_evtx_magic_bytes(tmp_file):
    p = tmp_file(b"ElfFile\x00" + b"\x00" * 100, "test.evtx")
    assert detect_log_type(p) == LogType.EVTX


def test_evtx_magic_with_trailing_data(tmp_file):
    p = tmp_file(b"ElfFile\x00some random trailing data here", "test.evtx")
    assert detect_log_type(p) == LogType.EVTX


# ── JSON Winlogbeat ──────────────────────────────────────────────────────────


def test_json_winlogbeat_winlog_key(tmp_file):
    line = json.dumps({"winlog": {"event_id": 1}, "message": "test"})
    p = tmp_file(line, "winlogbeat.json")
    assert detect_log_type(p) == LogType.JSON_WINLOGBEAT


def test_json_winlogbeat_agent_key(tmp_file):
    line = json.dumps({"agent": {"name": "host1"}, "message": "test"})
    p = tmp_file(line, "winlogbeat.json")
    assert detect_log_type(p) == LogType.JSON_WINLOGBEAT


# ── JSON EVTX ────────────────────────────────────────────────────────────────


def test_json_evtx_eventid(tmp_file):
    line = json.dumps({"EventID": 4688, "Computer": "DC01"})
    p = tmp_file(line, "evtx.json")
    assert detect_log_type(p) == LogType.JSON_EVTX


def test_json_evtx_event_key(tmp_file):
    line = json.dumps({"Event": {"System": {"EventID": 1}}})
    p = tmp_file(line, "evtx.json")
    assert detect_log_type(p) == LogType.JSON_EVTX


def test_json_evtx_system_key(tmp_file):
    line = json.dumps({"System": {"EventID": 1}})
    p = tmp_file(line, "evtx.json")
    assert detect_log_type(p) == LogType.JSON_EVTX


# ── JSON with unknown keys → UNKNOWN ────────────────────────────────────────


def test_json_unknown_keys(tmp_file):
    line = json.dumps({"custom_field": "value", "data": 123})
    p = tmp_file(line, "unknown.json")
    assert detect_log_type(p) == LogType.UNKNOWN


# ── Auditd ───────────────────────────────────────────────────────────────────


def test_auditd_syscall(tmp_file):
    content = "type=SYSCALL msg=audit(1234567890.123:456): arch=c000003e syscall=59\n"
    p = tmp_file(content, "audit.log")
    assert detect_log_type(p) == LogType.AUDITD


def test_auditd_execve(tmp_file):
    content = 'type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="/bin/sh"\n'
    p = tmp_file(content, "audit.log")
    assert detect_log_type(p) == LogType.AUDITD


def test_auditd_audit_paren(tmp_file):
    content = 'node=host1 audit(1234567890.123:456): key="test"\n'
    p = tmp_file(content, "audit.log")
    assert detect_log_type(p) == LogType.AUDITD


# ── Journald ─────────────────────────────────────────────────────────────────


def test_journald_json_export_realtime_timestamp(tmp_file):
    line = json.dumps(
        {
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "__CURSOR": "s=abc123",
            "MESSAGE": "Started Session 1 of user root.",
            "_SYSTEMD_UNIT": "session-1.scope",
        }
    )
    p = tmp_file(line, "journal.json")
    assert detect_log_type(p) == LogType.JOURNALD


def test_journald_json_message_and_systemd_key(tmp_file):
    line = json.dumps({"MESSAGE": "some message", "_SYSTEMD_UNIT": "sshd.service"})
    p = tmp_file(line, "journal.json")
    assert detect_log_type(p) == LogType.JOURNALD


def test_journald_json_message_and_hostname_key(tmp_file):
    line = json.dumps({"MESSAGE": "some message", "_HOSTNAME": "web01"})
    p = tmp_file(line, "journal.json")
    assert detect_log_type(p) == LogType.JOURNALD


def test_journald_text_export_cursor(tmp_file):
    content = "__CURSOR=s=abc123;i=1;b=def\n__REALTIME_TIMESTAMP=1700000000000000\nMESSAGE=hello\n"
    p = tmp_file(content, "journal.export")
    assert detect_log_type(p) == LogType.JOURNALD


def test_journald_json_message_alone_is_unknown(tmp_file):
    """A bare MESSAGE key without any journald-specific field is not enough."""
    line = json.dumps({"MESSAGE": "some message"})
    p = tmp_file(line, "unknown.json")
    assert detect_log_type(p) == LogType.UNKNOWN


# ── Sysmon for Linux ─────────────────────────────────────────────────────────


def test_sysmon_linux_provider_marker(tmp_file):
    content = 'Jan  5 12:34:56 web01 sysmon: <Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID></System></Event>\n'
    p = tmp_file(content, "sysmon.log")
    assert detect_log_type(p) == LogType.SYSMON_LINUX


def test_sysmon_linux_marker_on_later_line(tmp_file):
    content = 'Jan  5 12:34:55 web01 systemd[1]: Started Sysmon daemon.\nJan  5 12:34:56 web01 sysmon: <Event><System><Provider Name="Linux-Sysmon"/></System></Event>\n'
    p = tmp_file(content, "sysmon.log")
    assert detect_log_type(p) == LogType.SYSMON_LINUX


# ── Syslog ───────────────────────────────────────────────────────────────────


def test_syslog_rfc5424_pri_version(tmp_file):
    content = "<34>1 2024-10-11T22:14:15.003Z host1 su - ID47 - 'su root' failed\n"
    p = tmp_file(content, "syslog")
    assert detect_log_type(p) == LogType.SYSLOG


def test_syslog_rfc3164_pri(tmp_file):
    content = "<34>Oct 11 22:14:15 host1 su: 'su root' failed for user on /dev/pts/8\n"
    p = tmp_file(content, "syslog")
    assert detect_log_type(p) == LogType.SYSLOG


def test_syslog_month_prefix(tmp_file):
    content = "Jan  5 12:34:56 myhost sshd[1234]: Accepted publickey for user\n"
    p = tmp_file(content, "syslog")
    assert detect_log_type(p) == LogType.SYSLOG


def test_syslog_iso_timestamp(tmp_file):
    content = "2024-01-15T10:30:00+00:00 myhost kernel: some message\n"
    p = tmp_file(content, "syslog")
    assert detect_log_type(p) == LogType.SYSLOG


# ── Unknown / edge cases ────────────────────────────────────────────────────


def test_empty_file(tmp_file):
    p = tmp_file(b"", "empty.log")
    assert detect_log_type(p) == LogType.UNKNOWN


def test_garbage_binary(tmp_file):
    p = tmp_file(b"\x89PNG\r\n\x1a\n\x00\x00\x00", "image.png")
    assert detect_log_type(p) == LogType.UNKNOWN


def test_nonexistent_file(tmp_path):
    p = tmp_path / "does_not_exist.log"
    assert detect_log_type(p) == LogType.UNKNOWN


def test_plain_text_unknown(tmp_file):
    p = tmp_file("hello world\nthis is just text\n", "plain.txt")
    assert detect_log_type(p) == LogType.UNKNOWN


def test_ndjson_winlogbeat(tmp_file):
    """NDJSON: first line determines type."""
    lines = "\n".join(
        [
            json.dumps({"winlog": {"event_id": 1}}),
            json.dumps({"winlog": {"event_id": 2}}),
        ]
    )
    p = tmp_file(lines, "ndjson.json")
    assert detect_log_type(p) == LogType.JSON_WINLOGBEAT


# ── non-object JSON first lines ─────────────────────────────────────────────
#
# Only one *object* per line is a JSON log. Probing a non-dict with `in` would
# either crash (`"winlog" in 1718000000` → TypeError) or quietly substring-match,
# which is worse: the job runs the wrong parser and reports zero findings, reading
# as *clean* rather than *not analysed*.


def test_bare_number_first_line_does_not_crash(tmp_file):
    p = tmp_file("1718000000\nsome more log text\n", "ids.log")
    assert detect_log_type(p) == LogType.UNKNOWN


def test_bare_bool_first_line_does_not_crash(tmp_file):
    p = tmp_file("true\nmore\n", "flag.log")
    assert detect_log_type(p) == LogType.UNKNOWN


def test_quoted_string_mentioning_winlog_is_not_winlogbeat(tmp_file):
    """A substring match on a JSON string must not be read as a winlogbeat log."""
    p = tmp_file('"user opened the winlog viewer"\nmore text\n', "note.log")
    assert detect_log_type(p) == LogType.UNKNOWN


def test_quoted_string_mentioning_event_is_not_json_evtx(tmp_file):
    p = tmp_file('"EventID stuff happened"\nmore text\n', "note.log")
    assert detect_log_type(p) == LogType.UNKNOWN


def test_json_array_first_line_is_not_a_json_log(tmp_file):
    """Zircolite needs --json-array-input for arrays; we only classify NDJSON objects."""
    p = tmp_file('[{"Event": {"EventID": 1}}]\n', "array.json")
    assert detect_log_type(p) == LogType.UNKNOWN


def test_non_object_json_falls_through_to_text_heuristics(tmp_file):
    """A scalar first line must not short-circuit the later auditd/syslog checks."""
    p = tmp_file("1718000000\ntype=SYSCALL msg=audit(1.0:1): a0=1\n", "odd.log")
    assert detect_log_type(p) == LogType.AUDITD


@pytest.mark.parametrize(
    "body, expected",
    [
        (b'{"winlog": {"event_id": 4688}}\n', "json_winlogbeat"),
        (b'{"Event": {"System": {"EventID": 4688}}}\n', "json_evtx"),
        (b"Jan  1 00:00:00 host sshd[1]: Accepted password for root\n" * 3, "syslog"),
        (b"type=SYSCALL msg=audit(1700000000.000:1): arch=c000003e syscall=59 success=yes\n" * 3, "auditd"),
    ],
)
def test_a_utf8_byte_order_mark_does_not_hide_the_format(body, expected):
    """PowerShell and .NET write UTF-8 with a BOM by default. It is invisible in an editor,
    `str.strip()` leaves it, and every `^`-anchored pattern then misses — so the file came
    out `unknown` and every typed workflow refused it."""
    from app.detection.detector import detect_log_type_from_bytes

    assert detect_log_type_from_bytes(body).value == expected, "control: without a BOM"
    assert detect_log_type_from_bytes(b"\xef\xbb\xbf" + body).value == expected
