"""
Log file type auto-detection.
Uses magic bytes and content heuristics — no external library needed.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.json_utils import loads as json_loads
from app.models import LogType

# EVTX magic: "ElfFile\x00"
_EVTX_MAGIC = b"ElfFile\x00"

# Pre-compiled syslog detection patterns
_RE_SYSLOG_MONTH = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+")
_RE_SYSLOG_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
# RFC3164/RFC5424 priority prefix ("<34>..."), optionally followed by a version digit
_RE_SYSLOG_PRI = re.compile(r"^<\d{1,3}>")
_RE_SYSLOG_VERSION = re.compile(r"^\d{1,2}\s+")

# Sysmon for Linux writes syslog-wrapped XML events tagged with this provider name
_SYSMON_LINUX_MARKER = "Linux-Sysmon"

# Windows event XML (wevtutil qe /f:xml, Get-WinEvent | ForEach ToXml). Anchored at the
# start of the buffer, optionally past a BOM and an XML declaration, so a syslog-wrapped
# Sysmon-for-Linux line — which also contains "<Event>" but begins with a timestamp —
# cannot match. The namespace is required too: both conditions, never either.
_WIN_EVENT_NS = "schemas.microsoft.com/win/2004/08/events/event"
_RE_XML_EVENT_START = re.compile(r"^﻿?\s*(?:<\?xml[^>]*\?>\s*)?<Events?[\s>]")


def detect_log_type_from_bytes(header: bytes) -> LogType:
    """Detect log type from a raw header buffer (the first 64 KB of a file)."""
    # 1. Binary magic bytes -> EVTX
    if header[:8] == _EVTX_MAGIC:
        return LogType.EVTX

    # 2. Try JSON / NDJSON inspection
    try:
        # `utf-8-sig` drops a leading byte-order mark, which PowerShell and .NET write by
        # default: `strip()` leaves it, and every `^`-anchored test below would then miss.
        text = header.decode("utf-8-sig", errors="ignore")
    except Exception:
        return LogType.UNKNOWN

    lines = text.split("\n", 11)  # at most 11 lines (need 10 for auditd check)
    first_line = lines[0].strip() if lines else ""

    if first_line:
        try:
            data = json_loads(first_line)
        except ValueError:
            data = None

        # Every JSON log shape we support is one *object* per line, so anything else — a
        # bare scalar, an array, a quoted string — is not a JSON log and must fall through
        # to the text heuristics below rather than be probed with `in`. Membership on a
        # non-dict silently means something else:
        #   - `"winlog" in 1718000000` raises TypeError, crashing detection outright for any
        #     file whose first line is a bare number or bool (reachable from the anonymous
        #     /upload and /detect-preview endpoints);
        #   - `"winlog" in "…winlog…"` is a *substring* test, so a plain-text line that
        #     happens to be valid quoted JSON would read as winlogbeat — the worst outcome
        #     of the three, because the job then runs the wrong parser and reports zero
        #     findings, which looks *clean* rather than *not analysed*.
        if isinstance(data, dict):
            if "winlog" in data or "agent" in data:
                return LogType.JSON_WINLOGBEAT
            if "EventID" in data or "Event" in data or "System" in data:
                return LogType.JSON_EVTX
            if "__REALTIME_TIMESTAMP" in data or "__CURSOR" in data or ("MESSAGE" in data and any(k.startswith("_SYSTEMD") or k == "_HOSTNAME" for k in data)):
                return LogType.JOURNALD
            return LogType.UNKNOWN

    # 3. Journald binary-export text format (journalctl -o export)
    if first_line.startswith("__CURSOR="):
        return LogType.JOURNALD

    # 4. Sysmon for Linux — syslog-wrapped XML events (must precede the syslog check)
    sample = lines[:10]
    if any(_SYSMON_LINUX_MARKER in line for line in sample):
        return LogType.SYSMON_LINUX

    # 5. Windows event XML — after the Linux-Sysmon check above, which is also <Event>
    # XML but syslog-wrapped, so it must keep winning.
    if _RE_XML_EVENT_START.match(text) and _WIN_EVENT_NS in text[:8192]:
        return LogType.XML_EVTX

    # 6. Auditd text format
    auditd_markers = ["type=SYSCALL", "type=EXECVE", "type=PROCTITLE", "audit("]
    if any(marker in line for line in sample for marker in auditd_markers):
        return LogType.AUDITD

    # 7. Syslog format (pre-compiled regexes)
    if first_line:
        if _RE_SYSLOG_MONTH.match(first_line):
            return LogType.SYSLOG
        if _RE_SYSLOG_ISO.match(first_line):
            return LogType.SYSLOG
        pri = _RE_SYSLOG_PRI.match(first_line)
        if pri:
            rest = first_line[pri.end() :]
            version = _RE_SYSLOG_VERSION.match(rest)
            if version:
                rest = rest[version.end() :]
            if _RE_SYSLOG_MONTH.match(rest) or _RE_SYSLOG_ISO.match(rest):
                return LogType.SYSLOG

    return LogType.UNKNOWN


def detect_log_type(file_path: Path) -> LogType:
    """Detect log type from a single buffered read of the file header."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(65536)  # 64 KB is plenty for all heuristics
    except OSError:
        return LogType.UNKNOWN
    return detect_log_type_from_bytes(header)


# Human-readable labels for the UI
LOG_TYPE_LABELS = {
    LogType.EVTX: "Windows Event Log (EVTX)",
    LogType.JSON_EVTX: "JSON EVTX",
    LogType.JSON_WINLOGBEAT: "JSON Winlogbeat",
    LogType.XML_EVTX: "Windows Event XML",
    LogType.AUDITD: "Linux Auditd",
    LogType.SYSLOG: "Syslog",
    LogType.JOURNALD: "Journald (JSON export)",
    LogType.SYSMON_LINUX: "Sysmon for Linux",
    LogType.UNKNOWN: "Unknown / Manual selection",
}
