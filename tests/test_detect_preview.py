"""Tests for POST /detect-preview — pre-upload log type preview.

The upload form posts the first 64 KB of a dropped file here so the detected
type is visible (and the workflow list filterable) before submission. Uses the
committed samples/ files, whose expected types are pinned by test_sample_logs.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.models import LogType, SiteSettings

_SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"

# sample path (relative to samples/) → expected (log_type value, label)
_CASES = {
    "linux/auditd_sample.log": ("auditd", "Linux Auditd"),
    "linux/syslog_intrusion.log": ("syslog", "Syslog"),
    "linux/sysmon_linux_sample.log": ("sysmon_linux", "Sysmon for Linux"),
    "windows/bitsadmin.evtx": ("evtx", "Windows Event Log (EVTX)"),
    "windows/sysmon_process_creation.json": ("json_evtx", "JSON EVTX"),
    "windows/sysmon_winlogbeat.json": ("json_winlogbeat", "JSON Winlogbeat"),
    "windows/security_events.xml": ("xml_evtx", "Windows Event XML"),
}


@pytest.mark.parametrize("rel_path,expected", sorted(_CASES.items()))
async def test_detect_preview_samples(test_client, rel_path, expected):
    header = (_SAMPLES_DIR / rel_path).read_bytes()[:65536]
    resp = await test_client.post("/detect-preview", files={"file": ("sample", header, "application/octet-stream")})
    assert resp.status_code == 200
    assert resp.json() == {"log_type": expected[0], "label": expected[1]}


async def test_detect_preview_reads_at_most_64k(test_client):
    """Content past the 64 KB cap must not influence detection."""
    body = b"x" * 70000 + b"ElfFile\x00"
    resp = await test_client.post("/detect-preview", files={"file": ("big", body, "application/octet-stream")})
    assert resp.status_code == 200
    assert resp.json()["log_type"] == "unknown"


async def test_detect_preview_empty_file(test_client):
    resp = await test_client.post("/detect-preview", files={"file": ("empty", b"", "application/octet-stream")})
    assert resp.status_code == 200
    assert resp.json()["log_type"] == LogType.UNKNOWN.value


async def test_detect_preview_demo_mode(test_client, async_db):
    async_db.add(SiteSettings(id=1, demo_mode=True))
    await async_db.commit()
    resp = await test_client.post("/detect-preview", files={"file": ("f", b"data", "application/octet-stream")})
    assert resp.status_code == 403
