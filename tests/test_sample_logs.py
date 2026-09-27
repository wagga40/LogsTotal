"""Detector coverage over the committed real-world sample logs in samples/.

Pins that each shipped sample classifies as its documented LogType — guards the
detector against regressions using authentic data, and keeps the samples/README
tables honest. See samples/linux/README.md and samples/windows/README.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.detection.detector import detect_log_type, detect_log_type_from_bytes
from app.models import LogType

_SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"

# sample path (relative to samples/) → expected detected LogType
_MANIFEST: dict[str, LogType] = {
    "linux/syslog_intrusion.log": LogType.SYSLOG,
    "linux/syslog_benign.log": LogType.SYSLOG,
    "linux/auditd_sample.log": LogType.AUDITD,
    "linux/sysmon_linux_sample.log": LogType.SYSMON_LINUX,
    # `journalctl -o json` NDJSON export. The only sample for the one supported log type
    # that had none, which is why `linux_journald.yml` could not be smoke-tested with what
    # ships. Captured from a throwaway Ubuntu 26.04 VM — see samples/linux/README.md.
    "linux/journald_sample.json": LogType.JOURNALD,
    "windows/sysmon_process_creation.json": LogType.JSON_EVTX,
    "windows/sysmon_winlogbeat.json": LogType.JSON_WINLOGBEAT,
    "windows/bitsadmin.evtx": LogType.EVTX,
    # Rootless wevtutil-style export. Zircolite reads it fully with --evtxtract-input,
    # which the adapter selects by sniffing the root element (see ZircoliteAdapter).
    "windows/security_events.xml": LogType.XML_EVTX,
}


@pytest.mark.parametrize("rel_path,expected", sorted((k, v) for k, v in _MANIFEST.items()))
def test_sample_detects_as_expected(rel_path: str, expected: LogType):
    path = _SAMPLES_DIR / rel_path
    assert path.exists(), f"sample missing: {path}"
    assert detect_log_type(path) == expected


@pytest.mark.parametrize("rel_path,expected", sorted((k, v) for k, v in _MANIFEST.items()))
def test_sample_bytes_detection_parity(rel_path: str, expected: LogType):
    """detect_log_type_from_bytes over the first 64 KB matches the file-based result."""
    path = _SAMPLES_DIR / rel_path
    header = path.read_bytes()[:65536]
    assert detect_log_type_from_bytes(header) == expected


def test_manifest_covers_every_sample():
    """Every log file under samples/ must appear in the manifest (no orphans)."""
    on_disk = {str(p.relative_to(_SAMPLES_DIR)) for p in _SAMPLES_DIR.rglob("*") if p.is_file() and p.suffix in {".log", ".json", ".xml", ".evtx"}}
    assert on_disk == set(_MANIFEST), f"drift between samples/ and manifest: {on_disk ^ set(_MANIFEST)}"
