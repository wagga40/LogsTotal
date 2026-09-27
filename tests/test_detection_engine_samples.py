"""Real-engine regression checks for the workflows affected by tool upgrades.

Vendored native binaries run without network access. Set
RUN_DOCKER_DETECTION_TESTS=1 to include all Zircolite input formats with the
workflow's digest-pinned image (requires a Docker daemon and the image).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

from app.tools.base import resolve_tool_path
from app.tools.chainsaw import ChainsawAdapter
from app.tools.hayabusa import HayabusaAdapter
from app.tools.zircolite import ZircoliteAdapter

ROOT = Path(__file__).resolve().parent.parent


def task_config(workflow, tool):
    data = yaml.safe_load((ROOT / "workflows" / workflow).read_text())
    return next(task for task in data["tasks"] if task["tool"] == tool)


@pytest.mark.parametrize("tool,adapter_class", [("chainsaw", ChainsawAdapter), ("hayabusa", HayabusaAdapter)])
def test_windows_bitsadmin_detection_survives_upgrade(tool, adapter_class, tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    config = task_config("windows_full.yml", tool)
    binary, reason = resolve_tool_path(config["tool_path"])
    if reason:
        pytest.skip(reason)
    assert binary and Path(binary).is_file(), "vendored binary is missing"
    result = adapter_class(config).run(ROOT / "samples/windows/bitsadmin.evtx", tmp_path, log_type="evtx")
    assert result.success, f"{result.error}\n{result.stderr}"
    bits = [finding for finding in result.findings if "File Download Via Bitsadmin" in finding.rule_name]
    assert len(bits) == 1, [finding.rule_name for finding in result.findings]
    assert bits[0].count >= 1
    assert bits[0].severity == "medium"
    assert bits[0].rule_id
    assert bits[0].details
    assert bits[0].rule_content


JOURNALD_RULES = {
    "83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871": 8,
    "30bcce26-51c5-49f2-99c8-7b59e3af36c7": 1,
    "403ed92c-b7ec-4edd-9947-5b535ee12d46": 2,
    "b45e3d6f-42c6-47d8-a478-df6bd6cf534c": 27,
    "6104e693-a7d6-4891-86cb-49a258523559": 2,
    "42df45e7-e6e9-43b5-8f26-bec5b39cc239": 1,
    "e7bd1cfa-b446-4c88-8afb-403bcd79e3fa": 4,
}


@pytest.mark.skipif(os.environ.get("RUN_DOCKER_DETECTION_TESTS") != "1", reason="opt-in Docker detection checks")
@pytest.mark.parametrize(
    "workflow,sample,log_type,expected",
    [
        ("windows_full.yml", "windows/bitsadmin.evtx", "evtx", {"d059842b-6b9d-4ed1-b5c3-5b89143c6ede": 1}),
        ("windows_full.yml", "windows/sysmon_process_creation.json", "json_evtx", {"fb843269-508c-4b76-8b8d-88679db22ce7": 1}),
        ("windows_full.yml", "windows/sysmon_winlogbeat.json", "json_winlogbeat", {}),
        ("windows_xml.yml", "windows/security_events.xml", "xml_evtx", {}),
        ("linux_auditd.yml", "linux/auditd_sample.log", "auditd", {}),
        ("linux_sysmon.yml", "linux/sysmon_linux_sample.log", "sysmon_linux", {}),
        ("linux_journald.yml", "linux/journald_sample.json", "journald", JOURNALD_RULES),
    ],
)
def test_zircolite_sample_coverage(workflow, sample, log_type, expected, tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    adapter = ZircoliteAdapter(task_config(workflow, "zircolite"))
    result = adapter.run(ROOT / "samples" / sample, tmp_path, log_type=log_type)
    assert result.success, f"{result.error}\n{result.stderr}"
    observed = {finding.rule_id: finding.count for finding in result.findings}
    # A zero-finding fixture still has to be parsed completely. Success alone
    # would let an incompatible input flag silently turn an unread file clean.
    expected_events = {
        "windows/bitsadmin.evtx": 1,
        "windows/sysmon_process_creation.json": 4,
        "windows/sysmon_winlogbeat.json": 2,
        "windows/security_events.xml": 2,
        "linux/auditd_sample.log": 35,
        "linux/sysmon_linux_sample.log": 5,
        "linux/journald_sample.json": 181,
    }
    parsed = re.search(r"Total events processed: ([\d,]+)", result.stdout)
    assert parsed, result.stdout
    assert int(parsed[1].replace(",", "")) == expected_events[sample]
    for rule_id, count in expected.items():
        assert observed.get(rule_id, 0) >= count, f"lost baseline detection {rule_id}: {observed}"
    assert all(f.rule_name and f.details and f.count > 0 for f in result.findings)
