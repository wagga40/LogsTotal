"""The one test that runs a real detection engine against a real log.

Everything else in this suite stops short of the product's actual promise.
`test_integration_worker.py` swaps in a `FakeAdapter`, so the worker pipeline is exercised
with no tool; `test_sample_logs.py` pins log-*type* detection but never runs a rule;
`test_tool_normalize.py` feeds hand-written fixtures to the normalizers. A ruleset that
loaded nothing, a binary that no longer executes, an adapter flag the tool stopped
accepting — none of it would fail a single test.

ChopChopGo is the engine that makes this cheap: it is a vendored binary needing no Docker
and no network, and `samples/linux/syslog_intrusion.log` already documents its exact
expected result in `samples/linux/README.md`.

**What is asserted, and why not "findings > 0".** A broken ruleset that loads three rules
instead of six hundred still produces findings on this file. So the assertions are the
named rules from that README — the specific detections a working install must produce.
Rule *count* is asserted as a floor rather than an equality: adding rules upstream is
routine and must not fail the build, while losing one of these is exactly the regression
worth catching.

Skipped where the engine cannot run — ChopChopGo ships Linux binaries only, so this is a
no-op on the macOS development machine and runs for real on CI's `ubuntu-latest`.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from app.tools.chopchopgo import ChopChopGoAdapter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = PROJECT_ROOT / "samples" / "linux" / "syslog_intrusion.log"
RULES = PROJECT_ROOT / "tools" / "chopchopgo" / "rules" / "builtin"

#: Documented in `samples/linux/README.md`, which is the contract this test enforces.
#: Substrings, because upstream renames a rule's suffix more often than its subject.
EXPECTED_RULES = (
    "Shellshock Expression",
    "Suspicious OpenSSH Daemon Error",
    "Suspicious Reverse Shell Command Line",
    "Suspicious Activity in Shell Commands",
    "Symlink Etc Passwd",
    "Code Injection by ld.so Preload",
    "Modifying Crontab",
    "Remote File Copy",
    "Linux Command History Tampering",
    "Commands to Clear or Remove the Syslog",
)

#: The README documents 13 detections across 10 rules. Asserted as floors: new upstream
#: rules matching this file are a fine outcome, losing coverage is not.
MIN_RULES = 10
MIN_DETECTIONS = 13


def _binary() -> Path | None:
    """The vendored binary for this host, or None if there is not one."""
    machine = platform.machine().lower()
    machine = "aarch64" if machine == "arm64" else machine
    system = platform.system().lower()
    candidates = {
        "x86_64-linux": "chopchopgo-intel-lin",
        "aarch64-linux": "chopchopgo-arm-lin",
    }
    name = candidates.get(f"{machine}-{system}")
    if not name:
        return None
    path = PROJECT_ROOT / "tools" / "chopchopgo" / name
    return path if path.exists() else None


@pytest.fixture(scope="module")
def findings(tmp_path_factory):
    binary = _binary()
    if binary is None:
        pytest.skip(f"no vendored ChopChopGo binary for {platform.machine()}-{platform.system()} (Linux only)")
    if not SAMPLE.exists():
        pytest.skip(f"sample missing: {SAMPLE}")

    adapter = ChopChopGoAdapter(
        {
            "tool_path": str(binary),
            "rules_path": str(RULES),
            "timeout": 300,
            "target": "syslog",
            "max_finding_details": 10,
        }
    )
    out = adapter.run(SAMPLE, tmp_path_factory.mktemp("cc"), log_type="syslog")
    assert out.success, f"ChopChopGo failed to run: {out.error}\nstderr: {out.stderr[:2000]}"
    return out.findings


def test_the_engine_produces_the_documented_rule_count(findings):
    assert len(findings) >= MIN_RULES, (
        f"{len(findings)} rules fired, expected at least {MIN_RULES} (samples/linux/README.md). "
        f"A ruleset that fails to load still produces *some* findings on this file, so a drop here usually means the rules directory, not the sample."
    )


def test_the_engine_produces_the_documented_detection_count(findings):
    total = sum(f.count for f in findings)
    assert total >= MIN_DETECTIONS, f"{total} detections, expected at least {MIN_DETECTIONS} (samples/linux/README.md)"


@pytest.mark.parametrize("expected", EXPECTED_RULES)
def test_each_documented_rule_fires(findings, expected: str):
    """Named rules, not a count — this is what makes the test meaningful.

    Parametrised so a failure names the detection that was lost rather than reporting a
    number that is one too small.
    """
    names = [f.rule_name for f in findings]
    assert any(expected.lower() in name.lower() for name in names), f"{expected!r} did not fire. Rules that did: {sorted(names)}"


def test_every_finding_is_normalized(findings):
    """The adapter's own contract, checked against real tool output rather than a fixture.

    ChopChopGo writes matched events to stdout with no severity; the adapter recovers it by
    looking the rule up in the Sigma YAML (`_lookup_rule_yaml`). A regression there yields
    findings that all read `informational`, which is not obviously broken on screen.
    """
    valid = {"critical", "high", "medium", "low", "informational"}
    for f in findings:
        assert f.rule_name, "a finding has no rule name"
        assert f.severity in valid, f"{f.rule_name}: bad severity {f.severity!r}"
        assert f.count >= 1, f"{f.rule_name}: non-positive count {f.count}"
    assert any(f.severity in {"critical", "high", "medium"} for f in findings), (
        "every finding came back low/informational — severity recovery from the Sigma YAML is broken, which is invisible on the job page because the findings still render."
    )


def test_the_binary_actually_executes():
    """An arch or glibc mismatch is a class of failure `task doctor` cannot see.

    Doctor stats the tool binaries but never runs one, so a build for the wrong
    architecture — or one linked against a newer glibc than the host — passes preflight and
    fails on the first job instead.
    """
    binary = _binary()
    if binary is None:
        pytest.skip("no vendored ChopChopGo binary for this platform")
    if not shutil.which("file"):
        pytest.skip("`file` not available")
    proc = subprocess.run([str(binary), "-h"], capture_output=True, timeout=60, check=False)
    combined = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    assert combined.strip(), f"the vendored binary produced no output at all (exit {proc.returncode}) — likely an arch or glibc mismatch"
