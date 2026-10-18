"""Regressions found while preparing the next release."""

from __future__ import annotations

import pytest
import regex

from app.tools.chopchopgo import ChopChopGoAdapter


def test_regex_timeout_cannot_borrow_the_next_events_allowance(monkeypatch):
    import app.threat_detection as td

    class TimedOut:
        def search(self, value, *, timeout):
            raise TimeoutError

    budget = td._RegexBudget()
    budget.remaining = 0.001
    clock = iter([100.0, 100.05, 100.06, 100.06001])
    monkeypatch.setattr(td.time, "monotonic", lambda: next(clock))
    budget.search(TimedOut(), "pathological input")
    event = "procdump.exe -ma lsass.exe"
    budget.credit([{"CommandLine": event}])
    assert budget.search(regex.compile(r"procdump.*lsass"), event)
    assert budget.timeouts == 1


@pytest.mark.parametrize("suffix", ["yml", "yaml"])
def test_new_run_uses_refreshed_rule_metadata(tmp_path, suffix):
    rule = tmp_path / f"rule.{suffix}"
    rule.write_text("id: old\ntitle: Old\nlevel: high\n")
    config = {"tool_path": "/unused", "rules_path": str(tmp_path)}
    first = ChopChopGoAdapter(config)
    assert first._rule_severity("old")[0] == "high"
    rule.write_text("id: new\ntitle: New\nlevel: critical\n")
    second = ChopChopGoAdapter(config)
    assert second._rule_severity("new")[0] == "critical"
    assert second._lookup_rule_yaml("old") == ""
