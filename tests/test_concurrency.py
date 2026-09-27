"""Tests for the pure effective-concurrency model (app/concurrency.py)."""

from __future__ import annotations

from app.concurrency import compute_concurrency, compute_host_concurrency


def _host(**kw):
    base = {
        "hostname": "h1",
        "huey_workers": 2,
        "cpu_count": 8,
        "tool_max_workers": 2,
        "parallel_execution": False,
        "max_tools_per_workflow": 3,
        "max_workflow_threads": 2,
    }
    base.update(kw)
    return compute_host_concurrency(**base)


def test_serial_peak_is_workers_times_threads():
    r = _host(huey_workers=4, max_workflow_threads=2, parallel_execution=False)
    assert r.serial_peak == 8
    assert r.effective_peak == 8  # parallel off -> serial applies


def test_parallel_peak_multiplies_by_tools_per_job():
    r = _host(huey_workers=2, tool_max_workers=3, max_tools_per_workflow=3, max_workflow_threads=2, parallel_execution=True)
    # 2 workers x min(3,3) tools x 2 threads
    assert r.parallel_peak == 12
    assert r.effective_peak == 12


def test_tools_per_job_bounded_by_tool_max_workers():
    # workflow has 5 tools but TOOL_MAX_WORKERS caps the per-job pool at 2
    r = _host(tool_max_workers=2, max_tools_per_workflow=5, parallel_execution=True)
    assert r.tools_per_job == 2


def test_tools_per_job_bounded_by_workflow_tool_count():
    # TOOL_MAX_WORKERS is 5 but the largest workflow only has 3 tools
    r = _host(tool_max_workers=5, max_tools_per_workflow=3, parallel_execution=True)
    assert r.tools_per_job == 3


def test_over_provisioned_flag():
    over = _host(huey_workers=2, tool_max_workers=3, max_tools_per_workflow=3, max_workflow_threads=2, cpu_count=8, parallel_execution=True)
    assert over.effective_peak == 12 and over.over_provisioned is True
    fine = _host(huey_workers=2, max_workflow_threads=2, cpu_count=8, parallel_execution=False)
    assert fine.effective_peak == 4 and fine.over_provisioned is False


def test_unknown_cpu_count_never_over_provisioned():
    r = _host(cpu_count=0, huey_workers=8, max_workflow_threads=4, parallel_execution=False)
    assert r.over_provisioned is False


def test_terms_guarded_to_at_least_one():
    r = _host(huey_workers=0, max_workflow_threads=0, tool_max_workers=0, max_tools_per_workflow=0, parallel_execution=True)
    assert r.huey_workers == 1
    assert r.threads_per_tool == 1
    assert r.tools_per_job == 1
    assert r.serial_peak == 1
    assert r.parallel_peak == 1


def test_compute_concurrency_empty_input():
    assert compute_concurrency([], tool_max_workers=2, parallel_execution=False, max_tools_per_workflow=3, max_workflow_threads=2) == []


def test_compute_concurrency_aggregates_processes_per_host():
    # two worker processes on the same host each run HUEY_WORKERS=2 -> 4 job slots
    meta = [
        {"hostname": "hostA", "huey_workers": "2", "cpu_count": "8"},
        {"hostname": "hostA", "huey_workers": "2", "cpu_count": "8"},
        {"hostname": "hostB", "huey_workers": "1", "cpu_count": "4"},
    ]
    rows = compute_concurrency(meta, tool_max_workers=2, parallel_execution=False, max_tools_per_workflow=3, max_workflow_threads=2)
    assert [r.hostname for r in rows] == ["hostA", "hostB"]  # sorted
    a, b = rows
    assert a.huey_workers == 4 and a.cpu_count == 8
    assert a.serial_peak == 8  # 4 x 2 threads
    assert b.huey_workers == 1 and b.serial_peak == 2


def test_compute_concurrency_coerces_string_meta():
    meta = [{"hostname": "h", "huey_workers": "not-a-number", "cpu_count": "also-bad"}]
    rows = compute_concurrency(meta, tool_max_workers=2, parallel_execution=False, max_tools_per_workflow=3, max_workflow_threads=2)
    assert rows[0].huey_workers == 1  # bad -> 0 aggregate -> guarded to 1
    assert rows[0].cpu_count == 0
    assert rows[0].over_provisioned is False
