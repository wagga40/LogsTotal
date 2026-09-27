"""Effective-concurrency model — pure, importable without FastAPI/Huey.

Encodes the same peak-CPU model documented in docs/scaling.md and applied by
scripts/recommend_scaling.py:

    peak CPU pressure  ~=  HUEY_WORKERS x (tools-per-job if parallel else 1) x per-tool threads

The parallel term is bounded by the per-job tool executor in
app/workers/tasks.py, which builds ``ThreadPoolExecutor(max_workers=min(
TOOL_MAX_WORKERS, len(work_items)))``. A job can therefore never run more
concurrent tools than the largest workflow has tasks, so the bound here is
``min(tool_max_workers, max_tools_per_workflow)`` rather than ``tool_max_workers``
alone. Keep this formula in ONE place.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Rough memory budget per concurrent job (a tool subprocess parsing a large
# EVTX can be heavy). Shared by scripts/recommend_scaling.py and the RAM
# oversubscription check in app/system_checks.py.
RAM_GB_PER_WORKER = 1.5


@dataclass
class HostConcurrency:
    hostname: str
    huey_workers: int  # concurrent jobs on this host (summed across worker processes)
    cpu_count: int  # 0 when unknown
    threads_per_tool: int
    tools_per_job: int  # parallel bound: min(tool_max_workers, max_tools_per_workflow)
    serial_peak: int  # huey_workers x threads
    parallel_peak: int  # huey_workers x tools_per_job x threads
    parallel_execution: bool
    effective_peak: int  # the applicable peak given parallel_execution
    over_provisioned: bool  # effective_peak > cpu_count (only when cpu_count known)


def _coerce_int(value: object, default: int) -> int:
    """Best-effort int parse (worker meta arrives as Redis strings)."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def compute_host_concurrency(
    *,
    hostname: str,
    huey_workers: int,
    cpu_count: int,
    tool_max_workers: int,
    parallel_execution: bool,
    max_tools_per_workflow: int,
    max_workflow_threads: int,
) -> HostConcurrency:
    """Compute the peak-CPU concurrency figures for one host.

    Guards every term to at least 1 (a host always runs at least one job, one
    tool, one thread); ``cpu_count`` stays 0 when unknown so over-provisioning
    is not claimed without evidence.
    """
    hw = max(1, huey_workers)
    threads = max(1, max_workflow_threads)
    tmw = max(1, tool_max_workers)
    max_tools = max(1, max_tools_per_workflow)
    tools_per_job = min(tmw, max_tools)

    serial_peak = hw * threads
    parallel_peak = hw * tools_per_job * threads
    effective_peak = parallel_peak if parallel_execution else serial_peak
    over = cpu_count > 0 and effective_peak > cpu_count

    return HostConcurrency(
        hostname=hostname,
        huey_workers=hw,
        cpu_count=max(0, cpu_count),
        threads_per_tool=threads,
        tools_per_job=tools_per_job,
        serial_peak=serial_peak,
        parallel_peak=parallel_peak,
        parallel_execution=parallel_execution,
        effective_peak=effective_peak,
        over_provisioned=over,
    )


def compute_concurrency(
    worker_meta: list[dict],
    *,
    tool_max_workers: int,
    parallel_execution: bool,
    max_tools_per_workflow: int,
    max_workflow_threads: int,
) -> list[HostConcurrency]:
    """Aggregate per-process worker meta by hostname, then compute per host.

    ``worker_meta`` is a list of dicts with ``hostname``, ``huey_workers`` and
    ``cpu_count`` (values may be Redis strings). Multiple worker processes on
    the same host contribute additive job slots (matching ``host_threads`` in
    ``routers/admin.py::_fetch_worker_data``); ``cpu_count`` is a host property,
    so the max across a host's processes is used. Empty input yields ``[]``.
    """
    hosts: dict[str, dict] = {}
    for w in worker_meta:
        hn = str(w.get("hostname") or "unknown")
        entry = hosts.setdefault(hn, {"huey_workers": 0, "cpu_count": 0})
        entry["huey_workers"] += max(0, _coerce_int(w.get("huey_workers"), 0))
        entry["cpu_count"] = max(entry["cpu_count"], _coerce_int(w.get("cpu_count"), 0))

    return [
        compute_host_concurrency(
            hostname=hn,
            huey_workers=entry["huey_workers"],
            cpu_count=entry["cpu_count"],
            tool_max_workers=tool_max_workers,
            parallel_execution=parallel_execution,
            max_tools_per_workflow=max_tools_per_workflow,
            max_workflow_threads=max_workflow_threads,
        )
        for hn, entry in sorted(hosts.items())
    ]


def recommend_host_settings(cores: int, ram_gb: float | None, max_tool_count: int | None = None) -> dict:
    """Recommended settings + reasoning for a host with `cores` CPUs and `ram_gb` RAM.

    The sizing inverse of the peak formula above (given a core budget, pick the
    knobs). Single source of truth for `./logstotal recommend-scaling`
    (scripts/recommend_scaling.py) and the admin concurrency card's
    current-vs-recommended readout. `max_tool_count` is the largest workflow's
    tool count; None → fallback of 2, the TOOL_MAX_WORKERS default.
    """
    threads_per_tool = 2 if cores >= 4 else 1

    # CPU-bound ceiling: workers x threads ≈ cores.
    workers_by_cpu = max(1, cores // threads_per_tool)

    # RAM ceiling: don't run more concurrent jobs than memory comfortably allows.
    if ram_gb:
        workers_by_ram = max(1, int(ram_gb // RAM_GB_PER_WORKER))
        workers = min(workers_by_cpu, workers_by_ram)
        ram_bound = workers_by_ram < workers_by_cpu
    else:
        workers = workers_by_cpu
        ram_bound = False

    # TOOL_MAX_WORKERS only bites when parallel_execution is ON: a single job then runs up
    # to this many of its tools at once. Size it for the largest workflow (fallback 2 when
    # none detected), but cap at the CPU ceiling so that job's parallel peak
    # (tool_max_workers x threads_per_tool) stays within the core budget — keeping the
    # documented peak formula from exploding on the single-job latency scenario.
    tool_count = max_tool_count if (max_tool_count and max_tool_count > 0) else 2
    tool_max_workers = max(1, min(tool_count, workers_by_cpu))

    db_pool_size = max(5, workers)
    peak = workers * threads_per_tool

    # parallel_execution trades throughput for per-job latency: it speeds up a single
    # job by running its tools at once, but oversubscribes CPU under steady load. Worth
    # *considering* only on larger hosts where jobs typically arrive one at a time.
    suggest_parallel = cores >= 8

    return {
        "cores": cores,
        "ram_gb": ram_gb,
        "huey_workers": workers,
        "threads_per_tool": threads_per_tool,
        "tool_max_workers": tool_max_workers,
        "max_tool_count": tool_count,
        "db_pool_size": db_pool_size,
        "peak_cpu": peak,
        "ram_bound": ram_bound,
        "suggest_parallel": suggest_parallel,
    }


def detect_ram_gb() -> float | None:
    """Total RAM of THIS host in GB, or None when undetectable (never raises)."""
    try:
        if platform.system() == "Linux":
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / (1024**2)  # kB → GB
        elif platform.system() == "Darwin":
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            return int(out.stdout.strip()) / (1024**3)
    except Exception:
        return None
    return None
