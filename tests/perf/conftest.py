"""Performance budgets: skipped unless LOGSTOTAL_PERF=1 (`./logstotal test:perf` sets it).

They need a 2M-event synthetic store (built once into tests/perf/.store/) and measure
wall-clock time, so they would only slow the ordinary suite and flake under its parallelism.
"""

from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config, items):
    if os.environ.get("LOGSTOTAL_PERF") == "1":
        return
    skip = pytest.mark.skip(reason="performance budgets run with ./logstotal test:perf")
    for item in items:
        if "tests/perf/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip)
