"""Hayabusa's ``options.min_level``.

The adapter's docstring has always advertised this setting; until 2026-08-18 nothing
read it, so a workflow that set it got no flag and no warning — the rules all loaded and
the analyst's "medium and above" run quietly returned informational hits. Tier 1: the
command is built from config, so it can be asserted without running the binary.

The level vocabulary is Hayabusa's own (``hayabusa dfir-timeline --help``: *Minimum level
for rules to load (default: informational)*), not LogsTotal's severity list — they happen
to coincide, and pinning it here is what will catch it if either side moves.
"""

from __future__ import annotations

import pytest

from app.tools.hayabusa import MIN_LEVELS, HayabusaAdapter


def _args(**options):
    config = {"tool_path": "/fake/hayabusa", "rules_path": "/fake/rules"}
    if options:
        config["options"] = options
    return HayabusaAdapter(config)._core_args("/log.evtx", "/out.json", "/rules")


def test_the_documented_levels_are_the_ones_hayabusa_accepts():
    assert sorted(MIN_LEVELS) == ["critical", "high", "informational", "low", "medium"]


def test_no_min_level_emits_no_flag():
    """Hayabusa's own default is `informational`; passing it explicitly would be noise."""
    assert "-m" not in _args()


def test_v4_keeps_jsonl_output_and_thread_limit_separate():
    args = HayabusaAdapter({"threads": 3})._core_args("/log.evtx", "/out.json", "/rules")
    assert args[0] == "dfir-timeline"
    assert args[args.index("--output-type") + 1] == "jsonl"
    assert args[args.index("--threads") + 1] == "3"
    assert "--JSONL-output" not in args
    assert "-t" not in args


@pytest.mark.parametrize("level", sorted(MIN_LEVELS))
def test_each_level_reaches_the_command(level):
    args = _args(min_level=level)
    assert args[args.index("-m") + 1] == level


def test_case_and_whitespace_are_forgiven():
    """It is hand-typed into a YAML file."""
    assert _args(min_level="  Medium ")[_args(min_level="  Medium ").index("-m") + 1] == "medium"


def test_an_unknown_level_is_dropped_rather_than_passed_through():
    """Hayabusa exits non-zero on a bad `-m`, which would fail the whole task for a typo
    in an optional setting. Dropping it runs the workflow with Hayabusa's default."""
    assert "-m" not in _args(min_level="urgent")


@pytest.mark.parametrize("flag", ["-m", "--min-level"])
def test_an_explicit_extra_arg_wins(flag):
    """`extra_args` is the documented escape hatch and `_core_args` appends it verbatim, so
    emitting our own `-m` beside it would pass the flag twice — the dedupe `zircolite.py`
    does for its `-AU`/`-S`/`-j` input-format flags."""
    config = {"tool_path": "/fake/hayabusa", "rules_path": "/fake/rules", "options": {"min_level": "low"}, "extra_args": [flag, "high"]}
    args = HayabusaAdapter(config)._core_args("/log.evtx", "/out.json", "/rules")
    assert args.count(flag) == 1
    assert "low" not in args
