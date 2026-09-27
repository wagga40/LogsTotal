"""Thread-cap defaulting for detection tool adapters.

LogsTotal always passes an explicit thread cap to CPU-bound tools so they don't
silently grab every logical core. When a workflow omits ``threads:``, the cap
defaults to ``DEFAULT_TOOL_THREADS`` (1); an explicit value is used verbatim.
"""

from __future__ import annotations

from app.tools.base import DEFAULT_TOOL_THREADS
from app.tools.chainsaw import ChainsawAdapter
from app.tools.hayabusa import HayabusaAdapter


def test_default_tool_threads_is_one():
    assert DEFAULT_TOOL_THREADS == 1


def test_omitted_threads_defaults_to_one():
    adapter = HayabusaAdapter({"tool_path": "/fake/hayabusa", "rules_path": "/fake/rules"})
    assert adapter._threads == DEFAULT_TOOL_THREADS == 1


def test_explicit_threads_used_verbatim():
    adapter = HayabusaAdapter({"tool_path": "/fake/hayabusa", "rules_path": "/fake/rules", "threads": 3})
    assert adapter._threads == 3


def test_string_threads_coerced_to_int():
    adapter = HayabusaAdapter({"tool_path": "/fake/hayabusa", "rules_path": "/fake/rules", "threads": "4"})
    assert adapter._threads == 4


def test_hayabusa_command_includes_thread_flag_when_omitted():
    adapter = HayabusaAdapter({"tool_path": "/fake/hayabusa", "rules_path": "/fake/rules"})
    args = adapter._core_args("/log.evtx", "/out.json", "/rules")
    idx = args.index("--threads")
    assert args[idx + 1] == "1"


def test_chainsaw_local_command_includes_thread_flag_when_omitted(tmp_path):
    binary = tmp_path / "chainsaw"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)

    adapter = ChainsawAdapter({"tool_path": str(binary), "rules_path": str(tmp_path)})
    cmd, err = adapter._build_local_cmd(binary, tmp_path / "log.evtx", tmp_path / "out.json")
    assert err == ""
    idx = cmd.index("--num-threads")
    assert cmd[idx + 1] == "1"
    assert idx < cmd.index("hunt")
