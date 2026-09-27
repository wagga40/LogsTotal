"""Chainsaw is a local-binary tool; its Docker path must fail loudly, not silently.

Upstream ships release binaries rather than a Docker image, and a Chainsaw hunt needs
three separate host paths inside the container (`--sigma` rules, `-r` Chainsaw rules and
a `--mapping` file) while the shared Docker runner binds exactly one rules path. The
adapter therefore defines no `_docker_tool_args` override.

These tests pin the *consequence* of that choice — a clean, actionable error — rather
than the mere absence of a method, so a future "fix" that emits an argv Chainsaw would
reject (`--mapping` is required whenever `--sigma` is used) still fails here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.tools.chainsaw import ChainsawAdapter


def test_docker_config_returns_a_clean_error(tmp_path: Path):
    """Configuring chainsaw with docker_image yields an error, never a broken command."""
    log = tmp_path / "sample.evtx"
    log.write_bytes(b"ElfFile\x00")
    rules = tmp_path / "rules"
    rules.mkdir()

    adapter = ChainsawAdapter({"docker_image": "chainsaw:latest", "rules_path": str(rules)})
    result = adapter.run(log, tmp_path / "out", log_type="evtx")

    assert result.success is False
    assert "Docker tool arguments" in (result.error or "")


def test_no_docker_tool_args_override():
    """The base class hook is inherited, not overridden.

    Guards the deliberate omission: re-adding a partial override would build a command
    line Chainsaw rejects outright, which is strictly worse than the inherited error.
    """
    assert "_docker_tool_args" not in vars(ChainsawAdapter)


def test_local_command_keeps_the_required_mapping_and_rules_flags(tmp_path: Path):
    """`--mapping` is mandatory for `--sigma`; `-r` adds Chainsaw's own rules."""
    binary = tmp_path / "chainsaw"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    rules = tmp_path / "sigma"
    rules.mkdir()

    adapter = ChainsawAdapter({"tool_path": str(binary), "rules_path": str(rules)})
    cmd, err = adapter._build_local_cmd(binary, tmp_path / "in.evtx", tmp_path / "out.json")

    assert err == ""
    assert cmd is not None
    for flag in ("--sigma", "-r", "--mapping", "--jsonl", "--output"):
        assert flag in cmd
    assert cmd[cmd.index("--mapping") + 1] == ChainsawAdapter._DEFAULT_MAPPING


@pytest.mark.parametrize("adapter_module", ["chainsaw", "chopchopgo"])
def test_local_only_adapters_agree(adapter_module: str):
    """Chainsaw and ChopChopGo share the same local-only shape."""
    import importlib

    mod = importlib.import_module(f"app.tools.{adapter_module}")
    cls = next(obj for name, obj in vars(mod).items() if isinstance(obj, type) and name.endswith("Adapter") and obj.__module__ == mod.__name__)
    assert "_docker_tool_args" not in vars(cls)
