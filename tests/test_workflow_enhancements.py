"""Tests for workflow enhancements: extra_args, threads, arch detection, dict tool_path."""

from __future__ import annotations

from unittest.mock import patch

from app.tools.base import _current_arch, resolve_tool_path

# ── Architecture detection ────────────────────────────────────────────────────


class TestCurrentArch:
    def test_returns_string(self):
        arch = _current_arch()
        assert isinstance(arch, str)
        assert "-" in arch

    @patch("app.tools.base.platform")
    def test_normalises_arm64_to_aarch64(self, mock_platform):
        _current_arch.cache_clear()
        mock_platform.machine.return_value = "arm64"
        mock_platform.system.return_value = "Darwin"
        assert _current_arch() == "aarch64-darwin"
        _current_arch.cache_clear()

    @patch("app.tools.base.platform")
    def test_x86_64_linux(self, mock_platform):
        _current_arch.cache_clear()
        mock_platform.machine.return_value = "x86_64"
        mock_platform.system.return_value = "Linux"
        assert _current_arch() == "x86_64-linux"
        _current_arch.cache_clear()

    @patch("app.tools.base.platform")
    def test_aarch64_linux(self, mock_platform):
        _current_arch.cache_clear()
        mock_platform.machine.return_value = "aarch64"
        mock_platform.system.return_value = "Linux"
        assert _current_arch() == "aarch64-linux"
        _current_arch.cache_clear()


# ── resolve_tool_path ─────────────────────────────────────────────────────────


class TestResolveToolPath:
    def test_string_passthrough(self):
        path, skip = resolve_tool_path("tools/hayabusa/hayabusa")
        assert path == "tools/hayabusa/hayabusa"
        assert skip is None

    def test_none_passthrough(self):
        path, skip = resolve_tool_path(None)
        assert path is None
        assert skip is None

    @patch("app.tools.base._current_arch", return_value="x86_64-linux")
    def test_dict_match(self, _):
        raw = {
            "x86_64-linux": "tools/hayabusa/hayabusa-intel-lin",
            "aarch64-linux": "tools/hayabusa/hayabusa-arm-lin",
        }
        path, skip = resolve_tool_path(raw)
        assert path == "tools/hayabusa/hayabusa-intel-lin"
        assert skip is None

    @patch("app.tools.base._current_arch", return_value="x86_64-darwin")
    def test_dict_no_match(self, _):
        raw = {
            "x86_64-linux": "tools/hayabusa/hayabusa-intel-lin",
            "aarch64-linux": "tools/hayabusa/hayabusa-arm-lin",
        }
        path, skip = resolve_tool_path(raw)
        assert path is None
        assert skip is not None
        assert "x86_64-darwin" in skip

    @patch("app.tools.base._current_arch", return_value="aarch64-darwin")
    def test_dict_arm64_alias(self, _):
        """arm64-darwin in YAML should match aarch64-darwin runtime (via alias fallback)."""
        raw = {"arm64-darwin": "tools/hayabusa/hayabusa-mac"}
        path, skip = resolve_tool_path(raw)
        assert path == "tools/hayabusa/hayabusa-mac"
        assert skip is None

    def test_invalid_type(self):
        path, skip = resolve_tool_path(42)
        assert path is None
        assert "Invalid" in skip


# ── extra_args ────────────────────────────────────────────────────────────────


class TestExtraArgs:
    def test_hayabusa_extra_args_in_core_args(self):
        from app.tools.hayabusa import HayabusaAdapter

        adapter = HayabusaAdapter(
            {
                "tool_path": "/fake/hayabusa",
                "rules_path": "/fake/rules",
                "extra_args": ["--EID-filter", "--enable-deprecated-rules"],
            }
        )
        args = adapter._core_args("/log.evtx", "/out.json", "/rules")
        assert "--EID-filter" in args
        assert "--enable-deprecated-rules" in args

    def test_hayabusa_no_extra_args(self):
        from app.tools.hayabusa import HayabusaAdapter

        adapter = HayabusaAdapter(
            {
                "tool_path": "/fake/hayabusa",
                "rules_path": "/fake/rules",
            }
        )
        args = adapter._core_args("/log.evtx", "/out.json", "/rules")
        assert "--EID-filter" not in args

    def test_chainsaw_extra_args_in_local_cmd(self, tmp_path):
        from app.tools.chainsaw import ChainsawAdapter

        binary = tmp_path / "chainsaw"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)

        adapter = ChainsawAdapter(
            {
                "tool_path": str(binary),
                "rules_path": str(tmp_path),
                "extra_args": ["--full", "--skip-errors"],
            }
        )
        cmd, err = adapter._build_local_cmd(binary, tmp_path / "log.evtx", tmp_path / "out.json")
        assert err == ""
        assert "--full" in cmd
        assert "--skip-errors" in cmd

    def test_hayabusa_extra_args_in_docker_args(self):
        """Chainsaw is local-only (see tests/test_chainsaw_local_only.py), so the
        "extra_args reach the container command" property is pinned on Hayabusa,
        whose Docker path is real."""
        from app.tools.hayabusa import HayabusaAdapter

        adapter = HayabusaAdapter(
            {
                "docker_image": "hayabusa:latest",
                "rules_path": "/rules",
                "extra_args": ["--full"],
            }
        )
        args = adapter._docker_tool_args("/case/log.evtx", "/rules", "/out/result.json")
        assert "--full" in args

    def test_zircolite_extra_args_over_legacy(self, tmp_path):
        from app.tools.zircolite import ZircoliteAdapter

        script = tmp_path / "zircolite.py"
        script.write_text("# fake\n")
        rules = tmp_path / "rules.json"
        rules.write_text("{}")

        adapter = ZircoliteAdapter(
            {
                "tool_path": str(script),
                "rules_path": str(rules),
                "extra_args": ["--new-flag"],
                "zircolite_args": ["--old-flag"],
            }
        )
        cmd, err = adapter._build_local_cmd(script, tmp_path / "log.evtx", tmp_path / "out.json")
        assert err == ""
        assert "--new-flag" in cmd
        assert "--old-flag" not in cmd

    def test_zircolite_legacy_fallback(self, tmp_path):
        from app.tools.zircolite import ZircoliteAdapter

        script = tmp_path / "zircolite.py"
        script.write_text("# fake\n")
        rules = tmp_path / "rules.json"
        rules.write_text("{}")

        adapter = ZircoliteAdapter(
            {
                "tool_path": str(script),
                "rules_path": str(rules),
                "zircolite_args": ["--old-flag"],
            }
        )
        cmd, err = adapter._build_local_cmd(script, tmp_path / "log.evtx", tmp_path / "out.json")
        assert err == ""
        assert "--old-flag" in cmd


# ── threads ───────────────────────────────────────────────────────────────────


class TestThreads:
    def test_hayabusa_threads(self):
        from app.tools.hayabusa import HayabusaAdapter

        adapter = HayabusaAdapter(
            {
                "tool_path": "/fake/hayabusa",
                "rules_path": "/fake/rules",
                "threads": 4,
            }
        )
        args = adapter._core_args("/log.evtx", "/out.json", "/rules")
        idx = args.index("--threads")
        assert args[idx + 1] == "4"

    def test_hayabusa_default_threads_when_omitted(self):
        from app.tools.hayabusa import HayabusaAdapter

        adapter = HayabusaAdapter(
            {
                "tool_path": "/fake/hayabusa",
                "rules_path": "/fake/rules",
            }
        )
        args = adapter._core_args("/log.evtx", "/out.json", "/rules")
        idx = args.index("--threads")
        assert args[idx + 1] == "1"

    def test_chainsaw_threads_local(self, tmp_path):
        from app.tools.chainsaw import ChainsawAdapter

        binary = tmp_path / "chainsaw"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)

        adapter = ChainsawAdapter(
            {
                "tool_path": str(binary),
                "rules_path": str(tmp_path),
                "threads": 2,
            }
        )
        cmd, err = adapter._build_local_cmd(binary, tmp_path / "log.evtx", tmp_path / "out.json")
        assert err == ""
        idx = cmd.index("--num-threads")
        assert cmd[idx + 1] == "2"
        assert idx < cmd.index("hunt")

    def test_hayabusa_threads_docker(self):
        """Thread cap reaches the container command (on Hayabusa — Chainsaw is local-only)."""
        from app.tools.hayabusa import HayabusaAdapter

        adapter = HayabusaAdapter(
            {
                "docker_image": "hayabusa:latest",
                "rules_path": "/rules",
                "threads": 3,
            }
        )
        args = adapter._docker_tool_args("/case/log.evtx", "/rules", "/out/result.json")
        idx = args.index("--threads")
        assert args[idx + 1] == "3"

    def test_chainsaw_default_threads_when_omitted(self, tmp_path):
        from app.tools.chainsaw import ChainsawAdapter

        binary = tmp_path / "chainsaw"
        binary.write_text("#!/bin/sh\n")
        binary.chmod(0o755)

        adapter = ChainsawAdapter(
            {
                "tool_path": str(binary),
                "rules_path": str(tmp_path),
            }
        )
        cmd, err = adapter._build_local_cmd(binary, tmp_path / "log.evtx", tmp_path / "out.json")
        assert err == ""
        idx = cmd.index("--num-threads")
        assert cmd[idx + 1] == "1"
        assert idx < cmd.index("hunt")


# ── arch-aware run (integration) ──────────────────────────────────────────────


class TestArchAwareRun:
    @patch("app.tools.base._current_arch", return_value="x86_64-darwin")
    def test_run_skips_on_arch_mismatch(self, _, tmp_path):
        from app.tools.hayabusa import HayabusaAdapter

        adapter = HayabusaAdapter(
            {
                "tool_path": {
                    "x86_64-linux": "tools/hayabusa/hayabusa-intel-lin",
                    "aarch64-linux": "tools/hayabusa/hayabusa-arm-lin",
                },
                "rules_path": "/fake/rules",
            }
        )
        output = adapter.run(tmp_path / "log.evtx", tmp_path / "out", log_type="evtx")
        assert not output.success
        assert output.error.startswith("arch:skip:")

    @patch("app.tools.base._current_arch", return_value="x86_64-linux")
    def test_run_resolves_matching_arch(self, _, tmp_path):
        """With a matching arch, tool_path resolves to a string and _run_local is called."""
        from app.tools.hayabusa import HayabusaAdapter

        adapter = HayabusaAdapter(
            {
                "tool_path": {
                    "x86_64-linux": "/nonexistent/hayabusa",
                },
                "rules_path": "/fake/rules",
            }
        )
        output = adapter.run(tmp_path / "log.evtx", tmp_path / "out", log_type="evtx")
        assert not output.success
        assert "Binary not found" in output.error


# ── workflow_runner parsing ───────────────────────────────────────────────────


class TestWorkflowParsing:
    def test_parse_dict_tool_path(self):
        from app.detection.workflow_runner import parse_workflow_yaml

        yaml_str = """
tasks:
  - tool: hayabusa
    tool_path:
      x86_64-linux: tools/hayabusa/hayabusa-intel-lin
      aarch64-linux: tools/hayabusa/hayabusa-arm-lin
    rules_path: tools/hayabusa/rules/
    timeout: 600
    threads: 2
    extra_args:
      - "--EID-filter"
"""
        tasks = parse_workflow_yaml(yaml_str)
        assert len(tasks) == 1
        task = tasks[0]
        assert isinstance(task["tool_path"], dict)
        assert task["tool_path"]["x86_64-linux"] == "tools/hayabusa/hayabusa-intel-lin"
        assert task["threads"] == 2
        assert task["extra_args"] == ["--EID-filter"]
        assert task["timeout"] == 600

    def test_parse_string_tool_path_still_works(self):
        from app.detection.workflow_runner import parse_workflow_yaml

        yaml_str = """
tasks:
  - tool: chainsaw
    tool_path: tools/chainsaw/chainsaw-mac
    rules_path: tools/chainsaw/sigma/
"""
        tasks = parse_workflow_yaml(yaml_str)
        assert len(tasks) == 1
        assert tasks[0]["tool_path"] == "tools/chainsaw/chainsaw-mac"


# ── HUEY_QUEUE_EXPIRY config ─────────────────────────────────────────────────


class TestHueyQueueExpiry:
    def test_new_env_var(self, monkeypatch):
        from app.config import Settings

        monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
        monkeypatch.setenv("HUEY_QUEUE_EXPIRY", "900")
        monkeypatch.delenv("HUEY_TASK_TIMEOUT", raising=False)
        s = Settings()
        assert s.huey_queue_expiry == 900

    def test_deprecated_alias(self, monkeypatch):
        from app.config import Settings

        monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
        monkeypatch.setenv("HUEY_TASK_TIMEOUT", "600")
        monkeypatch.delenv("HUEY_QUEUE_EXPIRY", raising=False)
        s = Settings()
        assert s.huey_queue_expiry == 600

    def test_default_value(self, monkeypatch):
        from app.config import Settings

        monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
        monkeypatch.delenv("HUEY_TASK_TIMEOUT", raising=False)
        monkeypatch.delenv("HUEY_QUEUE_EXPIRY", raising=False)
        s = Settings()
        assert s.huey_queue_expiry == 1800
