"""Tests for app.tools.base — timeout normalization and timeout-as-failure behavior."""

from __future__ import annotations

import sys
import threading
import time
from unittest.mock import patch

from app.tools.base import CANCELLED_ERROR, ToolAdapter
from app.tools.chainsaw import ChainsawAdapter


class _FakeProc:
    """Minimal Popen stand-in for tests that only exercise the happy path."""

    returncode = 0
    stdout = None
    stderr = None

    def communicate(self, timeout=None):
        return "ok", ""


class TestNormalizeTimeout:
    """ToolAdapter._normalize_timeout clamps to [1, 86400] and handles invalid values."""

    def test_valid_int_unchanged(self):
        assert ToolAdapter._normalize_timeout(300) == 300
        assert ToolAdapter._normalize_timeout(1) == 1
        assert ToolAdapter._normalize_timeout(86400) == 86400

    def test_clamp_low(self):
        assert ToolAdapter._normalize_timeout(0) == 1
        assert ToolAdapter._normalize_timeout(-10) == 1

    def test_clamp_high(self):
        assert ToolAdapter._normalize_timeout(100000) == 86400

    def test_string_coerced(self):
        assert ToolAdapter._normalize_timeout("600") == 600

    def test_invalid_returns_300(self):
        assert ToolAdapter._normalize_timeout("not_a_number") == 300
        assert ToolAdapter._normalize_timeout(None) == 300


class TestExecuteAndParseTimeoutFailure:
    """When _exec returns rc=-1 (timeout), _execute_and_parse returns failure even if output file exists."""

    def test_timed_out_returns_failure(self, tmp_path):
        """Timed-out run (rc=-1) must return success=False regardless of output file."""
        output_file = tmp_path / "out.json"
        output_file.write_text("[]")
        cfg = {"tool_path": "/nonexistent/for/build_cmd", "timeout": 5}
        adapter = ChainsawAdapter(cfg)
        with patch.object(ToolAdapter, "_exec", return_value=(-1, "", "Command timed out after 5s")):
            result = adapter._execute_and_parse(["sleep", "99"], output_file)
        assert result.success is False
        assert "timed out" in result.error.lower() or "5" in result.error


class TestExecSecurityInvariant:
    """Tool execution must always avoid shell interpretation and must isolate
    the child in its own process group (timeout kills the whole tree)."""

    def test_exec_sets_shell_false(self):
        with patch("subprocess.Popen", return_value=_FakeProc()) as popen_mock:
            rc, out, err = ToolAdapter._exec(["echo", "ok"], timeout=1)
        assert rc == 0
        assert out == "ok"
        assert err == ""
        assert popen_mock.call_args.kwargs["shell"] is False
        assert popen_mock.call_args.kwargs["start_new_session"] is True


class TestExecProcessGroupKill:
    """The per-tool timeout must hold even when the tool spawns grandchildren."""

    def test_exec_kills_grandchild_pipe_holder(self):
        """A grandchild inheriting the stdout pipe must not block the drain.

        subprocess.run(timeout=...) kills only the direct child and then blocks
        ~15s in communicate(), because the grandchild keeps its inherited copy
        of the pipe open.
        """
        script = "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15)']); time.sleep(15)"
        t0 = time.monotonic()
        rc, _out, err = ToolAdapter._exec([sys.executable, "-c", script], timeout=1)
        elapsed = time.monotonic() - t0
        assert rc == -1
        assert "timed out after 1s" in err
        assert elapsed < 6, f"_exec blocked {elapsed:.1f}s past its 1s timeout"


class TestExecCancelEvent:
    """A set cancel event aborts the subprocess (or skips spawning it)."""

    def test_cancel_event_terminates_early(self):
        ev = threading.Event()
        threading.Timer(0.3, ev.set).start()
        t0 = time.monotonic()
        rc, _out, err = ToolAdapter._exec(["sleep", "30"], timeout=30, cancel_event=ev)
        assert rc == -1
        assert err == CANCELLED_ERROR
        assert time.monotonic() - t0 < 5

    def test_preset_cancel_event_skips_spawn(self):
        ev = threading.Event()
        ev.set()
        with patch("subprocess.Popen") as popen_mock:
            rc, out, err = ToolAdapter._exec(["sleep", "30"], timeout=5, cancel_event=ev)
        assert (rc, out, err) == (-1, "", CANCELLED_ERROR)
        popen_mock.assert_not_called()
