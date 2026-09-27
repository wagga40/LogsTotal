"""Tests for app.workers.utils — ANSI stripping and log combining."""

from __future__ import annotations

from app.workers.utils import _combine_logs, _strip_ansi

# ── _strip_ansi ──────────────────────────────────────────────────────────────


class TestStripAnsi:
    def test_no_escapes(self):
        assert _strip_ansi("hello world") == "hello world"

    def test_color_codes(self):
        assert _strip_ansi("\x1b[31mERROR\x1b[0m") == "ERROR"

    def test_cursor_movement(self):
        assert _strip_ansi("\x1b[2Jcleared") == "cleared"

    def test_empty_string(self):
        assert _strip_ansi("") == ""

    def test_multiple_escapes(self):
        text = "\x1b[1m\x1b[32mGREEN\x1b[0m normal \x1b[33mYELLOW\x1b[0m"
        assert _strip_ansi(text) == "GREEN normal YELLOW"


# ── _combine_logs ────────────────────────────────────────────────────────────


class TestCombineLogs:
    def test_both_present(self):
        result = _combine_logs("out", "err")
        assert "=== stdout ===" in result
        assert "=== stderr ===" in result
        assert "out" in result
        assert "err" in result

    def test_stdout_only(self):
        result = _combine_logs("out", "")
        assert "=== stdout ===" in result
        assert "stderr" not in result

    def test_stderr_only(self):
        result = _combine_logs("", "err")
        assert "=== stderr ===" in result
        assert "stdout" not in result

    def test_both_empty(self):
        assert _combine_logs("", "") == ""

    def test_whitespace_only_treated_as_empty(self):
        assert _combine_logs("   ", "   ") == ""

    def test_truncation(self):
        result = _combine_logs("A" * 200, "", max_bytes=50)
        assert "...[truncated]..." in result

    def test_ansi_stripped(self):
        result = _combine_logs("\x1b[31mred\x1b[0m", "")
        assert "\x1b" not in result
        assert "red" in result
