"""Tests for app.similarity — rule signatures and TLSH hashing."""

from __future__ import annotations

import pytest

from app.similarity.correlator import make_rule_signature
from app.similarity.hasher import compute_tlsh

# ── make_rule_signature ──────────────────────────────────────────────────────


class TestMakeRuleSignature:
    def test_with_rule_id(self):
        sig = make_rule_signature("abc-123", "Some Rule", "high")
        assert sig == "abc-123:high"

    def test_without_rule_id_slug_fallback(self):
        sig = make_rule_signature(None, "Suspicious PowerShell", "medium")
        assert sig == "suspicious-powershell:medium"

    def test_empty_rule_id_uses_slug(self):
        sig = make_rule_signature("", "My Rule Name", "low")
        assert sig == "my-rule-name:low"

    def test_whitespace_rule_id_uses_slug(self):
        sig = make_rule_signature("   ", "My Rule", "low")
        assert sig == "my-rule:low"

    def test_special_chars_in_name(self):
        sig = make_rule_signature(None, "Rule: (test) [v2]!", "critical")
        # special chars become hyphens, stripped from edges
        assert ":critical" in sig
        assert " " not in sig

    def test_empty_name_fallback(self):
        sig = make_rule_signature(None, "", "high")
        assert sig == "unknown:high"


# ── compute_tlsh ─────────────────────────────────────────────────────────────


class TestComputeTlsh:
    def test_nonexistent_file(self, tmp_path):
        result = compute_tlsh(tmp_path / "nope.bin")
        assert result is None

    def test_small_file_returns_none(self, tmp_file):
        """TLSH needs minimum ~50 bytes of data with sufficient entropy."""
        p = tmp_file(b"tiny", "small.bin")
        result = compute_tlsh(p)
        assert result is None

    @pytest.mark.slow
    def test_valid_file_returns_hex(self, tmp_file):
        """A file with enough entropy should produce a TLSH digest."""
        import os

        data = os.urandom(4096)
        p = tmp_file(data, "random.bin")
        result = compute_tlsh(p)
        assert result is not None
        assert isinstance(result, str)
        assert len(result) >= 70
