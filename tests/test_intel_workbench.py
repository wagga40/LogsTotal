"""Tier-1 pure-function tests for the entity workbench helpers (no DB)."""

from __future__ import annotations

from app.intel.entities import _entity_appears_in_blob, _ip_pattern
from app.intel.queries import normalize_tag as _normalize_tag


class TestNormalizeTag:
    def test_lowercases_and_strips(self):
        assert _normalize_tag("  Apt28  ") == "apt28"

    def test_clamps_to_50_chars(self):
        long = "x" * 200
        assert _normalize_tag(long) == "x" * 50

    def test_empty_string_returns_empty(self):
        assert _normalize_tag("") == ""

    def test_none_returns_empty(self):
        assert _normalize_tag(None) == ""

    def test_preserves_internal_dashes(self):
        assert _normalize_tag("false-positive") == "false-positive"


class TestIpPatternBoundaries:
    def test_matches_exact_ip_in_json(self):
        blob = '{"IpAddress": "10.0.0.1", "User": "admin"}'
        assert _ip_pattern("10.0.0.1").search(blob)

    def test_does_not_match_inside_longer_ip(self):
        # "10.0.0.1" must NOT match inside "10.0.0.10"
        blob = '{"IpAddress": "10.0.0.10"}'
        assert _ip_pattern("10.0.0.1").search(blob) is None

    def test_does_not_match_inside_three_digit_octet(self):
        blob = '{"IpAddress": "10.0.0.100"}'
        assert _ip_pattern("10.0.0.1").search(blob) is None

    def test_matches_at_end_of_string(self):
        blob = "trailing 10.0.0.1"
        assert _ip_pattern("10.0.0.1").search(blob)

    def test_does_not_match_when_preceded_by_dot(self):
        blob = "192.168.10.0.0.1"  # contrived; the trailing 10.0.0.1 is preceded by .
        assert _ip_pattern("10.0.0.1").search(blob) is None


class TestEntityAppearsInBlob:
    def test_user_case_insensitive(self):
        blob = '{"User": "Administrator"}'
        assert _entity_appears_in_blob("administrator", "user", blob, blob.lower())

    def test_user_with_uppercase_value_finds_lowercase_blob(self):
        blob = '{"user": "alice"}'
        assert _entity_appears_in_blob("ALICE", "user", blob, blob.lower())

    def test_hash_matches_uppercase_in_blob(self):
        sha = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
        blob = f'{{"hash": "{sha}"}}'
        assert _entity_appears_in_blob(sha, "hash", blob, blob.lower())

    def test_hash_matches_lowercase_in_blob(self):
        sha = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
        blob_lower = f'{{"hash": "{sha.lower()}"}}'
        assert _entity_appears_in_blob(sha, "hash", blob_lower, blob_lower.lower())

    def test_executable_substring_in_cmdline(self):
        # cmd.exe is extracted as an entity from a longer CommandLine string
        blob = '{"CommandLine": "C:\\\\Windows\\\\System32\\\\cmd.exe /c whoami"}'
        assert _entity_appears_in_blob("cmd.exe", "executable", blob, blob.lower())

    def test_ip_does_not_substring_match(self):
        blob = '{"IpAddress": "10.0.0.10"}'
        # Should NOT find "10.0.0.1" inside "10.0.0.10"
        assert not _entity_appears_in_blob("10.0.0.1", "ip_address", blob, blob.lower())

    def test_ip_exact_match(self):
        blob = '{"IpAddress": "10.0.0.1"}'
        assert _entity_appears_in_blob("10.0.0.1", "ip_address", blob, blob.lower())

    def test_empty_value_returns_false(self):
        blob = '{"anything": "here"}'
        assert not _entity_appears_in_blob("", "user", blob, blob.lower())

    def test_value_absent_returns_false(self):
        blob = '{"unrelated": "data"}'
        assert not _entity_appears_in_blob("notpresent", "user", blob, blob.lower())
