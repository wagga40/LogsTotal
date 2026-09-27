"""Tier-1 tests for the API token + Fernet helpers."""

from __future__ import annotations

from starlette.requests import Request

from app.auth.api_tokens import (
    KNOWN_SCOPES,
    basic_auth_in_front,
    decrypt_secret,
    encrypt_secret,
    generate_token,
    hash_token,
    validate_scopes,
)


def _request(*authorization: str) -> Request:
    return Request({"type": "http", "headers": [(b"authorization", v.encode()) for v in authorization]})


class TestBasicAuthInFront:
    def test_a_basic_header_means_a_proxy_asked_for_one(self):
        assert basic_auth_in_front(_request("Basic dXNlcjpwYXNz"))

    def test_the_scheme_is_case_insensitive(self):
        assert basic_auth_in_front(_request("basic dXNlcjpwYXNz"))

    def test_no_header_is_not_basic_auth(self):
        assert not basic_auth_in_front(_request())

    def test_a_bearer_token_is_not_basic_auth(self):
        assert not basic_auth_in_front(_request("Bearer lgt_abc"))

    def test_every_header_is_read_not_only_the_first(self):
        assert basic_auth_in_front(_request("Bearer lgt_abc", "Basic dXNlcjpwYXNz"))


class TestGenerateToken:
    def test_prefix_is_lgt(self):
        plaintext, _, prefix = generate_token()
        assert plaintext.startswith("lgt_")
        assert prefix == plaintext[:8]

    def test_hash_matches_plaintext(self):
        plaintext, digest, _ = generate_token()
        assert hash_token(plaintext) == digest

    def test_two_tokens_are_distinct(self):
        p1, h1, _ = generate_token()
        p2, h2, _ = generate_token()
        assert p1 != p2
        assert h1 != h2

    def test_hash_is_sha256_hex(self):
        _, digest, _ = generate_token()
        assert len(digest) == 64
        int(digest, 16)  # raises if not hex


class TestValidateScopes:
    def test_filters_unknown_scopes(self):
        result = validate_scopes(["ioc_feed:read", "bogus:write", "taxii:read"])
        assert result == ["ioc_feed:read", "taxii:read"]

    def test_deduplicates(self):
        result = validate_scopes(["ioc_feed:read", "ioc_feed:read"])
        assert result == ["ioc_feed:read"]

    def test_empty_returns_empty(self):
        assert validate_scopes([]) == []

    def test_all_known_scopes_accepted(self):
        result = validate_scopes(list(KNOWN_SCOPES))
        assert set(result) == set(KNOWN_SCOPES)


class TestFernetRoundtrip:
    def test_encrypt_decrypt_roundtrip(self):
        ct = encrypt_secret("my-api-key-123")
        assert decrypt_secret(ct) == "my-api-key-123"

    def test_decrypt_empty_returns_none(self):
        assert decrypt_secret("") is None

    def test_decrypt_garbage_returns_none(self):
        assert decrypt_secret("not-a-valid-fernet-token") is None

    def test_ciphertext_is_not_plaintext(self):
        ct = encrypt_secret("hello")
        assert "hello" not in ct
