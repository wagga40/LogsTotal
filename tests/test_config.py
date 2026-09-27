"""Settings validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_secret_key_rejects_placeholder(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "change-me-in-production")
    with pytest.raises(ValidationError):
        Settings()


def test_secret_key_accepts_non_placeholder(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    s = Settings()
    assert s.secret_key == "test-secret-key-not-for-production"


def test_cookie_secure_debug_allows_http_session(monkeypatch):
    """DEBUG=true → non-Secure cookies (e.g. httpx / local http://)."""
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("DEBUG", "true")
    s = Settings()
    assert s.cookie_secure is False


def test_cookie_secure_production_https_only_by_default(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("COOKIE_INSECURE", "false")
    s = Settings()
    assert s.cookie_secure is True


def test_cookie_insecure_allows_http_with_debug_false(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("COOKIE_INSECURE", "true")
    s = Settings()
    assert s.cookie_secure is False
