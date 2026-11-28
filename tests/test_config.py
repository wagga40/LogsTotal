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


# ── the sync URL always names its PostgreSQL driver ──────────────────────────
#
# SQLAlchemy 2.1 maps a bare `postgresql://` to psycopg 3, which is not installed. Up to 2.0
# it meant psycopg2. Deriving the sync URL by STRIPPING `+asyncpg` therefore worked for years
# and then, on the 2.1 upgrade, would have stopped every Huey worker and every migration from
# connecting — on PostgreSQL only, which no SQLite test sees.


@pytest.mark.parametrize(
    ("database_url", "expected"),
    [
        ("postgresql+asyncpg://u:p@db:5432/lt", "postgresql+psycopg2://u:p@db:5432/lt"),
        ("sqlite+aiosqlite:///./logstotal.db", "sqlite:///./logstotal.db"),
    ],
)
def test_the_derived_sync_url_names_its_driver(monkeypatch, database_url, expected):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.delenv("SYNC_DATABASE_URL", raising=False)
    assert Settings().sync_database_url == expected


@pytest.mark.parametrize(
    ("sync_url", "expected"),
    [
        # A hand-written URL from before the upgrade keeps working.
        ("postgresql://u:p@db/lt", "postgresql+psycopg2://u:p@db/lt"),
        # Anything that names its driver is the operator's choice and is left alone.
        ("postgresql+psycopg2://u:p@db/lt", "postgresql+psycopg2://u:p@db/lt"),
        ("postgresql+psycopg://u:p@db/lt", "postgresql+psycopg://u:p@db/lt"),
        ("sqlite:////data/x.db", "sqlite:////data/x.db"),
    ],
)
def test_an_explicit_bare_sync_url_is_pinned_to_psycopg2(monkeypatch, sync_url, expected):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@db/lt")
    monkeypatch.setenv("SYNC_DATABASE_URL", sync_url)
    assert Settings().sync_database_url == expected


def test_the_sync_url_resolves_to_an_installed_driver(monkeypatch):
    """The point of the pin, asserted against the installed SQLAlchemy rather than a string."""
    from sqlalchemy.engine import make_url

    monkeypatch.setenv("SECRET_KEY", "test-secret-key-not-for-production")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@db/lt")
    monkeypatch.delenv("SYNC_DATABASE_URL", raising=False)
    dialect = make_url(Settings().sync_database_url).get_dialect()
    assert dialect.driver == "psycopg2"
    dialect.import_dbapi()  # raises ImportError if the driver is not installed
