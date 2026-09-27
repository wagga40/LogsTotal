"""Tier-1 tests for the `time_ago` Jinja filter (app/templates_config.py).

Renders relative timestamps ("2h ago") for entity/case/watchlist views.
Naive datetimes are treated as UTC (the DB stores naive UTC).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.templates_config import _time_ago, templates


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def test_none_returns_empty_string():
    assert _time_ago(None) == ""


def test_just_now_under_a_minute():
    assert _time_ago(_utcnow() - timedelta(seconds=30)) == "just now"


def test_minutes():
    assert _time_ago(_utcnow() - timedelta(minutes=5)) == "5m ago"


def test_hours():
    assert _time_ago(_utcnow() - timedelta(hours=3)) == "3h ago"


def test_days():
    assert _time_ago(_utcnow() - timedelta(days=6)) == "6d ago"


def test_beyond_30_days_shows_absolute_date():
    dt = _utcnow() - timedelta(days=45)
    assert _time_ago(dt) == dt.strftime("%Y-%m-%d")


def test_future_clamps_to_just_now():
    assert _time_ago(_utcnow() + timedelta(hours=2)) == "just now"


def test_aware_datetime_supported():
    assert _time_ago(datetime.now(UTC) - timedelta(minutes=10)) == "10m ago"


def test_registered_as_jinja_filter():
    assert templates.env.filters["time_ago"] is _time_ago
