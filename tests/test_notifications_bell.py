"""The nav bell's merge of two streams into one ordered list.

Tier 1. `app/notifications.py` unions rule alerts and job-watch events in Python, and the
only thing it does to the merged list is sort it — so the sort key is the whole of the
logic worth pinning, and it can be pinned without a database.
"""

from __future__ import annotations

from datetime import datetime

from app.notifications import newest_first


def test_newer_sorts_first():
    items = [{"at": datetime(2026, 1, 1)}, {"at": datetime(2026, 6, 1)}]
    items.sort(key=newest_first, reverse=True)
    assert items[0]["at"] == datetime(2026, 6, 1)


def test_a_missing_timestamp_misorders_rather_than_raising():
    """`created_at` is NOT NULL on both tables, so this is belt-and-braces — but the whole
    reason to have the fallback is that one bad row must not take down the bell for every
    stream at once.

    It is `datetime.min` and not `""`: the columns are naive `DateTime`, and comparing a
    str against a datetime raises exactly the way the bare None would have, so this test is
    the one that catches a `""` fallback.
    """
    items = [{"at": datetime(2026, 1, 1)}, {"at": None}, {"at": datetime(2026, 6, 1)}]
    items.sort(key=newest_first, reverse=True)
    assert [i["at"] for i in items] == [datetime(2026, 6, 1), datetime(2026, 1, 1), None]


def test_the_fallback_is_comparable_with_a_real_timestamp():
    """A guard that raises on the value it exists to handle is not a guard."""
    assert newest_first({"at": None}) < newest_first({"at": datetime(2026, 1, 1)})
