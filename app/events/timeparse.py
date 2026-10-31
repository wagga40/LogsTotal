"""Event times to UTC, or None. Never a guess.

Accepts what the parsed formats carry: ISO 8601 with `Z` or an offset, a space instead of the
`T`, 7-digit (Windows FILETIME) fractions, and epoch numbers in seconds, milliseconds or
microseconds (journald's `__REALTIME_TIMESTAMP`). A naive time is read as UTC. Anything else is
None: an undated event sorts last rather than being placed at a time it never had.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

_FRACTION = re.compile(r"(\.\d{6})\d+")
_EPOCH_RANGES = ((1e9, 1e11, 1), (1e12, 1e14, 1e3), (1e15, 1e17, 1e6))


def parse_time(value: object) -> datetime | None:
    """A naive UTC datetime (what a DuckDB TIMESTAMP holds), or None."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return _from_epoch(float(value))
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return _from_epoch(float(text))
    text = text.replace("Z", "+00:00").replace("z", "+00:00")
    if len(text) > 10 and text[10] == " ":
        text = text[:10] + "T" + text[11:]
    text = _FRACTION.sub(r"\1", text)
    # "+02:00" or "+0200" or " +02:00" (Hayabusa) all normalise to fromisoformat's form.
    text = re.sub(r"\s*([+-]\d{2}):?(\d{2})$", r"\1:\2", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _from_epoch(number: float) -> datetime | None:
    for low, high, scale in _EPOCH_RANGES:
        if low <= number < high:
            try:
                return datetime.fromtimestamp(number / scale, UTC).replace(tzinfo=None)
            except (OverflowError, OSError, ValueError):
                return None
    return None


def iso(value: datetime | None) -> str | None:
    """The spool's text form, which DuckDB reads straight into a TIMESTAMP."""
    return value.isoformat(sep=" ") if value is not None else None
