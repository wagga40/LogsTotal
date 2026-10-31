"""The Explore histogram's time axis. Pure.

A bucket width from a fixed ladder (1 s … 365 d), chosen so the range fits in at most
`max_bins(width)` bars, and an origin aligned to a multiple of that width, so the same
range always produces the same bars and a zoom lands on round boundaries.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

_DAY = 86_400
LADDER = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, _DAY, 2 * _DAY, 7 * _DAY, 14 * _DAY, 30 * _DAY, 90 * _DAY, 365 * _DAY)
MIN_BINS = 12
MAX_BINS = 400


def max_bins(width_px: int) -> int:
    """One bar per four pixels, never fewer than MIN_BINS or more than MAX_BINS."""
    return max(MIN_BINS, min(MAX_BINS, int(width_px) // 4))


def choose_bucket(span_seconds: float, bins: int) -> int:
    """The narrowest ladder width that fits *span_seconds* in *bins* bars."""
    for width in LADDER:
        if span_seconds / width <= bins:
            return width
    return LADDER[-1] * math.ceil(span_seconds / (LADDER[-1] * bins))


@dataclass(frozen=True)
class Axis:
    origin: datetime  # the first bar's start (naive UTC, as the store holds times)
    bucket_seconds: int
    bins: int

    @property
    def end(self) -> datetime:
        """Exclusive: the last bar ends here."""
        return self.origin + timedelta(seconds=self.bucket_seconds * self.bins)

    @property
    def origin_ms(self) -> int:
        return int(self.origin.replace(tzinfo=UTC).timestamp() * 1000)


def axis(start: datetime, end: datetime, width_px: int = 800) -> Axis:
    """Bars covering [start, end] — *end* inclusive, so the newest event has a bar."""
    if end < start:
        start, end = end, start
    first = start.replace(tzinfo=UTC).timestamp()
    last = end.replace(tzinfo=UTC).timestamp()
    # Two bars of slack: aligning the origin down can add a partial bar at each end.
    width = choose_bucket(max(1.0, last - first), max_bins(width_px) - 2)
    origin = math.floor(first / width) * width
    bins = max(1, math.floor((last - origin) / width) + 1)
    return Axis(datetime.fromtimestamp(origin, UTC).replace(tzinfo=None), width, bins)
