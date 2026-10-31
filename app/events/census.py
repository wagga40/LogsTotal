"""What a store's columns are, learned from every value in one pass. Pure.

Typed from all values, never the first (Zircolite's measured lesson): a column is BIGINT only
when every value was an int that fits 64 bits, DOUBLE only when every value was a number and
at least one a float, and VARCHAR otherwise. The census also keeps each column's non-null
count (the Fields panel's coverage, with no scan), its longest text, the column set of each
(channel, event id) family (the event drawer reads only those), the time range, and whether
the events arrived in time order.
"""

from __future__ import annotations

from datetime import datetime

INT, FLOAT, STR = 1, 2, 4
I64_MIN, I64_MAX = -(2**63), 2**63 - 1


class Census:
    def __init__(self, max_columns: int):
        self.max_columns = max_columns
        self.ids: dict[tuple, int] = {}  # lower-cased path -> column id
        self.masks: list[int] = []
        self.counts: list[int] = []
        self.max_len: list[int] = []
        self.families: dict[tuple, set[int]] = {}
        self.family_counts: dict[tuple, int] = {}
        self.overflow_paths = 0
        self.events = 0
        self.undated = 0
        self.time_min: datetime | None = None
        self.time_max: datetime | None = None
        self.out_of_order = 0
        self._last_time: datetime | None = None

    def column(self, path: tuple) -> int | None:
        """The path's column id, or None past the column cap (its value goes to `_lt_extra`)."""
        cid = self.ids.get(path)
        if cid is None:
            if len(self.ids) >= self.max_columns:
                return None
            cid = self.ids[path] = len(self.ids)
            self.masks.append(0)
            self.counts.append(0)
            self.max_len.append(0)
        return cid

    def observe(self, cid: int, value: object) -> None:
        if isinstance(value, int):
            self.masks[cid] |= INT if I64_MIN <= value <= I64_MAX else STR
        elif isinstance(value, float):
            self.masks[cid] |= FLOAT
        else:
            self.masks[cid] |= STR
            self.max_len[cid] = max(self.max_len[cid], len(value))
        self.counts[cid] += 1

    def event(self, family: tuple, columns: list[int], when: datetime | None) -> None:
        self.events += 1
        self.family_counts[family] = self.family_counts.get(family, 0) + 1
        self.families.setdefault(family, set()).update(columns)
        if when is None:
            self.undated += 1
            return
        if self.time_min is None or when < self.time_min:
            self.time_min = when
        if self.time_max is None or when > self.time_max:
            self.time_max = when
        if self._last_time is not None and when < self._last_time:
            self.out_of_order += 1
        self._last_time = when

    def duck_type(self, cid: int) -> str:
        mask = self.masks[cid]
        if mask == INT:
            return "BIGINT"
        if mask and not mask & STR:
            return "DOUBLE"
        return "VARCHAR"
