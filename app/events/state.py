"""Explore's URL state: what the address bar carries, clamped on the way in. Pure.

`q det cols sort dir page ev from to` — a copied link reproduces the view, and a reload
restores it (the results route answers with `HX-Replace-Url`). Every value is parsed and
bounded here, so a route never sees a raw parameter; a column the store does not have is
dropped rather than refused, because links outlive the stores they were made on.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from urllib.parse import urlencode

from app.events.query import MAX_QUERY_CHARS
from app.events.timeparse import parse_time

PER_PAGE = 100
PAGE_MAX = 1_000_000
MAX_COLUMNS = 30
FIXED_LABELS = {"_lt_time": "Time (UTC)", "_lt_host": "Host", "_lt_channel": "Channel", "_lt_eid": "Event ID", "_lt_rid": "Record ID", "_lt_seq": "Sequence", "_lt_line": "Line"}
DEFAULT_COLUMNS = ("_lt_time", "_lt_host", "_lt_channel", "_lt_eid")
#: After the fixed columns, the first two of these the store has, as the summary columns.
SUMMARY_CANDIDATES = ("CommandLine", "Image", "TargetUserName", "ServiceName", "QueryName", "proctitle", "exe", "MESSAGE", "message")


@dataclass(frozen=True)
class ExploreState:
    q: str = ""
    det: bool = False
    cols: tuple[str, ...] = ()
    sort: str | None = None
    desc: bool = False
    page: int = 1
    ev: int | None = None
    start: datetime | None = None
    end: datetime | None = None

    @classmethod
    def from_params(cls, params: Mapping[str, str], columns: set[str]) -> ExploreState:
        """Parse *params* against the store's *columns* (fixed ones included)."""
        cols = tuple(dict.fromkeys(c for c in (params.get("cols") or "").split(",") if c in columns))[:MAX_COLUMNS]
        sort = params.get("sort") or None
        return cls(
            q=(params.get("q") or "")[:MAX_QUERY_CHARS],
            det=(params.get("det") or "") in ("1", "true", "on", "yes"),
            cols=cols,
            sort=sort if sort in columns else None,
            desc=params.get("dir") == "desc",
            page=_int(params.get("page"), 1, 1, PAGE_MAX),
            ev=_int(params.get("ev"), None, 0, 1 << 62),
            start=parse_time(params.get("from")),
            end=parse_time(params.get("to")),
        )

    def columns_or(self, defaults: tuple[str, ...]) -> tuple[str, ...]:
        return self.cols or defaults

    @property
    def offset(self) -> int:
        return (self.page - 1) * PER_PAGE

    def control_terms(self, *, linked: bool, with_range: bool = True) -> str:
        """The terms the controls add beside the typed query: detections only, the brush.

        "Detections only" needs the overlay; without it the box is disabled and ignored.
        The histogram leaves the range out, because the range is its axis.
        """
        terms = ["det:yes"] if self.det and linked else []
        if with_range and self.start is not None:
            terms.append(f"after:{self.start.isoformat()}")
        if with_range and self.end is not None:
            terms.append(f"before:{self.end.isoformat()}")
        return " ".join(terms)

    def pairs(self, **override) -> list[tuple[str, str]]:
        """The non-default parameters, in a stable order, with *override* applied."""
        state = replace(self, **override) if override else self
        out: list[tuple[str, str]] = []
        if state.q:
            out.append(("q", state.q))
        if state.det:
            out.append(("det", "1"))
        if state.cols:
            out.append(("cols", ",".join(state.cols)))
        if state.sort:
            out.append(("sort", state.sort))
            if state.desc:
                out.append(("dir", "desc"))
        if state.page > 1:
            out.append(("page", str(state.page)))
        if state.ev is not None:
            out.append(("ev", str(state.ev)))
        if state.start is not None:
            out.append(("from", state.start.isoformat()))
        if state.end is not None:
            out.append(("to", state.end.isoformat()))
        return out

    def qs(self, **override) -> str:
        return urlencode(self.pairs(**override))


def default_columns(manifest: dict) -> tuple[str, ...]:
    names = {c["name"] for c in manifest.get("columns") or []}
    summary = [c for c in SUMMARY_CANDIDATES if c in names][:2]
    return (*DEFAULT_COLUMNS, *summary)


def column_label(name: str) -> str:
    return FIXED_LABELS.get(name, name)


def _int(raw: str | None, default, lo: int, hi: int):
    text = (raw or "").strip()
    if not text.isdigit() or not text.isascii():
        return default
    return max(lo, min(hi, int(text)))
