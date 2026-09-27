"""Zoom-adaptive alert markers — build, slice and merge a job's event index.

Pure module, like ``app/similarity/`` and ``app/intel/relationships.py``: stdlib plus
``app.json_utils``. It must never import FastAPI, Huey or SQLAlchemy — the *worker* builds
the index during the analytics pass and the *web tier* slices it per request, and neither
may drag the other's stack in.

This is the *lower* of the two timeline modules and owns the shared timestamp primitives:
``event_timeline`` imports the two regexes and ``normalize_severity`` from here, never the
reverse. The dependency runs one way on purpose — ``event_timeline`` needs
``normalize_severity`` for its per-tool severity fallback, so the opposite arrangement
would cycle.

The index is a columnar snapshot of every matched alert, collapsed by
``(rule, computer, time-window)``. It is stored gzipped on ``AnalysisJob.event_markers``
rather than as a file under ``uploads/job_{id}/`` because that directory is not a reliable
artifact store: ``event_timeline`` reads it through the filesystem directly, bypassing
``app/storage.py``, so on an S3 deployment the tree is already gone by the time analytics
runs — and it is deleted outright by ``JOB_OUTPUT_RETENTION_DAYS`` cleanup. A DB blob
survives both, exactly like ``analytics_json``.

Timestamps are absolute UTC epoch **seconds**, sorted, so a range query is a ``bisect``
rather than a scan. The HTTP layer speaks epoch *milliseconds*; conversion happens there.
"""

from __future__ import annotations

import gzip
import re
from bisect import bisect_left, bisect_right
from datetime import UTC, datetime

from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads

# auditd ``audit(<epoch>.<frac>:<serial>)`` marker — modeled on app/intel/lineage.py's
# ``_RE_AUDIT_EPOCH`` (kept untouched there). Shared with ``event_timeline``, which imports
# both of these rather than keeping a second copy that could drift.
_RE_AUDIT_EPOCH = re.compile(r"audit\((\d+)\.(\d+):\d+\)")
_RE_ISO_HOUR_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}")

# Payload schema version. Bump when the columnar shape changes; readers reject anything else
# and report the index as missing, which degrades to "rebuild via backfill_analytics".
INDEX_VERSION = 1

# Coarsening ladder, in seconds. ``build_index`` stores at the finest step whose collapsed
# marker count fits MAX_MARKERS; ``slice_index`` walks up it when a single range query
# exceeds its item cap.
RESOLUTION_LADDER = (1, 5, 15, 60, 300, 900, 3600, 86400)

# Markers persisted per job. Measured on a real job (82,658 events / 66 rules / 586-hour span):
# the 1-second collapse is 37,605 markers, so real jobs keep full second fidelity and the
# ladder only engages on pathological input — which is the point of having it.
MAX_MARKERS = 60_000

# Live accumulator entries before it coarsens one ladder step. ``MAX_PARSE_EVENTS`` is
# applied *per file*, so a four-tool workflow can push ~1M events through here; this bounds
# the working set regardless of input.
MARKER_ACCUM_CAP = 250_000

# Items returned by one range query.
MAX_TIMELINE_ITEMS = 2000

UNKNOWN_SEVERITY = "unknown"

# Tools spell severity differently (Hayabusa "crit"/"med"/"info", Sigma "informational").
# The canonical source is ``Finding.severity``, already one of app.constants.SEVERITY_ORDER;
# this only defends the fallback path where a raw event's own level is all we have.
_SEVERITY_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "med": "medium",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
    "information": "informational",
}


def normalize_severity(value: object) -> str:
    """Map a tool-specific severity spelling onto the canonical set, or ``"unknown"``."""
    if not isinstance(value, str):
        return UNKNOWN_SEVERITY
    return _SEVERITY_ALIASES.get(value.strip().lower(), UNKNOWN_SEVERITY)


def event_epoch_seconds(ts: object) -> int | None:
    """Parse a heterogeneous event timestamp into **UTC** epoch seconds, or ``None``.

    Deliberately stricter than its sibling ``normalize_event_time``, which preserves an
    ISO offset verbatim and lets the caller slice an hour key out of the string. That is
    fine for an hourly histogram but wrong for a zoomable axis: a job mixing ``+09:00`` and
    ``Z`` events would place them hours away from their true alignment. Here every input
    lands on one absolute instant.

    Accepts the same three shapes ``normalize_event_time`` does — an auditd
    ``audit(<epoch>.<frac>:<serial>)`` marker anywhere in the string, an ISO timestamp with
    either separator, and nothing else. A naive timestamp is assumed to be UTC.
    """
    if not isinstance(ts, str):
        return None

    m = _RE_AUDIT_EPOCH.search(ts)
    if m:
        return int(m.group(1))

    s = ts.strip()
    if len(s) < 13 or not _RE_ISO_HOUR_PREFIX.match(s):
        return None

    if s[10] == " ":
        s = s[:10] + "T" + s[11:]

    # Hayabusa emits "2021-12-01 09:23:45.123 +09:00" — a space before the offset, which
    # fromisoformat rejects. Zircolite and Chainsaw emit a trailing "Z".
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    else:
        head, sep, tail = s.rpartition(" ")
        if sep and tail and tail[0] in "+-":
            s = head + tail

    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # Fall back to the fixed-width prefix — enough for any trailing garbage a tool
        # appends after the seconds field.
        try:
            dt = datetime.fromisoformat(s[:19])
        except ValueError:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


def _next_resolution(resolution: int) -> int | None:
    """The next coarser step on the ladder, or ``None`` at the top."""
    for step in RESOLUTION_LADDER:
        if step > resolution:
            return step
    return None


def _comparable(key: tuple) -> tuple:
    """A total-order-safe view of a marker key, for sorting only.

    Marker keys carry ``None`` wherever a field could not be resolved (no matching Finding
    means no rule_id and no finding_id), and Python refuses to order ``None`` against ``str``.
    """
    return tuple("" if v is None else str(v) for v in key)


def _recollapse(counts: dict[tuple, int], resolution: int) -> dict[tuple, int]:
    """Re-bucket ``{(key, bucket): n}`` onto a coarser resolution, summing collisions."""
    rebuilt: dict[tuple, int] = {}
    for (key, bucket), n in counts.items():
        k = (key, bucket - bucket % resolution)
        rebuilt[k] = rebuilt.get(k, 0) + n
    return rebuilt


class MarkerAccumulator:
    """Collapses alerts into ``(key, time-window)`` markers with a bounded footprint.

    One instance per parse thread (``parse_single_output_file`` takes it as an optional
    sink); fold them together with :meth:`merge` afterwards. ``event_timeline`` imports this
    class and calls only :meth:`add` and :meth:`merge`; nothing here imports
    ``event_timeline``, so the dependency stays one-directional.
    """

    __slots__ = ("_cap", "_counts", "_saturated", "resolution", "total", "truncated", "undated")

    def __init__(self, resolution: int = 1, cap: int = MARKER_ACCUM_CAP) -> None:
        self.resolution = resolution
        self.total = 0
        self.undated = 0
        self.truncated = False
        self._cap = cap
        self._counts: dict[tuple, int] = {}
        self._saturated = False

    def __len__(self) -> int:
        return len(self._counts)

    def add(self, key: tuple, ts: object) -> None:
        """Record one alert. ``key`` identifies the marker lane, ``ts`` is its raw timestamp."""
        self.total += 1
        epoch = event_epoch_seconds(ts)
        if epoch is None:
            self.undated += 1
            return

        k = (key, epoch - epoch % self.resolution)
        current = self._counts.get(k)
        if current is not None:
            self._counts[k] = current + 1
            return

        if self._saturated:
            # Ladder exhausted and still over cap: distinct keys dominate, so coarsening
            # cannot help. Drop rather than grow without bound, and say so.
            self.truncated = True
            return

        self._counts[k] = 1
        if len(self._counts) > self._cap:
            self._enforce_cap()

    def merge(self, other: MarkerAccumulator) -> None:
        """Fold another accumulator into this one, aligning to the coarser resolution."""
        self.total += other.total
        self.undated += other.undated
        self.truncated = self.truncated or other.truncated

        mine, theirs = self._counts, other._counts
        if other.resolution > self.resolution:
            self.resolution = other.resolution
            mine = _recollapse(mine, self.resolution)
        elif other.resolution < self.resolution:
            theirs = _recollapse(theirs, self.resolution)

        for k, n in theirs.items():
            mine[k] = mine.get(k, 0) + n
        self._counts = mine
        self._enforce_cap()

    def _enforce_cap(self) -> None:
        while len(self._counts) > self._cap:
            nxt = _next_resolution(self.resolution)
            if nxt is None:
                self._saturated = True
                return
            self.resolution = nxt
            self._counts = _recollapse(self._counts, nxt)

    def collapsed(self, resolution: int) -> dict[tuple, int]:
        """The accumulated counts re-bucketed onto *resolution* (must be >= current)."""
        if resolution <= self.resolution:
            return dict(self._counts)
        return _recollapse(self._counts, resolution)


def pack_index(payload: dict | None) -> bytes | None:
    """Serialise an index for ``AnalysisJob.event_markers``: orjson, then gzip.

    Returns ``None`` for an empty or marker-less index so the column stays NULL and the
    endpoint reports ``index_missing`` rather than handing the client an empty axis.
    """
    if not payload or not payload.get("ts"):
        return None
    return gzip.compress(json_dumps(payload).encode(), compresslevel=6)


def unpack_index(blob: bytes | None) -> dict | None:
    """Inverse of :func:`pack_index`. Returns ``None`` on absent or unreadable data."""
    if not blob:
        return None
    try:
        return json_loads(gzip.decompress(blob))
    except Exception:
        # A corrupt or truncated blob must degrade to "no index" — this is a derived
        # artifact, and backfill_analytics rebuilds it.
        return None


def build_index(acc: MarkerAccumulator, *, cap: int = MAX_MARKERS) -> dict:
    """Turn an accumulator into the storable v1 payload.

    Picks the finest ladder step at or above the accumulator's own resolution whose marker
    count fits *cap*. Timestamps are absolute (not delta-encoded) on purpose: the blob is
    decoded whole per request anyway, and absolute values let ``bisect`` work directly on
    the ``ts`` column.
    """
    resolution = acc.resolution
    counts = acc.collapsed(resolution)
    while len(counts) > cap:
        nxt = _next_resolution(resolution)
        if nxt is None:
            break
        resolution = nxt
        counts = _recollapse(counts, resolution)

    computers: dict[str, int] = {}
    tools: dict[str, int] = {}
    keys: dict[tuple, int] = {}

    ts_col: list[int] = []
    k_col: list[int] = []
    n_col: list[int] = []

    # Sorting by (bucket, key) keeps ``ts`` non-decreasing, which is what bisect requires.
    # The key tuple goes through _comparable first: rule_id and finding_id are None whenever
    # a rule has no matching Finding, and a real job mixes both — comparing the raw tuples
    # then dies with "'<' not supported between instances of 'str' and 'NoneType'".
    for (key, bucket), n in sorted(counts.items(), key=lambda kv: (kv[0][1], _comparable(kv[0][0]))):
        key_idx = keys.get(key)
        if key_idx is None:
            key_idx = len(keys)
            keys[key] = key_idx
            computers.setdefault(key[4] or "", len(computers))
            tools.setdefault(key[5] or "", len(tools))
        ts_col.append(bucket)
        k_col.append(key_idx)
        n_col.append(n)

    # 7th element (finding_id) is appended, never inserted: readers index defensively so an
    # index written before it existed still slices correctly instead of reporting itself
    # missing until a backfill runs.
    key_rows = [[k[0], k[1], k[2] or UNKNOWN_SEVERITY, k[3], computers[k[4] or ""], tools[k[5] or ""], (k[6] if len(k) > 6 else None)] for k in sorted(keys, key=keys.__getitem__)]

    return {
        "v": INDEX_VERSION,
        "res": resolution,
        "ts": ts_col,
        "k": k_col,
        "n": n_col,
        "keys": key_rows,
        "computers": sorted(computers, key=computers.__getitem__),
        "tools": sorted(tools, key=tools.__getitem__),
        "total": acc.total,
        "undated": acc.undated,
        "source_truncated": acc.truncated,
    }


def _empty_slice(resolution: int = 1) -> dict:
    return {
        "items": [],
        "discarded": 0,
        "total": 0,
        "resolution": resolution,
        "base_resolution": resolution,
        "truncated": False,
        "extent": None,
        "groupings": [],
    }


def index_groupings(payload: dict) -> list[str]:
    """Every tactic present in the whole index, not just in a slice.

    The renderer draws one lane per grouping, and lane identity has to be a property of the
    *job*, not of the current viewport: deriving it from the returned items would make lanes
    — and therefore the canvas height — change on every zoom, resizing the panel under the
    cursor. It is also more correct, since a slice can be capped and
    drop a rare tactic entirely.
    """
    seen: dict[str, None] = {}
    for row in payload.get("keys") or []:
        if len(row) > 3:
            seen.setdefault(str(row[3]), None)
    return list(seen)


def active_finding_ids(payload: dict | None, frm: int | None = None, to: int | None = None) -> set[int]:
    """Every ``Finding.id`` with at least one marker inside ``[frm, to]`` (epoch seconds).

    Deliberately **not** routed through :func:`slice_index`. That function is a *display*
    path: it caps at ``MAX_TIMELINE_ITEMS`` and walks the resolution ladder coarser until
    the window fits, dropping whole marker keys — and therefore whole finding ids — on the
    way. A lossy path cannot be a set extractor. Under-reporting here renders a genuinely
    active entity as dimmed, which is a false negative presented as fact; so this bisects
    the sorted ``ts`` column directly and reads ``keys[k][6]`` with no cap at all.

    ``keys`` rows written before the ``finding_id`` column existed are 6 wide, so the index
    is read defensively: such a job contributes no ids rather than raising, and the caller
    reports it as a distinct empty state (see the graph's time link).
    """
    if not isinstance(payload, dict) or payload.get("v") != INDEX_VERSION:
        return set()
    ts_col: list[int] = payload.get("ts") or []
    k_col: list[int] = payload.get("k") or []
    key_rows: list[list] = payload.get("keys") or []
    if not ts_col or not key_rows:
        return set()

    lo = bisect_left(ts_col, frm) if frm is not None else 0
    hi = bisect_right(ts_col, to) if to is not None else len(ts_col)
    if lo >= hi:
        return set()

    # Resolve each key index at most once — a busy job has far more markers than keys.
    seen_keys: set[int] = set()
    out: set[int] = set()
    for i in range(lo, hi):
        key_idx = k_col[i]
        if key_idx in seen_keys:
            continue
        seen_keys.add(key_idx)
        row = key_rows[key_idx] if 0 <= key_idx < len(key_rows) else None
        if row is None or len(row) < 7:
            continue
        fid = row[6]
        if isinstance(fid, int):
            out.add(fid)
    return out


def slice_index(
    payload: dict,
    frm: int | None = None,
    to: int | None = None,
    resolution: int | None = None,
    *,
    cap: int = MAX_TIMELINE_ITEMS,
    job_id: int | None = None,
    severities: set[str] | None = None,
) -> dict:
    """Extract the markers in ``[frm, to]`` (epoch **seconds**) at *resolution*.

    Bisects the sorted ``ts`` column, re-collapses the window onto the requested
    resolution, and caps the result — walking one ladder step coarser at a time until it
    fits, then reporting ``truncated``. ``extent`` is the payload's full span so a client
    can frame itself without a second request.
    """
    if not isinstance(payload, dict) or payload.get("v") != INDEX_VERSION:
        return _empty_slice()

    ts_col: list[int] = payload.get("ts") or []
    k_col: list[int] = payload.get("k") or []
    n_col: list[int] = payload.get("n") or []
    key_rows: list[list] = payload.get("keys") or []
    base_resolution = int(payload.get("res") or 1)

    groupings = index_groupings(payload)

    if not ts_col:
        out = _empty_slice(base_resolution)
        out["base_resolution"] = base_resolution
        out["groupings"] = groupings
        return out

    extent = [ts_col[0] * 1000, (ts_col[-1] + base_resolution) * 1000]

    lo = bisect_left(ts_col, frm) if frm is not None else 0
    hi = bisect_right(ts_col, to) if to is not None else len(ts_col)
    if lo >= hi:
        out = _empty_slice(base_resolution)
        out["base_resolution"] = base_resolution
        out["extent"] = extent
        # Lanes survive an empty viewport too — zooming into a quiet gap must not collapse
        # the panel to nothing and then re-expand when you pan back.
        out["groupings"] = groupings
        return out

    # A resolution finer than what was stored cannot be honoured — the detail is gone.
    effective = max(int(resolution or base_resolution), base_resolution)

    computers: list[str] = payload.get("computers") or []
    tools: list[str] = payload.get("tools") or []

    allowed: set[int] | None = None
    if severities:
        wanted = {s.lower() for s in severities}
        allowed = {i for i, row in enumerate(key_rows) if str(row[2]).lower() in wanted}

    def _collapse(step: int) -> dict[tuple[int, int], int]:
        out: dict[tuple[int, int], int] = {}
        for i in range(lo, hi):
            key_idx = k_col[i]
            if allowed is not None and key_idx not in allowed:
                continue
            bucket = ts_col[i] - ts_col[i] % step
            k = (key_idx, bucket)
            out[k] = out.get(k, 0) + n_col[i]
        return out

    collapsed = _collapse(effective)
    truncated = False
    while len(collapsed) > cap:
        nxt = _next_resolution(effective)
        if nxt is None:
            truncated = True
            break
        effective = nxt
        collapsed = _collapse(effective)

    items = _build_items(collapsed, key_rows, computers, tools, job_id)
    if len(items) > cap:
        items.sort(key=lambda it: (-it["meta"]["discarded"], it["start"]))
        items = items[:cap]
        truncated = True

    items.sort(key=lambda it: (it["start"], it["label"]))

    return {
        "items": items,
        "discarded": sum(it["meta"]["discarded"] for it in items),
        "total": sum(collapsed.values()),
        "resolution": effective,
        "base_resolution": base_resolution,
        "truncated": truncated,
        "extent": extent,
        "groupings": groupings,
    }


def _build_items(
    collapsed: dict[tuple[int, int], int],
    key_rows: list[list],
    computers: list[str],
    tools: list[str],
    job_id: int | None,
) -> list[dict]:
    items: list[dict] = []
    for (key_idx, bucket), n in collapsed.items():
        try:
            row = key_rows[key_idx]
        except IndexError:
            continue
        if len(row) < 6:
            continue
        rule_id, rule_name, severity, tactic, computer_idx, tool_idx = row[:6]
        # Positional, not unpacked: rows written before finding_id existed are 6 wide, and
        # a fixed-arity unpack would silently drop every marker from those indexes.
        finding_id = row[6] if len(row) > 6 else None
        items.append(
            {
                "id": f"{job_id if job_id is not None else '-'}:{key_idx}:{bucket}",
                "start": bucket * 1000,
                "label": rule_name or rule_id or "Unknown rule",
                "grouping": tactic,
                "category": severity,
                "meta": {
                    "rule_id": rule_id,
                    "computer": _at(computers, computer_idx),
                    "tool": _at(tools, tool_idx),
                    "job_id": job_id,
                    "finding_id": finding_id,
                    "events": n,
                    "discarded": n - 1,
                },
            }
        )
    return items


def _at(values: list[str], idx: object) -> str | None:
    if isinstance(idx, int) and 0 <= idx < len(values):
        return values[idx] or None
    return None


def merge_sliced(results: list[dict], *, cap: int = MAX_TIMELINE_ITEMS) -> dict:
    """Merge per-job slices into one case-wide result, re-capping globally.

    Keeps the coarsest resolution any input used, so the merged axis is honest about the
    least-detailed contributor rather than implying uniform precision.
    """
    results = [r for r in results if r]
    if not results:
        return _empty_slice()

    items: list[dict] = []
    truncated = False
    resolution = 0
    base_resolution = 0
    total = 0
    extents = []
    groupings: dict[str, None] = {}

    for r in results:
        items.extend(r.get("items") or [])
        truncated = truncated or bool(r.get("truncated"))
        resolution = max(resolution, int(r.get("resolution") or 1))
        base_resolution = max(base_resolution, int(r.get("base_resolution") or 1))
        total += int(r.get("total") or 0)
        if r.get("extent"):
            extents.append(r["extent"])
        # Union, not intersection: a case's lane set is every tactic any member job saw, so
        # the axis stays put when a filter narrows the case to one job.
        for g in r.get("groupings") or []:
            groupings.setdefault(g, None)

    if len(items) > cap:
        items.sort(key=lambda it: (-it["meta"]["discarded"], it["start"]))
        items = items[:cap]
        truncated = True

    items.sort(key=lambda it: (it["start"], it["label"]))

    return {
        "items": items,
        "discarded": sum(it["meta"]["discarded"] for it in items),
        "total": total,
        "resolution": resolution or 1,
        "base_resolution": base_resolution or 1,
        "truncated": truncated,
        "extent": [min(e[0] for e in extents), max(e[1] for e in extents)] if extents else None,
        "groupings": list(groupings),
    }
