"""DuckDB over event stores, in the web process. The only web-side module that imports duckdb.

Four rules, each measured on DuckDB 2.0 and pinned by `tests/test_events_engine.py`:

1. **One connection per process, a fresh cursor per query.** A connection used from two
   threads raises `ResourceInUseException`, and so does a new query on a connection with an
   open result. Every call here takes `self._con.cursor()` and closes it.
2. **Every setting is `SET GLOBAL`.** Each cursor is its own session; with a plain `SET`,
   `parquet_metadata_cache` stayed off for every new cursor and each query re-parsed the
   store's footer — a 39 ms floor on a 300-column store.
3. **Locked down before the first query:** `allowed_directories` (the store and cache roots),
   then `enable_external_access = false`, then `lock_configuration = true`. A query can then
   read and write only under those roots and change no setting. The order matters: the
   directories cannot be changed once external access is off.
4. **Histogram bins divide with `/` and `floor`, never `//`**: 2.0 raises on integer division
   by zero instead of returning NULL.

Queries are blocking; routes call these methods through `run_in_threadpool`. Concurrency is
bounded by a semaphore (`EVENTS_MAX_CONCURRENT_QUERIES`): a call that cannot get a slot in
`SLOT_WAIT_SECONDS` raises `EngineBusy`, which the page renders as a retrying placeholder. A
query past `EVENTS_QUERY_TIMEOUT_SECONDS` is interrupted and raises `EngineTimeout`.

Expensive answers are kept. A **match-set** — the matching uids in display order, as a narrow
Parquet file under `.events_cache/matches/` — is built once for a query with free-text words,
a column sort or a deep page, and the list, count, histogram and facets then read it instead
of re-running the text scan. Counts are kept in Redis per store generation.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.events import histogram
from app.events.query import HITS, LEVELS_TABLE, TEXT, Compiled

logger = logging.getLogger(__name__)

#: Columns every store has, beside the ones its manifest lists.
FIXED = ("_lt_uid", "_lt_time", "_lt_host", "_lt_channel", "_lt_eid", "_lt_rid", "_lt_seq", "_lt_line", "_lt_family", "_lt_extra")
_FIXED_TYPES = {"_lt_uid": "BIGINT", "_lt_time": "TIMESTAMP", "_lt_eid": "BIGINT", "_lt_rid": "BIGINT", "_lt_seq": "BIGINT", "_lt_line": "BIGINT"}
PAGE_MAX = 500
#: Past this offset a page reads a match-set instead of an OFFSET over the store.
DEEP_OFFSET = 20_000
SLOT_WAIT_SECONDS = 2.0
FACET_MAX = 50
STACK_MAX = 1000
STACK_FIELDS_MAX = 3
EXPORT_BATCH = 5000
#: A whole export stream, slow readers included; past it the stream ends and the slot frees.
EXPORT_MAX_SECONDS = 300
MATCHES_MAX_BYTES = 512 << 20
_COUNT_TTL = 7 * 86_400
_TIME_ORDER = "_lt_time NULLS LAST, _lt_uid"


class EngineError(RuntimeError):
    pass


class EngineBusy(EngineError):
    """Every query slot is taken; try again shortly."""


class EngineTimeout(EngineError):
    """The query ran past EVENTS_QUERY_TIMEOUT_SECONDS and was interrupted."""


def _lit(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _with(ctes: list[str], *more: str) -> str:
    parts = [*ctes, *more]
    return ("WITH " + ", ".join(parts) + " ") if parts else ""


@dataclass(frozen=True)
class StoreView:
    """One store as a query sees it: local files, its manifest, and the job's overlay."""

    root: Path
    manifest: dict
    gen: str
    overlay: Path | None = None
    overlay_tag: str = ""

    @property
    def events(self) -> str:
        return f"read_parquet({_lit(self.root / 'events.parquet')})"

    @property
    def columns(self) -> dict[str, str]:
        """Every queryable column, fixed ones first, with its type."""
        types = {name: _FIXED_TYPES.get(name, "VARCHAR") for name in FIXED}
        types.update({c["name"]: c["type"] for c in self.manifest.get("columns") or []})
        return types

    def column(self, name: str) -> str:
        if name not in self.columns:
            raise EngineError(f"no column {name!r} in this store")
        return name

    def family_columns(self, channel: str | None, eid: int | None) -> list[str] | None:
        """The columns events of one (channel, event id) family carry, or None if unknown."""
        known = self.columns
        for family in self.manifest.get("families") or []:
            if family.get("channel") == channel and family.get("eid") == eid:
                return [c for c in family.get("columns") or [] if c in known]
        return None


@dataclass(frozen=True)
class Page:
    rows: list[dict]
    offset: int
    limit: int


class Engine:
    def __init__(self, *, roots: list[Path], cache_dir: Path, threads: int = 2, memory_mb: int = 768, max_concurrent: int = 2, timeout_seconds: float = 10.0):
        import duckdb

        self._duckdb = duckdb
        self.cache_dir = Path(cache_dir).resolve()
        self.matches_dir = self.cache_dir / "matches"
        self.matches_dir.mkdir(parents=True, exist_ok=True)
        temp = self.cache_dir / "tmp"
        temp.mkdir(parents=True, exist_ok=True)
        allowed = sorted({str(Path(r).resolve()) for r in roots} | {str(self.cache_dir)})
        for directory in allowed:
            Path(directory).mkdir(parents=True, exist_ok=True)
        self._con = duckdb.connect(
            ":memory:",
            config={
                "threads": int(threads),
                "memory_limit": f"{int(memory_mb)}MB",
                "temp_directory": str(temp),
                "autoload_known_extensions": False,
                "autoinstall_known_extensions": False,
            },
        )
        self._con.execute("SET GLOBAL parquet_metadata_cache = true")
        self._con.execute("SET GLOBAL allowed_directories = [" + ", ".join(_lit(Path(d)) for d in allowed) + "]")
        self._con.execute("SET GLOBAL enable_external_access = false")
        self._con.execute("SET GLOBAL lock_configuration = true")
        self.timeout_seconds = float(timeout_seconds)
        self._slots = threading.BoundedSemaphore(max(1, int(max_concurrent)))
        self._export_slot = threading.BoundedSemaphore(1)

    # ── plumbing ────────────────────────────────────────────────────────────

    @contextlib.contextmanager
    def _slot(self):
        if not self._slots.acquire(timeout=SLOT_WAIT_SECONDS):
            raise EngineBusy("every Explore query slot is busy")
        try:
            yield
        finally:
            self._slots.release()

    def _run(self, sql: str, params: list | tuple = (), *, names: bool = False):
        """One query on its own cursor, interrupted past the timeout.

        Returns the rows, or `(column names, rows)` with *names*.
        """
        with self._slot():
            cur = self._con.cursor()
            timer = threading.Timer(self.timeout_seconds, cur.interrupt)
            timer.daemon = True
            timer.start()
            try:
                rows = cur.execute(sql, list(params)).fetchall()
                return ([d[0] for d in cur.description], rows) if names else rows
            except self._duckdb.InterruptException as exc:
                raise EngineTimeout(f"the query ran past {self.timeout_seconds:g} s") from exc
            finally:
                timer.cancel()
                cur.close()

    def _ctes(self, view: StoreView, compiled: Compiled, *extra: str) -> list[str]:
        parts = []
        if "hits" in compiled.needs or "hits" in extra:
            parts.append(f"{HITS} AS (SELECT * FROM read_parquet({_lit(self._overlay_file(view, 'hits.parquet'))}))")  # noqa: S608 — server-built paths and manifest identifiers; values are bound
        if "levels" in compiled.needs or "levels" in extra:
            parts.append(f"{LEVELS_TABLE} AS (SELECT * FROM read_parquet({_lit(self._overlay_file(view, 'levels.parquet'))}))")  # noqa: S608 — server-built paths and manifest identifiers; values are bound
        if "text" in compiled.needs:
            parts.append(f"{TEXT} AS (SELECT * FROM read_parquet({_lit(view.root / 'text.parquet')}))")  # noqa: S608 — server-built paths and manifest identifiers; values are bound
        return parts

    @staticmethod
    def _overlay_file(view: StoreView, name: str) -> Path:
        if view.overlay is None:
            raise EngineError("this job's detections are not linked to the store yet")
        return view.overlay / name

    def _filter(self, view: StoreView, compiled: Compiled) -> tuple[str, list]:
        """(WHERE body, params) for *compiled*: its match-set when one exists, else the query."""
        if compiled.where is None:
            return "TRUE", []
        cached = self._match_path(view, compiled, None, False)
        if cached.is_file():
            return f"_lt_uid IN (SELECT _lt_uid FROM read_parquet({_lit(cached)}))", []  # noqa: S608 — server-built paths and manifest identifiers; values are bound
        return compiled.where, list(compiled.params)

    def _matched(self, view: StoreView, compiled: Compiled, select: str, *extra: str) -> tuple[list[str], str, list]:
        """(CTEs, `SELECT <select> FROM events WHERE (<filter>)`, params) for the matching events.

        The filter is parenthesised, so a caller may append `AND …` whatever the query's own
        OR structure. A query answered from its match-set needs none of its own CTEs.
        """
        where, params = self._filter(view, compiled)
        query = compiled if where == compiled.where else Compiled(where=None)
        return self._ctes(view, query, *extra), f"SELECT {select} FROM {view.events} WHERE ({where})", params  # noqa: S608 — identifiers from the manifest, values bound

    # ── match-sets ──────────────────────────────────────────────────────────

    def _match_path(self, view: StoreView, compiled: Compiled, sort: str | None, desc: bool) -> Path:
        order = "time" if sort is None else hashlib.sha256(f"{sort}:{desc}".encode()).hexdigest()[:12]
        tag = hashlib.sha256(view.overlay_tag.encode()).hexdigest()[:8] if view.overlay_tag else "0"
        key = compiled.key if compiled.where is not None else "all"
        return self.matches_dir / f"{view.gen}-{tag}-{key}-{order}.parquet"

    def _sort_key(self, view: StoreView, sort: str | None, desc: bool) -> str:
        if sort is None:
            return _TIME_ORDER
        ctype = view.columns[view.column(sort)]
        expr = _ident(sort) if ctype in ("BIGINT", "DOUBLE", "TIMESTAMP") else f"lower(left(CAST({_ident(sort)} AS VARCHAR), 128))"
        return f"{expr} {'DESC' if desc else 'ASC'} NULLS LAST, {_TIME_ORDER}"

    def match_set(self, view: StoreView, compiled: Compiled, sort: str | None = None, desc: bool = False) -> Path:
        """The matching uids in display order, `(_m_pos, _lt_uid)`, built once and kept."""
        path = self._match_path(view, compiled, sort, desc)
        if path.is_file():
            with contextlib.suppress(OSError):
                os.utime(path)
            return path
        part = path.with_name(f".{path.name}.{uuid.uuid4().hex}.part")
        ctes = self._ctes(view, compiled)
        sql = (
            f"COPY ({_with(ctes)}SELECT row_number() OVER (ORDER BY {self._sort_key(view, sort, desc)}) - 1 AS _m_pos, _lt_uid "  # noqa: S608 — server-built paths and manifest identifiers; values are bound
            f"FROM {view.events} WHERE ({compiled.where or 'TRUE'}) ORDER BY _m_pos) TO {_lit(part)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 100000)"
        )
        try:
            self._run(sql, compiled.params)
            os.replace(part, path)
        finally:
            part.unlink(missing_ok=True)
        self._trim_matches()
        return path

    def _trim_matches(self) -> None:
        """Keep the match-set cache under MATCHES_MAX_BYTES, least recently used first out."""
        try:
            files = sorted((p.stat().st_mtime, p.stat().st_size, p) for p in self.matches_dir.glob("*.parquet"))
        except OSError:
            return
        total = sum(size for _m, size, _p in files)
        for _mtime, size, path in files:
            if total <= MATCHES_MAX_BYTES:
                break
            path.unlink(missing_ok=True)
            total -= size

    def forget_store(self, gen: str) -> None:
        """Drop every match-set of a store generation (it was deleted or evicted)."""
        forget_generation(gen, self.cache_dir)

    def _wants_match_set(self, compiled: Compiled, sort: str | None, offset: int) -> bool:
        return sort is not None or offset + PAGE_MAX > DEEP_OFFSET or bool(compiled.bare_words)

    # ── reads ───────────────────────────────────────────────────────────────

    def count(self, view: StoreView, compiled: Compiled) -> int:
        if compiled.where is None:
            return int((view.manifest.get("totals") or {}).get("events") or 0)
        cached = _count_get(view, compiled)
        if cached is not None:
            return cached
        if compiled.bare_words:
            path = self.match_set(view, compiled)
            (n,) = self._run(f"SELECT count(*) FROM read_parquet({_lit(path)})")[0]  # noqa: S608
        else:
            ctes, sql, params = self._matched(view, compiled, "count(*)")
            (n,) = self._run(_with(ctes) + sql, params)[0]
        _count_set(view, compiled, int(n))
        return int(n)

    def page(
        self, view: StoreView, compiled: Compiled, *, offset: int = 0, limit: int = 100, columns: list[str] | None = None, sort: str | None = None, desc: bool = False
    ) -> Page:
        """One page of matching events, in time order or by *sort*, with their detections."""
        offset, limit = max(0, int(offset)), max(1, min(PAGE_MAX, int(limit)))
        if sort is not None:
            view.column(sort)
        if compiled.where is None and sort is None:
            order = view.root / "order.parquet"
            uids = [r[0] for r in self._run(f"SELECT _lt_uid FROM read_parquet({_lit(order)}) WHERE _lt_pos >= ? AND _lt_pos < ? ORDER BY _lt_pos", [offset, offset + limit])]  # noqa: S608
        elif self._wants_match_set(compiled, sort, offset):
            path = self.match_set(view, compiled, sort, desc)
            uids = [r[0] for r in self._run(f"SELECT _lt_uid FROM read_parquet({_lit(path)}) WHERE _m_pos >= ? AND _m_pos < ? ORDER BY _m_pos", [offset, offset + limit])]  # noqa: S608
        else:
            ctes, sql, params = self._matched(view, compiled, "_lt_uid")
            uids = [r[0] for r in self._run(f"{_with(ctes)}{sql} ORDER BY {_TIME_ORDER} LIMIT ? OFFSET ?", [*params, limit, offset])]
        return Page(rows=self.rows(view, uids, columns), offset=offset, limit=limit)

    def rows(self, view: StoreView, uids: list[int], columns: list[str] | None = None) -> list[dict]:
        """Rows for *uids*, in that order, with `_det` (highest level rank) and `_rules`."""
        if not uids:
            return []
        wanted = ["_lt_uid", *(c for c in (columns or ["_lt_time", "_lt_host", "_lt_channel", "_lt_eid"]) if c != "_lt_uid")]
        names = [view.column(c) for c in dict.fromkeys(wanted)]
        ids = ", ".join(str(int(u)) for u in uids)  # our own integers
        got = {r[0]: dict(zip(names, r, strict=True)) for r in self._run(f"SELECT {', '.join(map(_ident, names))} FROM {view.events} WHERE _lt_uid IN ({ids})")}  # noqa: S608
        if view.overlay is not None:
            levels = _lit(view.overlay / "levels.parquet")
            for uid, rank, n_rules in self._run(f"SELECT _lt_uid, level_rank, n_rules FROM read_parquet({levels}) WHERE _lt_uid IN ({ids})"):  # noqa: S608
                if uid in got:
                    got[uid]["_det"], got[uid]["_rules"] = rank, n_rules
        return [got[u] for u in uids if u in got]

    def histogram(self, view: StoreView, compiled: Compiled, *, start: datetime | None = None, end: datetime | None = None, width_px: int = 800) -> dict:
        """Events and detected events per bar over [start, end] (default: the store's span)."""
        span = view.manifest.get("time") or {}
        from app.events.timeparse import parse_time

        start = start or parse_time(span.get("min"))
        end = end or parse_time(span.get("max"))
        if start is None or end is None:
            return {"bucket_seconds": 0, "origin": None, "counts": [], "detected": []}
        ax = histogram.axis(start, end, width_px)
        linked = view.overlay is not None
        ctes, sql, params = self._matched(view, compiled, "_lt_uid, _lt_time", *(("levels",) if linked else ()))
        detected = "count(l._lt_uid)" if linked else "0"
        join = f" LEFT JOIN {LEVELS_TABLE} l ON l._lt_uid = m._lt_uid" if linked else ""
        rows = self._run(
            f"{_with(ctes, f'm AS ({sql} AND _lt_time >= ? AND _lt_time < ?)')}"  # noqa: S608 — server-built paths and manifest identifiers; values are bound
            f"SELECT CAST(floor((epoch_ms(m._lt_time) - ?) / ?) AS BIGINT) AS b, count(*), {detected} FROM m{join} GROUP BY b",
            [*params, ax.origin, ax.end, ax.origin_ms, ax.bucket_seconds * 1000],
        )
        counts, dets = [0] * ax.bins, [0] * ax.bins
        for b, n, d in rows:
            if 0 <= b < ax.bins:
                counts[b], dets[b] = int(n), int(d)
        return {"bucket_seconds": ax.bucket_seconds, "origin": ax.origin.isoformat(), "end": ax.end.isoformat(), "counts": counts, "detected": dets}

    def facet(self, view: StoreView, compiled: Compiled, column: str, *, limit: int = 10) -> dict:
        """The most frequent values of *column* among matching events."""
        col = _ident(view.column(column))
        limit = max(1, min(FACET_MAX, int(limit)))
        ctes, sql, params = self._matched(view, compiled, f"{col} AS v")
        head = _with(ctes, f"m AS ({sql})")
        top = self._run(f"{head}SELECT v, count(*) AS n FROM m WHERE v IS NOT NULL GROUP BY v ORDER BY n DESC, v LIMIT ?", [*params, limit])  # noqa: S608
        matched, present, distinct = self._run(f"{head}SELECT count(*), count(v), approx_count_distinct(v) FROM m", params)[0]  # noqa: S608
        return {"column": column, "values": [(v, int(n)) for v, n in top], "matched": int(matched), "present": int(present), "distinct": int(distinct)}

    def stack(self, view: StoreView, compiled: Compiled, fields: list[str], *, limit: int = STACK_MAX) -> dict:
        """Value combinations of 1 to 3 fields among matching events, rarest first."""
        names = list(dict.fromkeys(fields))
        if not 1 <= len(names) <= STACK_FIELDS_MAX:
            raise EngineError(f"stack 1 to {STACK_FIELDS_MAX} fields")
        cols = [_ident(view.column(n)) for n in names]
        aliases = [f"f{i}" for i in range(len(cols))]
        ctes, sql, params = self._matched(view, compiled, ", ".join(f"{c} AS {a}" for c, a in zip(cols, aliases, strict=True)))
        head = _with(ctes, f"m AS ({sql})")
        present = " OR ".join(f"{a} IS NOT NULL" for a in aliases)
        group = ", ".join(aliases)
        rows = self._run(
            f"{head}SELECT {group}, count(*) AS n FROM m WHERE {present} GROUP BY {group} ORDER BY n, {group} NULLS LAST LIMIT ?",  # noqa: S608
            [*params, max(1, min(STACK_MAX, int(limit)))],
        )
        (groups,) = self._run(f"{head}SELECT count(*) FROM (SELECT DISTINCT {group} FROM m WHERE {present})", params)[0]  # noqa: S608
        return {"fields": names, "rows": [(list(r[:-1]), int(r[-1])) for r in rows], "groups": int(groups)}

    def event(self, view: StoreView, uid: int) -> dict | None:
        """One event's fields (present ones only) and the rules that matched it."""
        head = self._run(f"SELECT _lt_channel, _lt_eid FROM {view.events} WHERE _lt_uid = ?", [int(uid)])  # noqa: S608
        if not head:
            return None
        # Only the columns this event's family can hold (the manifest lists them): decoding all
        # ~300 columns of a wide store for one row cost 57 ms, its family's ~30 a few.
        family = view.family_columns(*head[0])
        select = "*" if family is None else ", ".join(_ident(c) for c in dict.fromkeys([*FIXED, *family]))
        names, rows = self._run(f"SELECT {select} FROM {view.events} WHERE _lt_uid = ?", [int(uid)], names=True)  # noqa: S608
        record = dict(zip(names, rows[0], strict=True))
        rules: list[int] = []
        if view.overlay is not None:
            rules = [r[0] for r in self._run(f"SELECT rule_ix FROM read_parquet({_lit(view.overlay / 'hits.parquet')}) WHERE _lt_uid = ? ORDER BY rule_ix", [int(uid)])]  # noqa: S608
        return {"fields": {k: v for k, v in record.items() if v is not None}, "rules": rules}

    def export(self, view: StoreView, compiled: Compiled, columns: list[str], *, max_rows: int) -> Iterator[list[tuple]]:
        """Matching events in time order, in batches, on a dedicated cursor.

        One export at a time per process (`EngineBusy` otherwise). The slot and the cursor are
        released when the generator closes — including when the client goes away mid-stream,
        which Starlette signals by closing it. Two time limits, so neither a heavy query nor a
        slow reader can hold the slot: the query is interrupted if its first batch takes
        longer than the query timeout, and the stream ends with `EngineTimeout` past
        EXPORT_MAX_SECONDS in all.
        """
        names = [view.column(c) for c in dict.fromkeys(columns)]
        if not self._export_slot.acquire(blocking=False):
            raise EngineBusy("an export is already running")
        cur = None
        timer = None
        deadline = time.monotonic() + EXPORT_MAX_SECONDS
        try:
            ctes, sql, params = self._matched(view, compiled, ", ".join(map(_ident, names)))
            cur = self._con.cursor()
            timer = threading.Timer(self.timeout_seconds, cur.interrupt)
            timer.daemon = True
            timer.start()
            try:
                cur.execute(f"{_with(ctes)}{sql} ORDER BY {_TIME_ORDER} LIMIT ?", [*params, int(max_rows)])
                batch = cur.fetchmany(EXPORT_BATCH)
            except self._duckdb.InterruptException as exc:
                raise EngineTimeout(f"the export query ran past {self.timeout_seconds:g} s") from exc
            finally:
                timer.cancel()
            while batch:
                yield batch
                if time.monotonic() > deadline:
                    raise EngineTimeout(f"the export ran past {EXPORT_MAX_SECONDS} s")
                batch = cur.fetchmany(EXPORT_BATCH)
        finally:
            if timer is not None:
                timer.cancel()
            if cur is not None:
                with contextlib.suppress(Exception):
                    cur.close()
            self._export_slot.release()


# ── count cache ─────────────────────────────────────────────────────────────


def _count_key(view: StoreView) -> str:
    return f"logstotal:events:v1:{view.gen}"


def _count_field(view: StoreView, compiled: Compiled) -> str:
    return f"{view.overlay_tag or '0'}:{compiled.key}"


def _count_get(view: StoreView, compiled: Compiled) -> int | None:
    try:
        from app.redis_client import get_redis

        value = get_redis().hget(_count_key(view), _count_field(view, compiled))
        return int(value) if value is not None else None
    except Exception:
        return None


def _count_set(view: StoreView, compiled: Compiled, n: int) -> None:
    try:
        from app.redis_client import get_redis

        redis = get_redis()
        redis.hset(_count_key(view), _count_field(view, compiled), n)
        redis.expire(_count_key(view), _COUNT_TTL)
    except Exception:
        pass


def forget_counts(gen: str) -> None:
    """Drop a store generation's cached counts (it was deleted or evicted)."""
    try:
        from app.redis_client import get_redis

        get_redis().delete(f"logstotal:events:v1:{gen}")
    except Exception:
        pass


def forget_generation(gen: str, cache_dir: Path | None = None) -> None:
    """Everything kept for one store generation: its match-sets and its counts.

    Needs no engine, so the worker's store deletion and eviction call it too. Never raises.
    """
    from app.storage import _STORE_GEN

    if not _STORE_GEN.match(gen or ""):
        return
    if cache_dir is None:
        from app.config import settings

        cache_dir = Path(settings.upload_dir) / ".events_cache"
    for path in (Path(cache_dir) / "matches").glob(f"{gen}-*.parquet"):
        path.unlink(missing_ok=True)
    forget_counts(gen)


# ── the process's engine ────────────────────────────────────────────────────

_engine: Engine | None = None
_engine_lock = threading.Lock()


def get_engine() -> Engine:
    """This process's engine, created on first use from the settings."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                from app.config import settings

                upload_dir = Path(settings.upload_dir)
                _engine = Engine(
                    roots=[upload_dir / "events"],
                    cache_dir=upload_dir / ".events_cache",
                    threads=settings.events_duckdb_threads,
                    memory_mb=settings.events_duckdb_memory_mb,
                    max_concurrent=settings.events_max_concurrent_queries,
                    timeout_seconds=settings.events_query_timeout_seconds,
                )
    return _engine
