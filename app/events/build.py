"""Build one upload's event store. Run as a subprocess: `python -m app.events.build …`.

The only worker-side code that imports duckdb, and a separate process so the worker can kill
its whole process group on timeout, cancel or memory use without the Huey process ever
loading the engine. Two stages, as measured on real EVTX (G2 in the plan):

1. Parse, flatten and census every event; spool rows as zstd NDJSON parts, and the text index
   as a separate narrow spool. Building the text index from a wide events.parquet ran out of
   memory at 1 GB with any thread count; the narrow spool takes 0.74 s at 256 MB.
2. DuckDB reads the spool with explicit column types and writes events.parquet (one thread:
   1.84 s and 724 MB against 2.02 s and 1,060 MB on two), then order.parquet from two narrow
   columns (the wide sort that spilled in Zircolite never happens) and text.parquet without
   insertion order.

manifest.json is written last; a store without a valid one is never published.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import orjson

from app.compression_utils import open_write
from app.events.census import FLOAT, I64_MAX, I64_MIN, INT, STR, Census
from app.events.flatten import assign_names
from app.events.manifest import BUILDER_VERSION, FORMAT, FORMAT_VERSION, MANIFEST
from app.events.parsers import iter_events
from app.events.timeparse import iso

SPOOL_ROWS = 100_000
TEXT_VALUE_CAP = 4096
SEP = "\x1f"  # between fields in the text index, so a phrase never matches across two
_IDENT = re.compile(r"^[0-9A-Za-z_]+$")


def _lit(path: Path) -> str:
    """A path as a DuckDB string literal. COPY and read_json take no bound parameters for
    paths, so every path here is built by the worker and escaped all the same."""
    return "'" + str(path).replace("'", "''") + "'"


def _ident(name: str) -> str:
    """A column name as a quoted identifier; names come from flatten's sanitiser, checked again."""
    if not _IDENT.match(name):
        raise ValueError(f"unsafe column name {name!r}")
    return f'"{name}"'


FIXED_COLUMNS = {
    "_lt_uid": "BIGINT",
    "_lt_time": "TIMESTAMP",
    "_lt_host": "VARCHAR",
    "_lt_channel": "VARCHAR",
    "_lt_eid": "BIGINT",
    "_lt_rid": "BIGINT",
    "_lt_seq": "BIGINT",
    "_lt_line": "BIGINT",
    "_lt_family": "VARCHAR",
    "_lt_extra": "VARCHAR",
}


def _progress(out: Path, **values) -> None:
    tmp = out / "progress.json.tmp"
    tmp.write_text(json.dumps({**values, "at": time.time()}))
    os.replace(tmp, out / "progress.json")


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def spool(args) -> tuple[Census, dict, list[Path], Path | None, dict]:
    """Stage 1. Returns the census, the path spellings, the spool parts, the text spool, stats."""
    out = Path(args.out)
    census = Census(args.max_columns)
    spellings: dict = {}
    stats: dict = {"truncated": False}
    parts: list[Path] = []
    part = None
    text_path = out / "text.ndjson.zst" if args.text_index else None
    text = open_write(text_path, level=1) if text_path else None
    reference = datetime.fromisoformat(args.reference) if args.reference else None
    last_progress = time.monotonic()
    uid = 0
    ids, masks, counts, max_len = census.ids, census.masks, census.counts, census.max_len
    keys: list[str] = []  # "c{cid}", indexed by column id
    try:
        for flat, fixed in iter_events(Path(args.input), args.log_type, stats=stats, spellings=spellings, reference=reference, evtx_threads=args.threads):
            if uid >= args.max_events:
                stats["truncated"] = True
                break
            if uid % SPOOL_ROWS == 0:
                if part:
                    part.close()
                parts.append(out / f"spool-{len(parts):05d}.ndjson.zst")
                part = open_write(parts[-1], level=1)
            row: dict = {"_lt_uid": uid}
            extra: dict = {}
            columns: list[int] = []
            words: list[str] = []
            # The census update, inlined: one method call per value was the parse's second
            # largest cost (5M calls for 184k events).
            for path, value in flat.items():
                cid = ids.get(path)
                if cid is None:
                    cid = census.column(path)
                    if cid is None:
                        extra["/".join(spellings.get(path, path))] = value
                        continue
                    keys.append(f"c{cid}")
                kind = type(value)
                if kind is str:
                    masks[cid] |= STR
                    if len(value) > max_len[cid]:  # noqa: PLR1730 — hot loop; a max() call per value costs ~0.3 s per 5M
                        max_len[cid] = len(value)
                    if text is not None:
                        words.append(value[:TEXT_VALUE_CAP])
                else:
                    masks[cid] |= (INT if I64_MIN <= value <= I64_MAX else STR) if kind is int else FLOAT
                    if text is not None:
                        words.append(str(value))
                counts[cid] += 1
                row[keys[cid]] = value
                columns.append(cid)
            family = (fixed["channel"], fixed["eid"])
            census.event(family, columns, fixed["time"])
            row["_lt_time"] = iso(fixed["time"])
            for key in ("host", "channel", "eid", "rid", "seq", "line"):
                if fixed[key] is not None:
                    row[f"_lt_{key}"] = fixed[key]
            row["_lt_family"] = f"{fixed['channel'] or ''}|{fixed['eid'] if fixed['eid'] is not None else ''}"
            if extra:
                census.overflow_paths += 1
                row["_lt_extra"] = orjson.dumps(extra).decode()
            part.write(orjson.dumps(row) + b"\n")
            if text is not None:
                text.write(orjson.dumps({"_lt_uid": uid, "_lt_text": SEP.join(words).lower()}) + b"\n")
            uid += 1
            if time.monotonic() - last_progress > 2:
                _progress(out, stage="parse", events=uid)
                last_progress = time.monotonic()
    finally:
        if part:
            part.close()
        if text is not None:
            text.close()
    return census, spellings, parts, text_path, stats


def write_parquet(args, census: Census, names: dict, parts: list[Path], text_path: Path | None) -> dict[str, int]:
    """Stage 2. Returns {file name: rows}."""
    import duckdb

    out = Path(args.out)
    rows: dict[str, int] = {}
    con = duckdb.connect(
        config={
            "threads": 1,
            "memory_limit": f"{args.memory_mb}MB",
            "temp_directory": str(out / "tmp"),
            "preserve_insertion_order": True,
            "autoload_known_extensions": False,
            "autoinstall_known_extensions": False,
        }
    )
    try:
        spec = dict(FIXED_COLUMNS)
        select = [_ident(name) for name in FIXED_COLUMNS]
        for path, cid in census.ids.items():
            spec[f"c{cid}"] = census.duck_type(cid)
            select.append(f"{_ident(f'c{cid}')} AS {_ident(names[path])}")
        width = len(spec)
        row_group = max(2048, min(20000, 1000 * (4_000_000 // (1000 * width))))
        events = out / "events.parquet"
        if parts:
            # Every interpolated piece is server-built: paths via _lit, names via _ident, types
            # from the census's fixed set, sizes are ints. No value from the log enters SQL.
            source = f"read_json([{', '.join(_lit(p) for p in parts)}], format='newline_delimited', compression='zstd', columns={json.dumps(spec)})"
            con.execute(f"COPY (SELECT {', '.join(select)} FROM {source}) TO {_lit(events)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE {int(row_group)})")  # noqa: S608
        else:
            empty = ", ".join(f"CAST(NULL AS {t}) AS {_ident(n)}" for n, t in FIXED_COLUMNS.items())
            con.execute(f"COPY (SELECT {empty} WHERE false) TO {_lit(events)} (FORMAT parquet)")
        rows["events.parquet"] = census.events
        _progress(out, stage="order", events=census.events)
        con.execute(
            f"COPY (SELECT row_number() OVER (ORDER BY _lt_time NULLS LAST, _lt_uid) - 1 AS _lt_pos, _lt_uid, _lt_time FROM read_parquet({_lit(events)})) "  # noqa: S608
            f"TO {_lit(out / 'order.parquet')} (FORMAT parquet, COMPRESSION zstd)"
        )
        rows["order.parquet"] = census.events
        if text_path is not None and census.events:
            _progress(out, stage="text", events=census.events)
            con.execute(f"SET threads = {max(1, args.threads)}")
            con.execute("SET preserve_insertion_order = false")
            con.execute(
                f"COPY (SELECT * FROM read_json({_lit(text_path)}, format='newline_delimited', compression='zstd', columns={{'_lt_uid': 'BIGINT', '_lt_text': 'VARCHAR'}})) "  # noqa: S608
                f"TO {_lit(out / 'text.parquet')} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 5000)"
            )
            rows["text.parquet"] = census.events
    finally:
        con.close()
    return rows, row_group


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.events.build")
    parser.add_argument("--input", required=True)
    parser.add_argument("--log-type", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--source-sha256", default="")
    parser.add_argument("--reference", default="", help="the upload's date (ISO), for year-less syslog")
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--memory-mb", type=int, default=1024)
    parser.add_argument("--max-events", type=int, default=5_000_000)
    parser.add_argument("--max-columns", type=int, default=4096)
    parser.add_argument("--text-index", type=int, default=1)
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if hasattr(os, "nice"):
        os.nice(10)  # beside the detection tools, the store build yields the CPU
    started = time.monotonic()
    census, spellings, parts, text_path, stats = spool(args)
    names = assign_names({path: census.counts[cid] for path, cid in census.ids.items()}, spellings)
    rows, row_group = write_parquet(args, census, names, parts, text_path)
    for p in parts:
        p.unlink(missing_ok=True)
    if text_path is not None:
        text_path.unlink(missing_ok=True)
    by_cid = {cid: path for path, cid in census.ids.items()}
    columns = [
        {
            "name": names[by_cid[cid]],
            "path": "/".join(spellings.get(by_cid[cid], by_cid[cid])),
            "type": census.duck_type(cid),
            "count": census.counts[cid],
            "max_len": census.max_len[cid],
        }
        for cid in range(len(census.ids))
    ]
    families = [
        {"channel": channel, "eid": eid, "count": census.family_counts[(channel, eid)], "columns": sorted(names[by_cid[c]] for c in cids)}
        for (channel, eid), cids in sorted(census.families.items(), key=lambda item: -census.family_counts[item[0]])
    ]
    warnings = []
    if stats.get("truncated"):
        warnings.append(f"only the first {args.max_events:,} events are stored")
    if census.overflow_paths:
        warnings.append(f"{census.overflow_paths:,} events carried fields past the {args.max_columns:,}-column cap, kept in _lt_extra")
    if stats.get("dtd_refused"):
        warnings.append("the XML declared a DTD and was not parsed")
    if stats.get("errors"):
        warnings.append(f"{stats['errors']:,} records could not be parsed and were skipped")
    files = [{"name": name, "bytes": (out / name).stat().st_size, "rows": count, "sha256": _sha256(out / name)} for name, count in rows.items()]
    manifest = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "builder_version": BUILDER_VERSION,
        "status": "complete",
        "created": datetime.now(UTC).isoformat(),
        "source": {"sha256": args.source_sha256, "log_type": args.log_type, "bytes": Path(args.input).stat().st_size},
        "totals": {"events": census.events, "undated": census.undated, "parse_errors": stats.get("errors", 0), "truncated": bool(stats.get("truncated"))},
        "time": {"min": iso(census.time_min), "max": iso(census.time_max)},
        "layout": {"row_group_rows": row_group, "time_sorted": census.out_of_order == 0},
        "columns": columns,
        "families": families,
        "text_index": {"present": "text.parquet" in rows, "value_cap": TEXT_VALUE_CAP},
        "files": files,
        "warnings": warnings,
        "build_seconds": round(time.monotonic() - started, 2),
    }
    tmp = out / (MANIFEST + ".tmp")
    tmp.write_text(json.dumps(manifest))
    with tmp.open("rb") as stream:
        os.fsync(stream.fileno())
    os.replace(tmp, out / MANIFEST)
    (out / "progress.json").unlink(missing_ok=True)
    print(out / MANIFEST)
    return 0


if __name__ == "__main__":
    sys.exit(main())
