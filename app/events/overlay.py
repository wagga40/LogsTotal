"""Mark which stored events a job detected: `python -m app.events.overlay …` (a subprocess).

Joins the job's `event_links` (each detection's source-event identity, app/tools/event_keys.py)
onto the store, and writes beside it:

- `hits.parquet`   `(_lt_uid, rule_ix)` — every (event, rule) pair, distinct;
- `levels.parquet` `(_lt_uid, level_rank, n_rules, tools_mask)` — one row per detected event,
  its highest severity first, so "detections only" and level filters are one join;
- `overlay.json`   the rules table and, per tool, links linked / unlinked / ambiguous.

Exact keys (Windows host + channel + record id, or host + event id + record id) join directly.
Hints (Linux text logs) join only where they pick out exactly one event; an ambiguous one is
counted, never guessed. Imports duckdb, so it runs out of the worker process like the build.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import orjson

from app.tools.event_keys import HINTS, WINDOWS, WINDOWS_BY_EVENT_ID

LEVELS = ("informational", "low", "medium", "high", "critical")
_IDENT = re.compile(r"^[0-9A-Za-z_]+$")


def _lit(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def level_rank(severity: str) -> int:
    return LEVELS.index(severity) if severity in LEVELS else 0


def _links_table(con, links: dict, work: Path) -> int:
    """Write the links as an NDJSON table the join reads; returns how many."""
    path = work / "links.ndjson"
    rows = 0
    with path.open("wb") as out:
        for link in links.get("links") or []:
            rule_ix, kind, *key = link
            row: dict = {"rule_ix": rule_ix, "kind": kind}
            if kind == WINDOWS and len(key) == 3:
                row.update(host=key[0], channel=key[1], rid=key[2])
            elif kind == WINDOWS_BY_EVENT_ID and len(key) == 3:
                row.update(host=key[0], eid=key[1], rid=key[2])
            elif kind == HINTS and len(key) == 5:
                row.update(epoch=key[0], cursor=key[1], seq=key[2], pid=key[3], sha=key[4])
            else:
                continue
            row["link_id"] = rows
            out.write(orjson.dumps(row) + b"\n")
            rows += 1
    columns = {
        "link_id": "BIGINT",
        "rule_ix": "BIGINT",
        "kind": "VARCHAR",
        "host": "VARCHAR",
        "channel": "VARCHAR",
        "rid": "BIGINT",
        "eid": "BIGINT",
        "epoch": "BIGINT",
        "cursor": "VARCHAR",
        "seq": "BIGINT",
        "pid": "BIGINT",
        "sha": "VARCHAR",
    }
    if rows:
        con.execute(f"CREATE TEMP TABLE links AS SELECT * FROM read_json({_lit(path)}, format='newline_delimited', columns={json.dumps(columns)})")  # noqa: S608 — server-built path
    else:
        con.execute("CREATE TEMP TABLE links (" + ", ".join(f"{c} {t}" for c, t in columns.items()) + ")")
    return rows


def _optional_column(names: set[str], *candidates: str) -> str | None:
    for name in candidates:
        if name in names and _IDENT.match(name):
            return f'"{name}"'
    return None


#: Fields `lineage` reads from a flattened event, projected from the store when present.
_LINEAGE_FIELDS = (
    "EventID",
    "Computer",
    "Channel",
    "Image",
    "NewProcessName",
    "ProcessName",
    "ProcessGuid",
    "ParentProcessGuid",
    "ProcessId",
    "ParentProcessId",
    "NewProcessId",
    "CommandLine",
    "User",
    "SubjectUserName",
    "TargetUserName",
    "UtcTime",
    "SystemTime",
    "Hashes",
    "ParentImage",
    "ParentProcessName",
    "OriginalFileName",
    "exe",
    "comm",
    "pid",
    "ppid",
    "proctitle",
    "acct",
    "auid",
    "uid",
    "hostname",
)
#: execve and execveat on x86_64 (59, 322) and aarch64 (221, 281): every other syscall
#: record also carries exe and pid, and would otherwise all read as process creations.
_EXEC_SYSCALLS = (59, 322, 221, 281)


def _full_forest(con, events: str, names: set[str], levels: dict[int, int], max_nodes: int) -> dict:
    """The process forest from every process creation in the store, detections marked."""
    from app.intel.lineage import build_process_forest, mark_detections

    present = [f for f in _LINEAGE_FIELDS if f in names and _IDENT.match(f)]
    where = ["(_lt_eid = 1 AND _lt_channel LIKE '%sysmon%')", "(_lt_eid = 4688 AND _lt_channel = 'security')"]
    if {"type", "syscall"} <= names:
        where.append(f"(_lt_channel = 'auditd' AND \"type\" = 'SYSCALL' AND TRY_CAST(\"syscall\" AS BIGINT) IN {_EXEC_SYSCALLS})")
    columns = ", ".join(["_lt_uid", "_lt_time", "_lt_host", *(f'"{f}"' for f in present)])
    cursor = con.execute(f"SELECT {columns} FROM read_parquet({events}) WHERE {' OR '.join(where)} ORDER BY _lt_time NULLS LAST, _lt_uid")  # noqa: S608 — names from the store schema, checked
    keys = ["_lt_uid", "_lt_time", "_lt_host", *present]
    rows = []
    while batch := cursor.fetchmany(10_000):
        for values in batch:
            event = {k: v for k, v in zip(keys, values, strict=True) if v is not None}
            when = event.pop("_lt_time", None)
            host = event.pop("_lt_host", None)
            if when is not None:
                event.setdefault("SystemTime", when.isoformat())
            if host:
                event.setdefault("Computer", host)
            rows.append(event)
    return mark_detections(build_process_forest(rows, max_nodes=max_nodes), levels)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.events.overlay")
    parser.add_argument("--store", required=True, help="the store directory (events.parquet)")
    parser.add_argument("--links", required=True, help="the job's event_links JSON")
    parser.add_argument("--out", required=True)
    parser.add_argument("--memory-mb", type=int, default=512)
    parser.add_argument("--max-processes", type=int, default=20_000)
    args = parser.parse_args(argv)
    import duckdb

    store, out = Path(args.store), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    links = orjson.loads(Path(args.links).read_bytes())
    rules = links.get("rules") or []
    con = duckdb.connect(
        config={"threads": 2, "memory_limit": f"{args.memory_mb}MB", "temp_directory": str(out / "tmp"), "autoload_known_extensions": False, "autoinstall_known_extensions": False}
    )
    try:
        total = _links_table(con, links, out)
        events = _lit(store / "events.parquet")
        names = {row[0] for row in con.execute(f"DESCRIBE SELECT * FROM read_parquet({events})").fetchall()}  # noqa: S608
        sha_col = _optional_column(names, "message_sha")
        cursor_col = _optional_column(names, "CURSOR", "cursor")
        pid_col = _optional_column(names, "pid", "PID", "_PID")
        hint_terms = ["epoch(e._lt_time)::BIGINT = l.epoch"]
        if sha_col:
            hint_terms.append(f"(l.sha IS NULL OR e.{sha_col} = l.sha)")
        if cursor_col:
            hint_terms.append(f"(l.cursor IS NULL OR e.{cursor_col} = l.cursor)")
        if pid_col:
            hint_terms.append(f"(l.pid IS NULL OR TRY_CAST(e.{pid_col} AS BIGINT) = l.pid)")
        hint_terms.append("(l.seq IS NULL OR e._lt_seq = l.seq)")
        con.execute(
            f"""
            CREATE TEMP TABLE matched AS
            SELECT l.link_id, l.rule_ix, l.kind, e._lt_uid
            FROM links l JOIN read_parquet({events}) e
              ON l.kind = '{WINDOWS}' AND e._lt_host = l.host AND e._lt_channel = l.channel AND e._lt_rid = l.rid
            UNION ALL
            SELECT l.link_id, l.rule_ix, l.kind, e._lt_uid
            FROM links l JOIN read_parquet({events}) e
              ON l.kind = '{WINDOWS_BY_EVENT_ID}' AND e._lt_host = l.host AND e._lt_eid = l.eid AND e._lt_rid = l.rid
            UNION ALL
            SELECT l.link_id, l.rule_ix, l.kind, e._lt_uid
            FROM links l JOIN read_parquet({events}) e
              ON l.kind = '{HINTS}' AND l.epoch IS NOT NULL AND e._lt_time IS NOT NULL AND {" AND ".join(hint_terms)}
            """  # noqa: S608 — names checked by _optional_column, values only in the links table
        )
        # A link that matched several events is ambiguous: dropped and counted, never guessed.
        con.execute("CREATE TEMP TABLE unique_links AS SELECT link_id FROM matched GROUP BY link_id HAVING count(*) = 1")
        con.execute("CREATE TEMP TABLE hits AS SELECT DISTINCT m._lt_uid, m.rule_ix FROM matched m JOIN unique_links u USING (link_id)")
        con.execute(f"COPY (SELECT * FROM hits ORDER BY _lt_uid, rule_ix) TO {_lit(out / 'hits.parquet')} (FORMAT parquet, COMPRESSION zstd)")  # noqa: S608
        con.execute("CREATE TEMP TABLE rules (rule_ix BIGINT, tool VARCHAR, level_rank INTEGER)")
        if rules:
            con.executemany("INSERT INTO rules VALUES (?, ?, ?)", [(ix, r[0], level_rank(r[3])) for ix, r in enumerate(rules)])
        tools = sorted({r[0] for r in rules})
        bit = {tool: 1 << i for i, tool in enumerate(tools)}
        con.execute("CREATE TEMP TABLE tool_bits (tool VARCHAR, b BIGINT)")
        if bit:
            con.executemany("INSERT INTO tool_bits VALUES (?, ?)", list(bit.items()))
        con.execute(
            f"""COPY (
                SELECT h._lt_uid, max(r.level_rank) AS level_rank, count(DISTINCT h.rule_ix) AS n_rules, bit_or(t.b) AS tools_mask
                FROM hits h JOIN rules r USING (rule_ix) LEFT JOIN tool_bits t USING (tool)
                GROUP BY h._lt_uid ORDER BY h._lt_uid
            ) TO {_lit(out / "levels.parquet")} (FORMAT parquet, COMPRESSION zstd)"""  # noqa: S608
        )
        per_tool = {
            tool: {"links": links_n, "linked": linked or 0, "ambiguous": ambiguous or 0}
            for tool, links_n, linked, ambiguous in con.execute(
                """
                SELECT r.tool, count(*) AS links_n,
                       count(*) FILTER (WHERE u.link_id IS NOT NULL) AS linked,
                       count(*) FILTER (WHERE u.link_id IS NULL AND m.link_id IS NOT NULL) AS ambiguous
                FROM links l JOIN rules r USING (rule_ix)
                LEFT JOIN unique_links u USING (link_id)
                LEFT JOIN (SELECT DISTINCT link_id FROM matched) m USING (link_id)
                GROUP BY r.tool
                """
            ).fetchall()
        }
        detected = con.execute("SELECT count(*) FROM (SELECT DISTINCT _lt_uid FROM hits)").fetchone()[0]
        levels = dict(con.execute(f"SELECT _lt_uid, level_rank FROM read_parquet({_lit(out / 'levels.parquet')})").fetchall())  # noqa: S608
        forest = _full_forest(con, events, names, levels, args.max_processes)
        (out / "proc_forest_full.json").write_bytes(orjson.dumps(forest))
    finally:
        con.close()
    (out / "links.ndjson").unlink(missing_ok=True)
    meta = {
        "v": 1,
        "rules": rules,
        "tools": tools,
        "links": total,
        "unkeyed": links.get("unkeyed", 0),
        "truncated": bool(links.get("truncated")),
        "detected_events": detected,
        "per_tool": per_tool,
    }
    tmp = out / "overlay.json.tmp"
    tmp.write_text(json.dumps(meta))
    os.replace(tmp, out / "overlay.json")
    print(out / "overlay.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
