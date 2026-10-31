"""A synthetic event store shaped like a large real one, for the engine's performance budgets.

2M events x ~300 sparse columns: 15 system columns on every row, then 20 event families of
14 columns each, present only on that family's rows (Sysmon EID 1 is 25% of them, with the
long, high-cardinality text columns analysts filter and facet on). Plus an overlay: about 1%
of events detected by one of 20 rules. Written with DuckDB in well under a minute and kept
under tests/perf/.store/ between runs.
"""

from __future__ import annotations

import json
from pathlib import Path

import duckdb

VERSION = 2
FAMILIES = 20

_FAMILY = "CASE WHEN hash(i) % 4 = 0 THEN 0 ELSE 1 + (hash(i * 7) % 19) END"
_HOST = "lpad(CAST(hash(i * 3) % 50 AS VARCHAR), 2, '0')"
_CHANNEL = "CASE WHEN f = 0 THEN 'Microsoft-Windows-Sysmon/Operational' ELSE 'Channel-' || CAST(f AS VARCHAR) END"
_EID = "CAST(CASE WHEN f = 0 THEN 1 ELSE 4600 + f END AS BIGINT)"
_FIXED = [
    "i AS _lt_uid",
    # nearly time-ordered, with small local jitter, like a real EVTX
    "TIMESTAMP '2026-10-12 08:00:00' + to_milliseconds(i * 250 + (hash(i) % 5000)) AS _lt_time",
    f"'host-' || {_HOST} AS _lt_host",
    f"lower({_CHANNEL}) AS _lt_channel",
    f"{_EID} AS _lt_eid",
    "CAST(i + 1000 AS BIGINT) AS _lt_rid",
    "CAST(NULL AS BIGINT) AS _lt_seq",
    "CAST(NULL AS BIGINT) AS _lt_line",
    "CAST(f AS VARCHAR) AS _lt_family",
    "CAST(NULL AS VARCHAR) AS _lt_extra",
]
_SYSTEM = [
    f"{_EID} AS EventID",
    f"'HOST-' || {_HOST} || '.corp.local' AS Computer",
    f"{_CHANNEL} AS Channel",
    "'Provider-' || CAST(f AS VARCHAR) AS Provider_Name",
    "CAST(i + 1000 AS BIGINT) AS EventRecordID",
    "CAST(hash(i * 11) % 9000 AS BIGINT) AS Execution_ProcessID",
    "CAST(hash(i * 13) % 9000 AS BIGINT) AS Execution_ThreadID",
    "CAST(hash(i) % 5 AS BIGINT) AS Level",
    "CAST(hash(i * 17) % 30 AS BIGINT) AS Task",
    "CAST(0 AS BIGINT) AS Opcode",
    "'0x8000000000000000' AS Keywords",
    "CAST(hash(i) % 3 AS BIGINT) AS Version",
    "'S-1-5-' || CAST(hash(i * 19) % 300 AS VARCHAR) AS Security_UserID",
    "strftime(TIMESTAMP '2026-10-12 08:00:00' + to_milliseconds(i * 250), '%Y-%m-%dT%H:%M:%S.%fZ') AS SystemTime",
    "CAST(hash(i * 23) % 100000 AS BIGINT) AS Correlation",
]
_PROCESS = [
    (
        "Image",
        "'C:\\Windows\\System32\\' || (['cmd.exe','powershell.exe','rundll32.exe','svchost.exe','conhost.exe','mshta.exe','whoami.exe','net.exe'])[1 + CAST(hash(i*29) % 8 AS BIGINT)]",
    ),
    ("ParentImage", "'C:\\Windows\\' || (['explorer.exe','services.exe','winlogon.exe','System32\\cmd.exe'])[1 + CAST(hash(i*31) % 4 AS BIGINT)]"),
    (
        "CommandLine",
        "(['cmd.exe /c ', 'powershell.exe -nop -w hidden -enc ', 'rundll32.exe ', 'svchost.exe -k netsvcs -p -s ', 'whoami /all ', 'net user '])[1 + CAST(hash(i*37) % 6 AS BIGINT)]"
        " || md5(CAST(i AS VARCHAR)) || ' ' || md5(CAST(i * 41 AS VARCHAR)) || CASE WHEN hash(i) % 20000 = 0 THEN ' mimikatz sekurlsa::logonpasswords' ELSE '' END",
    ),
    ("User", "'CORP\\user' || CAST(hash(i * 43) % 200 AS VARCHAR)"),
    ("Hashes", "'SHA256=' || sha256(CAST(hash(i * 47) % 50000 AS VARCHAR))"),
    ("ProcessGuid", "'{' || md5(CAST(i * 53 AS VARCHAR)) || '}'"),
    ("ParentProcessGuid", "'{' || md5(CAST(i * 59 AS VARCHAR)) || '}'"),
    ("ProcessId", "CAST(hash(i * 61) % 30000 AS BIGINT)"),
    ("ParentProcessId", "CAST(hash(i * 67) % 30000 AS BIGINT)"),
    ("IntegrityLevel", "(['Medium','High','System'])[1 + CAST(hash(i*71) % 3 AS BIGINT)]"),
    ("CurrentDirectory", "'C:\\Users\\user' || CAST(hash(i * 43) % 200 AS VARCHAR) || '\\'"),
    ("LogonId", "'0x' || to_hex(hash(i * 73) % 100000)"),
    ("OriginalFileName", "(['Cmd.Exe','PowerShell.EXE','RUNDLL32.EXE','svchost.exe'])[1 + CAST(hash(i*79) % 4 AS BIGINT)]"),
    ("Description", "'Windows Command Processor'"),
]


def _select(n: int) -> str:
    cols = list(_FIXED) + list(_SYSTEM)
    cols += [f"CASE WHEN f = 0 THEN {expr} END AS {name}" for name, expr in _PROCESS]
    for family in range(1, FAMILIES):
        for k in range(14):
            if k % 4 == 0:
                expr = f"CAST(hash(i * {k + 83}) % 1000 AS BIGINT)"
            elif k % 4 == 1:
                expr = f"'f{family}v' || CAST(hash(i * {k + 89}) % 50 AS VARCHAR)"
            else:
                expr = f"'value-{family}-{k}-' || CAST(hash(i * {k + 97}) % 20000 AS VARCHAR)"
            cols.append(f"CASE WHEN f = {family} THEN {expr} END AS F{family}_C{k}")
    return f"(SELECT {', '.join(cols)} FROM (SELECT i, {_FAMILY} AS f FROM range({int(n)}) t(i)))"


def build(out: Path, n: int = 2_000_000) -> dict:
    """Write the store (and its overlay under out/overlay) unless this version is already there."""
    marker = out / "manifest.json"
    if marker.is_file():
        manifest = json.loads(marker.read_text())
        if manifest.get("synth") == [VERSION, n]:
            return manifest
    out.mkdir(parents=True, exist_ok=True)
    (out / "overlay").mkdir(exist_ok=True)
    con = duckdb.connect(config={"threads": 4, "memory_limit": "4GB", "temp_directory": str(out / "tmp")})
    events = out / "events.parquet"
    con.execute(f"COPY {_select(n)} TO '{events}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 13000)")
    con.execute(
        f"COPY (SELECT row_number() OVER (ORDER BY _lt_time NULLS LAST, _lt_uid) - 1 AS _lt_pos, _lt_uid, _lt_time FROM read_parquet('{events}')) TO '{out}/order.parquet' (FORMAT parquet, COMPRESSION zstd)"
    )
    described = con.execute(f"DESCRIBE SELECT * FROM read_parquet('{events}')").fetchall()
    user = [(name, ctype) for name, ctype, *_ in described if not name.startswith("_lt_")]
    text = ", ".join(name for name, ctype in user if ctype == "VARCHAR")
    con.execute("SET preserve_insertion_order = false")
    con.execute(
        f"COPY (SELECT _lt_uid, lower(concat_ws(chr(31), {text})) AS _lt_text FROM read_parquet('{events}')) TO '{out}/text.parquet' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 5000)"
    )
    hits = out / "overlay" / "hits.parquet"
    con.execute(
        f"COPY (SELECT _lt_uid, CAST(hash(_lt_uid * 101) % 20 AS BIGINT) AS rule_ix FROM read_parquet('{events}') WHERE hash(_lt_uid) % 100 = 0 ORDER BY _lt_uid) TO '{hits}' (FORMAT parquet, COMPRESSION zstd)"
    )
    con.execute(
        f"COPY (SELECT _lt_uid, CAST(rule_ix % 5 AS INTEGER) AS level_rank, CAST(1 AS BIGINT) AS n_rules, CAST(1 AS BIGINT) AS tools_mask FROM read_parquet('{hits}') ORDER BY _lt_uid) "
        f"TO '{out}/overlay/levels.parquet' (FORMAT parquet, COMPRESSION zstd)"
    )
    lo, hi = con.execute(f"SELECT min(_lt_time), max(_lt_time) FROM read_parquet('{events}')").fetchone()
    con.close()
    system = [expr.rsplit(" AS ", 1)[1] for expr in _SYSTEM]
    families = [{"channel": "microsoft-windows-sysmon/operational", "eid": 1, "columns": system + [name for name, _e in _PROCESS]}]
    families += [{"channel": f"channel-{f}", "eid": 4600 + f, "columns": system + [f"F{f}_C{k}" for k in range(14)]} for f in range(1, FAMILIES)]
    manifest = {
        "synth": [VERSION, n],
        "families": families,
        "columns": [{"name": name, "type": ctype if ctype in ("BIGINT", "DOUBLE") else "VARCHAR", "path": name} for name, ctype in user],
        "totals": {"events": n, "undated": 0},
        "time": {"min": lo.isoformat(), "max": hi.isoformat()},
        "text_index": {"present": True},
    }
    marker.write_text(json.dumps(manifest))
    return manifest
