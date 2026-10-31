"""The Explore grammar, judged by what a compiled query *matches* on a real DuckDB table.

Asserting SQL strings would pin the spelling and miss the semantics; these run every
compiled WHERE against a small in-memory table shaped like a store (plus the overlay and
text tables the engine binds), so precedence, NULL handling and wildcards are checked by
the engine that will run them.
"""

from __future__ import annotations

import random
import re
from datetime import datetime

import duckdb
import pytest

from app.events import query as q
from app.events.query import QueryError, Rule, Schema, column_filter_to_terms, compile_query
from app.intel.queries import scan_query

COLUMNS = {
    "Image": "VARCHAR",
    "CommandLine": "VARCHAR",
    "EventID": "BIGINT",
    "User": "VARCHAR",
    "TargetUserName": "VARCHAR",
    "Level": "BIGINT",
    "Score": "DOUBLE",
    "ProcessId": "VARCHAR",
}
PATHS = {"CommandLine": "EventData/CommandLine", "Level": "System/Level", "Image": "EventData/Image"}
# uid, time, host, channel, eid, Image, CommandLine, EventID, User, TargetUserName, Level, Score, ProcessId
ROWS = [
    (0, "2026-01-05 08:00:00", "ws1", "security", 4624, None, None, 4624, None, "alice", 0, 1.5, None),
    (1, "2026-01-05 09:30:00", "ws1", "sysmon", 1, r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", 1, r"CORP\bob", None, 4, 2.0, "4321"),
    (
        2,
        "2026-01-06 23:15:00",
        "ws2",
        "sysmon",
        1,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -enc AAA (x)",
        1,
        r"CORP\svc_backup",
        None,
        4,
        None,
        "0x10e1",
    ),
    (3, "2026-01-10 12:00:00", "dc1", "security", 4625, None, None, 4625, None, "Administrator", 0, 10.0, None),
    (4, None, "dc1", "system", 7045, r"C:\temp\a*b.exe", "a*b", 7045, None, None, 4, None, "12"),
]
RULES = (
    Rule(0, "hayabusa", "r-1", "Suspicious Whoami", "medium", ("discovery",), ("T1033",)),
    Rule(1, "zircolite", "r-2", "Encoded PowerShell", "high", ("execution",), ("T1059.001",)),
    Rule(2, "chainsaw", "r-3", "Failed logon", "low", ("credential-access",), ("T1110",)),
)
HITS = [(1, 0), (2, 1), (3, 2)]
LEVELS = [(1, 2), (2, 3), (3, 1)]


def _manifest(text_index: bool = True) -> dict:
    return {"columns": [{"name": n, "type": t, "path": PATHS.get(n, n)} for n, t in COLUMNS.items()], "text_index": {"present": text_index}}


SCHEMA = Schema.from_manifest(_manifest(), overlay=True, rules=RULES)


@pytest.fixture(scope="module")
def con():
    con = duckdb.connect()
    cols = ", ".join(f'"{n}" {t}' for n, t in COLUMNS.items())
    con.execute(f"CREATE TABLE events (_lt_uid BIGINT, _lt_time TIMESTAMP, _lt_host VARCHAR, _lt_channel VARCHAR, _lt_eid BIGINT, {cols})")
    con.executemany(f"INSERT INTO events VALUES ({', '.join('?' * 13)})", ROWS)
    con.execute(f"CREATE TABLE {q.TEXT} AS SELECT _lt_uid, lower(concat_ws(chr(31), *COLUMNS(* EXCLUDE (_lt_uid, _lt_time)))) AS _lt_text FROM events")
    con.execute(f"CREATE TABLE {q.HITS} (_lt_uid BIGINT, rule_ix BIGINT)")
    con.executemany(f"INSERT INTO {q.HITS} VALUES (?, ?)", HITS)
    con.execute(f"CREATE TABLE {q.LEVELS_TABLE} (_lt_uid BIGINT, level_rank INTEGER)")
    con.executemany(f"INSERT INTO {q.LEVELS_TABLE} VALUES (?, ?)", LEVELS)
    yield con
    con.close()


def uids(con, text: str, schema: Schema = SCHEMA) -> list[int]:
    compiled = compile_query(text, schema)
    where = compiled.where or "TRUE"
    return [r[0] for r in con.execute(f"SELECT _lt_uid FROM events WHERE {where} ORDER BY 1", list(compiled.params)).fetchall()]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", [0, 1, 2, 3, 4]),
        ("WHOAMI", [1]),
        ("corp", [1, 2]),
        ('"-enc"', [2]),  # quoting keeps a leading dash literal
        ("-enc", [0, 1, 3, 4]),  # unquoted, it negates
        ('"enc aaa (x)"', [2]),
        ("pow*shell", [2]),
        ("image:c:\\windows\\system32\\cmd.exe", [1]),
        ("Image:*powershell*", [2]),
        ("Image:C:\\Windows*", [1, 2]),
        ("Image:*.exe", [1, 2, 4]),
        ("Image:C:*32*cmd*", [1]),
        ("User:corp\\svc_*", [2]),  # `_` is literal, not LIKE's any-one-char
        ("User:corp\\svc*backup", [2]),
        ("Image:=C:\\temp\\a*b.exe", [4]),  # `=`: the star is literal
        ("Image:C:\\temp\\a*b.exe", [4]),  # unescaped it is a wildcard and still matches
        ('CommandLine:"powershell -enc AAA (x)"', [2]),
        ("EventData/CommandLine:*whoami*", [1]),
        ("EventData.CommandLine:*whoami*", [1]),
        ("EventID:4624", [0]),
        ("EventID:4624,4625", [0, 3]),
        ("EventID:>=4625", [3, 4]),
        ("EventID:<2", [1, 2]),
        ("EventID:46*", [0, 3]),  # a wildcard on a number compares its text
        ("EventID:1.5", []),
        ("Score:>1.5", [1, 3]),
        ("ProcessId:>100", [1]),  # text column: numeric only where it parses
        ("Image:*", [1, 2, 4]),
        ("-Image:*", [0, 3]),
        ("-Image:*cmd*", [0, 2, 3, 4]),  # events without the field count as not matching
        ("NOT Image:*cmd*", [0, 2, 3, 4]),
        ("has:CommandLine", [1, 2, 4]),
        ("sysmon -cmd", [2]),
        ("sysmon AND cmd", [1]),
        ("cmd OR alice", [0, 1]),
        ("sysmon cmd OR alice", [0, 1]),  # AND binds tighter than OR
        ("sysmon (cmd OR alice)", [1]),
        ("-(cmd OR alice)", [2, 3, 4]),
        ("NOT (cmd OR alice) dc1", [3, 4]),
        ('"OR"', [1, 2, 3]),  # a quoted keyword is a word (corp, administrator), not an operator
        ("host:WS1", [0, 1]),
        ("channel:sys*", [1, 2, 4]),
        ("eid:4624,7045", [0, 4]),
        ("user:*bob", [1]),
        ("user:alice", [0]),
        ("after:2026-01-06", [2, 3]),
        ("before:2026-01-05T09:00", [0]),
        ("after:2026-01-05 before:2026-01-07", [0, 1, 2]),
        ("hour:9-12", [1, 3]),
        ("hour:22-8", [0, 2]),  # wraps past midnight
        ("weekday:sat,sun", [3]),  # 2026-01-10 is a Saturday
        ("weekday:mon-tue", [0, 1, 2]),
        ("det:yes", [1, 2, 3]),
        ("det:no", [0, 4]),
        ("level:>=medium", [1, 2]),
        ("level:low", [3]),
        ("rule:*powershell*", [2]),
        ("rule:suspicious whoami", []),  # one word each: `rule:suspicious` then `whoami`
        ('rule:"suspicious whoami"', [1]),
        ("rulekey:R-3", [3]),
        ("tool:hayabusa OR tool:chainsaw", [1, 3]),
        ("tactic:credential_access", [3]),
        ("tactic:Credential-Access", [3]),
        ("technique:T1059", [2]),  # a technique covers its sub-techniques
        ("technique:t1059.001", [2]),
        ("rule:nothing-like-this", []),
        (".Level:4", [1, 2, 4]),  # the column, not the shortcut
        ("System/Level:0", [0, 3]),
        ("C:\\Windows\\System32\\cmd.exe", [1]),  # a drive path is text, not field `C`
        ("fe80::1", []),
        ("https://example.com", []),
    ],
)
def test_matches(con, text, expected):
    assert uids(con, text) == expected


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("(cmd", "never closed"),
        ("cmd)", "closes no"),
        ("()", "Empty parentheses"),
        ("OR cmd", "needs a term before"),
        ("cmd OR", "needs a term after"),
        ("cmd AND OR alice", "needs a term after"),
        ("-", "needs a term after"),
        ("ComandLine:x", "Did you mean CommandLine"),
        ("levle:high", "Did you mean level:"),
        ("EventID:abc", "holds numbers"),
        ("EventID:>x", "compares numbers"),
        ("Image:", "needs a value"),
        ("level:urgent", "level: takes"),
        ("det:maybe", "det: takes"),
        ("after:yesterday", "needs a date"),
        ("hour:25", "0-23"),
        ("weekday:funday", "weekday: takes"),
        ("has:Nope", "no field"),
        ("rule:", "needs a value"),
        ("(" * 9 + "cmd" + ")" * 9, "nest at most"),
        (" ".join(f"w{i}" for i in range(9)), "free-text words"),
        (" ".join(f"EventID:{i}" for i in range(33)), "At most 32 terms"),
        ("x" * 2001, "longer than"),
    ],
)
def test_refusals(text, message):
    with pytest.raises(QueryError) as caught:
        compile_query(text, SCHEMA)
    assert message in str(caught.value)


def test_a_refusal_points_at_the_offending_term():
    with pytest.raises(QueryError) as caught:
        compile_query("cmd ComandLine:x", SCHEMA)
    assert (caught.value.start, caught.value.end) == (4, 16) and caught.value.suggestions == ("CommandLine",)


def test_detections_and_free_text_need_what_the_store_has():
    unlinked = Schema.from_manifest(_manifest(), overlay=False)
    with pytest.raises(QueryError, match="not linked"):
        compile_query("det:yes", unlinked)
    assert compile_query("Image:*cmd*", unlinked).needs == frozenset()
    no_text = Schema.from_manifest(_manifest(text_index=False))
    with pytest.raises(QueryError, match="without free-text search"):
        compile_query("whoami", no_text)
    assert compile_query("cmd level:high rule:x", SCHEMA).needs == {"text", "levels", "hits"}


def test_compiled_metadata():
    compiled = compile_query("Image:*cmd* user:bob cmd", SCHEMA)
    assert compiled.fields == ("Image", "User", "TargetUserName") and compiled.bare_words == ("cmd",) and compiled.terms == 3
    assert compile_query("Image:*CMD*", SCHEMA).key == compile_query("image:*cmd*", SCHEMA).key, "the cache key follows meaning, not spelling"
    assert compile_query("a", SCHEMA).key != compile_query("b", SCHEMA).key


@pytest.mark.parametrize(
    ("column", "cell", "expected"),
    [
        ("Image", "cmd", [1]),
        ("Image", "=C:\\temp\\a*b.exe", [4]),
        ("Image", "!cmd", [0, 2, 3, 4]),
        ("Image", "*", [1, 2, 4]),
        ("Image", "!*", [0, 3]),
        ("EventID", ">=4625", [3, 4]),
        ("CommandLine", "-enc aaa (x)", [2]),
        ("CommandLine", 'say "hi"', []),
        ("Level", "=4", [1, 2, 4]),  # a column sharing a shortcut's name stays the column
    ],
)
def test_filter_row_cells_become_query_terms(con, column, cell, expected):
    term = column_filter_to_terms(column, cell)
    assert uids(con, term) == expected, term


def test_an_empty_filter_cell_adds_nothing():
    assert column_filter_to_terms("Image", "  ") == ""


def test_quoted_values_leave_the_other_grammars_alone():
    """The jobs and entity grammars never pass quoted_values; for them nothing changed."""
    for text in ['tag:"a b"', 'CommandLine:"x y" z', '-"enc" re:/a b/ in:(a,b)', 'x:"open']:
        assert scan_query(text) == scan_query(text, quoted_values=False)
        assert scan_query(text, split_groups=True) == scan_query(text, split_groups=True, quoted_values=False)
    assert scan_query('CommandLine:"x y" z', quoted_values=True) == [(0, 17, "CommandLine:x y"), (18, 19, "z")]
    assert scan_query('CommandLine:"x y" z') == [(0, 14, 'CommandLine:"x'), (15, 17, 'y"'), (18, 19, "z")]


# ── Injection: no typed text reaches the SQL ─────────────────────────────────

_SQL_WORDS = {
    "AND", "OR", "NOT", "IN", "IS", "NULL", "TRUE", "FALSE", "SELECT", "FROM", "WHERE", "LIKE", "ESCAPE", "CAST", "AS", "VARCHAR", "DOUBLE",
    "TRY_CAST", "coalesce", "lower", "contains", "starts_with", "ends_with", "hour", "isodow", "_lt_uid", "_lt_time", "_lt_host",
    "_lt_channel", "_lt_eid", "_lt_text", "rule_ix", "level_rank", q.HITS, q.LEVELS_TABLE, q.TEXT,
}  # fmt: skip
_ALPHABET = ["'", '"', ";", "--", "/*", "*/", "\\", "(", ")", ":", "*", "=", ">=", "<", ",", "-", " ", "OR", "AND", "NOT", "DROP", "x", "é", "%", "_",
             "Image", "EventID", "level", "rule", "user", "after", "hour", "det", "has", ".Level", "EventData/CommandLine", "4624", "0x1f", "high", "yes"]  # fmt: skip


def test_no_user_text_ever_reaches_the_sql(con):
    """Fuzzed queries: the SQL is drawn from a closed vocabulary, with no string literal but
    the ESCAPE character, and every query that compiles is one DuckDB accepts."""
    allowed = _SQL_WORDS | {f'"{c}"' for c in COLUMNS}
    rng = random.Random(20261031)
    compiled_ok = 0
    for _ in range(3000):
        text = "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(1, 14)))
        try:
            compiled = compile_query(text, SCHEMA)
        except QueryError:
            continue
        compiled_ok += 1
        sql = compiled.where or ""
        literals = re.findall(r"'[^']*'", sql)
        assert set(literals) <= {"'\\'"}, (text, sql)
        stripped = re.sub(r"'\\\\'", "", sql)
        for word in re.findall(r'"[^"]*"|[A-Za-z_][A-Za-z_0-9]*', stripped):
            assert word in allowed, (text, word, sql)
        con.execute(f"SELECT count(*) FROM events WHERE {sql or 'TRUE'}", list(compiled.params)).fetchone()
    assert compiled_ok > 500, "the fuzz must exercise compiling queries, not only refusals"


def test_params_carry_the_values():
    compiled = compile_query("Image:*It's*; DROP", SCHEMA)
    assert "It's" not in compiled.where and compiled.params == ("%it's%;", "drop")
    assert compile_query("after:2026-01-02", SCHEMA).params == (datetime(2026, 1, 2),)


def test_level_names_agree_with_the_overlay():
    from app.events.overlay import LEVELS as OVERLAY_LEVELS

    assert q.LEVELS == OVERLAY_LEVELS, "level_rank is an index into both"


def test_the_help_panel_is_a_jinja_global():
    from app.templates_config import templates

    assert templates.env.globals["explore_syntax_help"] is q.SYNTAX_HELP
    assert all(len(row) == 2 for row in q.SYNTAX_HELP)
