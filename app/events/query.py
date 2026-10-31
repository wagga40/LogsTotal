"""The Explore search grammar: query text → a DuckDB WHERE clause over one event store. Pure.

Precedence, loosest first: `OR`, then `AND` or plain juxtaposition, then `-`/`NOT`, then
parentheses (at most `MAX_DEPTH` deep). The tokenizer is `intel.queries.scan_query` with
`quoted_values`, so the search box's caret logic cannot disagree with this parser about
where a term ends.

A term is a bare word (matched against the store's text index), a `field:value`, or a
shortcut (`det:`, `level:`, `host:`…). Two rules carry the safety of the whole thing, and an
injection property test pins both: **no text the user typed ever reaches the SQL** — every
value is a bound parameter — and **every identifier comes from the store's manifest**, never
from the query. What the user writes only chooses among SQL fragments written here.

Matching is case-insensitive. A negated term is `NOT coalesce(p, FALSE)`, so an event that
lacks the field counts as "not matching" rather than vanishing from both sides.
"""

from __future__ import annotations

import difflib
import hashlib
import math
import re
from dataclasses import dataclass, field

from app.events.timeparse import parse_time
from app.intel.queries import scan_query

MAX_QUERY_CHARS = 2000
MAX_TERMS = 32
MAX_BARE_WORDS = 8
MAX_DEPTH = 8

#: Table names the engine binds (as CTEs over the store's files) when a query needs them.
HITS = "__hits"
LEVELS_TABLE = "__levels"
TEXT = "__text"

#: Detection levels, lowest first; the overlay's `level_rank` is an index into this.
LEVELS = ("informational", "low", "medium", "high", "critical")
_LEVEL_ALIASES = {"info": 0, "informational": 0, "low": 1, "med": 2, "medium": 2, "high": 3, "crit": 4, "critical": 4}

SHORTCUTS = ("rule", "rulekey", "level", "tool", "tactic", "technique", "det", "has", "host", "channel", "eid", "user", "hour", "weekday", "after", "before")
#: What `user:` searches, whichever of them the log has.
USER_FIELDS = ("User", "SubjectUserName", "TargetUserName", "AccountName", "UserName", "SamAccountName", "acct")
_WEEKDAYS = {"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7}
_YES, _NO = ("yes", "true", "1", "y"), ("no", "false", "0", "n")
_COMPARE = (">=", "<=", ">", "<")
#: A `word:rest` that is a value rather than a field term: a drive path, a URL, an IPv6 or
#: MAC address, a clock time. Only consulted when `word` names no field.
_VALUE_LIKE = re.compile(r"^(?:[A-Za-z]|[0-9A-Fa-f]+)$")

SYNTAX_INTRO = "Search every event of the upload. Terms are ANDed; matching ignores case."
SYNTAX_HELP = (
    ("word", "The event's text contains it, in any field"),
    ('"two words"', "A phrase; quoting also makes OR, AND, - and ( ) literal"),
    ("Field:value", "The field equals the value (Image:C:\\Windows\\System32\\cmd.exe)"),
    ("Field:*part*", "Wildcards: contains; part* starts with; *part ends with"),
    ('Field:"a b"', "A value with spaces or parentheses"),
    ("Field:=a*b", "Exact, with * taken literally"),
    ("Field:>=10", "Compare numbers: > >= < <="),
    ("EventID:4624,4625", "Any of several numbers"),
    ("Field:*   -Field:*", "The field is present / absent"),
    ("-term   NOT (…)", "Not"),
    ("a OR b   (a b) OR c", "OR binds loosest; AND is implied between terms"),
    ("det:yes   level:>=high", "Detected events, by their highest level"),
    ("rule:*mimikatz*   rulekey:<id>   tool:hayabusa", "Events a rule, rule id or tool matched"),
    ("tactic:execution   technique:T1059", "Events detected under a MITRE tactic or technique"),
    ("host:   channel:   eid:   user:", "Normalised host, channel and event id; any user field"),
    ("has:Field", "The field is present"),
    ("after:2026-01-01   before:2026-01-02T10:00", "Time range, UTC"),
    ("hour:9-17   weekday:sat,sun", "Hour of day and day of week, UTC"),
    (".Level:4   System/Level:4", "A field whose name is also a shortcut"),
)


class QueryError(ValueError):
    """A query this grammar refuses, with the span of the offending text."""

    def __init__(self, message: str, start: int = 0, end: int = 0, suggestions: tuple[str, ...] = ()):
        super().__init__(message)
        self.start, self.end, self.suggestions = start, end, suggestions


@dataclass(frozen=True)
class Rule:
    """One rule the overlay knows, by its `rule_ix` in `hits.parquet`."""

    ix: int
    tool: str
    key: str
    name: str
    level: str
    tactics: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()


@dataclass(frozen=True)
class Schema:
    """What a query may name: the store's columns and, once linked, its detections."""

    columns: dict[str, str]
    by_lower: dict[str, str]
    by_path: dict[str, str]
    text_index: bool = True
    overlay: bool = False
    rules: tuple[Rule, ...] = ()

    @classmethod
    def from_manifest(cls, manifest: dict, *, overlay: bool = False, rules: tuple[Rule, ...] = ()) -> Schema:
        columns = {c["name"]: c["type"] for c in manifest.get("columns") or []}
        by_path = {}
        for c in manifest.get("columns") or []:
            by_path.setdefault(str(c.get("path") or "").lower(), c["name"])
        return cls(
            columns=columns,
            by_lower={name.lower(): name for name in columns},
            by_path=by_path,
            text_index=bool((manifest.get("text_index") or {}).get("present")),
            overlay=overlay,
            rules=tuple(rules),
        )

    def resolve(self, name: str) -> str | None:
        """The column a field name means: by name, then by path (`/` or `.` separated)."""
        key = name.lower()
        return self.by_lower.get(key) or self.by_path.get(key.replace(".", "/"))


@dataclass(frozen=True)
class Compiled:
    """A compiled query. `where` is None for "every event"."""

    where: str | None
    params: tuple = ()
    needs: frozenset[str] = frozenset()
    fields: tuple[str, ...] = ()
    bare_words: tuple[str, ...] = ()
    terms: int = 0

    @property
    def key(self) -> str:
        """Stable identity for caches: two queries that compile alike share entries."""
        return hashlib.sha256(repr((self.where, self.params)).encode()).hexdigest()[:32]


@dataclass
class _Tok:
    start: int
    end: int
    text: str
    quoted: bool

    @property
    def word(self) -> str | None:
        """The structural keyword this token is, if any; a quoted token never is one."""
        return None if self.quoted else self.text


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def combine(*parts: Compiled) -> Compiled:
    """Every part must match: the typed query AND the controls' terms (det, the brush).

    Compiled apart rather than concatenated as text, so the typed query keeps its own limits
    and an error in it points at what the analyst typed, not at an offset into a string the
    page assembled.
    """
    live = [p for p in parts if p.where is not None]
    if not live:
        return Compiled(where=None)
    if len(live) == 1:
        return live[0]
    params: tuple = ()
    for p in live:
        params += p.params
    return Compiled(
        where=" AND ".join(f"({p.where})" for p in live),
        params=params,
        needs=frozenset().union(*(p.needs for p in live)),
        fields=tuple(dict.fromkeys(f for p in live for f in p.fields)),
        bare_words=tuple(w for p in live for w in p.bare_words),
        terms=sum(p.terms for p in live),
    )


def compile_query(raw: str, schema: Schema) -> Compiled:
    """Compile *raw* against *schema*, or raise QueryError."""
    raw = raw or ""
    if len(raw) > MAX_QUERY_CHARS:
        raise QueryError(f"The query is longer than {MAX_QUERY_CHARS:,} characters.", MAX_QUERY_CHARS, len(raw))
    parser = _Parser(raw, schema)
    return parser.run()


@dataclass
class _Parser:
    raw: str
    schema: Schema
    toks: list[_Tok] = field(default_factory=list)
    i: int = 0
    depth: int = 0
    terms: int = 0
    needs: set[str] = field(default_factory=set)
    fields: list[str] = field(default_factory=list)
    bare: list[str] = field(default_factory=list)

    def __post_init__(self):
        for start, end, text in scan_query(self.raw, split_groups=True, quoted_values=True):
            lead = self.raw[start : start + 2]
            self.toks.append(_Tok(start, end, text, lead[:1] == '"' or lead == '-"'))

    def run(self) -> Compiled:
        if not self.toks:
            return Compiled(where=None)
        sql, params = self.or_()
        if (tok := self.peek()) is not None:
            raise QueryError(f"Unexpected {tok.text!r}." if tok.text != ")" else "A ')' closes no '('.", tok.start, tok.end)
        return Compiled(where=sql, params=tuple(params), needs=frozenset(self.needs), fields=tuple(dict.fromkeys(self.fields)), bare_words=tuple(self.bare), terms=self.terms)

    # ── structure ────────────────────────────────────────────────────────────

    def peek(self) -> _Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _expect_term_after(self, tok: _Tok) -> None:
        nxt = self.peek()
        if nxt is None or nxt.word in ("OR", "AND", ")"):
            raise QueryError(f"{tok.text} needs a term after it.", tok.start, tok.end)

    def or_(self) -> tuple[str, list]:
        parts = [self.and_()]
        while (tok := self.peek()) is not None and tok.word == "OR":
            self.i += 1
            self._expect_term_after(tok)
            parts.append(self.and_())
        return _join(parts, " OR ")

    def and_(self) -> tuple[str, list]:
        parts = [self.unary()]
        while (tok := self.peek()) is not None and tok.word not in ("OR", ")"):
            if tok.word == "AND":
                self.i += 1
                self._expect_term_after(tok)
            parts.append(self.unary())
        return _join(parts, " AND ")

    def unary(self) -> tuple[str, list]:
        tok = self.peek()
        if tok is None:
            raise QueryError("The query ends where a term was expected.", len(self.raw), len(self.raw))
        if tok.word in ("-", "NOT"):
            self.i += 1
            if self.peek() is None:
                raise QueryError(f"{tok.text} needs a term after it.", tok.start, tok.end)
            sql, params = self.unary()
            return f"(NOT coalesce({sql}, FALSE))", params
        return self.atom()

    def atom(self) -> tuple[str, list]:
        tok = self.peek()
        assert tok is not None
        if tok.word == "(":
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise QueryError(f"Parentheses nest at most {MAX_DEPTH} deep.", tok.start, tok.end)
            self.i += 1
            if (nxt := self.peek()) is not None and nxt.word == ")":
                raise QueryError("Empty parentheses.", tok.start, nxt.end)
            sql, params = self.or_()
            close = self.peek()
            if close is None or close.word != ")":
                raise QueryError("A '(' is never closed.", tok.start, tok.end)
            self.i += 1
            self.depth -= 1
            return f"({sql})", params
        if tok.word == ")":
            raise QueryError("A ')' closes no '('.", tok.start, tok.end)
        if tok.word in ("OR", "AND"):
            raise QueryError(f"{tok.text} needs a term before it.", tok.start, tok.end)
        self.i += 1
        return self.term(tok)

    # ── terms ────────────────────────────────────────────────────────────────

    def term(self, tok: _Tok) -> tuple[str, list]:
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise QueryError(f"At most {MAX_TERMS} terms.", tok.start, tok.end)
        text = tok.text
        negated = self.raw[tok.start] == "-" and len(text) > 1
        if negated:
            text = text[1:]
        if tok.quoted:
            sql, params = self.bare_word(text, tok)
        else:
            name, sep, value = text.partition(":")
            if sep and name and self._is_field_term(name, value):
                sql, params = self.field_term(name, value, tok)
            else:
                sql, params = self.bare_word(text, tok)
        return (f"(NOT coalesce({sql}, FALSE))", params) if negated else (sql, params)

    def _is_field_term(self, name: str, value: str) -> bool:
        if name.startswith(".") or name.lower() in SHORTCUTS or self.schema.resolve(name):
            return True
        # Not a field: a value that happens to hold a colon stays a text search.
        return not (_VALUE_LIKE.match(name) or value[:1] in ("\\", "/", ":"))

    def field_term(self, name: str, value: str, tok: _Tok) -> tuple[str, list]:
        forced = name.startswith(".")
        bare_name = name[1:] if forced else name
        if not forced and bare_name.lower() in SHORTCUTS:
            return self.shortcut(bare_name.lower(), value, tok)
        column = self.schema.resolve(bare_name)
        if column is None:
            known = {name.lower(): name for name in self.schema.columns} | {s: f"{s}:" for s in SHORTCUTS}
            close = tuple(known[m] for m in difflib.get_close_matches(bare_name.lower(), list(known), n=3, cutoff=0.6))
            hint = f" Did you mean {', '.join(close)}?" if close else ""
            raise QueryError(f"This log has no field {bare_name!r}.{hint}", tok.start, tok.end, close)
        self.fields.append(column)
        return _column_match(_ident(column), self.schema.columns[column], value, self._value_quoted(tok), column, tok)

    def _value_quoted(self, tok: _Tok) -> bool:
        return '"' in self.raw[tok.start : tok.end]

    def bare_word(self, text: str, tok: _Tok) -> tuple[str, list]:
        core = text.lower().strip("*")
        if not core:
            return "(TRUE)", []
        if not self.schema.text_index:
            raise QueryError("This log was indexed without free-text search: name a field (Field:value).", tok.start, tok.end)
        self.bare.append(core)
        if len(self.bare) > MAX_BARE_WORDS:
            raise QueryError(f"At most {MAX_BARE_WORDS} free-text words; name a field for the rest.", tok.start, tok.end)
        self.needs.add("text")
        if "*" in core:
            pattern, escaped = _like_pattern("*" + core + "*")
            test = f"_lt_text LIKE ?{_ESCAPE if escaped else ''}"
            return f"(_lt_uid IN (SELECT _lt_uid FROM {TEXT} WHERE {test}))", [pattern]  # noqa: S608 — table names are module constants; values are bound
        return f"(_lt_uid IN (SELECT _lt_uid FROM {TEXT} WHERE contains(_lt_text, ?)))", [core]  # noqa: S608 — table names are module constants; values are bound

    # ── shortcuts ────────────────────────────────────────────────────────────

    def shortcut(self, key: str, value: str, tok: _Tok) -> tuple[str, list]:
        quoted = self._value_quoted(tok)
        if key == "host":
            return _column_match("_lt_host", "VARCHAR", value, quoted, "host", tok)
        if key == "channel":
            return _column_match("_lt_channel", "VARCHAR", value, quoted, "channel", tok)
        if key == "eid":
            return _column_match("_lt_eid", "BIGINT", value, quoted, "eid", tok)
        if key == "has":
            column = self.schema.resolve(value.lstrip("."))
            if column is None:
                raise QueryError(f"This log has no field {value!r}.", tok.start, tok.end)
            self.fields.append(column)
            return f"({_ident(column)} IS NOT NULL)", []
        if key == "user":
            columns = [c for c in (self.schema.resolve(f) for f in USER_FIELDS) if c]
            if not columns:
                raise QueryError("This log has no user field.", tok.start, tok.end)
            parts = [_column_match(_ident(c), self.schema.columns[c], value, quoted, c, tok) for c in dict.fromkeys(columns)]
            self.fields.extend(columns)
            sql, params = _join(parts, " OR ")
            return f"({sql})", params
        if key in ("after", "before"):
            when = parse_time(value)
            if when is None:
                raise QueryError(f"{key}: needs a date or time, like 2026-01-31 or 2026-01-31T14:00.", tok.start, tok.end)
            return ("(_lt_time >= ?)" if key == "after" else "(_lt_time < ?)"), [when]
        if key == "hour":
            return _hour(value, tok)
        if key == "weekday":
            return _weekday(value, tok)
        return self.detection(key, value, tok)

    def detection(self, key: str, value: str, tok: _Tok) -> tuple[str, list]:
        if not self.schema.overlay:
            raise QueryError("Detections are not linked to this log's events yet.", tok.start, tok.end)
        if key == "det":
            answer = value.lower()
            if answer not in _YES + _NO:
                raise QueryError("det: takes yes or no.", tok.start, tok.end)
            self.needs.add("levels")
            sql = f"(_lt_uid IN (SELECT _lt_uid FROM {LEVELS_TABLE}))"  # noqa: S608 — table names are module constants; values are bound
            return (sql, []) if answer in _YES else (f"(NOT {sql})", [])
        if key == "level":
            op, name = _split_compare(value)
            rank = _LEVEL_ALIASES.get(name.lower())
            if rank is None:
                raise QueryError(f"level: takes one of {', '.join(LEVELS)}.", tok.start, tok.end)
            self.needs.add("levels")
            return f"(_lt_uid IN (SELECT _lt_uid FROM {LEVELS_TABLE} WHERE level_rank {op or '='} ?))", [rank]  # noqa: S608 — table names are module constants; values are bound
        if not value:
            raise QueryError(f"{key}: needs a value.", tok.start, tok.end)
        matched = sorted({r.ix for r in self.schema.rules if _rule_matches(key, value, r)})
        self.needs.add("hits")
        if not matched:
            return "(FALSE)", []
        ids = ", ".join(str(int(ix)) for ix in matched)  # our own integers, never user text
        return f"(_lt_uid IN (SELECT _lt_uid FROM {HITS} WHERE rule_ix IN ({ids})))", []  # noqa: S608 — table names are module constants; values are bound


# ── value matching ───────────────────────────────────────────────────────────

_ESCAPE = " ESCAPE '\\'"


def _join(parts: list[tuple[str, list]], op: str) -> tuple[str, list]:
    if len(parts) == 1:
        return parts[0]
    params: list = []
    for _sql, p in parts:
        params.extend(p)
    return op.join(sql for sql, _p in parts), params


def _like_pattern(value: str) -> tuple[str, bool]:
    """`*` → `%`; literal `%`, `_` and `\\` escaped. Returns (pattern, needs_escape)."""
    escaped = any(ch in value for ch in "%_\\")
    pieces = [re.sub(r"([%_\\])", r"\\\1", piece) if escaped else piece for piece in value.split("*")]
    return "%".join(pieces), escaped


def _split_compare(value: str) -> tuple[str | None, str]:
    for op in _COMPARE:
        if value.startswith(op):
            return op, value[len(op) :]
    return None, value


def _number(text: str) -> int | float | None:
    text = text.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        pass
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def _column_match(col: str, ctype: str, value: str, quoted: bool, label: str, tok: _Tok) -> tuple[str, list]:
    """One column against one value, by the column's type."""
    numeric = ctype in ("BIGINT", "DOUBLE")
    if value == "" and not quoted:
        raise QueryError(f"{label}: needs a value ({label}:* matches any).", tok.start, tok.end)
    if value and not value.strip("*"):
        return f"({col} IS NOT NULL)", []
    op, rest = _split_compare(value)
    if op is not None:
        number = _number(rest)
        if number is None:
            raise QueryError(f"{op} compares numbers; {rest!r} is not one.", tok.start, tok.end)
        target = col if numeric else f"TRY_CAST({col} AS DOUBLE)"
        return f"({target} {op} ?)", [number if ctype == "BIGINT" or not isinstance(number, int) else float(number)]
    exact = value.startswith("=")
    if exact:
        value = value[1:]
    if numeric and not ("*" in value and not exact):
        numbers = [_number(v) for v in value.split(",")] if value else [None]
        if any(n is None for n in numbers):
            raise QueryError(f"{label} holds numbers; {value!r} is not one.", tok.start, tok.end)
        if ctype == "BIGINT" and any(isinstance(n, float) and not n.is_integer() for n in numbers):
            return "(FALSE)", []
        cast = [int(n) if ctype == "BIGINT" else float(n) for n in numbers]
        if len(cast) == 1:
            return f"({col} = ?)", cast
        return f"({col} IN ({', '.join('?' * len(cast))}))", cast
    target = f"CAST({col} AS VARCHAR)" if numeric else f"lower({col})"
    lowered = value.lower()
    if exact or "*" not in lowered:
        return f"({target} = ?)", [lowered]
    inner = lowered.strip("*")
    if "*" not in inner:
        lead, trail = lowered.startswith("*"), lowered.endswith("*")
        func = "contains" if lead and trail else ("ends_with" if lead else "starts_with")
        return f"({func}({target}, ?))", [inner]
    pattern, escaped = _like_pattern(lowered)
    return f"({target} LIKE ?{_ESCAPE if escaped else ''})", [pattern]


def _wild(value: str, text: str) -> bool:
    """The grammar's wildcard rule applied in Python (rule names, tools, techniques)."""
    value, text = value.lower(), (text or "").lower()
    if value.startswith("="):
        return value[1:] == text
    if "*" not in value:
        return value == text
    regex = "^" + ".*".join(re.escape(p) for p in value.split("*")) + "$"
    return re.match(regex, text, re.DOTALL) is not None


def _norm_tactic(name: str) -> str:
    return re.sub(r"[\s\-]+", "_", name.strip().lower())


def _rule_matches(key: str, value: str, rule: Rule) -> bool:
    if key == "rule":
        return _wild(value, rule.name)
    if key == "rulekey":
        return _wild(value, rule.key)
    if key == "tool":
        return _wild(value, rule.tool)
    if key == "tactic":
        return any(_wild(_norm_tactic(value), _norm_tactic(t)) for t in rule.tactics)
    # technique:T1059 also matches its sub-techniques (T1059.001).
    want = value.upper()
    return any(_wild(want, t) or t.upper().startswith(want + ".") for t in rule.techniques)


def _hour(value: str, tok: _Tok) -> tuple[str, list]:
    hours: set[int] = set()
    for part in value.split(","):
        lo, sep, hi = part.partition("-")
        try:
            a, b = int(lo), int(hi) if sep else int(lo)
        except ValueError:
            raise QueryError("hour: takes hours 0-23, a range like 9-17, or a list like 8,20.", tok.start, tok.end) from None
        if not (0 <= a <= 23 and 0 <= b <= 23):
            raise QueryError("hour: takes hours 0-23.", tok.start, tok.end)
        hours.update(range(a, b + 1) if a <= b else [*range(a, 24), *range(0, b + 1)])  # 22-6 wraps
    ids = ", ".join(str(h) for h in sorted(hours))
    return f"(hour(_lt_time) IN ({ids}))", []


def _weekday(value: str, tok: _Tok) -> tuple[str, list]:
    def day(text: str) -> int:
        text = text.strip().lower()
        if text[:3] in _WEEKDAYS:
            return _WEEKDAYS[text[:3]]
        if text.isdigit() and 1 <= int(text) <= 7:
            return int(text)
        raise QueryError("weekday: takes mon…sun or 1-7 (Monday is 1), a range like mon-fri, or a list.", tok.start, tok.end)

    days: set[int] = set()
    for part in value.split(","):
        lo, sep, hi = part.partition("-")
        a, b = day(lo), day(hi) if sep else day(lo)
        days.update(range(a, b + 1) if a <= b else [*range(a, 8), *range(1, b + 1)])
    return f"(isodow(_lt_time) IN ({', '.join(str(d) for d in sorted(days))}))", []


def column_filter_to_terms(column: str, cell: str, *, shortcut: bool = False) -> str:
    """A filter-row cell (`x`, `=x`, `!x`, `>=1`, `*`, `!*`) as a query term for *column*.

    The filter row is a way of writing the query, not a second filter: its terms go into `q`,
    so the box always shows what is applied and a copied URL reproduces it.
    """
    cell = (cell or "").strip()
    if not cell:
        return ""
    negate = cell.startswith("!")
    if negate:
        cell = cell[1:].strip()
    if cell == "*":
        body = "*"
    elif cell.startswith("="):
        body = "=" + cell[1:]
    elif _split_compare(cell)[0] is not None:
        body = cell
    else:
        body = "*" + cell.strip("*") + "*"
    if '"' in body:
        # A quote cannot sit inside a quoted value; it becomes a one-place wildcard, so an
        # exact term turns into a wildcard one (still matching the value it came from).
        body = (body[1:] if body.startswith("=") else body).replace('"', "*")
    if any(ch.isspace() or ch in "()" for ch in body):
        body = f'"{body}"'
    # A column sharing a shortcut's name is reached with a leading dot; *shortcut* means the
    # caller asked for the shortcut itself (host:, channel:, eid: for the fixed columns).
    name = f".{column}" if column.lower() in SHORTCUTS and not shortcut else column
    return f"{'-' if negate else ''}{name}:{body}"
