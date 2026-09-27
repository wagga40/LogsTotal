"""Advanced entity-search query primitives — CIDR, regex, wildcard, literal.

Pure-Python module: no FastAPI, no async. Used by /intel/entities-partial and by
saved searches. Designed to be safe against pathological user input:
  * Regex: length-capped, nested-quantifier rejected, matched case-insensitively in
    Python over whatever rows SQL returned — a regex term adds no SQL narrowing of its
    own, so the caller must bound the window (see `query_needs_post_filter`).
  * CIDR: parsed via `ipaddress`; mismatched address family yields zero results.
  * Wildcard: `*` is converted to SQL LIKE `%`; literal LIKE characters are escaped.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections.abc import Callable, Collection
from datetime import datetime
from typing import Any

import regex
from sqlalchemy import Select, and_, false, func, or_, select

from app.constants import ENTITY_TYPES
from app.database import parse_row_id
from app.json_utils import dumps as _json_dumps
from app.models import Entity, EntityJobLink, EntityTag, RuleList, RuleListValue

_log = logging.getLogger(__name__)

REGEX_MAX_LEN = 200
QUERY_KINDS = ("literal", "wildcard", "regex", "cidr", "attr", "tag", "job", "type", "list", "inset")

# `tag:a,b` is a pivot affordance, so multiple tags widen the net (any-of), matching how
# the `types` CSV already behaves. The cap keeps the IN-list bounded.
TAG_QUERY_MAX = 10

# `job:1,2` is any-of for the same reason, and bounded for the same reason.
JOB_QUERY_MAX = 10

# `type:` accepts the canonical keys. `ip` is aliased because `ip_address` is the one key
# nobody guesses; everything else is either the word itself or listed back in the error.
TYPE_ALIASES = {"ip": "ip_address", "ips": "ip_address", "exe": "executable", "cmdline": "cmdline_file"}

# EntityTag.tag is String(50) and always stored lowercased. The read path (`tag:`
# queries, the `tags` filter) must normalize identically to the write path in
# `app/tags.py::parse_tag_write`, or `tag:APT28` silently misses a stored `apt28`.
TAG_MAX_LENGTH = 50


def normalize_tag(raw: str) -> str:
    """Lowercase, strip and clamp a tag to the column width."""
    return (raw or "").strip().lower()[:TAG_MAX_LENGTH]


# Regex matching runs on the third-party ``regex`` engine, which supports a
# per-call ``timeout``. Even a catastrophic-backtracking pattern that slips past
# the cheap nested-quantifier pre-check is bounded by REGEX_MATCH_BUDGET_S total
# wall-clock across the scanned rows, with each value truncated to REGEX_INPUT_MAX.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")
REGEX_MATCH_BUDGET_S = 0.25
REGEX_INPUT_MAX = 1024

# `attr:<key>` filters map to a (field, value) pair inside Entity.attributes_json
# (see app/intel/attributes.py). The SQL match is a LIKE on a fragment built with
# the same serializer used to write the column, so spacing always lines up.
ATTR_FILTERS: dict[str, tuple[str, object]] = {
    "private": ("is_private", True),
    "public": ("category", "public"),
    "rfc1918": ("category", "rfc1918"),
    "cgnat": ("category", "cgnat"),
    "loopback": ("category", "loopback"),
    "link_local": ("category", "link_local"),
    "multicast": ("category", "multicast"),
    "reserved": ("category", "reserved"),
    "signed_path": ("looks_signed_keyword", True),
    "dga": ("looks_dga", True),
    "suspicious_tld": ("suspicious_tld", True),
    "lolbin": ("is_lolbin", True),
    "gtfobin": ("is_gtfobin", True),
    "machine": ("is_machine_account", True),
    "privileged": ("looks_privileged", True),
    "md5": ("algorithm", "md5"),
    "sha1": ("algorithm", "sha1"),
    "sha256": ("algorithm", "sha256"),
    "sha512": ("algorithm", "sha512"),
}

_ATTR_ALIASES = {"suspicious": "suspicious_tld", "machine_account": "machine", "priv": "privileged"}


def _attr_fragment(field: str, value: object) -> str:
    """Serialize {field: value} with the column's serializer; strip the wrapping braces."""
    return _json_dumps({field: value})[1:-1]


def escape_like(raw: str) -> str:
    """Escape SQL LIKE metacharacters so a search term matches itself literally.

    Backslash first, or the escapes we add would themselves be escaped. Used by both the
    wildcard branch (which then translates ``*`` → ``%``) and the literal branch — unescaped,
    a search for the literal ``admin_1`` would match ``admin-1`` too, and a bare ``%`` every
    entity.
    """
    return raw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def parse_search_query(raw: str) -> dict[str, Any]:
    """Parse an entity search query into a tagged dict.

    Syntax:
      * `label:<key>`       → a system attribute if the registry knows it, else an analyst tag
      * `tag:a,b`           → analyst tags, any-of
      * `attr:<key>`        → derived attribute only
      * `type:ip_address`   → entity type
      * `job:42`            → seen in this job (needs `resolve_job_terms` before use)
      * `list:lolbas`       → in a named list (Rules → Lists)
      * `cidr:1.2.3.0/24`   → inside any of the comma-separated networks (IPv4 or IPv6)
      * `re:/<pattern>/`    → Python regex (case-insensitive); pattern must be safe
      * `<term>*` or `*<term>*` → wildcard (`*` → SQL `%`)
      * anything else       → literal substring (ilike `%term%`)

    Returns a dict with at minimum `{"kind": <kind>, "raw": <raw>}` plus kind-specific
    fields. Invalid input falls back to literal kind with an `error` field.

    Single-term only, and a thin wrapper over `_parse_term` so it can never disagree with
    `parse_query` about what one term means. No app code calls it; it is the stable
    single-term entry point, exercised by tests/test_intel_query_grammar.py.
    """
    return _parse_term(raw)


def _parse_term(raw: str) -> dict[str, Any]:
    """Parse exactly one query term. The single source of truth for term semantics."""
    raw = (raw or "").strip()
    if not raw:
        return {"kind": "literal", "raw": "", "value": ""}

    lowered = raw.lower()
    if lowered.startswith("label:"):
        # One token, two possible sources. Resolution is syntactic — no DB — so this
        # module stays pure: a key the attribute registry knows is a system label,
        # anything else is an analyst tag. System wins on collision; `attr:` and `tag:`
        # remain available as unambiguous escape hatches.
        key = _ATTR_ALIASES.get(raw[6:].strip().lower(), raw[6:].strip().lower())
        if key in ATTR_FILTERS:
            field, value = ATTR_FILTERS[key]
            return {"kind": "attr", "raw": raw, "attr_key": key, "fragment": _attr_fragment(field, value)}
        tags = parse_tags_csv(raw[6:])
        if not tags:
            return {"kind": "literal", "raw": raw, "value": raw, "error": "label: needs a value"}
        return {"kind": "tag", "raw": raw, "tags": tags}

    if lowered.startswith("tag:"):
        tags = parse_tags_csv(raw[4:])
        if not tags:
            return {"kind": "literal", "raw": raw, "value": raw, "error": "tag: needs a value"}
        return {"kind": "tag", "raw": raw, "tags": tags}

    if lowered.startswith("type:"):
        wanted = [TYPE_ALIASES.get(p.strip().lower(), p.strip().lower()) for p in raw[5:].split(",") if p.strip()]
        if not wanted:
            return {"kind": "literal", "raw": raw, "value": raw, "error": "type: needs an entity type"}
        unknown = [t for t in wanted if t not in ENTITY_TYPES]
        if unknown:
            return {"kind": "literal", "raw": raw, "value": raw, "error": f"unknown type: {unknown[0]!r} — try one of {', '.join(ENTITY_TYPES)}"}
        return {"kind": "type", "raw": raw, "types": list(dict.fromkeys(wanted))}

    if lowered.startswith("job:"):
        # Ids only — no visibility check here, because this module is pure and has no user.
        # `resolve_job_terms` is the required companion; an unresolved job term is applied
        # as "match nothing" so that forgetting to call it cannot leak a private job's
        # entity set. See the note on `apply_entity_filters`.
        raw_ids = [p.strip() for p in raw[4:].split(",") if p.strip()]
        if not raw_ids:
            return {"kind": "literal", "raw": raw, "value": raw, "error": "job: needs a job id"}
        bad = [p for p in raw_ids if parse_row_id(p) is None]
        if bad:
            return {"kind": "literal", "raw": raw, "value": raw, "error": f"job: needs a numeric id, got {bad[0]!r}"}
        ids = list(dict.fromkeys(int(p) for p in raw_ids))[:JOB_QUERY_MAX]
        return {"kind": "job", "raw": raw, "job_ids": ids, "resolved": False}

    if lowered.startswith("attr:"):
        key = raw[5:].strip().lower()
        key = _ATTR_ALIASES.get(key, key)
        spec = ATTR_FILTERS.get(key)
        if spec is None:
            return {"kind": "literal", "raw": raw, "value": raw, "error": f"unknown attr: {key}"}
        field, value = spec
        return {"kind": "attr", "raw": raw, "attr_key": key, "fragment": _attr_fragment(field, value)}

    if lowered.startswith("list:"):
        return _parse_list_term(raw)

    if lowered.startswith("in:"):
        return _parse_inset_term(raw)

    if lowered.startswith("cidr:"):
        return _parse_cidr_term(raw)

    if lowered.startswith("re:/") and raw.endswith("/") and len(raw) > 5:
        pattern = raw[4:-1]
        if len(pattern) > REGEX_MAX_LEN:
            return {"kind": "literal", "raw": raw, "value": raw, "error": f"regex >{REGEX_MAX_LEN} chars"}
        if _NESTED_QUANTIFIER_RE.search(pattern):
            return {"kind": "literal", "raw": raw, "value": raw, "error": "regex contains nested quantifier"}
        try:
            compiled = regex.compile(pattern, regex.IGNORECASE)
            return {"kind": "regex", "raw": raw, "pattern": compiled}
        except regex.error as exc:
            return {"kind": "literal", "raw": raw, "value": raw, "error": f"invalid regex: {exc}"}

    if "*" in raw:
        # Escape SQL LIKE metas, then translate `*` → `%`. Underscore stays literal.
        escaped = escape_like(raw).replace("*", "%")
        # If the user wrote no leading/trailing `*` we still want substring semantics.
        if not escaped.startswith("%"):
            escaped = "%" + escaped
        if not escaped.endswith("%"):
            escaped = escaped + "%"
        return {"kind": "wildcard", "raw": raw, "pattern": escaped}

    return {"kind": "literal", "raw": raw, "value": raw}


# `cidr:a,b,…` compiles to an `or_()` of coarse prefixes, so it is bounded like `tag:a,b`.
# Sixteen fits the widest shipped rule — `public` negates thirteen special-purpose blocks.
CIDR_QUERY_MAX = 16


_LIST_NAME_RE = re.compile(r"^[a-z0-9_]{1,50}$")


def _parse_list_term(raw: str) -> dict[str, Any]:
    """`list:<name>` — membership in a named list (Rules → Lists), one name per term.

    Nothing is resolved here: this module is pure and the lists live in the database, so the
    term carries only the name and `_term_clause` compiles it to an EXISTS the database
    answers. That is also what lets `list:` sit under an `OR`, which `re:`/`cidr:` cannot.
    Whether the name exists is a separate question — `unknown_list_errors` answers it for
    the callers that can ask the database, and the form refuses a rule that names nothing.
    """
    name = raw[5:].strip().lower()
    if not name:
        return {"kind": "literal", "raw": raw, "value": raw, "error": "list: needs a list name"}
    if not _LIST_NAME_RE.match(name):
        return {"kind": "literal", "raw": raw, "value": raw, "error": f"list: names are lowercase letters, digits and underscores, one per term — not {name!r}"}
    return {"kind": "list", "raw": raw, "name": name}


#: `in:(a,b,c)` is a list too small to deserve a name. Twenty is where "I am spelling out a
#: handful of binaries" becomes "I am maintaining a list in a text field" — past it the
#: editor offers to promote the set to a real `RuleList`, which is versioned, described,
#: reusable and searchable, none of which a literal in one condition is.
MAX_INSET_VALUES = 20


def _parse_inset_term(raw: str) -> dict[str, Any]:
    """`in:(a,b,c)` — the value is exactly one of these.

    A `list:` without the list. The named kind earns its keep when a set is shared between
    rules, described, or long; spelling out two binaries should not require creating and
    naming a row first.

    **Exact, matching `RuleList`'s default match kind** — not substring, which a bare term
    already gives, and not suffix, which `(*.tk OR *.top)` already gives. Compiled to a
    plain `IN`, so unlike `re:`/`cidr:` this may sit under an `OR`; the values are known at
    parse time, which is the same thing that makes `list:` OR-safe.
    """
    body = raw[3:]
    if not (body.startswith("(") and body.endswith(")")):
        return {"kind": "literal", "raw": raw, "value": raw, "error": "in: needs a parenthesised set, as in:(a,b,c)"}
    values = [p.strip().lower() for p in body[1:-1].split(",")]
    values = list(dict.fromkeys(v for v in values if v))
    if not values:
        return {"kind": "literal", "raw": raw, "value": raw, "error": "in: needs at least one value"}
    if len(values) > MAX_INSET_VALUES:
        return {"kind": "literal", "raw": raw, "value": raw, "error": f"in: takes at most {MAX_INSET_VALUES} values — make it a list instead"}
    return {"kind": "inset", "raw": raw, "values": values}


def _parse_cidr_term(raw: str) -> dict[str, Any]:
    """`cidr:<net>[,<net>…]` — inside any of up to `CIDR_QUERY_MAX` networks, the `tag:a,b` idiom.

    A comma list because the address-space labels are unions: RFC1918 is three ranges, and
    "public" is spelled as a negated list of every special-purpose block.
    """
    specs = [p.strip() for p in raw[5:].split(",") if p.strip()]
    if not specs:
        return {"kind": "literal", "raw": raw, "value": raw, "error": "cidr: needs a network"}
    if len(specs) > CIDR_QUERY_MAX:
        return {"kind": "literal", "raw": raw, "value": raw, "error": f"cidr: at most {CIDR_QUERY_MAX} networks"}
    networks = []
    for spec in specs:
        try:
            networks.append(ipaddress.ip_network(spec, strict=False))
        except (ValueError, TypeError) as exc:
            return {"kind": "literal", "raw": raw, "value": raw, "error": f"invalid CIDR: {exc}"}
    return {"kind": "cidr", "raw": raw, "networks": networks}


# A conjunction is bounded so one query cannot emit an unbounded pile of EXISTS/LIKE
# clauses, and regex terms are bounded harder because they all share one CPU budget.
MAX_TERMS = 12
MAX_REGEX_TERMS = 2

# What makes a query "structured" — and therefore parsed term by term rather than as one
# whole phrase. A prefix missing here still parses when it stands alone but is swallowed
# into a literal the moment the query has two terms.
_PREFIXES = ("label:", "tag:", "attr:", "list:", "cidr:", "re:/", "job:", "type:", "in:")

#: Everything the entity search box understands, as `(syntax, what it does)`.
#:
#: The twin of `jobs_query.SYNTAX_HELP`, and it exists for the same reason: the help panel
#: is generated from the list the parser reads, so a term cannot be documented and
#: unimplemented, or implemented and undiscoverable.
SYNTAX_INTRO = "Terms are AND-ed. Prefix any with - to exclude."
SYNTAX_HELP: list[tuple[str, str]] = [
    ("svchost", "value contains this"),
    ('"exact phrase"', "…with spaces"),
    ("svc-*", "wildcard"),
    ("label:lolbin", "a derived attribute or one of your tags"),
    ("tag:apt28,c2", "carries any of these tags"),
    ("attr:dga", "derived attribute only"),
    ("list:lolbas", "in a named list (Rules → Lists)"),
    ("in:(psexec.exe,wmic.exe)", "…or a set too small to name"),
    ("type:ip_address", "entity type"),
    ("job:42", "seen in a job you can open"),
    ("cidr:10.0.0.0/8,172.16.0.0/12", "IPs inside any of these networks"),
    ("re:/^admin\\..*/", "regular expression"),
    ("-tag:known-good", "any term can be negated"),
    ("(tag:a OR tag:b) -tag:x", "AND binds tighter than OR"),
]

# Boolean grammar. Operators are **bare uppercase words only** and parentheses only group
# when the query is already structured — see `_is_boolean` for why that asymmetry is
# load-bearing rather than fussy.
_OR = "OR"
_AND = "AND"
MAX_GROUP_DEPTH = 8

# Post-filtered kinds: matched in Python, contributing no SQL narrowing. Sound under AND
# (the SQL result is a superset the filter then narrows) and *unsound* under OR, where the
# branch would have to contribute rows SQL never fetched. `_validate_tree` rejects them
# there rather than returning quietly wrong counts. `list:` is deliberately not here: its
# values are known at parse time and compile to SQL, so it is as OR-safe as `tag:`.
_POST_FILTERED_KINDS = ("regex", "cidr")


def scan_query(raw: str, *, split_groups: bool = False) -> list[tuple[int, int, str]]:
    """Scan a query into `(start, end, token)` spans over the *original* string.

    The single scanner. `tokenize_query` is the text-only view of it and `caret_token` is
    the positional one, so the search box's autocomplete cannot disagree with the parser
    about where one term ends and the next begins — which is the entire reason the caret
    logic lives in this module rather than in JavaScript.

    `re:/…/` needs its own pass because a regex may legitimately contain spaces
    (`re:/^svc a/`), and splitting it on whitespace would turn one valid pattern into two
    junk terms. `token` is the *processed* text (quotes stripped, negation carried as a
    leading `-`); `raw[start:end]` is what the analyst actually typed, which is what a
    completion has to replace.

    With `split_groups`, `(` and `)` become standalone spans even when glued to a term.
    They are split *after* the quoted and `re:/…/` passes, so `re:/(a|b)/` and `"(literal)"`
    keep their parentheses — a regex full of grouping parens must not be shredded into
    grammar.
    """
    spans: list[tuple[int, int, str]] = []
    i, n = 0, len(raw)
    while i < n:
        if raw[i].isspace():
            i += 1
            continue
        if split_groups and raw[i] in "()":
            spans.append((i, i + 1, raw[i]))
            i += 1
            continue
        # A quoted run, optionally negated (`-"enc"`). Quotes are stripped from the token
        # and the negation is carried as a leading `-`, so callers see one uniform shape.
        start = i
        quote_at = i + 1 if raw[i] == "-" and i + 1 < n and raw[i + 1] == '"' else (i if raw[i] == '"' else -1)
        if quote_at != -1:
            neg_prefix = "-" if quote_at != i else ""
            j = raw.find('"', quote_at + 1)
            if j == -1:
                spans.append((start, n, neg_prefix + raw[quote_at + 1 :]))
                break
            spans.append((start, j + 1, neg_prefix + raw[quote_at + 1 : j]))
            i = j + 1
            continue
        rest = raw[i:]
        neg = rest.startswith("-")
        probe = rest[1:] if neg else rest
        if probe.lower().startswith("re:/"):
            # Scan to the closing unescaped '/'.
            j = i + (1 if neg else 0) + 4
            while j < n:
                if raw[j] == "\\":
                    j += 2
                    continue
                if raw[j] == "/":
                    break
                j += 1
            end = min(j + 1, n)
            spans.append((start, end, raw[start:end]))
            i = end
            continue
        if probe.lower().startswith("in:("):
            # `in:(a,b,c)` is one token, parens and all. Its own pass for the same reason
            # `re:/…/` has one: the generic walk below ends a term at whitespace and — under
            # `split_groups` — at a parenthesis, either of which would shred one valid set
            # into junk terms and, worse, feed its `(` to the boolean parser as grouping.
            j = raw.find(")", i)
            end = n if j == -1 else j + 1
            spans.append((start, end, raw[start:end]))
            i = end
            continue
        j = i
        while j < n and not raw[j].isspace() and not (split_groups and raw[j] in "()"):
            j += 1
        spans.append((start, j, raw[start:j]))
        i = j
    return spans


def tokenize_query(raw: str, *, split_groups: bool = False) -> list[str]:
    """Terms only — the text view of `scan_query`."""
    return [text for _s, _e, text in scan_query(raw, split_groups=split_groups)]


# Recognised as a completable prefix even mid-word: `re:/` is included because its opening
# slash is part of the prefix rather than the value.
_COMPLETABLE = ("label:", "tag:", "attr:", "list:", "cidr:", "job:", "type:", "re:/")


def caret_token(raw: str, pos: int, prefixes: tuple[str, ...] = _COMPLETABLE) -> dict[str, Any]:
    """What the caret is sitting in, and the span a completion would replace.

    Returns ``{"start", "end", "text", "prefix", "fragment"}``. ``prefix`` is the
    ``key:`` the analyst has committed to (``None`` when they are still typing the key
    itself, in which case ``fragment`` is the partial key and the caller should offer
    prefixes). ``start``/``end`` bound the *typed* characters, so replacing that slice
    edits only the term under the caret and leaves the rest of a boolean query intact.

    A caret at a token's end still belongs to that token — that is the ordinary case of
    typing at the end of a word, and the whole feature is useless without it.

    ``prefixes`` defaults to the entity grammar's keys and is passed explicitly by the jobs
    list, whose grammar shares this scanner but names different things. Parameterising it
    here rather than writing a second caret parser is the same decision that put this
    function in Python at all: the caret rules have to agree with the tokenizer about where
    a term begins and ends, and two implementations of that will drift.
    """
    raw = raw or ""
    pos = max(0, min(int(pos), len(raw)))
    for start, end, _text in scan_query(raw, split_groups=True):
        if start <= pos <= end and raw[start:end] not in ("(", ")"):
            typed = raw[start:end]
            body = typed[1:] if typed.startswith("-") else typed
            lowered = body.lower()
            for pref in prefixes:
                if lowered.startswith(pref):
                    return {"start": start, "end": end, "text": typed, "prefix": pref, "fragment": body[len(pref) :]}
            # Uppercase operators are grammar, not something to complete.
            if body in (_OR, _AND):
                return {"start": start, "end": end, "text": typed, "prefix": None, "fragment": ""}
            return {"start": start, "end": end, "text": typed, "prefix": None, "fragment": body}
    return {"start": pos, "end": pos, "text": "", "prefix": None, "fragment": ""}


def _is_boolean(raw: str) -> bool:
    """Does this query opt into the boolean grammar?

    Two ways in, and the asymmetry between them is what keeps plain phrases stable:

      * a bare uppercase ``OR``/``AND`` token — lowercase ``or`` is left alone, because
        ``powershell or cmd`` is a phrase somebody may have saved and it must keep its
        meaning;
      * parentheses, but *only* when the query is already structured. ``powershell
        (encoded)`` has no prefix and no operator, so it stays a literal phrase, while
        ``tag:a (tag:b OR tag:c)`` groups.

    Saved searches and watch rules are stored as raw text and re-parsed on every use, so a
    grammar that reinterpreted them would silently change what existing alerts fire on.
    """
    toks = tokenize_query(raw, split_groups=True)
    if any(t in (_OR, _AND) for t in toks):
        return True
    return ("(" in toks or ")" in toks) and _is_structured(raw)


def _is_structured(raw: str) -> bool:
    """Does this query use syntax that makes whitespace a term separator?

    A bare leading ``-`` deliberately does NOT count. ``powershell -enc payload`` is a
    real, common search where ``-enc`` is part of the phrase, not a negation — treating it
    as structured would silently change what every such saved search matches. Negating a
    plain literal is spelled ``-"enc"``, which is structured because of the quotes.
    """
    if '"' in raw:
        return True
    return any((tok[1:] if tok.startswith("-") else tok).lower().startswith(_PREFIXES) for tok in raw.split())


class _Parser:
    """Recursive descent over the token list.

        expr    := or_expr
        or_expr := and_expr (OR and_expr)*
        and_expr:= unary (AND? unary)*        # juxtaposition is AND
        unary   := '-'? primary
        primary := '(' expr ')' | term

    Nodes are ``{"op": "and"|"or", "nodes": [...]}``; leaves are the term dicts
    ``_parse_term`` returns, so one ``_term_clause`` still defines what every term means.
    Errors accumulate rather than raise: a half-typed query in a live search box should
    narrow to something sensible and say what it ignored, not blank the page.
    """

    def __init__(self, tokens: list[str]) -> None:
        self.toks = tokens
        self.i = 0
        self.errors: list[str] = []
        self.leaves: list[dict[str, Any]] = []
        self.regex_terms = 0

    def _peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def parse(self) -> dict[str, Any] | None:
        node = self._or(depth=0)
        if self._peek() == ")":
            # Unbalanced close: parsing stops here, so record it rather than reading the
            # rest as terms.
            self.errors.append("unbalanced ')' in query")
        return node

    def _or(self, depth: int) -> dict[str, Any] | None:
        nodes = [self._and(depth)]
        while self._peek() == _OR:
            self.i += 1
            nodes.append(self._and(depth))
        kept = [n for n in nodes if n is not None]
        if not kept:
            return None
        return kept[0] if len(kept) == 1 else {"op": "or", "nodes": kept}

    def _and(self, depth: int) -> dict[str, Any] | None:
        nodes = []
        while True:
            tok = self._peek()
            if tok is None or tok in (_OR, ")"):
                break
            if tok == _AND:  # explicit AND is the same as juxtaposition
                self.i += 1
                continue
            node = self._unary(depth)
            if node is not None:
                nodes.append(node)
        if not nodes:
            return None
        return nodes[0] if len(nodes) == 1 else {"op": "and", "nodes": nodes}

    def _unary(self, depth: int) -> dict[str, Any] | None:
        tok = self._peek()
        if tok is None:
            return None
        if tok == "(":
            if depth >= MAX_GROUP_DEPTH:
                self.errors.append(f"groups nested deeper than {MAX_GROUP_DEPTH} were ignored")
                self._skip_group()
                return None
            self.i += 1
            inner = self._or(depth + 1)
            if self._peek() == ")":
                self.i += 1
            else:
                self.errors.append("unbalanced '(' in query")
            return inner
        self.i += 1
        negated = tok.startswith("-") and len(tok) > 1
        if len(self.leaves) >= MAX_TERMS:
            if not any(e.startswith("only the first") for e in self.errors):
                self.errors.append(f"only the first {MAX_TERMS} terms were applied")
            return None
        term = _parse_term(tok[1:] if negated else tok)
        if term.get("kind") == "regex":
            self.regex_terms += 1
            if self.regex_terms > MAX_REGEX_TERMS:
                self.errors.append(f"only {MAX_REGEX_TERMS} regex terms are allowed")
                return None
        if term.get("error"):
            self.errors.append(term["error"])
        term["negated"] = negated
        self.leaves.append(term)
        return term

    def _skip_group(self) -> None:
        """Consume a balanced group without parsing it."""
        depth = 0
        while self.i < len(self.toks):
            tok = self.toks[self.i]
            self.i += 1
            if tok == "(":
                depth += 1
            elif tok == ")":
                depth -= 1
                if depth <= 0:
                    return


def _tree_has_or(node: dict[str, Any] | None) -> bool:
    if not node or "op" not in node:
        return False
    return node["op"] == "or" or any(_tree_has_or(child) for child in node["nodes"])


def _validate_tree(node: dict[str, Any] | None, *, under_or: bool = False) -> list[str]:
    """Reject post-filtered kinds that sit under an OR.

    `re:`/`cidr:` add no SQL narrowing — they are matched in Python over the rows SQL
    returned. As an AND conjunct that is sound, because those rows are a superset of the
    answer. Inside an OR the branch would have to *contribute* rows nothing fetched, so the
    result would silently omit matches and report a total that is not merely approximate
    but wrong. Better a precise error than a plausible lie.
    """
    if not node:
        return []
    if "op" not in node:
        if under_or and node.get("kind") in _POST_FILTERED_KINDS:
            label = "re:" if node["kind"] == "regex" else "cidr:"
            return [f"{label} cannot be combined with OR (it is matched outside the database) — use it with AND, or split the search"]
        return []
    is_or = node["op"] == "or"
    errs: list[str] = []
    for child in node["nodes"]:
        errs.extend(_validate_tree(child, under_or=under_or or is_or))
    return errs


def parse_query(raw: str) -> dict[str, Any]:
    """Parse a query into AND-ed terms.

    Terms AND together; values *inside* one term (``label:a,b``) stay any-of, matching
    ``tag:a,b``. A leading ``-`` negates a term.

    **Phrase mode is load-bearing.** If the query uses none of the structured syntax, the
    whole raw string becomes a single literal term — so a saved plain search, including
    multi-word values like ``powershell -enc``, keeps matching as one phrase. Only
    structured syntax makes whitespace mean AND.

    Returns ``{"raw", "terms": [<term dict>, …], "tree": <node|None>, "errors": [str, …]}``.
    Term dicts are the same shape ``parse_search_query`` returns, so both feed one
    ``_term_clause``.

    ``tree`` is set **only when the query actually contains an OR**. Grouping alone
    (``(a b) c``) is still a pure conjunction, so it collapses back to the flat ``terms``
    list and the flat callers — `post_filter`, the tag folding in `entities_partial`, the
    rule matcher — run unchanged. The tree is the exception.
    """
    raw = (raw or "").strip()
    if not raw:
        return {"raw": "", "terms": [], "tree": None, "errors": []}

    if _is_boolean(raw):
        parser = _Parser(tokenize_query(raw, split_groups=True))
        tree = parser.parse()
        errors = list(parser.errors)
        errors.extend(_validate_tree(tree))
        # An OR is what makes the tree load-bearing; without one the conjunction is exactly
        # what the flat path already expresses, and reusing it keeps post-filtering sound.
        has_or = _tree_has_or(tree)
        # A rejected combination makes the whole query unusable rather than partly applied:
        # running it minus the offending term would answer a different question than the
        # one on screen, and the analyst would have no way to tell.
        invalid = bool(_validate_tree(tree))
        return {"raw": raw, "terms": parser.leaves, "tree": tree if has_or else None, "errors": errors, "invalid": invalid}

    if not _is_structured(raw):
        term = _parse_term(raw)
        term["negated"] = False
        return {"raw": raw, "terms": [term], "tree": None, "errors": [term["error"]] if term.get("error") else []}

    terms: list[dict[str, Any]] = []
    errors: list[str] = []
    regex_terms = 0
    for tok in tokenize_query(raw):
        if len(terms) >= MAX_TERMS:
            errors.append(f"only the first {MAX_TERMS} terms were applied")
            break
        negated = tok.startswith("-") and len(tok) > 1
        term = _parse_term(tok[1:] if negated else tok)
        if term.get("kind") == "regex":
            regex_terms += 1
            if regex_terms > MAX_REGEX_TERMS:
                errors.append(f"only {MAX_REGEX_TERMS} regex terms are allowed")
                continue
        if term.get("error"):
            errors.append(term["error"])
        term["negated"] = negated
        terms.append(term)

    return {"raw": raw, "terms": terms, "tree": None, "errors": errors}


def apply_entity_filters(
    stmt: Select,
    *,
    parsed_query: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    types: list[str] | None = None,
    since: datetime | None = None,
    min_jobs: int = 0,
    watchlist_only: bool = False,
    allowlisted_visible: bool = True,
    tags: list[str] | None = None,
    job_id: int | None = None,
) -> Select:
    """Apply user-supplied filters to a `select(Entity)` statement.

    Notes:
      * A regex term contributes **no** SQL narrowing (`_term_clause` returns None for it).
        The caller must fetch a bounded window and apply `post_filter` /
        `regex_post_filter` to the result set.
      * `min_jobs=0` is a no-op; `min_jobs=1` excludes entities with no job links.
      * `watchlist_only=True` ANDs `Entity.watchlist == True`.
      * `allowlisted_visible=False` adds `Entity.allowlisted == False`.
      * `tags` is **any-of**: an entity matches if it carries at least one of them.
        Tag chips are a pivot affordance, so clicking a second one should widen the net,
        the same way the `types` CSV behaves. All-of would be a
        `count(distinct tag) == len(tags)` subquery, but nothing in the UI can express it.
      * `job_id` narrows to the entities observed in one job. **This function does no
        authorization** — it is pure and has no user. The caller must have already
        established that the viewer may see that job (see `entities_partial`), or the
        filter becomes an oracle for a private job's entity set.
    """
    if types:
        stmt = stmt.where(Entity.entity_type.in_(types))

    if job_id:
        stmt = stmt.where(select(EntityJobLink.id).where(EntityJobLink.entity_id == Entity.id, EntityJobLink.job_id == job_id).exists())

    if tags:
        stmt = stmt.where(select(EntityTag.id).where(EntityTag.entity_id == Entity.id, EntityTag.tag.in_(tags)).exists())

    if since is not None:
        stmt = stmt.where(Entity.last_seen_at >= since)

    # `>= 1`, not `> 1`: the UI labels this "Seen in >= N jobs", so N=1 must exclude
    # entities whose job links have all been removed.
    if min_jobs and min_jobs >= 1:
        stmt = stmt.where(Entity.job_count >= min_jobs)

    if watchlist_only:
        stmt = stmt.where(Entity.watchlist.is_(True))

    if not allowlisted_visible:
        stmt = stmt.where(Entity.allowlisted.is_(False))

    if query is not None:
        if query.get("invalid"):
            # Rejected query: match nothing, so the UI shows the error over an empty table
            # instead of a plausible result set answering a question nobody asked.
            return stmt.where(false())
        tree = query.get("tree")
        if tree:
            clause = _tree_clause(tree)
            if clause is not None:
                stmt = stmt.where(clause)
        else:
            for term in query.get("terms", []):
                stmt = _apply_term(stmt, term)
    elif (parsed_query and parsed_query.get("kind") != "literal") or (parsed_query and parsed_query.get("value")):
        stmt = _apply_term(stmt, parsed_query)

    return stmt


def job_terms(query: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Every `job:` term in a parsed query, tree or flat."""
    return [t for t in (query or {}).get("terms", []) if t.get("kind") == "job"]


def list_terms(query: dict[str, Any] | None) -> list[str]:
    """The list names a parsed query tests, in order, deduplicated."""
    return list(dict.fromkeys(t["name"] for t in (query or {}).get("terms", []) if t.get("kind") == "list"))


def unknown_list_errors(query: dict[str, Any] | None, known: Collection[str]) -> list[str]:
    """One error per `list:` name the database does not carry — for callers that can ask it.

    The parser cannot (it is pure), so a `list:` term parses clean and, unresolved, matches
    nothing. A search box or a rule form that stayed silent about that would let a typo
    look like an empty result, which is the failure `attr:` guards against at parse time.
    """
    known = set(known)
    hint = f" — try {', '.join(sorted(known))}" if known else " — no lists are defined yet"
    return [f"unknown list: {name}{hint}" for name in list_terms(query) if name not in known]


def resolve_job_terms(query: dict[str, Any] | None, visible_ids: set[int]) -> bool:
    """Mark `job:` terms resolved, keeping only ids the viewer may actually see.

    Must be called by anything that applies a user-supplied query, because this module is
    pure and cannot ask who is asking. Until it is, `_term_clause` renders a job term as
    FALSE, so the failure mode of forgetting is an empty result rather than a disclosure.

    A term left with no visible ids stays "match nothing" rather than being dropped.
    Dropping it would turn `tag:x job:<private>` into a plain `tag:x` and present the
    result as though it came from that job. The caller should say the filter did not apply,
    in wording that does not distinguish "no such job" from "not yours" — otherwise the
    message itself becomes the id oracle the check exists to close.

    Returns True if any term lost ids, so the caller can surface that.
    """
    dropped = False
    for term in job_terms(query):
        kept = [i for i in term.get("job_ids", []) if i in visible_ids]
        if len(kept) != len(term.get("job_ids", [])):
            dropped = True
        term["job_ids"] = kept
        term["resolved"] = True
    return dropped


def _term_clause(term: dict[str, Any]):
    """The SQL clause for one parsed term, or None when it contributes no narrowing.

    The single source of truth for what a term *means* in SQL — the conjunctive path, the
    single-term path and the boolean tree all go through here, so they cannot drift.

    None means "SQL cannot express this": regex always, and a negated CIDR (whose prefix
    prefilter would also exclude every non-IP entity). Under AND that is fine, because
    `post_filter` then narrows the superset SQL returned. `_validate_tree` is what stops it
    reaching an OR, where the same None would silently mean "matches nothing".
    """
    kind = term.get("kind")
    negated = bool(term.get("negated"))

    def _n(clause):
        return ~clause if negated else clause

    if kind == "literal":
        v = term.get("value", "")
        return _n(Entity.value.ilike(f"%{escape_like(v)}%", escape="\\")) if v else None
    if kind == "wildcard":
        return _n(Entity.value.ilike(term["pattern"], escape="\\"))
    if kind == "regex":
        # No coarse prefix is extractable safely; fall back to no SQL narrowing.
        # Caller must apply post_filter/regex_post_filter to the result set.
        return None
    if kind == "attr":
        # Substring match on the JSON blob; fragment was built with the same
        # serializer used to write attributes_json so it lines up exactly.
        return _n(Entity.attributes_json.like(f"%{term['fragment']}%"))
    if kind == "tag":
        return _n(select(EntityTag.id).where(EntityTag.entity_id == Entity.id, EntityTag.tag.in_(term["tags"])).exists())
    if kind == "type":
        return _n(Entity.entity_type.in_(term["types"]))
    if kind == "job":
        # Unresolved means nobody checked the viewer may see these jobs, so it matches
        # nothing. Failing closed here is deliberate: the alternative — treating it as
        # "no filter" — turns a forgotten `resolve_job_terms` call into a way to read a
        # private job's entity set. See `resolve_job_terms`.
        ids = term.get("job_ids") or []
        if not term.get("resolved") or not ids:
            return _n(false())
        return _n(select(EntityJobLink.id).where(EntityJobLink.entity_id == Entity.id, EntityJobLink.job_id.in_(ids)).exists())
    if kind == "inset":
        # `func.lower` on both sides, exactly as the `list:` exact branch below does — the
        # values were lowercased at parse time and `Entity.value` is stored as it was seen.
        return _n(func.lower(Entity.value).in_(term["values"]))
    if kind == "list":
        # An EXISTS the database answers through the `(list_id, value)` index: nothing is
        # resolved at parse time, so the parser stays pure and nothing has to be cached
        # across the web and worker processes. An exact list compares the lowercased value;
        # a suffix list uses the LIKE pattern computed when the entry was written. A name no
        # list carries matches nothing (negated: everything) — `unknown_list_errors` is how
        # a caller says so.
        lowered = func.lower(Entity.value)
        return _n(
            select(RuleListValue.id)
            .join(RuleList, RuleList.id == RuleListValue.list_id)
            .where(
                RuleList.name == term["name"],
                or_(
                    and_(RuleList.match == "exact", RuleListValue.value == lowered),
                    and_(RuleList.match == "suffix", lowered.like(RuleListValue.pattern, escape="\\")),
                ),
            )
            .exists()
        )
    if kind == "cidr":
        # Coarse: ilike on the value's textual prefix, one per network, any-of. Final
        # containment check in Python. Three octets at /24 or narrower, two at /16 to /23,
        # one at /8 to /15; below /8 and for IPv6 there is no prefix, and if *any* network
        # has none the prefixes cannot narrow at all — only the entity_type clause does.
        if negated:
            # A negated CIDR cannot use the prefix prefilter (it would also exclude every
            # non-IP entity), so it is resolved entirely in post_filter.
            return None
        prefixes = [_coarse_cidr_prefix(network) for network in term["networks"]]
        clause = Entity.entity_type == "ip_address"
        if all(prefixes):
            return and_(or_(*[Entity.value.ilike(f"{p}%") for p in prefixes]), clause)
        return clause
    return None


def _apply_term(stmt: Select, term: dict[str, Any]) -> Select:
    """AND one parsed term onto the statement."""
    clause = _term_clause(term)
    return stmt if clause is None else stmt.where(clause)


def _tree_clause(node: dict[str, Any] | None):
    """Fold a boolean tree into one SQL clause.

    A branch whose children all contribute nothing collapses to None rather than to an
    empty `and_()`, which SQLAlchemy renders as literal TRUE — inside an OR that would
    quietly widen the query to everything.
    """
    if not node:
        return None
    if "op" not in node:
        return _term_clause(node)
    parts = [c for c in (_tree_clause(child) for child in node["nodes"]) if c is not None]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return or_(*parts) if node["op"] == "or" else and_(*parts)


def _coarse_cidr_prefix(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str | None:
    """Cheap LIKE-friendly prefix for an IPv4 network: three octets at /24 or narrower, two
    at /16 to /23, one at /8 to /15. None for IPv6 and for prefixes shorter than /8.
    """
    if isinstance(network, ipaddress.IPv4Network):
        if network.prefixlen >= 24:
            return ".".join(str(network.network_address).split(".")[:3]) + "."
        if network.prefixlen >= 16:
            return ".".join(str(network.network_address).split(".")[:2]) + "."
        if network.prefixlen >= 8:
            return str(network.network_address).split(".")[0] + "."
    return None


def regex_post_filter(entities: list[Entity], parsed_query: dict[str, Any] | None) -> list[Entity]:
    """Apply a parsed regex/CIDR match to a pre-fetched entity list.

    No-op for literal/wildcard queries (SQL handles those).
    """
    if not parsed_query:
        return entities
    kind = parsed_query.get("kind")
    if kind == "regex":
        pat = parsed_query["pattern"]
        deadline = time.monotonic() + REGEX_MATCH_BUDGET_S
        out = []
        for e in entities:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break  # total budget spent — return what matched so far
            try:
                if pat.search((e.value or "")[:REGEX_INPUT_MAX], timeout=remaining):
                    out.append(e)
            except TimeoutError:
                break  # pathological pattern — stop scanning
        return out
    if kind == "cidr":
        return [e for e in entities if e.entity_type == "ip_address" and _in_any_network(e.value, parsed_query["networks"])]
    return entities


def _in_any_network(value: str | None, networks: list) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in networks)


def query_needs_post_filter(query: dict[str, Any] | None) -> bool:
    """Does this query have a term SQL could not express?

    False for a rejected query — it already matches nothing, so there is nothing to narrow
    and no reason to pay for the wide fetch the post-filter path uses.

    Post-filtered terms only ever reach here as AND conjuncts (`_validate_tree` rejects
    them under an OR), so narrowing the fetched rows sequentially remains correct even when
    the query has a boolean tree.
    """
    if not query or query.get("invalid"):
        return False
    return any(t.get("kind") in _POST_FILTERED_KINDS for t in query.get("terms", []))


def post_filter(entities: list[Entity], query: dict[str, Any] | None, *, strict: bool = False) -> list[Entity]:
    """Apply every regex/CIDR term of a conjunctive query to a pre-fetched list.

    Terms AND, so each one narrows the survivors of the last. All regex terms share a
    single `REGEX_MATCH_BUDGET_S` — N patterns must not cost N times the CPU, or adding
    terms would be a way to buy scan time.

    `strict` is for callers that *write* on the answer — the rule matcher and the labels
    backfill. When the budget runs out mid-scan, the dashboard keeps the unscanned remainder
    of a positive term (its count is already flagged approximate, and a row that might match
    is more useful on screen than a silent gap). A rule must never tag a row nothing
    verified, so `strict` drops the remainder and logs how many rows went unchecked.
    """
    if not query:
        return entities
    deadline = time.monotonic() + REGEX_MATCH_BUDGET_S
    out = entities
    for term in query.get("terms", []):
        kind = term.get("kind")
        negated = bool(term.get("negated"))
        if kind == "regex":
            pat = term["pattern"]
            kept = []
            for i, e in enumerate(out):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    kept.extend(_unscanned(out, i, negated=negated, strict=strict))
                    break
                try:
                    hit = bool(pat.search((e.value or "")[:REGEX_INPUT_MAX], timeout=remaining))
                except TimeoutError:
                    # A pathological pattern: nothing past this row can be trusted either way.
                    _unscanned(out, i, negated=True, strict=strict)
                    break
                if hit != negated:
                    kept.append(e)
            out = kept
        elif kind == "cidr":
            networks = term["networks"]
            # A negated CIDR keeps non-IP entities; a positive one drops them.
            out = [e for e in out if (e.entity_type == "ip_address" and _in_any_network(e.value, networks)) != negated]
    return out


def _unscanned(rows: list, index: int, *, negated: bool, strict: bool) -> list:
    """What to keep of the rows a spent regex budget left unscanned, from `index` on.

    A negated term keeps none — keeping a row would assert a non-match nobody verified.
    A strict caller keeps none either, and says so in the log. The approximate path keeps
    them all for a positive term, the "already flagged approximate" trade.
    """
    left = len(rows) - index
    if strict:
        _log.warning("regex budget exhausted: %d of %d rows were not checked and were dropped", left, len(rows))
        return []
    return [] if negated else rows[index:]


def _list_matcher(term: dict[str, Any], lists: dict[str, tuple[str, tuple[str, ...]]]) -> Callable[[str], bool]:
    """The Python half of a `list:` term, over an already-lowercased value.

    `lists` is `name → (match, values)` as `rule_lists.load_list_values` returns it; a name
    it lacks matches nothing, the same answer the SQL gives.
    """
    match, values = lists.get(term["name"], ("exact", ()))
    if match == "suffix":
        suffixes = tuple(values)
        return lambda v: v.endswith(suffixes)
    members = frozenset(values)
    return lambda v: v in members


def match_entity_rows(query: dict[str, Any] | None, rows: list[Any], *, lists: dict[str, tuple[str, tuple[str, ...]]] | None = None) -> tuple[set[int], bool]:
    """Match the server-side terms of a parsed query against in-hand rows.

    Returns `(matching ids, budget_exhausted)`. `lists` is what `list:` terms are answered
    from — `name → (match, values)`, loaded by the caller, since this module cannot.

    The relationship graph needs "which of *these* nodes match?" rather than "which rows
    does SQL return?" — the node set is already fixed by the traversal, and filtering it
    server-side would answer a different question. Every other term kind is evaluated on the
    client against decoded node attributes; two reach here. ``re:``, because a JS ``RegExp``
    has no timeout and the nested-quantifier pre-check catches accidents but not a
    deliberately catastrophic pattern. ``list:``, because the lists live in the server's
    database and shipping them with every payload buys nothing a round trip does not.

    *rows* need only expose ``.id`` and ``.value``.

    The second element is load-bearing. ``REGEX_MATCH_BUDGET_S`` is a *total* wall-clock
    budget across the scan, and when it runs out the loop stops — so on a large graph the
    returned set can be a strict subset of the true matches. Silently rendering that as
    "these are the matches, everything else is dimmed" is the same false-negative-as-fact
    failure the ``job:`` fail-closed rule exists to avoid, so the flag rides out to the
    payload as ``mt_partial`` and the UI says the matches may be incomplete.
    """
    if not query:
        return set(), False
    terms = query.get("terms", [])
    patterns = [(t["pattern"], bool(t.get("negated"))) for t in terms if t.get("kind") == "regex"]
    list_checks = [(_list_matcher(t, lists or {}), bool(t.get("negated"))) for t in terms if t.get("kind") == "list"]
    # `in:` is answered here rather than on the client for one reason only: consistency with
    # `list:`, which it is the anonymous form of. Both are membership in a set the server
    # knows, and having one answered in each place is how they come to disagree.
    inset_checks = [(frozenset(t["values"]), bool(t.get("negated"))) for t in terms if t.get("kind") == "inset"]
    if not patterns and not list_checks and not inset_checks:
        return set(), False

    deadline = time.monotonic() + REGEX_MATCH_BUDGET_S
    exhausted = False
    matched: set[int] = set()
    for row in rows:
        value = getattr(row, "value", None) or ""
        if any(matcher(value.lower()) == negated for matcher, negated in list_checks):
            continue
        if any((value.lower() in members) == negated for members, negated in inset_checks):
            continue
        if patterns:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                exhausted = True
                break
            ok = True
            for pattern, negated in patterns:
                try:
                    hit = bool(pattern.search(value[:REGEX_INPUT_MAX], timeout=max(remaining, 0.001)))
                except TimeoutError:
                    exhausted = True
                    ok = False
                    break
                if hit == negated:
                    ok = False
                    break
            if exhausted:
                break
            if not ok:
                continue
        matched.add(int(row.id))
    return matched, exhausted


def parse_since(raw: str) -> datetime | None:
    """Parse an ISO date or datetime string. Returns None if blank/invalid."""
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        try:
            return datetime.strptime(raw, "%Y-%m-%d")
        except ValueError:
            return None


def parse_types_csv(raw: str, valid_set: set[str]) -> list[str]:
    """Parse a CSV string of entity types and keep only known values."""
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip() in valid_set]


def parse_tags_csv(raw: str) -> list[str]:
    """Normalize + dedupe a CSV of tags, capped at `TAG_QUERY_MAX`, order preserved.

    Uses the same `normalize_tag` the write path uses, so `tag:APT28` matches a tag
    stored as `apt28`. Unlike `parse_types_csv` there is no valid-set to check against:
    tags are freeform, and an unknown one legitimately matches nothing.
    """
    if not raw:
        return []
    seen = [normalize_tag(part) for part in raw.split(",")]
    return list(dict.fromkeys(t for t in seen if t))[:TAG_QUERY_MAX]


# Keep these re-exports for explicit imports elsewhere.
__all__ = [
    "QUERY_KINDS",
    "REGEX_MAX_LEN",
    "TAG_MAX_LENGTH",
    "apply_entity_filters",
    "normalize_tag",
    "parse_search_query",
    "parse_since",
    "parse_tags_csv",
    "parse_types_csv",
    "regex_post_filter",
]
