"""The jobs-list search grammar — `?q=` on `/jobs`.

Pure, like `app/intel/queries.py` and for the same reason: it is imported by a router and
must never import one back. No FastAPI here.

**Modelled on the Intel grammar, deliberately narrowed.** An analyst who has learned
`tag:apt29 -is:private` on one list should not have to learn a second dialect on the other,
so the shape is identical: whitespace means AND, a leading `-` negates, `"quoted phrases"`
survive, and an unparseable value degrades to a filter that matches nothing rather than
raising. The tokenizer is literally Intel's — `scan_query` — so the two cannot disagree
about where one term ends and the next begins.

**Every term compiles to SQL.** That is the one place this deliberately diverges. Intel
supports `re:/…/` and `cidr:` by fetching a 1000-row window and filtering in Python, which
makes its totals approximate and lets its pager offer a page the data cannot fill. The jobs
list is the app's front page and its pager is its main affordance, so the cost is not worth
it here: a regex over filenames buys little that `*` wildcards do not, and there is no
address column to put a CIDR against.

Everything is a correlated EXISTS or a plain `AnalysisJob` column — never a JOIN — because
the identical builder has to run against both `select(AnalysisJob)` and
`select(func.count(AnalysisJob.id))`, and a JOIN would multiply rows in the second.
"""

from __future__ import annotations

import math
from datetime import timedelta

from sqlalchemy import and_, false, func, or_, select

from app.database import parse_row_id, utc_now_naive
from app.intel.queries import escape_like, normalize_tag, scan_query
from app.models import AnalysisJob, Finding, JobStatus, JobTag, JobWatch, LogFile, LogType, TaskResult, WorkflowDef

# Same ceiling as the entity grammar: a query is a filter, not a program.
MAX_TERMS = 12

#: `is:` flags, and what each asks. Values, not code, so the help panel and the parser are
#: the same list — a flag the parser knows and the help does not is a feature nobody finds.
IS_FLAGS = {
    "private": "only private submissions",
    "public": "only public submissions",
    "mine": "submitted by you",
    "anonymous": "submitted without an account",
    "watched": "jobs you are watching",
    "hits": "at least one finding",
    "clean": "no findings",
    "error": "recorded an error",
    "running": "still in progress",
    "done": "finished, one way or another",
}

#: Everything the search box understands, for the help panel. `(syntax, what it does)`.
SYNTAX_HELP = [
    ("report.evtx", "filename contains this"),
    ('"my report"', "…with spaces"),
    ("srv01*", "filename wildcard"),
    ("tag:apt29,c2", "carries any of these tags"),
    ("status:failed", "pending · running · completed · partial · failed · cancelled"),
    ("type:evtx", "log type"),
    ("workflow:windows", "workflow name contains this"),
    ("sev:critical,high", "has a finding of this severity"),
    ("tool:chainsaw", "this tool ran on the job"),
    ("findings:>10", "also  =0  <5  5..50"),
    ("after:2026-08-01", "also  after:7d  before:…"),
    ("id:42", "job number"),
    ("sha256:9f2c", "file hash, by prefix"),
    ("is:watched", " · ".join(sorted(IS_FLAGS))),
    ("-tag:reviewed", "any term can be negated"),
]

#: Keys the search box completes, and what each is for. The prefix set is passed to
#: `queries.caret_token`, which is shared with the entity grammar — the caret rules have to
#: agree with the tokenizer about where a term begins and ends, and a second implementation
#: of that would drift from the first.
#:
#: `id:` and `sha256:` are deliberately absent. Both would enumerate: a completion list of
#: job numbers or file hashes hands over exactly what the term itself is careful not to leak,
#: and unlike `job:` on the entity dashboard there is no filename the viewer already sees to
#: make the trade worth it. They still parse — they are just not offered.
COMPLETABLE_PREFIXES: tuple[str, ...] = ("tag:", "status:", "type:", "workflow:", "sev:", "tool:", "findings:", "after:", "before:", "is:")

#: Every prefix `_parse_terms` gives a meaning to, completable or not.
#:
#: Wider than `COMPLETABLE_PREFIXES` — `id:` and `sha256:` parse but are deliberately not
#: offered, because a completion list over them is an enumeration surface. This exists so
#: the condition editor can colour a prefix it recognises without re-deriving the if-chain
#: in JavaScript; `tests/test_jobs_query.py` walks that chain's AST and fails if the two
#: disagree, which is the only thing stopping a new prefix from rendering as plain text.
PREFIXES: tuple[str, ...] = (
    "tag:",
    "status:",
    "type:",
    "workflow:",
    "sev:",
    "severity:",
    "tool:",
    "findings:",
    "after:",
    "before:",
    "id:",
    "sha256:",
    "hash:",
    "is:",
)

PREFIX_HELP: tuple[tuple[str, str], ...] = (
    ("tag:", "your analyst tags"),
    ("status:", "how the job ended"),
    ("type:", "log type"),
    ("sev:", "a finding of this severity"),
    ("workflow:", "the workflow that ran"),
    ("tool:", "a tool that ran on it"),
    ("findings:", "how many findings"),
    ("after:", "submitted since"),
    ("before:", "submitted up to"),
    ("is:", "private, mine, watched, clean…"),
)

_SEVERITIES = ("critical", "high", "medium", "low", "informational")
_STATUS_VALUES = frozenset(m.value for m in JobStatus)
_LOGTYPE_VALUES = frozenset(m.value for m in LogType)


def _csv(value: str) -> list[str]:
    """`a,b , c` → `['a','b','c']`, order preserved, blanks dropped."""
    out: list[str] = []
    for part in value.split(","):
        part = part.strip()
        if part and part not in out:
            out.append(part)
    return out


def _parse_amount(value: str) -> tuple[str, float, float] | None:
    """`>10` / `<5` / `=0` / `10` / `5..50` → `(op, lo, hi)`, or None if unparseable."""
    v = value.strip()
    if ".." in v:
        lo, _, hi = v.partition("..")
        try:
            lo_n, hi_n = float(lo), float(hi)
        except ValueError:
            return None
        return ("range", lo_n, hi_n) if math.isfinite(lo_n) and math.isfinite(hi_n) else None
    op = "="
    if v[:2] in (">=", "<="):
        op, v = v[:2], v[2:]
    elif v[:1] in (">", "<", "="):
        op, v = v[:1], v[1:]
    try:
        n = float(v)
    except ValueError:
        return None
    return (op, n, 0.0) if math.isfinite(n) else None


def _parse_when(value: str):
    """An absolute `YYYY-MM-DD` or a relative `7d` / `12h`, as a naive UTC datetime.

    Relative is the form people actually type into a job list — "what broke this week" —
    and an absolute date alone would make that a mental arithmetic exercise.
    """
    v = value.strip().lower()
    if v and v[-1] in "dhw" and v[:-1].isascii() and v[:-1].isdigit():
        n = int(v[:-1])
        try:
            delta = {"d": timedelta(days=n), "h": timedelta(hours=n), "w": timedelta(weeks=n)}[v[-1]]
            return utc_now_naive() - delta
        except (OverflowError, ValueError):  # further back than datetime can count
            return None
    from datetime import datetime

    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    return None


def parse_jobs_query(raw: str) -> dict:
    """`{"terms": [...], "invalid": bool}` — one dict per term, negation carried on it.

    Never raises. A term whose value makes no sense keeps its `kind` and gains an `error`,
    so the box can say what it ignored instead of the page 500ing on a half-typed word.
    """
    terms: list[dict] = []
    for token in scan_query(raw or ""):
        text = token[2]
        negated = text.startswith("-")
        if negated:
            text = text[1:]
        if not text:
            continue

        lowered = text.lower()
        kind, _, value = lowered.partition(":")
        if not _:  # no colon — a bare word or phrase, matched against the filename
            terms.append({"kind": "text", "value": text, "negated": negated})
        elif kind == "tag":
            tags = [t for t in (normalize_tag(t) for t in _csv(value)) if t]
            terms.append({"kind": "tag", "tags": tags, "negated": negated, **({} if tags else {"error": "no tag named"})})
        elif kind == "status":
            wanted = [s for s in _csv(value) if s in _STATUS_VALUES]
            terms.append({"kind": "status", "values": wanted, "negated": negated, **({} if wanted else {"error": f"unknown status: {value}"})})
        elif kind == "type":
            wanted = [t for t in _csv(value) if t in _LOGTYPE_VALUES]
            terms.append({"kind": "logtype", "values": wanted, "negated": negated, **({} if wanted else {"error": f"unknown log type: {value}"})})
        elif kind == "workflow":
            terms.append({"kind": "workflow", "values": _csv(text.partition(":")[2]), "negated": negated})
        elif kind in ("sev", "severity"):
            wanted = [s for s in _csv(value) if s in _SEVERITIES]
            terms.append({"kind": "severity", "values": wanted, "negated": negated, **({} if wanted else {"error": f"unknown severity: {value}"})})
        elif kind == "tool":
            terms.append({"kind": "tool", "values": _csv(value), "negated": negated})
        elif kind == "findings":
            parsed = _parse_amount(value)
            terms.append({"kind": "findings", "amount": parsed, "negated": negated, **({} if parsed else {"error": f"not a number: {value}"})})
        elif kind in ("after", "before"):
            when = _parse_when(value)
            terms.append({"kind": kind, "when": when, "negated": negated, **({} if when else {"error": f"not a date: {value}"})})
        elif kind == "id":
            ids = [n for n in (parse_row_id(v) for v in _csv(value)) if n is not None]
            terms.append({"kind": "id", "values": ids, "negated": negated, **({} if ids else {"error": f"not a job number: {value}"})})
        elif kind in ("sha256", "hash"):
            terms.append({"kind": "sha256", "value": value, "negated": negated})
        elif kind == "is":
            flags = [f for f in _csv(value) if f in IS_FLAGS]
            terms.append({"kind": "is", "values": flags, "negated": negated, **({} if flags else {"error": f"unknown flag: {value}"})})
        else:
            # An unknown `word:value` is a filename search for the whole thing, not an
            # error: paths and rule ids contain colons, and refusing them would make the
            # commonest search fail on its most distinctive input.
            terms.append({"kind": "text", "value": text, "negated": negated})

        if len(terms) >= MAX_TERMS:
            break

    return {"terms": terms, "invalid": any(t.get("error") for t in terms)}


def query_errors(parsed: dict) -> list[str]:
    """What the box should say it ignored. Empty when everything parsed."""
    return [t["error"] for t in parsed.get("terms", []) if t.get("error")]


def _file_exists(*clauses):
    return select(LogFile.id).where(LogFile.id == AnalysisJob.file_id, *clauses).exists()


def _term_clause(term: dict, *, viewer_id):
    """One term → one SQL clause, or None when it cannot contribute.

    A term carrying an `error` returns `false()` rather than None: the analyst typed
    something, and silently widening the result to everything is the one behaviour that
    would mislead them about what they are looking at. Negation must not undo that —
    `~false()` is TRUE — so an errored term has to reach the query unnegated.
    """
    kind = term["kind"]
    if term.get("error"):
        return false()

    if kind == "text":
        value = term["value"]
        if "*" in value:
            # A wildcard is an explicit anchor: `srv01*` means starts-with, not contains.
            # `escape_like` first, so a literal `%` or `_` in a filename stays literal and
            # only the `*` the analyst typed becomes a wildcard.
            pattern = escape_like(value).replace("*", "%")
            return AnalysisJob.filename.ilike(pattern, escape="\\")
        return AnalysisJob.filename.ilike(f"%{escape_like(value)}%", escape="\\")
    if kind == "tag":
        return select(JobTag.id).where(JobTag.job_id == AnalysisJob.id, JobTag.tag.in_(term["tags"])).exists()
    if kind == "status":
        return AnalysisJob.status.in_(term["values"])
    if kind == "logtype":
        return AnalysisJob.effective_log_type.in_(term["values"])
    if kind == "workflow":
        return (
            select(WorkflowDef.id)
            .where(
                WorkflowDef.id == AnalysisJob.workflow_id,
                or_(*[WorkflowDef.name.ilike(f"%{escape_like(n)}%", escape="\\") for n in term["values"]]),
            )
            .exists()
        )
    if kind == "severity":
        return (
            select(Finding.id).join(TaskResult, Finding.task_result_id == TaskResult.id).where(TaskResult.job_id == AnalysisJob.id, Finding.severity.in_(term["values"])).exists()
        )
    if kind == "tool":
        return (
            select(TaskResult.id)
            .where(
                TaskResult.job_id == AnalysisJob.id,
                or_(*[TaskResult.tool_name.ilike(f"%{escape_like(n)}%", escape="\\") for n in term["values"]]),
            )
            .exists()
        )
    if kind == "findings":
        op, lo, hi = term["amount"]
        col = func.coalesce(AnalysisJob.total_findings, 0)
        return {
            ">": col > lo,
            "<": col < lo,
            ">=": col >= lo,
            "<=": col <= lo,
            "=": col == lo,
            "range": and_(col >= lo, col <= hi),
        }[op]
    if kind == "after":
        return AnalysisJob.created_at >= term["when"]
    if kind == "before":
        return AnalysisJob.created_at < term["when"]
    if kind == "id":
        return AnalysisJob.id.in_(term["values"])
    if kind == "sha256":
        # Prefix, so a short hash from a ticket works without the whole 64 characters.
        return _file_exists(LogFile.sha256.like(f"{escape_like(term['value'])}%", escape="\\"))
    if kind == "is":
        return or_(*[c for c in (_flag_clause(f, viewer_id) for f in term["values"]) if c is not None])
    return None


def _flag_clause(flag: str, viewer_id):
    if flag == "private":
        return AnalysisJob.is_private.is_(True)
    if flag == "public":
        return AnalysisJob.is_private.is_(False)
    if flag == "anonymous":
        return AnalysisJob.submitted_by_user_id.is_(None)
    if flag == "mine":
        # `false()` rather than None for a signed-out viewer: "mine" for nobody is nothing,
        # and dropping the term would silently show them everybody's.
        return AnalysisJob.submitted_by_user_id == viewer_id if viewer_id is not None else false()
    if flag == "watched":
        if viewer_id is None:
            return false()
        return select(JobWatch.id).where(JobWatch.job_id == AnalysisJob.id, JobWatch.user_id == viewer_id).exists()
    if flag == "hits":
        return func.coalesce(AnalysisJob.total_findings, 0) > 0
    if flag == "clean":
        return func.coalesce(AnalysisJob.total_findings, 0) == 0
    if flag == "error":
        return AnalysisJob.error_message.isnot(None)
    if flag == "running":
        return AnalysisJob.status.in_(["pending", "running"])
    if flag == "done":
        return AnalysisJob.status.in_(["completed", "partial", "failed", "cancelled"])
    return None


def apply_jobs_query(stmt, parsed: dict, *, viewer_id=None):
    """AND every term onto *stmt*. Safe to call with an empty parse.

    An errored term is applied unnegated, for the reason `_term_clause` gives: it compiles
    to `false()`, and `~false()` is `WHERE TRUE`, so negating a typo would hand back the
    whole unfiltered list — the one widening the `false()` exists to prevent.
    """
    for term in parsed.get("terms", []):
        clause = _term_clause(term, viewer_id=viewer_id)
        if clause is None:
            continue
        negate = term.get("negated") and not term.get("error")
        stmt = stmt.where(~clause if negate else clause)
    return stmt


def describe(term: dict) -> str:
    """A term as a chip label. Used for the active-filter row above the table."""
    prefix = "-" if term.get("negated") else ""
    kind = term["kind"]
    if kind == "text":
        return f"{prefix}{term['value']}"
    if kind == "tag":
        return f"{prefix}tag:{','.join(term['tags'])}"
    if kind == "findings":
        amount = term.get("amount")
        if not amount:
            return f"{prefix}findings:?"
        op, lo, hi = amount
        body = f"{lo:g}..{hi:g}" if op == "range" else f"{'' if op == '=' else op}{lo:g}"
        return f"{prefix}findings:{body}"
    if kind in ("after", "before"):
        when = term.get("when")
        return f"{prefix}{kind}:{when.strftime('%Y-%m-%d') if when else '?'}"
    if kind == "sha256":
        return f"{prefix}sha256:{term['value'][:12]}"
    values = term.get("values") or []
    label = {"logtype": "type", "severity": "sev"}.get(kind, kind)
    return f"{prefix}{label}:{','.join(str(v) for v in values)}"


__all__ = [
    "COMPLETABLE_PREFIXES",
    "IS_FLAGS",
    "MAX_TERMS",
    "PREFIXES",
    "PREFIX_HELP",
    "SYNTAX_HELP",
    "apply_jobs_query",
    "describe",
    "parse_jobs_query",
    "query_errors",
]
