"""Named lists — the sets a rule condition tests with `list:<name>`.

The rules' own vocabulary of values: LOLBAS names, GTFOBins names, suspicious TLDs, and
whatever an admin adds. Seeded from `rules/lists.yml` at start, edited on the Rules page,
exported and imported with the rules (`rules_yaml.py` owns the document; this module owns
the lists themselves).

Pure half: `ListSpec`, `normalize_values`, `validate_list_spec`, `list_hash`,
`value_pattern`. Impure half: the four session helpers at the bottom, all async, none of
which commit — the caller owns the transaction.

Not `config/threat_detection.yaml`. That file configures the detection pipeline that runs on
an upload and decides what a finding is; this decides what happens after. The pipeline keeps
its own copy of the LOLBAS set for that reason, and the two may drift by choice.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intel.queries import escape_like, list_terms, parse_query
from app.models import IntelRule, RuleList, RuleListValue

#: How a list compares a value to its entries. `exact` is the whole value; `suffix` is for
#: the TLD list, whose entries keep their leading dot so `.tk` cannot match `stk`.
LIST_MATCH_KINDS = ("exact", "suffix")
LIST_MATCH_LABELS = {"exact": "whole value", "suffix": "ends with"}
#: The same shape as a tag name and a rule key: what `list:<name>` can carry in a query.
LIST_NAME_RE = re.compile(r"^[a-z0-9_]{1,50}$")
MAX_LIST_VALUES = 2000
VALUE_MAX = 200
DESCRIPTION_MAX = 500


@dataclass(frozen=True)
class ListSpec:
    """One list as data — what the file, the form, the export and the import all speak."""

    name: str
    match: str = "exact"
    description: str = ""
    values: tuple[str, ...] = ()


def normalize_values(raw: Any) -> tuple[str, ...]:
    """Entries from a list, or from text with one per line (commas count too): lowercased,
    stripped, blanks dropped, duplicates dropped, order kept."""
    if raw is None:
        return ()
    if not isinstance(raw, str):
        if not isinstance(raw, (list, tuple)) or any(not is_list_scalar(v) for v in raw):
            raise ValueError("values must contain only strings or finite numbers")
    parts = re.split(r"[\n,]", raw) if isinstance(raw, str) else [str(v) for v in raw]
    return tuple(dict.fromkeys(p.strip().lower() for p in parts if p and p.strip()))


def is_list_scalar(value: Any) -> bool:
    """Only these scalars may be converted to a list value or HTTP header."""
    return isinstance(value, str) or type(value) is int or (type(value) is float and math.isfinite(value))


def validate_list_spec(spec: ListSpec) -> list[str]:
    """Every reason this list may not be written, in field order. Empty means it may."""
    errors: list[str] = []
    if not LIST_NAME_RE.match(spec.name or ""):
        errors.append("name must be 1-50 lowercase letters, digits or underscores")
    if spec.match not in LIST_MATCH_KINDS:
        errors.append(f"match must be one of {', '.join(LIST_MATCH_KINDS)}")
    if len(spec.description) > DESCRIPTION_MAX:
        errors.append(f"description is longer than {DESCRIPTION_MAX} characters")
    if not spec.values:
        errors.append("a list needs at least one value")
    elif len(spec.values) > MAX_LIST_VALUES:
        errors.append(f"a list may hold at most {MAX_LIST_VALUES} values")
    too_long = [v for v in spec.values if len(v) > VALUE_MAX]
    if too_long:
        errors.append(f"value {too_long[0][:40]!r}… is longer than {VALUE_MAX} characters")
    return errors


def spec_to_mapping(spec: ListSpec) -> dict[str, Any]:
    out: dict[str, Any] = {"name": spec.name, "match": spec.match}
    if spec.description:
        out["description"] = spec.description
    out["values"] = list(spec.values)
    return out


def list_hash(spec: ListSpec) -> str:
    """What `RuleList.seed_hash` stores: the seeded definition, canonically serialised."""
    return hashlib.sha256(json.dumps(spec_to_mapping(spec), sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def value_pattern(value: str, match: str) -> str:
    """The SQL side of an entry: the value for an exact list, `%` + escaped value for a suffix one."""
    return f"%{escape_like(value)}" if match == "suffix" else value


# ── session helpers ─────────────────────────────────────────────────────────────


async def load_lists(db: AsyncSession) -> list[tuple[RuleList, ListSpec]]:
    """Every list with its entries, by name. Two queries, however many lists there are."""
    rows = (await db.execute(select(RuleList).order_by(RuleList.name))).scalars().all()
    if not rows:
        return []
    values: dict[int, list[str]] = {r.id: [] for r in rows}
    for list_id, value in (await db.execute(select(RuleListValue.list_id, RuleListValue.value).order_by(RuleListValue.id))).all():
        values[list_id].append(value)
    return [(r, ListSpec(name=r.name, match=r.match or "exact", description=r.description or "", values=tuple(values[r.id]))) for r in rows]


async def list_names(db: AsyncSession) -> set[str]:
    return set((await db.execute(select(RuleList.name))).scalars().all())


async def load_list_values(db: AsyncSession, names: list[str]) -> dict[str, tuple[str, tuple[str, ...]]]:
    """`name → (match, values)` for the named lists — what `match_entity_rows` evaluates
    `list:` with when the rows are already in hand (the relationship graph)."""
    if not names:
        return {}
    rows = (await db.execute(select(RuleList).where(RuleList.name.in_(names)))).scalars().all()
    out: dict[str, tuple[str, tuple[str, ...]]] = {}
    for r in rows:
        vals = (await db.execute(select(RuleListValue.value).where(RuleListValue.list_id == r.id).order_by(RuleListValue.id))).scalars().all()
        out[r.name] = (r.match or "exact", tuple(vals))
    return out


async def rules_naming(db: AsyncSession, name: str) -> list[str]:
    """Names of every rule on the instance whose condition tests `list:<name>`."""
    rows = (await db.execute(select(IntelRule.name, IntelRule.query).where(IntelRule.scope == "entity", IntelRule.query.like("%list:%")))).all()
    return [rule_name for rule_name, query in rows if name in list_terms(parse_query(query or ""))]


def write_list_sync(db, row: RuleList | None, spec: ListSpec, *, seed_hash: str | None) -> RuleList:
    """`write_list` for a sync session — the Huey worker's half.

    A twin rather than a shared body: async and sync SQLAlchemy do not mix, and this
    codebase keeps the two apart by rule (async in routes, sync in tasks). The one thing
    that must not drift is *what* is written, so both go through `value_pattern` and both
    replace the entries wholesale; a test asserts they produce the same rows.

    Flushes; does not commit — the caller decides the transaction, which for the refresh
    sweep means one commit per list so a dead feed cannot hold the writer lock.
    """
    if row is None:
        row = RuleList(name=spec.name)
        db.add(row)
    row.name = spec.name
    row.match = spec.match
    row.description = spec.description or None
    row.seed_hash = seed_hash
    db.flush()
    db.execute(delete(RuleListValue).where(RuleListValue.list_id == row.id))
    db.add_all([RuleListValue(list_id=row.id, value=v, pattern=value_pattern(v, spec.match)) for v in spec.values])
    db.flush()
    return row


async def write_list(db: AsyncSession, row: RuleList | None, spec: ListSpec, *, seed_hash: str | None) -> RuleList:
    """Create `spec` as a new list, or rewrite `row` to it. Entries are replaced wholesale.

    `seed_hash` is the seeder's mark; the form and the import pass None, which is what makes
    a list a person wrote hands-off for the seeder. Flushes; does not commit.
    """
    if row is None:
        row = RuleList(name=spec.name)
        db.add(row)
    row.name = spec.name
    row.match = spec.match
    row.description = spec.description or None
    row.seed_hash = seed_hash
    await db.flush()
    await db.execute(delete(RuleListValue).where(RuleListValue.list_id == row.id))
    db.add_all([RuleListValue(list_id=row.id, value=v, pattern=value_pattern(v, spec.match)) for v in spec.values])
    await db.flush()
    return row
