"""The one writer of `rule_text`: a rule's source text, stored once per distinct content.

Sync, for the worker. A tool's findings are persisted together, and many cite the same rule,
so ids are resolved for the whole batch at once: one SELECT for the known hashes, one insert
for the new ones (on-conflict-do-nothing, so two workers persisting the same rule both
succeed), and one more SELECT for the ids that insert produced.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.models import RuleText


def rule_text_sha(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def rule_text_ids_sync(db, contents: Iterable[str | None]) -> dict[str, int]:
    """`{sha256: rule_text.id}` for every non-empty content, inserting the missing ones."""
    by_sha = {rule_text_sha(c): c for c in contents if c}
    if not by_sha:
        return {}
    ids = dict(db.execute(select(RuleText.sha256, RuleText.id).where(RuleText.sha256.in_(list(by_sha)))).all())
    missing = [{"sha256": sha, "content": content} for sha, content in by_sha.items() if sha not in ids]
    if missing:
        insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
        db.execute(insert(RuleText).values(missing).on_conflict_do_nothing(index_elements=["sha256"]))
        ids.update(db.execute(select(RuleText.sha256, RuleText.id).where(RuleText.sha256.in_([m["sha256"] for m in missing]))).all())
    return ids


def rule_text_id_sync(db, content: str | None) -> int | None:
    """One content's id; for tests and one-off writers. Batches go through `rule_text_ids_sync`."""
    if not content:
        return None
    return rule_text_ids_sync(db, [content])[rule_text_sha(content)]
