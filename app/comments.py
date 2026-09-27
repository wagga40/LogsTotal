"""Comment threads on cases, entities, and jobs — helpers shared by the routers.

Mostly-pure module: SQLAlchemy queries in, plain data out. No FastAPI routing
lives here (see ``app/routers/comments.py``), but ``clean_text`` raises
``HTTPException`` because every caller wants the same 400-over-cap behaviour, and
three copies would drift.
"""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Comment

# Comments are messages, not documents — half the 8000-char narrative cap.
COMMENT_MAX = 4000
# Newest N rendered per thread; older ones stay in the DB and are counted.
THREAD_PAGE = 100
TARGET_TYPES = ("case", "entity", "job")


def clean_text(raw: str, cap: int, *, label: str = "Note") -> str | None:
    """Strip freeform text; empty -> None; over *cap* chars -> HTTP 400.

    Shared by case notes, the comment routes and the entity-notes route, so all three
    have one contract. Rejecting is deliberate: a ``[:cap]`` truncation would silently
    discard the tail of an analyst's write.
    """
    trimmed = (raw or "").strip()
    if len(trimmed) > cap:
        raise HTTPException(400, f"{label} too long (max {cap} chars)")
    return trimmed or None


def target_column(target_type: str):
    """Comment column for a target kind — the one place this mapping lives."""
    try:
        return {"case": Comment.case_id, "entity": Comment.entity_id, "job": Comment.job_id}[target_type]
    except KeyError:
        raise HTTPException(404, "Unknown comment target") from None


async def thread_for(
    db: AsyncSession,
    target_type: str,
    target_id: int,
    *,
    limit: int | None = None,
) -> tuple[list[Comment], int]:
    """Return (oldest-first page of the newest *limit* comments, total live count).

    Fetched newest-first so a long thread keeps its tail, then reversed in Python
    for the chat-style oldest-at-top render. Soft-deleted rows are excluded here,
    so they behave exactly like hard deletes everywhere downstream.

    `limit=None` resolves THREAD_PAGE at call time rather than binding it as a default
    argument, so the page size stays overridable in tests.
    """
    limit = THREAD_PAGE if limit is None else limit
    col = target_column(target_type)
    total = await db.scalar(select(func.count(Comment.id)).where(col == target_id, Comment.deleted_at.is_(None))) or 0
    rows = (
        (
            await db.execute(
                select(Comment)
                .where(col == target_id, Comment.deleted_at.is_(None))
                .options(selectinload(Comment.author))
                .order_by(Comment.created_at.desc(), Comment.id.desc())
                .limit(max(1, limit))
            )
        )
        .scalars()
        .all()
    )
    return list(reversed(rows)), int(total)


async def comment_counts_for(db: AsyncSession, target_type: str, target_ids: list[int]) -> dict[int, int]:
    """Bulk live-comment counts keyed by target id — used for tab badges."""
    if not target_ids:
        return {}
    col = target_column(target_type)
    rows = (await db.execute(select(col, func.count(Comment.id)).where(col.in_(target_ids), Comment.deleted_at.is_(None)).group_by(col))).all()
    return {int(tid): int(n) for tid, n in rows if tid is not None}


def can_edit(comment: Comment, user) -> bool:
    """Only the author may edit — an admin rewriting someone's words would be worse
    than useless on a shared investigation surface. Admins can still delete."""
    return comment.author_user_id is not None and user is not None and comment.author_user_id == user.id


def can_delete(comment: Comment, user, *, target_type: str, target) -> bool:
    """Author, admin, or — for case threads — the case owner."""
    if user is None:
        return False
    if can_edit(comment, user) or bool(getattr(user, "is_superuser", False)):
        return True
    return target_type == "case" and getattr(target, "created_by_user_id", None) == user.id
