"""Discussion threads on cases, entities, and jobs.

One router, one partial, three targets. Read/write gating differs per target and lives in
`_resolve_target` rather than on the route dependencies, because the three targets have
genuinely different audiences:

  * case   — member+, and the case must be visible (own or shared)
  * entity — member+ (Intel is member-only)
  * job    — any logged-in user who can already view the job; anonymous never

Every route therefore takes `current_user_required` and escalates from there.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity, job_watch
from app.auth.users import MEMBER_ROLES, current_user_required
from app.comments import COMMENT_MAX, TARGET_TYPES, can_delete, can_edit, clean_text, thread_for
from app.database import get_async_session
from app.models import AnalysisJob, Comment, Entity, InvestigationCase, User, can_view_job
from app.site_settings import get_site_settings
from app.templates_config import templates

router = APIRouter(prefix="/comments")

# One 404 message per resource kind. "No such row" and "exists but you may not see it"
# must be indistinguishable, or the 404 text becomes an existence oracle — same reasoning
# as routers/cases.py::case_job_note_save.
_NOT_FOUND = {"case": "Case not found", "entity": "Entity not found", "job": "Job not found"}


def _is_member(user: User) -> bool:
    return bool(user.is_superuser) or user.role in MEMBER_ROLES


async def _resolve_target(db: AsyncSession, target_type: str, target_id: int, user: User):
    """Return the target row for a thread, or raise 404/403.

    Also the authorization gate — see the module docstring for the per-target rules.
    """
    if target_type not in TARGET_TYPES:
        raise HTTPException(404, "Unknown comment target")

    if target_type == "job":
        job = await db.get(AnalysisJob, target_id)
        # A private job the requester can't see is treated as non-existent.
        if not job or not can_view_job(job, user):
            raise HTTPException(404, _NOT_FOUND["job"])
        return job

    # Cases and entities are Intel surfaces: member-or-above only.
    if not _is_member(user):
        raise HTTPException(403, "Member access required.")

    if target_type == "entity":
        entity = await db.get(Entity, target_id)
        if not entity:
            raise HTTPException(404, _NOT_FOUND["entity"])
        return entity

    case = await db.get(InvestigationCase, target_id)
    if not case or not (user.is_superuser or case.created_by_user_id == user.id or case.is_shared):
        raise HTTPException(404, _NOT_FOUND["case"])
    return case


def _target_of(comment: Comment) -> tuple[str, int]:
    """Recover `(target_type, target_id)` from whichever FK the row populated."""
    for kind, value in (("case", comment.case_id), ("entity", comment.entity_id), ("job", comment.job_id)):
        if value is not None:
            return kind, int(value)
    raise HTTPException(404, "Comment has no target")  # ck_comment_single_target makes this unreachable


async def _render_thread(request: Request, db: AsyncSession, target_type: str, target_id: int, user: User, target) -> HTMLResponse:
    comments, total = await thread_for(db, target_type, target_id)
    rows = [
        {
            "c": c,
            "can_edit": can_edit(c, user),
            "can_delete": can_delete(c, user, target_type=target_type, target=target),
        }
        for c in comments
    ]
    return templates.TemplateResponse(
        request,
        "partials/_comment_thread.html",
        {
            "request": request,
            "user": user,
            "target_type": target_type,
            "target_id": target_id,
            "rows": rows,
            "total": total,
            "shown": len(rows),
            "comment_max": COMMENT_MAX,
            # Drives Markdown rendering via the rich_text() macro. Absent would mean "on",
            # which would ignore an instance that switched it off.
            "site_settings": await get_site_settings(db),
        },
    )


async def _load_comment_or_404(db: AsyncSession, comment_id: int, user: User) -> tuple[Comment, str, int, object]:
    """Fetch a live comment and re-authorize against its target.

    Re-running `_resolve_target` (rather than trusting the comment id) is what stops a
    member who has since lost access to a case from editing through a stale id.
    """
    comment = await db.get(Comment, comment_id)
    if comment is None or comment.deleted_at is not None:
        raise HTTPException(404, "Comment not found")
    target_type, target_id = _target_of(comment)
    target = await _resolve_target(db, target_type, target_id, user)
    return comment, target_type, target_id, target


@router.post("/{comment_id}/edit", response_class=HTMLResponse)
async def comment_edit(
    request: Request,
    comment_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
    body: str = Form(""),
):
    """Edit your own comment. Admins can delete other people's comments but not rewrite
    them — silently changing what a colleague said on an investigation is worse than
    removing it."""
    comment, target_type, target_id, target = await _load_comment_or_404(db, comment_id, user)
    if not can_edit(comment, user):
        raise HTTPException(403, "Only the author can edit this comment")
    text = clean_text(body, COMMENT_MAX, label="Comment")
    if text:
        comment.body = text
        comment.edited_at = datetime.now(UTC).replace(tzinfo=None)
        await db.commit()
        await activity.record(
            "discussion.edit",
            request=request,
            user=user,
            target_type=target_type,
            target_id=str(target_id),
            summary=f"comment #{comment.id} on {target_type} #{target_id}",
        )
    return await _render_thread(request, db, target_type, target_id, user, target)


@router.post("/{comment_id}/delete", response_class=HTMLResponse)
async def comment_delete(
    request: Request,
    comment_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Soft-delete a comment: the body is blanked so the text is genuinely gone, while
    the row survives as an audit trail of who removed what. Author, admin, or (for a case
    thread) the case owner."""
    comment, target_type, target_id, target = await _load_comment_or_404(db, comment_id, user)
    if not can_delete(comment, user, target_type=target_type, target=target):
        raise HTTPException(403, "Not allowed to delete this comment")
    author_was_someone_else = comment.author_user_id != user.id
    comment.body = ""
    comment.deleted_at = datetime.now(UTC).replace(tzinfo=None)
    comment.deleted_by_user_id = user.id
    await db.commit()
    # Whether it was somebody else's is the fact worth surfacing: an admin or case owner
    # removing a colleague's words is the case this record exists for.
    await activity.record(
        "discussion.delete",
        request=request,
        user=user,
        target_type=target_type,
        target_id=str(target_id),
        summary=f"comment #{comment.id} on {target_type} #{target_id}" + (" (another author's)" if author_was_someone_else else ""),
        meta={"comment_id": comment.id, "own_comment": not author_was_someone_else},
    )
    return await _render_thread(request, db, target_type, target_id, user, target)


# ── Thread routes ────────────────────────────────────────────────────────────
#
# Registered AFTER /{comment_id}/edit and /{comment_id}/delete on purpose: both shapes
# are two segments, so `/comments/5/delete` also matches `/comments/{target_type}/{target_id}`
# and would 422 trying to coerce "delete" to an int. Starlette matches in registration
# order, so the literal-suffix routes must come first. Same hazard the `list.json`
# ordering comment in routers/cases.py calls out.


@router.get("/{target_type}/{target_id}", response_class=HTMLResponse)
async def comment_thread(
    request: Request,
    target_type: str,
    target_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
):
    """Render a target's discussion thread."""
    target = await _resolve_target(db, target_type, target_id, user)
    return await _render_thread(request, db, target_type, target_id, user, target)


@router.post("/{target_type}/{target_id}", response_class=HTMLResponse)
async def comment_create(
    request: Request,
    target_type: str,
    target_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_user_required),
    body: str = Form(""),
):
    """Post a comment. An empty body is a no-op re-render, not a 400 — the same
    forgiving treatment the notes forms give a blank submit."""
    target = await _resolve_target(db, target_type, target_id, user)
    text = clean_text(body, COMMENT_MAX, label="Comment")
    event_ids: list[int] = []
    if text:
        comment = Comment(**{f"{target_type}_id": target_id}, author_user_id=user.id, body=text)
        db.add(comment)
        if target_type == "job":
            # Auto-watch on comment. One upsert in a route that already writes, and it is
            # what makes a discussion a discussion: without it the second person's reply is
            # never seen by the first. In the *same transaction* as the comment rather than
            # via a task — a subscription is a first-class effect of the click, and must not
            # depend on Redis being up.
            await job_watch.ensure_watch_async(db, target_id, user.id)
            await db.flush()  # the comment id and the watch id have to exist to fan out
            # Inline, not enqueued: a few reads plus one insert per watcher, bounded at
            # MAX_WATCHERS_FANOUT. Running it here keeps the notification atomic with the
            # comment and takes Redis out of the path entirely.
            event_ids = await job_watch.record_events_async(
                db,
                kind="comment",
                job_id=target_id,
                ref_id=comment.id,
                actor_user_id=user.id,
                summary=f"{user.display_name or user.email} commented",
            )
        await db.commit()
        if target_type == "job" and event_ids:
            # After the commit: a rollback must never strand a queued delivery for events
            # that do not exist.
            await job_watch.enqueue_webhooks_async(db, target_id, event_ids)
        # The length, never the text — see the note beside the `discussion.*` actions.
        await activity.record(
            "discussion.comment",
            request=request,
            user=user,
            target_type=target_type,
            target_id=str(target_id),
            summary=f"comment on {target_type} #{target_id}",
            meta={"chars": len(text)},
        )
    return await _render_thread(request, db, target_type, target_id, user, target)
