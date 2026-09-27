"""
Tag vocabulary management — member-or-above.

Tagging is CRUD over ``TagDefinition``/``EntityTag`` with no dependency on entity
intelligence: the entity page calls in to add and remove tags — and to save its analyst
note — while everything else here (the manager page, rename, merge, recolour,
delete-everywhere, bulk apply) is about the vocabulary rather than any one entity.

Routes live under the ``/intel`` prefix; ``tests/test_route_table_is_stable.py`` pins the
paths.
"""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity
from app.auth.users import current_member_or_above
from app.comments import clean_text
from app.constants import NOTE_MAX_LENGTH, TAG_COLORS
from app.database import get_async_session
from app.intel.queries import normalize_tag
from app.models import (
    Entity,
    EntityTag,
    JobTag,
    TagDefinition,
    User,
    visible_job_filter,
)
from app.site_settings import get_site_settings
from app.tags import (
    BULK_TAG_CAP,
    delete_tag_everywhere,
    ensure_tag_definition,
    merge_tag_into,
    parse_id_csv,
    parse_tag_write,
    rule_maintained_tags,
    set_tag_color,
    tag_rows,
)
from app.templates_config import negotiated as _negotiated
from app.templates_config import templates

router = APIRouter(prefix="/intel")


async def _render_tags_region(request: Request, db: AsyncSession, entity: Entity) -> HTMLResponse:
    tags = (await db.execute(select(EntityTag).where(EntityTag.entity_id == entity.id).order_by(EntityTag.tag))).scalars().all()
    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_header_tags.html",
        {"request": request, "entity": entity, "tags": tags, "tag_colors": TAG_COLORS},
    )


# ── Tag management ───────────────────────────────────────────────────────────
#
# The vocabulary an analyst builds up is the whole value of tagging, so it gets one place
# to be seen, renamed, merged and removed everywhere.


async def _render_tag_manager(request: Request, db: AsyncSession, user: User, q: str = "", sort: str = "count", notice: str = "", tone: str = "") -> HTMLResponse:
    # The Jobs column is a *link*, so its count must be what the reader will actually find
    # on the other side of it. `visible_job_filter` returns the literal True for an admin,
    # which is not a clause.
    vis = visible_job_filter(user)
    job_filter = None if vis is True else vis
    rows = await tag_rows(db, q, sort, job_filter=job_filter)
    total = len(await tag_rows(db, "", sort, limit=500, job_filter=job_filter))
    tagged_entities = await db.scalar(select(func.count(func.distinct(EntityTag.entity_id)))) or 0
    return _negotiated(
        request,
        page="intel/tags.html",
        fragment="intel/partials/_tag_manager_table.html",
        context={
            "request": request,
            "user": user,
            "tag_rows": rows,
            "tag_total": total,
            "tagged_entities": tagged_entities,
            "current_q": q,
            "current_sort": sort,
            "tag_colors": TAG_COLORS,
            "notice": notice,
            # "refused" recolours the slot and appends the link to Rules. A refusal in the
            # success colour is a refusal nobody reads.
            "notice_tone": tone,
        },
    )


@router.get("/tags", response_class=HTMLResponse)
async def tags_page(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    q: str = "",
    sort: str = "count",
):
    """Tag manager — the vocabulary an analyst has built, in one place.

    Serves the Intel dashboard's Tags tab too; there is no separate `-partial` route. The
    write handlers below re-render through the same helper, so a search, a create and a
    rename all come back in whichever representation the caller asked for.
    """
    return await _render_tag_manager(request, db, user, q, sort)


@router.post("/entities/bulk-tag", response_class=HTMLResponse)
async def entities_bulk_tag(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    entity_ids: str = Form(""),
    tag: str = Form(...),
    color: str = Form("gray"),
):
    """Apply one or more tags to many entities at once.

    The obvious workflow: search, then label what you found.
    """
    ids = parse_id_csv(entity_ids, BULK_TAG_CAP)
    pairs = parse_tag_write(tag, color)
    if not pairs:
        raise HTTPException(400, "Tag cannot be empty")
    if not ids:
        raise HTTPException(400, "No entities selected")

    # Only ids that exist — a stale selection must not create orphan rows.
    known = set((await db.execute(select(Entity.id).where(Entity.id.in_(ids)))).scalars().all())

    # Two counts, and the distinction matters once a submission can carry several tags:
    # `touched` is how many entities gained *something* (what the analyst asked about), and
    # `links` is how many rows that took. Reporting links as entities would say "tagged 6
    # entities" for two tags on three.
    touched: set[int] = set()
    links = 0
    for norm, safe_color in pairs:
        existing = set((await db.execute(select(EntityTag.entity_id).where(EntityTag.tag == norm, EntityTag.entity_id.in_(known)))).scalars().all())
        # Same instance-wide colour invariant the single-entity add form maintains.
        await ensure_tag_definition(db, norm, safe_color, user.id)
        await set_tag_color(db, norm, safe_color)
        for eid in known - existing:
            db.add(EntityTag(entity_id=eid, tag=norm, color=safe_color, created_by_user_id=user.id))
        touched |= known - existing
        links += len(known - existing)
    added = len(touched)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
    names = ", ".join(t for t, _ in pairs)
    if added:
        # One row carrying a count, never one per (tag, entity): a single click can
        # produce TAG_WRITE_MAX * BULK_TAG_CAP links, and the audit log is a record of what
        # a person did, not of every row it touched.
        await activity.record(
            "intel.tag.add",
            request=request,
            user=user,
            target_type="tag",
            target_id=pairs[0][0],
            summary=f"'{names}' applied to {added} entit{'y' if added == 1 else 'ies'}",
            meta={"count": added, "links": links, "bulk": True, "tags": [t for t, _ in pairs]},
        )
    return HTMLResponse(f'<span class="text-xs text-green-300">Tagged {added} entit{"y" if added == 1 else "ies"} with \u201c{escape(names)}\u201d.</span>')


@router.post("/entities/bulk-untag", response_class=HTMLResponse)
async def entities_bulk_untag(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    _user: User = Depends(current_member_or_above),
    entity_ids: str = Form(""),
    tag: str = Form(...),
):
    """Remove one or more tags from many entities at once."""
    ids = parse_id_csv(entity_ids, BULK_TAG_CAP)
    names = [t for t, _ in parse_tag_write(tag)]
    if not names or not ids:
        raise HTTPException(400, "Tag and selection are required")
    result = await db.execute(delete(EntityTag).where(EntityTag.tag.in_(names), EntityTag.entity_id.in_(ids)))
    await db.commit()
    n = result.rowcount or 0
    label = ", ".join(names)
    if n:
        await activity.record(
            "intel.tag.remove",
            request=request,
            user=_user,
            target_type="tag",
            target_id=names[0],
            summary=f"'{label}' removed from {n} entity tag{'' if n == 1 else 's'}",
            meta={"count": n, "bulk": True, "tags": names},
        )
    return HTMLResponse(f'<span class="text-xs text-green-300">Removed \u201c{escape(label)}\u201d from {n} entity tag{"" if n == 1 else "s"}.</span>')


@router.post("/tags", response_class=HTMLResponse)
async def tag_create(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    tag: str = Form(...),
    color: str = Form("gray"),
    description: str = Form(""),
    q: str = Form(""),
    sort: str = Form("count"),
):
    """Add one or more tags to the vocabulary before anything carries them."""
    pairs = parse_tag_write(tag, color)
    if not pairs:
        raise HTTPException(400, "Tag cannot be empty")

    created: list[str] = []
    existing: list[str] = []
    for norm, safe_color in pairs:
        existed = bool(await db.scalar(select(TagDefinition.id).where(TagDefinition.tag == norm)))
        await ensure_tag_definition(db, norm, safe_color, user.id)
        # One description for one tag only: it describes *this* name, and copying it across
        # several would put the same sentence under every one of them.
        if description.strip() and len(pairs) == 1:
            await db.execute(update(TagDefinition).where(TagDefinition.tag == norm).values(description=description.strip()[:300]))
        await set_tag_color(db, norm, safe_color)
        (existing if existed else created).append(norm)
    await db.commit()
    for norm in created:
        await activity.record("intel.tag.create", request=request, user=user, target_type="tag", target_id=norm, summary=norm)
    parts = []
    if created:
        made = ", ".join(created)
        parts.append(f"Created '{made}'.")
    if existing:
        had = ", ".join(existing)
        parts.append(f"'{had}' already exist{'s' if len(existing) == 1 else ''}.")
    return await _render_tag_manager(request, db, user, q, sort, notice=" ".join(parts))


async def _refused(request: Request, db: AsyncSession, user: User, q: str, sort: str, reason: str) -> HTMLResponse:
    """The region back, with the reason, scrolled to where the reason is.

    `show:top` rides on the *response*, not on the forms, so only a refusal moves the page.
    The notice renders at the top of the region and the form that was submitted can be a
    hundred rows below it — a refusal off-screen is the no-op this click already looked
    like. htmx parses `HX-Reswap` through the full `hx-swap` grammar, modifiers included.
    """
    response = await _render_tag_manager(request, db, user, q, sort, notice=reason, tone="refused")
    response.headers["HX-Reswap"] = "outerHTML show:top"
    return response


def _rules_phrase(names: list[str]) -> str:
    """One rule is a fact the reader can act on; several is a list to hunt through, and the
    link under the notice goes to the page holding all of them anyway."""
    return f"the shared rule '{names[0]}'" if len(names) == 1 else "shared rules"


def _merge_refusal(source: str, target: str, maintained: dict[str, list[str]], *, is_merge: bool) -> str:
    """Why this fold must not happen, or `""` when it may. Pure.

    Folding a rule-maintained name **away** is undone by the next matching job: history ends
    up under the new name while the rule keeps minting the old one, so the vocabulary splits
    in two and reads as a bug. Folding something **into** one puts a name that means "the
    shared rule matched this" onto entities the rule never matched. Neither can be unpicked
    afterwards — the rows carry no record of which name they arrived under.

    `is_merge` is what separates the two directions. A rename onto a name already in use *is*
    a merge (it goes through `merge_tag_into`), so the source check has to cover it or Merge
    is guarded and Rename is the back door. A rename to a fresh name stays allowed: equally
    futile, which the row's amber mark says, but reversible — you can rename back.

    The target check ignores `is_merge` deliberately. A shared rule that has not fired yet
    owns a name nothing carries, so renaming onto it is a rename by that test — and the first
    matching job pollutes it exactly as a merge would. "You may rename into it until the rule
    fires" is not a rule anyone could hold in their head.
    """
    if target in maintained:
        return (
            f"'{target}' is maintained by {_rules_phrase(maintained[target])}, so it means the rule matched this. "
            f"Folding '{source}' into it would put that name on entities the rule never matched."
        )
    if is_merge and source in maintained:
        return (
            f"'{source}' is maintained by {_rules_phrase(maintained[source])}: it comes back on the next matching job, "
            f"leaving history under '{target}' and new hits under '{source}'. Switch the rule off first."
        )
    return ""


async def _tag_exists(db: AsyncSession, tag: str) -> bool:
    """Is this name already in use anywhere — which is what makes a rename a merge.

    The vocabulary row counts: a tag can be agreed before anything carries it, and renaming
    onto one still folds two entries into one.
    """
    if await db.scalar(select(TagDefinition.id).where(TagDefinition.tag == tag)):
        return True
    if await db.scalar(select(EntityTag.id).where(EntityTag.tag == tag).limit(1)):
        return True
    return bool(await db.scalar(select(JobTag.id).where(JobTag.tag == tag).limit(1)))


@router.post("/tags/rename", response_class=HTMLResponse)
async def tag_rename(
    request: Request,
    tag: str = Form(...),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    new_tag: str = Form(...),
    color: str = Form(""),
    q: str = Form(""),
    sort: str = Form("count"),
):
    """Rename a tag everywhere. Renaming onto an existing name merges into it."""
    old = normalize_tag(tag)
    new = normalize_tag(new_tag)
    if not new:
        raise HTTPException(400, "Tag cannot be empty")
    if old != new:
        # A rename onto a name already in use is a merge, and a merge that a shared rule
        # would undo or pollute is refused — see `_merge_refusal`.
        refusal = _merge_refusal(old, new, await rule_maintained_tags(db), is_merge=await _tag_exists(db, new))
        if refusal:
            return await _refused(request, db, user, q, sort, refusal)
        await merge_tag_into(db, old, new, color=color or None)
        await db.commit()
        # Renaming onto an existing name is a merge, and the log says which happened —
        # the two are indistinguishable afterwards but not in their consequences.
        await activity.record(
            "intel.tag.rename",
            request=request,
            user=user,
            target_type="tag",
            target_id=new,
            summary=f"'{old}' renamed to '{new}'",
            meta={"from": old, "to": new},
        )
    return await _render_tag_manager(request, db, user, q, sort, notice=f"Renamed '{old}' to '{new}'.")


@router.post("/tags/merge", response_class=HTMLResponse)
async def tag_merge(
    request: Request,
    tag: str = Form(...),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    into: str = Form(...),
    color: str = Form(""),
    q: str = Form(""),
    sort: str = Form("count"),
):
    """Fold this tag into another. The surviving rows all take one colour."""
    old = normalize_tag(tag)
    target = normalize_tag(into)
    if not target:
        raise HTTPException(400, "Target tag cannot be empty")
    if old == target:
        return await _render_tag_manager(request, db, user, q, sort)
    refusal = _merge_refusal(old, target, await rule_maintained_tags(db), is_merge=True)
    if refusal:
        # 200 with the region and the reason, never an `HTTPException`: this posts from
        # `hx-post` into `#tag-manager-region`, and htmx does not swap a non-2xx — a 400
        # leaves the page looking as though the click did nothing at all.
        return await _refused(request, db, user, q, sort, refusal)
    await merge_tag_into(db, old, target, color=color or None)
    await db.commit()
    await activity.record(
        "intel.tag.merge",
        request=request,
        user=user,
        target_type="tag",
        target_id=target,
        summary=f"'{old}' merged into '{target}'",
        meta={"from": old, "into": target},
    )
    return await _render_tag_manager(request, db, user, q, sort, notice=f"Merged '{old}' into '{target}'.")


@router.post("/tags/recolor", response_class=HTMLResponse)
async def tag_recolor(
    request: Request,
    tag: str = Form(...),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    color: str = Form("gray"),
    q: str = Form(""),
    sort: str = Form("count"),
):
    """One colour per tag name, instance-wide — same invariant the add form maintains."""
    norm = normalize_tag(tag)
    safe = color if color in TAG_COLORS else "gray"
    await set_tag_color(db, norm, safe)
    await db.commit()
    await activity.record("intel.tag.recolor", request=request, user=user, target_type="tag", target_id=norm, summary=f"'{norm}' set to {safe}", meta={"color": safe})
    return await _render_tag_manager(request, db, user, q, sort)


@router.post("/tags/delete", response_class=HTMLResponse)
async def tag_delete_everywhere(
    request: Request,
    tag: str = Form(...),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    q: str = Form(""),
    sort: str = Form("count"),
):
    """Remove a tag from every entity carrying it."""
    norm = normalize_tag(tag)
    await delete_tag_everywhere(db, norm)
    await db.commit()
    # Irreversible and instance-wide: the tag disappears from every entity at once.
    await activity.record("intel.tag.delete_everywhere", request=request, user=user, target_type="tag", target_id=norm, summary=norm)
    return await _render_tag_manager(request, db, user, q, sort, notice=f"Deleted '{norm}' and removed it from every entity.")


@router.post("/entities/{entity_id}/tags", response_class=HTMLResponse)
async def entity_tag_add(
    request: Request,
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    tag: str = Form(...),
    color: str = Form("gray"),
):
    """Add one or more tags to the entity (or recolor them); returns the tags region.

    A tag name carries **one color instance-wide** — the same label meaning different
    colors on different entities makes the chips useless for scanning. So the submitted
    color is applied to every row bearing that name, not just this entity's. The add form
    pre-fills the color of a known tag, so the normal flow preserves it and only a
    deliberate change recolors.

    Re-adding a tag that is already on this entity is not an error: it just applies the
    color. The IntegrityError branch remains as the concurrent-insert fallback.
    """
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")
    pairs = parse_tag_write(tag, color)
    if not pairs:
        raise HTTPException(400, "Tag cannot be empty")

    added: list[str] = []
    for norm, safe_color in pairs:
        # One color per tag name, everywhere it appears — including the vocabulary row, so a
        # tag first coined here is still offered by the picker after its last entity is removed.
        await ensure_tag_definition(db, norm, safe_color, user.id)
        await set_tag_color(db, norm, safe_color)

        existing = (await db.execute(select(EntityTag).where(EntityTag.entity_id == entity.id, EntityTag.tag == norm))).scalar_one_or_none()
        if existing is None:
            db.add(EntityTag(entity_id=entity.id, tag=norm, color=safe_color, created_by_user_id=user.id))
            added.append(norm)
    try:
        await db.commit()
    except IntegrityError:
        # Lost an insert race. The racing row exists, but the rollback drops the whole
        # transaction with it — the colour writes and any sibling tags from the same
        # submission. The region returned below re-reads from the DB, so the analyst sees
        # the true state; the activity row still names everything in `added`.
        await db.rollback()
    if added:
        names = ", ".join(added)
        # Only genuine additions. Re-adding to apply a colour is a recolour, not a tagging.
        await activity.record(
            "intel.tag.add",
            request=request,
            user=user,
            target_type="entity",
            target_id=str(entity.id),
            summary=f"'{names}' on {entity.value}",
            meta={"tags": added},
        )
    return await _render_tags_region(request, db, entity)


# Tag names travel as form data; URL normalization must never change an action.
@router.post("/entities/{entity_id}/tags/remove", response_class=HTMLResponse)
async def entity_tag_remove(
    request: Request,
    entity_id: int,
    tag: str = Form(...),
    db: AsyncSession = Depends(get_async_session),
    _user: User = Depends(current_member_or_above),
):
    """Remove a tag from the entity; returns the updated tags region."""
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")
    norm = normalize_tag(tag)
    existing = (await db.execute(select(EntityTag).where(EntityTag.entity_id == entity.id, EntityTag.tag == norm))).scalar_one_or_none()
    if existing:
        await db.delete(existing)
        await db.commit()
        await activity.record(
            "intel.tag.remove",
            request=request,
            user=_user,
            target_type="entity",
            target_id=str(entity.id),
            summary=f"'{norm}' from {entity.value}",
            meta={"tag": norm},
        )
    return await _render_tags_region(request, db, entity)


@router.post("/entities/{entity_id}/notes", response_class=HTMLResponse)
async def entity_notes_save(
    request: Request,
    entity_id: int,
    db: AsyncSession = Depends(get_async_session),
    _user: User = Depends(current_member_or_above),
    body: str = Form(""),
):
    """Save (or clear, when empty) the analyst note for this entity.

    Over-cap input is rejected with a 400 rather than silently truncated, matching
    `cases.py::case_notes_save` — losing the tail of an analyst's write without
    telling them is worse than making them shorten it.
    """
    entity = await db.get(Entity, entity_id)
    if not entity:
        raise HTTPException(404, "Entity not found")
    entity.notes = clean_text(body, NOTE_MAX_LENGTH, label="Note")
    await db.commit()
    return templates.TemplateResponse(
        request,
        "intel/partials/_entity_notes.html",
        {"request": request, "entity": entity, "site_settings": await get_site_settings(db)},
    )
