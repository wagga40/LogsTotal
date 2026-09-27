"""The analyst tag vocabulary — one set of names and colours, several things to hang it on.

The rule this module exists to enforce is that a tag means **one thing instance-wide**:
`apt29` is one entry in the vocabulary, one colour, whether it is on an entity or on a job.
Rename, merge, recolour and delete-everywhere therefore have to reach every link table, and
the moment that logic lives inside a router it can only reach the tables that router knows
about.

A router importing another router is how this codebase gets an import cycle, so the shared
half lives here — the ``app/comments.py`` ↔ ``app/routers/comments.py`` split, for the same
reason. These functions take a ``user_id`` rather than a ``User`` so nothing here has to
import the auth layer.

**Two link tables, and the duplication in ``merge_tag_into`` is deliberate.** The unique
constraints are per table (``uq_entity_tag(entity_id, tag)`` and ``uq_job_tag(job_id,
tag)``) and collide independently — an entity carrying both names collides only in
``entity_tag`` — so the delete-dupes-then-update pair is written once per table rather than
generalised into something that reads as one statement and is not.

Nothing here commits. Callers own the transaction, the same contract as
``app/intel/rules.py``.
"""

from __future__ import annotations

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.constants import TAG_COLORS
from app.database import parse_row_id
from app.intel.queries import escape_like, normalize_tag
from app.models import AnalysisJob, EntityTag, IntelRule, JobTag, SiteSettings, TagDefinition

# Cap on how many ids one bulk tag/untag may touch. A module constant rather than a
# Settings field, like `MAX_RULES_EVALUATED` — it bounds a single request, not a
# deployment's behaviour, and nobody has ever wanted it configurable.
BULK_TAG_CAP = 500

TAG_PAGE_SIZE = 100

#: How many tags one submission may apply. Matches `TAG_QUERY_MAX` on the read side, so
#: "label these with the five tags I search for" is expressible in both directions. A module
#: constant rather than a Settings field, like `BULK_TAG_CAP` above.
TAG_WRITE_MAX = 10


def parse_tag_write(tags: str, colors: str = "") -> list[tuple[str, str]]:
    """`("apt29,c2", "red,blue")` → `[("apt29", "red"), ("c2", "blue")]`.

    The one parser for every tag *write*, and the reason it is one function rather than a
    line in each route is that two rules have to hold together everywhere:

    * **normalization matches the read path.** `normalize_tag` is what `tag:` queries use,
      so a tag written any other way is a tag that cannot be found.
    * **colours are index-aligned and validated.** The picker sends one colour per tag
      because each pill keeps the colour of the tag it names; a single colour for the whole
      submission would repaint every existing tag in it, and a tag carries one colour
      instance-wide.

    Degrades in the useful direction at every step: a short colour list reuses the last
    colour given, an unknown colour becomes `gray`, blanks and duplicates drop out, and the
    whole thing is capped. A single `tag=x&color=red` — which is what every non-picker
    caller sends — parses to exactly one pair.

    No name is reserved: the shipped labels are ordinary tags written by ordinary rules. An
    analyst may type `lolbin`; a built-in rule may already have.
    """
    palette = [c.strip().lower() for c in (colors or "").split(",")]
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for i, part in enumerate((tags or "").split(",")):
        tag = normalize_tag(part)
        if not tag or tag in seen:
            continue
        # Walk back for the colour rather than indexing: `?tags=a,b,c&color=red` means "all
        # of them red", which is what a caller who sends one colour intends.
        color = next((c for c in reversed(palette[: i + 1]) if c), "gray")
        out.append((tag, color if color in TAG_COLORS else "gray"))
        seen.add(tag)
        if len(out) >= TAG_WRITE_MAX:
            break
    return out


def parse_id_csv(raw: str, cap: int) -> list[int]:
    """Ids from a comma-separated field, entries no row could have dropped, capped."""
    out: list[int] = []
    for part in (raw or "").split(","):
        n = parse_row_id(part)
        if n is None:
            continue
        out.append(n)
        if len(out) >= cap:
            break
    return out


async def ensure_tag_definition(db: AsyncSession, tag: str, color: str, user_id=None) -> None:
    """Register a tag in the vocabulary if it is not there yet. Idempotent.

    Called from the apply paths so a tag first coined by tagging something still exists in
    the picker after its last entity is removed — and from the watch-rule form, so naming a
    tag in a rule coins it there and then rather than when the rule first matches.

    **A savepoint, not `db.rollback()`.** Rolling the session back on the race would discard
    the *whole* outer transaction rather than the failed insert — the bug
    `app/intel/rules.py::_record_matches` uses savepoints to avoid: a collision while
    registering the tenth tag of a bulk write would undo the nine before it.
    """
    if await db.scalar(select(TagDefinition.id).where(TagDefinition.tag == tag)):
        return
    try:
        async with db.begin_nested():
            db.add(TagDefinition(tag=tag, color=color, created_by_user_id=user_id))
            await db.flush()
    except IntegrityError:
        pass  # lost an insert race; the definition exists, which is the point


def ensure_tag_definition_sync(db: Session, tag: str, color: str, user_id=None) -> None:
    """`ensure_tag_definition` for the worker — the `app/activity.py` twin shape.

    The rule engine runs in Huey, sync, and cannot call the async version. Without this, a
    tag coined by a rule would be missing from the manager until the rule first fired, and
    vanish again when its last `EntityTag` row went — unlike every tag coined by hand.

    Deliberately does **not** recolour. `_apply_tag` reads the vocabulary's colour for a
    name that already exists precisely so an automated rule cannot repaint an analyst's
    palette, and registering must not smuggle that repaint back in through the other door.
    """
    if db.scalar(select(TagDefinition.id).where(TagDefinition.tag == tag)):
        return
    try:
        with db.begin_nested():
            db.add(TagDefinition(tag=tag, color=color, created_by_user_id=user_id))
            db.flush()
    except IntegrityError:
        pass  # lost an insert race; the definition exists, which is the point


async def set_tag_color(db: AsyncSession, tag: str, color: str) -> None:
    """Apply one colour to a tag everywhere it can live: the two association tables the
    chips render from, and the vocabulary row that survives when nothing carries it."""
    await db.execute(update(EntityTag).where(EntityTag.tag == tag, EntityTag.color != color).values(color=color))
    await db.execute(update(JobTag).where(JobTag.tag == tag, JobTag.color != color).values(color=color))
    await db.execute(update(TagDefinition).where(TagDefinition.tag == tag, TagDefinition.color != color).values(color=color))


async def rule_maintained_tags(db: AsyncSession) -> dict[str, list[str]]:
    """The tag names a **live** shared rule re-applies, mapped to the rules that write them.

    One predicate behind both the manager's amber mark and the merge guard. They answer the
    same question about the same tag — "will this name come back on its own?" — so they
    share one answer.

    **Live, not merely declared.** A rule an admin switched off, or a whole instance running
    with `SiteSettings.builtin_rules_enabled` false, writes nothing: the tag is ordinary and
    merges like any other.

    Read from the rule rows rather than a list of reserved names, because a shared rule is a
    row an admin can edit, import or add — no registry could know the answer. And parsed
    through `parse_tag_write`, the same function the engine's `_apply_tag` uses, so the names
    here are exactly the ones that will be written: a rule spelling its tag `LolBin` writes
    `lolbin`, and a rule naming twelve tags writes the first `TAG_WRITE_MAX`.
    """
    site = await db.scalar(select(SiteSettings.builtin_rules_enabled).limit(1))
    if site is not None and not site:
        return {}
    rows = (
        await db.execute(
            select(IntelRule.name, IntelRule.action_tag, IntelRule.action_tag_color).where(IntelRule.is_builtin.is_(True), IntelRule.enabled.is_(True)).order_by(IntelRule.name)
        )
    ).all()
    out: dict[str, list[str]] = {}
    for name, csv, colors in rows:
        for tag, _color in parse_tag_write(csv or "", colors or "gray"):
            names = out.setdefault(tag, [])
            if name not in names:
                names.append(name)
    return out


async def merge_tag_into(db: AsyncSession, old: str, new: str, *, color: str | None = None) -> None:
    """Move every row from `old` to `new`, leaving one colour behind.

    Each link table's unique constraint means a row carrying *both* names would collide on
    a plain UPDATE, so the dupes are dropped first and the rest updated — once per table,
    because the two constraints are independent. Correct on SQLite and PostgreSQL alike,
    and idempotent.

    The colour pass is not optional. Moved rows keep the colour they had under the old
    name, so without it a merge leaves `beta` rendered red on some rows and blue on others
    — silently breaking the one-colour-per-name invariant that makes chips scannable.

    **The fallback chain starts at `TagDefinition`**, and that is not a cosmetic ordering.
    `min(EntityTag.color)` is NULL for a tag used only on *jobs*, which would skip the
    recolour pass and leave the moved rows in their old-name colour. Every write path
    maintains the definition row, so it is the one source that is always there.
    """
    if color not in TAG_COLORS:
        color = None
    if color is None:
        color = await db.scalar(select(TagDefinition.color).where(TagDefinition.tag == new))
    if color is None:
        color = await db.scalar(select(TagDefinition.color).where(TagDefinition.tag == old))
    if color is None:
        color = await db.scalar(select(func.min(EntityTag.color)).where(EntityTag.tag == new))
    if color is None:
        color = await db.scalar(select(func.min(EntityTag.color)).where(EntityTag.tag == old))
    if color is None:
        color = await db.scalar(select(func.min(JobTag.color)).where(JobTag.tag == new))
    if color is None:
        color = await db.scalar(select(func.min(JobTag.color)).where(JobTag.tag == old))

    entity_dupes = select(EntityTag.entity_id).where(EntityTag.tag == new)
    await db.execute(delete(EntityTag).where(EntityTag.tag == old, EntityTag.entity_id.in_(entity_dupes)))
    await db.execute(update(EntityTag).where(EntityTag.tag == old).values(tag=new))

    job_dupes = select(JobTag.job_id).where(JobTag.tag == new)
    await db.execute(delete(JobTag).where(JobTag.tag == old, JobTag.job_id.in_(job_dupes)))
    await db.execute(update(JobTag).where(JobTag.tag == old).values(tag=new))

    # The vocabulary follows the association: rename the definition when the target has
    # none, otherwise the two have merged and the old definition goes with it.
    old_def = (await db.execute(select(TagDefinition).where(TagDefinition.tag == old))).scalar_one_or_none()
    if old_def is not None:
        target_def = (await db.execute(select(TagDefinition).where(TagDefinition.tag == new))).scalar_one_or_none()
        if target_def is None:
            old_def.tag = new
        else:
            await db.delete(old_def)
        await db.flush()

    if color:
        await set_tag_color(db, new, color)


async def delete_tag_everywhere(db: AsyncSession, tag: str) -> None:
    """Remove a tag from every link table and from the vocabulary.

    One function so a new link table cannot be added to `set_tag_color` and forgotten
    here — which would leave the tag deleted from the manager and still rendering on rows.
    """
    await db.execute(delete(EntityTag).where(EntityTag.tag == tag))
    await db.execute(delete(JobTag).where(JobTag.tag == tag))
    await db.execute(delete(TagDefinition).where(TagDefinition.tag == tag))


async def tag_rows(db: AsyncSession, q: str = "", sort: str = "count", limit: int = TAG_PAGE_SIZE, *, job_filter=None) -> list[dict]:
    """Every tag in the vocabulary, with usage counts. Shared by the page and its partial.

    Unioned from three sources: `entity_tag` and `job_tag` (tags in use) and
    `tag_definition` (the vocabulary, including tags nobody has applied yet). Without the
    last, a tag could only come into existence by being applied to something, which makes
    "agree a vocabulary, then label against it" impossible — and leaves the manager able to
    edit only tags that work has already been done in.

    `job_filter` is a prebuilt WHERE clause over `AnalysisJob`, not a `User`: this module
    imports no auth layer, and the caller already holds `visible_job_filter(user)`. Pass it,
    or the Jobs column promises rows the reader cannot open — and it is a *link*, so an
    over-count lands them on a shorter list with no explanation. Entities need no equivalent:
    every entity is visible to every member.

    `count` means **entities**, with jobs reported separately as `job_count`: the manager's
    column is headed Entities, and a total there would change every number on the page
    without changing its heading.
    """
    q = (q or "").strip()
    pattern = f"%{escape_like(q)}%" if q else ""

    used_stmt = select(
        EntityTag.tag,
        func.count(EntityTag.id).label("n"),
        func.min(EntityTag.color).label("color"),
        func.max(EntityTag.created_at).label("last_used"),
    ).group_by(EntityTag.tag)
    jobs_stmt = select(
        JobTag.tag,
        func.count(JobTag.id).label("n"),
        func.min(JobTag.color).label("color"),
        func.max(JobTag.created_at).label("last_used"),
    ).group_by(JobTag.tag)
    if job_filter is not None:
        jobs_stmt = jobs_stmt.join(AnalysisJob, AnalysisJob.id == JobTag.job_id).where(job_filter)
    def_stmt = select(TagDefinition.tag, TagDefinition.color, TagDefinition.description)
    if q:
        used_stmt = used_stmt.where(EntityTag.tag.ilike(pattern, escape="\\"))
        jobs_stmt = jobs_stmt.where(JobTag.tag.ilike(pattern, escape="\\"))
        def_stmt = def_stmt.where(TagDefinition.tag.ilike(pattern, escape="\\"))

    builtin_tags = await rule_maintained_tags(db)
    used = {r[0]: r for r in (await db.execute(used_stmt)).all()}
    jobs = {r[0]: r for r in (await db.execute(jobs_stmt)).all()}
    defs = {r[0]: r for r in (await db.execute(def_stmt)).all()}

    rows: list[dict] = []
    for tag in set(used) | set(jobs) | set(defs):
        u, j, d = used.get(tag), jobs.get(tag), defs.get(tag)
        last_used = max([x for x in (u[3] if u else None, j[3] if j else None) if x is not None], default=None)
        rows.append(
            {
                "tag": tag,
                "count": int(u[1] or 0) if u else 0,
                "job_count": int(j[1] or 0) if j else 0,
                # A tag in use takes the colour its chips already render from; an unused one
                # has only its definition to go on.
                "color": (u[2] if u else None) or (j[2] if j else None) or (d[1] if d else None) or "gray",
                "last_used": last_used,
                "description": d[2] if d else None,
                # "A *live* shared rule reapplies this" — see `rule_maintained_tags` for what
                # live excludes. Deleting one is futile — it
                # comes back on the next matching job — and an analyst who does not know
                # that reads the reappearance as a bug. Merging one is refused outright
                # (`routers/intel_tags.py::_merge_refusal`), because the reappearance would
                # arrive under the old name and split the tag in two.
                "is_builtin": tag in builtin_tags,
                "defined": d is not None,
            }
        )

    # Sorted in Python because the sources are unioned here, not in SQL — the row count is
    # the tag vocabulary, which is small by construction.
    if sort == "name":
        rows.sort(key=lambda r: r["tag"])
    elif sort == "recent":
        # Descending. Ascending on `last_used` is "least recently used", which is the
        # opposite of what the option says — and looks like the control is ignored, because
        # the list does change, just the wrong way. Never-applied tags sort last, then name.
        rows.sort(key=lambda r: (r["last_used"] is None, -(r["last_used"].timestamp() if r["last_used"] else 0.0), r["tag"]))
    else:
        # Ranked on total usage: a tag applied to forty jobs and no entities is not an
        # unused tag, and burying it under the Entities column would say it was.
        rows.sort(key=lambda r: (-(r["count"] + r["job_count"]), r["tag"]))
    return rows[: min(max(limit, 1), 500)]
