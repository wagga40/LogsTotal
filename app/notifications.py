"""The nav bell — one badge, one dropdown, over three independent streams.

There are three kinds of alert and they are not the same thing:

* **entity-rule alerts** — an `IntelRule` with `scope="entity"` matched an entity in a job.
  Query-driven, member+, acknowledged per rule owner.
* **job-rule alerts** — an `IntelRule` with `scope="job"` matched a job. Also query-driven
  and member+, but keyed `(rule, job)` with no entity, which is why it is a separate table
  rather than a nullable column — see `JobRuleMatch`'s docstring.
* **job-watch events** — something happened on a job you subscribed to. Subscription-driven,
  any logged-in user, acknowledged per watcher.

They live in different tables for reasons argued in `JobWatch`'s and `JobRuleMatch`'s
docstrings, and they are unioned **here, in Python** rather than in SQL — the same call
`tags.tag_rows` makes, and for the same reason: three `LIMIT 25` queries merged by timestamp
is simpler to read and to get right than a UNION over dissimilar shapes, at a scale where it
cannot matter.

This lives outside both routers because both write into it: `/intel` acks a rule alert,
`/jobs` acks a watch event, and a router importing a router is how this codebase gets a
cycle.

**The visibility asymmetry is deliberate and is the thing to get right.**
`intel_rules._visible_rules` gives an admin *every* rule, which is correct for a shared
rule set. The job-watch half is `user_id == user.id` **for everyone, admins included** — a
watch belongs to exactly one person, so the same generosity would let one admin's
"Acknowledge all" silently empty every colleague's bell.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select

from app.models import (
    AnalysisJob,
    Entity,
    IntelRule,
    IntelRuleMatch,
    JobRuleMatch,
    JobWatch,
    JobWatchEvent,
    User,
    visible_job_filter,
)

DROPDOWN_LIMIT = 25

# How each job-watch event kind reads in the dropdown. A dict rather than a chain of
# template `{% if %}`s so an unknown kind degrades to something honest instead of a blank
# row — and so adding one is a line here, not a branch in markup.
KIND_LABELS = {
    "comment": "New comment",
    "ai": "AI analysis",
    "tag": "Tagged",
}


def alert_rule_ids(user: User):
    """Rule ids whose alerts belong to this user: their own rules, or every rule for an admin.

    **Ownership, not visibility.** A member may *read* every shared rule (`_visible_rules`),
    but an alert a shared rule raises is the admin's who switched "alert me" on. The one
    predicate for showing an alert (this bell, the Rules page) and for acknowledging it —
    when the two disagreed, a member's "Acknowledge all", its badge at 0, cleared alerts the
    admin had not yet seen.
    """
    if user.is_superuser:
        return select(IntelRule.id)
    return select(IntelRule.id).where(IntelRule.owner_user_id == user.id)


def _my_watches(user: User):
    """Watch ids belonging to this user — never widened for an admin. See the module note."""
    return select(JobWatch.id).where(JobWatch.user_id == user.id)


async def unacked_total(db, user: User) -> int:
    """The bell's badge: all three streams, one number."""
    mine = alert_rule_ids(user)
    rules = await db.scalar(select(func.count(IntelRuleMatch.id)).where(IntelRuleMatch.rule_id.in_(mine), IntelRuleMatch.acknowledged_at.is_(None))) or 0
    job_rules = await db.scalar(select(func.count(JobRuleMatch.id)).where(JobRuleMatch.rule_id.in_(mine), JobRuleMatch.acknowledged_at.is_(None))) or 0
    watches = await db.scalar(select(func.count(JobWatchEvent.id)).where(JobWatchEvent.watch_id.in_(_my_watches(user)), JobWatchEvent.acknowledged_at.is_(None))) or 0
    return rules + job_rules + watches


def newest_first(item: dict) -> datetime:
    """Sort key for the merged stream: a missing timestamp sorts oldest, never raises.

    `created_at` is server-defaulted and NOT NULL on both tables, so this is
    belt-and-braces — but the bell is one dropdown over two independent streams, and one
    bad row must not blank it for both. `datetime.min` and not `""`: the columns are naive
    `DateTime`, so a str fallback raises on the first comparison against a real timestamp,
    which is precisely the failure the fallback exists to prevent.
    """
    return item["at"] or datetime.min


async def dropdown_items(db, user: User) -> list[dict]:
    """The newest unacknowledged alerts from both streams, merged newest-first.

    Each item carries a `stream` discriminator so the template can render an entity chip for
    one and a job link for the other without guessing from which fields are present.
    """
    rule_rows = (
        await db.execute(
            select(IntelRuleMatch, Entity, AnalysisJob, IntelRule)
            .join(Entity, IntelRuleMatch.entity_id == Entity.id)
            .join(AnalysisJob, IntelRuleMatch.job_id == AnalysisJob.id)
            .join(IntelRule, IntelRuleMatch.rule_id == IntelRule.id)
            .where(IntelRuleMatch.rule_id.in_(alert_rule_ids(user)), IntelRuleMatch.acknowledged_at.is_(None))
            .order_by(IntelRuleMatch.created_at.desc())
            .limit(DROPDOWN_LIMIT)
        )
    ).all()

    # `visible_job_filter` even though the watcher subscribed themselves: a job can be made
    # private after the fact, and an event linking to a 404 would still leak that it exists.
    vis = visible_job_filter(user)

    # Job-rule alerts get the same treatment, and here it is not belt-and-braces: rule
    # evaluation checks visibility at *match* time, so an alert raised on a public job that
    # was made private afterwards would otherwise stay in the bell linking to a 404.
    job_rule_q = (
        select(JobRuleMatch, AnalysisJob, IntelRule)
        .join(AnalysisJob, JobRuleMatch.job_id == AnalysisJob.id)
        .join(IntelRule, JobRuleMatch.rule_id == IntelRule.id)
        .where(JobRuleMatch.rule_id.in_(alert_rule_ids(user)), JobRuleMatch.acknowledged_at.is_(None))
        .order_by(JobRuleMatch.created_at.desc())
        .limit(DROPDOWN_LIMIT)
    )
    if vis is not True:
        job_rule_q = job_rule_q.where(vis)
    job_rule_rows = (await db.execute(job_rule_q)).all()

    watch_q = (
        select(JobWatchEvent, AnalysisJob)
        .join(AnalysisJob, JobWatchEvent.job_id == AnalysisJob.id)
        .where(JobWatchEvent.watch_id.in_(_my_watches(user)), JobWatchEvent.acknowledged_at.is_(None))
        .order_by(JobWatchEvent.created_at.desc())
        .limit(DROPDOWN_LIMIT)
    )
    if vis is not True:
        watch_q = watch_q.where(vis)
    watch_rows = (await db.execute(watch_q)).all()

    items: list[dict] = [{"stream": "rule", "id": m.id, "at": m.created_at, "event": m, "entity": ent, "job": job, "rule": rule} for m, ent, job, rule in rule_rows]
    # No `entity` key, deliberately: the template branches on `stream`, and a None entity
    # that every branch has to guard is how a "job matched" row comes to render as a blank
    # observable chip.
    items += [{"stream": "jobrule", "id": m.id, "at": m.created_at, "event": m, "job": job, "rule": rule} for m, job, rule in job_rule_rows]
    items += [
        {
            "stream": "job",
            "id": ev.id,
            "at": ev.created_at,
            "event": ev,
            "job": job,
            "kind": ev.kind,
            "kind_label": KIND_LABELS.get(ev.kind, "Activity"),
        }
        for ev, job in watch_rows
    ]
    items.sort(key=newest_first, reverse=True)
    return items[:DROPDOWN_LIMIT]
