"""Watching a job — subscribe, and be told when something happens on it.

A **subscription**, not a query. That is the whole design, and it is why this is not an
`IntelRule`: see `JobWatch`'s docstring for why making `IntelRuleMatch.entity_id` nullable
would quietly destroy that table's idempotency guarantee.

Async/sync twins, the `app/activity.py` shape, because the three triggers live on both
sides of the process boundary: a comment arrives in an async FastAPI route, an AI analysis
finishes inside a sync Huey task. No FastAPI and no Huey imports here.

Three rules the callers depend on:

* **Visibility is `models.can_view_job`**, not a copy of it. `intel/rules.py` already
  carries a near-duplicate (`_owner_can_see_job`); a third would be the one that eventually
  gets it wrong, and getting it wrong means notifying someone about a job they cannot open.
* **Nothing here commits.** The caller owns the transaction, same contract as
  `app/intel/rules.py` and `app/tags.py`.
* **The unique constraint is the idempotency guarantee**, so a retried task or a
  double-submitted form cannot raise the same alert twice. Inserts go through a savepoint
  so a collision cannot roll back the caller's own work.
"""

from __future__ import annotations

import logging

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from app.database import utc_now_naive
from app.models import AnalysisJob, JobWatch, JobWatchEvent, can_view_job, has_intel_access

_log = logging.getLogger(__name__)

# What a watch can tell you about.
WATCH_EVENT_KINDS = ("comment", "ai", "tag")

# Ceiling on how many watchers one event fans out to. A module constant rather than a
# Settings field — the same call `MAX_RULES_EVALUATED` makes. It bounds one write, not a
# deployment's behaviour, and an instance with more than a hundred people watching one job
# has a communication problem a config knob will not fix.
MAX_WATCHERS_FANOUT = 100

# Ceiling on watches per user, so a script cannot turn the bell into a firehose.
JOB_WATCH_MAX_PER_USER = 200

_SUMMARY_MAX = 200


def should_notify(kind: str, watcher_id, actor_id) -> bool:
    """Should *this* watcher hear about an event *this* actor caused?

    The asymmetry lives here, in one function, because it is a judgement call rather than a
    rule and it needs somewhere to be argued:

    * **comment / tag — not the actor.** These are the synchronous consequence of a click
      the actor just made. Telling them about it is pure badge noise, and badge noise is
      how people learn to ignore a bell.
    * **ai — including the actor.** An AI run is a long-running background job whose
      completion is exactly the thing the requester cannot see: the pane only polls while
      the page is open, so "it finished" is genuinely new information to them.
    """
    if kind == "ai":
        return True
    if actor_id is None or watcher_id is None:
        return True
    return str(watcher_id) != str(actor_id)


# ── Subscriptions ────────────────────────────────────────────────────────────


async def ensure_watch_async(db, job_id: int, user_id) -> JobWatch | None:
    """Subscribe *user_id* to *job_id*, or return the existing subscription.

    Returns None when the per-user cap is reached — silently, because this is called as a
    side effect of commenting, and failing someone's comment because they watch too many
    jobs would be absurd.
    """
    existing = (await db.execute(select(JobWatch).where(JobWatch.job_id == job_id, JobWatch.user_id == user_id))).scalar_one_or_none()
    if existing is not None:
        return existing

    from sqlalchemy import func

    count = await db.scalar(select(func.count(JobWatch.id)).where(JobWatch.user_id == user_id)) or 0
    if count >= JOB_WATCH_MAX_PER_USER:
        return None

    watch = JobWatch(job_id=job_id, user_id=user_id)
    db.add(watch)
    try:
        async with db.begin_nested():
            await db.flush()
    except IntegrityError:
        # Lost an insert race; the subscription exists, which is what was wanted.
        return (await db.execute(select(JobWatch).where(JobWatch.job_id == job_id, JobWatch.user_id == user_id))).scalar_one_or_none()
    return watch


async def remove_watch_async(db, job_id: int, user_id) -> bool:
    """Unsubscribe. Returns True if a subscription was removed.

    The events go with it: they are addressed to a subscription that no longer exists, and
    leaving them would keep the bell's count non-zero over a dropdown that shows nothing.
    """
    watch = (await db.execute(select(JobWatch).where(JobWatch.job_id == job_id, JobWatch.user_id == user_id))).scalar_one_or_none()
    if watch is None:
        return False
    await db.execute(delete(JobWatchEvent).where(JobWatchEvent.watch_id == watch.id))
    await db.delete(watch)
    return True


async def is_watching_async(db, job_id: int, user_id) -> bool:
    return bool(await db.scalar(select(JobWatch.id).where(JobWatch.job_id == job_id, JobWatch.user_id == user_id)))


# ── Recording an event ───────────────────────────────────────────────────────


def _eligible(watchers, job, kind: str, actor_user_id):
    """Watchers eligible per `should_notify` who can still see the job, capped."""
    out = []
    for watch in watchers:
        if not should_notify(kind, watch.user_id, actor_user_id):
            continue
        # A watcher who can no longer see the job — it was made private, or they lost a
        # role — must not be told anything about it. The event would link to a 404 and
        # would itself leak that the job exists.
        if watch.user is not None and not can_view_job(job, watch.user):
            continue
        # A tag event names the tag, and tags are member-only: the job page withholds them
        # from `role=user`, so the bell must not read one out.
        if kind == "tag" and not has_intel_access(watch.user):
            continue
        out.append(watch)
        if len(out) >= MAX_WATCHERS_FANOUT:
            break
    return out


async def record_events_async(db, *, kind: str, job_id: int, ref_id: int, actor_user_id=None, summary: str = "") -> list[int]:
    """Fan one event out to a job's watchers. Returns the ids written.

    Never raises: a failed notification must not fail the thing it describes. The caller
    commits.
    """
    if kind not in WATCH_EVENT_KINDS:
        _log.warning("job watch: unknown event kind %r", kind)
        return []
    try:
        from sqlalchemy.orm import selectinload

        job = await db.get(AnalysisJob, job_id)
        if job is None:
            return []
        rows = await db.execute(select(JobWatch).where(JobWatch.job_id == job_id).options(selectinload(JobWatch.user)))
        watchers = _eligible(list(rows.scalars().all()), job, kind, actor_user_id)
        if not watchers:
            return []

        # Pre-filter against the constraint rather than relying on the exception: a
        # duplicate is the *normal* case on a retry, and one savepoint per row is a lot of
        # round trips to discover nothing needs doing.
        watch_ids = [w.id for w in watchers]
        seen = set(
            (await db.execute(select(JobWatchEvent.watch_id).where(JobWatchEvent.watch_id.in_(watch_ids), JobWatchEvent.kind == kind, JobWatchEvent.ref_id == ref_id)))
            .scalars()
            .all()
        )
        written: list[int] = []
        for watch in watchers:
            if watch.id in seen:
                continue
            event = JobWatchEvent(watch_id=watch.id, job_id=job_id, kind=kind, ref_id=ref_id, summary=(summary or "")[:_SUMMARY_MAX] or None)
            db.add(event)
            try:
                # Its own savepoint, the `intel/rules.py::_record_matches` shape: a
                # collision on one watcher must not roll back the events already written
                # for the ones before it, nor the caller's own staged work.
                async with db.begin_nested():
                    await db.flush()
            except IntegrityError:
                continue
            written.append(event.id)
        return written
    except Exception as exc:
        _log.warning("job watch: could not record %s event for job %s: %s", kind, job_id, exc)
        return []


def record_events_sync(db, *, kind: str, job_id: int, ref_id: int, actor_user_id=None, summary: str = "") -> list[int]:
    """Worker-side twin of `record_events_async`. Same contract, same guarantees."""
    if kind not in WATCH_EVENT_KINDS:
        _log.warning("job watch: unknown event kind %r", kind)
        return []
    try:
        from sqlalchemy.orm import selectinload

        job = db.get(AnalysisJob, job_id)
        if job is None:
            return []
        watchers = list(db.execute(select(JobWatch).where(JobWatch.job_id == job_id).options(selectinload(JobWatch.user))).scalars().all())
        watchers = _eligible(watchers, job, kind, actor_user_id)
        if not watchers:
            return []

        watch_ids = [w.id for w in watchers]
        seen = set(
            db.execute(select(JobWatchEvent.watch_id).where(JobWatchEvent.watch_id.in_(watch_ids), JobWatchEvent.kind == kind, JobWatchEvent.ref_id == ref_id)).scalars().all()
        )
        written: list[int] = []
        for watch in watchers:
            if watch.id in seen:
                continue
            event = JobWatchEvent(watch_id=watch.id, job_id=job_id, kind=kind, ref_id=ref_id, summary=(summary or "")[:_SUMMARY_MAX] or None)
            db.add(event)
            try:
                with db.begin_nested():
                    db.flush()
            except IntegrityError:
                continue
            written.append(event.id)
        return written
    except Exception as exc:
        _log.warning("job watch: could not record %s event for job %s: %s", kind, job_id, exc)
        return []


# ── Acknowledgement ──────────────────────────────────────────────────────────


async def ack_all_job_watch_events(db, user) -> int:
    """Mark every one of *user*'s unacknowledged job-watch events as read.

    **Own events only, for an admin too.** This is the one place where job watches
    deliberately diverge from watch rules: `intel_rules._visible_rules` gives an admin
    every rule, which is right for a shared rule set — but a watch belongs to exactly one
    person, so the same generosity here would mean one admin pressing "Acknowledge all"
    silently clearing everybody's bell.
    """
    from sqlalchemy import update

    owned = select(JobWatch.id).where(JobWatch.user_id == user.id)
    result = await db.execute(update(JobWatchEvent).where(JobWatchEvent.watch_id.in_(owned), JobWatchEvent.acknowledged_at.is_(None)).values(acknowledged_at=utc_now_naive()))
    return result.rowcount or 0


async def watched_count(db, user) -> int:
    """How many jobs this user is watching.

    What the "Watching" tab is *called*, and therefore what its badge should say. An unread
    count would drop to zero the moment you read the pane, showing nothing for someone
    watching twelve jobs. Unread events live in the nav bell, where a notification belongs.
    """
    from sqlalchemy import func

    return await db.scalar(select(func.count(JobWatch.id)).where(JobWatch.user_id == user.id)) or 0


async def unacked_count(db, user) -> int:
    """How many unread job-watch events this user has."""
    from sqlalchemy import func

    owned = select(JobWatch.id).where(JobWatch.user_id == user.id)
    return await db.scalar(select(func.count(JobWatchEvent.id)).where(JobWatchEvent.watch_id.in_(owned), JobWatchEvent.acknowledged_at.is_(None))) or 0


# ── Outbound delivery ────────────────────────────────────────────────────────


async def webhook_rule_id_for(db, user_id) -> int | None:
    """The rule whose webhook should carry this user's job-watch events, if any.

    A flag on an existing `IntelRule` rather than per-watch webhook columns — see
    `IntelRule.notify_job_watch` for why. Returns None when the owner has not opted in,
    which is the normal case — and when the owner has lost Intel access, the same line
    `rules._rule_may_run_on` draws.
    """
    from app.models import IntelRule, User, has_intel_access

    if not has_intel_access(await db.get(User, user_id)):
        return None
    return await db.scalar(
        select(IntelRule.id)
        .where(
            IntelRule.owner_user_id == user_id,
            IntelRule.notify_job_watch.is_(True),
            IntelRule.enabled.is_(True),
            IntelRule.webhook_enabled.is_(True),
            IntelRule.webhook_url.is_not(None),
        )
        .order_by(IntelRule.id)
        .limit(1)
    )


async def enqueue_webhooks_async(db, job_id: int, event_ids: list[int]) -> None:
    """Queue a webhook delivery per opted-in watcher. **Call after the commit.**

    A rollback must never strand a queued delivery for events that do not exist — the rule
    `_run_post_job_processing` states in the same words. Failures are logged and dropped:
    Redis being down loses a webhook, not the notification, and there is deliberately no
    reconciler (a backfill task would drag in an admin route, a docs table row and a
    task-registry entry for a payoff nobody has asked for).
    """
    if not event_ids:
        return
    try:
        rows = await db.execute(select(JobWatchEvent, JobWatch).join(JobWatch, JobWatch.id == JobWatchEvent.watch_id).where(JobWatchEvent.id.in_(event_ids)))
        by_user: dict = {}
        for event, watch in rows.all():
            by_user.setdefault(watch.user_id, []).append(event.id)

        from app.workers.tasks import deliver_webhook

        for user_id, ids in by_user.items():
            rule_id = await webhook_rule_id_for(db, user_id)
            if rule_id:
                deliver_webhook(rule_id, job_id, [], watch_event_ids=ids)
    except Exception as exc:
        _log.warning("job watch: could not queue webhook for job %s: %s", job_id, exc)


async def watched_rows(db, user) -> list[dict]:
    """Every job this user watches, with its unread count. Most unread first, then most
    recently watched.

    **Owner-only, admins included** — the divergence from `_visible_rules` argued in
    `ack_all_job_watch_events`. An admin's watch list is their own subscriptions, not
    everyone's.

    No pager: `JOB_WATCH_MAX_PER_USER` already bounds this set, and the LIMIT says so
    rather than leaving a reader to wonder whether the page is truncated.
    """
    from sqlalchemy import and_, func
    from sqlalchemy.orm import selectinload

    from app.models import AnalysisJob, visible_job_filter

    unread = func.count(JobWatchEvent.id)
    stmt = (
        select(AnalysisJob, JobWatch.created_at, unread.label("unread"))
        .join(JobWatch, JobWatch.job_id == AnalysisJob.id)
        .outerjoin(
            JobWatchEvent,
            and_(JobWatchEvent.watch_id == JobWatch.id, JobWatchEvent.acknowledged_at.is_(None)),
        )
        .options(selectinload(AnalysisJob.log_file), selectinload(AnalysisJob.tags))
        .where(JobWatch.user_id == user.id)
        .group_by(AnalysisJob.id, JobWatch.created_at)
        .order_by(unread.desc(), JobWatch.created_at.desc())
        .limit(JOB_WATCH_MAX_PER_USER)
    )
    # `visible_job_filter` returns the literal True for an admin, which is not a clause.
    vis = visible_job_filter(user)
    if vis is not True:
        stmt = stmt.where(vis)

    return [{"job": job, "since": since, "unread": int(n or 0)} for job, since, n in (await db.execute(stmt)).all()]


async def ack_job_events(db, job_id: int, user) -> int:
    """Mark this user's unread events for one job as read. Returns how many."""
    from sqlalchemy import update

    owned = select(JobWatch.id).where(JobWatch.user_id == user.id, JobWatch.job_id == job_id)
    result = await db.execute(update(JobWatchEvent).where(JobWatchEvent.watch_id.in_(owned), JobWatchEvent.acknowledged_at.is_(None)).values(acknowledged_at=utc_now_naive()))
    return result.rowcount or 0
