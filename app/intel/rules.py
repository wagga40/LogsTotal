"""Rule evaluation: per-user detection over each finished job.

Sync + DB, no FastAPI — the caller is the Huey worker. Does not commit; callers do.

**Rules reuse the search grammars they are written in.** This is deliberate and
load-bearing: an entity rule's criteria are the Intel dashboard's query language evaluated
by the dashboard's own filter builder, and a job rule's are the jobs list's, evaluated by
`apply_jobs_query`. So "what I searched is what alerts". A second, hand-rolled matcher would
drift from SQL semantics — case handling, LIKE escaping, the attribute-fragment encoding —
and the moment it did, the feature would stop being trustworthy in exactly the way that
matters.

**Two scopes, two shapes of work.** An entity rule asks "which of this job's entities match"
and can return many, so it is capped and its alerts are keyed `(rule, entity, job)`. A job
rule asks "does this job match" and returns one row or none, so it needs no cap and its
alerts are keyed `(rule, job)` in a second table — see `JobRuleMatch`'s docstring for why
that is a table and not a nullable column.

Cost is O(rules) queries, not O(rules x entities): each entity rule runs one SELECT already
narrowed to this job's entity links, which the planner drives from the indexed
`entity_job_link` rows rather than a full entity scan; each job rule runs one primary-key
lookup with the criteria as a WHERE.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.intel.queries import apply_entity_filters, parse_query, post_filter, query_needs_post_filter
from app.jobs_query import apply_jobs_query, parse_jobs_query
from app.json_utils import loads
from app.models import AnalysisJob, Entity, EntityTag, IntelRule, IntelRuleMatch, JobRuleMatch, JobTag, SiteSettings, TagDefinition, User, has_intel_access
from app.tags import ensure_tag_definition_sync, parse_tag_write

_log = logging.getLogger(__name__)

# A single job must not be able to fan out unboundedly. Both are logged when hit, so a
# truncated evaluation is never silent.
MAX_RULES_EVALUATED = 200
MAX_MATCHES_PER_RULE = 100

# A built-in label rule has to reach *every* matching entity in the job: a label that
# stopped at the hundredth LOLBin would be wrong in a way nobody could see, because the
# entities it missed simply look unlabelled. Still bounded — an unbounded pass is an
# unbounded transaction — just at a ceiling a real job does not reach.
MAX_MATCHES_PER_BUILTIN_RULE = 5000

# Job rules get their own budget rather than sharing the entity one. With a single cap, an
# instance past 200 entity rules would silently stop evaluating job rules
# altogether — the oldest-first ordering would spend the whole budget before reaching them,
# and the two kinds are not substitutes. Lower because a job rule is one row's worth of work
# and nobody needs hundreds of them.
MAX_JOB_RULES_EVALUATED = 100


@dataclass
class RuleRunResult:
    rules_evaluated: int = 0
    matches_created: int = 0
    tags_applied: int = 0
    # (rule_id, [match_id, ...]) for rules whose webhook should fire. The caller enqueues
    # delivery *after* committing, so a rollback can never strand a queued send for a match
    # that does not exist.
    webhook_jobs: list[tuple[int, list[int]]] = field(default_factory=list)


@dataclass
class JobRuleRunResult:
    """The job-scope twin. A separate type rather than more fields on `RuleRunResult`,
    because the two passes run independently and a caller that logs "3 matches" should not
    have to ask which kind."""

    rules_evaluated: int = 0
    matches_created: int = 0
    tags_applied: int = 0
    # Rule ids whose webhook should fire. No match-id list: a job rule's alert is 1:1 with
    # (rule, job) and the caller already knows the job, so the delivery reconstructs it.
    webhook_rules: list[int] = field(default_factory=list)


def _rule_may_run_on(rule: IntelRule, owner: User | None, job: AnalysisJob) -> bool:
    """Would this rule's owner be allowed to view this job?

    The single most important control in the feature. Without it, a member writes one
    broad rule and every private job's entity values are pushed to their own webhook —
    a disclosure the SSRF controls do nothing about, because the request is perfectly
    well-formed. Mirrors `visible_job_filter`: admins see all, the submitter sees their
    own, and a private anonymous submission has no submitter, so only admins see it.

    **A built-in label rule is exempt, and the exemption is conditional.** It has no owner,
    so the ordinary answer is False for every private job — which would mean a private
    submission's entities silently never get labelled, and only that submission's. The
    exemption is safe *because* a built-in only tags: no alert row for anyone to read, no
    webhook for anything to leave through. The moment one of those is true it is not a
    built-in label rule, so the condition names them rather than trusting the flag.

    **An owned rule acts for its owner, so it stops when the owner's Intel access does** —
    deactivated, or demoted below member — on public jobs too. Deactivation keeps
    `is_superuser`, so without this a departed admin's webhook would go on receiving every
    private job.
    """
    if rule.is_builtin and not rule.action_notify and not rule.webhook_enabled:
        return True
    if rule.owner_user_id is not None and not has_intel_access(owner):
        return False
    if not job.is_private:
        return True
    if owner is None:
        return False
    if owner.is_superuser:
        return True
    return job.submitted_by_user_id is not None and owner.id == job.submitted_by_user_id


def builtin_rules_enabled(db: Session) -> bool:
    """Read `SiteSettings.builtin_rules_enabled` without importing the web tier.

    A single-row table read straight through Core rather than through
    `app/site_settings.py`, which is async: this module runs in the worker. Missing row —
    a database whose settings have never been touched — means the default, which is on.
    Never raises: a rule pass must not fail because a settings read did.
    """
    try:
        value = db.scalar(select(SiteSettings.builtin_rules_enabled).limit(1))
    except Exception:  # pragma: no cover — a settings read must not fail the pass
        return True
    return True if value is None else bool(value)


def _entity_types(rule: IntelRule) -> list[str] | None:
    try:
        parsed = loads(rule.entity_types or "[]")
    except Exception:
        return None
    return [str(t) for t in parsed] if isinstance(parsed, list) and parsed else None


def _enabled_rules(db: Session, scope: str, cap: int, job_id: int, *, include_builtin: bool = True) -> list[IntelRule]:
    """The rules of one scope that this job will be measured against, oldest first.

    Ordered, because the LIMIT decides *which* rules fire once an instance has more than
    `cap` of them. `docs/limitations.md` promises oldest-first; without an ORDER BY that
    would hold on SQLite only by rowid accident and be arbitrary on PostgreSQL, evaluating a
    different subset run to run. `id` is the tiebreaker because
    `created_at` has second granularity and rules created by the entity ★ shortcut arrive in
    bursts.

    The `+1` is how truncation is detected rather than guessed at, and it is logged: a
    silently truncated evaluation is a rule that has simply stopped working.
    """
    stmt = select(IntelRule).where(IntelRule.enabled.is_(True), IntelRule.scope == scope)
    if not include_builtin:
        # Filtered in SQL, not in Python after the LIMIT. Built-ins are seeded first and so
        # sort oldest; excluding them afterwards would return `cap` minus the built-ins and
        # silently skip the tail an operator's own rules live in.
        stmt = stmt.where(IntelRule.is_builtin.is_(False))
    rows = db.execute(stmt.order_by(IntelRule.created_at, IntelRule.id).limit(cap + 1)).scalars().all()
    if len(rows) > cap:
        _log.warning("intel rules: %d enabled %s rules, evaluating the first %d for job %d", len(rows), scope, cap, job_id)
        return list(rows[:cap])
    return list(rows)


def _owners_for(db: Session, rules: list[IntelRule]) -> dict[object, User]:
    owner_ids = {r.owner_user_id for r in rules if r.owner_user_id is not None}
    if not owner_ids:
        return {}
    return {u.id: u for u in db.execute(select(User).where(User.id.in_(owner_ids))).scalars().all()}


def evaluate_rules_for_job(db: Session, job_id: int) -> RuleRunResult:
    """Run every enabled entity rule against the entities observed in `job_id`.

    Idempotent: `uq_intel_rule_match(rule_id, entity_id, job_id)` is the real guarantee, so
    re-running a job or a backfill raises no duplicate alerts.

    Job-scope rules are a separate pass — see `evaluate_job_rules_for_job`.
    """
    result = RuleRunResult()
    job = db.get(AnalysisJob, job_id)
    if job is None:
        return result

    # `builtin_rules_enabled` is one switch above the individual rule toggles, and it
    # gates *evaluation* — where the cost is, labelling being the only thing in this app that
    # writes a row per entity per job. Turning it off has to stop the work, not hide it.
    rules = _enabled_rules(db, "entity", MAX_RULES_EVALUATED, job_id, include_builtin=builtin_rules_enabled(db))
    if not rules:
        return result

    owners = _owners_for(db, rules)
    now = datetime.now(UTC).replace(tzinfo=None)

    for rule in rules:
        owner = owners.get(rule.owner_user_id) if rule.owner_user_id is not None else None
        if not _rule_may_run_on(rule, owner, job):
            continue

        try:
            matched = _match_rule(db, rule, job_id, cap=MAX_MATCHES_PER_BUILTIN_RULE if rule.is_builtin else MAX_MATCHES_PER_RULE)
        except Exception as exc:  # one broken rule must not stop the rest
            _log.warning("intel rule %s failed on job %s: %s", rule.id, job_id, exc)
            continue

        result.rules_evaluated += 1
        rule.last_evaluated_at = now
        if not matched:
            continue

        rule.last_matched_at = now

        # The three actions are three switches, and each has to work on its own.
        #
        # The ledger exists for two consumers: the bell, and `deliver_webhook`, which reads
        # `IntelRuleMatch.entity_id` back out of the ids it is handed and relies on the
        # unique constraint so a re-run cannot deliver twice. A rule that does neither has
        # no use for it — `uq_entity_tag(entity_id, tag)` is already the idempotency
        # guarantee for tagging — and skipping it is what keeps the built-in label rules
        # from writing thousands of rows per job that nobody will ever read.
        #
        # `silent` covers the middle case: a webhook rule with alerts turned off needs the
        # rows and must not put them in anyone's bell, so they are stamped acknowledged at
        # insert.
        new_ids: list[int] = []
        if rule.action_notify or rule.webhook_enabled:
            new_ids = _record_matches(db, rule, job_id, matched, silent=not rule.action_notify, now=now)
            rule.match_count = (rule.match_count or 0) + len(new_ids)
            result.matches_created += len(new_ids)

        # Tagging runs on every evaluation, not only when the ledger gained a row. It is
        # idempotent by construction, and a tag-only rule has no ledger to gate it on.
        if rule.action_tag:
            result.tags_applied += _apply_tag(db, rule, matched)
        if rule.webhook_enabled and rule.webhook_url and new_ids:
            result.webhook_jobs.append((rule.id, new_ids))

    return result


def evaluate_job_rules_for_job(db: Session, job_id: int) -> JobRuleRunResult:
    """Run every enabled job rule against `job_id` itself.

    A job rule's criteria are the jobs list's `?q=` grammar, compiled by the same
    `apply_jobs_query` the list uses — the entity-rule argument, applied to the other
    grammar. `viewer_id` is the rule's owner, so `is:mine` and `is:watched` mean what they
    say from the owner's point of view rather than from nobody's.

    Terms that only make sense mid-run (`is:running`) simply never match a finished job.
    That is left alone rather than rejected at save time: the grammar is shared with a list
    where those terms are useful, and a rule that matches nothing is a rule that matches
    nothing — no worse than a query for a value that never appears.

    Idempotent through `uq_job_rule_match(rule_id, job_id)`. Does not commit.
    """
    result = JobRuleRunResult()
    job = db.get(AnalysisJob, job_id)
    if job is None:
        return result

    # Shared job rules (`needs_triage`, `rerun`, `clean`) sit under the same site switch
    # as the shared entity rules; the private-job exemption and the ledger skip below
    # already cover them, since both key off "tags only" rather than off the scope.
    rules = _enabled_rules(db, "job", MAX_JOB_RULES_EVALUATED, job_id, include_builtin=builtin_rules_enabled(db))
    if not rules:
        return result

    owners = _owners_for(db, rules)
    now = datetime.now(UTC).replace(tzinfo=None)

    for rule in rules:
        owner = owners.get(rule.owner_user_id) if rule.owner_user_id is not None else None
        if not _rule_may_run_on(rule, owner, job):
            continue

        try:
            matched = _job_rule_matches(db, rule, job_id)
        except Exception as exc:  # one broken rule must not stop the rest
            _log.warning("job rule %s failed on job %s: %s", rule.id, job_id, exc)
            continue

        result.rules_evaluated += 1
        rule.last_evaluated_at = now
        if not matched:
            continue

        rule.last_matched_at = now

        # The same three switches as an entity rule, and for the same reasons — see the
        # comment in `evaluate_rules_for_job`.
        recorded = False
        if rule.action_notify or rule.webhook_enabled:
            recorded = _record_job_match(db, rule, job_id, silent=not rule.action_notify, now=now)
            if recorded:
                rule.match_count = (rule.match_count or 0) + 1
                result.matches_created += 1

        if rule.action_tag:
            result.tags_applied += _apply_job_tag(db, rule, job_id)
        if rule.webhook_enabled and rule.webhook_url and recorded:
            result.webhook_rules.append(rule.id)

    return result


def _job_rule_matches(db: Session, rule: IntelRule, job_id: int) -> bool:
    """Does this one job satisfy the rule? One row or none — no cap to apply.

    `select(AnalysisJob.id).where(id == job_id)` narrowed by the criteria is a primary-key
    lookup with a WHERE, not a scan: the grammar compiles every term to a correlated EXISTS
    or an `AnalysisJob` column, never a JOIN, precisely so it can ride an arbitrary base
    statement like this one.
    """
    parsed = parse_jobs_query(rule.query or "")
    stmt = apply_jobs_query(select(AnalysisJob.id).where(AnalysisJob.id == job_id), parsed, viewer_id=rule.owner_user_id)
    return db.scalar(stmt) is not None


def _record_job_match(db: Session, rule: IntelRule, job_id: int, *, silent: bool = False, now: datetime | None = None) -> bool:
    """Insert the alert if it is not there yet. True when one was written.

    Savepoint for the same reason as `_record_matches`: `evaluate_job_rules_for_job` runs
    every rule in one transaction, so a bare rollback on a collision would discard the
    matches and tags already flushed for every earlier rule.
    """
    if db.scalar(select(JobRuleMatch.id).where(JobRuleMatch.rule_id == rule.id, JobRuleMatch.job_id == job_id)):
        return False
    acked = (now or datetime.now(UTC).replace(tzinfo=None)) if silent else None
    try:
        with db.begin_nested():
            db.add(JobRuleMatch(rule_id=rule.id, job_id=job_id, acknowledged_at=acked))
            db.flush()
    except IntegrityError:
        return False  # lost the race; the alert exists, which is the point
    return True


def _apply_job_tag(db: Session, rule: IntelRule, job_id: int) -> int:
    """Auto-tag the matched job. The `_apply_tag` contract, one row's worth.

    Same restraint: the vocabulary's colour wins for a tag that already exists, and the
    rule's own swatch is used only for a name nothing has coined — an automated rule must
    not repaint an analyst's palette.
    """
    pairs = parse_tag_write(rule.action_tag or "", rule.action_tag_color or "gray")
    if not pairs:
        return 0
    existing = set(db.execute(select(JobTag.tag).where(JobTag.job_id == job_id)).scalars().all())
    added = 0
    for norm, fallback in pairs:
        known = db.scalar(select(TagDefinition.color).where(TagDefinition.tag == norm))
        color = known or fallback or "gray"
        ensure_tag_definition_sync(db, norm, color, rule.owner_user_id)
        if norm in existing:
            continue
        try:
            with db.begin_nested():
                db.add(JobTag(job_id=job_id, tag=norm, color=color, created_by_user_id=rule.owner_user_id))
                db.flush()
            added += 1
        except IntegrityError:
            continue
    return added


def _match_rule(db: Session, rule: IntelRule, job_id: int, *, cap: int = MAX_MATCHES_PER_RULE) -> list[Entity]:
    """Entity rows in this job that satisfy the rule, capped.

    The cap is a parameter because a built-in label rule needs a far higher one — see
    `MAX_MATCHES_PER_BUILTIN_RULE`. A single constant would silently stop labelling at the
    hundredth match, which reads as "these entities are not LOLBins" rather than as
    a truncation.
    """
    parsed = parse_query(rule.query or "")
    stmt = apply_entity_filters(
        select(Entity),
        query=parsed,
        types=_entity_types(rule),
        job_id=job_id,
    )
    needs_post = query_needs_post_filter(parsed)
    # +1 so we can tell "exactly at the cap" from "truncated". A post-filtered term (`re:`,
    # `cidr:`) narrows in Python *after* the fetch, so its window has to hold every
    # candidate the SQL half admits, not `cap + 1` of them: capping first would test the
    # first 101 candidates and quietly report the rest as non-matches.
    window = MAX_MATCHES_PER_BUILTIN_RULE + 1 if needs_post else cap + 1
    rows = list(db.execute(stmt.limit(window)).scalars().all())
    if needs_post:
        if len(rows) > MAX_MATCHES_PER_BUILTIN_RULE:
            _log.warning("intel rule %s: more than %d candidates in job %s; only the first were checked", rule.id, MAX_MATCHES_PER_BUILTIN_RULE, job_id)
        # Strict: a row the regex budget left unchecked is dropped, never tagged.
        rows = post_filter(rows, parsed, strict=True)
    if len(rows) > cap:
        _log.warning("intel rule %s matched >%d entities in job %s; truncating", rule.id, cap, job_id)
        rows = rows[:cap]
    return rows


def _record_matches(db: Session, rule: IntelRule, job_id: int, entities: list[Entity], *, silent: bool = False, now: datetime | None = None) -> list[int]:
    """Insert the alerts that do not exist yet; return their ids.

    Pre-filtering against existing rows keeps the common re-run cheap; the unique
    constraint is what actually guarantees correctness under a concurrent worker, so the
    IntegrityError path retries row by row.

    `silent` stamps `acknowledged_at` at insert, which is how a rule with alerts turned off
    but a webhook turned on keeps a ledger without putting anything in a bell: every
    unacknowledged-alert query — the badge, the dropdown, the Alerts section — filters on
    that column, so one write covers all three. `acknowledged_by_user_id` stays NULL, which
    is what distinguishes "never raised" from "somebody cleared it".
    """
    entity_ids = [e.id for e in entities]
    if not entity_ids:
        return []
    seen = set(
        db.execute(select(IntelRuleMatch.entity_id).where(IntelRuleMatch.rule_id == rule.id, IntelRuleMatch.job_id == job_id, IntelRuleMatch.entity_id.in_(entity_ids)))
        .scalars()
        .all()
    )
    fresh = [eid for eid in entity_ids if eid not in seen]
    if not fresh:
        return []

    # Savepoints, not `db.rollback()`. `evaluate_rules_for_job` runs every rule in one
    # transaction, so a bare rollback here would discard the matches, tag writes and
    # timestamps already flushed for every *earlier* rule — a collision on rule #5 wiping
    # rules #1-4. Same shape as `app/intel/entities.py`'s attribute pass.
    acked = (now or datetime.now(UTC).replace(tzinfo=None)) if silent else None

    def _row(eid: int) -> IntelRuleMatch:
        return IntelRuleMatch(rule_id=rule.id, entity_id=eid, job_id=job_id, acknowledged_at=acked)

    rows = [_row(eid) for eid in fresh]
    try:
        with db.begin_nested():
            db.add_all(rows)
            db.flush()
    except IntegrityError:
        rows = []
        for eid in fresh:
            row = _row(eid)
            try:
                with db.begin_nested():
                    db.add(row)
                    db.flush()
                rows.append(row)
            except IntegrityError:
                continue
    return [r.id for r in rows if r.id is not None]


def _apply_tag(db: Session, rule: IntelRule, entities: list[Entity]) -> int:
    """Auto-tag the matched entities with every tag the rule carries.

    Deliberately does NOT apply the instance-wide recolour that the manual add path does:
    an automated rule firing in the background must not repaint an analyst's palette. It
    goes further and *reads* the vocabulary colour for a tag that already exists, using the
    rule's own colour only for a name nothing has used yet. Writing `rule.action_tag_color`
    unconditionally would be the same repaint, arriving one entity at a time and only on
    the rows the rule happened to touch.

    **One savepoint for the batch, row-by-row only on collision** — the `_record_matches`
    shape. A savepoint per row is fine at a hundred and is not at the five thousand a
    built-in label rule is allowed: each one is a round trip inside the post-processing
    transaction, holding SQLite's single writer lock while every web write waits out
    `SQLITE_BUSY_TIMEOUT_MS` — the measured shape of the 80-second backfill stall, repeated
    on every analysis.
    """
    pairs = parse_tag_write(rule.action_tag or "", rule.action_tag_color or "gray")
    if not pairs:
        return 0
    entity_ids = [e.id for e in entities]
    added = 0
    for norm, fallback in pairs:
        known = db.scalar(select(TagDefinition.color).where(TagDefinition.tag == norm))
        color = known or fallback or "gray"
        # Register what we are about to apply. Every other write path does this; skipping it
        # would leave a rule-coined tag missing from the manager until the rule fired, and
        # gone again once its last EntityTag row was removed. `known` is read first, so a
        # tag that already exists keeps its own colour and this is a no-op for it.
        ensure_tag_definition_sync(db, norm, color, rule.owner_user_id)
        existing = set(db.execute(select(EntityTag.entity_id).where(EntityTag.tag == norm, EntityTag.entity_id.in_(entity_ids))).scalars().all())
        fresh = [eid for eid in entity_ids if eid not in existing]
        if not fresh:
            continue
        added += _insert_tags(db, rule, norm, color, fresh)
    return added


def _insert_tags(db: Session, rule: IntelRule, tag: str, color: str, entity_ids: list[int]) -> int:
    """Write one tag onto many entities. Returns how many rows landed.

    The pre-filter above makes the batch path the common one; the unique constraint is what
    actually guarantees correctness under a concurrent worker, so a collision falls back to
    one savepoint per row rather than losing the whole batch.
    """

    def _row(eid: int) -> EntityTag:
        return EntityTag(entity_id=eid, tag=tag, color=color, created_by_user_id=rule.owner_user_id)

    try:
        with db.begin_nested():
            db.add_all([_row(eid) for eid in entity_ids])
            db.flush()
        return len(entity_ids)
    except IntegrityError:
        pass

    written = 0
    for eid in entity_ids:
        try:
            with db.begin_nested():
                db.add(_row(eid))
                db.flush()
            written += 1
        except IntegrityError:
            continue
    return written
