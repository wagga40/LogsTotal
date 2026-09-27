"""
Rules and webhook delivery configuration — member-or-above.

A rule is criteria in a query language plus what to do when it matches. Nothing here is
reached from the entity or dashboard code beyond the ★ shortcut, which lives with the entity
page and only creates a row.

**Called Rules, not Watch rules.** "Watch" is a job subscription — the button on a job page,
`app/job_watch.py`, the Watching tab. Watching is a *feature* of this destination: a rule can
carry a person's job-watch deliveries, and their subscriptions are listed here.
``/intel/watch*`` redirects here; see the bottom of this file.

The audit trail keeps the ``watch_rule`` spelling: ``activity.record`` writes
``intel.watch_rule.create`` and ``target_type="watch_rule"``, because an audit log has to
stay queryable across a rename — the same reason ``ActivityEvent.target_type`` is a plain
string rather than a foreign key.
"""

from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity, job_watch
from app.auth.users import current_member_or_above, current_superuser
from app.config import settings
from app.constants import DEFAULT_RULE_SCOPE, ENTITY_TYPE_META, ENTITY_TYPES, RULE_SCOPE_LABELS, RULE_SCOPES, TAG_COLORS, parse_entity_types
from app.database import get_async_session, utc_now_naive
from app.intel.queries import (
    MAX_INSET_VALUES,
    apply_entity_filters,
    list_terms,
    parse_query,
    post_filter,
    query_needs_post_filter,
    scan_query,
    unknown_list_errors,
)
from app.intel.rule_lists import LIST_MATCH_KINDS, LIST_MATCH_LABELS, ListSpec, list_names, load_lists, normalize_values, rules_naming, validate_list_spec, write_list
from app.intel.rules import MAX_MATCHES_PER_RULE
from app.intel.rules_yaml import (
    CRITERIA_MAX,
    MAX_DOCUMENT_BYTES,
    RuleSpec,
    apply_spec,
    dump_rules_yaml,
    import_rules,
    parse_rules_yaml,
    rule_is_unedited,
    spec_from_rule,
    validate_spec,
)
from app.intel.webhooks import WEBHOOK_METHODS
from app.jobs_query import apply_jobs_query, parse_jobs_query, query_errors
from app.models import (
    AnalysisJob,
    Entity,
    IntelRule,
    IntelRuleMatch,
    JobRuleMatch,
    JobStatus,
    LogFile,
    RuleList,
    User,
    WebhookDelivery,
    visible_job_filter,
)
from app.notifications import alert_rule_ids
from app.site_settings import get_site_settings
from app.tags import ensure_tag_definition, parse_tag_write
from app.templates_config import negotiated as _negotiated
from app.templates_config import templates

router = APIRouter(prefix="/intel")


def _visible_rules(user: User):
    """Owner-only, admins see all — the same visibility rule as SavedSearch and cases.

    Plus every built-in. A built-in has no owner, so the ordinary clause would hide it from
    every member — but the shipped vocabulary is what `lolbin` and `privileged` *are* on this
    instance, and a member must be able to read the rule behind a tag they see every day.
    Editing it is a separate question, answered by `_rule_can_edit`.
    """
    if user.is_superuser:
        return IntelRule.id.is_not(None)
    return or_(IntelRule.owner_user_id == user.id, IntelRule.is_builtin.is_(True))


async def ack_all_visible_alerts(db: AsyncSession, user: User) -> int:
    """Acknowledge every unacked alert that is this user's (`alert_rule_ids`). Returns how many.

    Two surfaces do this — the nav bell dropdown (`/intel/watchlist-events/ack-all`) and the
    Rules page's Alerts section (`/intel/rules/alerts/ack-all`). They render different
    partials afterwards, so they stay separate routes, but share this write: a visibility
    rule written twice will eventually be written wrong.

    **Both alert tables, one sweep.** An "Acknowledge all" that clears entity-rule alerts and
    leaves job-rule ones sitting in the bell is worse than no button: the badge does not
    reach zero and the reader has no way to tell which kind is left.
    """
    mine = alert_rule_ids(user)
    acked = func.now()
    entity_alerts = await db.execute(
        update(IntelRuleMatch).where(IntelRuleMatch.rule_id.in_(mine), IntelRuleMatch.acknowledged_at.is_(None)).values(acknowledged_at=acked, acknowledged_by_user_id=user.id)
    )
    job_alerts = await db.execute(
        update(JobRuleMatch).where(JobRuleMatch.rule_id.in_(mine), JobRuleMatch.acknowledged_at.is_(None)).values(acknowledged_at=acked, acknowledged_by_user_id=user.id)
    )
    await db.commit()
    # The count is returned rather than discarded so a caller can say what it did — "12
    # alerts acknowledged" is a different statement from "acknowledged".
    return (entity_alerts.rowcount or 0) + (job_alerts.rowcount or 0)


def _rule_can_edit(rule: IntelRule, user: User) -> bool:
    """Admins, and whoever owns the rule.

    A built-in is instance-wide, so a member editing one would silently change what `lolbin`
    means for every colleague. The check is explicit rather than left to the owner
    comparison: `owner_user_id` is NULL on a built-in and never equals a member's id — the
    right answer for the wrong reason, and wrong the day a built-in gets an owner.
    """
    if rule.is_builtin:
        return bool(user.is_superuser)
    return user.is_superuser or rule.owner_user_id == user.id


#: How many values of a list the peek popover carries. Twenty is a screenful; the rest are
#: one click away on the Lists tab, and the popover says how many there are.
_LIST_PEEK_SAMPLE = 20


def _build_rules_tabs(*, rule_total: int, list_total: int, alert_total: int, watched: int) -> list[dict]:
    """The four panes of `/intel/rules`, in the house `{key, label, badge, lazy_event, icon}` shape.

    Same contract as `jobs._build_job_tabs` and `cases._build_case_tabs`, so the shared
    `resourceTabs` component and the `tab_icon`/`tab_badge` macros serve this strip too.

    **`lazy_event` is None on every tab, deliberately.** `_render_rules` already loads all
    four panes' data in one pass, so the panes are `x-show` and eager: lazily fetching them
    would need four new routes to buy back bytes this page re-sends on every action anyway
    (each POST swaps the whole `#rules-region`), and it would put the section headings
    behind a fetch.

    That whole-region swap is also why nothing here records which tab is open. `select()`
    writes `location.hash`, and the strip Alpine re-initialises after the swap reads it
    back — so the tab survives an action for free. A server-side `active_tab` would be a
    second, disagreeing answer to the same question.

    Rules leads because the page is named for them. Alerts keeps a red badge rather than
    the first slot: the nav bell already carries that count, and the thing you navigate
    here to do is read or write a rule.
    """
    return [
        {"key": "rules", "label": "Rules", "badge": rule_total or None, "lazy_event": None, "icon": "flow"},
        {"key": "lists", "label": "Lists", "badge": list_total or None, "lazy_event": None, "icon": "queue"},
        {"key": "alerts", "label": "Alerts", "badge": alert_total or None, "lazy_event": None, "icon": "shield"},
        {"key": "activity", "label": "Activity", "badge": watched or None, "lazy_event": None, "icon": "clock"},
    ]


async def _render_rules(request: Request, db: AsyncSession, user: User, notice: str = "", errors: list[str] | None = None, error_title: str = "That did not work:") -> HTMLResponse:
    # Two lists, **two queries**, and the second one is why. The built-ins are the shipped
    # vocabulary, the same on every instance, and mixing them into "my rules" would bury an
    # analyst's three under them and imply they are theirs to delete.
    # Splitting a single capped query in Python looks equivalent and is not: built-ins are
    # seeded first, so they sort oldest, and an admin (who sees every rule on the instance)
    # past the cap would push them off the end. The Built-in section would render empty with
    # nothing to say why.
    rules = (await db.execute(select(IntelRule).where(_visible_rules(user), IntelRule.is_builtin.is_(False)).order_by(IntelRule.created_at.desc()).limit(200))).scalars().all()
    # Seed order — `rules/builtin.yml` is written in reading order and the seeder inserts in
    # it — so the section reads like the vocabulary it is. Uncapped: the file bounds it.
    shared_rules = (await db.execute(select(IntelRule).where(IntelRule.is_builtin.is_(True)).order_by(IntelRule.created_at, IntelRule.id))).scalars().all()
    # The lists, each with the rules on this page whose condition names it — so a reader
    # sees what a list feeds, and an admin is told what a change reaches.
    used_by: dict[str, list[str]] = {}
    # The same walk, read the other way: which lists does *this* rule test, and does it
    # spell a set out inline? Both are rendered on the rule's own row — a condition reading
    # `list:lolbas` says nothing about what is in lolbas.
    rule_lists: dict[int, list[str]] = {}
    rule_sets: dict[int, list[str]] = {}
    for r in [*rules, *shared_rules]:
        if r.scope != "entity" or not r.query:
            continue
        if "list:" not in r.query and "in:" not in r.query:
            continue
        parsed = parse_query(r.query)
        names = list_terms(parsed)
        if names:
            rule_lists[r.id] = names
            for name in names:
                used_by.setdefault(name, []).append(r.name)
        # At most one inline set is promotable in one action; a condition with two is a
        # judgement call about which becomes a list, and that belongs to the analyst.
        sets = [t["values"] for t in parsed.get("terms", []) if t.get("kind") == "inset"]
        if len(sets) == 1:
            rule_sets[r.id] = sets[0]
    # Which shared rules differ from `rules/*.yml`. `seed_hash` already decides this — it is
    # what makes the seeder leave an edited row alone — and this makes it visible, so an
    # admin can see why an upgrade did not change a rule. A marker, not a Reset button: a
    # modified/Reset flag would fire on every row after an upgrade, and the seeding policy
    # already handles the update.
    edited_shared = {r.id for r in shared_rules if not rule_is_unedited(r)}
    lists = [{"row": row, "spec": spec, "used_by": used_by.get(spec.name, [])} for row, spec in await load_lists(db)]
    # Enough of each list to answer "what is in it" in place, keyed by the name a condition
    # writes. Capped: `gtfobins` ships 92 values and a list may hold 2,000, and this rides
    # on every render of a page that already re-sends itself on every action.
    list_peek = {
        spec.name: {
            "id": row.id,
            "count": len(spec.values),
            "match": LIST_MATCH_LABELS.get(spec.match, spec.match),
            "sample": list(spec.values[:_LIST_PEEK_SAMPLE]),
            "description": spec.description,
        }
        for row, spec in await load_lists(db)
    }

    # Alerts, and deliveries, from the rules whose alerts are this user's: their own, plus —
    # for an admin — the shared rules, which can be switched to "alert me" or given a webhook
    # like any other. The same line `notifications.alert_rule_ids` draws for the bell.
    rule_ids = [r.id for r in rules] + ([r.id for r in shared_rules] if user.is_superuser else [])

    alerts = []
    if rule_ids:
        rows = (
            await db.execute(
                select(IntelRuleMatch, Entity, IntelRule)
                .join(Entity, IntelRuleMatch.entity_id == Entity.id)
                .join(IntelRule, IntelRuleMatch.rule_id == IntelRule.id)
                .where(IntelRuleMatch.rule_id.in_(rule_ids), IntelRuleMatch.acknowledged_at.is_(None))
                .order_by(IntelRuleMatch.created_at.desc())
                .limit(100)
            )
        ).all()
        alerts = [{"match": m, "entity": e, "rule": r} for m, e, r in rows]

    job_alerts = []
    if rule_ids:
        # Joined to `AnalysisJob` rather than resolved per row: the section renders the
        # filename and status, and a lazy read of either off a detached instance is a
        # MissingGreenlet on the async side.
        job_rows = (
            await db.execute(
                select(JobRuleMatch, AnalysisJob, LogFile, IntelRule)
                .join(AnalysisJob, JobRuleMatch.job_id == AnalysisJob.id)
                .join(LogFile, AnalysisJob.file_id == LogFile.id)
                .join(IntelRule, JobRuleMatch.rule_id == IntelRule.id)
                .where(JobRuleMatch.rule_id.in_(rule_ids), JobRuleMatch.acknowledged_at.is_(None))
                .order_by(JobRuleMatch.created_at.desc())
                .limit(100)
            )
        ).all()
        job_alerts = [{"match": m, "job": j, "file": f, "rule": r} for m, j, f, r in job_rows]

    deliveries = []
    if rule_ids:
        deliveries = (await db.execute(select(WebhookDelivery).where(WebhookDelivery.rule_id.in_(rule_ids)).order_by(WebhookDelivery.created_at.desc()).limit(25))).scalars().all()

    site = await get_site_settings(db)

    # The jobs this person watches. A *subscription*, not a rule — but "Watch" is a feature
    # of this destination, so the two live on one page. The rows
    # and the partial are `/jobs/watching`'s, mounted a second time rather than copied; its
    # buttons post back to their own routes and swap `#jobs-watching-region`, independent of
    # `#rules-region`.
    #
    # `/jobs/watching` deliberately stays where it is. It is `current_user_required` and
    # this page is `current_member_or_above`, so moving it here would take watching away
    # from the one role that has it and no Intel access.
    watched_rows = await job_watch.watched_rows(db, user)

    # "What is on this page, in one number" — the `page_header(pills=…)` idiom every other
    # top-level page wears. Alerts only when there are some: a red zero reads as a problem.
    #
    # "N of M": the tab badge counts every rule behind the tab, so a pill counting only the
    # analyst's own would give a second answer one line away. The shipped rules would swamp
    # a bare total before anyone had written anything, but they are still rules on this page.
    rule_total = len(rules) + len(shared_rules)
    # Counted, not taken from `rules`: an admin's list holds every member's rules (and is
    # capped), so its length said "7 of 5 used" to an admin who had written none.
    own_count = await db.scalar(select(func.count(IntelRule.id)).where(IntelRule.owner_user_id == user.id, IntelRule.is_builtin.is_(False))) or 0
    pills = [(f"{own_count} of {rule_total} rules", "gray", "Rules you wrote, of every rule on this page")]
    total_alerts = len(alerts) + len(job_alerts)
    if total_alerts:
        pills.append((f"{total_alerts} alert{'' if total_alerts == 1 else 's'}", "red"))

    tabs = _build_rules_tabs(
        rule_total=rule_total,
        list_total=len(lists),
        alert_total=total_alerts,
        watched=len(watched_rows),
    )

    return _negotiated(
        request,
        page="intel/rules.html",
        fragment="intel/partials/_rules_body.html",
        context={
            "request": request,
            "user": user,
            "rules": rules,
            "shared_rules": shared_rules,
            "edited_shared": edited_shared,
            "lists": lists,
            "list_peek": list_peek,
            "inset_max": MAX_INSET_VALUES,
            "rule_lists": rule_lists,
            "rule_sets": rule_sets,
            "list_match_kinds": LIST_MATCH_KINDS,
            "list_match_labels": LIST_MATCH_LABELS,
            "builtin_rules_enabled": bool(getattr(site, "builtin_rules_enabled", True)),
            "rows": watched_rows,
            "watched": len(watched_rows),
            "alerts": alerts,
            "job_alerts": job_alerts,
            "deliveries": deliveries,
            "pills": pills,
            "entity_type_meta": ENTITY_TYPE_META,
            "all_entity_types": list(ENTITY_TYPES),
            "rule_scopes": RULE_SCOPES,
            "rule_scope_labels": RULE_SCOPE_LABELS,
            "tag_colors": TAG_COLORS,
            "rule_cap": settings.watch_rules_max_per_user,
            "own_rule_count": own_count,
            "require_public_host": settings.webhook_require_public_host,
            "webhook_methods": WEBHOOK_METHODS,
            "tabs": tabs,
            "notice": notice,
            "errors": errors or [],
            "error_title": error_title,
        },
    )


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """The rules panel: rules, lists, alerts, activity — four tabs over one region."""
    return await _render_rules(request, db, user)


async def _apply_rule_fields(
    rule: IntelRule,
    *,
    db: AsyncSession,
    name: str,
    scope: str,
    description: str = "",
    query: str,
    entity_types: str | list[str],
    action_tag: str,
    action_tag_color: str,
    action_notify: int,
    webhook_url: str,
    webhook_secret: str,
    webhook_method: str,
    webhook_headers: str,
    webhook_enabled: int,
    notify_job_watch: int = 0,
    clear_secret: int = 0,
) -> list[str]:
    """Validate and apply the rule form to `rule`, or return why it could not be applied.

    Shared by create and edit so the two can never disagree about what a field means — and
    by the YAML import and the seed as well: the form builds a `RuleSpec` and hands it to
    the one validator, so a document that imports is a
    form that would have saved. The clamps (name to 120, criteria and URL to 500, scope to a
    known value) are the form's own leniency and stay here: a posted body is degraded to
    something sensible, where a file says what it means and is refused when it does not.
    """
    spec = RuleSpec(
        key=rule.builtin_key,
        name=(name or "").strip()[:120],
        description=(description or "").strip()[:500],
        # Clamped rather than rejected, the `ALLOWED_JOBS_VIEWS` arrangement: the selector
        # posts one of two known values, so anything else is a hand-crafted body and
        # degrading it to the default is more useful than a 400 nobody will ever see.
        scope=scope if scope in RULE_SCOPES else DEFAULT_RULE_SCOPE,
        entity_types=tuple(parse_entity_types(entity_types)),
        criteria=(query or "").strip()[:500],
        # The same index-aligned CSV pair the picker posts, parsed by the same
        # `parse_tag_write` the manual tag routes use — so a rule cannot apply a tag that
        # could not have been typed by hand.
        tags=tuple(parse_tag_write(action_tag, action_tag_color)),
        notify=bool(action_notify),
        enabled=True if rule.enabled is None else bool(rule.enabled),
        webhook_url=(webhook_url or "").strip()[:500] or None,
        webhook_method=(webhook_method or "POST").upper(),
        webhook_headers_json=(webhook_headers or "").strip() or None,
        webhook_enabled=bool(webhook_enabled),
    )
    # Returned, not raised, and all of them: the form is a plain POST, so an HTTPException
    # would replace the page with an error screen, lose the draft and name only the first
    # problem. The caller aims them at a slot inside the form (`_rule_form_errors`). Nothing
    # has been applied yet, so returning here leaves `rule` untouched.
    errors = validate_spec(spec, known_lists=await list_names(db))
    if errors:
        return errors
    apply_spec(rule, spec)
    # Naming a tag here coins it, exactly as typing it into any other tag field does. The
    # worker registers it too, but only when the rule first matches — and a vocabulary you
    # cannot see until something happens to match it is not a vocabulary you can design
    # against, which is the whole reason `TagDefinition` exists.
    for norm, color in spec.tags:
        await ensure_tag_definition(db, norm, color, user_id=rule.owner_user_id)
    url = rule.webhook_url or ""
    # A blank secret on edit means "leave it alone" — otherwise re-saving any other field
    # would silently unsign every future delivery, since the form cannot echo it back.
    if clear_secret:
        rule.webhook_secret_encrypted = None
    elif (webhook_secret or "").strip():
        from app.auth.api_tokens import encrypt_secret

        rule.webhook_secret_encrypted = encrypt_secret(webhook_secret.strip())

    # At most one rule per owner carries job-watch deliveries — the `WorkflowDef.is_default`
    # rule. Two would mean the same event delivered twice, which reads as a retry storm.
    rule.notify_job_watch = bool(url) and bool(notify_job_watch)
    if rule.notify_job_watch and rule.owner_user_id is not None:
        await db.execute(update(IntelRule).where(IntelRule.owner_user_id == rule.owner_user_id, IntelRule.id != rule.id).values(notify_job_watch=False))
    return []


def _rule_form_errors(request: Request, errors: list[str], *, rule_id: int | None) -> HTMLResponse:
    """A failed save, reported without touching the form it came from.

    `_render_rules(errors=…)` — what the YAML import does — swaps the whole region, which
    re-renders the form from the database: an edit comes back as the stored rule and a
    create comes back empty. For a page whose subject is writing a condition, throwing the
    condition away to say it is wrong is the wrong trade.

    So this returns only the messages and tells htmx to put them in the form's own error
    slot (`HX-Retarget`) with `innerHTML` (`HX-Reswap`), leaving every field as typed —
    htmx's own answer to "this response belongs somewhere other than where the request said".

    **200, not 400**, because htmx does not swap a 4xx by default — the status would be
    correct and the reader would see nothing at all. Without htmx there is no slot to aim
    at, so that path keeps the 400, carrying every error.
    """
    return _form_errors(request, errors, slot=f"rule-form-errors-{rule_id if rule_id is not None else 'new'}")


def _form_errors(request: Request, errors: list[str], *, slot: str, title: str | None = None) -> HTMLResponse:
    """`_rule_form_errors` for any form on this page with an error slot — the list forms,
    Promote to a list and Import YAML carry the same draft and lost it the same way."""
    if not request.headers.get("HX-Request"):
        raise HTTPException(400, " — ".join(errors))
    html = templates.get_template("intel/partials/_rule_form_errors.html").render(errors=errors, error_title=title)
    return HTMLResponse(html, headers={"HX-Retarget": f"#{slot}", "HX-Reswap": "innerHTML"})


@router.post("/rules", response_class=HTMLResponse)
async def rule_create(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    name: str = Form(...),
    description: str = Form(""),
    # Form("entity"), unlike the checkboxes below: a radio group always posts exactly one of
    # its values, so there is no absent-means-off trap here — and a POST without it means
    # an entity rule.
    scope: str = Form(DEFAULT_RULE_SCOPE),
    query: str = Form(""),
    entity_types: list[str] = Form([]),
    action_tag: str = Form(""),
    action_tag_color: str = Form("gray"),
    # Form(0), not Form(1): an unticked checkbox is absent from the POST body, so a default
    # of 1 could never be switched off. The template sends value="1" when ticked.
    action_notify: int = Form(0),
    webhook_url: str = Form(""),
    webhook_secret: str = Form(""),
    webhook_method: str = Form("POST"),
    webhook_headers: str = Form(""),
    # Form(0) for the same reason as action_notify above.
    webhook_enabled: int = Form(0),
    notify_job_watch: int = Form(0),
):
    """Create a rule. Criteria use the dashboard query syntax."""
    owned = await db.scalar(select(func.count(IntelRule.id)).where(IntelRule.owner_user_id == user.id)) or 0
    if owned >= settings.watch_rules_max_per_user:
        return _rule_form_errors(request, [f"You already have {owned} rules (max {settings.watch_rules_max_per_user})."], rule_id=None)

    rule = IntelRule(owner_user_id=user.id, name="")
    errors = await _apply_rule_fields(
        rule,
        db=db,
        name=name,
        description=description,
        scope=scope,
        query=query,
        entity_types=entity_types,
        action_tag=action_tag,
        action_tag_color=action_tag_color,
        action_notify=action_notify,
        webhook_url=webhook_url,
        webhook_secret=webhook_secret,
        webhook_method=webhook_method,
        webhook_headers=webhook_headers,
        webhook_enabled=webhook_enabled,
        notify_job_watch=notify_job_watch,
    )
    # `rule` is not in the session yet, so a refusal here writes nothing at all.
    if errors:
        return _rule_form_errors(request, errors, rule_id=None)
    db.add(rule)
    await db.commit()
    # A watch rule POSTs to a URL its owner chose whenever it matches, so creating one is
    # configuring outbound traffic, not just a filter.
    await activity.record(
        "intel.watch_rule.create",
        request=request,
        user=user,
        target_type="watch_rule",
        target_id=str(rule.id),
        summary=rule.name,
        meta={"webhook": bool(getattr(rule, "webhook_url", None))},
    )
    return await _render_rules(request, db, user, notice=f"Rule '{rule.name}' created.")


# The inputs a shown webhook section always posts, even left empty.
_WEBHOOK_SECTION_FIELDS = frozenset({"webhook_url", "webhook_method", "webhook_headers", "webhook_secret"})


@router.post("/rules/{rule_id}/edit", response_class=HTMLResponse)
async def rule_edit(
    request: Request,
    rule_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    name: str = Form(...),
    description: str = Form(""),
    # Form("entity"), unlike the checkboxes below: a radio group always posts exactly one of
    # its values, so there is no absent-means-off trap here — and a POST without it means
    # an entity rule.
    scope: str = Form(DEFAULT_RULE_SCOPE),
    query: str = Form(""),
    entity_types: list[str] = Form([]),
    action_tag: str = Form(""),
    action_tag_color: str = Form("gray"),
    # Form(0), not Form(1): an unticked checkbox is absent from the POST body, so a default
    # of 1 could never be switched off. The template sends value="1" when ticked.
    action_notify: int = Form(0),
    webhook_url: str = Form(""),
    webhook_secret: str = Form(""),
    webhook_method: str = Form("POST"),
    webhook_headers: str = Form(""),
    # Form(0) for the same reason as action_notify above.
    webhook_enabled: int = Form(0),
    notify_job_watch: int = Form(0),
    clear_secret: int = Form(0),
):
    """Edit an existing rule. Same validation as create, by construction."""
    rule = await db.get(IntelRule, rule_id)
    if rule is None or not _rule_can_edit(rule, user):
        raise HTTPException(404, "Rule not found")
    if not _WEBHOOK_SECTION_FIELDS & set((await request.form()).keys()):
        # The webhook section was collapsed. "Hide webhook" removes its inputs from the form
        # (`x-if`), and reading every absent field as "cleared" deleted the rule's webhook on
        # an ordinary save. A shown section always posts its text fields — they submit even
        # when empty — so none of them at all means "not edited": keep what is stored. Read
        # from the raw form: FastAPI turns an empty string into the default, so the parameter
        # cannot tell "cleared" from "absent".
        webhook_url = rule.webhook_url or ""
        webhook_method = rule.webhook_method or "POST"
        webhook_headers = rule.webhook_headers_json or ""
        webhook_enabled = int(bool(rule.webhook_enabled))
        notify_job_watch = int(bool(rule.notify_job_watch))
        webhook_secret, clear_secret = "", 0
    errors = await _apply_rule_fields(
        rule,
        db=db,
        name=name,
        description=description,
        scope=scope,
        query=query,
        entity_types=entity_types,
        action_tag=action_tag,
        action_tag_color=action_tag_color,
        action_notify=action_notify,
        webhook_url=webhook_url,
        webhook_secret=webhook_secret,
        webhook_method=webhook_method,
        webhook_headers=webhook_headers,
        webhook_enabled=webhook_enabled,
        notify_job_watch=notify_job_watch,
        clear_secret=clear_secret,
    )
    # `_apply_rule_fields` returns before it touches `rule`, so the loaded row is unchanged
    # and there is nothing to roll back.
    if errors:
        return _rule_form_errors(request, errors, rule_id=rule_id)
    await db.commit()
    # The webhook URL is the interesting field: editing a rule can silently repoint where
    # matched entities are sent, which is the change worth being able to reconstruct.
    await activity.record(
        "intel.watch_rule.edit",
        request=request,
        user=user,
        target_type="watch_rule",
        target_id=str(rule_id),
        summary=rule.name,
        meta={"webhook": bool(rule.webhook_url), "enabled": bool(rule.enabled)},
    )
    return await _render_rules(request, db, user, notice=f"Rule '{rule.name}' updated.")


def _rule_notice(message: str) -> HTMLResponse:
    """One line of feedback in a rule's own row.

    The page-wide notice banner lives at the top of `#rules-region`, so showing one means
    swapping the region, which destroys every open form; single-row actions avoid it.
    Literal Tailwind classes, never `text-{tone}-400`: the production stylesheet is
    built by scanning templates for class names, and an assembled one is not there to find.
    """
    return HTMLResponse(f'<span class="text-green-400">{escape(message)}</span>')


def _rule_refused(request: Request, message: str) -> HTMLResponse:
    """A refusal shown in the same slot, but still a 400 to anything that is not htmx.

    The `_rule_form_errors` split, for the same reason: htmx does not swap a 4xx, so a
    correct status would show the reader nothing, while a caller that is not htmx — a test,
    a script, a form posted with JavaScript off — has no slot to put a sentence in and is
    owed the status code.
    """
    if not request.headers.get("HX-Request"):
        raise HTTPException(400, message)
    return HTMLResponse(f'<span class="text-amber-400">{escape(message)}</span>')


@router.get("/rules/{rule_id}/form-partial", response_class=HTMLResponse)
async def rule_form_partial(
    request: Request,
    rule_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """One rule's edit form, fetched the first time its Edit button is clicked.

    Rendering every form with the page is heavy — measured with thirty-seven rules: 1.29 MB
    and 9,227 DOM nodes, including thirty-eight `conditionEditor()` and thirty-eight
    `tagCombobox()` components, rebuilt on every action, to show at most one.

    `_rule_can_edit`, and a 404 rather than a 403 for a rule this caller may not edit: the
    two are indistinguishable from outside, which is what stops this becoming a probe for
    which rule ids exist.

    The context is the subset of `_render_rules`'s that the form reads. Everything else it
    needs — `condition_grammar`, `tag_write_max`, the two syntax-help lists — are Jinja
    globals, which is exactly why they are globals: a key missed here would render a working
    form over an empty help panel.
    """
    rule = await db.get(IntelRule, rule_id)
    if rule is None or not _rule_can_edit(rule, user):
        raise HTTPException(404, "Rule not found")
    return templates.TemplateResponse(
        request,
        "intel/partials/_rule_form_partial.html",
        {
            "request": request,
            "user": user,
            "rule": rule,
            "all_entity_types": list(ENTITY_TYPES),
            "rule_scopes": RULE_SCOPES,
            "rule_scope_labels": RULE_SCOPE_LABELS,
            "tag_colors": TAG_COLORS,
            "require_public_host": settings.webhook_require_public_host,
            "webhook_methods": WEBHOOK_METHODS,
        },
    )


@router.post("/rules/{rule_id}/test", response_class=HTMLResponse)
async def rule_test(
    request: Request,
    rule_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Send a synthetic delivery so a receiver can be verified without waiting for a job.

    Queued to the worker rather than sent inline: the request path must not block on a
    third-party endpoint, and the delivery must go through exactly the same code (and the
    same rate limit) as a real one, or a passing test would prove nothing.
    """
    rule = await db.get(IntelRule, rule_id)
    if rule is None or not _rule_can_edit(rule, user):
        raise HTTPException(404, "Rule not found")
    if not rule.webhook_url:
        return _rule_refused(request, "This rule has no webhook URL.")
    # `deliver_webhook` opens with `if not rule.webhook_enabled: return`, so without this the
    # button would report "queued" for a delivery that never happens. The template hides
    # the button in this state; the route says the same, because it is reachable directly.
    if not rule.webhook_enabled:
        return _rule_refused(request, "Turn on \u201cSend deliveries for this rule\u201d first \u2014 a test goes through the real delivery path.")

    from app.workers.tasks import deliver_webhook

    deliver_webhook(rule.id, None, [])
    # A test is a real signed POST to a real receiver, on the same path a match takes — so
    # it is outbound traffic like any other, not a dry run.
    await activity.record("intel.watch_rule.test", request=request, user=user, target_type="watch_rule", target_id=str(rule.id), summary=rule.name)
    return _rule_notice("Test delivery queued \u2014 it appears under Activity in a moment.")


@router.post("/rules/{rule_id}/toggle", response_class=HTMLResponse)
async def rule_toggle(
    request: Request,
    rule_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    rule = await db.get(IntelRule, rule_id)
    if rule is None or not _rule_can_edit(rule, user):
        raise HTTPException(404, "Rule not found")
    rule.enabled = not rule.enabled
    await db.commit()
    await activity.record(
        "intel.watch_rule.toggle",
        request=request,
        user=user,
        target_type="watch_rule",
        target_id=str(rule.id),
        summary=f"{rule.name} {'enabled' if rule.enabled else 'disabled'}",
        meta={"enabled": bool(rule.enabled)},
    )
    # The button, and nothing else. Enabling a rule changes one word on the page; a
    # whole-region swap would rebuild it and destroy every open edit form with its contents.
    return HTMLResponse(templates.get_template("intel/partials/_rule_toggle_button.html").module.rule_toggle_button(rule))


@router.post("/rules/{rule_id}/delete", response_class=HTMLResponse)
async def rule_delete(
    request: Request,
    rule_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    rule = await db.get(IntelRule, rule_id)
    if rule is None or not _rule_can_edit(rule, user):
        raise HTTPException(404, "Rule not found")
    await db.execute(delete(WebhookDelivery).where(WebhookDelivery.rule_id == rule_id))
    await db.execute(delete(IntelRuleMatch).where(IntelRuleMatch.rule_id == rule_id))
    # Core `delete()`, so no ORM cascade fires and every table referencing the rule has to
    # be named here — the `remove_entity_links_for_job_async` rule. Missing one leaves
    # dangling rows silently on SQLite (FKs off by default) and raises ForeignKeyViolation
    # on PostgreSQL.
    await db.execute(delete(JobRuleMatch).where(JobRuleMatch.rule_id == rule_id))
    rule_name = rule.name
    await db.delete(rule)
    await db.commit()
    await activity.record("intel.watch_rule.delete", request=request, user=user, target_type="watch_rule", target_id=str(rule_id), summary=rule_name)
    return await _render_rules(request, db, user, notice="Rule deleted.")


@router.get("/rules/preview", response_class=HTMLResponse)
async def rule_preview(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    query: str = "",
    scope: str = DEFAULT_RULE_SCOPE,
    entity_types: list[str] = Query([]),
):
    """How many things this criteria matches right now, in the grammar it was written in.

    Uses the same filter builder the rule evaluation and the corresponding list use, so the
    preview cannot promise something the rule will not deliver — and the same
    `parse_entity_types` the save path uses, so it cannot disagree about the type list
    either — "executable, domain", with the space a person naturally types, must preview
    the domains the saved rule matches.

    The job branch applies `visible_job_filter(user)`, which the entity branch has no need
    of — every entity is visible to every member, but a count of jobs is not. Without it a
    keystroke in this box would report how many private submissions other people hold.
    """
    if scope == "job":
        parsed_jobs = parse_jobs_query(query or "")
        errors = query_errors(parsed_jobs)
        if errors:
            return HTMLResponse(f'<span class="text-xs text-red-400">{escape(errors[0])}</span>')
        stmt = apply_jobs_query(select(AnalysisJob.id), parsed_jobs, viewer_id=user.id)
        vis = visible_job_filter(user)
        if vis is not True:
            stmt = stmt.where(vis)
        n = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        return HTMLResponse(f'<span class="text-xs text-gray-400">Matches {n} job{"" if n == 1 else "s"} you can see right now.</span>')

    parsed = parse_query(query or "")
    if list_terms(parsed):
        parsed["errors"].extend(unknown_list_errors(parsed, await list_names(db)))
    types = parse_entity_types(entity_types)
    stmt = apply_entity_filters(select(Entity), query=parsed, types=types or None)
    if query_needs_post_filter(parsed):
        rows = (await db.execute(stmt.limit(1000))).scalars().all()
        n = len(post_filter(list(rows), parsed))
        approx = True
    else:
        n = await db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        approx = False
    err = parsed["errors"][0] if parsed["errors"] else None
    if err:
        return HTMLResponse(f'<span class="text-xs text-red-400">{escape(err)}</span>')
    return HTMLResponse(f'<span class="text-xs text-gray-400">Matches {"~" if approx else ""}{n} entit{"y" if n == 1 else "ies"} right now.</span>')


#: How far back a dry run looks. Small on purpose: it is one SELECT per job for an entity
#: rule, run inline on the request path, and the question it answers ("would this have been
#: noisy?") is answered as well by the last twenty-five jobs as by the last thousand.
DRY_RUN_JOBS = 25


@router.post("/rules/dry-run", response_class=HTMLResponse)
async def rule_dry_run(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    query: str = Form(""),
    scope: str = Form(DEFAULT_RULE_SCOPE),
    entity_types: list[str] = Form([]),
):
    """What these criteria *would have* raised over the last few finished jobs.

    Writes nothing — no alert, no tag, no `last_evaluated_at`. The existing `/preview` is
    the keystroke-time answer ("how many entities match right now"); this is the one that
    tells you whether a rule will be quiet or will bury you, which is the question people
    actually get wrong. A rule matching six hundred entities across the last twenty-five
    jobs is a rule you want silent, and this finds that out without turning it on.

    Everything goes through `visible_job_filter(user)`: a dry run must not report on jobs
    the caller could not open, which would make it an oracle for how many private
    submissions other people hold.
    """
    # The criteria are checked before anything is fetched. "This condition is wrong" is true
    # whether or not there is a job to test it against; on a fresh instance a typo would
    # otherwise be answered "No finished jobs to test against yet.", which says nothing is wrong.
    if scope == "job":
        parsed_jobs = parse_jobs_query(query or "")
        errors = query_errors(parsed_jobs)
    else:
        parsed = parse_query(query or "")
        # The same list check `rule_preview` does, from the same two lines. Without it a
        # typo'd `list:lolbaz` parses cleanly, matches nothing in every job, and the dry run
        # answers "0 alerts across 0 jobs. Nothing was written." — which is exactly what a
        # correct, narrow rule looks like, while the preview above says "unknown list".
        if list_terms(parsed):
            parsed["errors"].extend(unknown_list_errors(parsed, await list_names(db)))
        errors = parsed["errors"]
    if errors:
        return HTMLResponse(f'<span class="text-xs text-red-400">{escape(errors[0])}</span>')

    vis = visible_job_filter(user)
    jobs_stmt = select(AnalysisJob.id).where(AnalysisJob.status == JobStatus.COMPLETED).order_by(AnalysisJob.id.desc()).limit(DRY_RUN_JOBS)
    if vis is not True:
        jobs_stmt = jobs_stmt.where(vis)
    job_ids = list((await db.execute(jobs_stmt)).scalars().all())
    if not job_ids:
        return HTMLResponse('<span class="text-xs text-gray-500">No finished jobs to test against yet.</span>')

    if scope == "job":
        stmt = apply_jobs_query(select(AnalysisJob.id).where(AnalysisJob.id.in_(job_ids)), parsed_jobs, viewer_id=user.id)
        hits = len(list((await db.execute(stmt)).scalars().all()))
        return HTMLResponse(
            f'<span class="text-xs text-gray-400">Over the last {len(job_ids)} job{"" if len(job_ids) == 1 else "s"} you can see: '
            f'<strong class="text-gray-200">{hits}</strong> would have matched.</span>'
        )

    types = parse_entity_types(entity_types) or None

    # One SELECT per job, not one over all of them: a rule is evaluated per job, and the
    # number that matters is how many alerts it would have raised in total — which double
    # counts an entity seen in two jobs, exactly as the real pass would.
    total = 0
    matched_jobs = 0
    for job_id in job_ids:
        stmt = apply_entity_filters(select(Entity), query=parsed, types=types, job_id=job_id)
        rows = list((await db.execute(stmt.limit(MAX_MATCHES_PER_RULE))).scalars().all())
        if query_needs_post_filter(parsed):
            rows = post_filter(rows, parsed)
        if rows:
            matched_jobs += 1
            total += len(rows)

    return HTMLResponse(
        f'<span class="text-xs text-gray-400">Over the last {len(job_ids)} job{"" if len(job_ids) == 1 else "s"} you can see: '
        f'<strong class="text-gray-200">{total}</strong> alert{"" if total == 1 else "s"} across '
        f'<strong class="text-gray-200">{matched_jobs}</strong> job{"" if matched_jobs == 1 else "s"}. Nothing was written.</span>'
    )


@router.post("/rules/alerts/{match_id}/ack", response_class=HTMLResponse)
async def rule_alert_ack(
    request: Request,
    match_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Acknowledge one alert. Per-user by construction — it belongs to one rule."""
    row = (await db.execute(select(IntelRuleMatch).where(IntelRuleMatch.id == match_id, IntelRuleMatch.rule_id.in_(alert_rule_ids(user))))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Alert not found")
    row.acknowledged_at = func.now()
    row.acknowledged_by_user_id = user.id
    await db.commit()
    await activity.record(
        "intel.watch_alert.ack",
        request=request,
        user=user,
        target_type="watch_alert",
        target_id=str(match_id),
        summary=f"alert on rule #{row.rule_id}",
        meta={"rule_id": row.rule_id, "entity_id": row.entity_id},
    )
    return await _render_rules(request, db, user)


@router.post("/rules/job-alerts/{match_id}/ack", response_class=HTMLResponse)
async def rule_job_alert_ack(
    request: Request,
    match_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Acknowledge one job-rule alert.

    A separate route from `rule_alert_ack` because the id comes from a different table —
    the same reason `/jobs/watch-events/{id}/ack` is separate from this one. Sharing a route
    would mean an id space where 7 could mean either row, and the wrong one is a silent
    404 or, worse, a silent ack of somebody else's alert.
    """
    row = (await db.execute(select(JobRuleMatch).where(JobRuleMatch.id == match_id, JobRuleMatch.rule_id.in_(alert_rule_ids(user))))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Alert not found")
    row.acknowledged_at = func.now()
    row.acknowledged_by_user_id = user.id
    await db.commit()
    await activity.record(
        "intel.watch_alert.ack",
        request=request,
        user=user,
        target_type="watch_alert",
        target_id=str(match_id),
        summary=f"job alert on rule #{row.rule_id}",
        meta={"rule_id": row.rule_id, "job_id": row.job_id, "scope": "job"},
    )
    return await _render_rules(request, db, user)


@router.post("/rules/alerts/ack-all", response_class=HTMLResponse)
async def rule_alerts_ack_all(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Acknowledge every unacked alert on *my* rules — never anyone else's."""
    acked = await ack_all_visible_alerts(db, user)
    # One row for the sweep, with the count — the same reasoning as a bulk tag.
    await activity.record("intel.watch_alert.ack", request=request, user=user, summary=f"{acked} alert(s) acknowledged", meta={"count": acked, "bulk": True})
    return await _render_rules(request, db, user)


# ── Redirects from `/intel/watch*` ───────────────────────────────────────────
#
# Two routes rather than nine, because nine hand-written shims are nine chances to
# forget one when a real route changes shape. The rewrite is small enough to read:
# `/intel/watch*` hangs everything under `/watch`, with rule verbs a segment deeper
# under `/watch/rules`, so dropping that inner segment is the whole translation.
#
# **307, not 302.** Five of these paths are POSTs, and a 302 downgrades a POST to a
# GET — which here means the redirect lands on a route that does not exist, or worse
# on one that does and reads as success while having saved nothing.
#
# `/intel/watchlist-events-partial` and friends live in `routers/intel.py` and are
# untouched: the catch-all needs the slash, and those have no segment break after
# "watch".


def _rules_path_for(rest: str) -> str:
    """`rules/7/edit` → `/intel/rules/7/edit`; `alerts/ack-all` → `/intel/rules/alerts/ack-all`."""
    if rest == "rules":
        return "/intel/rules"
    return "/intel/rules/" + (rest.removeprefix("rules/") if rest.startswith("rules/") else rest)


# ── load and save: the document `rules/builtin.yml` is written in ──────────────────────


@router.get("/rules/export.yml")
async def rules_export(
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
):
    """Your rules — and, for an admin, the shared rules and the lists — as the seed files' document.

    Shared rules carry their `key`, so re-importing them as shared updates in place; your
    own rules carry none, so they come back by name. The signing secret is never in it and
    cannot be imported, and `notify_job_watch` is a per-person preference rather than part
    of a rule. An admin's export holds the shared rules and *their own* rules, not every
    member's: a rule is its owner's, and a file that walked off with everyone's would be a
    new way to read a colleague's webhook URLs. Lists are instance-wide and only an admin
    can import them, so only an admin's export carries them — a member's file must be one
    they can import back.
    """
    specs = []
    if user.is_superuser:
        shared = (await db.execute(select(IntelRule).where(IntelRule.is_builtin.is_(True)).order_by(IntelRule.created_at, IntelRule.id))).scalars().all()
        specs.extend(spec_from_rule(r) for r in shared)
    own = (
        (await db.execute(select(IntelRule).where(IntelRule.owner_user_id == user.id, IntelRule.is_builtin.is_(False)).order_by(IntelRule.created_at, IntelRule.id)))
        .scalars()
        .all()
    )
    specs.extend(spec_from_rule(r) for r in own)
    lists = [spec for _row, spec in await load_lists(db)] if user.is_superuser else []
    return Response(dump_rules_yaml(specs, lists=lists), media_type="text/yaml; charset=utf-8", headers={"Content-Disposition": 'attachment; filename="logstotal-rules.yml"'})


@router.post("/rules/import", response_class=HTMLResponse)
async def rules_import(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_member_or_above),
    yaml_text: str = Form(""),
    file: UploadFile | None = File(None),
    as_shared: int = Form(0),
):
    """Import a rules document, pasted or uploaded. All or nothing.

    Every rule goes through the `validate_spec` the form uses, and one bad rule imports
    none: a partial import would leave a person guessing which half of their file is live.
    The outcome — a count, or the list of what stopped it — comes back as this region, so a
    bad line is reported beside the form rather than on a bare error page.

    `as_shared` is instance-wide and admin-only. A member is refused with 403 rather than
    silently demoted to a personal import: the box is not in their form, so a body carrying
    it is hand-made, and answering it with something else would mislead the hand. Lists in a
    document are always instance-wide, so a member's document may not carry any.
    """
    if as_shared and not user.is_superuser:
        raise HTTPException(403, "Only an administrator can import shared rules")

    async def refused(errors: list[str]) -> HTMLResponse:
        # Into the import form's own slot, so the pasted document and the open panel
        # survive; a region swap re-rendered both from nothing. Without htmx there is no
        # slot, and the region with the errors on top is still the best answer.
        if request.headers.get("HX-Request"):
            return _form_errors(request, errors, slot="rules-import-errors", title="Nothing was imported:")
        return await _render_rules(request, db, user, errors=errors, error_title="Nothing was imported:")

    text = (yaml_text or "").strip()
    if file is not None and file.filename:
        raw = await file.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) > MAX_DOCUMENT_BYTES:
            return await refused([f"the file is larger than {MAX_DOCUMENT_BYTES // 1024} KB"])
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return await refused(["the file is not UTF-8 text"])
    if not text:
        return await refused(["paste a YAML document or choose a file"])
    doc = parse_rules_yaml(text)
    if doc.errors:
        return await refused(doc.errors)
    result = await import_rules(
        db, doc.rules, doc.lists, user=user, as_shared=bool(as_shared), can_write_lists=bool(user.is_superuser), max_per_user=settings.watch_rules_max_per_user
    )
    if result.errors:
        return await refused(result.errors)
    await db.commit()
    # A document can repoint a webhook or retag every job on the instance, so the import is
    # recorded like the edits it stands in for. `meta` carries counts, never `changed=`.
    await activity.record(
        "intel.watch_rule.import",
        request=request,
        user=user,
        target_type="watch_rule",
        summary=result.summary() + (" (shared)" if as_shared else ""),
        meta={"created": result.created, "updated": result.updated, "lists_created": result.lists_created, "lists_updated": result.lists_updated, "shared": bool(as_shared)},
    )
    return await _render_rules(request, db, user, notice=f"Imported: {result.summary()}.")


# ── lists: the named sets a condition tests with `list:<name>` ──────────────────────


def _list_form_spec(name: str, match: str, description: str, values: str) -> ListSpec:
    return ListSpec(name=(name or "").strip().lower(), match=(match or "exact").strip().lower(), description=(description or "").strip()[:500], values=normalize_values(values))


def _apply_list_source(row: RuleList, source_url: str, refresh_hours: str) -> None:
    """Where this list's values come from, if anywhere.

    Deliberately **not** on `ListSpec`: that is the shape of the YAML document rules and
    lists are exported in, and where one instance fetches its copy from is not part of what
    the list *is*. Putting it there would ship one deployment's internal mirror to another's
    import.

    Clearing the URL clears the history with it — "last fetched 3 h ago" under a list that
    is no longer fetched from anywhere is a lie with a timestamp on it.
    """
    url = (source_url or "").strip()[:500]
    if not url:
        row.source_url = None
        row.refresh_hours = 0
        row.last_fetched_at = None
        row.last_fetch_ok = None
        row.last_fetch_error = None
        return
    row.source_url = url
    try:
        hours = int(refresh_hours or 0)
    except (TypeError, ValueError):
        hours = 0
    # A week is the longest interval the form offers; anything longer is "press Refresh".
    row.refresh_hours = max(0, min(hours, 168))


@router.post("/rules/lists", response_class=HTMLResponse)
async def rule_list_create(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
    name: str = Form(...),
    match: str = Form("exact"),
    description: str = Form(""),
    values: str = Form(""),
    source_url: str = Form(""),
    refresh_hours: str = Form("0"),
):
    """Create a list. Admin-only: a list is instance-wide, and every rule that names it
    changes meaning with it."""
    spec = _list_form_spec(name, match, description, values)
    errors = validate_list_spec(spec)
    if not errors and spec.name in await list_names(db):
        errors = [f"a list called {spec.name!r} already exists"]
    if errors:
        return _form_errors(request, errors, slot="list-form-errors-new", title="This list was not saved:")
    row = await write_list(db, None, spec, seed_hash=None)
    _apply_list_source(row, source_url, refresh_hours)
    await db.commit()
    await activity.record("intel.rule_list.create", request=request, user=user, target_type="rule_list", target_id=spec.name, summary=spec.name, meta={"values": len(spec.values)})
    return await _render_rules(request, db, user, notice=f"List '{spec.name}' created with {len(spec.values)} value{'s' if len(spec.values) != 1 else ''}.")


@router.post("/rules/{rule_id}/promote-set", response_class=HTMLResponse)
async def rule_promote_set(
    request: Request,
    rule_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
    name: str = Form(...),
    description: str = Form(""),
):
    """Turn this rule's inline `in:(a,b,c)` into a named list, and point the rule at it.

    One action, because the two halves are useless apart: a list nothing references is
    clutter, and a rule still spelling the set out has not been promoted. It is the moment
    a set outgrows the condition — when it wants a name, a description, and a second rule
    to test it.

    **Admin-only, like every other list write.** A list is instance-wide, so promoting one
    is a change to what every colleague's rules can say. The set itself was writable by the
    rule's owner, which is exactly the asymmetry that makes this a separate verb rather than
    part of saving a rule.

    Only a condition with **exactly one** inline set is offered this; with two, which one
    becomes a list is a judgement the analyst has to make, and the form is where they make
    it.
    """
    rule = await db.get(IntelRule, rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    if not _rule_can_edit(rule, user):
        raise HTTPException(404, "Rule not found")

    parsed = parse_query(rule.query or "")
    sets = [t for t in parsed.get("terms", []) if t.get("kind") == "inset"]
    slot = f"promote-errors-{rule_id}"
    if len(sets) != 1:
        return _form_errors(request, ["This rule does not spell out exactly one set to promote"], slot=slot, title="Nothing was promoted:")

    spec = ListSpec(name=(name or "").strip().lower(), match="exact", description=(description or "").strip()[:500], values=tuple(sets[0]["values"]))
    errors = validate_list_spec(spec)
    if not errors and spec.name in await list_names(db):
        errors = [f"a list called {spec.name!r} already exists"]
    if errors:
        return _form_errors(request, errors, slot=slot, title="Nothing was promoted:")

    # Replace the term's own span rather than the string `in:(…)` anywhere it occurs: the
    # scanner knows where the term starts and ends, and a condition may legitimately carry
    # the same characters inside a quoted phrase or a regex.
    span = next(((st, en) for st, en, tok in scan_query(rule.query or "") if tok.lower().lstrip("-").startswith("in:(")), None)
    if span is None:
        return _form_errors(request, ["This rule does not spell out exactly one set to promote"], slot=slot, title="Nothing was promoted:")
    start, end = span
    negation = "-" if (rule.query or "")[start] == "-" else ""
    rewritten = (rule.query or "")[:start] + f"{negation}list:{spec.name}" + (rule.query or "")[end:]
    if len(rewritten) > CRITERIA_MAX:
        return _form_errors(request, [f"the rewritten condition would be longer than {CRITERIA_MAX} characters"], slot=slot, title="Nothing was promoted:")

    await write_list(db, None, spec, seed_hash=None)
    rule.query = rewritten
    # A shared rule an admin edits stops tracking the file, exactly as any other edit does.
    rule.seed_hash = None
    await db.commit()
    await activity.record(
        "intel.rule_list.create",
        request=request,
        user=user,
        target_type="rule_list",
        target_id=spec.name,
        summary=f"{spec.name} (promoted from {rule.name})",
        meta={"values": len(spec.values), "promoted_from_rule": rule.id},
    )
    return await _render_rules(
        request, db, user, notice=f"List '{spec.name}' created with {len(spec.values)} value{'s' if len(spec.values) != 1 else ''}; '{rule.name}' now tests it."
    )


@router.post("/rules/lists/{list_id}/edit", response_class=HTMLResponse)
async def rule_list_edit(
    request: Request,
    list_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
    match: str = Form("exact"),
    description: str = Form(""),
    values: str = Form(""),
    source_url: str = Form(""),
    refresh_hours: str = Form("0"),
):
    """Rewrite a list's values, match and description. The name is its identity — every
    condition that says `list:<name>` — and is not editable; make a new list instead.

    An edit clears `seed_hash`, which is what makes the seeder leave the list alone from
    now on.
    """
    row = await db.get(RuleList, list_id)
    if row is None:
        raise HTTPException(404, "List not found")
    spec = _list_form_spec(row.name, match, description, values)
    errors = validate_list_spec(spec)
    if errors:
        return _form_errors(request, errors, slot=f"list-form-errors-{row.id}", title="This list was not saved:")
    await write_list(db, row, spec, seed_hash=None)
    _apply_list_source(row, source_url, refresh_hours)
    await db.commit()
    await activity.record("intel.rule_list.edit", request=request, user=user, target_type="rule_list", target_id=spec.name, summary=spec.name, meta={"values": len(spec.values)})
    return await _render_rules(request, db, user, notice=f"List '{spec.name}' saved with {len(spec.values)} value{'s' if len(spec.values) != 1 else ''}.")


@router.post("/rules/lists/{list_id}/refresh", response_class=HTMLResponse)
async def rule_list_refresh(
    request: Request,
    list_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Fetch this list's source URL now, rather than waiting for the sweep.

    Inline in a threadpool, not through Huey — the `/admin/ai/{id}/test` arrangement, and
    for the same reason: an admin who has just typed a URL wants to be told whether it works
    while they are still looking at the form. A queued task would report into a log they
    would have to go and find.

    **A failed fetch keeps the old values**, exactly as the sweep does. A feed that 404s
    must not empty a list every rule on the instance tests; the error goes on the row.
    """
    from app.intel.rule_list_fetch import FetchError, fetch_list_values

    row = await db.get(RuleList, list_id)
    if row is None:
        raise HTTPException(404, "List not found")
    if not row.source_url:
        raise HTTPException(400, "This list has no source URL")

    row.last_fetched_at = utc_now_naive()
    try:
        values = await run_in_threadpool(fetch_list_values, row.source_url)
    except FetchError as exc:
        row.last_fetch_ok = False
        row.last_fetch_error = str(exc)[:300]
        await db.commit()
        return await _render_rules(request, db, user, errors=[f"'{row.name}' could not be refreshed: {exc}"])

    spec = ListSpec(name=row.name, match=row.match, description=row.description or "", values=values)
    await write_list(db, row, spec, seed_hash=None)
    row.last_fetch_ok = True
    row.last_fetch_error = None
    await db.commit()
    await activity.record(
        "intel.rule_list.edit",
        request=request,
        user=user,
        target_type="rule_list",
        target_id=row.name,
        summary=f"{row.name} (refreshed from source)",
        meta={"values": len(values)},
    )
    return await _render_rules(request, db, user, notice=f"List '{row.name}' refreshed: {len(values)} value{'s' if len(values) != 1 else ''}.")


@router.post("/rules/lists/{list_id}/delete", response_class=HTMLResponse)
async def rule_list_delete(
    request: Request,
    list_id: int,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Delete a list nothing names. A list a condition still tests is refused, with the
    rules listed: a `list:` naming nothing matches nothing, silently, forever."""
    row = await db.get(RuleList, list_id)
    if row is None:
        raise HTTPException(404, "List not found")
    users = await rules_naming(db, row.name)
    if users:
        message = (
            f"'{row.name}' is used by {len(users)} rule{'s' if len(users) != 1 else ''} ({', '.join(users[:5])}{'…' if len(users) > 5 else ''}) — change those conditions first"
        )
        # The region with the refusal on top, the way a failed Refresh reports: htmx does not
        # swap a 400, so the rules blocking the delete reached nobody.
        if not request.headers.get("HX-Request"):
            raise HTTPException(400, message)
        return await _render_rules(request, db, user, errors=[message])
    name = row.name
    await db.delete(row)
    await db.commit()
    await activity.record("intel.rule_list.delete", request=request, user=user, target_type="rule_list", target_id=name, summary=name)
    return await _render_rules(request, db, user, notice=f"List '{name}' deleted.")


@router.api_route("/watch", methods=["GET"], include_in_schema=False)
async def legacy_watch_page() -> RedirectResponse:
    """The bookmark, the bell dropdown's footer, and every older release's docs."""
    return RedirectResponse("/intel/rules", status_code=307)


@router.api_route("/watch/{rest:path}", methods=["GET", "POST"], include_in_schema=False)
async def legacy_watch_paths(rest: str) -> RedirectResponse:
    return RedirectResponse(_rules_path_for(rest), status_code=307)
