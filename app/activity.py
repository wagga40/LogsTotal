"""Recording who did what — the write half of the activity log.

Three rules shape this module, and each of them exists because of a specific way the
obvious implementation goes wrong.

**It never raises.** A failed audit write must not fail the action it describes. Every
entry point is wrapped, the way ``workers/tasks.py::_mark_bg_task`` is, and reports the
failure to the log instead.

**It always opens its own session.** Sharing the caller's is wrong in both directions: a
route that raises after the ``add()`` silently loses the row, and — worse — a ``record()``
that commits would commit whatever else the caller had staged. Called from inside
``user_delete``, that would commit ``_clear_user_references``'s updates *before*
``db.delete(target)`` ran. Its own session, always.

**Actions come from a registry.** ``ACTIONS`` is the single source for the filter
dropdown, the docs table and the call sites, the same idiom as
``admin.MAINTENANCE_ACTIONS`` and ``intel/queries.py::SYNTAX_HELP``. A test asserts every
key passed to :func:`record` is registered, so a typo cannot ship an action nobody can
filter for.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import delete as sa_delete
from sqlalchemy import select

from app import database
from app.database import utc_now_naive
from app.json_utils import dumps as json_dumps
from app.logging_config import current_context
from app.models import ActivityEvent, SiteSettings

_log = logging.getLogger(__name__)

#: Caps so one pathological value cannot bloat the table. `summary`'s column is sized to
#: match; `metadata_json` is Text, so this cap is the only bound on it.
SUMMARY_MAX = 500
METADATA_MAX = 4000

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_DENIED = "denied"


@dataclass(frozen=True)
class ActionSpec:
    """One recordable action: its bucket and how it reads in the UI."""

    category: str
    label: str


#: Categories, in the order they appear in the filter. `export` is deliberately its own
#: bucket rather than a kind of `intel`: "what left this instance" is the question a
#: security tool is most often asked, and it should be one click.
#
# `discussion` is its own bucket rather than being split between `job` and `intel` by
# target: one thread partial serves cases, entities and jobs alike, so splitting it would
# mean the same feature landed in two filters depending on what it was attached to. It is
# also the most privacy-sensitive thing here — the rows name who said something and where,
# on an investigation surface colleagues share — so being able to suppress it on its own,
# without losing the admin trail, is the point of it having its own switch.
CATEGORIES = ("auth", "admin", "job", "intel", "discussion", "export")

ACTIONS: dict[str, ActionSpec] = {
    # ── auth ──
    "auth.login": ActionSpec("auth", "Signed in"),
    "auth.login_failed": ActionSpec("auth", "Sign-in failed"),
    # No `auth.logout`: fastapi-users exposes no hook on the logout route, and the session
    # is a 24h JWT cookie — "when did they leave" is neither knowable nor interesting next
    # to when they arrived. A registered action nobody records is worse than an absent one.
    "auth.register": ActionSpec("auth", "Account registered"),
    "auth.password_reset_requested": ActionSpec("auth", "Password reset requested"),
    # ── admin: users ──
    "admin.user.create": ActionSpec("admin", "User created"),
    "admin.user.delete": ActionSpec("admin", "User deleted"),
    "admin.user.role_change": ActionSpec("admin", "Role changed"),
    "admin.user.set_password": ActionSpec("admin", "Password set"),
    "admin.user.toggle_active": ActionSpec("admin", "Account activated/deactivated"),
    # ── admin: configuration ──
    "admin.settings.changed": ActionSpec("admin", "Site settings changed"),
    # A workflow says which tools run, with which rules, and — through `extra_args` — with
    # which raw CLI flags. That makes editing one the most consequential thing an admin can
    # do here.
    "admin.workflow.create": ActionSpec("admin", "Workflow created"),
    "admin.workflow.update": ActionSpec("admin", "Workflow updated"),
    "admin.workflow.delete": ActionSpec("admin", "Workflow deleted"),
    "admin.provider.create": ActionSpec("admin", "AI provider created"),
    "admin.provider.update": ActionSpec("admin", "AI provider updated"),
    "admin.provider.delete": ActionSpec("admin", "AI provider deleted"),
    "admin.provider.duplicate": ActionSpec("admin", "AI provider duplicated"),
    "admin.provider.toggle": ActionSpec("admin", "AI provider enabled/disabled"),
    "admin.provider.clear_token": ActionSpec("admin", "AI provider token cleared"),
    "admin.provider.test": ActionSpec("admin", "AI provider tested"),
    "admin.enrichment.create": ActionSpec("admin", "Enrichment service created"),
    "admin.enrichment.update": ActionSpec("admin", "Enrichment service updated"),
    "admin.enrichment.delete": ActionSpec("admin", "Enrichment service deleted"),
    "admin.enrichment.toggle": ActionSpec("admin", "Enrichment service enabled/disabled"),
    "admin.enrichment.clear_token": ActionSpec("admin", "Enrichment token cleared"),
    "admin.token.create": ActionSpec("admin", "API token issued"),
    "admin.token.revoke": ActionSpec("admin", "API token revoked"),
    # ── admin: maintenance ──
    "admin.maintenance.queued": ActionSpec("admin", "Maintenance task queued"),
    "admin.maintenance.cancel": ActionSpec("admin", "Background task cancelled"),
    "admin.maintenance.retry": ActionSpec("admin", "Background task retried"),
    "admin.maintenance.revoke": ActionSpec("admin", "Queued task revoked"),
    "admin.maintenance.recover": ActionSpec("admin", "Stuck work recovered"),
    "admin.worker.priority": ActionSpec("admin", "Worker capacity changed"),
    "admin.storage.purge_orphans": ActionSpec("admin", "Orphaned storage purged"),
    "admin.storage.retention": ActionSpec("admin", "Retention policy changed"),
    "admin.storage.vacuum": ActionSpec("admin", "Database vacuumed"),
    "admin.activity.prune": ActionSpec("admin", "Activity log pruned"),
    # ── jobs ──
    "job.upload": ActionSpec("job", "File submitted"),
    "job.cancel": ActionSpec("job", "Job cancelled"),
    "job.delete": ActionSpec("job", "Job deleted"),
    "job.resubmit": ActionSpec("job", "Job re-run"),
    "job.recalculate": ActionSpec("job", "Analytics recalculated"),
    "job.ai_run": ActionSpec("job", "AI analysis run"),
    # Category `job`, not `intel`, even though the vocabulary is shared with entity tags:
    # the row's target is a job, and an operator filtering the log by category is asking
    # about the thing acted on, not about which table the name happens to live in.
    "job.tag.add": ActionSpec("job", "Job tagged"),
    "job.tag.remove": ActionSpec("job", "Job tag removed"),
    "job.watch": ActionSpec("job", "Job watch toggled"),
    # ── discussions ──
    # The comment *text* is never recorded — only that a comment was made, by whom, and on
    # what. An audit log that quietly duplicated every analyst's prose would be a second,
    # unmanaged copy of the thing `Comment`'s soft delete exists to remove properly.
    "discussion.comment": ActionSpec("discussion", "Comment posted"),
    "discussion.edit": ActionSpec("discussion", "Comment edited"),
    "discussion.delete": ActionSpec("discussion", "Comment deleted"),
    # ── intel ──
    "intel.watch_rule.create": ActionSpec("intel", "Watch rule created"),
    "intel.watch_rule.edit": ActionSpec("intel", "Watch rule edited"),
    "intel.watch_rule.toggle": ActionSpec("intel", "Watch rule enabled/disabled"),
    "intel.watch_rule.test": ActionSpec("intel", "Watch rule webhook tested"),
    "intel.watch_rule.delete": ActionSpec("intel", "Watch rule deleted"),
    "intel.watch_rule.import": ActionSpec("intel", "Rules imported from YAML"),
    "intel.rule_list.create": ActionSpec("intel", "Rule list created"),
    "intel.rule_list.edit": ActionSpec("intel", "Rule list edited"),
    "intel.rule_list.delete": ActionSpec("intel", "Rule list deleted"),
    "intel.watch_alert.ack": ActionSpec("intel", "Alert acknowledged"),
    "intel.entity.allowlist": ActionSpec("intel", "Entity allowlisted"),
    # Tags. Applying one to a single entity is a high-frequency analyst action, so a bulk
    # operation records ONE row carrying the count rather than one row per entity — a
    # 200-entity bulk tag that buried everything else under it would be the fastest way to
    # make this log unreadable.
    "intel.tag.add": ActionSpec("intel", "Tag applied"),
    "intel.tag.remove": ActionSpec("intel", "Tag removed"),
    "intel.tag.create": ActionSpec("intel", "Tag defined"),
    "intel.tag.rename": ActionSpec("intel", "Tag renamed"),
    "intel.tag.merge": ActionSpec("intel", "Tag merged"),
    "intel.tag.recolor": ActionSpec("intel", "Tag recoloured"),
    "intel.tag.delete_everywhere": ActionSpec("intel", "Tag deleted everywhere"),
    "intel.case.create": ActionSpec("intel", "Case created"),
    "intel.case.ai_run": ActionSpec("intel", "Case AI analysis run"),
    "intel.case.delete": ActionSpec("intel", "Case deleted"),
    # ── export (data egress) ──
    "export.ioc_feed": ActionSpec("export", "IOC feed read"),
    "export.stix": ActionSpec("export", "STIX bundle exported"),
    "export.misp": ActionSpec("export", "MISP event exported"),
    "export.taxii": ActionSpec("export", "TAXII collection read"),
    "export.case": ActionSpec("export", "Case exported"),
    "export.job_findings": ActionSpec("export", "Job findings exported"),
    "export.job_raw": ActionSpec("export", "Raw job output downloaded"),
}


def category_of(action: str) -> str:
    spec = ACTIONS.get(action)
    return spec.category if spec else "admin"


def label_of(action: str) -> str:
    spec = ACTIONS.get(action)
    return spec.label if spec else action


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    value = str(value)
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _build(
    action: str,
    *,
    actor_user_id=None,
    actor_label: str | None = None,
    actor_ip: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    summary: str | None = None,
    meta: dict | None = None,
    outcome: str = OUTCOME_SUCCESS,
    request_id: str | None = None,
) -> ActivityEvent:
    """Assemble the row. Pure — no session, no settings read, so it is easy to test."""
    return ActivityEvent(
        created_at=utc_now_naive(),
        actor_user_id=actor_user_id,
        actor_label=_truncate(actor_label or "anonymous", 255),
        actor_ip=_truncate(actor_ip, 45),
        action=action,
        category=category_of(action),
        target_type=_truncate(target_type, 40),
        target_id=_truncate(None if target_id is None else str(target_id), 64),
        summary=_truncate(summary, SUMMARY_MAX),
        metadata_json=_truncate(json_dumps(meta), METADATA_MAX) if meta else None,
        request_id=_truncate(request_id or current_context().get("request_id"), 64),
        outcome=outcome,
    )


def _actor_from(user) -> tuple[object | None, str]:
    """``(user_id, label)`` for a possibly-absent user."""
    if user is None:
        return None, "anonymous"
    return user.id, (getattr(user, "email", None) or "unknown")


def parse_categories(raw: str | None) -> frozenset[str]:
    """The categories a CSV setting enables. Empty or unset means all of them.

    Unknown names are dropped rather than honoured, so a hand-edited row cannot enable a
    bucket the UI has no filter for. An explicit "none" is expressible only by turning the
    whole log off, which is the honest way to say it.
    """
    if not raw or not raw.strip():
        return frozenset(CATEGORIES)
    chosen = {part.strip() for part in raw.split(",") if part.strip()}
    valid = chosen & set(CATEGORIES)
    return frozenset(valid) if valid else frozenset(CATEGORIES)


async def capture_policy(db) -> frozenset[str] | None:
    """Which categories to capture, or ``None`` when capture is off entirely.

    Read through the caller's session — a read cannot commit anything of theirs, and it
    saves a connection on the common path.
    """
    try:
        row = (await db.execute(select(SiteSettings.activity_log_enabled, SiteSettings.activity_categories).where(SiteSettings.id == 1))).first()
        if row is None or not row[0]:
            return None
        return parse_categories(row[1])
    except Exception:
        return None


async def record(
    action: str,
    *,
    request=None,
    user=None,
    actor_label: str | None = None,
    actor_user_id=None,
    actor_ip: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    summary: str | None = None,
    meta: dict | None = None,
    outcome: str = OUTCOME_SUCCESS,
    force: bool = False,
) -> None:
    """Record one action. Never raises, never touches the caller's session.

    *request* is optional — ``UserManager.authenticate`` has no access to one — and when it
    is absent the client IP is simply omitted while ``request_id`` still arrives through
    the logging contextvar the middleware set.

    *force* skips the capture policy, for exactly one caller: the settings save that turns
    capture off (or drops its category). The policy is read after that change commits, so
    without it the one edit that stops the audit trail would leave no record of itself.
    """
    try:
        if actor_user_id is None and user is not None:
            actor_user_id, derived_label = _actor_from(user)
            actor_label = actor_label or derived_label
        if actor_ip is None and request is not None:
            try:
                from app.network.client_ip import get_client_ip

                actor_ip = get_client_ip(request)
            except Exception:
                actor_ip = None

        # Resolved through the module rather than imported at the top, so a test (or any
        # host that rebinds the engine) redirects this the same way it redirects
        # `get_async_session`. Without the indirection an audit write in a test would land
        # in the developer's real database.
        async with database.async_session_maker() as session:
            if not force:
                allowed = await capture_policy(session)
                if allowed is None or category_of(action) not in allowed:
                    return
            session.add(
                _build(
                    action,
                    actor_user_id=actor_user_id,
                    actor_label=actor_label,
                    actor_ip=actor_ip,
                    target_type=target_type,
                    target_id=target_id,
                    summary=summary,
                    meta=meta,
                    outcome=outcome,
                )
            )
            await session.commit()
    except Exception as exc:
        _log.warning("activity: could not record %s: %s", action, exc)


def record_sync(
    action: str,
    *,
    actor_label: str | None = None,
    actor_user_id=None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    summary: str | None = None,
    meta: dict | None = None,
    outcome: str = OUTCOME_SUCCESS,
) -> None:
    """Worker-side twin. Same guarantees; sync engine, per the Huey rule."""
    db = None
    try:
        db = database.get_sync_session()
        row = db.execute(select(SiteSettings.activity_log_enabled, SiteSettings.activity_categories).where(SiteSettings.id == 1)).first()
        if row is None or not row[0] or category_of(action) not in parse_categories(row[1]):
            return
        db.add(
            _build(
                action,
                actor_user_id=actor_user_id,
                actor_label=actor_label or "system",
                target_type=target_type,
                target_id=target_id,
                summary=summary,
                meta=meta,
                outcome=outcome,
            )
        )
        db.commit()
    except Exception as exc:
        _log.warning("activity: could not record %s: %s", action, exc)
        if db is not None:
            try:
                db.rollback()
            except Exception:
                pass
    finally:
        if db is not None:
            db.close()


def prune_sync(days: int) -> int:
    """Delete rows older than *days*. Returns the count; ``0`` disables."""
    if not days or days <= 0:
        return 0
    from datetime import timedelta

    db = database.get_sync_session()
    try:
        cutoff = utc_now_naive() - timedelta(days=days)
        deleted = db.execute(sa_delete(ActivityEvent).where(ActivityEvent.created_at < cutoff)).rowcount or 0
        if deleted:
            db.commit()
        return deleted
    except Exception as exc:
        _log.warning("activity prune failed: %s", exc)
        db.rollback()
        return 0
    finally:
        db.close()


def diff_settings(before: dict, after: dict) -> dict[str, dict]:
    """``{field: {"from": x, "to": y}}`` for the fields that actually changed.

    The settings row is the single most valuable thing in this log, and "settings were
    saved" is nearly worthless next to "someone turned `demo_mode` off". Values are booleans,
    small ints and the categories CSV — no secret ever reaches this function.
    """
    return {key: {"from": before[key], "to": after[key]} for key in after if key in before and before[key] != after[key]}
