"""One description of every Huey task — the `app/tools/registry.py` idiom, applied to work.

The dashboard's maintenance rows, the queue inspector's argument labels and the admin
tables all read from here. Two boundaries are deliberate and enforced:

**It does not own the route URLs.** The docs-sync guards regex `app/routers/admin.py`'s
*source* for literal ``@router.post("/backfill-…")`` decorators, so generating those routes
from this dict would break the check that keeps them documented. `MAINTENANCE_ACTIONS`
keeps its literal urls; a parity test asserts the two agree.

**`app/workers/tasks.py` must never import this module.** `tests/test_migrations_auto.py`
forbids `app.routers` there, and the dependency only makes sense one way round: the
registry describes the tasks, the tasks do not consult the registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Categories, in the order the admin UI groups them.
ANALYSIS = "analysis"
MAINTENANCE = "maintenance"
SCHEDULED = "scheduled"
DELIVERY = "delivery"
AI = "ai"


@dataclass(frozen=True)
class TaskSpec:
    """What an operator needs to know about one task."""

    key: str
    label: str
    category: str
    #: Positional argument names, in order — how `huey_inspect` labels a queued entry.
    args: tuple[str, ...] = ()
    #: Can an admin stop it once it is running? Only the cooperative-cancel family can.
    cancellable: bool = False
    #: Can an admin re-run it from a finished row, unchanged?
    retryable: bool = False
    #: Maintenance url, when the task has an admin trigger. Mirrors MAINTENANCE_ACTIONS.
    url: str | None = None
    #: Free-text warning shown on the cancel/retry confirm dialog.
    caveat: str | None = None
    notes: str = field(default="")


_SPECS: tuple[TaskSpec, ...] = (
    TaskSpec(
        key="run_analysis",
        label="Analysis job",
        category=ANALYSIS,
        args=("job_id",),
        # Cancellation for a job goes through POST /jobs/{id}/cancel, which has a complete
        # documented three-case protocol. A second, weaker mechanism on the same task is
        # how the two come to disagree — so this is False here on purpose.
        cancellable=False,
        retryable=False,
        notes="Cancel from the job page; retry by re-submitting the file.",
    ),
    TaskSpec(key="recalculate_single_analytics", label="Recalculate analytics", category=MAINTENANCE, args=("job_id", "bg_task_id"), retryable=True),
    TaskSpec(
        key="backfill_similarity",
        label="Similarity Backfill",
        category=MAINTENANCE,
        args=("bg_task_id",),
        cancellable=True,
        retryable=True,
        url="/admin/backfill-similarity",
        notes="Resumable: it only visits rows still missing a hash, so a cancelled run picks up where it stopped.",
    ),
    TaskSpec(
        key="backfill_analytics", label="Analytics Cache Rebuild", category=MAINTENANCE, args=("bg_task_id",), cancellable=True, retryable=True, url="/admin/backfill-analytics"
    ),
    TaskSpec(
        key="backfill_entities",
        label="Entity Backfill",
        category=MAINTENANCE,
        args=("bg_task_id",),
        cancellable=True,
        retryable=True,
        url="/admin/backfill-entities",
        caveat="Entity job counts are rebuilt in one pass at the end; a cancelled run still rebuilds them before stopping.",
    ),
    TaskSpec(
        key="backfill_entity_attributes",
        label="Entity Attribute Backfill",
        category=MAINTENANCE,
        args=("bg_task_id",),
        cancellable=True,
        retryable=True,
        url="/admin/backfill-entity-attributes",
        caveat="Batches of 500 — cancelling takes effect at the next batch boundary.",
    ),
    TaskSpec(
        key="backfill_builtin_labels",
        label="Shared Rules",
        category=MAINTENANCE,
        args=("bg_task_id",),
        cancellable=True,
        retryable=True,
        url="/admin/backfill-builtin-labels",
        caveat="Batches of 500 — cancelling takes effect at the next batch boundary. Evaluates each shared rule's condition as it stands, lists included. No shipped rule uses an attr: term; one you wrote reads stored attributes, which the Entity Attribute Backfill refreshes.",
    ),
    TaskSpec(
        key="backfill_relationships",
        label="Relationship Backfill",
        category=MAINTENANCE,
        args=("bg_task_id",),
        cancellable=True,
        retryable=True,
        url="/admin/backfill-relationships",
        notes="Safe to re-run: occurrence counts are derived from per-job evidence rows, not incremented.",
    ),
    TaskSpec(
        key="backfill_finding_entity_links",
        label="Finding-Entity Link Backfill",
        category=MAINTENANCE,
        args=("bg_task_id",),
        cancellable=True,
        retryable=True,
        url="/admin/backfill-finding-entity-links",
    ),
    TaskSpec(
        key="cleanup_old_job_outputs",
        label="Output Directory Cleanup",
        category=MAINTENANCE,
        args=("bg_task_id",),
        cancellable=True,
        retryable=True,
        url="/admin/cleanup-outputs",
        caveat="Batches of 200 — cancelling takes effect at the next batch boundary. Deleted directories are not restored.",
    ),
    TaskSpec(
        key="purge_orphaned_storage",
        label="Purge orphaned storage",
        category=MAINTENANCE,
        args=("bg_task_id",),
        cancellable=True,
        retryable=True,
        caveat="Removes output directories whose job row is gone, and stale upload spools. Nothing is restored.",
    ),
    TaskSpec(
        key="vacuum_database",
        label="Vacuum database",
        category=MAINTENANCE,
        args=("bg_task_id",),
        retryable=True,
        caveat="SQLite takes an exclusive lock and rewrites the whole file. Expect the application to pause for the duration.",
    ),
    TaskSpec(key="deliver_webhook", label="Watch-rule webhook", category=DELIVERY, args=("rule_id", "job_id", "match_ids", "attempt")),
    TaskSpec(key="run_case_ai_analysis", label="Case AI analysis", category=AI, args=("analysis_id",), notes="Stop it from the case AI Analysis tab."),
    TaskSpec(key="run_ai_analysis", label="AI analysis", category=AI, args=("analysis_id",), notes="Stop it from the job's AI Analysis tab."),
    # ── periodic ──
    TaskSpec(key="prune_expired_api_tokens_periodic", label="Prune revoked API tokens", category=SCHEDULED, notes="Removes tokens revoked more than 90 days ago."),
    TaskSpec(key="prune_enrichment_results_periodic", label="Prune enrichment cache", category=SCHEDULED, notes="Removes results not fetched again in 30 days."),
    TaskSpec(
        key="refresh_rule_lists_periodic",
        label="Refresh rule lists from source",
        category=SCHEDULED,
        notes="Hourly; re-fetches each list whose own interval has elapsed. A failed fetch keeps the values it has.",
    ),
    TaskSpec(key="prune_webhook_deliveries_periodic", label="Prune webhook deliveries", category=SCHEDULED, notes="Window: WEBHOOK_DELIVERY_RETENTION_DAYS."),
    TaskSpec(key="prune_deleted_comments_periodic", label="Prune comment tombstones", category=SCHEDULED, notes="Removes soft-deleted comments after 180 days."),
    TaskSpec(key="cleanup_job_outputs_periodic", label="Sweep old job outputs", category=SCHEDULED, notes="Window: JOB_OUTPUT_RETENTION_DAYS; 0 disables."),
    TaskSpec(key="prune_activity_events_periodic", label="Prune activity log", category=SCHEDULED, notes="Window: ACTIVITY_RETENTION_DAYS; 0 keeps forever."),
    TaskSpec(key="prune_background_tasks_periodic", label="Prune task history", category=SCHEDULED, notes="Window: BACKGROUND_TASK_RETENTION_DAYS."),
    TaskSpec(key="prune_old_uploads_periodic", label="Prune old uploads", category=SCHEDULED, notes="Window: UPLOAD_RETENTION_DAYS; 0 (the default) disables it entirely."),
)

REGISTRY: dict[str, TaskSpec] = {spec.key: spec for spec in _SPECS}

#: Keys whose rows an admin may cancel mid-run.
CANCELLABLE = frozenset(spec.key for spec in _SPECS if spec.cancellable)
#: Keys an admin may re-run from a finished row.
RETRYABLE = frozenset(spec.key for spec in _SPECS if spec.retryable)
#: Keys that run on a schedule; the Scheduled panel is built from these.
PERIODIC = tuple(spec.key for spec in _SPECS if spec.category == SCHEDULED)


def get(key: str) -> TaskSpec | None:
    return REGISTRY.get(key)


def label(key: str) -> str:
    spec = REGISTRY.get(key)
    return spec.label if spec else key


def arg_names(key: str) -> tuple[str, ...]:
    spec = REGISTRY.get(key)
    return spec.args if spec else ()


def maintenance_urls() -> dict[str, str]:
    """``{key: url}`` for every task with an admin trigger — the parity-test surface."""
    return {spec.key: spec.url for spec in _SPECS if spec.url}


def resolve_callable(key: str):
    """The Huey task for *key*, imported lazily.

    Late import, always: `app/workers/tasks.py` pulls in the whole worker stack, and the
    dependency runs registry → tasks and never back.
    """
    if key not in REGISTRY:
        return None
    from app.workers import tasks as worker_tasks

    return getattr(worker_tasks, key, None)


def next_run(key: str, *, after, horizon_minutes: int = 60 * 24 * 8):
    """The next datetime at which the periodic task *key* fires, or ``None``.

    Computed by stepping a minute at a time through the task's own crontab validator rather
    than read from a schedule string stored here. A hard-coded copy of the schedule is a
    drift bug waiting to happen — `_TASK_ARG_LABELS` going stale is the proof — and this
    way editing a ``crontab()`` in `tasks.py` is enough. The step loop is cheap: eight days
    is 11,520 predicate calls, microseconds in total.
    """
    from datetime import timedelta

    task = _periodic_task(key)
    if task is None:
        return None
    # Start at the next whole minute: `validate_datetime` is minute-granular, and testing
    # the current one would report "now" for a task that has just run.
    probe = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(horizon_minutes):
        if task.validate_datetime(probe):
            return probe
        probe += timedelta(minutes=1)
    return None


def _periodic_task(key: str):
    """The registered periodic task instance for *key*, or ``None``."""
    try:
        from app.workers.huey_app import huey

        for task in huey._registry.periodic_tasks:
            if type(task).__name__ == key or getattr(task, "name", None) == key:
                return task
    except Exception:
        return None
    return None
