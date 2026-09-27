"""Huey queue introspection for admin dashboards.

Read-only by default. The one write — :func:`revoke_task` — is a separate function so a
caller has to ask for it explicitly.

**The pending queue is not the whole queue.** ``storage.enqueued_items()`` misses a job
re-enqueued by the slot-cap deferral (``run_analysis.schedule(delay=…)``) and every webhook
retry backoff — that work waits in the *schedule*, and an admin would see an idle queue.
:func:`get_scheduled_snapshot` is the other half.

**Argument labels come from** :mod:`app.task_registry`, never a local table, or a task
missing from it renders its arguments as bare positional values.
"""

from __future__ import annotations

import logging

from app.task_registry import arg_names

_log = logging.getLogger(__name__)


def _summarize_args(task_name: str, args: tuple | None, kwargs: dict | None) -> str:
    """Build a human-readable summary of task arguments."""
    labels = arg_names(_short_name(task_name))
    parts: list[str] = []
    for i, label in enumerate(labels):
        if args and i < len(args):
            parts.append(f"{label}={args[i]}")
        elif kwargs and label in kwargs:
            parts.append(f"{label}={kwargs[label]}")
    if not parts:
        raw: list[str] = []
        if args:
            raw.extend(str(a) for a in args)
        if kwargs:
            raw.extend(f"{k}={v}" for k, v in kwargs.items())
        return ", ".join(raw) if raw else ""
    return ", ".join(parts)


def _short_name(task_name: str) -> str:
    """``app.workers.tasks.run_analysis`` -> ``run_analysis``.

    Huey registers tasks by dotted path; the registry and the UI both key on the bare name.
    """
    return task_name.rsplit(".", 1)[-1] if task_name else task_name


def _describe(task) -> dict:
    from app.task_registry import label

    short = _short_name(task.name)
    return {
        "task_name": short,
        "label": label(short),
        "args_summary": _summarize_args(task.name, task.args, task.kwargs),
        "task_id": task.id,
    }


def get_queue_snapshot(limit: int = 20) -> dict:
    """Return a non-destructive snapshot of the Huey Redis queue.

    Returns dict with keys:
        queue_size (int): total items in the queue
        items (list[dict]): up to *limit* deserialized tasks
        error (str | None): set if Redis or deserialization failed
    """
    limit = min(limit, 100)
    result: dict = {"queue_size": 0, "items": [], "error": None}

    try:
        from app.workers.huey_app import huey

        result["queue_size"] = huey.storage.queue_size()

        if limit <= 0:
            return result

        raw_items = huey.storage.enqueued_items(limit=limit)
        for raw in raw_items:
            try:
                result["items"].append(_describe(huey.deserialize_task(raw)))
            except Exception:
                result["items"].append(
                    {
                        "task_name": "?",
                        "label": "?",
                        "args_summary": "(could not decode)",
                        "task_id": "?",
                    }
                )
    except Exception as exc:
        _log.warning("Failed to read Huey queue: %s", exc)
        result["error"] = str(exc)

    return result


def get_scheduled_snapshot(limit: int = 20) -> dict:
    """Tasks waiting on the *schedule* rather than the queue.

    This is where a slot-cap deferral (`run_analysis.schedule(delay=…)`) and every webhook
    retry backoff live. Without it the admin sees an empty queue while work is pending, and
    concludes the worker is idle when it is waiting.

    Returns ``{scheduled_size, items, error}``; each item carries ``eta`` when Huey knows it.
    """
    limit = min(limit, 100)
    result: dict = {"scheduled_size": 0, "items": [], "error": None}
    try:
        from app.workers.huey_app import huey

        result["scheduled_size"] = huey.storage.schedule_size()
        if limit <= 0:
            return result
        for raw in huey.storage.scheduled_items(limit=limit):
            try:
                task = huey.deserialize_task(raw)
                item = _describe(task)
                eta = getattr(task, "eta", None)
                item["eta"] = eta.isoformat(timespec="seconds") if eta else None
                result["items"].append(item)
            except Exception:
                result["items"].append({"task_name": "?", "label": "?", "args_summary": "(could not decode)", "task_id": "?", "eta": None})
    except Exception as exc:
        _log.warning("Failed to read the Huey schedule: %s", exc)
        result["error"] = str(exc)
    return result


def revoke_task(task_id: str) -> bool:
    """Mark *task_id* revoked so the consumer skips it at pickup.

    ``revoke_once=True`` is not optional. Huey's default writes a revoke marker with **no
    expiry**, so the id stays permanently revoked in the result store and the key is never
    reclaimed; with it, the consumer consumes the marker when it checks.

    Note the semantics for the UI: this does not remove the entry from the queue. The task
    is still dequeued, finds itself revoked, and is dropped. Say "will be skipped", not
    "removed".
    """
    try:
        from app.workers.huey_app import huey

        huey.revoke_by_id(task_id, revoke_once=True)
        return True
    except Exception as exc:
        _log.warning("Could not revoke Huey task %s: %s", task_id, exc)
        return False


def restore_task(task_id: str) -> bool:
    """Undo :func:`revoke_task` for *task_id*."""
    try:
        from app.workers.huey_app import huey

        huey.restore_by_id(task_id)
        return True
    except Exception as exc:
        _log.warning("Could not restore Huey task %s: %s", task_id, exc)
        return False


def get_scheduled_task_status() -> list[dict]:
    """Last-run and next-run for every periodic task, for the Scheduled panel.

    Last run is read from Redis (written by `_ScheduledRun` in the worker); next run is
    *computed* from the task's own crontab rather than a copy of the schedule kept here,
    so editing a `crontab()` is enough and the two cannot drift.
    """
    from app.database import utc_now_naive
    from app.redis_client import TASK_LAST_RUN_PREFIX, get_redis
    from app.task_registry import PERIODIC, label, next_run

    now = utc_now_naive()
    rows: list[dict] = []
    r = None
    try:
        r = get_redis()
    except Exception:
        pass
    for key in PERIODIC:
        last: dict = {}
        if r is not None:
            try:
                last = r.hgetall(f"{TASK_LAST_RUN_PREFIX}{key}") or {}
            except Exception:
                last = {}
        rows.append(
            {
                "key": key,
                "label": label(key),
                "last_ts": last.get("ts"),
                "last_outcome": last.get("outcome"),
                "last_detail": last.get("detail"),
                "last_duration_ms": int(last["duration_ms"]) if last.get("duration_ms", "").isdigit() else None,
                "next_run": next_run(key, after=now),
            }
        )
    return rows
