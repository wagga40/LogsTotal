"""The task registry, and the two things it exists to stop drifting.

`huey_inspect._TASK_ARG_LABELS` was a hand-maintained table that had gone stale — five of
the sixteen task names were missing, so their arguments rendered as bare positional values
and nobody noticed. The parity test here is the mechanised version of remembering.
"""

from __future__ import annotations

import datetime

import pytest

from app import task_registry as tr


def _registered_task_names() -> set[str]:
    """Every task Huey knows about, by bare name."""
    from app.workers.huey_app import huey

    return {name.rsplit(".", 1)[-1] for name in huey._registry._registry}


# ── Parity, both directions ──────────────────────────────────────────────────


def test_every_huey_task_is_described():
    """The failure this catches: a new task ships and renders as an unlabelled row with
    unnamed arguments."""
    missing = sorted(_registered_task_names() - set(tr.REGISTRY))
    assert not missing, f"tasks with no registry entry: {missing}"


def test_the_registry_describes_no_task_that_does_not_exist():
    stale = sorted(set(tr.REGISTRY) - _registered_task_names())
    assert not stale, f"registry entries for tasks that no longer exist: {stale}"


def test_the_maintenance_urls_match_the_admin_actions():
    """The registry deliberately does NOT generate these routes — two docs-sync guards
    regex admin.py's source for literal decorators. This is the parity that replaces it."""
    from app.routers.admin import MAINTENANCE_ACTIONS

    assert set(tr.maintenance_urls().values()) == {action["url"] for action in MAINTENANCE_ACTIONS}


def test_the_registry_does_not_generate_the_backfill_routes():
    """Registering them from a loop would make `@router.post("/backfill-…")` unfindable to
    the docs-sync grep, whose assertion is that the match is non-empty."""
    import re
    from pathlib import Path

    source = Path("app/routers/admin.py").read_text(encoding="utf-8")
    # Includes `/backfill-builtin-labels`: labels are stored tags, so entities last seen
    # before the built-in rules existed carry none until it runs.
    assert len(re.findall(r'@router\.post\("(/backfill-[a-z-]+)"\)', source)) == 7


def test_the_worker_never_imports_the_registry():
    """The dependency runs registry → tasks, one way. The reverse would also risk the
    import cycle `huey_app` already has to work around."""
    from pathlib import Path

    source = Path("app/workers/tasks.py").read_text(encoding="utf-8")
    assert "task_registry" not in source


def test_every_spec_is_usable():
    for key, spec in tr.REGISTRY.items():
        assert spec.key == key
        assert spec.label, key
        assert spec.category in {tr.ANALYSIS, tr.MAINTENANCE, tr.SCHEDULED, tr.DELIVERY, tr.AI}


def test_retryable_tasks_all_resolve_to_a_real_callable():
    """Retry dispatches through this — an entry that resolves to nothing is a 400 the
    admin cannot act on."""
    for key in tr.RETRYABLE:
        assert tr.resolve_callable(key) is not None, key


def test_run_analysis_is_not_cancellable_from_here():
    """It has a complete, documented three-case cancel protocol on the job page. A second,
    weaker mechanism on the same task is how the two come to disagree."""
    assert "run_analysis" not in tr.CANCELLABLE


# ── next_run ─────────────────────────────────────────────────────────────────


def test_every_periodic_task_reports_a_next_run():
    now = datetime.datetime(2026, 8, 15, 12, 0)
    for key in tr.PERIODIC:
        assert tr.next_run(key, after=now) is not None, key


@pytest.mark.parametrize(
    "key,after,expected",
    [
        # Daily at 03:00 — asked at 03:15, so tomorrow.
        ("prune_expired_api_tokens_periodic", datetime.datetime(2026, 8, 15, 3, 15), datetime.datetime(2026, 8, 16, 3, 0)),
        # Daily at 04:45 — asked at 03:15, so later today.
        ("cleanup_job_outputs_periodic", datetime.datetime(2026, 8, 15, 3, 15), datetime.datetime(2026, 8, 15, 4, 45)),
    ],
)
def test_next_run_is_computed_from_the_real_crontab(key, after, expected):
    """Computed, not read from a schedule string stored here: a copy would drift the
    moment someone edited a `crontab()`, which is precisely how the arg-label table rotted."""
    assert tr.next_run(key, after=after) == expected


def test_next_run_is_none_for_a_task_that_is_not_periodic():
    assert tr.next_run("backfill_similarity", after=datetime.datetime(2026, 8, 15, 12, 0)) is None


# ── huey_inspect uses it ─────────────────────────────────────────────────────


def test_queued_arguments_are_labelled_for_every_task():
    """A task name with no entry renders its args unlabelled."""
    from app.huey_inspect import _summarize_args

    assert _summarize_args("app.workers.tasks.run_analysis", (7,), None) == "job_id=7"
    assert _summarize_args("app.workers.tasks.deliver_webhook", (3, 9, [1, 2]), None).startswith("rule_id=3, job_id=9")
    assert _summarize_args("app.workers.tasks.run_ai_analysis", (5,), None) == "analysis_id=5"
    assert _summarize_args("app.workers.tasks.backfill_relationships", (4,), None) == "bg_task_id=4"


def test_revoke_uses_revoke_once(monkeypatch):
    """Huey's default writes a revoke marker with NO expiry: the id stays revoked forever
    and the key is never reclaimed."""
    from app import huey_inspect

    seen = {}

    class _FakeHuey:
        def revoke_by_id(self, task_id, revoke_once=False):
            seen["task_id"] = task_id
            seen["revoke_once"] = revoke_once

    import app.workers.huey_app as huey_app

    monkeypatch.setattr(huey_app, "huey", _FakeHuey())
    assert huey_inspect.revoke_task("abc") is True
    assert seen == {"task_id": "abc", "revoke_once": True}
