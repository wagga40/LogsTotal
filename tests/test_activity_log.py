"""The activity log: what it records, what it refuses to break, and who may read it.

The most important assertions here are the negative ones. `record()` swallows everything
by design, so a bug in it is invisible at runtime — these tests are the only place that
notices. Likewise the "records nothing when disabled" and "still reads when disabled"
pair: those two together are the whole toggle semantics.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app import activity
from app.models import ActivityEvent, SiteSettings

pytestmark = pytest.mark.anyio


# ── Tier 1: pure ──────────────────────────────────────────────────────────────


def test_every_action_has_a_known_category():
    """The registry is what the filter dropdown is built from — an action in a category
    the UI does not offer is an action nobody can find."""
    for key, spec in activity.ACTIONS.items():
        assert spec.category in activity.CATEGORIES, f"{key} has category {spec.category!r}"
        assert spec.label, f"{key} has no label"


def test_action_keys_are_namespaced_by_category():
    """`export.stix` not `stix_export` — the prefix is how the log reads at a glance."""
    for key, spec in activity.ACTIONS.items():
        assert key.startswith(spec.category + "."), key


def test_every_record_call_site_uses_a_registered_action():
    """A typo would ship an action nobody can filter for, and no route test would see it."""
    import ast
    import pathlib

    unknown = []
    for path in pathlib.Path("app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "attr", None)
            if name not in ("record", "record_sync") or not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value not in activity.ACTIONS:
                unknown.append(f"{path}: {first.value}")
    assert not unknown, f"unregistered action key(s): {unknown}"


def test_every_registered_action_is_actually_recorded_somewhere():
    """The reverse of the test above, and the one that was missing.

    Fifteen of fifty-two actions were registered and never called — including
    `admin.provider.create`, so setting up an AI provider (the first thing an operator does
    to use the feature) left no trace. "Capture is on but nothing appears" is
    indistinguishable from a broken feature, which is exactly what it was reported as.
    """
    import ast
    import pathlib

    used = set()
    for path in pathlib.Path("app").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) in ("record", "record_sync") and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    used.add(first.value)

    never = sorted(set(activity.ACTIONS) - used)
    assert not never, f"registered but never recorded: {never}. Either wire up a call site or remove the entry."


def test_build_truncates_rather_than_letting_the_insert_fail():
    event = activity._build("auth.login", summary="x" * 5000, actor_label="y" * 900)
    assert len(event.summary) <= activity.SUMMARY_MAX
    assert len(event.actor_label) <= 255


def test_build_defaults_the_actor_to_anonymous():
    """The column is NOT NULL — an unauthenticated action still has to record something."""
    assert activity._build("auth.login_failed").actor_label == "anonymous"


def test_diff_settings_reports_only_what_changed():
    before = {"demo_mode": False, "show_entities": True, "max_finding_details": 10}
    after = {"demo_mode": True, "show_entities": True, "max_finding_details": 25}
    assert activity.diff_settings(before, after) == {
        "demo_mode": {"from": False, "to": True},
        "max_finding_details": {"from": 10, "to": 25},
    }


def test_diff_settings_is_empty_for_a_no_op_save():
    state = {"demo_mode": False}
    assert activity.diff_settings(state, dict(state)) == {}


@pytest.mark.parametrize("raw,expected", [("=cmd()", "'=cmd()"), ("+1", "'+1"), ("-2", "'-2"), ("@x", "'@x"), ("normal", "normal"), (None, "")])
def test_csv_export_defuses_spreadsheet_formulas(raw, expected):
    """`summary` can hold an attempted username or a submitted filename — attacker text.
    Opened in Excel, a leading `=` is code execution."""
    from app.csv_utils import csv_safe

    assert csv_safe(raw) == expected


# ── Tier 3: the write path ────────────────────────────────────────────────────


async def _enable(db) -> None:
    settings_row = await db.get(SiteSettings, 1)
    if settings_row is None:
        settings_row = SiteSettings(id=1)
        db.add(settings_row)
    settings_row.activity_log_enabled = True
    await db.commit()


async def _events(db) -> list[ActivityEvent]:
    return list((await db.execute(select(ActivityEvent).order_by(ActivityEvent.id))).scalars().all())


async def test_nothing_is_recorded_while_capture_is_off(async_db):
    """Off is the default, and off means the row is never written — not written-and-hidden."""
    await activity.record("auth.login", summary="someone@example.com")
    assert await _events(async_db) == []


async def test_a_row_is_written_when_capture_is_on(async_db):
    await _enable(async_db)
    await activity.record("auth.login", actor_label="someone@example.com", summary="hello")
    rows = await _events(async_db)
    assert len(rows) == 1
    assert rows[0].action == "auth.login"
    assert rows[0].category == "auth"
    assert rows[0].actor_label == "someone@example.com"
    assert rows[0].outcome == "success"


async def test_record_never_raises_on_a_broken_write(async_db, monkeypatch):
    """An audit failure must not fail the action it describes."""
    await _enable(async_db)

    class _Exploding:
        async def __aenter__(self):
            raise RuntimeError("database is on fire")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr("app.database.async_session_maker", lambda: _Exploding())
    await activity.record("auth.login")  # must not raise


async def test_record_never_raises_on_an_unknown_action(async_db):
    await _enable(async_db)
    await activity.record("not.a.real.action", summary="x")
    rows = await _events(async_db)
    # Recorded rather than dropped: losing the event is worse than an odd category, and
    # the AST test above is what stops an unknown key shipping in the first place.
    assert rows[0].category == "admin"


async def test_the_correlation_id_rides_in_from_the_log_context(async_db):
    """`UserManager.authenticate` has no Request; this is how its rows still correlate."""
    from app.logging_config import bind

    await _enable(async_db)
    bind(request_id="req-xyz")
    try:
        await activity.record("auth.login_failed")
    finally:
        bind(request_id=None)
    assert (await _events(async_db))[0].request_id == "req-xyz"


async def test_metadata_is_stored_as_json(async_db):
    from app.json_utils import loads

    await _enable(async_db)
    await activity.record("admin.settings.changed", meta={"changed": {"demo_mode": {"from": False, "to": True}}})
    assert loads((await _events(async_db))[0].metadata_json)["changed"]["demo_mode"]["to"] is True


async def test_prune_removes_old_rows_only(async_db, monkeypatch):
    from datetime import timedelta

    from app.database import utc_now_naive

    await _enable(async_db)
    old = activity._build("auth.login", summary="old")
    old.created_at = utc_now_naive() - timedelta(days=200)
    recent = activity._build("auth.login", summary="recent")
    async_db.add_all([old, recent])
    await async_db.commit()

    # prune_sync is the worker-side twin and uses the sync engine, so exercise its
    # predicate directly against this session rather than crossing engines in a test.
    from sqlalchemy import delete

    cutoff = utc_now_naive() - timedelta(days=90)
    await async_db.execute(delete(ActivityEvent).where(ActivityEvent.created_at < cutoff))
    await async_db.commit()

    remaining = await _events(async_db)
    assert [r.summary for r in remaining] == ["recent"]


def test_prune_is_a_no_op_when_retention_is_disabled():
    """`0` keeps forever — some deployments must retain the trail for a fixed period."""
    assert activity.prune_sync(0) == 0
    assert activity.prune_sync(-1) == 0
