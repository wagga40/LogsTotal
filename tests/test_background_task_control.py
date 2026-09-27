"""Cancelling, retrying, revoking and recovering background tasks.

The cancel route mirrors `POST /jobs/{id}/cancel`'s three cases, and the assertions here
are deliberately about *ordering*: the Redis flag must be set before the DB is touched, or
a worker reading between the two writes stops for a reason nobody recorded.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.database import utc_now_naive
from app.models import BackgroundTask, BackgroundTaskStatus
from app.redis_client import BGTASK_CANCEL_PREFIX

pytestmark = pytest.mark.anyio


async def _make(db, **kwargs) -> BackgroundTask:
    row = BackgroundTask(
        name=kwargs.pop("name", "Similarity Backfill"),
        kind=kwargs.pop("kind", "backfill_similarity"),
        status=kwargs.pop("status", BackgroundTaskStatus.RUNNING),
        **kwargs,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


# ── Access ────────────────────────────────────────────────────────────────────


async def test_control_routes_require_an_admin(member_client, async_db):
    row = await _make(async_db)
    assert (await member_client.post(f"/admin/tasks/{row.id}/cancel", follow_redirects=False)).status_code in (403, 404)
    assert (await member_client.post("/admin/tasks/recover", follow_redirects=False)).status_code in (403, 404)


async def test_cancelling_an_unknown_task_is_a_404(admin_client):
    assert (await admin_client.post("/admin/tasks/99999/cancel", follow_redirects=False)).status_code == 404


# ── Cancel ────────────────────────────────────────────────────────────────────


async def test_cancelling_a_running_task_sets_the_flag_and_leaves_the_row_to_the_worker(admin_client, async_db, fake_redis):
    """The worker owns a row it is actively writing to. Finalising it here would race the
    task's own commit — the same reasoning as a job with a live heartbeat."""
    row = await _make(async_db, status=BackgroundTaskStatus.RUNNING, heartbeat_at=utc_now_naive())
    resp = await admin_client.post(f"/admin/tasks/{row.id}/cancel", follow_redirects=False)
    assert resp.status_code == 303
    assert fake_redis.exists(f"{BGTASK_CANCEL_PREFIX}{row.id}")

    await async_db.refresh(row)
    assert row.status == BackgroundTaskStatus.RUNNING, "the worker finalises it, not the route"


async def test_cancelling_a_pending_task_finalises_it_here(admin_client, async_db, fake_redis):
    """Nothing has picked it up, so nobody would ever read the flag."""
    row = await _make(async_db, status=BackgroundTaskStatus.PENDING)
    resp = await admin_client.post(f"/admin/tasks/{row.id}/cancel", follow_redirects=False)
    assert resp.status_code == 303

    await async_db.refresh(row)
    assert row.status == BackgroundTaskStatus.CANCELLED
    assert row.finished_at is not None


async def test_cancelling_a_finished_task_is_a_no_op(admin_client, async_db, fake_redis):
    row = await _make(async_db, status=BackgroundTaskStatus.COMPLETED, finished_at=utc_now_naive())
    resp = await admin_client.post(f"/admin/tasks/{row.id}/cancel", follow_redirects=False)
    assert resp.status_code == 303
    assert not fake_redis.exists(f"{BGTASK_CANCEL_PREFIX}{row.id}")


async def test_a_task_that_cannot_be_cancelled_is_refused(admin_client, async_db):
    """`run_analysis` has its own protocol on the job page; a second one here would let
    the two disagree about what cancelling means."""
    row = await _make(async_db, kind="run_analysis", name="Analysis job", status=BackgroundTaskStatus.RUNNING)
    assert (await admin_client.post(f"/admin/tasks/{row.id}/cancel", follow_redirects=False)).status_code == 400


async def test_cancel_refuses_when_redis_is_unreachable(admin_client, async_db, monkeypatch):
    """Without Redis the worker can never learn it was cancelled, so writing the row would
    state something the system cannot make true."""
    import app.redis_client as rc

    def _boom():
        raise RuntimeError("redis is down")

    monkeypatch.setattr(rc, "get_redis", _boom)
    row = await _make(async_db, status=BackgroundTaskStatus.RUNNING)
    assert (await admin_client.post(f"/admin/tasks/{row.id}/cancel", follow_redirects=False)).status_code == 503


# ── Retry ─────────────────────────────────────────────────────────────────────


async def test_retry_creates_a_new_row_and_leaves_the_original_untouched(admin_client, async_db, monkeypatch):
    """History is never mutated: overwriting the failed run destroys the only evidence of
    what went wrong."""
    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "backfill_similarity", lambda *a, **k: None)

    original = await _make(async_db, status=BackgroundTaskStatus.FAILED, error_message="it broke", finished_at=utc_now_naive())
    resp = await admin_client.post(f"/admin/tasks/{original.id}/retry", follow_redirects=False)
    assert resp.status_code == 303

    await async_db.refresh(original)
    assert original.status == BackgroundTaskStatus.FAILED
    assert original.error_message == "it broke"

    rows = (await async_db.execute(select(BackgroundTask).order_by(BackgroundTask.id))).scalars().all()
    assert len(rows) == 2
    assert rows[1].status == BackgroundTaskStatus.PENDING
    assert rows[1].kind == original.kind


async def test_a_recalculation_retry_reports_into_its_new_row(admin_client, async_db, monkeypatch):
    """Recalculation takes the job id — and has to be told which row to close, or the retry
    sits at "pending" for good, exactly like the run it replaced."""
    from app.workers import tasks as worker_tasks

    calls: list[tuple] = []
    monkeypatch.setattr(worker_tasks, "recalculate_single_analytics", lambda *a, **k: calls.append((a, k)))

    original = await _make(async_db, kind="recalculate_single_analytics", target_id="7", status=BackgroundTaskStatus.FAILED, finished_at=utc_now_naive())
    assert (await admin_client.post(f"/admin/tasks/{original.id}/retry", follow_redirects=False)).status_code == 303

    fresh = (await async_db.execute(select(BackgroundTask).order_by(BackgroundTask.id.desc()))).scalars().first()
    assert calls == [((7,), {"bg_task_id": fresh.id})]


async def test_retry_refuses_a_running_task(admin_client, async_db):
    row = await _make(async_db, status=BackgroundTaskStatus.RUNNING)
    assert (await admin_client.post(f"/admin/tasks/{row.id}/retry", follow_redirects=False)).status_code == 400


async def test_retry_refuses_a_task_with_no_registry_entry(admin_client, async_db):
    """A row from an older build naming a task this one no longer has."""
    row = await _make(async_db, kind="backfill_something_removed", status=BackgroundTaskStatus.FAILED, finished_at=utc_now_naive())
    assert (await admin_client.post(f"/admin/tasks/{row.id}/retry", follow_redirects=False)).status_code == 400


# ── Recover ───────────────────────────────────────────────────────────────────


async def test_recover_closes_a_row_whose_worker_stopped_reporting(admin_client, async_db):
    """Before `heartbeat_at`, nothing could tell a long backfill apart from a dead one."""
    stale = await _make(async_db, status=BackgroundTaskStatus.RUNNING, heartbeat_at=utc_now_naive() - timedelta(hours=3))
    resp = await admin_client.post("/admin/tasks/recover", follow_redirects=False)
    assert resp.status_code == 303

    await async_db.refresh(stale)
    assert stale.status == BackgroundTaskStatus.FAILED
    assert "Worker lost" in stale.error_message


async def test_recover_leaves_a_live_task_alone(admin_client, async_db):
    live = await _make(async_db, status=BackgroundTaskStatus.RUNNING, heartbeat_at=utc_now_naive())
    await admin_client.post("/admin/tasks/recover", follow_redirects=False)
    await async_db.refresh(live)
    assert live.status == BackgroundTaskStatus.RUNNING


async def test_a_pending_row_is_judged_by_age_not_heartbeat(async_db):
    """Nothing beats for a task nobody has picked up, so the queue expiry is the bound."""
    from app.config import settings
    from app.routers.admin import _bg_task_is_stalled

    fresh = BackgroundTask(name="x", kind="backfill_similarity", status=BackgroundTaskStatus.PENDING, created_at=utc_now_naive())
    old = BackgroundTask(
        name="x",
        kind="backfill_similarity",
        status=BackgroundTaskStatus.PENDING,
        created_at=utc_now_naive() - timedelta(seconds=settings.huey_queue_expiry + 3600),
    )
    assert not _bg_task_is_stalled(fresh)
    assert _bg_task_is_stalled(old)


def test_a_terminal_row_is_never_stalled():
    from app.routers.admin import _bg_task_is_stalled

    for status in (BackgroundTaskStatus.COMPLETED, BackgroundTaskStatus.FAILED, BackgroundTaskStatus.CANCELLED):
        row = BackgroundTask(name="x", status=status, finished_at=utc_now_naive() - timedelta(days=30))
        assert not _bg_task_is_stalled(row)


# ── The page ──────────────────────────────────────────────────────────────────


async def test_the_tasks_page_renders_all_three_panes(admin_client):
    resp = await admin_client.get("/admin/tasks")
    assert resp.status_code == 200
    for marker in ("Running now", "Waiting for a worker", "Recurring tasks"):
        assert marker in resp.text


async def test_the_scheduled_pane_lists_every_periodic_task(admin_client):
    from app import task_registry as tr

    resp = await admin_client.get("/admin/tasks")
    for key in tr.PERIODIC:
        assert key in resp.text, f"{key} missing from the Scheduled pane"


async def test_the_poll_stops_when_nothing_is_active(admin_client):
    """The `_job_status.html` rule. Inverted, every admin with the page open polls a
    perfectly idle instance every five seconds, forever."""
    resp = await admin_client.get("/admin/tasks")
    assert 'hx-trigger="every 5s"' not in resp.text


async def test_the_poll_region_morphs(admin_client):
    """`morph:outerHTML` is not recognised by the extension, falls through to innerHTML,
    and rebuilds every child on each poll."""
    resp = await admin_client.get("/admin/tasks")
    assert 'hx-swap="morph"' in resp.text
    assert "morph:outerHTML" not in resp.text
    assert 'hx-ext="alpine-morph"' in resp.text


# ── The worker side ───────────────────────────────────────────────────────────


def test_every_cancellable_backfill_checks_the_flag_at_its_batch_boundary():
    """A `_CancelWatcher`-style thread exists to interrupt a *subprocess*; a backfill's
    loop body is a DB batch, and the commit at the end of it is already the consistent
    point to stop at. This asserts each one actually does the check."""
    import inspect

    from app import task_registry as tr
    from app.workers import tasks as worker_tasks

    for key in sorted(tr.CANCELLABLE):
        fn = getattr(worker_tasks, key, None)
        source = inspect.getsource(getattr(fn, "func", fn))
        assert "_bg_cancel_requested(bg_task_id)" in source, f"{key} never checks for cancellation"


def test_backfill_entities_rebuilds_counts_on_the_cancel_path():
    """It is one statement, and skipping it leaves `Entity.job_count` inconsistent with
    `entity_job_link` on the dashboard — a stopped backfill should not leave wrong numbers."""
    import inspect

    from app.workers import tasks as worker_tasks

    source = inspect.getsource(worker_tasks.backfill_entities.func)
    rebuild_at = source.index("rebuild_entity_job_counts(db)")
    cancel_finalise_at = source.index("_finish_cancelled(")
    assert rebuild_at < cancel_finalise_at, "the counts must be rebuilt before the cancel is finalised"


def test_a_cancelled_backfill_clears_its_own_flag(fake_redis):
    """Left behind, the flag would immediately cancel the retry."""
    from app.models import BackgroundTask, BackgroundTaskStatus
    from app.redis_client import BGTASK_CANCEL_PREFIX
    from app.workers import tasks as worker_tasks

    class _Session:
        is_active = True
        row = BackgroundTask(id=1, name="x", status=BackgroundTaskStatus.RUNNING)

        def get(self, _model, _pk):
            return self.row

        def commit(self):
            pass

        def rollback(self):
            pass

    fake_redis.set(f"{BGTASK_CANCEL_PREFIX}1", "someone")
    worker_tasks._finish_cancelled(_Session(), 1, "stopped")
    assert not fake_redis.exists(f"{BGTASK_CANCEL_PREFIX}1")
    assert _Session.row.status == BackgroundTaskStatus.CANCELLED


def test_every_periodic_task_records_its_last_run():
    """A prune that silently stopped running looks identical to one with nothing to do."""
    import inspect

    from app import task_registry as tr
    from app.workers import tasks as worker_tasks

    for key in tr.PERIODIC:
        fn = getattr(worker_tasks, key, None)
        assert fn is not None, f"{key} is registered but not defined"
        source = inspect.getsource(getattr(fn, "func", fn))
        assert f'_ScheduledRun("{key}")' in source, f"{key} does not record when it ran"


# ── Where the backfills commit ────────────────────────────────────────────────

#: Backfills whose loop body is expensive — a raw-output parse, a TLSH digest over a whole
#: upload. These must commit per item. `backfill_entity_attributes` is row-wise arithmetic
#: and deliberately absent.
_PER_ITEM_COMMIT = (
    "backfill_similarity",
    "backfill_analytics",
    "backfill_entities",
    "backfill_relationships",
    "backfill_finding_entity_links",
)


@pytest.mark.parametrize("key", _PER_ITEM_COMMIT)
def test_expensive_backfills_commit_per_item_not_per_batch(key):
    """SQLite has one writer, and these hold it for as long as their transaction is open.

    Committing at the batch boundary holds the lock across every parse in the batch —
    measured at 80 seconds for nine EVTX jobs with `BATCH = 100`, during which every write
    in the web tier timed out and returned a 500. The batch is the query
    window; it is not the transaction.

    Asserted against the AST rather than a substring, because the whole distinction is
    *where* the call sits: the wrong shape has `db.commit()` in the `while` body, one
    indent out from the `for` that does the work, and no string test can tell those apart.
    """
    import ast
    import inspect

    from app.workers import tasks as worker_tasks

    fn = getattr(worker_tasks, key)
    tree = ast.parse(inspect.getsource(getattr(fn, "func", fn)))

    def commits(node) -> bool:
        return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "commit" for n in ast.walk(node))

    assert any(commits(loop) for loop in ast.walk(tree) if isinstance(loop, ast.For)), f"{key} never commits inside its per-item loop — the write lock is held for the whole batch"


# ── Queueing the same maintenance task twice ──────────────────────────────────


def _stub_task(name: str):
    """A stand-in for a Huey `TaskWrapper` that still answers `.func.__name__`.

    A bare lambda does not, and `_queue_background_task` reads exactly that to decide the
    row's `kind` — so patching one in makes `kind` None, which disables the duplicate guard
    and lets the test pass for the wrong reason.
    """

    def _enqueue(*_a, **_k):
        return None

    inner = lambda *_a, **_k: None  # noqa: E731 — needs a rebindable __name__
    inner.__name__ = name
    _enqueue.func = inner
    return _enqueue


async def test_queueing_a_backfill_that_is_already_running_does_not_start_a_second(admin_client, async_db, monkeypatch):
    """Two copies re-read the same raw output and re-write the same rows, and the Run
    button gives no sign the first click landed — so it invites exactly that."""
    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "backfill_similarity", _stub_task("backfill_similarity"))

    running = await _make(async_db, status=BackgroundTaskStatus.RUNNING, started_at=utc_now_naive(), heartbeat_at=utc_now_naive())

    resp = await admin_client.post("/admin/backfill-similarity", headers={"hx-request": "true"})
    assert resp.status_code == 200
    assert "Already running" in resp.text

    rows = (await async_db.execute(select(BackgroundTask))).scalars().all()
    assert [r.id for r in rows] == [running.id]


async def test_a_stalled_row_does_not_wedge_the_button(admin_client, async_db, monkeypatch):
    """A row whose worker died sits at `running` forever. Treating that as in flight would
    make Run permanently inert — and clicking it again is the recovery an admin expects."""
    from app.routers.admin import BG_TASK_STALE_SECONDS
    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "backfill_similarity", _stub_task("backfill_similarity"))

    dead = utc_now_naive() - timedelta(seconds=BG_TASK_STALE_SECONDS + 60)
    await _make(async_db, status=BackgroundTaskStatus.RUNNING, started_at=dead, heartbeat_at=dead)

    resp = await admin_client.post("/admin/backfill-similarity", headers={"hx-request": "true"})
    assert resp.status_code == 200

    rows = (await async_db.execute(select(BackgroundTask))).scalars().all()
    assert len(rows) == 2


async def test_a_task_the_queue_refuses_is_failed_not_left_pending(admin_client, async_db, monkeypatch):
    """The row is committed before the enqueue. When Redis refused the task, the route 500'd
    and the PENDING row stayed — so the next click, with Redis back, was told "Already
    queued" about a task nothing would ever run, for half an hour."""
    from app.workers import tasks as worker_tasks

    def _unreachable(*a, **k):
        raise ConnectionError("Error 111 connecting to localhost:6379")

    monkeypatch.setattr(worker_tasks, "backfill_similarity", _unreachable)
    resp = await admin_client.post("/admin/backfill-similarity", headers={"hx-request": "true"})
    assert resp.status_code == 200
    assert "Could not be queued" in resp.text

    row = (await async_db.execute(select(BackgroundTask))).scalars().one()
    assert row.status == BackgroundTaskStatus.FAILED

    monkeypatch.setattr(worker_tasks, "backfill_similarity", _stub_task("backfill_similarity"))
    again = await admin_client.post("/admin/backfill-similarity", headers={"hx-request": "true"})
    assert "Already" not in again.text
    assert len((await async_db.execute(select(BackgroundTask))).scalars().all()) == 2


async def test_retry_does_not_start_a_second_copy_of_a_task_already_running(admin_client, async_db, monkeypatch):
    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "backfill_similarity", lambda *a, **k: None)
    await _make(async_db, status=BackgroundTaskStatus.RUNNING, started_at=utc_now_naive(), heartbeat_at=utc_now_naive())
    failed = await _make(async_db, status=BackgroundTaskStatus.FAILED, finished_at=utc_now_naive())

    resp = await admin_client.post(f"/admin/tasks/{failed.id}/retry", follow_redirects=False)
    assert resp.status_code == 400
    assert len((await async_db.execute(select(BackgroundTask))).scalars().all()) == 2


async def test_a_busy_database_returns_the_chip_not_a_500(admin_client, async_db, monkeypatch):
    """A stack trace where a status chip belongs is the worst possible answer to a button
    an admin is allowed to press again."""
    from sqlalchemy.exc import OperationalError

    from app.workers import tasks as worker_tasks

    monkeypatch.setattr(worker_tasks, "backfill_similarity", _stub_task("backfill_similarity"))

    real_commit = type(async_db).commit
    calls = {"n": 0}

    async def _boom(self):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OperationalError("INSERT", {}, Exception("database is locked"))
        return await real_commit(self)

    monkeypatch.setattr(type(async_db), "commit", _boom)

    resp = await admin_client.post("/admin/backfill-similarity", headers={"hx-request": "true"})
    assert resp.status_code == 200
    assert "Database busy" in resp.text


async def test_a_cancelled_run_reads_as_cancelled_on_the_maintenance_chip(admin_client, async_db):
    """Every status that was not pending, running or completed fell into the red "Failed"
    branch, so a run an admin stopped on purpose was reported as broken."""
    row = await _make(async_db, status=BackgroundTaskStatus.CANCELLED, detail="cancelled after 12 jobs", finished_at=utc_now_naive())
    body = (await admin_client.get(f"/admin/background-tasks/{row.id}/status-partial")).text
    assert "Cancelled" in body
    assert "Failed" not in body
    assert "every 3s" not in body, "a cancelled run is terminal"
