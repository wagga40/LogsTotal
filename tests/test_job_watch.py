"""Watching a job.

A subscription, not a query — which is why it is a pair of new tables rather than a
widening of `intel_rule_match`. The things worth pinning are the ones a demo would not
show:

* **idempotency.** The unique constraint is the guarantee; a retried Huey task or a
  double-submitted form must not raise the same alert twice.
* **the self-notification asymmetry.** A comment and a tag are the synchronous consequence
  of your own click; an AI run finishing is not. One function decides, so the reasoning has
  somewhere to live.
* **visibility.** A watcher who can no longer see the job hears nothing — the event would
  link to a 404 and would itself leak that the job exists.
* **the ack asymmetry.** Admins see every watch *rule*, but only their own *watches*. The
  generous version would let one admin's "Acknowledge all" empty every colleague's bell.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app import job_watch
from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import AnalysisJob, JobStatus, JobWatch, JobWatchEvent, LogFile, User, WorkflowDef

pytestmark = pytest.mark.anyio


async def _user(async_db, *, email: str, role: str = "member", superuser: bool = False) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    return await UserManager(user_db).create(UserCreate(email=email, password="pass123456", is_superuser=superuser, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"})
    assert resp.status_code in (200, 204)


@pytest.fixture()
async def data(async_db):
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    await async_db.commit()

    alice = await _user(async_db, email="alice@jw.example.com")
    bob = await _user(async_db, email="bob@jw.example.com")
    basic = await _user(async_db, email="basic@jw.example.com", role="user")
    admin = await _user(async_db, email="admin@jw.example.com", role="admin", superuser=True)

    job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    private = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=bob.id)
    async_db.add_all([job, private])
    await async_db.commit()
    for obj in (job, private, alice, bob, basic, admin):
        await async_db.refresh(obj)
    return {"job": job, "private": private, "alice": alice, "bob": bob, "basic": basic, "admin": admin}


# ── Tier 1: should_notify ────────────────────────────────────────────────────


class TestShouldNotify:
    def test_you_do_not_hear_about_your_own_comment_or_tag(self):
        """Badge noise is how people learn to ignore a bell."""
        assert job_watch.should_notify("comment", "u1", "u1") is False
        assert job_watch.should_notify("tag", "u1", "u1") is False

    def test_you_do_hear_about_someone_elses(self):
        assert job_watch.should_notify("comment", "u1", "u2") is True
        assert job_watch.should_notify("tag", "u1", "u2") is True

    def test_you_do_hear_about_your_own_ai_run(self):
        """The one exception, and the reason it is one: the pane polls only while the page
        is open, so "it finished" is genuinely news to the person who started it."""
        assert job_watch.should_notify("ai", "u1", "u1") is True

    def test_an_unattributed_event_reaches_everyone(self):
        assert job_watch.should_notify("comment", "u1", None) is True


# ── The recorder ─────────────────────────────────────────────────────────────


async def test_recording_is_idempotent(async_db, data):
    """The unique constraint is the guarantee. A retried task must not raise twice."""
    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()

    for _ in range(3):
        await job_watch.record_events_async(async_db, kind="comment", job_id=data["job"].id, ref_id=42, actor_user_id=data["bob"].id)
        await async_db.commit()

    rows = (await async_db.execute(select(JobWatchEvent))).scalars().all()
    assert len(rows) == 1


async def test_a_watcher_who_cannot_see_the_job_hears_nothing(async_db, data):
    """The event would link to a 404, and would itself leak that the job exists."""
    await job_watch.ensure_watch_async(async_db, data["private"].id, data["alice"].id)
    await async_db.commit()

    await job_watch.record_events_async(async_db, kind="comment", job_id=data["private"].id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    assert (await async_db.execute(select(JobWatchEvent))).scalars().all() == []


async def test_the_owner_of_a_private_job_still_hears(async_db, data):
    await job_watch.ensure_watch_async(async_db, data["private"].id, data["bob"].id)
    await async_db.commit()

    await job_watch.record_events_async(async_db, kind="comment", job_id=data["private"].id, ref_id=1, actor_user_id=data["alice"].id)
    await async_db.commit()

    assert len((await async_db.execute(select(JobWatchEvent))).scalars().all()) == 1


async def test_an_unknown_kind_is_dropped_rather_than_stored(async_db, data):
    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()

    assert await job_watch.record_events_async(async_db, kind="nonsense", job_id=data["job"].id, ref_id=1) == []


async def test_a_missing_job_is_not_an_error(async_db, data):
    """It never raises — a failed notification must not fail the thing it describes."""
    assert await job_watch.record_events_async(async_db, kind="comment", job_id=999999, ref_id=1) == []


async def test_unwatching_takes_its_notifications_with_it(async_db, data):
    """Leaving them would keep the badge non-zero over a dropdown that shows nothing."""
    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()
    await job_watch.record_events_async(async_db, kind="comment", job_id=data["job"].id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    await job_watch.remove_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()

    assert (await async_db.execute(select(JobWatchEvent))).scalars().all() == []
    assert (await async_db.execute(select(JobWatch))).scalars().all() == []


# ── The toggle ───────────────────────────────────────────────────────────────


async def test_toggle_subscribes_then_unsubscribes(test_client, async_db, data):
    await _login(test_client, "alice@jw.example.com")
    job_id = data["job"].id

    body = (await test_client.post(f"/jobs/{job_id}/watch")).text
    assert "Watching" in body
    assert len((await async_db.execute(select(JobWatch))).scalars().all()) == 1

    body = (await test_client.post(f"/jobs/{job_id}/watch")).text
    assert "Watching" not in body
    assert (await async_db.execute(select(JobWatch))).scalars().all() == []


async def test_the_watch_cap_is_said_out_loud(test_client, async_db, data, monkeypatch):
    """At the cap the button swapped back to "Watch" with no word, and the audit log recorded
    "no longer watching" for a job that was never watched."""
    from app.models import ActivityEvent, SiteSettings

    monkeypatch.setattr(job_watch, "JOB_WATCH_MAX_PER_USER", 0)
    row = await async_db.get(SiteSettings, 1) or SiteSettings(id=1)
    row.activity_log_enabled = True
    async_db.add(row)
    await async_db.commit()

    await _login(test_client, "alice@jw.example.com")
    resp = await test_client.post(f"/jobs/{data['job'].id}/watch")
    assert resp.status_code == 200
    assert "limit" in resp.text.lower()
    assert (await async_db.execute(select(JobWatch))).scalars().all() == []
    summaries = (await async_db.execute(select(ActivityEvent.summary).where(ActivityEvent.action == "job.watch"))).scalars().all()
    assert "no longer watching" not in summaries


async def test_a_plain_user_may_watch(test_client, async_db, data):
    """Mirrors commenting: a job thread is open to any logged-in viewer, and a watch is the
    notification half of the same act."""
    await _login(test_client, "basic@jw.example.com")
    resp = await test_client.post(f"/jobs/{data['job'].id}/watch")
    assert resp.status_code == 200
    assert len((await async_db.execute(select(JobWatch))).scalars().all()) == 1


async def test_anonymous_cannot_watch(test_client, async_db, data):
    resp = await test_client.post(f"/jobs/{data['job'].id}/watch")
    assert resp.status_code in (401, 403)
    assert (await async_db.execute(select(JobWatch))).scalars().all() == []


async def test_watching_an_invisible_job_is_a_404(test_client, async_db, data):
    await _login(test_client, "alice@jw.example.com")
    assert (await test_client.post(f"/jobs/{data['private'].id}/watch")).status_code == 404
    assert (await test_client.post("/jobs/999999/watch")).status_code == 404


# ── The comment trigger, and auto-watch ──────────────────────────────────────


async def test_commenting_subscribes_you_and_notifies_the_others(test_client, async_db, data):
    """Auto-watch is what makes a discussion a discussion: without it the second person's
    reply is never seen by the first."""
    job_id = data["job"].id

    await _login(test_client, "alice@jw.example.com")
    await test_client.post(f"/comments/job/{job_id}", data={"body": "starting a thread"})

    watches = (await async_db.execute(select(JobWatch))).scalars().all()
    assert [w.user_id for w in watches] == [data["alice"].id]
    # ...and she is not told about her own comment.
    assert (await async_db.execute(select(JobWatchEvent))).scalars().all() == []

    await _login(test_client, "bob@jw.example.com")
    await test_client.post(f"/comments/job/{job_id}", data={"body": "replying"})

    events = (await async_db.execute(select(JobWatchEvent))).scalars().all()
    assert len(events) == 1, "alice hears about bob's reply"
    assert events[0].kind == "comment"


async def test_commenting_on_a_case_does_not_create_a_job_watch(test_client, async_db, data):
    """The hook is job-only; entity and case threads have no subscription concept."""
    await _login(test_client, "alice@jw.example.com")
    await test_client.post(f"/comments/job/{data['job'].id}", data={"body": "x"})
    before = len((await async_db.execute(select(JobWatch))).scalars().all())

    await test_client.post("/comments/entity/999999", data={"body": "y"})
    assert len((await async_db.execute(select(JobWatch))).scalars().all()) == before


# ── The tag trigger ──────────────────────────────────────────────────────────


async def test_tagging_notifies_watchers_but_not_the_tagger(test_client, async_db, data):
    job_id = data["job"].id
    await job_watch.ensure_watch_async(async_db, job_id, data["alice"].id)
    await job_watch.ensure_watch_async(async_db, job_id, data["bob"].id)
    await async_db.commit()

    await _login(test_client, "bob@jw.example.com")
    await test_client.post(f"/jobs/{job_id}/tags", data={"tag": "apt29"})

    events = (await async_db.execute(select(JobWatchEvent))).scalars().all()
    assert len(events) == 1
    assert events[0].kind == "tag"


async def test_a_watcher_below_member_is_not_told_a_tag_name(test_client, async_db, data):
    """Tags are member-only: the job page withholds them from `role=user`, so the bell must
    not read one out to them either."""
    job_id = data["job"].id
    await job_watch.ensure_watch_async(async_db, job_id, data["basic"].id)
    await job_watch.ensure_watch_async(async_db, job_id, data["alice"].id)
    await async_db.commit()

    await _login(test_client, "bob@jw.example.com")
    await test_client.post(f"/jobs/{job_id}/tags", data={"tag": "insider-suspect"})

    notified = (await async_db.execute(select(JobWatch.user_id).join(JobWatchEvent, JobWatchEvent.watch_id == JobWatch.id))).scalars().all()
    assert notified == [data["alice"].id]


async def test_bulk_tagging_never_notifies(test_client, async_db, data):
    """BULK_TAG_CAP jobs x MAX_WATCHERS_FANOUT watchers is a 50,000-row fan-out from one
    click. Same reasoning as the activity log's one-row-with-a-count rule."""
    job_id = data["job"].id
    await job_watch.ensure_watch_async(async_db, job_id, data["alice"].id)
    await async_db.commit()

    await _login(test_client, "bob@jw.example.com")
    await test_client.post("/jobs/bulk-tag", data={"job_ids": str(job_id), "tag": "sweep"})

    assert (await async_db.execute(select(JobWatchEvent))).scalars().all() == []


# ── The bell ─────────────────────────────────────────────────────────────────


async def test_the_bell_counts_both_streams(test_client, async_db, data):
    from app import notifications

    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()
    await job_watch.record_events_async(async_db, kind="comment", job_id=data["job"].id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    assert await notifications.unacked_total(async_db, data["alice"]) == 1

    await _login(test_client, "alice@jw.example.com")
    assert (await test_client.get("/intel/watchlist-events-partial?count_only=1")).text == "1"


async def test_a_plain_user_can_read_the_bell(test_client, async_db, data):
    """Relaxed from member+ because job-watch events belong to anyone who can view a job.
    It exposes nothing new on the rule side: a non-member owns no rule."""
    await _login(test_client, "basic@jw.example.com")
    resp = await test_client.get("/intel/watchlist-events-partial?count_only=1")
    assert resp.status_code == 200
    assert resp.text == "0"


async def test_acknowledging_one_event(test_client, async_db, data):
    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()
    ids = await job_watch.record_events_async(async_db, kind="comment", job_id=data["job"].id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    await _login(test_client, "alice@jw.example.com")
    resp = await test_client.post(f"/jobs/watch-events/{ids[0]}/ack")

    assert resp.status_code == 200
    row = (await async_db.execute(select(JobWatchEvent).where(JobWatchEvent.id == ids[0]))).scalar_one()
    assert row.acknowledged_at is not None


async def test_acknowledging_someone_elses_event_is_a_404(test_client, async_db, data):
    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()
    ids = await job_watch.record_events_async(async_db, kind="comment", job_id=data["job"].id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    await _login(test_client, "bob@jw.example.com")
    assert (await test_client.post(f"/jobs/watch-events/{ids[0]}/ack")).status_code == 404

    row = (await async_db.execute(select(JobWatchEvent).where(JobWatchEvent.id == ids[0]))).scalar_one()
    assert row.acknowledged_at is None


async def test_an_admin_ack_all_does_not_clear_everyone_elses_bell(test_client, async_db, data):
    """The asymmetry with watch rules, and the reason it exists. `_visible_rules` gives an
    admin every rule; the watch half must stay own-only or one click empties the instance."""
    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()
    await job_watch.record_events_async(async_db, kind="comment", job_id=data["job"].id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    await _login(test_client, "admin@jw.example.com")
    await test_client.post("/intel/watchlist-events/ack-all")

    rows = (await async_db.execute(select(JobWatchEvent))).scalars().all()
    assert rows[0].acknowledged_at is None, "alice's notification survives the admin's click"


async def test_the_watch_pages_ack_all_leaves_job_events_alone(test_client, async_db, data):
    """It never displayed a job event, so it must not silently discard one."""
    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()
    await job_watch.record_events_async(async_db, kind="comment", job_id=data["job"].id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    await _login(test_client, "alice@jw.example.com")
    await test_client.post("/intel/rules/alerts/ack-all")

    rows = (await async_db.execute(select(JobWatchEvent))).scalars().all()
    assert rows[0].acknowledged_at is None


async def test_the_bells_ack_all_clears_them(test_client, async_db, data):
    await job_watch.ensure_watch_async(async_db, data["job"].id, data["alice"].id)
    await async_db.commit()
    await job_watch.record_events_async(async_db, kind="comment", job_id=data["job"].id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    await _login(test_client, "alice@jw.example.com")
    await test_client.post("/intel/watchlist-events/ack-all")

    rows = (await async_db.execute(select(JobWatchEvent))).scalars().all()
    assert rows[0].acknowledged_at is not None


# ── Cleanup ──────────────────────────────────────────────────────────────────


async def test_deleting_a_job_removes_its_watches_and_events(test_client, async_db, data):
    job_id = data["job"].id
    await job_watch.ensure_watch_async(async_db, job_id, data["alice"].id)
    await async_db.commit()
    await job_watch.record_events_async(async_db, kind="comment", job_id=job_id, ref_id=1, actor_user_id=data["bob"].id)
    await async_db.commit()

    await _login(test_client, "admin@jw.example.com")
    assert (await test_client.post(f"/jobs/{job_id}/delete", follow_redirects=False)).status_code in (200, 303)

    assert (await async_db.execute(select(JobWatch))).scalars().all() == []
    assert (await async_db.execute(select(JobWatchEvent))).scalars().all() == []


# ── The AI trigger (worker side) ─────────────────────────────────────────────


class TestTheAiTrigger:
    """Two call sites, not three. `_finish` covers every terminal exit including
    cancel-before-start (which routes through it); the separate one is the outer
    unexpected-exception branch, which writes FAILED directly and never reaches it."""

    @staticmethod
    def _sync_setup(job_id: int, user_id):
        """A sync session with a watch already in place, mirroring the worker's world."""
        from app.database import get_sync_session
        from app.models import JobWatch as _Watch

        db = get_sync_session()
        db.add(_Watch(job_id=job_id, user_id=user_id))
        db.commit()
        return db

    async def test_completed_and_failed_notify_but_cancelled_does_not(self, async_db, data):
        """A cancel is a deliberate act by the only person who would be told about it."""
        from types import SimpleNamespace

        from app.models import AiAnalysisStatus
        from app.workers import tasks

        seen = []

        class _FakeWatch:
            @staticmethod
            def record_events_sync(_db, **kw):
                seen.append(kw["kind"])
                return [1]

        import app.job_watch as real

        original = real.record_events_sync
        real.record_events_sync = _FakeWatch.record_events_sync
        try:
            db = SimpleNamespace(commit=lambda: None, rollback=lambda: None)
            for status, expected in (
                (AiAnalysisStatus.COMPLETED, 1),
                (AiAnalysisStatus.FAILED, 1),
                (AiAnalysisStatus.CANCELLED, 0),
            ):
                seen.clear()
                row = SimpleNamespace(id=1, job_id=data["job"].id, status=status, provider_name="Ollama")
                tasks._notify_job_watchers_of_ai(db, row)
                assert len(seen) == expected, f"{status} should have produced {expected} event(s)"
        finally:
            real.record_events_sync = original

    async def test_a_notification_failure_never_undoes_the_run(self, data):
        """The analysis row is already terminal; a bell that could not be written must not
        take the result with it."""
        from types import SimpleNamespace

        from app.models import AiAnalysisStatus
        from app.workers import tasks

        rolled_back = []
        db = SimpleNamespace(commit=lambda: (_ for _ in ()).throw(RuntimeError("boom")), rollback=lambda: rolled_back.append(1))
        row = SimpleNamespace(id=1, job_id=data["job"].id, status=AiAnalysisStatus.COMPLETED, provider_name="Ollama")

        tasks._notify_job_watchers_of_ai(db, row)  # must not raise

        assert rolled_back == [1]


# ── The optional webhook ─────────────────────────────────────────────────────


class TestTheWebhookPayload:
    """Tier 1. A job-watch delivery rides an existing rule's webhook — its URL, its secret,
    its rate limit, its retry backoff — so the only new surface is the payload shape."""

    @staticmethod
    def _rule():
        from types import SimpleNamespace

        return SimpleNamespace(id=9, name="my deliveries")

    @staticmethod
    def _event(kind="comment", ref=1):
        from datetime import datetime
        from types import SimpleNamespace

        return SimpleNamespace(kind=kind, ref_id=ref, summary="alice commented", created_at=datetime(2026, 8, 16, 12, 0))

    def test_the_event_field_is_the_discriminator(self):
        from app.intel.webhooks import build_job_watch_payload

        payload = build_job_watch_payload(self._rule(), None, [self._event()])
        assert payload["event"] == "job.watch"

    def test_entities_is_present_and_empty(self):
        """A receiver written against rule.match very likely indexes payload["entities"].
        A KeyError there would turn a new feature into an outage in somebody else's script."""
        from app.intel.webhooks import build_job_watch_payload

        payload = build_job_watch_payload(self._rule(), None, [self._event()])
        assert payload["entities"] == []

    def test_the_events_carry_kind_and_summary(self):
        from app.intel.webhooks import build_job_watch_payload

        payload = build_job_watch_payload(self._rule(), None, [self._event(kind="ai", ref=4)])
        assert payload["events"] == [{"kind": "ai", "ref_id": 4, "summary": "alice commented", "at": "2026-08-16T12:00:00Z"}]

    def test_it_truncates_like_its_sibling(self):
        from app.intel.webhooks import WEBHOOK_MAX_ENTITIES, build_job_watch_payload

        events = [self._event(ref=i) for i in range(WEBHOOK_MAX_ENTITIES + 10)]
        payload = build_job_watch_payload(self._rule(), None, events)
        assert payload["truncated"] is True
        assert len(payload["events"]) == WEBHOOK_MAX_ENTITIES

    def test_the_event_header_follows_the_payload(self):
        """A receiver routing on X-LogsTotal-Event must not be told the two are the same."""
        from app.intel.webhooks import delivery_headers

        assert delivery_headers(1, "0", None)["X-LogsTotal-Event"] == "rule.match", "the default is unchanged"
        assert delivery_headers(1, "0", None, event="job.watch")["X-LogsTotal-Event"] == "job.watch"

    def test_a_rule_owner_cannot_spoof_the_event_header(self):
        from app.intel.webhooks import delivery_headers

        headers = delivery_headers(1, "0", None, {"X-LogsTotal-Event": "rule.match"}, event="job.watch")
        assert headers["X-LogsTotal-Event"] == "job.watch"


async def test_at_most_one_rule_per_owner_carries_job_watch_events(test_client, async_db, data):
    """Two would mean the same event delivered twice, which reads as a retry storm."""
    from app.models import IntelRule

    await _login(test_client, "alice@jw.example.com")
    for name in ("first", "second"):
        await test_client.post(
            "/intel/rules",
            data={
                "name": name,
                "query": "type:user",
                "webhook_url": "https://example.com/hook",
                "webhook_enabled": "1",
                "notify_job_watch": "1",
            },
        )

    rules = (await async_db.execute(select(IntelRule).where(IntelRule.owner_user_id == data["alice"].id))).scalars().all()
    assert len(rules) == 2
    assert sum(1 for r in rules if r.notify_job_watch) == 1, "the newer one wins; the older is cleared"


async def test_no_webhook_is_queued_without_an_opted_in_rule(async_db, data):
    """The normal case: a watch has no webhook configuration of its own, so nothing goes
    out unless the owner deliberately pointed a rule at it."""
    assert await job_watch.webhook_rule_id_for(async_db, data["alice"].id) is None


async def test_a_deactivated_owners_rule_no_longer_carries_job_watch_events(async_db, data):
    from app.models import IntelRule

    async_db.add(
        IntelRule(
            name="fwd",
            owner_user_id=data["alice"].id,
            query="",
            entity_types="[]",
            webhook_enabled=True,
            webhook_url="https://hooks.example/x",
            notify_job_watch=True,
        )
    )
    await async_db.commit()
    assert await job_watch.webhook_rule_id_for(async_db, data["alice"].id) is not None, "precondition"

    data["alice"].is_active = False
    await async_db.commit()
    assert await job_watch.webhook_rule_id_for(async_db, data["alice"].id) is None


class TestTheWatchingTabCountsWhatItNames:
    """The badge said how many *unread events* you had, on a tab called Watching.

    That number goes to zero the moment you read the pane, so someone watching twelve jobs
    saw a bare tab — while the count they asked for was nowhere on the page. Unread events
    keep their own home in the nav bell, which is where a notification belongs.
    """

    async def test_the_badge_is_the_number_of_watched_jobs(self, async_db, test_client, data):
        from app.job_watch import watched_count
        from app.routers.jobs import _build_jobs_page_tabs

        # Bob, because he owns the private job and can therefore watch both.
        await _login(test_client, data["bob"].email)
        for job in (data["job"], data["private"]):
            assert (await test_client.post(f"/jobs/{job.id}/watch")).status_code == 200

        assert await watched_count(async_db, data["bob"]) == 2
        tabs = _build_jobs_page_tabs(data["bob"], watched=2)
        assert [t["badge"] for t in tabs if t["key"] == "watching"] == [2]

    async def test_it_survives_reading_the_pane(self, async_db, test_client, data):
        """A badge that drops to nothing here looks broken."""
        from app.job_watch import watched_count

        await _login(test_client, data["alice"].email)
        await test_client.post(f"/jobs/{data['job'].id}/watch")
        await test_client.post("/jobs/watch-events/ack-all")
        assert await watched_count(async_db, data["alice"]) == 1

    async def test_the_pane_swaps_the_same_number_back_into_the_badge(self, test_client, data):
        """The pane replaces the badge out-of-band after Stop watching. Sending the unread
        count here is how the badge would mean two things depending on whether you had
        opened the tab."""
        await _login(test_client, data["alice"].email)
        await test_client.post(f"/jobs/{data['job'].id}/watch")
        body = (await test_client.get("/jobs/watching", headers={"HX-Request": "true"})).text
        assert 'id="tab-badge-watching"' in body
        assert ">1<" in body

    async def test_nothing_is_watched_means_no_badge(self, test_client, data):
        from app.routers.jobs import _build_jobs_page_tabs

        tabs = _build_jobs_page_tabs(data["alice"], watched=0)
        assert [t["badge"] for t in tabs if t["key"] == "watching"] == [None]
