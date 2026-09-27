"""Per-user watch rules: matching, idempotency, and the cross-user disclosure control.

The most important test in this file is
`test_a_rule_does_not_fire_on_a_job_its_owner_cannot_see`. Without that check a member
writes one broad rule and every private job's entity values are pushed to their own
webhook. That is a larger risk than the accepted SSRF trade-off and — crucially — the SSRF
controls do nothing about it, because the request is perfectly well-formed. It can only be
stopped where the rule is evaluated.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

import app.models  # noqa: F401 — populate Base.metadata
from app.intel.rules import MAX_MATCHES_PER_RULE, evaluate_rules_for_job
from app.json_utils import dumps as json_dumps
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    EntityTag,
    IntelRule,
    IntelRuleMatch,
    JobStatus,
    LogFile,
    LogType,
    User,
    WorkflowDef,
)


def _user(db, email, *, is_superuser=False):
    u = User(id=uuid.uuid4(), email=email, hashed_password="x", is_active=True, is_superuser=is_superuser, role="member")
    db.add(u)
    db.flush()
    return u


def _job(db, *, owner=None, private=False):
    wf = db.execute(select(WorkflowDef)).scalars().first()
    if wf is None:
        wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
        db.add(wf)
        db.flush()
    lf = LogFile(original_filename="x.evtx", stored_filename=f"{uuid.uuid4()}.evtx", sha256=uuid.uuid4().hex * 2, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    db.add(lf)
    db.flush()
    j = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, is_private=private, submitted_by_user_id=(owner.id if owner else None))
    db.add(j)
    db.flush()
    return j


def _entity(db, job, value, etype="executable", attrs=None):
    e = Entity(value=value, entity_type=etype, job_count=1, attributes_json=json_dumps(attrs) if attrs else None)
    db.add(e)
    db.flush()
    db.add(EntityJobLink(entity_id=e.id, job_id=job.id, occurrence_count=1))
    db.flush()
    return e


def _rule(db, owner, **kw):
    r = IntelRule(name=kw.pop("name", "R"), owner_user_id=(owner.id if owner else None), query=kw.pop("query", ""), entity_types=kw.pop("entity_types", "[]"), **kw)
    db.add(r)
    db.flush()
    return r


def _matches(db, rule_id):
    return db.execute(select(IntelRuleMatch).where(IntelRuleMatch.rule_id == rule_id)).scalars().all()


class TestMatching:
    def test_a_rule_matches_entities_in_the_job(self, sync_db):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True, "is_gtfobin": False})
        _entity(sync_db, job, "custom.exe", attrs={"is_lolbin": False, "is_gtfobin": False})
        r = _rule(sync_db, u, query="label:lolbin")
        sync_db.commit()

        res = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert res.matches_created == 1
        assert len(_matches(sync_db, r.id)) == 1

    def test_entity_type_scoping(self, sync_db):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "evil.com", etype="domain")
        _entity(sync_db, job, "evil.exe", etype="executable")
        r = _rule(sync_db, u, query="evil", entity_types='["domain"]')
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert len(_matches(sync_db, r.id)) == 1

    def test_only_this_jobs_entities_match(self, sync_db):
        u = _user(sync_db, "a@x.test")
        job_a, job_b = _job(sync_db, owner=u), _job(sync_db, owner=u)
        _entity(sync_db, job_a, "in-a.exe")
        _entity(sync_db, job_b, "in-b.exe")
        r = _rule(sync_db, u, query=".exe")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job_a.id)
        sync_db.commit()
        values = {m.entity_id for m in _matches(sync_db, r.id)}
        assert len(values) == 1

    def test_disabled_rules_are_skipped(self, sync_db):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "certutil.exe")
        r = _rule(sync_db, u, query="certutil", enabled=False)
        sync_db.commit()

        assert evaluate_rules_for_job(sync_db, job.id).matches_created == 0
        assert _matches(sync_db, r.id) == []

    def test_matches_are_capped(self, sync_db):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        for i in range(MAX_MATCHES_PER_RULE + 10):
            _entity(sync_db, job, f"file{i}.exe")
        r = _rule(sync_db, u, query=".exe")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert len(_matches(sync_db, r.id)) == MAX_MATCHES_PER_RULE


class TestIdempotency:
    def test_rerunning_the_same_job_creates_no_duplicate_alerts(self, sync_db):
        """Re-analysis and backfills both re-enter this path."""
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "certutil.exe")
        r = _rule(sync_db, u, query="certutil")
        sync_db.commit()

        first = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        second = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert first.matches_created == 1
        assert second.matches_created == 0
        assert len(_matches(sync_db, r.id)) == 1


class TestPrivateJobIsolation:
    def test_a_rule_does_not_fire_on_a_job_its_owner_cannot_see(self, sync_db):
        """The control that stops watch rules being a cross-user exfiltration channel."""
        owner = _user(sync_db, "owner@x.test")
        other = _user(sync_db, "other@x.test")
        job = _job(sync_db, owner=owner, private=True)
        _entity(sync_db, job, "secret.exe")
        theirs = _rule(sync_db, other, name="broad", query=".exe")
        mine = _rule(sync_db, owner, name="mine", query=".exe")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _matches(sync_db, theirs.id) == [], "a private job leaked into another member's rule"
        assert len(_matches(sync_db, mine.id)) == 1, "the submitter should still be alerted on their own job"

    def test_admins_see_private_jobs(self, sync_db):
        owner = _user(sync_db, "owner@x.test")
        admin = _user(sync_db, "admin@x.test", is_superuser=True)
        job = _job(sync_db, owner=owner, private=True)
        _entity(sync_db, job, "secret.exe")
        r = _rule(sync_db, admin, query=".exe")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert len(_matches(sync_db, r.id)) == 1

    def test_a_deactivated_owners_rule_stops_running(self, sync_db):
        """Deactivating is how an admin offboards someone while keeping their history, and it
        leaves `is_superuser` set. The rule must stop with the account, or a departed admin's
        webhook keeps receiving every private job's entities."""
        ex_admin = _user(sync_db, "gone@x.test", is_superuser=True)
        submitter = _user(sync_db, "s@x.test")
        private = _job(sync_db, owner=submitter, private=True)
        public = _job(sync_db, owner=submitter, private=False)
        _entity(sync_db, private, "secret-host.corp.local", etype="computer")
        _entity(sync_db, public, "public-host.corp.local", etype="computer")
        r = _rule(sync_db, ex_admin, query="corp", webhook_enabled=True, webhook_url="https://hooks.example/x")
        ex_admin.is_active = False
        sync_db.commit()

        for job in (private, public):
            res = evaluate_rules_for_job(sync_db, job.id)
            sync_db.commit()
            assert res.webhook_jobs == []
        assert _matches(sync_db, r.id) == []

    def test_an_owner_demoted_below_member_stops_running(self, sync_db):
        """`role=user` has no Intel at all, so rules written as a member must not keep acting."""
        m = _user(sync_db, "m@x.test")
        job = _job(sync_db, private=False)
        _entity(sync_db, job, "evil.exe")
        r = _rule(sync_db, m, query="evil", webhook_enabled=True, webhook_url="https://hooks.example/x")
        m.role = "user"
        sync_db.commit()

        res = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert res.webhook_jobs == []
        assert _matches(sync_db, r.id) == []

    def test_public_jobs_reach_every_rule(self, sync_db):
        """Otherwise the isolation test above could pass by never matching anything."""
        owner = _user(sync_db, "owner@x.test")
        other = _user(sync_db, "other@x.test")
        job = _job(sync_db, owner=owner, private=False)
        _entity(sync_db, job, "public.exe")
        theirs = _rule(sync_db, other, query=".exe")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert len(_matches(sync_db, theirs.id)) == 1


class TestTagAction:
    def test_auto_tag_applies_to_matches(self, sync_db):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        e = _entity(sync_db, job, "certutil.exe")
        _rule(sync_db, u, query="certutil", action_tag="auto-lolbin", action_tag_color="orange")
        sync_db.commit()

        res = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert res.tags_applied == 1
        tags = sync_db.execute(select(EntityTag.tag).where(EntityTag.entity_id == e.id)).scalars().all()
        assert tags == ["auto-lolbin"]

    def test_auto_tag_does_not_recolour_existing_tags_elsewhere(self, sync_db):
        """An automated rule must not repaint an analyst's palette instance-wide."""
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        other = Entity(value="unrelated", entity_type="user", job_count=1)
        sync_db.add(other)
        sync_db.flush()
        sync_db.add(EntityTag(entity_id=other.id, tag="shared", color="red"))
        _entity(sync_db, job, "certutil.exe")
        _rule(sync_db, u, query="certutil", action_tag="shared", action_tag_color="teal")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        color = sync_db.execute(select(EntityTag.color).where(EntityTag.entity_id == other.id)).scalar_one()
        assert color == "red", "the rule recoloured a tag it did not create"


class TestWebhookQueueing:
    def test_webhook_jobs_are_only_collected_when_configured(self, sync_db):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "certutil.exe")
        _rule(sync_db, u, name="no-hook", query="certutil")
        with_hook = _rule(sync_db, u, name="hook", query="certutil", webhook_url="https://example.test/h", webhook_enabled=True)
        sync_db.commit()

        res = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        rule_ids = [rid for rid, _ in res.webhook_jobs]
        assert rule_ids == [with_hook.id]


class TestTransactionIsolation:
    """A collision in one rule must not discard the work of the rules before it.

    `evaluate_rules_for_job` runs every rule inside **one** transaction. Handling
    `IntegrityError` in `_record_matches` or `_apply_tag` with a bare `db.rollback()` rolls
    that whole transaction back — so a duplicate raised while processing a later rule would
    silently discard the matches and auto-tags already flushed for the earlier ones, and the
    per-row retry loop would then re-flush into a rolled-back transaction and roll it back
    again. Each risky write gets a savepoint instead, the `app/intel/entities.py` shape.

    The `IntegrityError` is injected rather than raced for. Two other approaches do not
    work: pre-inserting the conflicting row is caught by the pre-filter SELECT, so no flush
    ever fails; and inserting it from a second session needs a second connection, which
    SQLite refuses once this transaction has written ("database is locked"). Injecting
    tests the recovery path directly — the handler must not care *why* the flush failed.
    """

    @staticmethod
    def _fail_first_flush_for(monkeypatch, db, predicate):
        """Raise IntegrityError on the first flush whose pending set matches `predicate`."""
        real_flush = type(db).flush
        fired = []

        def flaky_flush(self, *args, **kwargs):
            if not fired and predicate(list(self.new)):
                fired.append(True)
                raise IntegrityError("simulated collision", None, Exception("UNIQUE constraint failed"))
            return real_flush(self, *args, **kwargs)

        monkeypatch.setattr(type(db), "flush", flaky_flush)
        return fired

    def test_a_match_collision_does_not_discard_earlier_rules(self, sync_db, monkeypatch):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        first = _entity(sync_db, job, "certutil.exe")
        _entity(sync_db, job, "rundll32.exe")
        _entity(sync_db, job, "regsvr32.exe")
        early = _rule(sync_db, u, name="early", query="certutil")
        late = _rule(sync_db, u, name="late", query="32.exe")
        sync_db.commit()

        # Only the *bulk* insert fails (more than one pending row), so the per-row retry
        # loop underneath it still succeeds — which is the behaviour the savepoint preserves.
        fired = self._fail_first_flush_for(
            monkeypatch,
            sync_db,
            lambda pending: len([o for o in pending if isinstance(o, IntelRuleMatch) and o.rule_id == late.id]) > 1,
        )

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert fired, "the collision never fired — this test would pass vacuously"
        early_matches = _matches(sync_db, early.id)
        assert len(early_matches) == 1, "the earlier rule's match was discarded when the later rule collided"
        assert early_matches[0].entity_id == first.id
        assert len(_matches(sync_db, late.id)) == 2, "the per-row retry did not recover the later rule's matches"

    def test_a_tag_collision_does_not_discard_earlier_rules(self, sync_db, monkeypatch):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "certutil.exe")
        _entity(sync_db, job, "rundll32.exe")
        early = _rule(sync_db, u, name="early", query="certutil", action_tag="first-tag")
        _rule(sync_db, u, name="late", query="rundll32", action_tag="dupe")
        sync_db.commit()

        fired = self._fail_first_flush_for(
            monkeypatch,
            sync_db,
            lambda pending: any(isinstance(o, EntityTag) and o.tag == "dupe" for o in pending),
        )

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert fired, "the collision never fired — this test would pass vacuously"
        assert len(_matches(sync_db, early.id)) == 1, "the earlier rule's match was discarded when the later rule's tag collided"
        assert "first-tag" in set(sync_db.execute(select(EntityTag.tag)).scalars().all()), "the earlier rule's auto-tag was rolled back"


class TestRuleOrdering:
    def test_the_oldest_rules_are_the_ones_that_fire_past_the_cap(self, sync_db, monkeypatch):
        """`docs/limitations.md` promises oldest-first once past MAX_RULES_EVALUATED.

        Without an ORDER BY this held by accident on SQLite (rowid order) and was arbitrary
        on PostgreSQL, so *which* rules fired on a busy instance was not reproducible from
        one run to the next — the tail of the rule list was silently, non-deterministically
        dropped.

        The cap is lowered to 1 rather than creating 201 rules: the ordering is what is
        under test, and the cap's value is not.
        """
        import datetime as _dt

        import app.intel.rules as rules_mod

        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "certutil.exe")

        base = _dt.datetime(2026, 1, 1, 0, 0, 0)
        # Inserted newest-first, so rowid order and created_at order disagree — which is
        # what made the missing ORDER BY invisible on SQLite.
        newest = _rule(sync_db, u, name="newest", query="certutil")
        oldest = _rule(sync_db, u, name="oldest", query="certutil")
        newest.created_at = base + _dt.timedelta(days=2)
        oldest.created_at = base
        sync_db.commit()

        monkeypatch.setattr(rules_mod, "MAX_RULES_EVALUATED", 1)
        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert len(_matches(sync_db, oldest.id)) == 1, "the oldest rule did not fire — evaluation order is not oldest-first"
        assert len(_matches(sync_db, newest.id)) == 0, "a newer rule fired inside a cap that should have excluded it"


class TestPostFilteredRules:
    def test_a_regex_rule_sees_every_candidate_not_just_the_first_cap(self, sync_db):
        """`re:` narrows in Python after the fetch, so the fetch window must hold every
        candidate the SQL half admits. A `cap + 1` window would report a match past the
        hundredth candidate as a non-match."""
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        for i in range(MAX_MATCHES_PER_RULE + 20):
            _entity(sync_db, job, "needle.exe" if i == MAX_MATCHES_PER_RULE + 10 else f"file{i}.exe")
        r = _rule(sync_db, u, query="re:/^needle/")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert len(_matches(sync_db, r.id)) == 1

    def test_a_cidr_list_rule_matches_addresses_in_any_of_its_networks(self, sync_db):
        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        a = _entity(sync_db, job, "10.1.2.3", etype="ip_address")
        b = _entity(sync_db, job, "192.168.9.9", etype="ip_address")
        _entity(sync_db, job, "8.8.8.8", etype="ip_address")
        r = _rule(sync_db, u, query="cidr:10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert {m.entity_id for m in _matches(sync_db, r.id)} == {a.id, b.id}

    def test_a_list_rule_matches_by_membership_case_insensitively(self, sync_db):
        from app.intel.rule_lists import value_pattern
        from app.models import RuleList, RuleListValue

        u = _user(sync_db, "a@x.test")
        job = _job(sync_db, owner=u)
        hit = _entity(sync_db, job, "CertUtil.exe")
        _entity(sync_db, job, "custom.exe")
        lst = RuleList(name="lolbas", match="exact")
        sync_db.add(lst)
        sync_db.flush()
        sync_db.add(RuleListValue(list_id=lst.id, value="certutil.exe", pattern=value_pattern("certutil.exe", "exact")))
        r = _rule(sync_db, u, query="list:lolbas")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert {m.entity_id for m in _matches(sync_db, r.id)} == {hit.id}
