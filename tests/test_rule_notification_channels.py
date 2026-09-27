"""A rule's three actions are three switches, and each one has to work on its own.

A switch can have a checkbox, a form field on both routes, a column and a test — and no
effect. If `evaluate_rules_for_job` called `_record_matches` unconditionally and consulted
`action_notify` only when deciding whether to queue the *webhook*, which `webhook_enabled`
already gates, unticking "Raise an alert for every match" would suppress a delivery that was
already off and leave the bell exactly as it was.

`tests/test_watch_rule_toggles.py` asserts the column round-trips through the form. That is
the right test for a `Form(0)` defect, and blind to this one: every assertion it makes would
still be true.

The three actions and what each is allowed to do:

| `action_notify` | `webhook_enabled` | `action_tag` | ledger row | in the bell |
|---|---|---|---|---|
| on  | either | either | yes | yes |
| off | on     | either | yes, born acknowledged | no |
| off | off    | set    | **none** | no |

The middle row is the one worth explaining. `deliver_webhook` builds its entity list by
reading `IntelRuleMatch.entity_id` for the ids it was handed, so a
webhook rule needs the ledger whether or not anyone is being alerted — and the ledger is also
what stops a re-run delivering twice. Stamping `acknowledged_at` at insert keeps both of those
and takes the row out of every "unacknowledged" query, which is the whole of the bell.

The last row is what makes built-in label rules affordable: with no alert and no webhook there
is nothing for the ledger to make idempotent, because `uq_entity_tag(entity_id, tag)` already
does that for tagging.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

import app.models  # noqa: F401 — populate Base.metadata
from app.intel.rules import evaluate_rules_for_job
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


def _user(db, email="owner@x.test"):
    u = User(id=uuid.uuid4(), email=email, hashed_password="x", is_active=True, is_superuser=False, role="member")
    db.add(u)
    db.flush()
    return u


def _job(db, owner):
    wf = db.execute(select(WorkflowDef)).scalars().first()
    if wf is None:
        wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
        db.add(wf)
        db.flush()
    lf = LogFile(original_filename="x.evtx", stored_filename=f"{uuid.uuid4()}.evtx", sha256=uuid.uuid4().hex * 2, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    db.add(lf)
    db.flush()
    j = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, is_private=False, submitted_by_user_id=owner.id)
    db.add(j)
    db.flush()
    return j


def _entity(db, job, value="certutil.exe"):
    e = Entity(value=value, entity_type="executable", job_count=1, attributes_json=json_dumps({"is_lolbin": True}))
    db.add(e)
    db.flush()
    db.add(EntityJobLink(entity_id=e.id, job_id=job.id, occurrence_count=1))
    db.flush()
    return e


def _rule(db, owner, **kw):
    r = IntelRule(name=kw.pop("name", "R"), owner_user_id=owner.id, query=kw.pop("query", "label:lolbin"), entity_types="[]", **kw)
    db.add(r)
    db.flush()
    return r


def _ledger(db, rule_id):
    return db.execute(select(IntelRuleMatch).where(IntelRuleMatch.rule_id == rule_id)).scalars().all()


def _unacked(db, rule_id):
    return [m for m in _ledger(db, rule_id) if m.acknowledged_at is None]


@pytest.fixture()
def matched(sync_db):
    """One member, one public job, one LOLBin entity that `label:lolbin` matches."""
    owner = _user(sync_db)
    job = _job(sync_db, owner)
    entity = _entity(sync_db, job)
    sync_db.commit()
    return owner, job, entity


class TestSilenceMeansSilence:
    def test_a_tag_only_rule_raises_no_alert(self, sync_db, matched):
        """The complaint, exactly: the box is unticked and the bell must stay quiet."""
        owner, job, _entity_row = matched
        rule = _rule(sync_db, owner, action_notify=False, action_tag="triage", action_tag_color="red")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _unacked(sync_db, rule.id) == [], "'Raise an alert for every match' was unticked and an alert was raised anyway"

    def test_a_tag_only_rule_writes_no_ledger_at_all(self, sync_db, matched):
        """No alert and no webhook means nothing for the ledger to make idempotent.

        This is what keeps eighteen built-in label rules from writing thousands of rows per
        job that nobody will ever read; `uq_entity_tag` is already the guarantee.
        """
        owner, job, _entity_row = matched
        rule = _rule(sync_db, owner, action_notify=False, action_tag="triage")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _ledger(sync_db, rule.id) == []

    def test_a_silent_rule_still_tags(self, sync_db, matched):
        """Silencing the bell must not silence the rule — the fix cannot be "do nothing"."""
        owner, job, entity = matched
        _rule(sync_db, owner, action_notify=False, action_tag="triage", action_tag_color="red")
        sync_db.commit()

        result = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        tags = sync_db.execute(select(EntityTag.tag).where(EntityTag.entity_id == entity.id)).scalars().all()
        assert tags == ["triage"]
        assert result.tags_applied == 1

    def test_a_silent_rule_is_still_stamped_as_having_matched(self, sync_db, matched):
        """`last_matched_at` is how a tag-only rule reports that it is working at all."""
        owner, job, _entity_row = matched
        rule = _rule(sync_db, owner, action_notify=False, action_tag="triage")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        sync_db.refresh(rule)

        assert rule.last_matched_at is not None
        assert rule.last_evaluated_at is not None


class TestASilentWebhookStillDelivers:
    def test_the_delivery_is_still_queued(self, sync_db, matched):
        """`action_notify` must stop gating the webhook — `webhook_enabled` is that switch."""
        owner, job, _entity_row = matched
        rule = _rule(sync_db, owner, action_notify=False, webhook_enabled=True, webhook_url="https://hooks.example/x")
        sync_db.commit()

        result = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert [rid for rid, _ids in result.webhook_jobs] == [rule.id]

    def test_the_delivery_carries_real_match_ids(self, sync_db, matched):
        """`deliver_webhook` reads `IntelRuleMatch.entity_id` back out of these ids.

        Suppressing the ledger for a webhook rule would send an empty `entities` list on
        every delivery, which is a silent, permanent corruption of the payload.
        """
        owner, job, entity = matched
        _rule(sync_db, owner, action_notify=False, webhook_enabled=True, webhook_url="https://hooks.example/x")
        sync_db.commit()

        result = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        (_rid, match_ids) = result.webhook_jobs[0]
        entity_ids = sync_db.execute(select(IntelRuleMatch.entity_id).where(IntelRuleMatch.id.in_(match_ids))).scalars().all()
        assert entity_ids == [entity.id]

    def test_its_ledger_rows_are_born_acknowledged(self, sync_db, matched):
        """Present for the webhook and for idempotency; absent from the bell."""
        owner, job, _entity_row = matched
        rule = _rule(sync_db, owner, action_notify=False, webhook_enabled=True, webhook_url="https://hooks.example/x")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        rows = _ledger(sync_db, rule.id)
        assert len(rows) == 1
        assert rows[0].acknowledged_at is not None, "a silenced rule's match reaches the bell"
        assert rows[0].acknowledged_by_user_id is None, "nobody acknowledged this — it was never raised"

    def test_a_rerun_still_delivers_nothing_twice(self, sync_db, matched):
        """The ledger is what makes that true, so acknowledging at insert must not break it."""
        owner, job, _entity_row = matched
        _rule(sync_db, owner, action_notify=False, webhook_enabled=True, webhook_url="https://hooks.example/x")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        second = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert second.webhook_jobs == []


class TestTheAlertingPathIsUnchanged:
    def test_an_alerting_rule_still_raises_an_unacknowledged_alert(self, sync_db, matched):
        owner, job, _entity_row = matched
        rule = _rule(sync_db, owner, action_notify=True, action_tag="triage")
        sync_db.commit()

        result = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert result.matches_created == 1
        assert len(_unacked(sync_db, rule.id)) == 1
        sync_db.refresh(rule)
        assert rule.match_count == 1

    def test_an_alerting_rule_with_a_webhook_is_unchanged(self, sync_db, matched):
        owner, job, _entity_row = matched
        rule = _rule(sync_db, owner, action_notify=True, webhook_enabled=True, webhook_url="https://hooks.example/x")
        sync_db.commit()

        result = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert [rid for rid, _ids in result.webhook_jobs] == [rule.id]
        assert len(_unacked(sync_db, rule.id)) == 1

    def test_match_count_counts_the_ledger_and_nothing_else(self, sync_db, matched):
        """A tag-only rule reports through `last_matched_at`, not through a count.

        `_apply_tag` returns rows written across every tag the rule carries, so accruing it
        here would report 6 for a two-tag rule over three entities. The column keeps one
        meaning — alerts recorded — and stays 0 for a rule that raises none.
        """
        owner, job, _entity_row = matched
        rule = _rule(sync_db, owner, action_notify=False, action_tag="triage,review", action_tag_color="red,blue")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        sync_db.refresh(rule)

        assert rule.match_count == 0
