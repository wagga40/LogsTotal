"""A rule can be about the job, not only about what was found inside it.

`IntelRule.scope` splits the criteria language in two. An entity rule asks "which of this
job's entities match", through the Intel dashboard's grammar; a job rule asks "does this job
match", through the jobs list's. Both reuse the grammar's own filter builder rather than a
hand-rolled matcher, which is the whole reason "what I searched is what alerts" holds.

The structural point these tests exist to pin is `JobRuleMatch`. A job alert has no entity,
and `IntelRuleMatch.entity_id` is NOT NULL — making it nullable would look like the smaller
change and would quietly destroy the idempotency guarantee, because **SQLite and PostgreSQL
both treat NULL as distinct in a UNIQUE index**. `(5, NULL, 42)` would insert without limit,
for exactly the new rows and for nothing else, so a re-run would alert twice and only for
the feature being added. Hence a second table, the `JobTag`-beside-`EntityTag` argument.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

import app.models  # noqa: F401 — populate Base.metadata
from app.intel.rules import evaluate_job_rules_for_job, evaluate_rules_for_job
from app.models import (
    AnalysisJob,
    Finding,
    IntelRule,
    IntelRuleMatch,
    JobRuleMatch,
    JobStatus,
    JobTag,
    LogFile,
    LogType,
    TaskResult,
    TaskStatus,
    User,
    WorkflowDef,
)


def _user(db, email="owner@x.test", *, is_superuser=False):
    u = User(id=uuid.uuid4(), email=email, hashed_password="x", is_active=True, is_superuser=is_superuser, role="member")
    db.add(u)
    db.flush()
    return u


def _workflow(db):
    wf = db.execute(select(WorkflowDef)).scalars().first()
    if wf is None:
        wf = WorkflowDef(name="Windows EVTX", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
        db.add(wf)
        db.flush()
    return wf


def _job(db, *, owner=None, private=False, filename="report.evtx", findings=0, severity="critical"):
    lf = LogFile(original_filename=filename, stored_filename=f"{uuid.uuid4()}.evtx", sha256=uuid.uuid4().hex * 2, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    db.add(lf)
    db.flush()
    j = AnalysisJob(
        submitted_filename=lf.original_filename,
        effective_log_type=lf.log_type,
        file_id=lf.id,
        workflow_id=_workflow(db).id,
        status=JobStatus.COMPLETED,
        is_private=private,
        submitted_by_user_id=(owner.id if owner else None),
        total_findings=findings,
    )
    db.add(j)
    db.flush()
    if findings:
        tr = TaskResult(job_id=j.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=findings)
        db.add(tr)
        db.flush()
        for i in range(findings):
            db.add(Finding(task_result_id=tr.id, rule_id=f"r{i}", rule_name=f"Rule {i}", severity=severity, count=1))
        db.flush()
    return j


def _rule(db, owner, **kw):
    kw.setdefault("scope", "job")
    kw.setdefault("query", "")
    r = IntelRule(name=kw.pop("name", "R"), owner_user_id=(owner.id if owner else None), entity_types="[]", **kw)
    db.add(r)
    db.flush()
    return r


def _alerts(db, rule_id):
    return db.execute(select(JobRuleMatch).where(JobRuleMatch.rule_id == rule_id)).scalars().all()


class TestMatching:
    def test_a_job_rule_matches_the_job_it_is_run_against(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        rule = _rule(sync_db, u, query="intrusion")
        sync_db.commit()

        res = evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert res.matches_created == 1
        assert len(_alerts(sync_db, rule.id)) == 1

    def test_a_job_that_does_not_match_raises_nothing(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="quiet.evtx")
        rule = _rule(sync_db, u, query="intrusion")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _alerts(sync_db, rule.id) == []

    def test_the_severity_grammar_reaches_the_findings(self, sync_db):
        """`sev:` is a correlated EXISTS over `Finding` — the term this feature is for."""
        u = _user(sync_db)
        loud = _job(sync_db, owner=u, findings=3, severity="critical")
        quiet = _job(sync_db, owner=u, findings=2, severity="low")
        rule = _rule(sync_db, u, query="sev:critical")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, loud.id)
        evaluate_job_rules_for_job(sync_db, quiet.id)
        sync_db.commit()

        assert [a.job_id for a in _alerts(sync_db, rule.id)] == [loud.id]

    def test_a_negated_tag_term_works(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        sync_db.add(JobTag(job_id=job.id, tag="reviewed", color="gray"))
        rule = _rule(sync_db, u, query="intrusion -tag:reviewed")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _alerts(sync_db, rule.id) == []

    def test_entity_rules_are_not_evaluated_by_this_pass(self, sync_db):
        """Two passes, two scopes. A shared query would double-evaluate every rule."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        _rule(sync_db, u, scope="entity", query="intrusion")
        sync_db.commit()

        res = evaluate_job_rules_for_job(sync_db, job.id)
        assert res.rules_evaluated == 0

    def test_job_rules_are_not_evaluated_by_the_entity_pass(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        _rule(sync_db, u, scope="job", query="intrusion")
        sync_db.commit()

        res = evaluate_rules_for_job(sync_db, job.id)
        assert res.rules_evaluated == 0

    def test_a_disabled_rule_is_skipped(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        rule = _rule(sync_db, u, query="intrusion", enabled=False)
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _alerts(sync_db, rule.id) == []

    def test_a_broken_rule_does_not_stop_the_others(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        # `findings:` with an unparseable amount degrades to a filter matching nothing
        # rather than raising, so this is the honest shape of a "bad" rule.
        _rule(sync_db, u, name="odd", query="findings:>notanumber")
        good = _rule(sync_db, u, name="good", query="intrusion")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert len(_alerts(sync_db, good.id)) == 1


class TestIdempotency:
    def test_rerunning_the_same_job_raises_no_second_alert(self, sync_db):
        """`uq_job_rule_match(rule_id, job_id)` is the guarantee, and the reason this is a
        table of its own rather than a nullable column on the entity one."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        rule = _rule(sync_db, u, query="intrusion")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        second = evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert second.matches_created == 0
        assert len(_alerts(sync_db, rule.id)) == 1

    def test_the_match_count_does_not_drift_on_a_rerun(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        rule = _rule(sync_db, u, query="intrusion")
        sync_db.commit()

        for _ in range(3):
            evaluate_job_rules_for_job(sync_db, job.id)
            sync_db.commit()
        sync_db.refresh(rule)
        assert rule.match_count == 1


class TestPrivateJobIsolation:
    def test_a_job_rule_does_not_fire_on_a_job_its_owner_cannot_see(self, sync_db):
        """The control that stops one broad rule becoming a cross-user disclosure channel.

        Sharper here than for an entity rule: the alert links straight to the job and the
        webhook payload carries its filename, status and severity summary.
        """
        submitter = _user(sync_db, "sub@x.test")
        nosy = _user(sync_db, "nosy@x.test")
        job = _job(sync_db, owner=submitter, private=True, filename="secret.evtx")
        rule = _rule(sync_db, nosy, query="secret")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _alerts(sync_db, rule.id) == []

    def test_the_submitter_still_hears_about_their_own_private_job(self, sync_db):
        submitter = _user(sync_db, "sub@x.test")
        job = _job(sync_db, owner=submitter, private=True, filename="secret.evtx")
        rule = _rule(sync_db, submitter, query="secret")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert len(_alerts(sync_db, rule.id)) == 1

    def test_an_admin_sees_private_jobs(self, sync_db):
        submitter = _user(sync_db, "sub@x.test")
        admin = _user(sync_db, "admin@x.test", is_superuser=True)
        job = _job(sync_db, owner=submitter, private=True, filename="secret.evtx")
        rule = _rule(sync_db, admin, query="secret")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert len(_alerts(sync_db, rule.id)) == 1

    def test_is_mine_is_read_from_the_rules_owner(self, sync_db):
        """`viewer_id` is the owner, so viewer-relative terms mean something.

        With no viewer the term would silently match nothing and the rule would look
        broken rather than wrong — which is worse, because it looks like the criteria.
        """
        mine = _user(sync_db, "mine@x.test")
        theirs = _user(sync_db, "theirs@x.test")
        job = _job(sync_db, owner=mine, filename="report.evtx")
        ours = _rule(sync_db, mine, name="mine", query="is:mine")
        not_ours = _rule(sync_db, theirs, name="theirs", query="is:mine")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert len(_alerts(sync_db, ours.id)) == 1
        assert _alerts(sync_db, not_ours.id) == []


class TestActions:
    def test_a_job_rule_tags_the_job(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        _rule(sync_db, u, query="intrusion", action_tag="triage,urgent", action_tag_color="red,orange")
        sync_db.commit()

        res = evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        tags = sorted(sync_db.execute(select(JobTag.tag).where(JobTag.job_id == job.id)).scalars().all())
        assert tags == ["triage", "urgent"]
        assert res.tags_applied == 2

    def test_tagging_is_idempotent(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        _rule(sync_db, u, query="intrusion", action_tag="triage")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        rows = sync_db.execute(select(JobTag).where(JobTag.job_id == job.id)).scalars().all()
        assert len(rows) == 1

    def test_a_silent_job_rule_tags_without_alerting(self, sync_db):
        """The same three switches as an entity rule, and the same reasons."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        rule = _rule(sync_db, u, query="intrusion", action_notify=False, action_tag="triage")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _alerts(sync_db, rule.id) == []
        assert sync_db.execute(select(JobTag.tag).where(JobTag.job_id == job.id)).scalars().all() == ["triage"]

    def test_a_silent_job_rule_with_a_webhook_keeps_a_born_acknowledged_ledger(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        rule = _rule(sync_db, u, query="intrusion", action_notify=False, webhook_enabled=True, webhook_url="https://hooks.example/x")
        sync_db.commit()

        res = evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()

        rows = _alerts(sync_db, rule.id)
        assert len(rows) == 1
        assert rows[0].acknowledged_at is not None
        assert res.webhook_rules == [rule.id]

    def test_a_rerun_queues_no_second_delivery(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        _rule(sync_db, u, query="intrusion", webhook_enabled=True, webhook_url="https://hooks.example/x")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        second = evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert second.webhook_rules == []

    def test_the_entity_alert_table_is_left_alone(self, sync_db):
        """A job rule must never write an `intel_rule_match` — that row needs an entity."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx")
        _rule(sync_db, u, query="intrusion")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert sync_db.execute(select(IntelRuleMatch)).scalars().all() == []


class TestThePayload:
    def test_it_is_its_own_event_and_keeps_the_shared_keys(self, sync_db):
        """`event` is the discriminator across all three shapes, and `entities` is present
        and empty so a receiver written against `rule.match` does not KeyError."""
        from app.intel.webhooks import build_job_rule_payload

        u = _user(sync_db)
        job = _job(sync_db, owner=u, filename="intrusion.evtx", findings=4)
        rule = _rule(sync_db, u, query="sev:critical", action_tag="triage")
        sync_db.commit()

        payload = build_job_rule_payload(rule, job)
        assert payload["event"] == "job.match"
        assert payload["entities"] == []
        assert payload["match_count"] == 1
        assert payload["truncated"] is False
        assert payload["job"]["id"] == job.id
        assert payload["job"]["total_findings"] == 4
        assert payload["rule"]["query"] == "sev:critical"

    def test_it_carries_no_secret_material(self, sync_db):
        from app.intel.webhooks import build_job_rule_payload

        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        rule = _rule(sync_db, u, query="x", webhook_url="https://user:pass@hooks.example/x", webhook_secret_encrypted="ciphertext")
        sync_db.commit()

        blob = repr(build_job_rule_payload(rule, job))
        assert "ciphertext" not in blob
        assert "hooks.example" not in blob


class TestARetryKeepsItsShape:
    def test_the_job_rule_flag_rides_the_re_enqueue(self):
        """A dropped kwarg would make attempt two a *different message* than attempt one —
        a `job.match` arriving as a `rule.match` with an empty entity list, which a
        receiver accepts and misreads rather than rejecting."""
        import ast
        import inspect

        from app.workers import tasks

        # Module-level, so the source needs no dedent — but `getsource` keeps the decorator,
        # which parses fine at module scope.
        tree = ast.parse(inspect.getsource(tasks.deliver_webhook.func))
        assigned = {
            node.slice.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "retry_kwargs" and isinstance(node.slice, ast.Constant)
        }
        assert assigned == {"watch_event_ids", "job_rule_match"}, f"a payload-selecting kwarg is missing from the retry: {assigned}"


# ── through the real routes ──────────────────────────────────────────────────


class TestTheForm:
    """The scope selector, the preview it retargets, and the fields it hides.

    Route-level rather than unit, because the defect these guard against lives in the
    signature the framework fills in and in what htmx serialises — neither of which a call
    to `_apply_rule_fields` exercises.
    """

    pytestmark = pytest.mark.anyio

    async def test_creating_a_job_rule(self, member_client, async_db):
        resp = await member_client.post("/intel/rules", data={"name": "loud jobs", "scope": "job", "query": "sev:critical"})
        assert resp.status_code == 200, resp.text
        rule = (await async_db.execute(select(IntelRule))).scalars().one()
        assert rule.scope == "job"
        assert rule.query == "sev:critical"

    async def test_an_absent_scope_still_means_entity(self, member_client, async_db):
        """An older client, or any POST written before this field existed, must not change
        meaning under it."""
        await member_client.post("/intel/rules", data={"name": "r", "query": "evil"})
        rule = (await async_db.execute(select(IntelRule))).scalars().one()
        assert rule.scope == "entity"

    async def test_a_nonsense_scope_degrades_to_the_default(self, member_client, async_db):
        """Clamped, not 400'd: the selector posts one of two known values, so anything else
        is a hand-crafted body — and the `ALLOWED_JOBS_VIEWS` arrangement says degrade."""
        await member_client.post("/intel/rules", data={"name": "r", "scope": "wat", "query": "evil"})
        rule = (await async_db.execute(select(IntelRule))).scalars().one()
        assert rule.scope == "entity"

    async def test_a_job_rule_stores_no_entity_types(self, member_client, async_db):
        """They narrow an entity rule and mean nothing here. Left behind, they would be a
        filter that nothing applies and nothing displays."""
        await member_client.post("/intel/rules", data={"name": "r", "scope": "job", "query": "sev:high", "entity_types": ["executable"]})
        rule = (await async_db.execute(select(IntelRule))).scalars().one()
        assert rule.entity_types == "[]"

    async def test_switching_an_entity_rule_to_job_scope_clears_them(self, member_client, async_db):
        await member_client.post("/intel/rules", data={"name": "r", "query": "evil", "entity_types": ["executable"]})
        rule = (await async_db.execute(select(IntelRule))).scalars().one()
        assert rule.entity_types == '["executable"]'

        await member_client.post(f"/intel/rules/{rule.id}/edit", data={"name": "r", "scope": "job", "query": "sev:high"})
        await async_db.refresh(rule)
        assert (rule.scope, rule.entity_types) == ("job", "[]")

    async def test_a_job_rules_criteria_are_validated_by_the_jobs_grammar(self, member_client):
        """`job:` does not exist in it, so the entity-rule guard has nothing to say here —
        and a term the jobs grammar rejects must still be refused."""
        ok = await member_client.post("/intel/rules", data={"name": "r", "scope": "job", "query": "status:completed"})
        assert ok.status_code == 200, ok.text

        bad = await member_client.post("/intel/rules", data={"name": "r2", "scope": "job", "query": "status:notastatus"})
        assert bad.status_code == 400

    async def test_an_entity_rule_still_refuses_a_job_term(self, member_client):
        resp = await member_client.post("/intel/rules", data={"name": "r", "scope": "entity", "query": "job:1"})
        assert resp.status_code == 400

    async def test_the_row_says_which_scope_it_is(self, member_client):
        await member_client.post("/intel/rules", data={"name": "loud jobs", "scope": "job", "query": "sev:critical"})
        body = (await member_client.get("/intel/rules")).text
        assert ">jobs<" in body


class TestThePreview:
    pytestmark = pytest.mark.anyio

    async def test_it_counts_jobs_when_the_scope_is_jobs(self, member_client, async_db):
        resp = await member_client.get("/intel/rules/preview?scope=job&query=")
        assert resp.status_code == 200
        assert "job" in resp.text and "entit" not in resp.text

    async def test_it_still_counts_entities_by_default(self, member_client):
        resp = await member_client.get("/intel/rules/preview?query=")
        assert "entit" in resp.text

    async def test_a_bad_job_query_is_reported_not_swallowed(self, member_client):
        resp = await member_client.get("/intel/rules/preview?scope=job&query=status:notastatus")
        assert "text-red-400" in resp.text

    async def test_it_counts_only_jobs_the_asker_can_see(self, admin_client, member_user, async_db):
        """A keystroke in this box must not report how many private submissions other
        people hold. The entity branch needs no equivalent — every entity is visible to
        every member — which is exactly why it is easy to forget here.

        One client, logged in twice: `member_client` and `admin_client` are the *same*
        `test_client` with the later login winning, so asking for both in one test measures
        whoever the fixture resolved last.
        """
        from app.models import User as _User

        client = admin_client
        admin = (await async_db.execute(select(_User).where(_User.is_superuser.is_(True)))).scalars().first()
        lf = LogFile(
            original_filename="secret.evtx", stored_filename=f"{uuid.uuid4()}.evtx", sha256=uuid.uuid4().hex * 2, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX
        )
        async_db.add(lf)
        await async_db.flush()
        wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
        async_db.add(wf)
        await async_db.flush()
        async_db.add(
            AnalysisJob(
                submitted_filename=lf.original_filename,
                effective_log_type=lf.log_type,
                file_id=lf.id,
                workflow_id=wf.id,
                status=JobStatus.COMPLETED,
                is_private=True,
                submitted_by_user_id=admin.id,
            )
        )
        await async_db.commit()

        assert "Matches 1 job" in (await client.get("/intel/rules/preview?scope=job&query=")).text

        await client.post("/auth/cookie/login", data={"username": "member@test.example.com", "password": "testpass123"})
        assert "Matches 0 jobs" in (await client.get("/intel/rules/preview?scope=job&query=")).text


class TestAcknowledging:
    pytestmark = pytest.mark.anyio

    @pytest.fixture()
    async def a_job_alert(self, async_db, member_client):
        from app.models import User as _User

        owner = (await async_db.execute(select(_User).where(_User.is_superuser.is_(False)))).scalars().first()
        lf = LogFile(
            original_filename="intrusion.evtx", stored_filename=f"{uuid.uuid4()}.evtx", sha256=uuid.uuid4().hex * 2, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX
        )
        async_db.add(lf)
        await async_db.flush()
        wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
        async_db.add(wf)
        await async_db.flush()
        job = AnalysisJob(
            submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=owner.id
        )
        async_db.add(job)
        rule = IntelRule(name="loud", scope="job", query="intrusion", owner_user_id=owner.id, entity_types="[]")
        async_db.add(rule)
        await async_db.flush()
        match = JobRuleMatch(rule_id=rule.id, job_id=job.id)
        async_db.add(match)
        await async_db.commit()
        await async_db.refresh(match)
        return match

    async def test_the_alert_shows_on_the_rules_page(self, member_client, a_job_alert):
        body = (await member_client.get("/intel/rules")).text
        assert "intrusion.evtx" in body
        assert f"/intel/rules/job-alerts/{a_job_alert.id}/ack" in body

    async def test_acknowledging_one(self, member_client, async_db, a_job_alert):
        resp = await member_client.post(f"/intel/rules/job-alerts/{a_job_alert.id}/ack")
        assert resp.status_code == 200
        await async_db.refresh(a_job_alert)
        assert a_job_alert.acknowledged_at is not None

    async def test_acknowledging_someone_elses_is_a_404(self, member_client, async_db, a_job_alert):
        """404 rather than 403 — the existence-oracle discipline the rest of Intel uses.

        Driven from a *second member*, not an admin: an admin legitimately sees every rule,
        so a 404 there would mean the opposite of what this is testing.
        """
        from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

        from app.auth.schemas import UserCreate
        from app.auth.users import UserManager

        manager = UserManager(SQLAlchemyUserDatabase(async_db, User))
        await manager.create(UserCreate(email="other@example.com", password="pass123456", is_superuser=False, is_active=True, role="member"))
        await member_client.post("/auth/cookie/login", data={"username": "other@example.com", "password": "pass123456"})

        assert (await member_client.post(f"/intel/rules/job-alerts/{a_job_alert.id}/ack")).status_code == 404

    async def test_ack_all_clears_both_kinds(self, member_client, async_db, a_job_alert):
        """A sweep that leaves half the badge behind is worse than no sweep — the reader
        cannot tell which half is left."""
        assert (await member_client.get("/intel/watchlist-events-partial?count_only=1")).text.strip() == "1"
        await member_client.post("/intel/rules/alerts/ack-all")
        assert (await member_client.get("/intel/watchlist-events-partial?count_only=1")).text.strip() == "0"

    async def test_the_bell_counts_it(self, member_client, a_job_alert):
        assert (await member_client.get("/intel/watchlist-events-partial?count_only=1")).text.strip() == "1"

    async def test_the_bell_renders_it_as_its_own_kind(self, member_client, a_job_alert):
        """Three streams, three badges. An if/else pair silently gave the third the second's
        words — same shape, wrong meaning."""
        body = (await member_client.get("/intel/watchlist-events-partial")).text
        assert "Job matched" in body
        assert "loud" in body

    async def test_the_bells_ack_returns_the_dropdown_not_the_page(self, member_client, a_job_alert):
        """The write is the same as the Rules page's; what comes back is not. Sharing one
        route puts a whole rules section inside the dropdown."""
        resp = await member_client.post(f"/intel/watchlist-events/job-rule/{a_job_alert.id}/ack")
        assert resp.status_code == 200
        assert "watchlist-events-list" in resp.text
        assert 'id="rules-region"' not in resp.text

    async def test_deleting_the_rule_takes_its_job_alerts(self, member_client, async_db, a_job_alert):
        """A Core delete fires no ORM cascade, so every referencing table has to be named."""
        await member_client.post(f"/intel/rules/{a_job_alert.rule_id}/delete")
        assert (await async_db.execute(select(JobRuleMatch))).scalars().all() == []
