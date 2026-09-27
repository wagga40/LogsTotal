"""Labels are rules that write tags, and the seams that makes are all silent ones.

`lolbin`, `privileged` and the rest are `IntelRule` rows, seeded from `rules/builtin.yml`,
so they can be recoloured, switched off or added to; their criteria are real expressions in
the grammar — `list:lolbas`, `cidr:10.0.0.0/8,…`, `re:/^[0-9a-f]{32}$/`. The seeding and
the file itself are covered in `test_rules_yaml.py`; this file is about what the rows do
once they exist.

Five things have to be right for that to work, and **every one of them fails without a
visible error**:

1. A built-in has no owner, and `_rule_may_run_on` answers False for a private job when the
   owner is None — so without an exemption a private submission's entities would silently
   never be labelled, and only that submission's.
2. `MAX_MATCHES_PER_RULE` would stop labelling at the hundredth entity in a job. The ones
   past it do not look truncated; they look unremarkable.
3. Dozens of rules over every entity of every job would write thousands of alert-ledger rows
   nobody reads, so a rule that neither alerts nor delivers must record none.
4. `parse_tag_write` must not reserve the built-in names, or the built-ins would be
   literally unable to apply their own tags.
5. `_apply_tag` must not open a savepoint per row — fine at a hundred, a writer-lock stall
   at five thousand.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

import app.models  # noqa: F401 — populate Base.metadata
from app.intel.queries import ATTR_FILTERS
from app.intel.rule_lists import value_pattern
from app.intel.rules import MAX_MATCHES_PER_BUILTIN_RULE, MAX_MATCHES_PER_RULE, evaluate_job_rules_for_job, evaluate_rules_for_job
from app.intel.rules_yaml import apply_spec, load_rules_dir, sync_rules_from_dir
from app.json_utils import dumps as json_dumps
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    EntityTag,
    Finding,
    IntelRule,
    IntelRuleMatch,
    JobStatus,
    JobTag,
    LogFile,
    LogType,
    RuleList,
    RuleListValue,
    SiteSettings,
    TaskResult,
    TaskStatus,
    User,
    WorkflowDef,
)

# ── seeding ──────────────────────────────────────────────────────────────────

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
SHIPPED = load_rules_dir(RULES_DIR)
SHIPPED_RULES = {s.key: s for s in SHIPPED.rules}
# The eighteen rules that replaced a derived attribute — what the equivalence test is about.
LABEL_KEYS = [k for k in SHIPPED_RULES if k in ATTR_FILTERS]


async def _seed(db):
    return await sync_rules_from_dir(db, RULES_DIR)


@pytest.mark.anyio
class TestSeeding:
    async def test_it_creates_one_rule_per_shipped_spec(self, async_db):
        result = await _seed(async_db)
        await async_db.commit()

        assert (result.created, result.updated, result.errors) == (len(SHIPPED_RULES), 0, [])
        rows = (await async_db.execute(select(IntelRule).where(IntelRule.is_builtin.is_(True)))).scalars().all()
        assert {r.builtin_key for r in rows} == set(SHIPPED_RULES)
        by_key = {r.builtin_key: r for r in rows}
        assert by_key["lolbin"].query == "list:lolbas"
        assert by_key["rfc1918"].query.startswith("cidr:10.0.0.0/8")

    async def test_it_is_idempotent(self, async_db):
        await _seed(async_db)
        await async_db.commit()
        result = await _seed(async_db)
        await async_db.commit()

        assert (result.created, result.updated, result.errors) == (0, 0, [])
        assert result.kept == len(SHIPPED_RULES)

    async def test_a_resync_does_not_undo_an_admins_edits(self, async_db):
        """Making these editable is the entire point, so a re-sync must not quietly put a
        rule back or re-enable one somebody switched off. The other half — the file *does*
        update a rule nobody touched — is in test_rules_yaml.py."""
        await _seed(async_db)
        await async_db.commit()
        rule = (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "sha256"))).scalar_one()
        rule.enabled = False
        rule.action_tag_color = "purple"
        rule.query = "re:/^[0-9A-F]{64}$/"
        await async_db.commit()

        await _seed(async_db)
        await async_db.commit()
        await async_db.refresh(rule)
        assert rule.enabled is False
        assert rule.action_tag_color == "purple"
        assert rule.query == "re:/^[0-9A-F]{64}$/"

    async def test_a_deleted_builtin_comes_back(self, async_db):
        """`builtin_key` is the identity, so restoring one is a re-sync away."""
        await _seed(async_db)
        await async_db.commit()
        rule = (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "md5"))).scalar_one()
        await async_db.delete(rule)
        await async_db.commit()

        result = await _seed(async_db)
        await async_db.commit()
        assert result.created == 1

    async def test_every_seeded_rule_is_silent_and_ownerless(self, async_db):
        """Load-bearing, not defaults. The private-job exemption is conditional on both
        flags, and the ledger skip is conditional on both."""
        await _seed(async_db)
        await async_db.commit()

        rows = (await async_db.execute(select(IntelRule).where(IntelRule.is_builtin.is_(True)))).scalars().all()
        for r in rows:
            assert r.owner_user_id is None, r.builtin_key
            assert r.action_notify is False, r.builtin_key
            assert r.webhook_enabled is False, r.builtin_key
            assert r.scope in ("entity", "job"), r.builtin_key
            assert r.action_tag == r.builtin_key

    async def test_they_do_not_spend_a_members_rule_budget(self, member_client, async_db):
        """`watch_rules_max_per_user` counts `owner_user_id == user.id`, and a built-in has
        none — so eighteen shipped rows must not eat a third of anybody's fifty."""
        await _seed(async_db)
        await async_db.commit()

        body = (await member_client.get("/intel/rules")).text
        assert "0 of 50 used" in body


# ── evaluation ───────────────────────────────────────────────────────────────


def _user(db, email="owner@x.test"):
    u = User(id=uuid.uuid4(), email=email, hashed_password="x", is_active=True, is_superuser=False, role="member")
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
    e = Entity(value=value, entity_type=etype, job_count=1, attributes_json=json_dumps(attrs or {}))
    db.add(e)
    db.flush()
    db.add(EntityJobLink(entity_id=e.id, job_id=job.id, occurrence_count=1))
    db.flush()
    return e


def _ensure_lists(db):
    """The shipped lists, written through the sync session — `write_list` is async and this
    half is not. Without them a `list:lolbas` rule matches nothing."""
    existing = set(db.execute(select(RuleList.name)).scalars().all())
    for lspec in SHIPPED.lists:
        if lspec.name in existing:
            continue
        row = RuleList(name=lspec.name, match=lspec.match, description=lspec.description)
        db.add(row)
        db.flush()
        db.add_all([RuleListValue(list_id=row.id, value=v, pattern=value_pattern(v, lspec.match)) for v in lspec.values])
    db.flush()


def _builtin(db, key):
    """One shipped rule, built by hand — `sync_rules_from_dir` is async and this half is not."""
    _ensure_lists(db)
    r = IntelRule(name="", owner_user_id=None, is_builtin=True, builtin_key=key)
    apply_spec(r, SHIPPED_RULES[key])
    db.add(r)
    db.flush()
    return r


def _tags(db, entity_id):
    return sorted(db.execute(select(EntityTag.tag).where(EntityTag.entity_id == entity_id)).scalars().all())


class TestEvaluation:
    def test_a_builtin_labels_what_it_matches(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        hit = _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True, "is_gtfobin": False})
        miss = _entity(sync_db, job, "custom.exe", attrs={"is_lolbin": False, "is_gtfobin": False})
        _builtin(sync_db, "lolbin")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _tags(sync_db, hit.id) == ["lolbin"]
        assert _tags(sync_db, miss.id) == []

    def test_it_writes_no_alert_ledger(self, sync_db):
        """Eighteen rules over every entity of every job is thousands of rows nobody reads, and
        `uq_entity_tag` is already the idempotency guarantee for tagging."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True})
        _builtin(sync_db, "lolbin")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert sync_db.execute(select(IntelRuleMatch)).scalars().all() == []

    def test_it_labels_a_private_job_too(self, sync_db):
        """The exemption. A built-in has no owner, so the ordinary answer is False for every
        private job — which would leave exactly those entities unlabelled, and nothing would
        say so."""
        submitter = _user(sync_db, "sub@x.test")
        job = _job(sync_db, owner=submitter, private=True)
        hit = _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True})
        _builtin(sync_db, "lolbin")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _tags(sync_db, hit.id) == ["lolbin"]

    def test_the_exemption_is_conditional_on_being_silent(self, sync_db):
        """It is safe *because* a built-in only tags. An admin who gave one a webhook has
        made it something else, and it goes back to the ordinary visibility rule."""
        submitter = _user(sync_db, "sub@x.test")
        job = _job(sync_db, owner=submitter, private=True)
        hit = _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True})
        rule = _builtin(sync_db, "lolbin")
        rule.webhook_enabled = True
        rule.webhook_url = "https://hooks.example/x"
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _tags(sync_db, hit.id) == [], "a built-in with a webhook reached a private job"

    def test_a_disabled_builtin_labels_nothing(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        hit = _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True})
        rule = _builtin(sync_db, "lolbin")
        rule.enabled = False
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _tags(sync_db, hit.id) == []

    def test_the_site_switch_stops_the_whole_pass(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        hit = _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True})
        _builtin(sync_db, "lolbin")
        sync_db.add(SiteSettings(id=1, builtin_rules_enabled=False))
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _tags(sync_db, hit.id) == []

    def test_the_site_switch_leaves_an_analysts_own_rules_alone(self, sync_db):
        """It is a switch for the shipped vocabulary, not a kill switch for rules."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        hit = _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True})
        _builtin(sync_db, "lolbin")
        sync_db.add(IntelRule(name="mine", owner_user_id=u.id, scope="entity", query="certutil", entity_types="[]", action_tag="triage"))
        sync_db.add(SiteSettings(id=1, builtin_rules_enabled=False))
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _tags(sync_db, hit.id) == ["triage"]

    def test_it_reaches_past_the_ordinary_match_cap(self, sync_db):
        """A label that stopped at the hundredth LOLBin would be wrong in a way nobody can
        see: the entities it missed just look unremarkable."""
        assert MAX_MATCHES_PER_BUILTIN_RULE > MAX_MATCHES_PER_RULE
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        # Seventy-two LOLBAS names cannot exceed the cap; sixty-four-hex digests can.
        made = [_entity(sync_db, job, f"{i:064x}", etype="hash") for i in range(MAX_MATCHES_PER_RULE + 5)]
        _builtin(sync_db, "sha256")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        tagged = sync_db.execute(select(EntityTag.entity_id).where(EntityTag.tag == "sha256")).scalars().all()
        assert len(tagged) == len(made)

    def test_an_analysts_rule_keeps_the_ordinary_cap(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        for i in range(MAX_MATCHES_PER_RULE + 5):
            _entity(sync_db, job, f"lol{i}.exe", attrs={"is_lolbin": True})
        rule = IntelRule(name="mine", owner_user_id=u.id, scope="entity", query="attr:lolbin", entity_types="[]", action_notify=True)
        sync_db.add(rule)
        sync_db.commit()

        res = evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert res.matches_created == MAX_MATCHES_PER_RULE

    def test_labelling_is_idempotent_across_reruns(self, sync_db):
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        hit = _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True})
        _builtin(sync_db, "lolbin")
        sync_db.commit()

        for _ in range(3):
            evaluate_rules_for_job(sync_db, job.id)
            sync_db.commit()

        rows = sync_db.execute(select(EntityTag).where(EntityTag.entity_id == hit.id)).scalars().all()
        assert len(rows) == 1

    def test_the_tag_joins_the_vocabulary(self, sync_db):
        from app.models import TagDefinition

        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True})
        _builtin(sync_db, "lolbin")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        row = sync_db.execute(select(TagDefinition).where(TagDefinition.tag == "lolbin")).scalar_one()
        assert row.color == "orange"

    def test_entity_types_scope_the_rule(self, sync_db):
        """A domain called `certutil.exe` is not a LOLBin — the seeded `entity_types` narrows it."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        wrong = _entity(sync_db, job, "certutil.exe", etype="domain")
        _builtin(sync_db, "lolbin")
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _tags(sync_db, wrong.id) == []


class TestTheBatchedTagWrite:
    def test_one_savepoint_for_the_batch(self):
        """Five thousand savepoints inside the post-processing transaction is the measured
        shape of the 80-second SQLite writer-lock stall the backfill work fixed. Asserted
        from the AST, because the whole distinction is where the `begin_nested()` sits."""
        import ast
        import inspect

        from app.intel import rules as rules_mod

        tree = ast.parse(inspect.getsource(rules_mod._insert_tags))
        # The batch path adds a list, one savepoint. The fallback adds one row per savepoint.
        assert any(isinstance(n, ast.Attribute) and n.attr == "add_all" for n in ast.walk(tree)), "the batch insert is gone; every row would open its own savepoint"

    def test_a_collision_still_falls_back_row_by_row(self, sync_db):
        """The pre-filter makes the batch path common; the unique constraint is what
        actually guarantees correctness, so one duplicate must not lose the batch."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        a = _entity(sync_db, job, "a.exe", attrs={"is_lolbin": True})
        b = _entity(sync_db, job, "b.exe", attrs={"is_lolbin": True})
        rule = _builtin(sync_db, "lolbin")
        sync_db.commit()

        from app.intel.rules import _insert_tags

        sync_db.add(EntityTag(entity_id=a.id, tag="lolbin", color="orange"))
        sync_db.commit()
        # `a` collides, `b` does not — the batch fails and the row loop salvages `b`.
        assert _insert_tags(sync_db, rule, "lolbin", "orange", [a.id, b.id]) == 1
        sync_db.commit()
        assert _tags(sync_db, b.id) == ["lolbin"]


class TestTheBackfill:
    """The one-time catch-up. Labels are stored tags, and an entity last seen before the
    rules existed carries none of them until something touches it again."""

    @pytest.fixture(autouse=True)
    def _worker_session(self, sync_db, monkeypatch):
        """The task opens its own session through `get_sync_session`, which is a real
        engine. Rebind it at the module the task reads it from — the `test_comment_prune`
        idiom — and it must NOT close the fixture's session out from under the assertions."""
        from app.workers import tasks as tasks_mod

        monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
        monkeypatch.setattr(sync_db, "close", lambda: None)

    def test_it_labels_entities_no_job_will_touch_again(self, sync_db):
        from app.workers.tasks import backfill_builtin_labels

        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        hit = _entity(sync_db, job, "certutil.exe", attrs={"is_lolbin": True, "is_gtfobin": False})
        miss = _entity(sync_db, job, "custom.exe", attrs={"is_lolbin": False, "is_gtfobin": False})
        _builtin(sync_db, "lolbin")
        sync_db.commit()

        backfill_builtin_labels.call_local()

        assert _tags(sync_db, hit.id) == ["lolbin"]
        assert _tags(sync_db, miss.id) == []

    def test_a_shared_job_rule_is_not_run_against_entities(self, sync_db):
        """A job rule's condition is written in the jobs grammar. Read as an entity query,
        `tag:escalated` means "entities tagged escalated", so the backfill put a job-triage
        tag on entities — and a pure negation such as `-tag:reviewed` would tag them all."""
        from app.workers.tasks import backfill_builtin_labels

        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        e = _entity(sync_db, job, "evil.exe")
        sync_db.add(EntityTag(entity_id=e.id, tag="escalated", color="red"))
        sync_db.add(
            IntelRule(
                name="Second look",
                owner_user_id=None,
                is_builtin=True,
                builtin_key="second_look",
                scope="job",
                query="tag:escalated",
                entity_types="[]",
                action_tag="second_look",
                enabled=True,
            )
        )
        sync_db.commit()

        backfill_builtin_labels.call_local()

        assert _tags(sync_db, e.id) == ["escalated"]

    def test_it_reaches_entities_with_no_job_link_at_all(self, sync_db):
        """It works from the entity table rather than by replaying jobs — a label is a
        property of the entity, not of the run that happened to observe it."""
        from app.workers.tasks import backfill_builtin_labels

        orphan = Entity(value="rundll32.exe", entity_type="executable", job_count=0, attributes_json=json_dumps({"is_lolbin": True}))
        sync_db.add(orphan)
        _builtin(sync_db, "lolbin")
        sync_db.commit()
        sync_db.refresh(orphan)

        backfill_builtin_labels.call_local()
        assert _tags(sync_db, orphan.id) == ["lolbin"]

    def test_it_is_idempotent(self, sync_db):
        from app.workers.tasks import backfill_builtin_labels

        e = Entity(value="certutil.exe", entity_type="executable", job_count=0, attributes_json=json_dumps({"is_lolbin": True}))
        sync_db.add(e)
        _builtin(sync_db, "lolbin")
        sync_db.commit()
        sync_db.refresh(e)

        backfill_builtin_labels.call_local()
        backfill_builtin_labels.call_local()
        rows = sync_db.execute(select(EntityTag).where(EntityTag.entity_id == e.id)).scalars().all()
        assert len(rows) == 1

    def test_it_respects_the_entity_type_scope(self, sync_db):
        from app.workers.tasks import backfill_builtin_labels

        wrong = Entity(value="evil.com", entity_type="domain", job_count=0, attributes_json=json_dumps({"is_lolbin": True}))
        sync_db.add(wrong)
        _builtin(sync_db, "lolbin")
        sync_db.commit()
        sync_db.refresh(wrong)

        backfill_builtin_labels.call_local()
        assert _tags(sync_db, wrong.id) == []

    def test_a_disabled_rule_is_skipped(self, sync_db):
        from app.workers.tasks import backfill_builtin_labels

        e = Entity(value="certutil.exe", entity_type="executable", job_count=0, attributes_json=json_dumps({"is_lolbin": True}))
        sync_db.add(e)
        rule = _builtin(sync_db, "lolbin")
        rule.enabled = False
        sync_db.commit()
        sync_db.refresh(e)

        backfill_builtin_labels.call_local()
        assert _tags(sync_db, e.id) == []

    def test_the_site_switch_stops_it(self, sync_db):
        from app.workers.tasks import backfill_builtin_labels

        e = Entity(value="certutil.exe", entity_type="executable", job_count=0, attributes_json=json_dumps({"is_lolbin": True}))
        sync_db.add(e)
        _builtin(sync_db, "lolbin")
        sync_db.add(SiteSettings(id=1, builtin_rules_enabled=False))
        sync_db.commit()
        sync_db.refresh(e)

        backfill_builtin_labels.call_local()
        assert _tags(sync_db, e.id) == []

    def test_it_writes_no_alert_ledger_either(self, sync_db):
        from app.workers.tasks import backfill_builtin_labels

        e = Entity(value="certutil.exe", entity_type="executable", job_count=0, attributes_json=json_dumps({"is_lolbin": True}))
        sync_db.add(e)
        _builtin(sync_db, "lolbin")
        sync_db.commit()

        backfill_builtin_labels.call_local()
        assert sync_db.execute(select(IntelRuleMatch)).scalars().all() == []

    def test_every_shipped_rule_agrees_with_the_derivation_it_replaced(self, sync_db):
        """The point of the seed file: each default is *implementable in the logic*. For a
        value of every kind, the tags the shipped rules write are exactly the attribute
        keys `compute_attributes` derives — two excepted: `private`, implied by every
        private category, and `dga`, an entropy heuristic in code that no reader could edit,
        so it stays an attribute rather than a shipped rule."""
        from app.intel.attributes import attribute_flags, attribute_subtype, compute_attributes
        from app.workers.tasks import backfill_builtin_labels

        samples = [
            ("certutil.exe", "executable"),
            ("nmap", "executable"),
            ("custom.exe", "executable"),
            ("evil-c2.tk", "domain"),
            ("xk3jf9q2mz7v8bp1.com", "domain"),
            ("example.com", "domain"),
            ("Administrator", "user"),
            ("WIN-DC01$", "user"),
            ("alice", "user"),
            ("a" * 32, "hash"),
            ("b" * 40, "hash"),
            ("c" * 64, "hash"),
            ("d" * 128, "hash"),
            ("10.1.2.3", "ip_address"),
            ("172.16.5.5", "ip_address"),
            ("192.168.1.1", "ip_address"),
            ("100.64.1.1", "ip_address"),
            ("127.0.0.1", "ip_address"),
            ("::1", "ip_address"),
            ("169.254.1.1", "ip_address"),
            ("fe80::1", "ip_address"),
            ("224.0.0.1", "ip_address"),
            ("ff02::1", "ip_address"),
            ("8.8.8.8", "ip_address"),
            ("2606:4700::1111", "ip_address"),
            ("C:\\Windows\\System32\\svchost.exe", "service"),
            ("/opt/app/bin/agent", "service"),
        ]
        made = []
        for value, etype in samples:
            attrs = compute_attributes(value, etype)
            e = Entity(value=value, entity_type=etype, job_count=0, attributes_json=json_dumps(attrs or {}))
            sync_db.add(e)
            made.append((e, attrs))
        for key in LABEL_KEYS:
            _builtin(sync_db, key)
        sync_db.commit()

        backfill_builtin_labels.call_local()

        for e, attrs in made:
            sync_db.refresh(e)
            expected = set(attribute_flags(attrs)) - {"private", "dga"}
            subtype = attribute_subtype(attrs)
            if subtype:
                expected.add(subtype)
            assert set(_tags(sync_db, e.id)) == expected, f"{e.value}: the rules wrote {_tags(sync_db, e.id)}, the derivation says {sorted(expected)}"

    def test_the_rule_and_the_derivation_agree_on_a_reserved_address(self, sync_db):
        """240/4 is reserved, not RFC1918. The derivation used to call it rfc1918 (Python's
        `is_private` is True for it, and was tested first) while the CIDR rule said
        reserved; they now say the same thing."""
        from app.intel.attributes import attribute_subtype, compute_attributes
        from app.workers.tasks import backfill_builtin_labels

        attrs = compute_attributes("240.0.0.1", "ip_address")
        assert attribute_subtype(attrs) == "reserved"
        e = Entity(value="240.0.0.1", entity_type="ip_address", job_count=0, attributes_json=json_dumps(attrs))
        sync_db.add(e)
        for key in LABEL_KEYS:
            _builtin(sync_db, key)
        sync_db.commit()

        backfill_builtin_labels.call_local()
        sync_db.refresh(e)
        assert _tags(sync_db, e.id) == ["reserved"]

    def test_it_honours_an_edited_criteria(self, sync_db):
        """Matching by hand against `attributes_json` would have been cheaper by one query
        per rule per batch, and wrong in one silent way: an admin who edits a built-in's
        criteria to something that is not `attr:<key>` gets a rule that works during
        analysis and matches nothing here. It goes through the same filter builder the live
        pass uses, so it cannot form a second opinion."""
        from app.workers.tasks import backfill_builtin_labels

        e = Entity(value="custom.exe", entity_type="executable", job_count=0, attributes_json=json_dumps({"is_lolbin": False}))
        sync_db.add(e)
        rule = _builtin(sync_db, "lolbin")
        rule.query = "custom"  # a plain substring; `list:lolbas` would not match this
        sync_db.commit()
        sync_db.refresh(e)

        backfill_builtin_labels.call_local()
        assert _tags(sync_db, e.id) == ["lolbin"]


@pytest.mark.anyio
class TestTheSurfaces:
    async def test_the_rules_page_lists_them_separately(self, member_client, async_db):
        """Their own section, not eighteen rows at the top of "Rules" — which would bury an
        analyst's three under the shipped ones and imply they are theirs to delete."""
        await _seed(async_db)
        await async_db.commit()

        body = (await member_client.get("/intel/rules")).text
        assert "Shared rules" in body
        assert "list:lolbas" in body, "the condition is shown — that is the whole explanation"
        assert "Living-off-the-land binary" in body

    async def test_a_member_cannot_toggle_one(self, member_client, async_db):
        """Instance-wide: a member editing one changes what `lolbin` means for everybody."""
        await _seed(async_db)
        await async_db.commit()
        rule = (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "lolbin"))).scalar_one()

        assert (await member_client.post(f"/intel/rules/{rule.id}/toggle")).status_code == 404
        await async_db.refresh(rule)
        assert rule.enabled is True

    async def test_an_admin_can(self, admin_client, async_db):
        await _seed(async_db)
        await async_db.commit()
        rule = (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "lolbin"))).scalar_one()

        assert (await admin_client.post(f"/intel/rules/{rule.id}/toggle")).status_code == 200
        await async_db.refresh(rule)
        assert rule.enabled is False

    async def test_the_tag_manager_marks_a_built_in_tag(self, member_client, async_db):
        """The mark earns its place: a built-in rule reapplies this tag, so deleting it
        lasts until the next analysis."""
        from app.models import TagDefinition

        # The mark is read from the rules themselves, so the rules have to exist.
        await _seed(async_db)
        async_db.add(TagDefinition(tag="apt29", color="red"))
        await async_db.commit()

        body = (await member_client.get("/intel/tags")).text
        assert "shared rule" in body
        assert "shadowed" not in body


# ── load and save, and the lists ──────────────────────────────────────────────


def _edit_form(**over):
    base = {"name": "Living-off-the-land binary", "scope": "entity", "query": "list:lolbas", "entity_types": ["executable"], "action_tag": "lolbin", "action_tag_color": "orange"}
    base.update(over)
    return base


async def _as(client, email):
    """`admin_client` and `member_client` are one httpx client with one cookie jar — the
    last login wins — so a test that needs both switches explicitly."""
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "testpass123"})
    assert resp.status_code in (200, 204, 303)
    return client


ADMIN, MEMBER = "admin@test.example.com", "member@test.example.com"


@pytest.mark.anyio
class TestLoadAndSave:
    """The Rules page speaks the seed files' format: Download writes it, Import reads it, and
    an admin edits shared rules and lists in place."""

    async def _lolbin(self, db):
        return (await db.execute(select(IntelRule).where(IntelRule.builtin_key == "lolbin"))).scalar_one()

    async def test_an_admin_gets_an_edit_form_for_a_shared_rule_and_a_member_does_not(self, admin_client, member_user, async_db):
        # The form is not on the page — the row offers it and `/form-partial` serves
        # it on the first click. So the question "can this person edit it" is asked of both
        # halves: the offer in the row, and the route behind it.
        await _seed(async_db)
        await async_db.commit()
        rule = await self._lolbin(async_db)
        assert f"/intel/rules/{rule.id}/form-partial" in (await admin_client.get("/intel/rules")).text
        assert f'action="/intel/rules/{rule.id}/edit"' in (await admin_client.get(f"/intel/rules/{rule.id}/form-partial")).text
        member = await _as(admin_client, MEMBER)
        assert f"/intel/rules/{rule.id}/form-partial" not in (await member.get("/intel/rules")).text
        assert (await member.get(f"/intel/rules/{rule.id}/form-partial")).status_code == 404

    async def test_an_admins_edit_survives_the_next_start(self, admin_client, async_db):
        await _seed(async_db)
        await async_db.commit()
        rule = await self._lolbin(async_db)
        assert (await admin_client.post(f"/intel/rules/{rule.id}/edit", data=_edit_form(query="list:lolbas -tag:known-good"))).status_code == 200
        result = await _seed(async_db)
        await async_db.commit()
        await async_db.refresh(rule)
        assert rule.query == "list:lolbas -tag:known-good" and result.updated == 0

    async def test_a_condition_naming_no_list_is_refused_by_the_form(self, member_client):
        resp = await member_client.post("/intel/rules", data=_edit_form(name="Typo", query="list:lolbaz"))
        assert resp.status_code == 400 and "unknown list: lolbaz" in resp.text

    async def test_export_is_the_seed_format_and_shared_content_is_admin_only(self, admin_client, member_user, async_db):
        from app.intel.rules_yaml import parse_rules_yaml

        await _seed(async_db)
        await async_db.commit()
        resp = await admin_client.get("/intel/rules/export.yml")
        assert resp.status_code == 200 and "text/yaml" in resp.headers["content-type"]
        assert 'filename="logstotal-rules.yml"' in resp.headers["content-disposition"]
        assert "key: lolbin" in resp.text and "list:lolbas" in resp.text and "lists:" in resp.text
        doc = parse_rules_yaml(resp.text)
        assert doc.errors == [] and [s.key for s in doc.rules][:2] == ["lolbin", "gtfobin"]
        assert {"gtfobins", "lolbas", "suspicious_tlds"} <= {lspec.name for lspec in doc.lists}
        assert [lspec.name for lspec in doc.lists] == sorted(lspec.name for lspec in doc.lists)  # by name

        member = (await (await _as(admin_client, MEMBER)).get("/intel/rules/export.yml")).text
        assert "key:" not in member and "lolbin" not in member and "lists:" not in member

    async def test_import_creates_then_updates_own_rules_and_is_all_or_nothing(self, member_client, member_user, async_db):
        await _seed(async_db)
        await async_db.commit()
        doc = "rules:\n  - name: Mine\n    condition: 'list:lolbas -tag:known-good'\n    tags: [{name: triage, color: orange}]\n"
        assert "1 rule created, 0 updated" in (await member_client.post("/intel/rules/import", data={"yaml_text": doc})).text
        assert "0 rules created, 1 updated" in (await member_client.post("/intel/rules/import", data={"yaml_text": doc.replace("known-good", "reviewed")})).text
        rows = (await async_db.execute(select(IntelRule).where(IntelRule.owner_user_id == member_user.id))).scalars().all()
        assert len(rows) == 1 and rows[0].query == "list:lolbas -tag:reviewed" and rows[0].is_builtin is False

        bad = doc.replace("Mine", "Other") + "  - name: Broken\n    condition: 're:/^a/ OR tag:x'\n"
        body = (await member_client.post("/intel/rules/import", data={"yaml_text": bad})).text
        assert "Nothing was imported" in body and "cannot be combined with OR" in body
        rows = (await async_db.execute(select(IntelRule).where(IntelRule.owner_user_id == member_user.id))).scalars().all()
        assert [r.name for r in rows] == ["Mine"]

    async def test_a_file_upload_works_too(self, member_client):
        doc = b"rules:\n  - name: Uploaded\n    condition: 'tag:a'\n"
        body = (await member_client.post("/intel/rules/import", files={"file": ("rules.yml", doc, "text/yaml")})).text
        assert "1 rule created, 0 updated" in body

    async def test_an_empty_import_says_so(self, member_client):
        assert "paste a YAML document" in (await member_client.post("/intel/rules/import", data={"yaml_text": ""})).text

    async def test_shared_import_is_admin_only_and_updates_by_key(self, member_client, admin_user, async_db):
        await _seed(async_db)
        await async_db.commit()
        doc = "rules:\n  - key: lolbin\n    name: Living-off-the-land binary\n    entity_types: [executable]\n    condition: 'list:lolbas -tag:known-good'\n    tags: [{name: lolbin, color: orange}]\n"
        assert (await member_client.post("/intel/rules/import", data={"yaml_text": doc, "as_shared": "1"})).status_code == 403
        admin_client = await _as(member_client, ADMIN)
        assert "0 rules created, 1 updated" in (await admin_client.post("/intel/rules/import", data={"yaml_text": doc, "as_shared": "1"})).text
        rule = await self._lolbin(async_db)
        await async_db.refresh(rule)
        assert rule.query == "list:lolbas -tag:known-good" and rule.is_builtin is True and rule.owner_user_id is None

    async def test_a_member_cannot_import_lists(self, member_client):
        body = (await member_client.post("/intel/rules/import", data={"yaml_text": "lists:\n  - name: mine\n    values: [a]\n"})).text
        assert "Nothing was imported" in body and "only an administrator" in body

    async def test_the_page_shows_the_lists_and_what_uses_them(self, member_client, async_db):
        await _seed(async_db)
        await async_db.commit()
        body = (await member_client.get("/intel/rules")).text
        assert "list:lolbas" in body and "72 values, whole value" in body and "5 values, ends with" in body
        assert "used by 1 rule" in body

    async def test_an_admin_creates_edits_and_deletes_a_list_and_a_member_cannot(self, admin_client, member_user, async_db):
        from app.intel.rule_lists import load_lists

        body = (
            await admin_client.post("/intel/rules/lists", data={"name": "Known_Good", "match": "exact", "description": "ours", "values": "agent.exe\nBACKUP.EXE\nagent.exe"})
        ).text
        assert "created with 2 values" in body and "list:known_good" in body
        row, spec = next((r, s) for r, s in await load_lists(async_db) if s.name == "known_good")
        assert spec.values == ("agent.exe", "backup.exe") and row.seed_hash is None

        # A rule can test it at once, and the list then refuses to be deleted.
        assert (await admin_client.post("/intel/rules", data=_edit_form(name="Ours", query="-list:known_good", action_tag=""))).status_code == 200
        resp = await admin_client.post(f"/intel/rules/lists/{row.id}/delete")
        assert resp.status_code == 400 and "used by 1 rule (Ours)" in resp.text

        body = (await admin_client.post(f"/intel/rules/lists/{row.id}/edit", data={"match": "suffix", "description": "", "values": ".corp.example"})).text
        assert "saved with 1 value" in body
        _row, spec = next((r, s) for r, s in await load_lists(async_db) if s.name == "known_good")
        assert spec.match == "suffix" and spec.values == (".corp.example",)

        assert (await admin_client.post("/intel/rules/lists", data={"name": "known_good", "values": "x"})).status_code == 400
        assert (await admin_client.post("/intel/rules/lists", data={"name": "Bad Name", "values": "x"})).status_code == 400

        member = await _as(admin_client, MEMBER)
        assert (await member.post("/intel/rules/lists", data={"name": "theirs", "values": "x"})).status_code == 403
        assert (await member.post(f"/intel/rules/lists/{row.id}/edit", data={"values": "x"})).status_code == 403
        assert (await member.post(f"/intel/rules/lists/{row.id}/delete")).status_code == 403

    async def test_a_list_nothing_uses_can_be_deleted(self, admin_client, async_db):
        from app.intel.rule_lists import load_lists

        await admin_client.post("/intel/rules/lists", data={"name": "spare", "values": "x"})
        row = next(r for r, s in await load_lists(async_db) if s.name == "spare")
        assert "deleted" in (await admin_client.post(f"/intel/rules/lists/{row.id}/delete")).text
        assert not [s for _r, s in await load_lists(async_db) if s.name == "spare"]

    async def test_a_new_list_feeds_a_rule_end_to_end(self, sync_db):
        """The whole point of editable lists: a value added on the page tags on the next job."""
        u = _user(sync_db)
        job = _job(sync_db, owner=u)
        hit = _entity(sync_db, job, "ours.exe")
        lst = RuleList(name="ours", match="exact")
        sync_db.add(lst)
        sync_db.flush()
        sync_db.add(RuleListValue(list_id=lst.id, value="ours.exe", pattern=value_pattern("ours.exe", "exact")))
        sync_db.add(IntelRule(name="Ours", owner_user_id=u.id, scope="entity", query="list:ours", entity_types="[]", action_tag="ours", action_notify=False))
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert _tags(sync_db, hit.id) == ["ours"]


# ── the analyst rules ─────────────────────────────────────────────────────────


class TestTheAnalystRules:
    """The CTI/DFIR defaults shipped beside the labels: tooling, persistence, accounts,
    network, and three job-triage rules. Every shipped rule is seeded, so a value that
    should carry one tag and quietly picks up a second is caught here."""

    @pytest.fixture(autouse=True)
    def _worker_session(self, sync_db, monkeypatch):
        from app.workers import tasks as tasks_mod

        monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
        monkeypatch.setattr(sync_db, "close", lambda: None)

    def test_every_entity_rule_tags_what_it_says_and_nothing_else(self, sync_db):
        from app.intel.attributes import compute_attributes
        from app.workers.tasks import backfill_builtin_labels

        samples = [
            ("mimikatz.exe", "executable", {"offsec_tool"}),
            ("secretsdump.py", "cmdline_file", {"offsec_tool"}),
            ("anydesk.exe", "executable", {"remote_access"}),
            ("7z.exe", "executable", {"staging_tool"}),
            ("custom.exe", "executable", set()),
            ("payload.ps1", "cmdline_file", {"script_file"}),
            ("Invoice.SCR", "cmdline_file", {"odd_extension"}),
            ("helper.dll", "cmdline_file", set()),
            ("C:\\Users\\bob\\AppData\\Roaming\\svc.exe", "service", {"service_userpath"}),
            ("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", "service", {"service_lolbin", "encoded_command"}),
            ("C:\\Windows\\System32\\svchost.exe -k netsvcs", "service", {"signed_path"}),
            ("<Command>C:\\Windows\\System32\\mshta.exe</Command>", "task", {"task_lolbin"}),
            ("\\Microsoft\\Windows\\PowerShell\\ScheduledJobs\\Job1", "task", set()),
            ("<Command>C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe</Command>", "task", {"task_userpath"}),
            ("Guest", "user", {"builtin_account"}),
            ("ANONYMOUS LOGON", "user", {"anonymous_logon"}),
            ("alice", "user", set()),
            ("c2.duckdns.org", "domain", {"dyndns"}),
            ("cdn.discordapp.com", "domain", {"sharing_site"}),
            ("login-micros0ft.com", "domain", {"lookalike"}),
            ("login.microsoft.com", "domain", set()),
            ("DC01", "computer", {"domain_controller"}),
            ("srv-dc02", "computer", {"domain_controller"}),
            ("ws-042", "computer", set()),
        ]
        made = []
        for value, etype, expected in samples:
            e = Entity(value=value, entity_type=etype, job_count=0, attributes_json=json_dumps(compute_attributes(value, etype) or {}))
            sync_db.add(e)
            made.append((e, expected))
        for key in SHIPPED_RULES:
            rule = _builtin(sync_db, key)
            if key == "lookalike":
                rule.enabled = True  # shipped off; its condition is under test here
        sync_db.commit()

        backfill_builtin_labels.call_local()

        for e, expected in made:
            sync_db.refresh(e)
            assert set(_tags(sync_db, e.id)) == expected, f"{e.value}: got {_tags(sync_db, e.id)}, expected {sorted(expected)}"

    def _finished_job(self, db, *, owner, status=JobStatus.COMPLETED, findings=0, severity="critical"):
        job = _job(db, owner=owner)
        job.status = status
        job.total_findings = findings
        if findings:
            tr = TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=findings)
            db.add(tr)
            db.flush()
            for i in range(findings):
                db.add(Finding(task_result_id=tr.id, rule_id=f"r{i}", rule_name=f"Rule {i}", severity=severity, count=1))
        db.flush()
        return job

    def _job_tags(self, db, job_id):
        return sorted(db.execute(select(JobTag.tag).where(JobTag.job_id == job_id)).scalars().all())

    def test_the_job_triage_rules_tag_the_job(self, sync_db):
        u = _user(sync_db)
        hot = self._finished_job(sync_db, owner=u, findings=2, severity="high")
        reviewed = self._finished_job(sync_db, owner=u, findings=1, severity="critical")
        sync_db.add(JobTag(job_id=reviewed.id, tag="reviewed", color="gray"))
        partial = self._finished_job(sync_db, owner=u, status=JobStatus.PARTIAL, findings=1, severity="low")
        clean = self._finished_job(sync_db, owner=u, findings=0)
        for key in ("needs_triage", "rerun", "clean"):
            _builtin(sync_db, key)
        sync_db.commit()

        for job in (hot, reviewed, partial, clean):
            evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert self._job_tags(sync_db, hot.id) == ["needs_triage"]
        assert self._job_tags(sync_db, reviewed.id) == ["reviewed"]
        assert self._job_tags(sync_db, partial.id) == ["rerun"]
        assert self._job_tags(sync_db, clean.id) == ["clean"]

    def test_the_job_rules_reach_a_private_job_and_write_no_ledger(self, sync_db):
        """The same exemption the label rules have, for the same reason: a shared job rule
        only tags, so nothing leaves the instance and nobody's bell rings."""
        from app.models import JobRuleMatch

        submitter = _user(sync_db, "sub@x.test")
        job = self._finished_job(sync_db, owner=submitter, findings=1, severity="critical")
        job.is_private = True
        _builtin(sync_db, "needs_triage")
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert self._job_tags(sync_db, job.id) == ["needs_triage"]
        assert sync_db.execute(select(JobRuleMatch)).scalars().all() == []

    def test_the_site_switch_stops_the_job_rules_too(self, sync_db):
        u = _user(sync_db)
        job = self._finished_job(sync_db, owner=u, findings=1, severity="critical")
        _builtin(sync_db, "needs_triage")
        sync_db.add(SiteSettings(id=1, builtin_rules_enabled=False))
        sync_db.commit()

        evaluate_job_rules_for_job(sync_db, job.id)
        sync_db.commit()
        assert self._job_tags(sync_db, job.id) == []


class TestTheCopyDescribesTheRulesThatShip:
    """Admin text and docs still described the first cut: a `dga` shared rule (dropped —
    an entropy heuristic in code is not a condition anyone can read), "fifteen more" (36
    ship), and "run the Entity Attribute Backfill first", which only mattered while rules
    tested `attr:` terms. Shared rules test `list:` rows now, so an admin who followed that
    advice after editing the threat config saw no change and concluded the backfill was
    broken."""

    COPY = (
        "app/routers/admin.py",
        "app/task_registry.py",
        "app/templates/admin/settings.html",
        "app/templates/docs/index.html",
        "docs/reference/admin-ui.md",
        "docs/runbooks/upgrading.md",
    )

    def _texts(self):
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        return {p: (root / p).read_text() for p in self.COPY}

    def test_no_copy_names_a_dga_rule(self):
        import re

        for path, text in self._texts().items():
            assert not re.search(r"lolbin\W+dga\W+privileged|\bdga\W{0,3}\s+rule\b|\(the dga rule\)", text, re.I), path

    def test_no_copy_miscounts_the_shared_rules(self):
        for path, text in self._texts().items():
            assert "fifteen more" not in text, path

    def test_the_maintenance_row_does_not_send_admins_to_the_attribute_backfill(self):
        from app.routers.admin import MAINTENANCE_ACTIONS

        row = next(a for a in MAINTENANCE_ACTIONS if a["key"] == "builtin-labels")
        assert "dga" not in row["description"]
        assert "Attribute Backfill first" not in row["details"]
