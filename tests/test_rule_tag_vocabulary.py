"""A tag a rule applies is a tag, and it has to join the vocabulary like any other.

Every human write path calls `tags.ensure_tag_definition` — `entities_bulk_tag`,
`tag_create`, `entity_tag_add`, `jobs_bulk_tag`, `job_tag_add` — and `rules.py::_apply_tag`
must too. Reading `TagDefinition.color` to avoid repainting an existing tag without ever
inserting the row would leave a tag coined by a rule absent from `/intel/tags` until the
rule first fires, and gone again the moment its last `EntityTag` row is removed — unlike a
tag coined by hand, which the vocabulary keeps.

`ensure_tag_definition` is `async` and the rule engine runs in the worker, sync. Hence a
twin, the `activity.py` shape.

Two halves, and the first is the one that answers the complaint:

* **On save.** Naming a tag in a rule's Auto-tag field puts it in the vocabulary
  immediately. Waiting for a match means the tag manager cannot show you a vocabulary you
  have just finished designing.
* **On apply.** The worker registers anything that reaches it by another route — a seeded
  built-in rule, a row written straight into the table — so the invariant holds however the
  tag arrived.

The savepoint matters too. Handling the insert race with a plain `db.rollback()` discards
the **whole** outer transaction rather than the failed insert. Inside
`evaluate_rules_for_job`, which runs every rule in one transaction, that is the exact
failure `_record_matches`' savepoints exist to prevent: a collision on rule five wipes rules
one to four.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

import app.models  # noqa: F401 — populate Base.metadata
from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.intel.rules import evaluate_rules_for_job
from app.json_utils import dumps as json_dumps
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    EntityTag,
    IntelRule,
    JobStatus,
    LogFile,
    LogType,
    TagDefinition,
    User,
    WorkflowDef,
)

pytestmark_async = pytest.mark.anyio


# ── the worker half (sync) ───────────────────────────────────────────────────


def _sync_user(db, email="owner@x.test"):
    u = User(id=uuid.uuid4(), email=email, hashed_password="x", is_active=True, is_superuser=False, role="member")
    db.add(u)
    db.flush()
    return u


def _sync_job(db, owner):
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


def _sync_entity(db, job, value="certutil.exe"):
    e = Entity(value=value, entity_type="executable", job_count=1, attributes_json=json_dumps({"is_lolbin": True}))
    db.add(e)
    db.flush()
    db.add(EntityJobLink(entity_id=e.id, job_id=job.id, occurrence_count=1))
    db.flush()
    return e


def _definitions(db) -> dict[str, str]:
    return dict(db.execute(select(TagDefinition.tag, TagDefinition.color)).all())


class TestTheWorkerRegistersWhatItApplies:
    def test_a_rule_firing_registers_its_tag(self, sync_db):
        owner = _sync_user(sync_db)
        job = _sync_job(sync_db, owner)
        _sync_entity(sync_db, job)
        sync_db.add(IntelRule(name="R", owner_user_id=owner.id, query="label:lolbin", entity_types="[]", action_tag="triage", action_tag_color="red"))
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _definitions(sync_db) == {"triage": "red"}

    def test_the_tag_survives_its_last_entity(self, sync_db):
        """The whole point of `TagDefinition`: a vocabulary outlives what carries it."""
        owner = _sync_user(sync_db)
        job = _sync_job(sync_db, owner)
        entity = _sync_entity(sync_db, job)
        sync_db.add(IntelRule(name="R", owner_user_id=owner.id, query="label:lolbin", entity_types="[]", action_tag="triage", action_tag_color="red"))
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        sync_db.execute(EntityTag.__table__.delete().where(EntityTag.entity_id == entity.id))
        sync_db.commit()

        assert "triage" in _definitions(sync_db)

    def test_it_does_not_repaint_a_tag_that_already_has_a_colour(self, sync_db):
        """Registering must not become the recolour `_apply_tag` deliberately avoids."""
        owner = _sync_user(sync_db)
        job = _sync_job(sync_db, owner)
        _sync_entity(sync_db, job)
        sync_db.add(TagDefinition(tag="triage", color="blue"))
        sync_db.add(IntelRule(name="R", owner_user_id=owner.id, query="label:lolbin", entity_types="[]", action_tag="triage", action_tag_color="red"))
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _definitions(sync_db) == {"triage": "blue"}

    def test_registering_twice_is_harmless(self, sync_db):
        owner = _sync_user(sync_db)
        job = _sync_job(sync_db, owner)
        _sync_entity(sync_db, job)
        sync_db.add(IntelRule(name="R", owner_user_id=owner.id, query="label:lolbin", entity_types="[]", action_tag="triage,review", action_tag_color="red,blue"))
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()
        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _definitions(sync_db) == {"triage": "red", "review": "blue"}

    def test_a_definition_collision_does_not_discard_the_rules_before_it(self, sync_db):
        """`db.rollback()` here would take out every earlier rule's work.

        The async twin still used one; this asserts the sync path uses a savepoint, by
        driving a real duplicate through the pre-check via a second rule naming the same
        tag in the same pass.
        """
        owner = _sync_user(sync_db)
        job = _sync_job(sync_db, owner)
        _sync_entity(sync_db, job)
        sync_db.add(IntelRule(name="first", owner_user_id=owner.id, query="label:lolbin", entity_types="[]", action_tag="alpha", action_tag_color="red"))
        sync_db.add(IntelRule(name="second", owner_user_id=owner.id, query="label:lolbin", entity_types="[]", action_tag="alpha", action_tag_color="blue"))
        sync_db.commit()

        evaluate_rules_for_job(sync_db, job.id)
        sync_db.commit()

        assert _definitions(sync_db) == {"alpha": "red"}
        assert sync_db.execute(select(EntityTag.tag)).scalars().all() == ["alpha"]


# ── the save half (async, through the real route) ────────────────────────────


async def _member(async_db) -> User:
    manager = UserManager(SQLAlchemyUserDatabase(async_db, User))
    return await manager.create(UserCreate(email="rules@example.com", password="pass123456", is_superuser=False, is_active=True, role="member"))


@pytest.fixture()
async def logged_in(test_client, async_db):
    await _member(async_db)
    resp = await test_client.post("/auth/cookie/login", data={"username": "rules@example.com", "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text
    return test_client


@pytest.mark.anyio
class TestNamingATagInARuleCoinsIt:
    async def test_creating_a_rule_registers_its_tags_immediately(self, logged_in, async_db):
        """The complaint: the tag manager should not need a matching job to know the name."""
        resp = await logged_in.post(
            "/intel/rules",
            data={"name": "r", "query": "evil", "action_tag": "triage,review", "action_tag_color": "red,blue"},
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303), resp.text

        rows = dict((await async_db.execute(select(TagDefinition.tag, TagDefinition.color))).all())
        assert rows == {"triage": "red", "review": "blue"}

    async def test_the_new_tag_shows_up_in_the_manager(self, logged_in):
        await logged_in.post("/intel/rules", data={"name": "r", "query": "evil", "action_tag": "triage", "action_tag_color": "red"}, follow_redirects=False)
        body = (await logged_in.get("/intel/tags")).text
        assert "triage" in body

    async def test_editing_a_rule_registers_a_newly_named_tag(self, logged_in, async_db):
        await logged_in.post("/intel/rules", data={"name": "r", "query": "evil", "action_tag": "triage", "action_tag_color": "red"}, follow_redirects=False)
        rule = (await async_db.execute(select(IntelRule))).scalars().one()

        await logged_in.post(
            f"/intel/rules/{rule.id}/edit",
            data={"name": "r", "query": "evil", "action_tag": "triage,escalate", "action_tag_color": "red,orange"},
            follow_redirects=False,
        )
        rows = dict((await async_db.execute(select(TagDefinition.tag, TagDefinition.color))).all())
        assert rows == {"triage": "red", "escalate": "orange"}

    async def test_it_does_not_repaint_an_existing_tag(self, logged_in, async_db):
        """Same restraint as the worker: naming a tag is not recolouring it."""
        async_db.add(TagDefinition(tag="triage", color="blue"))
        await async_db.commit()

        await logged_in.post("/intel/rules", data={"name": "r", "query": "evil", "action_tag": "triage", "action_tag_color": "red"}, follow_redirects=False)

        rows = dict((await async_db.execute(select(TagDefinition.tag, TagDefinition.color))).all())
        assert rows == {"triage": "blue"}

    async def test_a_rule_with_no_tags_registers_nothing(self, logged_in, async_db):
        await logged_in.post("/intel/rules", data={"name": "r", "query": "evil"}, follow_redirects=False)
        assert (await async_db.execute(select(TagDefinition))).scalars().all() == []
