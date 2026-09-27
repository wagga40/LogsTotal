"""Delete a job and a user with foreign keys actually enforced.

The rest of the suite runs on SQLite, which has FK enforcement **off** by default — so a
dangling reference passes every existing test and only surfaces as a 500 on a production
PostgreSQL. These tests turn ``PRAGMA foreign_keys=ON`` on their own engine, which is what
makes them able to catch the class of bug they exist for.

Both scenarios put a watch rule in the picture, because that is where the gaps were: an
``IntelRuleMatch`` row (NOT NULL job FK) and a ``WebhookDelivery`` row survived a job
delete, and ``IntelRule``/``IntelRuleMatch``/``TagDefinition`` survived a user delete.

The entity is deliberately linked to a *second* job, so it is not an orphan when the first
job goes: the orphan path in ``remove_entity_links_for_job_async`` already cleaned these
tables, which is exactly why the gap stayed hidden.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.models  # noqa: F401 — populate Base.metadata
from app.database import Base
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    IntelRule,
    IntelRuleMatch,
    JobRuleMatch,
    JobStatus,
    LogFile,
    TagDefinition,
    User,
    WebhookDelivery,
    WorkflowDef,
)


@pytest_asyncio.fixture
async def fk_db():
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enforce_fks(dbapi_conn, _record):  # pragma: no cover - trivial
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _seed(db):
    """One user, one log file, two jobs sharing an entity, and a watch rule that fired."""
    user = User(id=uuid.uuid4(), email="analyst@example.com", hashed_password="x", is_superuser=False, is_active=True)
    workflow = WorkflowDef(name="w", tasks_yaml="tasks: []", log_types="[]")
    log_file = LogFile(original_filename="f.evtx", stored_filename="s.evtx", sha256="h", size_bytes=1, log_type="evtx")
    db.add_all([user, workflow, log_file])
    await db.commit()

    job = AnalysisJob(file_id=log_file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED)
    other_job = AnalysisJob(file_id=log_file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED)
    entity = Entity(value="10.0.0.9", entity_type="ip_address")
    db.add_all([job, other_job, entity])
    await db.commit()

    db.add_all([EntityJobLink(entity_id=entity.id, job_id=job.id), EntityJobLink(entity_id=entity.id, job_id=other_job.id)])
    rule = IntelRule(name="watch 10.0.0.9", owner_user_id=user.id, auto_entity_id=entity.id, query="10.0.0.9")
    db.add_all([rule, TagDefinition(tag="apt29", created_by_user_id=user.id)])
    await db.commit()

    db.add_all(
        [
            IntelRuleMatch(rule_id=rule.id, entity_id=entity.id, job_id=job.id, acknowledged_by_user_id=user.id),
            WebhookDelivery(rule_id=rule.id, job_id=job.id),
        ]
    )
    await db.commit()
    return user, job


@pytest.mark.asyncio
async def test_deleting_a_job_that_raised_a_watch_alert(fk_db):
    from app.routers.jobs import _delete_job

    _user, job = await _seed(fk_db)
    job_id = job.id

    await _delete_job(fk_db, await fk_db.get(AnalysisJob, job_id))

    assert await fk_db.get(AnalysisJob, job_id) is None
    # The alert and its delivery attempt go with the job — left behind, they keep the nav
    # bell's count non-zero over a dropdown that inner-joins AnalysisJob and finds nothing.
    assert (await fk_db.execute(select(IntelRuleMatch).where(IntelRuleMatch.job_id == job_id))).first() is None
    assert (await fk_db.execute(select(WebhookDelivery).where(WebhookDelivery.job_id == job_id))).first() is None
    # The rule itself is untouched: it belongs to the user, not to the job.
    assert (await fk_db.execute(select(IntelRule))).scalars().all() != []


@pytest.mark.asyncio
async def test_deleting_a_user_who_owned_a_watch_rule(fk_db):
    from app.routers.admin import _clear_user_references

    user, _job = await _seed(fk_db)

    await _clear_user_references(fk_db, user.id)
    await fk_db.delete(await fk_db.get(User, user.id))
    await fk_db.commit()

    # Authorship is anonymised — the team keeps the tag vocabulary.
    assert (await fk_db.execute(select(TagDefinition.created_by_user_id))).scalar() is None
    # The rule is deleted, not orphaned: an ownerless enabled rule keeps evaluating every
    # finished job and POSTing to a webhook nobody owns.
    assert (await fk_db.execute(select(IntelRule))).scalars().all() == []
    assert (await fk_db.execute(select(IntelRuleMatch))).scalars().all() == []
    assert (await fk_db.execute(select(WebhookDelivery))).scalars().all() == []


@pytest.mark.asyncio
async def test_deleting_the_last_job_of_a_watched_entity_whose_rule_now_watches_jobs(fk_db):
    """A star makes a personal rule tied to its entity, and the rule can then be switched to
    job scope. When the entity's last job goes, the orphan cleanup deletes that rule — and
    its job alerts reference it. Missing them failed the whole job delete."""
    from app.routers.jobs import _delete_job

    user = User(id=uuid.uuid4(), email="star@example.com", hashed_password="x", is_superuser=False, is_active=True)
    workflow = WorkflowDef(name="w", tasks_yaml="tasks: []", log_types="[]")
    log_file = LogFile(original_filename="f.evtx", stored_filename="s.evtx", sha256="h", size_bytes=1, log_type="evtx")
    fk_db.add_all([user, workflow, log_file])
    await fk_db.commit()
    only_job = AnalysisJob(file_id=log_file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED)
    matched_job = AnalysisJob(file_id=log_file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED)
    entity = Entity(value="evil.exe", entity_type="executable")
    fk_db.add_all([only_job, matched_job, entity])
    await fk_db.commit()
    fk_db.add(EntityJobLink(entity_id=entity.id, job_id=only_job.id))
    rule = IntelRule(name="evil.exe", owner_user_id=user.id, auto_entity_id=entity.id, query="evil", scope="job")
    fk_db.add(rule)
    await fk_db.commit()
    fk_db.add(JobRuleMatch(rule_id=rule.id, job_id=matched_job.id))
    await fk_db.commit()

    await _delete_job(fk_db, await fk_db.get(AnalysisJob, only_job.id))

    assert (await fk_db.execute(select(IntelRule))).scalars().all() == []
    assert (await fk_db.execute(select(JobRuleMatch))).scalars().all() == []
