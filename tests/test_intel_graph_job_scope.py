"""`job_id` narrows the graph to what one job observed — and does not narrow everything.

The entity graph draws an entity's whole observed neighbourhood across every job it ever
appeared in, which on a mature database is a hairball. Scoping it to one job is what makes
it readable, so the Graph tab refuses to draw until a job is chosen.

The scope is deliberately **not uniform**, and most of these tests are about the seams:

* Nodes and the job/finding edges between them are job-scoped. That is the feature.
* `_typed_edges` is not, because `EntityRelationship` has no job column and the only
  per-job record (`EntityRelationshipEvidence`) is incomplete for historical edges —
  filtering through it would silently drop real relationships.
* `fetch_threat_columns` is not, because its four columns are properties of the entity
  rather than facts about the job, and case membership has no job dimension at all.

Two more things that only look like details:

* `MAX_JOB_FANOUT` has to come off under a job scope. Its candidate set is then that one
  job, so any job touching more than the fanout would lose 100% of its edges and the
  banner would report "1 job excluded as a near-clique" about the only job in the picture.
* `stats.total_nodes` flips from null to exact. Every hop is constrained to the job, so
  the reachable set *is* the job's entity set — the one thing the scope gives away free.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.models  # noqa: F401 — populate Base.metadata
from app.database import Base
from app.intel.graph import JOB_SCOPE_MAX_NODES, build_entity_graph
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    EntityRelationship,
    Finding,
    FindingEntityLink,
    JobStatus,
    LogFile,
    Severity,
    TaskResult,
    TaskStatus,
    WorkflowDef,
)
from tests.conftest import decode_graph


@pytest_asyncio.fixture()
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as sess:
        yield sess
    await engine.dispose()


async def _base(db):
    db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="x" * 64, size_bytes=1))
    db.add(WorkflowDef(id=1, name="wf1"))
    await db.commit()


async def _job(db, jid, *, private=False):
    j = AnalysisJob(id=jid, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=private)
    db.add(j)
    await db.commit()
    return j


async def _entity(db, eid, value, etype="ip_address", *, allowlisted=False):
    e = Entity(id=eid, value=value, entity_type=etype, allowlisted=allowlisted, job_count=1)
    db.add(e)
    await db.commit()
    return e


async def _link(db, eid, jid, occurrence_count=1):
    db.add(EntityJobLink(entity_id=eid, job_id=jid, occurrence_count=occurrence_count))
    await db.commit()


def _ids(payload) -> set[int]:
    return {n["data"]["entity_id"] for n in decode_graph(payload)["nodes"]}


def _kinds(payload) -> list[str]:
    return [e["data"]["kind"] for e in decode_graph(payload)["edges"]]


# ─── The node set ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_only_entities_from_that_job_are_discovered(db):
    await _base(db)
    ja, jb = await _job(db, 1), await _job(db, 2)
    focal = await _entity(db, 1, "10.0.0.1")
    in_a = await _entity(db, 2, "10.0.0.2")
    in_b = await _entity(db, 3, "10.0.0.3")
    for eid in (focal.id, in_a.id):
        await _link(db, eid, ja.id)
    for eid in (focal.id, in_b.id):
        await _link(db, eid, jb.id)

    unscoped = _ids(await build_entity_graph(db, focal.id))
    assert unscoped == {1, 2, 3}

    assert _ids(await build_entity_graph(db, focal.id, job_id=ja.id)) == {1, 2}
    assert _ids(await build_entity_graph(db, focal.id, job_id=jb.id)) == {1, 3}


@pytest.mark.asyncio
async def test_a_job_the_entity_never_appeared_in_yields_only_the_focal_node(db):
    await _base(db)
    ja, jb = await _job(db, 1), await _job(db, 2)
    focal = await _entity(db, 1, "10.0.0.1")
    other = await _entity(db, 2, "10.0.0.2")
    await _link(db, focal.id, ja.id)
    await _link(db, other.id, jb.id)

    payload = await build_entity_graph(db, focal.id, job_id=jb.id)
    assert _ids(payload) == {focal.id}


# ─── stats ───────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_total_nodes_is_null_unscoped_and_exact_when_scoped(db):
    await _base(db)
    j = await _job(db, 1)
    focal = await _entity(db, 1, "10.0.0.1")
    for i in range(2, 6):
        e = await _entity(db, i, f"10.0.0.{i}")
        await _link(db, e.id, j.id)
    await _link(db, focal.id, j.id)

    # A traversal never learns the true total, so unscoped it declines to guess.
    assert (await build_entity_graph(db, focal.id))["stats"]["total_nodes"] is None

    scoped = await build_entity_graph(db, focal.id, job_id=j.id)
    assert scoped["stats"]["total_nodes"] == 5  # focal + four neighbours
    assert scoped["stats"]["job_scoped"] is True
    assert scoped["stats"]["job_id"] == j.id


@pytest.mark.asyncio
async def test_total_nodes_respects_the_same_allowlist_filter_the_traversal_used(db):
    """Otherwise the banner reads "3 of 4" against a universe it could never reach 4 of."""
    await _base(db)
    j = await _job(db, 1)
    focal = await _entity(db, 1, "10.0.0.1")
    plain = await _entity(db, 2, "10.0.0.2")
    muted = await _entity(db, 3, "10.0.0.3", allowlisted=True)
    for e in (focal, plain, muted):
        await _link(db, e.id, j.id)

    default = await build_entity_graph(db, focal.id, job_id=j.id)
    assert default["stats"]["total_nodes"] == 2
    assert _ids(default) == {1, 2}

    opened = await build_entity_graph(db, focal.id, job_id=j.id, include_allowlisted=True)
    assert opened["stats"]["total_nodes"] == 3


@pytest.mark.asyncio
async def test_stats_are_unscoped_shaped_when_no_job_is_given(db):
    await _base(db)
    j = await _job(db, 1)
    focal = await _entity(db, 1, "10.0.0.1")
    await _link(db, focal.id, j.id)

    stats = (await build_entity_graph(db, focal.id))["stats"]
    assert stats["job_scoped"] is False
    assert stats["job_id"] is None


# ─── The near-clique guard has to come off ───────────────────────────────────────


@pytest.mark.asyncio
async def test_the_fanout_guard_does_not_suppress_the_only_job_in_the_picture(db):
    """Unscoped, MAX_JOB_FANOUT drops near-clique jobs. Scoped, that job *is* the request.

    Seeded past the guard's threshold so the unscoped build genuinely suppresses it —
    otherwise this test would pass without the scoped exemption.

    The guard fires in the **traversal** (`_neighbors_for_hop` excludes hot jobs)
    rather than only in `_job_co_edges`, so the near-clique's entities are never
    discovered at all. `job_fanout_suppressed` still reports it: a guard that empties the
    picture and says nothing would be the graph lying about what it drew.
    """
    from app.intel.graph import MAX_JOB_FANOUT

    await _base(db)
    j = await _job(db, 1)
    focal = await _entity(db, 1, "10.0.0.1")
    await _link(db, focal.id, j.id)
    for i in range(2, MAX_JOB_FANOUT + 3):
        e = await _entity(db, i, f"10.0.{i // 256}.{i % 256}")
        await _link(db, e.id, j.id)

    unscoped = await build_entity_graph(db, focal.id, limit=500)
    assert unscoped["stats"]["job_fanout_suppressed"] == 1
    # Nothing was traversed *through* the near-clique, so nothing but the focal node is
    # drawn and there are no job edges to draw between them.
    n_neighbours = unscoped["stats"]["nodes"] - 1
    assert unscoped["stats"]["kinds"].get("job", 0) == 0

    scoped = await build_entity_graph(db, focal.id, limit=500, job_id=j.id)
    assert scoped["stats"]["job_fanout_suppressed"] == 0
    assert scoped["stats"]["kinds"]["job"] > n_neighbours, "the pairs the guard was hiding must come back"


@pytest.mark.asyncio
async def test_the_node_ceiling_is_clamped_under_a_job_scope(db):
    """`min()`, never an override — the 500-node export budget must stay the smaller one."""
    await _base(db)
    j = await _job(db, 1)
    focal = await _entity(db, 1, "10.0.0.1")
    await _link(db, focal.id, j.id)

    scoped = await build_entity_graph(db, focal.id, job_id=j.id, max_nodes=5000)
    assert scoped["stats"]["nodes"] <= JOB_SCOPE_MAX_NODES

    # A caller asking for less still gets less.
    tiny = await build_entity_graph(db, focal.id, job_id=j.id, max_nodes=1)
    assert tiny["stats"]["nodes"] == 1


@pytest.mark.asyncio
async def test_neighbours_are_ranked_by_within_job_occurrence_when_scoped(db):
    """Shared-job count is 1 for every pair under a job scope, so it cannot rank.

    Without the swap to `occurrence_count`, `ROW_NUMBER()` orders by a constant and the
    `limit` picks an arbitrary set by entity id — here, the two least interesting ones.
    """
    await _base(db)
    j = await _job(db, 1)
    focal = await _entity(db, 1, "10.0.0.1")
    await _link(db, focal.id, j.id, occurrence_count=1)
    # Deliberately inverted: the lowest ids have the lowest occurrence counts.
    for i in range(2, 7):
        e = await _entity(db, i, f"10.0.0.{i}")
        await _link(db, e.id, j.id, occurrence_count=i * 10)

    payload = await build_entity_graph(db, focal.id, job_id=j.id, limit=2)
    # Top two by occurrence_count are ids 6 and 5, not 2 and 3.
    assert _ids(payload) == {1, 6, 5}


# ─── The seams: what stays global ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_typed_edges_are_still_unfiltered_under_a_job_scope(db):
    """Not an oversight. `EntityRelationship` has no job column, and the per-job record is
    incomplete for older edges — filtering through it would hide real relationships.

    The node set is already job-scoped, so a typed edge here is a true statement about two
    entities this job saw. It just is not a statement about this job, which is why
    `_graph_help.html` spells that out under a job scope.
    """
    await _base(db)
    j = await _job(db, 1)
    a = await _entity(db, 1, "10.0.0.1")
    b = await _entity(db, 2, "host", etype="computer")
    await _link(db, a.id, j.id)
    await _link(db, b.id, j.id)
    # The edge itself carries no job, and no evidence row exists for it at all.
    db.add(EntityRelationship(source_entity_id=a.id, target_entity_id=b.id, relationship_type="runs_on", occurrence_count=1))
    await db.commit()

    payload = await build_entity_graph(db, a.id, job_id=j.id)
    assert "typed" in _kinds(payload), "a typed edge with no evidence row must still render"


@pytest.mark.asyncio
async def test_finding_edges_are_scoped_because_their_colour_promises_it(db):
    """An amber "same Sigma finding" edge from a different job is the one edge whose
    appearance actively misleads under a job scope."""
    await _base(db)
    ja, jb = await _job(db, 1), await _job(db, 2)
    a = await _entity(db, 1, "10.0.0.1")
    b = await _entity(db, 2, "10.0.0.2")
    for e in (a, b):
        await _link(db, e.id, ja.id)
        await _link(db, e.id, jb.id)

    # The only shared finding lives in job B.
    tr = TaskResult(job_id=jb.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=1)
    db.add(tr)
    await db.commit()
    f = Finding(task_result_id=tr.id, rule_name="Shared", severity=Severity.HIGH, count=1)
    db.add(f)
    await db.commit()
    db.add_all([FindingEntityLink(finding_id=f.id, entity_id=a.id), FindingEntityLink(finding_id=f.id, entity_id=b.id)])
    await db.commit()

    assert "finding" in _kinds(await build_entity_graph(db, a.id, job_id=jb.id))
    assert "finding" not in _kinds(await build_entity_graph(db, a.id, job_id=ja.id))


@pytest.mark.asyncio
async def test_a_private_job_scope_narrows_to_nothing_rather_than_widening(db):
    """Belt and braces on top of the route's explicit refusal.

    `visible_job_filter` still applies underneath `job_id`, so even an unvalidated id can
    only ever narrow the result — never widen it back to every job.
    """
    from types import SimpleNamespace

    await _base(db)
    public = await _job(db, 1)
    secret = await _job(db, 2, private=True)
    focal = await _entity(db, 1, "10.0.0.1")
    hidden = await _entity(db, 2, "10.0.0.2")
    await _link(db, focal.id, public.id)
    await _link(db, focal.id, secret.id)
    await _link(db, hidden.id, secret.id)

    stranger = SimpleNamespace(id="00000000-0000-0000-0000-000000000009", is_superuser=False, role="member")
    payload = await build_entity_graph(db, focal.id, viewer=stranger, job_id=secret.id)
    assert _ids(payload) == {focal.id}
    assert payload["stats"]["total_nodes"] == 0
