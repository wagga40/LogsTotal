"""Tier-2 tests for the relationship graph builders against an in-memory SQLite DB.

`build_entity_graph` and `neighbors_of` are async-only — exercised via pytest-asyncio.
`build_case_graph` is similarly async.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.models  # noqa: F401 — populate Base.metadata
from app.database import Base
from app.intel.graph import build_case_graph, build_entity_graph, neighbors_of
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    JobStatus,
    LogFile,
    Severity,
    TaskStatus,
    WorkflowDef,
)
from tests.conftest import decode_graph


@pytest_asyncio.fixture()
async def async_session():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as sess:
        yield sess
    await engine.dispose()


async def _seed_logfile_and_workflow(db):
    db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="x" * 64, size_bytes=1))
    db.add(WorkflowDef(id=1, name="wf1"))
    await db.commit()


async def _seed_job(db, jid):
    job = AnalysisJob(id=jid, file_id=1, workflow_id=1, status=JobStatus.COMPLETED)
    db.add(job)
    await db.commit()
    return job


async def _seed_entity(db, eid, value, etype="ip_address", *, watchlist=False, allowlisted=False, job_count=1):
    e = Entity(
        id=eid,
        value=value,
        entity_type=etype,
        watchlist=watchlist,
        allowlisted=allowlisted,
        job_count=job_count,
    )
    db.add(e)
    await db.commit()
    return e


async def _link(db, entity_id, job_id):
    db.add(EntityJobLink(entity_id=entity_id, job_id=job_id))
    await db.commit()


@pytest.mark.asyncio
class TestNeighborsOf:
    async def test_returns_entities_sharing_jobs(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        focal = await _seed_entity(async_session, 1, "10.0.0.1")
        n1 = await _seed_entity(async_session, 2, "10.0.0.2")
        n2 = await _seed_entity(async_session, 3, "evil.example", etype="domain")
        await _link(async_session, focal.id, j.id)
        await _link(async_session, n1.id, j.id)
        await _link(async_session, n2.id, j.id)

        results = await neighbors_of(async_session, focal.id, limit=10)
        ids = sorted([r[0].id for r in results])
        assert ids == [n1.id, n2.id]

    async def test_excludes_allowlisted_by_default(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        focal = await _seed_entity(async_session, 1, "10.0.0.1")
        good = await _seed_entity(async_session, 2, "10.0.0.2")
        muted = await _seed_entity(async_session, 3, "10.0.0.3", allowlisted=True)
        await _link(async_session, focal.id, j.id)
        await _link(async_session, good.id, j.id)
        await _link(async_session, muted.id, j.id)

        results = await neighbors_of(async_session, focal.id)
        assert [r[0].id for r in results] == [good.id]

    async def test_include_allowlisted_opt_in(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        focal = await _seed_entity(async_session, 1, "10.0.0.1")
        muted = await _seed_entity(async_session, 2, "10.0.0.2", allowlisted=True)
        await _link(async_session, focal.id, j.id)
        await _link(async_session, muted.id, j.id)

        results = await neighbors_of(async_session, focal.id, include_allowlisted=True)
        assert [r[0].id for r in results] == [muted.id]

    async def test_isolated_entity_no_neighbors(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        focal = await _seed_entity(async_session, 1, "10.0.0.1")
        results = await neighbors_of(async_session, focal.id)
        assert results == []


@pytest.mark.asyncio
class TestBuildEntityGraph:
    async def test_focal_only_when_isolated(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        focal = await _seed_entity(async_session, 1, "10.0.0.1")
        payload = await build_entity_graph(async_session, focal.id, hops=1)
        assert payload["stats"]["nodes"] == 1
        assert payload["stats"]["edges"] == 0
        assert decode_graph(payload)["nodes"][0]["data"]["focal"] is True

    async def test_one_hop_includes_neighbours(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        focal = await _seed_entity(async_session, 1, "10.0.0.1")
        n = await _seed_entity(async_session, 2, "10.0.0.2")
        await _link(async_session, focal.id, j.id)
        await _link(async_session, n.id, j.id)

        payload = await build_entity_graph(async_session, focal.id, hops=1)
        assert payload["stats"]["nodes"] == 2
        assert payload["stats"]["edges"] == 1

    async def test_two_hop_expansion(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j1 = await _seed_job(async_session, 1)
        j2 = await _seed_job(async_session, 2)
        focal = await _seed_entity(async_session, 1, "a")
        mid = await _seed_entity(async_session, 2, "b")
        far = await _seed_entity(async_session, 3, "c")
        # focal — mid via j1, mid — far via j2 (focal is NOT in j2)
        await _link(async_session, focal.id, j1.id)
        await _link(async_session, mid.id, j1.id)
        await _link(async_session, mid.id, j2.id)
        await _link(async_session, far.id, j2.id)

        one_hop = await build_entity_graph(async_session, focal.id, hops=1)
        assert one_hop["stats"]["nodes"] == 2  # focal + mid only

        two_hop = await build_entity_graph(async_session, focal.id, hops=2)
        assert two_hop["stats"]["nodes"] == 3  # focal + mid + far

    async def test_hops_clamped_to_max(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        focal = await _seed_entity(async_session, 1, "x")
        payload = await build_entity_graph(async_session, focal.id, hops=99)
        # MAX_HOPS=3 — but isolated focal still only one node
        assert payload["stats"]["hops_used"] <= 3

    async def test_missing_entity_returns_empty(self, async_session):
        graph = decode_graph(await build_entity_graph(async_session, 9999, hops=1))
        assert graph["nodes"] == []
        assert graph["edges"] == []
        assert graph["stats"]["nodes"] == 0


@pytest.mark.asyncio
class TestBuildCaseGraph:
    async def test_empty_when_no_ids(self, async_session):
        graph = decode_graph(await build_case_graph(async_session, []))
        assert graph["nodes"] == []
        assert graph["edges"] == []

    async def test_only_members_appear(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        a = await _seed_entity(async_session, 1, "a")
        b = await _seed_entity(async_session, 2, "b")
        outsider = await _seed_entity(async_session, 3, "c")  # not in case
        await _link(async_session, a.id, j.id)
        await _link(async_session, b.id, j.id)
        await _link(async_session, outsider.id, j.id)

        graph = decode_graph(await build_case_graph(async_session, [a.id, b.id]))
        ids = sorted(n["data"]["id"] for n in graph["nodes"])
        assert ids == ["e1", "e2"]
        # Edges restricted to the bounded set — outsider isn't included even though it co-occurs.
        assert all("e3" not in (e["data"]["source"], e["data"]["target"]) for e in graph["edges"])

    async def test_excludes_allowlisted_by_default(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        a = await _seed_entity(async_session, 1, "a")
        b = await _seed_entity(async_session, 2, "b", allowlisted=True)
        graph = decode_graph(await build_case_graph(async_session, [a.id, b.id]))
        assert [n["data"]["id"] for n in graph["nodes"]] == [f"e{a.id}"]


@pytest.mark.asyncio
class TestTypedRelationshipEdges:
    async def test_typed_edge_upgrades_kind_and_carries_label(self, async_session):
        from app.models import EntityRelationship

        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        exe = await _seed_entity(async_session, 1, "powershell.exe", etype="executable")
        h = await _seed_entity(async_session, 2, "A" * 64, etype="hash")
        # both co-occur in the same job (so the hash is a neighbour of the exe)
        await _link(async_session, exe.id, j.id)
        await _link(async_session, h.id, j.id)
        async_session.add(EntityRelationship(source_entity_id=exe.id, target_entity_id=h.id, relationship_type="hashes_to", occurrence_count=3))
        await async_session.commit()

        graph = decode_graph(await build_entity_graph(async_session, exe.id, hops=1))
        typed = [e for e in graph["edges"] if e["data"]["kind"] == "typed"]
        assert len(typed) == 1
        assert typed[0]["data"]["rel_type"] == "hashes_to"
        # Directed, and in the direction the relationship was recorded — not normalised to
        # a (low, high) pair the way a collapsed edge would be.
        assert (typed[0]["data"]["source_id"], typed[0]["data"]["target_id"]) == (exe.id, h.id)
        assert typed[0]["data"]["weight"] == 3, "occurrence_count rides the edge, with no rendering floor added"

    async def test_case_graph_typed_edge(self, async_session):
        from app.models import EntityRelationship

        await _seed_logfile_and_workflow(async_session)
        d = await _seed_entity(async_session, 1, "evil.example", etype="domain")
        ip = await _seed_entity(async_session, 2, "1.2.3.4", etype="ip_address")
        async_session.add(EntityRelationship(source_entity_id=d.id, target_entity_id=ip.id, relationship_type="resolves_to", occurrence_count=1))
        await async_session.commit()

        graph = decode_graph(await build_case_graph(async_session, [d.id, ip.id]))
        kinds = {e["data"]["kind"] for e in graph["edges"]}
        assert "typed" in kinds


# ── Case-graph caps, job_edges toggle, and finding-edge visibility ────────────


async def _seed_finding(db, *, fid, job_id, task_result_id, entity_ids):
    """One Finding under `job_id`, linked to each entity in `entity_ids`."""
    from app.models import Finding, FindingEntityLink, TaskResult

    if await db.get(TaskResult, task_result_id) is None:
        db.add(TaskResult(id=task_result_id, job_id=job_id, tool_name="zircolite", status=TaskStatus.COMPLETED))
        await db.commit()
    db.add(Finding(id=fid, task_result_id=task_result_id, rule_id=f"r{fid}", rule_name=f"rule {fid}", severity=Severity.HIGH, count=1))
    await db.commit()
    for eid in entity_ids:
        db.add(FindingEntityLink(finding_id=fid, entity_id=eid))
    await db.commit()


@pytest.mark.asyncio
class TestCaseGraphCaps:
    async def test_job_edges_off_drops_job_only_pairs(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        a = await _seed_entity(async_session, 1, "10.0.0.1")
        b = await _seed_entity(async_session, 2, "10.0.0.2")
        await _link(async_session, a.id, j.id)
        await _link(async_session, b.id, j.id)

        with_jobs = decode_graph(await build_case_graph(async_session, [a.id, b.id], job_edges=True))
        assert len(with_jobs["edges"]) == 1
        assert with_jobs["edges"][0]["data"]["kind"] == "job"

        without = decode_graph(await build_case_graph(async_session, [a.id, b.id], job_edges=False))
        assert without["edges"] == [], "job-only pairs must not be shipped when job_edges=0"
        assert without["stats"]["job_edges"] is False

    async def test_job_edges_off_keeps_typed_edges(self, async_session):
        from app.models import EntityRelationship

        await _seed_logfile_and_workflow(async_session)
        a = await _seed_entity(async_session, 1, "10.0.0.1")
        b = await _seed_entity(async_session, 2, "evil.example", etype="domain")
        async_session.add(EntityRelationship(source_entity_id=a.id, target_entity_id=b.id, relationship_type="resolves_to", occurrence_count=3))
        await async_session.commit()

        graph = decode_graph(await build_case_graph(async_session, [a.id, b.id], job_edges=False))
        assert [e["data"]["kind"] for e in graph["edges"]] == ["typed"]

    async def test_edge_weight_equals_shared_job_count(self, async_session):
        """Pins the SQL self-join against a Python pairwise counter."""
        await _seed_logfile_and_workflow(async_session)
        a = await _seed_entity(async_session, 1, "10.0.0.1")
        b = await _seed_entity(async_session, 2, "10.0.0.2")
        for jid in (1, 2, 3):
            j = await _seed_job(async_session, jid)
            await _link(async_session, a.id, j.id)
            await _link(async_session, b.id, j.id)

        graph = decode_graph(await build_case_graph(async_session, [a.id, b.id], job_edges=True))
        assert graph["edges"][0]["data"]["weight"] == 3

    async def test_node_cap_reports_honest_totals(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        ids = []
        for i in range(1, 13):
            e = await _seed_entity(async_session, i, f"10.0.0.{i}", job_count=i)
            await _link(async_session, e.id, j.id)
            ids.append(e.id)

        payload = await build_case_graph(async_session, ids, max_nodes=5)
        stats = payload["stats"]
        assert stats["nodes"] == 5
        assert stats["total_nodes"] == 12
        assert stats["truncated"] is True
        assert "nodes" in stats["truncated_reason"]
        # Ranked by job_count desc, so the five busiest entities survive.
        assert {n["data"]["label"] for n in decode_graph(payload)["nodes"]} == {f"10.0.0.{i}" for i in (12, 11, 10, 9, 8)}

    async def test_edge_cap_reports_total_edges(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        ids = []
        for i in range(1, 6):  # 5 entities in one job -> 10 pairs
            e = await _seed_entity(async_session, i, f"10.0.0.{i}")
            await _link(async_session, e.id, j.id)
            ids.append(e.id)

        payload = await build_case_graph(async_session, ids, max_edges=4)
        stats = payload["stats"]
        assert stats["edges"] == 4
        assert stats["total_edges"] == 10
        assert stats["truncated"] is True
        assert "edges" in stats["truncated_reason"]

    async def test_untruncated_graph_reports_totals_equal_to_emitted(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        j = await _seed_job(async_session, 1)
        a = await _seed_entity(async_session, 1, "10.0.0.1")
        b = await _seed_entity(async_session, 2, "10.0.0.2")
        await _link(async_session, a.id, j.id)
        await _link(async_session, b.id, j.id)

        stats = (await build_case_graph(async_session, [a.id, b.id]))["stats"]
        assert stats["truncated"] is False
        assert stats["truncated_reason"] == ""
        assert stats["total_nodes"] == stats["nodes"] == 2
        assert stats["total_edges"] == stats["edges"] == 1


async def _seed_clique(db, n):
    """`n` entities all sharing one job — so the BFS sees every pair at hops=2."""
    await _seed_logfile_and_workflow(db)
    j = await _seed_job(db, 1)
    ids = []
    for i in range(1, n + 1):
        e = await _seed_entity(db, i, f"10.0.0.{i}")
        await _link(db, e.id, j.id)
        ids.append(e.id)
    return ids


@pytest.mark.asyncio
class TestEntityGraphCaps:
    """The entity builder caps edges, not only nodes.

    Capping nodes alone does not bound the payload: the BFS adds up to `limit` edges per
    frontier node, so a mid-range `limit` fans out *more* edges than a large one (a large
    one trips MAX_NODES and breaks the BFS early). Measured on a 1,944-entity dev DB,
    hops=2/limit=120 emitted 9,837 edges / 1.08 MB and reported `truncated: False`, so the
    UI banner stayed silent about it.
    """

    async def test_edge_cap_truncates_and_reports_the_true_total(self, async_session):
        ids = await _seed_clique(async_session, 6)  # C(6,2) = 15 pairs at hops=2

        payload = await build_entity_graph(async_session, ids[0], hops=2, max_edges=6)
        stats = payload["stats"]
        assert len(decode_graph(payload)["edges"]) == 6
        assert stats["edges"] == 6
        assert stats["total_edges"] == 15, "total must be the pre-cap count, not the emitted count"
        assert stats["truncated"] is True
        assert "edges" in stats["truncated_reason"]

    async def test_focal_keeps_its_edges_when_the_cap_bites(self, async_session):
        """A cap must never orphan the node the whole view is centred on.

        The focal is the *highest* id on purpose. In a clique every pair has the same
        weight, so the tie-break is the pair tuple ascending — which would hand every
        surviving edge to the low ids and leave the focal stranded. Only the focal-first
        clause in the sort key saves it, so picking ids[0] here would pass either way.
        """
        ids = await _seed_clique(async_session, 6)
        focal = ids[-1]

        graph = decode_graph(await build_entity_graph(async_session, focal, hops=2, max_edges=3))
        assert len(graph["edges"]) == 3
        endpoints = [(e["data"]["source"], e["data"]["target"]) for e in graph["edges"]]
        assert all(f"e{focal}" in pair for pair in endpoints), f"focal-incident edges must be ranked first, got {endpoints}"

    async def test_explicit_max_edges_is_honoured(self, async_session):
        """The GraphML route raises the budget — a downloaded file has no banner to warn."""
        ids = await _seed_clique(async_session, 6)

        stats = (await build_entity_graph(async_session, ids[0], hops=2, max_edges=50))["stats"]
        assert stats["edges"] == 15
        assert stats["total_edges"] == 15
        assert stats["truncated"] is False

    async def test_entity_scope_reports_a_null_node_total(self, async_session):
        """`total_nodes` is `int | null`, and entity scope emits **null**.

        A traversal never learns the true node total. Mirroring the emitted count into
        `total_nodes` would leave the stats template compensating with an "is the total
        actually known?" predicate. Emitting null says the same thing honestly, and the
        banner reports a *budget* rather than a ratio.
        """
        ids = await _seed_clique(async_session, 3)

        stats = (await build_entity_graph(async_session, ids[0], hops=1))["stats"]
        assert stats["truncated"] is False
        assert stats["truncated_reason"] == ""
        assert stats["total_nodes"] is None
        assert stats["nodes"] == 3

    async def test_entity_scope_emits_the_induced_edge_set_not_the_traversal_tree(self, async_session):
        """All three pairs of a 3-clique, not the two the expansion happened to walk.

        Keeping only the edges a BFS traversed would make Louvain rediscover the traversal
        tree, and a path between two neighbours would detour through the focal node.
        """
        ids = await _seed_clique(async_session, 3)

        graph = decode_graph(await build_entity_graph(async_session, ids[0], hops=1))
        pairs = {tuple(sorted((e["data"]["source_id"], e["data"]["target_id"]))) for e in graph["edges"]}
        assert pairs == {(1, 2), (1, 3), (2, 3)}

    async def test_typed_edges_survive_the_cap_when_they_outweigh_job_edges(self, async_session):
        """Evidence-backed edges outrank co-occurrence when the cap bites.

        No visibility floor is added to typed edges — that would be a rendering constant
        travelling into the GraphML export — so an explicit kind tier (typed > finding >
        job) is what keeps a typed edge alive, and this test pins the tier rather than the
        arithmetic.
        """
        from app.models import EntityRelationship

        ids = await _seed_clique(async_session, 6)
        # A typed edge between two *non-focal* entities, which would otherwise rank last.
        async_session.add(
            EntityRelationship(
                source_entity_id=ids[4],
                target_entity_id=ids[5],
                relationship_type="resolves_to",
                occurrence_count=1,
            )
        )
        await async_session.commit()

        graph = decode_graph(await build_entity_graph(async_session, ids[0], hops=2, max_edges=6))
        kinds = {e["data"]["kind"] for e in graph["edges"]}
        assert "typed" in kinds, "a typed edge outranks a plain job edge and must survive"


@pytest.mark.asyncio
class TestFindingEdgeVisibility:
    async def test_private_job_finding_edge_hidden_from_other_viewers(self, async_session):
        """A 'same Sigma finding' edge must not reveal co-occurrence inside a private job."""
        await _seed_logfile_and_workflow(async_session)
        owner_id = uuid.uuid4()
        job = AnalysisJob(id=1, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner_id)
        async_session.add(job)
        await async_session.commit()

        a = await _seed_entity(async_session, 1, "10.0.0.1")
        b = await _seed_entity(async_session, 2, "10.0.0.2")
        await _seed_finding(async_session, fid=1, job_id=job.id, task_result_id=1, entity_ids=[a.id, b.id])

        owner = SimpleNamespace(id=owner_id, is_superuser=False)
        stranger = SimpleNamespace(id=uuid.uuid4(), is_superuser=False)
        admin = SimpleNamespace(id=uuid.uuid4(), is_superuser=True)

        def kinds(payload):
            return {e["data"]["kind"] for e in decode_graph(payload)["edges"]}

        assert kinds(await build_case_graph(async_session, [a.id, b.id], viewer=owner, job_edges=False)) == {"finding"}
        assert kinds(await build_case_graph(async_session, [a.id, b.id], viewer=admin, job_edges=False)) == {"finding"}

        stranger_payload = decode_graph(await build_case_graph(async_session, [a.id, b.id], viewer=stranger, job_edges=False))
        assert stranger_payload["edges"] == [], "finding edge leaked a private job's co-occurrence"
        anon_payload = decode_graph(await build_case_graph(async_session, [a.id, b.id], viewer=None, job_edges=False))
        assert anon_payload["edges"] == []

    async def test_public_job_finding_edge_visible_to_anonymous(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        job = await _seed_job(async_session, 1)
        a = await _seed_entity(async_session, 1, "10.0.0.1")
        b = await _seed_entity(async_session, 2, "10.0.0.2")
        await _seed_finding(async_session, fid=1, job_id=job.id, task_result_id=1, entity_ids=[a.id, b.id])

        graph = decode_graph(await build_case_graph(async_session, [a.id, b.id], viewer=None, job_edges=False))
        assert [e["data"]["kind"] for e in graph["edges"]] == ["finding"]


async def _seed_private_pair(db, owner_id):
    """Two entities linked only by one private job. Returns (entity_a, entity_b)."""
    await _seed_logfile_and_workflow(db)
    db.add(AnalysisJob(id=1, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner_id))
    await db.commit()
    a = await _seed_entity(db, 1, "10.0.0.1")
    b = await _seed_entity(db, 2, "10.0.0.2")
    await _link(db, a.id, 1)
    await _link(db, b.id, 1)
    return a, b


@pytest.mark.asyncio
class TestJobEdgeVisibility:
    """Job-kind edges must obey the same rule as finding-kind ones.

    They did not: `_job_co_edges` and `neighbors_of` never joined `AnalysisJob`, so a
    "shared job" edge — the *default* edge source, unlike finding edges — announced that
    two entities co-occurred inside a job the viewer cannot open. Every assertion in
    `TestFindingEdgeVisibility` passes `job_edges=False`, which is exactly why this went
    unnoticed.
    """

    async def test_case_graph_job_edge_hidden_from_other_viewers(self, async_session):
        owner_id = uuid.uuid4()
        a, b = await _seed_private_pair(async_session, owner_id)

        owner = SimpleNamespace(id=owner_id, is_superuser=False)
        stranger = SimpleNamespace(id=uuid.uuid4(), is_superuser=False)
        admin = SimpleNamespace(id=uuid.uuid4(), is_superuser=True)

        async def kinds(viewer):
            graph = decode_graph(await build_case_graph(async_session, [a.id, b.id], viewer=viewer, job_edges=True))
            return [e["data"]["kind"] for e in graph["edges"]]

        assert await kinds(owner) == ["job"]
        assert await kinds(admin) == ["job"]
        assert await kinds(stranger) == [], "job edge leaked a private job's co-occurrence"
        assert await kinds(None) == []

    async def test_neighbors_of_excludes_private_jobs(self, async_session):
        owner_id = uuid.uuid4()
        a, b = await _seed_private_pair(async_session, owner_id)

        owner = SimpleNamespace(id=owner_id, is_superuser=False)
        stranger = SimpleNamespace(id=uuid.uuid4(), is_superuser=False)

        assert [n.id for n, _ in await neighbors_of(async_session, a.id, viewer=owner)] == [b.id]
        assert await neighbors_of(async_session, a.id, viewer=stranger) == []
        assert await neighbors_of(async_session, a.id, viewer=None) == []

    async def test_entity_graph_drops_private_neighbour(self, async_session):
        owner_id = uuid.uuid4()
        a, b = await _seed_private_pair(async_session, owner_id)

        stranger = SimpleNamespace(id=uuid.uuid4(), is_superuser=False)
        graph = decode_graph(await build_entity_graph(async_session, a.id, viewer=stranger))
        assert [n["data"]["id"] for n in graph["nodes"]] == [f"e{a.id}"]
        assert graph["edges"] == []

        owner_graph = decode_graph(await build_entity_graph(async_session, a.id, viewer=SimpleNamespace(id=owner_id, is_superuser=False)))
        assert {n["data"]["id"] for n in owner_graph["nodes"]} == {f"e{a.id}", f"e{b.id}"}

    async def test_total_edge_count_banner_excludes_private_pairs(self, async_session):
        """`_total_edges_probe` feeds the "showing top N of M" banner, so M must not count
        pairs the viewer may not see — otherwise the banner itself leaks the co-occurrence.

        Needs three entities and a forced truncation: with a single visible pair the total
        is zero either way, which is how an earlier version of this test passed against the
        unfixed code.
        """
        await _seed_logfile_and_workflow(async_session)
        owner_id = uuid.uuid4()
        async_session.add(AnalysisJob(id=1, file_id=1, workflow_id=1, status=JobStatus.COMPLETED))
        async_session.add(AnalysisJob(id=2, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner_id))
        await async_session.commit()

        a = await _seed_entity(async_session, 1, "10.0.0.1")
        b = await _seed_entity(async_session, 2, "10.0.0.2")
        c = await _seed_entity(async_session, 3, "10.0.0.3")
        await _link(async_session, a.id, 1)  # public job: a—b
        await _link(async_session, b.id, 1)
        await _link(async_session, a.id, 2)  # private job: a—c
        await _link(async_session, c.id, 2)

        ids = [a.id, b.id, c.id]

        async def total_edges(viewer):
            # max_edges=1 forces the truncation branch, which is the only path that
            # actually queries `_total_edges_probe`.
            stats = (await build_case_graph(async_session, ids, viewer=viewer, job_edges=True, max_edges=1))["stats"]
            return stats["total_edges"]

        assert await total_edges(SimpleNamespace(id=owner_id, is_superuser=False)) == 2
        assert await total_edges(SimpleNamespace(id=uuid.uuid4(), is_superuser=True)) == 2
        assert await total_edges(SimpleNamespace(id=uuid.uuid4(), is_superuser=False)) == 1
        assert await total_edges(None) == 1

    async def test_public_job_edge_still_visible_to_anonymous(self, async_session):
        await _seed_logfile_and_workflow(async_session)
        job = await _seed_job(async_session, 1)
        a = await _seed_entity(async_session, 1, "10.0.0.1")
        b = await _seed_entity(async_session, 2, "10.0.0.2")
        await _link(async_session, a.id, job.id)
        await _link(async_session, b.id, job.id)

        graph = decode_graph(await build_case_graph(async_session, [a.id, b.id], viewer=None, job_edges=True))
        assert [e["data"]["kind"] for e in graph["edges"]] == ["job"]
        assert [n.id for n, _ in await neighbors_of(async_session, a.id, viewer=None)] == [b.id]


@pytest.mark.asyncio
async def test_case_graph_hides_hashes_by_default_entity_graph_does_not(async_session):
    """A case pulls in a hash per file touched; they crowd out the structure an analyst
    reads the graph for. Entity scope keeps them — there the focal node is often a hash.

    The decision moved server-side (`defaults.hidden_types`), so it is asserted on the
    payload. A route assertion alone would silently lose coverage of the client half, so
    `tests/test_graph_client_contract.py` also greps graph.js for the read.
    """
    await _seed_logfile_and_workflow(async_session)
    focal = await _seed_entity(async_session, 1, "10.0.0.1")

    case_payload = await build_case_graph(async_session, [focal.id])
    entity_payload = await build_entity_graph(async_session, focal.id)

    assert case_payload["defaults"]["hidden_types"] == ["hash"]
    assert entity_payload["defaults"]["hidden_types"] == []


class TestCooccurrenceWeight:
    """`_cooccurrence_weight` resolves an undirected pair to `(kind, weight)`.

    Typed relationships are not folded onto the same line: they are their own directed
    edges carrying `occurrence_count` verbatim, and the stroke-width floor lives in the
    client reducer where it cannot travel into the GraphML export as though it were
    evidence.
    """

    @staticmethod
    def _w(pair, *, job=0, finding=0):
        from app.intel.graph import _cooccurrence_weight

        return _cooccurrence_weight(pair, job_co={pair: job} if job else {}, finding_co={pair: finding} if finding else {})

    def test_job_only(self):
        assert self._w((1, 2), job=3) == ("job", 3)

    def test_finding_upgrades_the_kind_and_adds_to_the_weight(self):
        assert self._w((1, 2), job=3, finding=2) == ("finding", 5)

    def test_finding_is_counted_exactly_once(self):
        """Recomputing `weight` in the finding branch and adding `finding_co` again in the
        typed branch would render a pair backed by both twice as thick."""
        assert self._w((1, 2), job=3, finding=2)[1] == 5

    def test_a_pair_with_no_co_occurrence_still_has_a_positive_weight(self):
        assert self._w((1, 2))[1] == 1


@pytest.mark.asyncio
async def test_typed_edges_are_deliberately_unfiltered(async_session):
    """The one documented exception to viewer filtering — read it, don't rediscover it.

    `EntityRelationship` is a cross-job aggregate with no job column, and the entity
    Relationships tab lists those edges unfiltered by design, so gating them here alone
    would hide the edge while leaving the same fact one click away.

    This redesign makes typed edges far more prominent — their own directed edge, an arrow,
    a label, and the *only* kind a path traverses — so someone will eventually try to "fix"
    this. The boundary is precise and is documented in docs/security.md: the **existence**
    of a typed edge is unfiltered; everything **derived** from it (evidence rows, per-job
    counts, observed times — see `/intel/relationships/{id}/timespan.json`) is filtered.
    """
    from app.models import EntityRelationship

    await _seed_logfile_and_workflow(async_session)
    owner_id = uuid.uuid4()
    async_session.add(AnalysisJob(id=1, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner_id))
    await async_session.commit()

    a = await _seed_entity(async_session, 1, "evil.example", etype="domain")
    b = await _seed_entity(async_session, 2, "1.2.3.4")
    await _link(async_session, a.id, 1)
    await _link(async_session, b.id, 1)
    async_session.add(EntityRelationship(source_entity_id=a.id, target_entity_id=b.id, relationship_type="resolves_to", occurrence_count=2))
    await async_session.commit()

    stranger = SimpleNamespace(id=uuid.uuid4(), is_superuser=False)
    graph = decode_graph(await build_case_graph(async_session, [a.id, b.id], viewer=stranger, job_edges=True))

    kinds = [e["data"]["kind"] for e in graph["edges"]]
    assert kinds == ["typed"], "the job edge must be filtered out; the typed edge deliberately is not"


@pytest.mark.asyncio
async def test_typed_edges_keep_their_direction_and_type(async_session):
    """One directed edge per `(source, target, relationship_type)` — no normalisation.

    Collapsing every typed relationship between a pair onto one undirected line keyed
    `(low_id, high_id)`, with the type names merged into a comma-joined label and an
    arrowhead drawn on it anyway, would turn two relationships in opposite directions into
    one line pointing the wrong way half the time.
    """
    from app.models import EntityRelationship

    await _seed_logfile_and_workflow(async_session)
    a = await _seed_entity(async_session, 1, "a.exe", etype="executable")
    b = await _seed_entity(async_session, 2, "b.exe", etype="executable")
    async_session.add_all(
        [
            EntityRelationship(source_entity_id=a.id, target_entity_id=b.id, relationship_type="parent_of", occurrence_count=5),
            EntityRelationship(source_entity_id=b.id, target_entity_id=a.id, relationship_type="loads", occurrence_count=2),
        ]
    )
    await async_session.commit()

    graph = decode_graph(await build_case_graph(async_session, [a.id, b.id], job_edges=False))
    edges = {(e["data"]["source_id"], e["data"]["target_id"], e["data"]["rel_type"]): e["data"]["weight"] for e in graph["edges"]}
    assert edges == {(a.id, b.id, "parent_of"): 5, (b.id, a.id, "loads"): 2}


# ── near-clique jobs must not be traversed ──────────────────────────────────


@pytest.mark.asyncio
class TestNearCliqueTraversal:
    async def test_traversal_skips_a_near_clique_job(self, async_session, monkeypatch):
        """`_job_co_edges` has always suppressed these jobs' edges while the traversal
        walked straight through them — discovering nodes it would then draw no edge for,
        and letting one enormous job dominate the neighbour ranking."""
        from app.intel import graph as graph_mod

        monkeypatch.setattr(graph_mod, "MAX_JOB_FANOUT", 3)

        await _seed_logfile_and_workflow(async_session)
        wide = await _seed_job(async_session, 1)
        narrow = await _seed_job(async_session, 2)

        focal = await _seed_entity(async_session, 1, "focal.example", etype="domain")
        wide_ids = []
        for i in range(5):
            e = await _seed_entity(async_session, 10 + i, f"wide{i}.example", etype="domain")
            wide_ids.append(e.id)
            await _link(async_session, e.id, wide.id)
        await _link(async_session, focal.id, wide.id)

        real = await _seed_entity(async_session, 50, "real.example", etype="domain")
        await _link(async_session, real.id, narrow.id)
        await _link(async_session, focal.id, narrow.id)

        payload = decode_graph(await build_entity_graph(async_session, focal.id, hops=1, limit=50))
        ids = {n["data"]["id"] for n in payload["nodes"]}

        assert f"e{real.id}" in ids, "the narrow job's neighbour is the real relation"
        assert not (ids & {f"e{i}" for i in wide_ids}), "the near-clique job must not be traversed"

    async def test_a_job_scope_still_traverses_its_own_wide_job(self, async_session, monkeypatch):
        """Under `?job=` the candidate set *is* that job, so suppressing it for being wide
        would suppress exactly what was asked for."""
        from app.intel import graph as graph_mod

        monkeypatch.setattr(graph_mod, "MAX_JOB_FANOUT", 3)

        await _seed_logfile_and_workflow(async_session)
        wide = await _seed_job(async_session, 1)
        focal = await _seed_entity(async_session, 1, "focal2.example", etype="domain")
        await _link(async_session, focal.id, wide.id)
        other_ids = []
        for i in range(5):
            e = await _seed_entity(async_session, 20 + i, f"scoped{i}.example", etype="domain")
            other_ids.append(e.id)
            await _link(async_session, e.id, wide.id)

        payload = decode_graph(await build_entity_graph(async_session, focal.id, hops=1, limit=50, job_id=wide.id))
        ids = {n["data"]["id"] for n in payload["nodes"]}
        assert ids & {f"e{i}" for i in other_ids}, "a job scope must show that job's entities"
