"""Tier-2 tests for persist_relationships against an in-memory SQLite DB."""

from __future__ import annotations

import app.models  # noqa: F401 — populate Base.metadata
from app.intel.entities import persist_entities_from_analytics
from app.intel.relationships import persist_relationships
from app.models import AnalysisJob, Entity, EntityRelationship, EntityRelationshipEvidence, JobStatus, LogFile, WorkflowDef


def _seed(db, value: str, etype: str) -> Entity:
    e = Entity(value=value, entity_type=etype)
    db.add(e)
    db.commit()
    return e


def _entity_map(db) -> dict[tuple[str, str], Entity]:
    return {(e.value, e.entity_type): e for e in db.query(Entity).all()}


def test_inserts_edge_when_both_endpoints_are_entities(sync_db):
    _seed(sync_db, "powershell.exe", "executable")
    _seed(sync_db, "A" * 64, "hash")
    tuples = [("powershell.exe", "executable", "A" * 64, "hash", "hashes_to")]

    n = persist_relationships(sync_db, 1, tuples, _entity_map(sync_db))
    sync_db.commit()

    assert n == 1
    rows = sync_db.query(EntityRelationship).all()
    assert len(rows) == 1
    assert rows[0].relationship_type == "hashes_to"
    assert rows[0].occurrence_count == 1


def test_drops_edge_when_endpoint_missing(sync_db):
    _seed(sync_db, "powershell.exe", "executable")
    # hash entity intentionally absent
    tuples = [("powershell.exe", "executable", "A" * 64, "hash", "hashes_to")]

    n = persist_relationships(sync_db, 1, tuples, _entity_map(sync_db))
    sync_db.commit()

    assert n == 0
    assert sync_db.query(EntityRelationship).count() == 0


def test_counts_repeated_tuples_within_one_call(sync_db):
    _seed(sync_db, "evil.exe", "executable")
    _seed(sync_db, "HOST1", "computer")
    tuples = [("evil.exe", "executable", "HOST1", "computer", "runs_on")] * 3

    persist_relationships(sync_db, 1, tuples, _entity_map(sync_db))
    sync_db.commit()

    row = sync_db.query(EntityRelationship).one()
    assert row.occurrence_count == 3


def test_reoccurrence_increments_and_refreshes_last_seen(sync_db):
    _seed(sync_db, "evil.exe", "executable")
    _seed(sync_db, "HOST1", "computer")
    emap = _entity_map(sync_db)
    tuples = [("evil.exe", "executable", "HOST1", "computer", "runs_on")]

    persist_relationships(sync_db, 1, tuples, emap)
    sync_db.commit()
    persist_relationships(sync_db, 2, tuples, emap)
    sync_db.commit()

    row = sync_db.query(EntityRelationship).one()
    assert row.occurrence_count == 2


def test_skips_self_loops(sync_db):
    e = _seed(sync_db, "a.exe", "executable")
    # a tuple that resolves source and target to the same entity id
    tuples = [("a.exe", "executable", "a.exe", "executable", "parent_of")]
    n = persist_relationships(sync_db, 1, tuples, {(e.value, e.entity_type): e})
    sync_db.commit()
    assert n == 0
    assert sync_db.query(EntityRelationship).count() == 0


def test_empty_inputs_return_zero(sync_db):
    assert persist_relationships(sync_db, 1, [], _entity_map(sync_db)) == 0
    assert persist_relationships(sync_db, 1, [("a", "executable", "b", "hash", "hashes_to")], {}) == 0


def _seed_job(db) -> AnalysisJob:
    db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="x" * 64, size_bytes=1))
    db.add(WorkflowDef(id=1, name="wf1"))
    job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED)
    db.add(job)
    db.commit()
    return job


def test_persist_entities_also_persists_relationships(sync_db):
    """The pipeline integration: relationships ride along on analytics_data."""
    job = _seed_job(sync_db)
    analytics_data = {
        "executables": ["powershell.exe"],
        "hashes": ["A" * 64],
        "computers": ["WS01"],
        # transient key threaded through from _compute_analytics_data
        "relationships": [
            ("powershell.exe", "executable", "A" * 64, "hash", "hashes_to"),
            ("powershell.exe", "executable", "WS01", "computer", "runs_on"),
            # endpoint not in any entity list -> must be dropped
            ("powershell.exe", "executable", "ghost.exe", "executable", "parent_of"),
        ],
    }

    persist_entities_from_analytics(sync_db, job.id, analytics_data)
    sync_db.commit()

    rels = {(r.relationship_type) for r in sync_db.query(EntityRelationship).all()}
    assert rels == {"hashes_to", "runs_on"}
    assert sync_db.query(EntityRelationship).count() == 2


def test_evidence_rows_written_with_samples(sync_db):
    _seed(sync_db, "evil.exe", "executable")
    _seed(sync_db, "HOST1", "computer")
    tup = ("evil.exe", "executable", "HOST1", "computer", "runs_on")
    evidence = {tup: [{"EventID": 1, "Image": "evil.exe", "Computer": "HOST1"}]}

    persist_relationships(sync_db, 7, [tup, tup], _entity_map(sync_db), evidence=evidence)
    sync_db.commit()

    ev_rows = sync_db.query(EntityRelationshipEvidence).all()
    assert len(ev_rows) == 1
    assert ev_rows[0].job_id == 7
    assert ev_rows[0].occurrence_count == 2  # per-job count reused from the edge tally
    assert "evil.exe" in ev_rows[0].sample_events_json
    rel = sync_db.query(EntityRelationship).one()
    assert ev_rows[0].relationship_id == rel.id


def test_evidence_is_idempotent_per_job(sync_db):
    _seed(sync_db, "evil.exe", "executable")
    _seed(sync_db, "HOST1", "computer")
    emap = _entity_map(sync_db)
    tup = ("evil.exe", "executable", "HOST1", "computer", "runs_on")
    evidence = {tup: [{"EventID": 1, "Image": "evil.exe"}]}

    persist_relationships(sync_db, 9, [tup], emap, evidence=evidence)
    sync_db.commit()
    persist_relationships(sync_db, 9, [tup], emap, evidence=evidence)
    sync_db.commit()

    # Same (relationship, job) → one evidence row, count set wholesale (not doubled).
    ev_rows = sync_db.query(EntityRelationshipEvidence).all()
    assert len(ev_rows) == 1
    assert ev_rows[0].occurrence_count == 1


def test_no_evidence_arg_still_writes_the_per_job_ledger_row(sync_db):
    """Without samples there is still a row — it is the ledger, the samples are extra.

    The tally on ``EntityRelationship`` is derived by summing these per-job rows, so an
    edge that captured no sample events still needs its count recorded or it vanishes from
    the sum.
    """
    _seed(sync_db, "evil.exe", "executable")
    _seed(sync_db, "HOST1", "computer")
    tup = ("evil.exe", "executable", "HOST1", "computer", "runs_on")

    persist_relationships(sync_db, 1, [tup], _entity_map(sync_db))
    sync_db.commit()

    row = sync_db.query(EntityRelationshipEvidence).one()
    assert row.occurrence_count == 1
    assert row.sample_events_json == "[]"
    assert sync_db.query(EntityRelationship).one().occurrence_count == 1


def test_recomputing_a_job_does_not_inflate_the_edge_tally(sync_db):
    """Three runs of one job's data leave the tally at its true value, not 3x it.

    An upsert doing ``occurrence_count + excluded.occurrence_count`` would make every
    "Recalculate analytics" and every ``backfill_analytics`` re-add the job's whole
    contribution: an edge seen 7 times would read 14 after one recompute and 21 after two.
    """
    _seed(sync_db, "cmd.exe", "executable")
    _seed(sync_db, "evil.exe", "executable")
    emap = _entity_map(sync_db)
    tup = ("cmd.exe", "executable", "evil.exe", "executable", "parent_of")
    pairs = [tup] * 7

    for _ in range(3):
        persist_relationships(sync_db, 1, pairs, emap, evidence={tup: [{"EventID": 1}]})
        sync_db.commit()
    assert sync_db.query(EntityRelationship).one().occurrence_count == 7

    # A genuinely different job still accumulates — idempotence must not become inertness.
    persist_relationships(sync_db, 2, pairs, emap, evidence={tup: [{"EventID": 1}]})
    sync_db.commit()
    assert sync_db.query(EntityRelationship).one().occurrence_count == 14


class TestCountedInput:
    """`relationship_tuples` may arrive as a Counter instead of a flat list.

    A flat list holds one tuple per relationship *per event* — growing with
    `max_parse_events` (250,000) times relationships-per-event — only to be folded here into
    `{(src, tgt, rel): count}` first thing. Counting at the source keeps the peak
    proportional to the number of *distinct* edges.

    The list form is still accepted, so these tests pin that both spellings produce
    identical rows. If they ever diverge, occurrence counts silently drift between the live
    analytics path (Counter) and `backfill_relationships` (also Counter, but reachable by
    older callers and by tests as a list).
    """

    @staticmethod
    def _edge(db):
        return db.query(EntityRelationship).one()

    def test_a_counter_and_a_repeated_list_agree(self, sync_db):
        from collections import Counter

        _seed(sync_db, "powershell.exe", "executable")
        _seed(sync_db, "A" * 64, "hash")
        tup = ("powershell.exe", "executable", "A" * 64, "hash", "hashes_to")

        n = persist_relationships(sync_db, 1, Counter({tup: 3}), _entity_map(sync_db))
        sync_db.commit()
        assert n == 1, "a Counter with one distinct edge must touch exactly one edge"
        assert self._edge(sync_db).occurrence_count == 3, "the Counter's tally was not carried into occurrence_count"

    def test_the_list_form_is_unchanged(self, sync_db):
        _seed(sync_db, "powershell.exe", "executable")
        _seed(sync_db, "A" * 64, "hash")
        tup = ("powershell.exe", "executable", "A" * 64, "hash", "hashes_to")

        n = persist_relationships(sync_db, 1, [tup, tup, tup], _entity_map(sync_db))
        sync_db.commit()
        assert n == 1
        assert self._edge(sync_db).occurrence_count == 3, "the list form must still count each occurrence once"

    def test_evidence_still_resolves_from_a_counter(self, sync_db):
        """Evidence is keyed by the value-tuple, so the input's shape must not matter."""
        from collections import Counter

        _seed(sync_db, "powershell.exe", "executable")
        _seed(sync_db, "A" * 64, "hash")
        tup = ("powershell.exe", "executable", "A" * 64, "hash", "hashes_to")

        persist_relationships(sync_db, 1, Counter({tup: 2}), _entity_map(sync_db), evidence={tup: [{"Computer": "HOST1"}]})
        sync_db.commit()
        row = sync_db.query(EntityRelationshipEvidence).one()
        assert row.occurrence_count == 2
        assert "HOST1" in (row.sample_events_json or "")


def _two_jobs_sharing_an_edge(db):
    from collections import Counter

    wf = WorkflowDef(name="WF", log_types="[]", tasks_yaml="tasks: []")
    lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1)
    db.add_all([wf, lf])
    db.flush()
    a = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    b = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    db.add_all([a, b])
    db.commit()
    edge = ("cmd.exe", "executable", "alice", "user", "runs_as")
    base = {"users": ["alice"], "executables": ["cmd.exe"]}
    persist_entities_from_analytics(db, a.id, {**base, "relationships": Counter({edge: 2}), "relationship_evidence": {edge: []}})
    persist_entities_from_analytics(db, b.id, {**base, "relationships": Counter({edge: 7}), "relationship_evidence": {edge: []}})
    db.commit()
    assert db.query(EntityRelationship).one().occurrence_count == 9, "precondition"
    return a, b


def test_deleting_a_job_takes_its_share_out_of_the_edge_tally(sync_db):
    """The tally is derived from per-job evidence, and deleting a job deletes its evidence —
    but nothing re-derived the tally, so a deleted submission's occurrences stayed counted."""
    from app.intel.entities import remove_entity_links_for_job_sync

    _a, b = _two_jobs_sharing_an_edge(sync_db)
    remove_entity_links_for_job_sync(sync_db, b.id)
    sync_db.delete(b)
    sync_db.commit()
    sync_db.expire_all()

    assert sync_db.query(EntityRelationship).one().occurrence_count == 2


async def test_the_async_twin_takes_the_share_out_too(async_db):
    """The delete route uses the async twin; the two are kept in lock-step."""
    from sqlalchemy import select

    from app.intel.entities import remove_entity_links_for_job_async

    def _setup(sync_session):
        return _two_jobs_sharing_an_edge(sync_session)[1].id

    b_id = await async_db.run_sync(_setup)
    await remove_entity_links_for_job_async(async_db, b_id)
    await async_db.commit()

    rel = (await async_db.execute(select(EntityRelationship))).scalars().one()
    await async_db.refresh(rel)
    assert rel.occurrence_count == 2
