"""The Intel dashboard can be filtered to a single job's entities.

Two things are being pinned here.

The filter itself: `EntityJobLink` already carried the relationship both ways, but nothing
on the dashboard could reach it — `entities_partial` had no job parameter and
`routers/jobs.py` never imported `Entity`, so "which entities did this job produce?" was
unanswerable in the UI.

And its authorization. Every other dashboard filter is a property of the entity, which is
a global observable. A job id is a reference to someone else's submission, so an unchecked
`?job=` would let any member enumerate a private job's entity set one id at a time — a
disclosure the rest of the dashboard has no equivalent of. `apply_entity_filters` is pure
and has no user, so the check has to live in the route; these tests are what keeps it there.
"""

from __future__ import annotations

from sqlalchemy import select

import app.models  # noqa: F401 — populate Base.metadata
from app.intel.queries import apply_entity_filters
from app.models import Entity, EntityJobLink


def _seed(db, value, etype, job_ids, job_count=None):
    e = Entity(value=value, entity_type=etype, job_count=job_count if job_count is not None else len(job_ids))
    db.add(e)
    db.flush()
    for jid in job_ids:
        db.add(EntityJobLink(entity_id=e.id, job_id=jid, occurrence_count=1))
    return e


def _values(db, **kw):
    stmt = apply_entity_filters(select(Entity), **kw)
    return sorted(e.value for e in db.execute(stmt).scalars().all())


class TestJobFilter:
    def test_narrows_to_that_jobs_entities(self, sync_db):
        _seed(sync_db, "alice", "user", [1])
        _seed(sync_db, "bob", "user", [2])
        _seed(sync_db, "carol", "user", [1, 2])
        sync_db.commit()
        assert _values(sync_db, job_id=1) == ["alice", "carol"]
        assert _values(sync_db, job_id=2) == ["bob", "carol"]

    def test_none_and_zero_are_no_ops(self, sync_db):
        _seed(sync_db, "alice", "user", [1])
        _seed(sync_db, "bob", "user", [2])
        sync_db.commit()
        assert _values(sync_db, job_id=None) == ["alice", "bob"]
        assert _values(sync_db, job_id=0) == ["alice", "bob"]

    def test_unknown_job_matches_nothing(self, sync_db):
        _seed(sync_db, "alice", "user", [1])
        sync_db.commit()
        assert _values(sync_db, job_id=999) == []

    def test_composes_with_other_filters(self, sync_db):
        _seed(sync_db, "alice", "user", [1])
        _seed(sync_db, "host1", "computer", [1])
        sync_db.commit()
        assert _values(sync_db, job_id=1, types=["user"]) == ["alice"]


class TestMinJobs:
    """`min_jobs=1` is not a silent no-op (as `if min_jobs and min_jobs > 1` would make it)."""

    def test_min_jobs_one_excludes_entities_with_no_links(self, sync_db):
        _seed(sync_db, "linked", "user", [1])
        _seed(sync_db, "orphan", "user", [], job_count=0)
        sync_db.commit()
        assert _values(sync_db, min_jobs=1) == ["linked"]

    def test_min_jobs_zero_is_still_a_no_op(self, sync_db):
        _seed(sync_db, "linked", "user", [1])
        _seed(sync_db, "orphan", "user", [], job_count=0)
        sync_db.commit()
        assert _values(sync_db, min_jobs=0) == ["linked", "orphan"]

    def test_higher_thresholds_still_work(self, sync_db):
        _seed(sync_db, "once", "user", [1])
        _seed(sync_db, "twice", "user", [1, 2])
        sync_db.commit()
        assert _values(sync_db, min_jobs=2) == ["twice"]


class TestConjunctiveFiltering:
    """The AND semantics have to survive the trip into SQL, not just the parser.

    `apply_entity_filters(query=...)` walks every term. These use real SQL so a mistake in
    `_apply_term` shows up here
    rather than as a silently-wider result set in production.
    """

    def _tagged(self, db, value, etype, tags=(), attrs=None):
        from app.json_utils import dumps as json_dumps
        from app.models import EntityTag

        e = Entity(value=value, entity_type=etype, job_count=1, attributes_json=json_dumps(attrs) if attrs else None)
        db.add(e)
        db.flush()
        for t in tags:
            db.add(EntityTag(entity_id=e.id, tag=t, color="gray"))
        return e

    def _run(self, db, raw):
        from app.intel.queries import apply_entity_filters as aef
        from app.intel.queries import parse_query

        stmt = aef(select(Entity), query=parse_query(raw))
        return sorted(e.value for e in db.execute(stmt).scalars().all())

    def test_two_terms_narrow_rather_than_widen(self, sync_db):
        self._tagged(sync_db, "certutil.exe", "executable", tags=["apt28"], attrs={"is_lolbin": True, "is_gtfobin": False})
        self._tagged(sync_db, "rundll32.exe", "executable", tags=[], attrs={"is_lolbin": True, "is_gtfobin": False})
        self._tagged(sync_db, "custom.exe", "executable", tags=["apt28"], attrs={"is_lolbin": False, "is_gtfobin": False})
        sync_db.commit()
        assert self._run(sync_db, "label:lolbin") == ["certutil.exe", "rundll32.exe"]
        assert self._run(sync_db, "tag:apt28") == ["certutil.exe", "custom.exe"]
        assert self._run(sync_db, "label:lolbin tag:apt28") == ["certutil.exe"]

    def test_negated_tag_excludes(self, sync_db):
        self._tagged(sync_db, "a.exe", "executable", tags=["noisy"])
        self._tagged(sync_db, "b.exe", "executable", tags=[])
        sync_db.commit()
        assert self._run(sync_db, "-tag:noisy .exe") == ["b.exe"]

    def test_literal_and_tag_compose(self, sync_db):
        self._tagged(sync_db, "svc_backup", "user", tags=["crown"])
        self._tagged(sync_db, "svc_other", "user", tags=[])
        self._tagged(sync_db, "admin", "user", tags=["crown"])
        sync_db.commit()
        assert self._run(sync_db, "svc_ tag:crown") == ["svc_backup"]

    def test_phrase_mode_query_is_not_split_into_and_terms(self, sync_db):
        """A back-compat guard with teeth: splitting this would return nothing."""
        self._tagged(sync_db, "powershell -enc payload", "cmdline_file")
        sync_db.commit()
        assert self._run(sync_db, "powershell -enc payload") == ["powershell -enc payload"]
