"""`GET /intel/cases/{id}/graph-active.json` — the graph's time link.

Three things this endpoint has to get right, and one it has to be honest about:

  * `AnalysisJob.event_markers` is `deferred()`. Reading it off an ORM instance raises
    `MissingGreenlet` on a detached object under async SQLAlchemy, and this route iterates
    ORM jobs — so it must be selected as an explicit column.
  * Every `CaseJobLink` job passes `can_view_job` **before** any blob is read. A marker
    index carries rule names, computers, tools and event timestamps.
  * Two empty states are not "nothing was active": a job with no index at all, and a job
    whose index predates the appended `finding_id` column. They need different responses
    from the analyst, so they are reported separately.

The honesty: the chain resolves to *"a rule this entity is linked to fired in this
window"*, not *"this entity appeared in this window"*, because a Finding aggregates every
matched event for one rule in one TaskResult.
"""

from __future__ import annotations

import gzip

import pytest

from app.intel.event_markers import MarkerAccumulator, build_index, pack_index
from app.models import (
    AnalysisJob,
    CaseEntityLink,
    CaseJobLink,
    Entity,
    Finding,
    FindingEntityLink,
    InvestigationCase,
    JobStatus,
    LogFile,
    Severity,
    TaskResult,
    TaskStatus,
    WorkflowDef,
)

T0 = "2024-01-05T12:00:00Z"
E0 = 1704456000
T1 = "2024-01-05T14:00:00Z"
E1 = 1704463200


def _index(*rows) -> bytes:
    """rows: (finding_id, timestamp)."""
    acc = MarkerAccumulator()
    for fid, ts in rows:
        acc.add((f"rule-{fid}", f"Rule {fid}", "high", "execution", "WIN94", "hayabusa", fid), ts)
    return pack_index(build_index(acc))


@pytest.fixture()
async def case_with_markers(async_db, member_user):
    """A shared case with one public job whose index covers findings 1 (T0) and 2 (T1)."""
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="x" * 64, size_bytes=1))
    async_db.add(WorkflowDef(id=1, name="wf1"))
    await async_db.commit()

    job = AnalysisJob(id=1, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, event_markers=_index((1, T0), (2, T1)))
    async_db.add(job)
    await async_db.commit()
    async_db.add(TaskResult(id=1, job_id=1, tool_name="hayabusa", status=TaskStatus.COMPLETED))
    await async_db.commit()

    early = Entity(id=1, value="early.example", entity_type="domain")
    late = Entity(id=2, value="late.example", entity_type="domain")
    async_db.add_all([early, late])
    await async_db.commit()
    async_db.add_all(
        [
            Finding(id=1, task_result_id=1, rule_id="r1", rule_name="Rule 1", severity=Severity.HIGH, count=1, tags="[]"),
            Finding(id=2, task_result_id=1, rule_id="r2", rule_name="Rule 2", severity=Severity.HIGH, count=1, tags="[]"),
        ]
    )
    await async_db.commit()
    async_db.add_all([FindingEntityLink(finding_id=1, entity_id=1), FindingEntityLink(finding_id=2, entity_id=2)])

    case = InvestigationCase(id=1, name="Case", created_by_user_id=member_user.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()
    async_db.add_all(
        [
            CaseJobLink(case_id=1, job_id=1, added_by_user_id=member_user.id),
            CaseEntityLink(case_id=1, entity_id=1, added_by_user_id=member_user.id),
            CaseEntityLink(case_id=1, entity_id=2, added_by_user_id=member_user.id),
        ]
    )
    await async_db.commit()
    return case


async def test_a_window_selects_only_the_entities_active_in_it(member_client, case_with_markers):
    body = (await member_client.get(f"/intel/cases/1/graph-active.json?frm={E0 * 1000}&to={(E0 + 60) * 1000}")).json()
    assert body["entity_ids"] == [1]

    body = (await member_client.get(f"/intel/cases/1/graph-active.json?frm={E1 * 1000}&to={(E1 + 60) * 1000}")).json()
    assert body["entity_ids"] == [2]


async def test_the_full_extent_selects_everything(member_client, case_with_markers):
    body = (await member_client.get("/intel/cases/1/graph-active.json")).json()
    assert sorted(body["entity_ids"]) == [1, 2]
    assert body["jobs"] == 1
    assert body["index_missing"] is False


async def test_milliseconds_in_seconds_out(member_client, case_with_markers):
    """`frm`/`to` are epoch **milliseconds**; the index stores seconds. The upper bound
    rounds up so a sub-second window at the very end of a bucket still includes it."""
    just_after = (await member_client.get(f"/intel/cases/1/graph-active.json?frm={E0 * 1000}&to={E0 * 1000 + 1}")).json()
    assert just_after["entity_ids"] == [1]


async def test_a_window_with_nothing_in_it_is_empty_not_an_error(member_client, case_with_markers):
    body = (await member_client.get(f"/intel/cases/1/graph-active.json?frm={(E0 - 7200) * 1000}&to={(E0 - 3600) * 1000}")).json()
    assert body["entity_ids"] == []
    assert body["jobs_without_index"] == 0
    assert body["jobs_without_finding_ids"] == 0


async def test_a_job_with_no_index_is_reported_as_such(member_client, async_db, case_with_markers, member_user):
    """`index_missing` is a 200, not an error — and it is a *different* state from "quiet"."""
    async_db.add(AnalysisJob(id=2, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, event_markers=None))
    await async_db.commit()
    async_db.add(CaseJobLink(case_id=1, job_id=2, added_by_user_id=member_user.id))
    await async_db.commit()

    body = (await member_client.get("/intel/cases/1/graph-active.json")).json()
    assert body["jobs"] == 2
    assert body["jobs_without_index"] == 1
    assert body["index_missing"] is False
    assert sorted(body["entity_ids"]) == [1, 2]


async def test_a_legacy_index_without_finding_ids_is_its_own_empty_state(member_client, async_db, case_with_markers, member_user):
    """Six-wide `keys` rows resolve nothing, and no amount of brushing will change that —
    so `jobs_without_index` staying 0 while nothing appears must not read as "quiet"."""
    from app.intel.event_markers import unpack_index
    from app.json_utils import dumps as json_dumps

    payload = unpack_index(_index((3, T0)))
    payload["keys"] = [row[:6] for row in payload["keys"]]
    legacy = gzip.compress(json_dumps(payload).encode())

    async_db.add(AnalysisJob(id=2, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, event_markers=legacy))
    await async_db.commit()
    async_db.add(CaseJobLink(case_id=1, job_id=2, added_by_user_id=member_user.id))
    await async_db.commit()

    body = (await member_client.get("/intel/cases/1/graph-active.json")).json()
    assert body["jobs_without_finding_ids"] == 1
    assert body["jobs_without_index"] == 0


async def test_an_empty_case_reports_index_missing(member_client, async_db, member_user):
    case = InvestigationCase(id=9, name="Empty", created_by_user_id=member_user.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()

    body = (await member_client.get("/intel/cases/9/graph-active.json")).json()
    assert body["entity_ids"] == []
    assert body["index_missing"] is True


async def test_a_private_jobs_index_is_never_read_for_a_non_owner(member_client, async_db, admin_user, member_user):
    """The index carries rule names, computers, tools and event timestamps."""
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="x" * 64, size_bytes=1))
    async_db.add(WorkflowDef(id=1, name="wf1"))
    await async_db.commit()
    async_db.add(
        AnalysisJob(
            id=1,
            file_id=1,
            workflow_id=1,
            status=JobStatus.COMPLETED,
            is_private=True,
            submitted_by_user_id=admin_user.id,
            event_markers=_index((1, T0)),
        )
    )
    await async_db.commit()
    async_db.add(TaskResult(id=1, job_id=1, tool_name="hayabusa", status=TaskStatus.COMPLETED))
    await async_db.commit()
    async_db.add(Entity(id=1, value="secret.example", entity_type="domain"))
    async_db.add(Finding(id=1, task_result_id=1, rule_id="r1", rule_name="Secret Rule", severity=Severity.HIGH, count=1, tags="[]"))
    await async_db.commit()
    async_db.add(FindingEntityLink(finding_id=1, entity_id=1))
    async_db.add(InvestigationCase(id=1, name="Shared case", created_by_user_id=member_user.id, is_shared=True))
    await async_db.commit()
    async_db.add(CaseJobLink(case_id=1, job_id=1, added_by_user_id=member_user.id))
    async_db.add(CaseEntityLink(case_id=1, entity_id=1, added_by_user_id=member_user.id))
    await async_db.commit()

    body = (await member_client.get("/intel/cases/1/graph-active.json")).json()
    assert body["entity_ids"] == [], "a private job's markers leaked through the time link"
    assert body["jobs"] == 0
    assert body["index_missing"] is True


async def test_an_invisible_job_id_404s_like_an_unknown_one(member_client, case_with_markers):
    """Same message either way, so the filter cannot become an existence oracle."""
    assert (await member_client.get("/intel/cases/1/graph-active.json?job_id=999")).status_code == 404


async def test_job_id_narrows_to_one_member_job(member_client, case_with_markers):
    body = (await member_client.get("/intel/cases/1/graph-active.json?job_id=1")).json()
    assert sorted(body["entity_ids"]) == [1, 2]


async def test_requires_member_or_above(test_client, case_with_markers):
    assert (await test_client.get("/intel/cases/1/graph-active.json")).status_code in (401, 403, 404)


async def test_the_case_visibility_filter_applies(member_client, async_db, admin_user, member_user):
    """An unshared case belongs to its owner; a non-owner gets the same 404 an unknown id gets.

    `member_client` and `admin_client` are the same httpx client, so the admin half logs in
    explicitly after the member assertion rather than being requested as a second fixture.
    """
    async_db.add(InvestigationCase(id=5, name="Not yours", created_by_user_id=admin_user.id, is_shared=False))
    await async_db.commit()

    assert (await member_client.get("/intel/cases/5/graph-active.json")).status_code == 404
    assert (await member_client.get("/intel/cases/404404/graph-active.json")).status_code == 404

    await member_client.post("/auth/cookie/login", data={"username": "admin@test.example.com", "password": "testpass123"})
    assert (await member_client.get("/intel/cases/5/graph-active.json")).status_code == 200
