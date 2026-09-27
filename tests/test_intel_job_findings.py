"""`/intel/jobs/{id}/findings` — one job's findings, read from the Intel side.

This page exists for exactly one reason: `/jobs/{id}` already lists every finding, but it
cannot say which *entities* each one resolved to. That is the whole delta, so the tests
that matter are about the chips — that they are there, that they are bounded, and that
producing them does not cost a query per row.

The rest is ordinary: visibility (a private job and a nonexistent one must 404 with the
same message), filters, and pagination.
"""

from __future__ import annotations

import pytest


async def _seed_job(async_db, *, n_findings=3, n_entities=1, private=False, owner_id=None):
    from app.models import (
        AnalysisJob,
        Entity,
        Finding,
        FindingEntityLink,
        JobStatus,
        LogFile,
        Severity,
        TaskResult,
        TaskStatus,
        WorkflowDef,
    )

    lf = LogFile(original_filename="sec.evtx", stored_filename="s.evtx", sha256="e" * 64, size_bytes=1)
    wf = WorkflowDef(name="wf")
    async_db.add_all([lf, wf])
    await async_db.commit()

    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, is_private=private, submitted_by_user_id=owner_id)
    async_db.add(job)
    await async_db.commit()

    tr = TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=n_findings)
    async_db.add(tr)
    await async_db.commit()

    entities = [Entity(value=f"host{i:02d}", entity_type="computer", job_count=1) for i in range(n_entities)]
    async_db.add_all(entities)
    await async_db.commit()

    findings = []
    for i in range(n_findings):
        f = Finding(
            task_result_id=tr.id,
            rule_id=f"r-{i}",
            rule_name=f"Rule number {i}",
            severity=Severity.CRITICAL if i == 0 else Severity.LOW,
            count=1,
            details='[{"EventID": 1}]' if i == 0 else None,
        )
        async_db.add(f)
        await async_db.commit()
        findings.append(f)
        for e in entities:
            async_db.add(FindingEntityLink(finding_id=f.id, entity_id=e.id))
    await async_db.commit()
    return job, findings, entities


@pytest.mark.asyncio
async def test_the_page_lists_the_findings_and_leads_with_the_job_page(member_client, async_db):
    job, _findings, _entities = await _seed_job(async_db)

    resp = await member_client.get(f"/intel/jobs/{job.id}/findings")
    assert resp.status_code == 200
    body = resp.text
    assert "Rule number 0" in body and "Rule number 2" in body
    # The rich view is elsewhere and the header says so first.
    assert f'href="/jobs/{job.id}"' in body
    assert "Open full job page" in body


@pytest.mark.asyncio
async def test_entity_chips_are_the_reason_this_page_exists(member_client, async_db):
    job, _findings, entities = await _seed_job(async_db, n_entities=2)

    body = (await member_client.get(f"/intel/jobs/{job.id}/findings")).text
    for e in entities:
        assert e.value in body
        assert f'href="/intel/entities/{e.id}"' in body


@pytest.mark.asyncio
async def test_chips_are_capped_with_an_exact_overflow_count(member_client, async_db):
    """Six chips fit a row; the remainder is reported as a number, never elided."""
    from app.routers.intel import _FINDING_ENTITY_CHIPS

    extra = 4
    job, _findings, _entities = await _seed_job(async_db, n_findings=1, n_entities=_FINDING_ENTITY_CHIPS + extra)

    body = (await member_client.get(f"/intel/jobs/{job.id}/findings")).text
    assert f"+{extra} more" in body


@pytest.mark.asyncio
async def test_chips_cost_one_query_for_the_whole_page_not_one_per_row(member_client, async_db):
    """A chip list per row is the obvious shape and the wrong query.

    Counted directly rather than asserted in prose: `_entity_chips_for_findings` must
    issue exactly one statement no matter how many findings it is handed.
    """
    from sqlalchemy import event

    from app.routers.intel import _entity_chips_for_findings

    _job, findings, _entities = await _seed_job(async_db, n_findings=8, n_entities=2)

    statements: list[str] = []
    engine = async_db.get_bind()  # the sync Engine behind the AsyncSession

    def _record(conn, cursor, statement, *args):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _record)
    try:
        chips = await _entity_chips_for_findings(async_db, [f.id for f in findings])
    finally:
        event.remove(engine, "before_cursor_execute", _record)

    assert len(chips) == 8
    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(selects) == 1, f"expected one windowed query, got {len(selects)}:\n" + "\n".join(selects)


@pytest.mark.asyncio
async def test_an_empty_finding_list_is_cheap(member_client, async_db):
    from app.routers.intel import _entity_chips_for_findings

    assert await _entity_chips_for_findings(async_db, []) == {}


@pytest.mark.asyncio
async def test_severity_and_entity_filters(member_client, async_db):
    job, _findings, entities = await _seed_job(async_db, n_findings=3, n_entities=1)

    crit = await member_client.get(f"/intel/jobs/{job.id}/findings?severity=critical")
    assert "Rule number 0" in crit.text
    assert "Rule number 1" not in crit.text

    scoped = await member_client.get(f"/intel/jobs/{job.id}/findings?entity_id={entities[0].id}")
    assert "Rule number 0" in scoped.text

    # An entity linked to nothing in this job filters everything out.
    from app.models import Entity

    stranger = Entity(value="nobody", entity_type="user", job_count=0)
    async_db.add(stranger)
    await async_db.commit()
    empty = await member_client.get(f"/intel/jobs/{job.id}/findings?entity_id={stranger.id}")
    assert "No findings match these filters" in empty.text


@pytest.mark.asyncio
async def test_pagination_walks_every_finding_exactly_once(member_client, async_db):
    from app.routers.intel import PAGE_SIZE

    n = PAGE_SIZE + 7
    job, _findings, _entities = await _seed_job(async_db, n_findings=n, n_entities=1)

    seen: set[str] = set()
    for page in (1, 2):
        body = (await member_client.get(f"/intel/jobs/{job.id}/findings?page={page}")).text
        for i in range(n):
            if f"Rule number {i}<" in body or f"Rule number {i}\n" in body or f">Rule number {i} " in body:
                seen.add(str(i))
    # Every rule name appears somewhere across the two pages.
    assert len(seen) == n, f"saw {len(seen)} of {n}"


@pytest.mark.asyncio
async def test_a_private_job_is_indistinguishable_from_a_nonexistent_one(member_client, admin_user, async_db):
    job, _findings, _entities = await _seed_job(async_db, private=True, owner_id=admin_user.id)

    private = await member_client.get(f"/intel/jobs/{job.id}/findings")
    absent = await member_client.get("/intel/jobs/999999/findings")
    assert private.status_code == absent.status_code == 404
    assert private.json() == absent.json()


@pytest.mark.asyncio
async def test_a_plain_user_cannot_reach_it(user_client, async_db):
    job, _findings, _entities = await _seed_job(async_db)
    assert (await user_client.get(f"/intel/jobs/{job.id}/findings")).status_code == 403


def test_the_intel_finding_row_markup_lives_in_exactly_one_place():
    """Both Intel surfaces render the same row; a second copy would drift immediately.

    Scoped to `templates/intel/`. The job page keeps its own row in `_job_status.html`
    on purpose — it is a different object: nested inside a per-severity accordion, with a
    tool filter, a rule-YAML expander and a correlation pivot the Intel row has no use
    for. Folding the two together would mean one macro with six flags.
    """
    from pathlib import Path

    intel = Path(__file__).resolve().parent.parent / "app" / "templates" / "intel"
    callers = {p.name for p in intel.rglob("*.html") if "finding_row(" in p.read_text() and p.name != "_finding_row.html"}
    assert callers == {"_entity_findings.html", "job_findings.html"}

    # The disclosure button exists once across all of Intel: in the macro.
    definers = [p.name for p in intel.rglob("*.html") if "Hide events' : 'Show events'" in p.read_text()]
    assert definers == ["_finding_row.html"]
