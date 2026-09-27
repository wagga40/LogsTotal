"""The entity Findings tab offers sample events inline, without shipping them up front.

Two things are pinned here, and the second is the one that matters.

The affordance: a finding whose `details` blob is non-empty gets a "Show events" button
wired to the job page's own finding-scoped endpoint; one without gets no button, because a
disclosure that opens onto "No event details available." is worse than no disclosure.

And the cost. `Finding.details` is a JSON array of matched events — up to
`max_finding_details` of them per finding. Selecting that column into a fifty-row page
would put megabytes on the wire to render a chevron. The query asks only whether the blob
is non-empty; the events arrive one finding at a time, on click. `test_events_are_not_in
_the_page_before_you_ask_for_them` is what keeps it that way, because the feature looks
completely correct either way in a browser.
"""

from __future__ import annotations

import pytest

SAMPLE_EVENT_MARKER = "Invoke-Mimikatz-Was-Here"


async def _seed_finding(async_db, *, details: str | None):
    """One entity linked to one finding of one completed job."""
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

    entity = Entity(value="powershell.exe", entity_type="executable", job_count=1)
    lf = LogFile(original_filename="sec.evtx", stored_filename="s.evtx", sha256="c" * 64, size_bytes=1)
    wf = WorkflowDef(name="wf")
    async_db.add_all([entity, lf, wf])
    await async_db.commit()

    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.commit()

    tr = TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=1)
    async_db.add(tr)
    await async_db.commit()

    finding = Finding(
        task_result_id=tr.id,
        rule_id="rule-001",
        rule_name="Credential dumping via PowerShell",
        severity=Severity.CRITICAL,
        count=3,
        details=details,
    )
    async_db.add(finding)
    await async_db.commit()

    async_db.add(FindingEntityLink(finding_id=finding.id, entity_id=entity.id))
    await async_db.commit()

    return entity, job, finding


@pytest.mark.asyncio
async def test_a_finding_with_events_offers_the_expander(member_client, async_db):
    from app.json_utils import dumps as json_dumps

    entity, _job, finding = await _seed_finding(async_db, details=json_dumps([{"EventID": 4104, "ScriptBlockText": SAMPLE_EVENT_MARKER}]))

    resp = await member_client.get(f"/intel/entities/{entity.id}/findings-partial")
    assert resp.status_code == 200
    body = resp.text

    assert "Show events" in body
    assert f"/jobs/findings/{finding.id}/events" in body
    # Fetched at most once, like every other disclosure in this codebase.
    assert 'hx-trigger="click once"' in body
    # Namespaced away from the job page's own `#events-{id}` target.
    assert f'id="entity-finding-events-{finding.id}"' in body


@pytest.mark.asyncio
async def test_events_are_not_in_the_page_before_you_ask_for_them(member_client, async_db):
    """The expander is a promise of events, not a delivery of them."""
    from app.json_utils import dumps as json_dumps

    entity, _job, _finding = await _seed_finding(async_db, details=json_dumps([{"EventID": 4104, "ScriptBlockText": SAMPLE_EVENT_MARKER}]))

    resp = await member_client.get(f"/intel/entities/{entity.id}/findings-partial")
    assert SAMPLE_EVENT_MARKER not in resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("details", [None, ""])
async def test_a_finding_with_no_events_offers_nothing(member_client, async_db, details):
    """`coalesce(details, '') != ''` must agree with the job page's `bool(f.details)`."""
    entity, _job, _finding = await _seed_finding(async_db, details=details)

    resp = await member_client.get(f"/intel/entities/{entity.id}/findings-partial")
    assert resp.status_code == 200
    assert "Show events" not in resp.text


@pytest.mark.asyncio
async def test_the_expander_target_actually_serves_the_events(member_client, async_db):
    """The reused endpoint is finding-scoped (`/jobs/findings/{id}/events`), not nested
    under a job id, and does its own visibility check — so it works unchanged from here."""
    from app.json_utils import dumps as json_dumps

    _entity, _job, finding = await _seed_finding(async_db, details=json_dumps([{"EventID": 4104, "ScriptBlockText": SAMPLE_EVENT_MARKER}]))

    resp = await member_client.get(f"/jobs/findings/{finding.id}/events")
    assert resp.status_code == 200
    assert SAMPLE_EVENT_MARKER in resp.text
