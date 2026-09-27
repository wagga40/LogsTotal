"""Workflow CRUD answers refusals with a reason, never a 500.

Two ordinary admin actions raised IntegrityError straight out of the route:

* **Deleting a workflow any job ran.** `analysisjob.workflow_id` is NOT NULL and the ORM
  tries to null it, so Delete was a 500 for every workflow that had ever done anything — on
  SQLite and PostgreSQL alike. Deleting job history to make it work would be worse, so the
  delete is refused with the count and the page says why.
* **A second workflow with a taken name**, created or renamed — `workflowdef.name` is unique.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models import AnalysisJob, JobStatus, LogFile, WorkflowDef

pytestmark = pytest.mark.anyio

YAML = "tasks:\n  - tool: zircolite\n"


async def _workflow(db, name="Windows"):
    wf = WorkflowDef(name=name, tasks_yaml=YAML, log_types='["evtx"]')
    db.add(wf)
    await db.commit()
    await db.refresh(wf)
    return wf


async def test_a_workflow_with_jobs_is_not_deleted_and_the_page_says_why(admin_client, async_db):
    wf = await _workflow(async_db)
    lf = LogFile(original_filename="a.evtx", stored_filename="a", sha256="a" * 64, size_bytes=1)
    async_db.add(lf)
    await async_db.flush()
    async_db.add(AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED))
    await async_db.commit()

    resp = await admin_client.post(f"/workflows/{wf.id}/delete", follow_redirects=True)
    assert resp.status_code == 200
    assert "1 job" in resp.text
    assert (await async_db.execute(select(WorkflowDef))).scalars().all() != []


async def test_a_workflow_nothing_ran_is_still_deleted(admin_client, async_db):
    wf = await _workflow(async_db)
    resp = await admin_client.post(f"/workflows/{wf.id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert (await async_db.execute(select(WorkflowDef))).scalars().all() == []


async def test_creating_a_workflow_with_a_taken_name_is_refused(admin_client, async_db):
    await _workflow(async_db)
    resp = await admin_client.post("/workflows/new", data={"name": "Windows", "tasks_yaml": YAML}, follow_redirects=False)
    assert resp.status_code == 400
    assert "already exists" in resp.text


async def test_renaming_onto_a_taken_name_is_refused(admin_client, async_db):
    await _workflow(async_db)
    other = await _workflow(async_db, name="Linux")
    resp = await admin_client.post(f"/workflows/{other.id}/edit", data={"name": "Windows", "tasks_yaml": YAML}, follow_redirects=False)
    assert resp.status_code == 400
    assert "already exists" in resp.text
