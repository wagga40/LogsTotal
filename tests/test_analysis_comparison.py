"""Stored analysis comparisons obey visibility and distinguish changes from gaps."""

from __future__ import annotations

import json

import pytest

from app.models import AnalysisJob, Finding, JobStatus, LogFile, LogType, TaskResult, TaskStatus, WorkflowDef


@pytest.fixture
async def runs(async_db):
    workflow = WorkflowDef(name="Compare", log_types='["evtx"]', tasks_yaml="tasks: []")
    file = LogFile(original_filename="sample.evtx", stored_filename="sample", sha256="a" * 64, size_bytes=10, log_type=LogType.EVTX)
    async_db.add_all([workflow, file])
    await async_db.flush()
    jobs = [AnalysisJob(file_id=file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED) for _ in range(2)]
    async_db.add_all(jobs)
    await async_db.flush()
    tasks = [TaskResult(job_id=j.id, tool_name="hayabusa", status=TaskStatus.COMPLETED) for j in jobs]
    async_db.add_all(tasks)
    await async_db.flush()
    async_db.add_all(
        [
            Finding(task_result_id=tasks[0].id, rule_id="same", rule_name="Old title", severity="low", count=2),
            Finding(task_result_id=tasks[1].id, rule_id="same", rule_name="New title", severity="high", count=3),
            Finding(task_result_id=tasks[0].id, rule_id="missing", rule_name="Previous only", severity="high", count=1),
            Finding(task_result_id=tasks[1].id, rule_id="added", rule_name="New only", severity="medium", count=1),
        ]
    )
    await async_db.commit()
    return jobs, tasks


async def test_comparison_matches_rule_identity_across_title_and_severity_changes(test_client, runs):
    jobs, _ = runs
    url = f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}"
    shell = await test_client.get(url)
    assert "Provenance unavailable" in shell.text
    response = await test_client.get(url, headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "New title" in response.text
    assert "Changed" in response.text
    assert "No longer observed" in response.text
    assert "Added" in response.text
    # One page: the full pager renders nothing, so the compact one carries the count.
    assert "3 rule comparisons" in response.text


async def test_comparison_defaults_to_the_previous_visible_run(test_client, async_db, runs):
    jobs, _ = runs
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "Previous only" in response.text
    jobs[0].is_private = True
    await async_db.commit()
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare")
    assert response.status_code == 200
    assert "No earlier visible run" in response.text
    assert "Previous only" not in response.text


async def test_comparison_authorizes_both_jobs(test_client, async_db, runs):
    jobs, _ = runs
    jobs[0].is_private = True
    await async_db.commit()
    for current, baseline in [(jobs[1], jobs[0]), (jobs[0], jobs[1])]:
        response = await test_client.get(f"/jobs/{current.id}/compare?baseline={baseline.id}")
        assert response.status_code == 404
        assert "Previous only" not in response.text


async def test_comparison_rejects_running_or_different_input(test_client, async_db, runs):
    jobs, _ = runs
    jobs[0].status = JobStatus.RUNNING
    await async_db.commit()
    assert (await test_client.get(f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}")).status_code == 409
    jobs[0].status = JobStatus.COMPLETED
    other = LogFile(original_filename="other", stored_filename="other", sha256="b" * 64, size_bytes=1)
    async_db.add(other)
    await async_db.flush()
    jobs[0].file_id = other.id
    await async_db.commit()
    url = f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}"
    # The client shares this session; a real request's fresh one would not hold the old file.
    async_db.expire(jobs[0])
    assert (await test_client.get(url)).status_code == 400


async def test_incomplete_engine_does_not_imply_detections_disappeared(test_client, async_db, runs):
    jobs, tasks = runs
    tasks[1].status = TaskStatus.PARTIAL
    jobs[1].status = JobStatus.PARTIAL
    await async_db.commit()
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "Not comparable" in response.text
    assert "No longer observed" not in response.text


async def test_analysis_report_preserves_legacy_unknowns_and_filters_internal_metadata(test_client, async_db, runs):
    jobs, tasks = runs
    tasks[1].execution_snapshot = json.dumps({"schema_version": 1, "tool": "hayabusa", "engine_version": "4.2.0", "secret": "PRIVATE_TOKEN", "tool_path": "/private/path"})
    await async_db.commit()
    response = await test_client.get(f"/jobs/{jobs[1].id}/analysis.json")
    assert response.status_code == 200
    data = response.json()
    assert data["provenance"] is None
    assert data["tasks"][0]["provenance"]["engine_version"] == "4.2.0"
    assert {f["rule_id"] for f in data["tasks"][0]["findings"]} == {"same", "added"}
    assert "PRIVATE_TOKEN" not in response.text
    assert "/private/path" not in response.text
    jobs[1].is_private = True
    await async_db.commit()
    assert (await test_client.get(f"/jobs/{jobs[1].id}/analysis.json")).status_code == 404


async def test_an_unbindable_baseline_is_not_found(test_client, runs):
    """Past int4 the bind is a 500 on both backends, anonymously; no row can have it."""
    jobs, _ = runs
    for baseline in (2**31, 10**20):
        assert (await test_client.get(f"/jobs/{jobs[1].id}/compare?baseline={baseline}")).status_code == 404


async def test_analysis_report_download_is_audited_like_the_findings_export(test_client, async_db, runs):
    from sqlalchemy import select

    from app.models import ActivityEvent, SiteSettings

    jobs, _ = runs
    site = await async_db.get(SiteSettings, 1) or SiteSettings(id=1)
    site.activity_log_enabled = True
    async_db.add(site)
    await async_db.commit()
    assert (await test_client.get(f"/jobs/{jobs[1].id}/analysis.json")).status_code == 200
    rows = (await async_db.scalars(select(ActivityEvent).where(ActivityEvent.action == "export.job_analysis"))).all()
    assert [(row.target_type, row.target_id) for row in rows] == [("job", str(jobs[1].id))]


async def test_analysis_details_appear_only_for_tools_that_ran(test_client, async_db, runs):
    jobs, tasks = runs
    tasks[1].diagnostics_json = json.dumps(
        {"schema_version": 1, "completion": "complete", "processed_events": 7, "rules_loaded": 9, "rules_skipped": None, "records_skipped": 0, "warnings": []}
    )
    async_db.add(TaskResult(job_id=jobs[1].id, tool_name="chainsaw", status=TaskStatus.SKIPPED, error_message="not supported"))
    await async_db.commit()
    page = (await test_client.get(f"/jobs/{jobs[1].id}/status-partial")).text
    assert page.count("Analysis details") == 1
    assert "Events processed: 7" in page
    assert "coverage unverified" not in page
