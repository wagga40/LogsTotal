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
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}")
    assert response.status_code == 200
    assert "New title" in response.text
    assert "Changed" in response.text
    assert "No longer observed" in response.text
    assert "Added" in response.text
    assert "Provenance unavailable" in response.text


async def test_comparison_defaults_to_the_previous_visible_run(test_client, async_db, runs):
    jobs, _ = runs
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare")
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
    assert (await test_client.get(f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}")).status_code == 400


async def test_incomplete_engine_does_not_imply_detections_disappeared(test_client, async_db, runs):
    jobs, tasks = runs
    tasks[1].status = TaskStatus.PARTIAL
    jobs[1].status = JobStatus.PARTIAL
    await async_db.commit()
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}")
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
