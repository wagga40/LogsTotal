"""Comparison loading stays bounded by a page, not by the size of both runs."""

import json
import shutil
import subprocess
from html.parser import HTMLParser

import pytest
from sqlalchemy import event

from app.models import AnalysisJob, Finding, JobStatus, LogFile, TaskResult, TaskStatus, WorkflowDef

HX = {"HX-Request": "true", "HX-Target": "comparison-results"}


class _LoadingControls(HTMLParser):
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "@htmx:before-request" in attrs:
            self.state = attrs


@pytest.fixture
async def paged_runs(async_db):
    workflow = WorkflowDef(name="Paged", tasks_yaml="tasks: []")
    file = LogFile(original_filename="sample", stored_filename="sample", sha256="f" * 64, size_bytes=1)
    async_db.add_all([workflow, file])
    await async_db.flush()
    jobs = [AnalysisJob(file_id=file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED, analytics_json='{"unused":"large"}') for _ in range(2)]
    async_db.add_all(jobs)
    await async_db.flush()
    tasks = [TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.COMPLETED) for job in jobs]
    async_db.add_all(tasks)
    await async_db.flush()
    async_db.add_all(
        Finding(task_result_id=task.id, rule_id=f"r{i:03d}", rule_name=f"Rule {i:03d}", severity="low", count=1, details='[{"unused":"large"}]')
        for task in tasks
        for i in range(205)
    )
    await async_db.commit()
    return jobs, tasks


async def test_initial_comparison_does_not_query_findings_or_large_job_fields(test_client, async_db, paged_runs):
    jobs, _ = paged_runs
    statements = []
    engine = async_db.get_bind()

    def record(conn, cursor, statement, *args):
        statements.append(statement.lower())

    event.listen(engine, "before_cursor_execute", record)
    try:
        response = await test_client.get(f"/jobs/{jobs[1].id}/compare")
    finally:
        event.remove(engine, "before_cursor_execute", record)

    assert response.status_code == 200
    assert 'id="comparison-results"' in response.text
    assert 'hx-trigger="load"' in response.text
    assert "Rule 000" not in response.text
    assert not any("from finding" in sql or "analysisjob.analytics_json" in sql for sql in statements)


async def test_fragment_pages_have_bounded_results_and_canonical_history(test_client, paged_runs):
    jobs, _ = paged_runs
    path = f"/jobs/{jobs[1].id}/compare"
    for page, first, last, missing in [(1, "000", "099", "100"), (2, "100", "199", "000"), (999, "200", "204", "199")]:
        response = await test_client.get(f"{path}?baseline={jobs[0].id}&page={page}", headers=HX)
        assert response.status_code == 200
        assert "<html" not in response.text
        assert f"Rule {first}" in response.text and f"Rule {last}" in response.text
        assert f"Rule {missing}" not in response.text
        assert "205 rule comparisons" in response.text
        expected_page = min(page, 3)
        assert response.headers["HX-Push-Url"] == f"{path}?baseline={jobs[0].id}&page={expected_page}"


async def test_paged_aggregation_preserves_duplicates_severities_and_identity_kinds(async_db, paged_runs):
    from app.analysis_comparison import compare_findings_page

    jobs, tasks = paged_runs
    async_db.add_all(
        [
            Finding(task_result_id=tasks[0].id, rule_id="r000", rule_name="Later title", severity="high", count=3),
            Finding(task_result_id=tasks[1].id, rule_id="r000", rule_name="Rule 000", severity="high", count=4),
            Finding(task_result_id=tasks[1].id, rule_id=None, rule_name="r000", severity="low", count=2),
            Finding(task_result_id=tasks[1].id, rule_id="", rule_name="r000", severity="low", count=3),
        ]
    )
    await async_db.commit()

    result = await compare_findings_page(async_db, jobs[0].id, jobs[1].id, page=1, per_page=100)
    row = result["rows"][0]
    assert result["total"] == 206
    assert len(result["rows"]) == 100
    assert row["change"] == "Changed"
    assert row["before"]["title"] == "Rule 000"
    assert row["before"]["count"] == 4
    assert row["before"]["severities"] == {"low": 1, "high": 3}
    assert row["after"]["count"] == 5
    last = await compare_findings_page(async_db, jobs[0].id, jobs[1].id, page=3, per_page=100)
    assert last["rows"][-1]["title"] == "r000"
    assert last["rows"][-1]["change"] == "Added"
    assert last["rows"][-1]["after"]["count"] == 5


async def test_multiple_tasks_and_absent_tools_preserve_incomplete_comparisons(async_db, paged_runs):
    from app.analysis_comparison import compare_findings_page

    jobs, _ = paged_runs
    extra = TaskResult(job_id=jobs[1].id, tool_name="zircolite", status=TaskStatus.PARTIAL)
    absent = TaskResult(job_id=jobs[1].id, tool_name="chainsaw", status=TaskStatus.COMPLETED)
    post = TaskResult(job_id=jobs[1].id, tool_name="Computing analytics", status=TaskStatus.COMPLETED)
    async_db.add_all([extra, absent, post])
    await async_db.flush()
    async_db.add_all(
        [
            Finding(task_result_id=extra.id, rule_id="r000", rule_name="Rule 000", severity="low", count=3),
            Finding(task_result_id=absent.id, rule_id="r000", rule_name="Other tool", severity="low", count=1),
            Finding(task_result_id=post.id, rule_id="exclude", rule_name="Post processing", severity="low", count=1),
        ]
    )
    await async_db.commit()
    result = await compare_findings_page(async_db, jobs[0].id, jobs[1].id, page=1, per_page=100)
    assert result["total"] == 206
    assert result["rows"][0]["tool"] == "chainsaw"
    assert result["rows"][0]["change"] == "Not comparable"
    assert result["rows"][1]["after"]["count"] == 4
    assert result["rows"][1]["change"] == "Not comparable"


async def test_representative_title_follows_task_order_not_completion_order(async_db, paged_runs):
    from app.analysis_comparison import compare_findings_page

    jobs, tasks = paged_runs
    extras = [TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.COMPLETED) for job in jobs]
    async_db.add_all(extras)
    await async_db.flush()
    # Parallel workers can persist the second task's findings before the first's.
    for task, title in [(extras[0], "Alternative title"), (tasks[0], "Primary title"), (tasks[1], "Primary title"), (extras[1], "Alternative title")]:
        async_db.add(Finding(task_result_id=task.id, rule_id="aaa-order", rule_name=title, severity="low", count=1))
        await async_db.flush()
    result = await compare_findings_page(async_db, jobs[0].id, jobs[1].id, page=1, per_page=100)
    row = result["rows"][0]
    assert row["change"] == "Unchanged"
    assert row["before"]["title"] == row["after"]["title"] == "Primary title"
    assert row["before"]["count"] == row["after"]["count"] == 2


async def test_fragment_never_materializes_findings_or_loads_their_blobs(test_client, async_db, paged_runs):
    jobs, _ = paged_runs
    path = f"/jobs/{jobs[1].id}/compare"
    loaded, statements = [], []
    engine = async_db.get_bind()

    def finding_loaded(target, context):
        loaded.append(target.id)

    def record(conn, cursor, statement, *args):
        statements.append(statement.lower())

    async_db.expunge_all()
    event.listen(Finding, "load", finding_loaded)
    event.listen(engine, "before_cursor_execute", record)
    try:
        response = await test_client.get(path, headers=HX)
    finally:
        event.remove(Finding, "load", finding_loaded)
        event.remove(engine, "before_cursor_execute", record)
    assert response.status_code == 200
    assert "Rule 000" in response.text
    assert not loaded
    assert not any(field in sql for sql in statements for field in [".details", ".rule_content", ".analytics_json", ".log_output"])


async def test_comparison_metadata_uses_saved_version_without_full_logs(test_client, async_db, paged_runs):
    jobs, tasks = paged_runs
    tasks[1].execution_snapshot = json.dumps({"schema_version": 1, "engine_version": None, "execution_mode": "docker"})
    tasks[1].log_output = "-= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-\n v4.2.0\n" + "PRIVATE_LOG" * 10000
    await async_db.commit()
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare")
    assert "Version 4.2.0" in response.text
    assert "PRIVATE_LOG" not in response.text


async def test_history_restore_returns_the_full_page(test_client, paged_runs):
    jobs, _ = paged_runs
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare?page=2", headers={**HX, "HX-History-Restore-Request": "true"})
    assert response.status_code == 200
    assert "<html" in response.text
    assert 'id="comparison-results"' in response.text


async def test_initial_async_load_replaces_history_instead_of_adding_a_page(test_client, paged_runs):
    jobs, _ = paged_runs
    url = f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}&page=2"
    response = await test_client.get(url, headers={**HX, "HX-Trigger": "comparison-results"})
    assert response.status_code == 200
    assert response.headers.get("HX-Replace-Url") == url
    assert "HX-Push-Url" not in response.headers
    assert "data-comparison-loaded" in response.text


@pytest.mark.skipif(not shutil.which("node"), reason="Node is required to evaluate rendered Alpine controls")
async def test_loading_state_recovers_after_failure_and_cached_history(test_client, paged_runs):
    from tests.test_alpine_bindings_initialize import assert_all_bindings_scoped, assert_alpine_expressions_are_intact, assert_scope_identifiers_resolve

    jobs, _ = paged_runs
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare")
    assert_all_bindings_scoped(response.text, "comparison shell")
    assert_alpine_expressions_are_intact(response.text, "comparison shell")
    assert_scope_identifiers_resolve(response.text, "comparison shell")
    parser = _LoadingControls()
    parser.feed(response.text)
    controls = parser.state
    result = subprocess.run(
        [
            "node",
            "-e",
            """
const attrs = JSON.parse(process.argv[1]);
const evaluate = (state, expression, successful) => new Function('state', '$event', 'with (state) { ' + expression + ' }')(state, {detail: {successful}});
const capture = state => [state.loading, state.failed, state.loaded];
const results = [false, true].map(cached => {
  const state = new Function('$el', 'return (' + attrs['x-data'] + ')')({querySelector: () => cached ? {} : null});
  const initial = capture(state);
  evaluate(state, attrs['@htmx:before-request']);
  evaluate(state, attrs['@htmx:after-request'], false);
  const failed = capture(state);
  evaluate(state, attrs['@htmx:before-request']);
  const retrying = capture(state);
  evaluate(state, attrs['@htmx:after-request'], true);
  return { initial, failed, retrying, done: capture(state) };
});
console.log(JSON.stringify(results));
""",
            json.dumps(controls),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == [
        {"initial": [True, False, False], "failed": [False, True, False], "retrying": [True, False, False], "done": [False, False, True]},
        {"initial": [False, False, True], "failed": [False, True, True], "retrying": [True, False, True], "done": [False, False, True]},
    ]


@pytest.mark.parametrize("private_index", [0, 1])
async def test_fragment_rechecks_visibility(test_client, async_db, paged_runs, private_index):
    jobs, _ = paged_runs
    jobs[private_index].is_private = True
    await async_db.commit()
    response = await test_client.get(f"/jobs/{jobs[1].id}/compare?baseline={jobs[0].id}", headers=HX)
    assert response.status_code == 404
    assert "Rule 000" not in response.text
