"""Comparison choices and submitted baselines obey the same eligibility rules."""

from datetime import datetime
from html.parser import HTMLParser

import pytest

from app.models import AnalysisJob, Finding, JobStatus, LogFile, TaskResult, TaskStatus, WorkflowDef


class _BaselineOptions(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.in_selector = False
        self.current = None
        self.options = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "select":
            self.in_selector = attrs.get("name") == "baseline"
        if tag == "option" and self.in_selector:
            self.current = {"id": int(attrs["value"]), "selected": "selected" in attrs, "text": ""}
            self.options.append(self.current)

    def handle_data(self, data):
        if self.current is not None:
            self.current["text"] += data

    def handle_endtag(self, tag):
        if tag == "option":
            self.current = None
        if tag == "select":
            self.in_selector = False


@pytest.fixture
async def comparison_choices(async_db, member_user):
    workflow = WorkflowDef(name="Comparison workflow", log_types='["evtx"]', tasks_yaml="tasks: []")
    private_workflow = WorkflowDef(name="Owner-only workflow", log_types='["evtx"]', tasks_yaml="tasks: []")
    file = LogFile(original_filename="sample.evtx", stored_filename="sample", sha256="a" * 64, size_bytes=10)
    other_file = LogFile(original_filename="other.evtx", stored_filename="other", sha256="b" * 64, size_bytes=10)
    async_db.add_all([workflow, private_workflow, file, other_file])
    await async_db.flush()
    jobs = {}
    for name, day, status in [
        ("oldest", 1, JobStatus.COMPLETED),
        ("failed", 2, JobStatus.FAILED),
        ("cancelled", 3, JobStatus.CANCELLED),
        ("previous", 4, JobStatus.PARTIAL),
        ("private", 4, JobStatus.COMPLETED),
        ("pending", 4, JobStatus.PENDING),
        ("running", 4, JobStatus.RUNNING),
        ("different", 4, JobStatus.COMPLETED),
        ("current", 5, JobStatus.COMPLETED),
        ("same_time", 5, JobStatus.COMPLETED),
        ("future", 6, JobStatus.COMPLETED),
    ]:
        jobs[name] = AnalysisJob(
            file_id=other_file.id if name == "different" else file.id,
            workflow_id=private_workflow.id if name == "private" else workflow.id,
            status=status,
            created_at=datetime(2026, 1, day),
            is_private=name == "private",
            submitted_by_user_id=member_user.id if name == "private" else None,
        )
    async_db.add_all(jobs.values())
    await async_db.commit()
    return jobs


async def test_selector_only_lists_earlier_visible_terminal_runs(test_client, comparison_choices):
    jobs = comparison_choices
    response = await test_client.get(f"/jobs/{jobs['current'].id}/compare")
    assert response.status_code == 200
    options = _BaselineOptions(response.text).options
    assert [option["id"] for option in options] == [jobs[name].id for name in ("previous", "cancelled", "failed", "oldest")]
    assert [option["id"] for option in options if option["selected"]] == [jobs["previous"].id]
    assert "Compare with" in response.text
    assert "Owner-only workflow" not in response.text
    for option, name in zip(options, ("previous", "cancelled", "failed", "oldest"), strict=True):
        assert f"#{jobs[name].id}" in option["text"]
        assert "Comparison workflow" in option["text"]
        assert jobs[name].created_at.strftime("%Y-%m-%d %H:%M") in option["text"]
        assert jobs[name].status.value in option["text"]


@pytest.mark.parametrize("viewer", ["owner", "admin", "other"])
async def test_selector_preserves_private_baseline_visibility(test_client, comparison_choices, member_user, admin_user, regular_user, viewer):
    user = {"owner": member_user, "admin": admin_user, "other": regular_user}[viewer]
    await test_client.post("/auth/cookie/login", data={"username": user.email, "password": "testpass123"})
    jobs = comparison_choices
    response = await test_client.get(f"/jobs/{jobs['current'].id}/compare")
    options = _BaselineOptions(response.text).options
    expected_names = ("private", "previous", "cancelled", "failed", "oldest") if viewer != "other" else ("previous", "cancelled", "failed", "oldest")
    assert [option["id"] for option in options] == [jobs[name].id for name in expected_names]
    assert [option["id"] for option in options if option["selected"]] == [jobs[expected_names[0]].id]
    explicit = await test_client.get(f"/jobs/{jobs['current'].id}/compare?baseline={jobs['private'].id}")
    assert explicit.status_code == (200 if viewer != "other" else 404)


async def test_selecting_an_eligible_run_changes_findings_and_keeps_pagination(test_client, async_db, comparison_choices):
    jobs = comparison_choices
    tasks = {name: TaskResult(job_id=jobs[name].id, tool_name="hayabusa", status=TaskStatus.COMPLETED) for name in ("oldest", "previous", "current")}
    async_db.add_all(tasks.values())
    await async_db.flush()
    async_db.add_all(
        [Finding(task_result_id=tasks[name].id, rule_id="aaa-marker", rule_name=f"Only from {name}", severity="low", count=1) for name in ("oldest", "previous")]
        + [Finding(task_result_id=tasks["current"].id, rule_id=f"current-{i}", rule_name=f"Current rule {i}", severity="low", count=1) for i in range(100)]
    )
    await async_db.commit()
    for name, excluded in (("oldest", "previous"), ("previous", "oldest")):
        baseline_id = jobs[name].id
        response = await test_client.get(f"/jobs/{jobs['current'].id}/compare?baseline={baseline_id}")
        assert response.status_code == 200
        options = _BaselineOptions(response.text).options
        assert [option["id"] for option in options if option["selected"]] == [baseline_id]
        results = await test_client.get(f"/jobs/{jobs['current'].id}/compare?baseline={baseline_id}", headers={"HX-Request": "true"})
        assert f"Only from {name}" in results.text
        assert f"Only from {excluded}" not in results.text
        assert f'hx-get="/jobs/{jobs["current"].id}/compare?page=2&amp;baseline={baseline_id}"' in results.text
        next_page = await test_client.get(f"/jobs/{jobs['current'].id}/compare?page=2&baseline={baseline_id}", headers={"HX-Request": "true"})
        assert next_page.status_code == 200
        assert f"baseline={baseline_id}" in next_page.headers["HX-Push-Url"]


async def test_selector_is_absent_when_there_are_no_eligible_runs(test_client, comparison_choices):
    response = await test_client.get(f"/jobs/{comparison_choices['oldest'].id}/compare")
    assert response.status_code == 200
    assert 'name="baseline"' not in response.text
    assert "No earlier visible run" in response.text


@pytest.mark.parametrize(
    "choice, status", [("future", 400), ("same_time", 400), ("current", 400), ("different", 400), ("pending", 409), ("running", 409), ("private", 404), ("missing", 404)]
)
async def test_forged_baseline_cannot_bypass_selector_eligibility(test_client, comparison_choices, choice, status):
    jobs = comparison_choices
    baseline_id = jobs[choice].id if choice != "missing" else 999999
    response = await test_client.get(f"/jobs/{jobs['current'].id}/compare?baseline={baseline_id}")
    assert response.status_code == status
    assert "Owner-only workflow" not in response.text
