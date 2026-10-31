"""Job actions follow comparison availability and download permissions."""

import json
import shutil
import subprocess
from datetime import timedelta
from html.parser import HTMLParser

import pytest

from app.models import AnalysisJob, JobStatus, LogFile, LogType, WorkflowDef


class _Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.stack = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.elements.append((tag, attrs, tuple(self.stack)))
        if tag not in {"input", "meta", "link", "br", "hr", "img", "source"}:
            self.stack.append((tag, attrs))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break


@pytest.fixture
async def action_runs(async_db):
    workflow = WorkflowDef(name="Actions", log_types='["evtx"]', tasks_yaml="tasks: []")
    file = LogFile(original_filename="sample.evtx", stored_filename="sample", sha256="a" * 64, size_bytes=10, log_type=LogType.EVTX)
    async_db.add_all([workflow, file])
    await async_db.flush()
    jobs = [AnalysisJob(file_id=file.id, workflow_id=workflow.id, status=JobStatus.COMPLETED) for _ in range(2)]
    async_db.add_all(jobs)
    await async_db.commit()
    return jobs


@pytest.mark.parametrize("suffix", ["", "/status-partial"])
@pytest.mark.parametrize("scenario", ["completed", "partial", "failed", "cancelled", "pending", "running", "private", "newer", "different_hash", "current_running", "first_run"])
async def test_compare_action_requires_an_earlier_visible_terminal_run(test_client, async_db, action_runs, suffix, scenario):
    baseline, current = action_runs
    if scenario in {"completed", "partial", "failed", "cancelled", "pending", "running"}:
        baseline.status = JobStatus(scenario)
    elif scenario == "private":
        baseline.is_private = True
    elif scenario == "newer":
        baseline.created_at = current.created_at + timedelta(days=1)
    elif scenario == "different_hash":
        other = LogFile(original_filename="other.evtx", stored_filename="other", sha256="b" * 64, size_bytes=1, log_type=LogType.EVTX)
        async_db.add(other)
        await async_db.flush()
        baseline.file_id = other.id
    elif scenario == "current_running":
        current.status = JobStatus.RUNNING
    elif scenario == "first_run":
        current = baseline
    await async_db.commit()

    response = await test_client.get(f"/jobs/{current.id}{suffix}")
    assert response.status_code in (200, 286)
    expected = scenario in {"completed", "partial", "failed", "cancelled"}
    assert (f'href="/jobs/{current.id}/compare"' in response.text) is expected
    # Zero findings still permit comparison. Server-generated equal timestamps
    # must use the job ID tie-break instead of Python-bound datetime precision.
    if expected:
        comparison = await test_client.get(f"/jobs/{current.id}/compare")
        assert f'Baseline: <a href="/jobs/{baseline.id}"' in comparison.text


@pytest.mark.parametrize("as_admin", [False, True])
async def test_compare_action_accepts_a_private_baseline_visible_to_the_viewer(test_client, async_db, action_runs, member_user, admin_user, as_admin):
    baseline, current = action_runs
    baseline.is_private = True
    baseline.submitted_by_user_id = member_user.id
    await async_db.commit()
    viewer = admin_user if as_admin else member_user
    await test_client.post("/auth/cookie/login", data={"username": viewer.email, "password": "testpass123"})
    for suffix in ("", "/status-partial"):
        response = await test_client.get(f"/jobs/{current.id}{suffix}")
        assert f'href="/jobs/{current.id}/compare"' in response.text


@pytest.mark.parametrize("role", ["anonymous", "user", "member", "admin"])
async def test_download_menu_preserves_role_gates(test_client, action_runs, regular_user, member_user, admin_user, role):
    if role != "anonymous":
        viewer = {"user": regular_user, "member": member_user, "admin": admin_user}[role]
        await test_client.post("/auth/cookie/login", data={"username": viewer.email, "password": "testpass123"})
    job_id = action_runs[1].id
    response = await test_client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    elements = _Elements(response.text).elements
    links = {attrs["href"] for tag, attrs, ancestors in elements if tag == "a" and any(a.get("id") == "job-downloads-menu" for _, a in ancestors)}
    expected = {f"/jobs/{job_id}/findings.json"}
    if role == "admin":
        expected |= {f"/jobs/{job_id}/download", f"/jobs/{job_id}/export-raw"}
    assert links == expected
    if role != "admin":
        for route in ("download", "export-raw"):
            assert f'href="/jobs/{job_id}/{route}"' not in response.text
            assert (await test_client.get(f"/jobs/{job_id}/{route}")).status_code in (401, 403)
    assert (await test_client.get(f"/jobs/{job_id}/findings.json")).status_code == 200


@pytest.mark.skipif(shutil.which("node") is None, reason="Analytics binding execution requires Node.js")
async def test_analytics_starts_empty_and_cannot_export_until_selected(admin_client, action_runs):
    response = await admin_client.get(f"/jobs/{action_runs[1].id}")
    elements = _Elements(response.text).elements
    scope = next(attrs["x-data"] for _, attrs, _ in elements if "exportUrl" in attrs.get("x-data", ""))
    control = next((element for element in elements if element[1].get("id") == "job-analytics-download"), None)
    assert control is not None, "Analytics needs a disabled download control until a section is selected"
    tag, button, _ = control
    assert tag == "button"
    assert "disabled" in button  # Native disabled state covers pointer and keyboard activation before Alpine initializes.
    result = subprocess.run(
        [
            "node",
            "-e",
            """
const { scope, disabled, click } = JSON.parse(process.argv[1]);
const state = new Function('return (' + scope + ')')();
const window = { location: { href: '' } };
const evaluate = expression => new Function('state', 'window', 'with (state) { return (' + expression + '); }')(state, window);
const activate = () => new Function('state', 'window', 'with (state) { ' + click + ' }')(state, window);
const initial = [state.mitre, state.timeline, state.entities, state.threats];
const initiallyDisabled = evaluate(disabled);
activate();
const emptyNavigation = window.location.href;
state.entities = true;
const selectedDisabled = evaluate(disabled);
activate();
const selectedNavigation = window.location.href;
state.entities = false;
window.location.href = '';
activate();
console.log(JSON.stringify({ initial, initiallyDisabled, emptyNavigation, selectedDisabled, selectedNavigation, clearedNavigation: window.location.href }));
""",
            json.dumps({"scope": scope, "disabled": button[":disabled"], "click": button["@click"]}),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == {
        "initial": [False, False, False, False],
        "initiallyDisabled": True,
        "emptyNavigation": "",
        "selectedDisabled": False,
        "selectedNavigation": f"/jobs/{action_runs[1].id}/analytics.json?sections=entities",
        "clearedNavigation": "",
    }
