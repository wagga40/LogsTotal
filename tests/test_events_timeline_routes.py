"""HTTP surface for the zoomable events timeline.

Two endpoints, one shared slicer. The load-bearing tests here are the visibility ones: a
private job must not leak markers through either surface, and the case merge must apply
`can_view_job` before it reads any index — the same lesson `_finding_co_edges` learned when
an amber graph edge revealed co-occurrence inside a private job.
"""

from __future__ import annotations

import pytest

from app.intel.event_markers import MarkerAccumulator, build_index, pack_index
from app.models import (
    AnalysisJob,
    CaseJobLink,
    InvestigationCase,
    JobStatus,
    LogFile,
    LogType,
    WorkflowDef,
)

E0 = 1704456000  # 2024-01-05T12:00:00Z


def _blob(rule="Rule A", severity="high", computer="WIN94", offsets=(0, 60, 120)):
    from datetime import UTC, datetime

    acc = MarkerAccumulator()
    for off in offsets:
        ts = datetime.fromtimestamp(E0 + off, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        acc.add(("rid-1", rule, severity, "execution", computer, "hayabusa"), ts)
    return pack_index(build_index(acc))


@pytest.fixture()
async def tl_data(async_db, admin_user, member_user):
    wf = WorkflowDef(name="TL WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    lf_pub = LogFile(
        original_filename="pub.evtx",
        stored_filename="pub.evtx",
        sha256="e" * 64,
        size_bytes=1,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    lf_priv = LogFile(
        original_filename="priv.evtx",
        stored_filename="priv.evtx",
        sha256="f" * 64,
        size_bytes=1,
        log_type=LogType.EVTX,
        detected_type=LogType.EVTX,
    )
    async_db.add_all([wf, lf_pub, lf_priv])
    await async_db.flush()

    job_pub = AnalysisJob(
        file_id=lf_pub.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        event_markers=_blob(rule="Public Rule"),
    )
    job_priv = AnalysisJob(
        file_id=lf_priv.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        is_private=True,
        submitted_by_user_id=admin_user.id,
        event_markers=_blob(rule="Secret Rule", severity="critical"),
    )
    job_noindex = AnalysisJob(file_id=lf_pub.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add_all([job_pub, job_priv, job_noindex])
    await async_db.flush()

    case = InvestigationCase(name="TL Case", created_by_user_id=admin_user.id, is_shared=True)
    async_db.add(case)
    await async_db.flush()
    async_db.add_all(
        [
            CaseJobLink(case_id=case.id, job_id=job_pub.id, added_by_user_id=admin_user.id),
            CaseJobLink(case_id=case.id, job_id=job_priv.id, added_by_user_id=admin_user.id),
        ]
    )
    await async_db.commit()
    return {"case": case, "job_pub": job_pub, "job_priv": job_priv, "job_noindex": job_noindex}


async def _login(client, email):
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "testpass123"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


# ── Job endpoint ─────────────────────────────────────────────────────────────


async def test_job_timeline_returns_markers(test_client, tl_data):
    resp = await test_client.get(f"/jobs/{tl_data['job_pub'].id}/events-timeline")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 3
    assert body["items"][0]["label"] == "Public Rule"
    assert body["items"][0]["start"] == E0 * 1000
    assert body["index_missing"] is False


async def test_job_timeline_ships_the_palette(test_client, tl_data):
    """Colours come from the server so the canvas has one source of truth with the
    severity macros and the MITRE tactic map."""
    body = (await test_client.get(f"/jobs/{tl_data['job_pub'].id}/events-timeline")).json()
    assert body["colors"]["severity"]["critical"].startswith("#")
    assert body["colors"]["tactic"]["execution"].startswith("#")
    assert "_other" in body["colors"]["tactic"], "the resolver's fallback bucket needs a colour too"


async def test_job_timeline_range_is_epoch_millis(test_client, tl_data):
    jid = tl_data["job_pub"].id
    body = (await test_client.get(f"/jobs/{jid}/events-timeline", params={"frm": E0 * 1000, "to": (E0 + 60) * 1000})).json()
    assert [it["start"] for it in body["items"]] == [E0 * 1000, (E0 + 60) * 1000]


async def test_job_timeline_reports_extent(test_client, tl_data):
    body = (await test_client.get(f"/jobs/{tl_data['job_pub'].id}/events-timeline")).json()
    assert body["extent"][0] == E0 * 1000
    assert body["extent"][1] >= (E0 + 120) * 1000


async def test_job_timeline_severity_filter(test_client, tl_data):
    body = (await test_client.get(f"/jobs/{tl_data['job_pub'].id}/events-timeline", params={"severity": "low"})).json()
    assert body["items"] == []


async def test_job_without_an_index_is_200_not_500(test_client, tl_data):
    """Pre-upgrade jobs and jobs whose analytics never ran have no blob. That is a normal
    state the UI explains, not an error."""
    resp = await test_client.get(f"/jobs/{tl_data['job_noindex'].id}/events-timeline")
    assert resp.status_code == 200
    body = resp.json()
    assert body["index_missing"] is True
    assert body["items"] == []


async def test_unknown_job_404s(test_client):
    assert (await test_client.get("/jobs/999999/events-timeline")).status_code == 404


async def test_private_job_timeline_hidden_from_anonymous(test_client, tl_data):
    resp = await test_client.get(f"/jobs/{tl_data['job_priv'].id}/events-timeline")
    assert resp.status_code == 404, "a private job's markers must not be readable anonymously"


async def test_private_job_timeline_visible_to_its_submitter(test_client, tl_data, admin_user):
    await _login(test_client, admin_user.email)
    body = (await test_client.get(f"/jobs/{tl_data['job_priv'].id}/events-timeline")).json()
    assert body["items"][0]["label"] == "Secret Rule"


async def test_private_job_timeline_hidden_from_another_member(test_client, tl_data, member_user):
    await _login(test_client, member_user.email)
    resp = await test_client.get(f"/jobs/{tl_data['job_priv'].id}/events-timeline")
    assert resp.status_code == 404


# ── Case endpoint ────────────────────────────────────────────────────────────


async def test_case_timeline_requires_member(test_client, tl_data):
    assert (await test_client.get(f"/intel/cases/{tl_data['case'].id}/events-timeline")).status_code in (401, 403, 404)


async def test_case_timeline_merges_visible_jobs(test_client, tl_data, admin_user):
    await _login(test_client, admin_user.email)
    body = (await test_client.get(f"/intel/cases/{tl_data['case'].id}/events-timeline")).json()
    labels = {it["label"] for it in body["items"]}
    assert labels == {"Public Rule", "Secret Rule"}, "the owner sees both member jobs"
    assert {it["meta"]["job_id"] for it in body["items"]} == {tl_data["job_pub"].id, tl_data["job_priv"].id}


async def test_case_timeline_excludes_a_private_job_the_viewer_cannot_see(test_client, tl_data, member_user):
    """A private job linked into a shared case must not contribute markers to a non-owner.

    Without the `can_view_job` pass this endpoint would happily merge its index — the
    marker label alone names a Sigma rule that fired inside someone else's private upload.
    """
    await _login(test_client, member_user.email)
    body = (await test_client.get(f"/intel/cases/{tl_data['case'].id}/events-timeline")).json()
    labels = {it["label"] for it in body["items"]}
    assert labels == {"Public Rule"}
    assert "Secret Rule" not in labels


async def test_case_timeline_job_filter_narrows(test_client, tl_data, admin_user):
    await _login(test_client, admin_user.email)
    body = (await test_client.get(f"/intel/cases/{tl_data['case'].id}/events-timeline", params={"job_id": tl_data["job_pub"].id})).json()
    assert {it["label"] for it in body["items"]} == {"Public Rule"}


async def test_case_timeline_job_filter_cannot_probe_invisible_jobs(test_client, tl_data, member_user):
    """Filtering by a job the viewer cannot see must 404 exactly like an unknown id, so the
    filter is not an existence oracle."""
    await _login(test_client, member_user.email)
    hidden = await test_client.get(f"/intel/cases/{tl_data['case'].id}/events-timeline", params={"job_id": tl_data["job_priv"].id})
    unknown = await test_client.get(f"/intel/cases/{tl_data['case'].id}/events-timeline", params={"job_id": 999999})
    assert hidden.status_code == unknown.status_code == 404
    assert hidden.json()["detail"] == unknown.json()["detail"]


async def test_case_timeline_unknown_case_404s(test_client, admin_user):
    await _login(test_client, admin_user.email)
    assert (await test_client.get("/intel/cases/999999/events-timeline")).status_code == 404


# ── Rendering ────────────────────────────────────────────────────────────────


async def test_job_analytics_mounts_the_timeline(test_client, tl_data, async_db):
    """The panel must actually appear under the histogram on the job page.

    A broken `{% include %}` or a missing context var renders as *silence* here — the card
    simply vanishes — so assert on the mount rather than on a 200.
    """
    from app.json_utils import dumps as json_dumps

    job = tl_data["job_pub"]
    job.analytics_json = json_dumps(
        {
            "mitre_tactics": {},
            "timeline": [],
            "timeline_tactics": [],
            "users": [],
            "computers": [],
            "ip_addresses": [],
            "hashes": [],
            "executables": [],
            "domains": [],
            "cmdline_files": [],
            "services": [],
            "tasks": [],
            "threat_detection": {},
        }
    )
    await async_db.commit()

    html = (await test_client.get(f"/jobs/{job.id}/analytics")).text
    assert "eventTimeline(" in html, "the events timeline did not mount on the job page"
    assert f"/jobs/{job.id}/events-timeline" in html
    assert f"job:{job.id}" in html, "the surface needs its own key in the timelineRange store"


async def test_case_timeline_tab_mounts_the_timeline(test_client, tl_data, admin_user):
    await _login(test_client, admin_user.email)
    html = (await test_client.get(f"/intel/cases/{tl_data['case'].id}/timeline-partial")).text
    assert "eventTimeline(" in html, "the events timeline did not mount on the case Timeline tab"
    assert f"/intel/cases/{tl_data['case'].id}/events-timeline" in html


async def test_job_page_loads_the_timeline_scripts_before_alpine(test_client, tl_data):
    """Alpine evaluates x-data in a microtask right after its own script, so a factory
    defined in a later deferred script is undefined exactly when it is needed."""
    html = (await test_client.get(f"/jobs/{tl_data['job_pub'].id}")).text
    assert html.index("/static/timeline.js") < html.index("/static/vendor/alpine.min.js")
    assert html.index("/static/timeline-canvas.js") < html.index("/static/vendor/alpine.min.js")


async def test_pages_without_a_timeline_do_not_load_its_scripts(test_client):
    """The renderer is ~15 KB of canvas code; only two surfaces use it."""
    html = (await test_client.get("/jobs")).text
    assert "/static/timeline.js" not in html


async def test_job_timeline_ships_stable_groupings(test_client, tl_data):
    """The lane set must come from the index so zooming cannot resize the canvas."""
    jid = tl_data["job_pub"].id
    full = (await test_client.get(f"/jobs/{jid}/events-timeline")).json()
    assert full["groupings"] == ["execution"]

    # A window containing no markers still reports the lane.
    empty = (await test_client.get(f"/jobs/{jid}/events-timeline", params={"frm": (E0 + 900) * 1000, "to": (E0 + 1800) * 1000})).json()
    assert empty["items"] == []
    assert empty["groupings"] == ["execution"]


async def test_case_timeline_unions_groupings(test_client, tl_data, admin_user):
    await _login(test_client, admin_user.email)
    body = (await test_client.get(f"/intel/cases/{tl_data['case'].id}/events-timeline")).json()
    assert body["groupings"] == ["execution"]
