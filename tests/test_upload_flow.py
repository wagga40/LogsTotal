"""Integration tests for the upload flow (homepage + POST /upload)."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.database import utc_now_naive
from app.models import AnalysisJob, JobStatus, LogFile, LogType, WorkflowDef


@pytest.fixture()
async def seeded_workflow(async_db) -> WorkflowDef:
    """Insert a default workflow for upload tests."""
    wf = WorkflowDef(
        name="Test Workflow",
        description="For testing",
        log_types='["evtx"]',
        tasks_yaml="tasks:\n  - tool: zircolite\n    tool_path: tools/zircolite/zircolite.py\n    rules_path: tools/zircolite/rules\n",
        is_default=True,
    )
    async_db.add(wf)
    await async_db.commit()
    await async_db.refresh(wf)
    return wf


async def test_homepage_renders(test_client):
    """GET / should return 200 with the upload form."""
    resp = await test_client.get("/")
    assert resp.status_code == 200
    assert "upload" in resp.text.lower() or "LogsTotal" in resp.text


async def test_homepage_shows_workflows(test_client, seeded_workflow):
    """GET / should list available workflows."""
    resp = await test_client.get("/")
    assert resp.status_code == 200
    assert "Test Workflow" in resp.text


async def test_homepage_wires_detect_preview(test_client, seeded_workflow):
    """The upload form must call /detect-preview and still post log_type_override."""
    resp = await test_client.get("/")
    assert resp.status_code == 200
    assert "/static/upload.js" in resp.text
    source = (await test_client.get("/static/upload.js")).text
    assert "/detect-preview" in source
    assert "log_type_override: row.override" in source


async def test_upload_requires_workflow_id(test_client):
    """POST /upload without workflow_id should fail (422)."""
    resp = await test_client.post("/upload", data={"log_type_override": "auto"}, files={"file": ("test.log", b"hello", "application/octet-stream")})
    assert resp.status_code == 422


async def test_upload_rejects_invalid_workflow(test_client):
    """POST /upload with nonexistent workflow_id should return 400."""
    resp = await test_client.post(
        "/upload",
        data={"workflow_id": "99999", "log_type_override": "auto"},
        files={"file": ("test.log", b"some log data\n", "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_upload_accepts_valid_file(test_client, seeded_workflow):
    """POST /upload with a valid file should redirect to /jobs/{id}."""
    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(seeded_workflow.id), "log_type_override": "auto"},
        files={"file": ("test.evtx", b"ElfFile\x00" + b"\x00" * 100, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/jobs/" in resp.headers.get("location", "")


async def test_upload_duplicate_redirects(test_client, seeded_workflow):
    """Uploading the same file twice should redirect to the existing job with ?dup=1."""
    file_content = b"ElfFile\x00" + b"\x00" * 100
    # First upload
    resp1 = await test_client.post(
        "/upload",
        data={"workflow_id": str(seeded_workflow.id), "log_type_override": "auto"},
        files={"file": ("test.evtx", file_content, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp1.status_code == 303

    # Second upload (same content)
    resp2 = await test_client.post(
        "/upload",
        data={"workflow_id": str(seeded_workflow.id), "log_type_override": "auto"},
        files={"file": ("test.evtx", file_content, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp2.status_code == 303
    assert "dup=1" in resp2.headers.get("location", "")


_SYSLOG_BODY = b"2026-07-19T10:00:00+02:00 host sshd[1]: Accepted password for root\n"
_EVTX_BODY = b"ElfFile\x00" + b"\x00" * 100


async def _upload_sample(client, workflow, **fields):
    return await client.post(
        "/upload",
        data={"workflow_id": str(workflow.id), "log_type_override": "auto", **fields},
        files={"file": ("test.evtx", _EVTX_BODY, "application/octet-stream")},
        follow_redirects=False,
    )


@pytest.mark.parametrize("was_private", [False, True])
async def test_duplicate_upload_honours_a_changed_privacy(user_client, async_db, seeded_workflow, was_private, monkeypatch):
    queued = []
    monkeypatch.setattr("app.routers.upload.run_analysis", queued.append)
    first = await _upload_sample(user_client, seeded_workflow, is_private=str(was_private).lower())
    second = await _upload_sample(user_client, seeded_workflow, is_private=str(not was_private).lower())

    assert first.status_code == second.status_code == 303
    jobs = (await async_db.scalars(select(AnalysisJob).order_by(AnalysisJob.id))).all()
    assert [job.is_private for job in jobs] == [was_private, not was_private]
    assert jobs[0].file_id == jobs[1].file_id
    assert second.headers["location"] == f"/jobs/{jobs[1].id}"
    assert queued == [job.id for job in jobs]
    user_client.cookies.clear()
    for job in jobs:
        assert (await user_client.get(f"/jobs/{job.id}")).status_code == (404 if job.is_private else 200)


@pytest.mark.parametrize("signed_in", [False, True])
@pytest.mark.parametrize("status", list(JobStatus))
async def test_duplicate_upload_retries_only_failed_or_cancelled_runs(user_client, async_db, seeded_workflow, monkeypatch, signed_in, status):
    if not signed_in:
        user_client.cookies.clear()
    queued = []
    monkeypatch.setattr("app.routers.upload.run_analysis", queued.append)
    fields = {"is_private": "true"} if signed_in else {}
    await _upload_sample(user_client, seeded_workflow, **fields)
    original = await async_db.scalar(select(AnalysisJob))
    original.status = status
    await async_db.commit()

    response = await _upload_sample(user_client, seeded_workflow, **fields)

    assert response.status_code == 303
    jobs = (await async_db.scalars(select(AnalysisJob).order_by(AnalysisJob.id))).all()
    if status in (JobStatus.FAILED, JobStatus.CANCELLED):
        assert len(jobs) == 2
        assert jobs[1].status == JobStatus.PENDING
        assert jobs[1].is_private == signed_in
        assert jobs[1].submitted_by_user_id == original.submitted_by_user_id
        assert response.headers["location"] == f"/jobs/{jobs[1].id}"
    else:
        assert len(jobs) == 1
        assert response.headers["location"].startswith(f"/jobs/{original.id}?dup=1")
    assert original.status == status
    assert queued == [job.id for job in jobs]


async def test_upload_retry_queues_a_new_analysis_after_a_queue_outage(test_client, async_db, seeded_workflow, monkeypatch):
    def unavailable(_job_id):
        raise ConnectionError("queue unavailable")

    monkeypatch.setattr("app.routers.upload.run_analysis", unavailable)
    assert (await _upload_sample(test_client, seeded_workflow)).status_code == 503
    queued = []
    monkeypatch.setattr("app.routers.upload.run_analysis", queued.append)

    retry = await _upload_sample(test_client, seeded_workflow)

    jobs = (await async_db.scalars(select(AnalysisJob).order_by(AnalysisJob.id))).all()
    assert [job.status for job in jobs] == [JobStatus.FAILED, JobStatus.PENDING]
    assert queued == [jobs[1].id]
    assert retry.headers["location"] == f"/jobs/{jobs[1].id}"


@pytest.mark.parametrize("newest_status", [JobStatus.FAILED, JobStatus.COMPLETED])
async def test_duplicate_upload_uses_the_newest_job_when_timestamps_tie(test_client, async_db, seeded_workflow, newest_status):
    await _upload_sample(test_client, seeded_workflow)
    first = await async_db.scalar(select(AnalysisJob))
    first.created_at = utc_now_naive().replace(microsecond=0)
    first.status = JobStatus.COMPLETED
    newest = AnalysisJob(
        submitted_filename=first.submitted_filename,
        effective_log_type=first.effective_log_type,
        file_id=first.file_id,
        workflow_id=first.workflow_id,
        created_at=first.created_at,
        status=newest_status,
    )
    async_db.add(newest)
    await async_db.commit()

    response = await _upload_sample(test_client, seeded_workflow)

    jobs = (await async_db.scalars(select(AnalysisJob).order_by(AnalysisJob.id))).all()
    if newest_status == JobStatus.FAILED:
        assert len(jobs) == 3
        assert response.headers["location"] == f"/jobs/{jobs[-1].id}"
    else:
        assert len(jobs) == 2
        assert response.headers["location"].startswith(f"/jobs/{newest.id}?dup=1")


@pytest.mark.parametrize("override", ["syslog", "not-a-log-type"])
async def test_duplicate_redirect_cannot_bypass_the_type_override(test_client, async_db, seeded_workflow, override):
    await _upload_sample(test_client, seeded_workflow)
    response = await _upload_sample(test_client, seeded_workflow, log_type_override=override)
    assert response.status_code == 400
    assert ("chosen log type" if override == "syslog" else "Invalid log type override") in response.text
    assert len((await async_db.scalars(select(AnalysisJob))).all()) == 1


async def test_duplicate_redirect_checks_a_workflows_current_compatibility(test_client, async_db, seeded_workflow):
    await _upload_sample(test_client, seeded_workflow)
    seeded_workflow.log_types = '["syslog"]'
    await async_db.commit()
    response = await _upload_sample(test_client, seeded_workflow)
    assert response.status_code == 400
    assert "does not support the detected log type" in response.text
    assert len((await async_db.scalars(select(AnalysisJob))).all()) == 1


@pytest.fixture()
async def any_type_workflow(async_db) -> WorkflowDef:
    """Workflow with empty log_types — compatible with every log type."""
    wf = WorkflowDef(
        name="Any Type",
        description="",
        log_types="[]",
        tasks_yaml="tasks:\n  - tool: zircolite\n",
        is_default=False,
    )
    async_db.add(wf)
    await async_db.commit()
    await async_db.refresh(wf)
    return wf


async def test_upload_rejects_incompatible_workflow(test_client, seeded_workflow):
    """syslog file + evtx-only workflow → 400 with explicit message."""
    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(seeded_workflow.id), "log_type_override": "auto"},
        files={"file": ("auth.log", _SYSLOG_BODY, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "does not support the detected log type 'syslog'" in resp.text


async def test_upload_rejects_incompatible_override(test_client, seeded_workflow):
    """Explicit type override that mismatches the workflow → 400."""
    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(seeded_workflow.id), "log_type_override": "syslog"},
        files={"file": ("x.evtx", _EVTX_BODY, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_upload_any_type_workflow_accepts_everything(test_client, any_type_workflow):
    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(any_type_workflow.id), "log_type_override": "auto"},
        files={"file": ("auth.log", _SYSLOG_BODY, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 303


async def test_upload_dedupe_path_checks_stored_type(test_client, seeded_workflow, any_type_workflow):
    """Re-upload of a known file must still enforce compatibility (stored-type branch)."""
    ok = await test_client.post(
        "/upload",
        data={"workflow_id": str(any_type_workflow.id), "log_type_override": "auto"},
        files={"file": ("auth.log", _SYSLOG_BODY, "application/octet-stream")},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(seeded_workflow.id), "log_type_override": "auto"},
        files={"file": ("auth.log", _SYSLOG_BODY, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 400


async def test_upload_rejects_oversized_file(test_client, seeded_workflow, monkeypatch):
    """POST /upload with a file exceeding MAX_UPLOAD_SIZE_MB should return 413."""
    from app import config

    monkeypatch.setattr(config.settings, "max_upload_size_mb", 0)

    resp = await test_client.post(
        "/upload",
        data={"workflow_id": str(seeded_workflow.id), "log_type_override": "auto"},
        files={"file": ("big.log", b"x" * 1024, "application/octet-stream")},
        follow_redirects=False,
    )
    assert resp.status_code == 413


# ── the upload progress bar ──────────────────────────────────────────────────
#
# A 500 MB upload needs more than a disabled button — a percentage, and a way out.
# These assertions are static because the behaviour is entirely client-side: the
# server sees an ordinary multipart POST either way, so no route test can catch a
# regression here.


def _index_html() -> str:
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    return (root / "app/templates/index.html").read_text() + (root / "app/static/upload.js").read_text()


def test_the_form_carries_the_action_the_xhr_handler_reads():
    """`submitUpload` posts to `e.target.getAttribute('action')` and sends
    `new FormData(e.target)`, so the action, method and encoding are what the XHR path
    itself runs on — not decoration around it."""
    html = _index_html()
    assert 'method="POST"' in html
    assert 'action="/upload"' in html
    assert 'enctype="multipart/form-data"' in html


def test_the_upload_card_admits_that_javascript_is_required():
    """Submitting a file is JavaScript-only by construction: the file input is `hidden` and
    reachable only through `$refs.fileInput.click()`, the workflow `<select>` takes its
    options from a `<template x-for>` and so has none without Alpine, and the form is
    `@submit.prevent`. With scripting off the card is a dead form, so it has to say so —
    and say it before the form, not after it."""
    html = _index_html()
    assert "<noscript>" in html, "no <noscript> on the upload card"
    notice = html.split("<noscript>", 1)[1].split("</noscript>", 1)[0]
    assert "JavaScript" in notice, notice
    assert html.index("<noscript>") < html.index("<form"), "the notice must precede the form"


def test_progress_comes_from_the_upload_object_not_the_response():
    """`xhr.onprogress` is the *download*. Only `xhr.upload.onprogress` reports bytes sent,
    and getting this wrong leaves a bar that does nothing until the upload is already over."""
    html = _index_html()
    assert "xhr.upload.onprogress" in html
    assert "lengthComputable" in html


def test_the_client_asks_for_json_so_errors_can_render_in_place():
    """Both the exception handler and the upload middleware negotiate on Accept. Asking for
    HTML here would return an error *page* the inline handler cannot read."""
    import re

    html = _index_html()
    assert "setRequestHeader('Accept', 'application/json')" in html
    # Every Accept header this page sets must be JSON-only — one stray `text/html` and the
    # server answers with a rendered page and the inline error box goes blank.
    accepts = re.findall(r"setRequestHeader\(\s*'Accept'\s*,\s*'([^']*)'", html)
    assert accepts, "no Accept header found"
    assert all(a == "application/json" for a in accepts), accepts


def test_the_upload_can_be_cancelled_and_reports_where_it_landed():
    html = _index_html()
    assert "cancelUpload()" in html
    assert "xhr.abort()" in html
    # The JSON receipt supplies the accepted job URL without an extra HTML GET.
    assert "window.location.href = data.job_url" in html


async def test_a_reupload_can_choose_an_independent_type(test_client, async_db):
    """One upload override cannot lock the type for another submission."""
    syslog_wf = WorkflowDef(name="Syslog WF", log_types='["syslog"]', tasks_yaml="tasks: []")
    auditd_wf = WorkflowDef(name="Auditd WF", log_types='["auditd"]', tasks_yaml="tasks: []")
    async_db.add_all([syslog_wf, auditd_wf])
    await async_db.commit()

    first = await test_client.post(
        "/upload",
        data={"workflow_id": str(syslog_wf.id), "log_type_override": "syslog"},
        files={"file": ("a.log", _SYSLOG_BODY, "application/octet-stream")},
        follow_redirects=False,
    )
    assert first.status_code == 303

    again = await test_client.post(
        "/upload",
        data={"workflow_id": str(auditd_wf.id), "log_type_override": "auditd"},
        files={"file": ("a.log", _SYSLOG_BODY, "application/octet-stream")},
        follow_redirects=False,
    )
    assert again.status_code == 303
    jobs = (await async_db.scalars(select(AnalysisJob).order_by(AnalysisJob.id))).all()
    assert [job.effective_log_type for job in jobs] == [LogType.SYSLOG, LogType.AUDITD]
    assert jobs[0].file_id == jobs[1].file_id


async def test_a_reupload_that_names_the_stored_type_still_goes_through(test_client, async_db, any_type_workflow):
    body = b"2026-07-19T10:00:00+02:00 host sshd[1]: something else\n"
    for _ in range(2):
        resp = await test_client.post(
            "/upload",
            data={"workflow_id": str(any_type_workflow.id), "log_type_override": "syslog", "force_resubmit": "true"},
            files={"file": ("b.log", body, "application/octet-stream")},
            follow_redirects=False,
        )
        assert resp.status_code == 303


async def test_an_anonymous_duplicate_is_not_offered_a_resubmit_it_cannot_make(test_client, seeded_workflow):
    """/upload sends an anonymous re-uploader to the existing job with ?dup=1, and the
    banner there offered "Force re-analyze" — a POST to /jobs/resubmit, which requires a
    login and answered the click with a 401 page."""
    for _ in range(2):
        resp = await test_client.post(
            "/upload",
            data={"workflow_id": str(seeded_workflow.id), "log_type_override": "auto"},
            files={"file": ("test.evtx", _EVTX_BODY, "application/octet-stream")},
            follow_redirects=False,
        )
    page = await test_client.get(resp.headers["location"])

    assert "This file was already analyzed" in page.text
    assert 'action="/jobs/resubmit"' not in page.text


async def _failed_job(async_db, owner) -> AnalysisJob:
    log_file = LogFile(original_filename="x.evtx", stored_filename="x", sha256="f" * 64, size_bytes=1)
    async_db.add(log_file)
    await async_db.flush()
    wf = (await async_db.execute(select(WorkflowDef))).scalars().first()
    job = AnalysisJob(file_id=log_file.id, workflow_id=wf.id, status=JobStatus.FAILED, error_message="boom", submitted_by_user_id=owner.id if owner else None)
    async_db.add(job)
    await async_db.commit()
    return job


async def test_a_failed_job_offers_resubmit_only_to_whoever_may_resubmit_it(user_client, async_db, seeded_workflow, member_user, regular_user):
    """A `role=user` viewing someone else's failed public job was shown Resubmit, and
    /jobs/resubmit 403s anyone who never submitted the file. The poll partial renders the
    same box, so both it and the page have to agree."""
    theirs = await _failed_job(async_db, member_user)
    for url in (f"/jobs/{theirs.id}", f"/jobs/{theirs.id}/status-partial"):
        assert 'action="/jobs/resubmit"' not in (await user_client.get(url)).text, url

    theirs.submitted_by_user_id = regular_user.id
    await async_db.commit()
    for url in (f"/jobs/{theirs.id}", f"/jobs/{theirs.id}/status-partial"):
        assert 'action="/jobs/resubmit"' in (await user_client.get(url)).text, url


def test_the_file_picker_can_be_opened_from_the_keyboard():
    """The site's primary action had no keyboard path: the drop zone was a `<div>` with only
    `@click`, and the file input is `display:none`, so Tab never reached anything that opens
    the picker and Analyze stays disabled until a file is chosen."""
    import re

    html = _index_html()
    zone = re.search(r"<div\s[^>]*@drop\.prevent[^>]*>", html)
    assert zone, "drop zone not found"
    tag = zone.group(0)
    assert re.search(r'\btabindex="0"|:tabindex="', tag), tag
    assert 'role="button"' in tag, tag
    assert "@keydown.enter" in tag and "@keydown.space" in tag, tag
