"""Bounded reproductions of the submission, tag, parser and receiver attacks."""

from __future__ import annotations

import asyncio
import json
import subprocess
from html.parser import HTMLParser

import httpx
import pytest
from sqlalchemy import select

from app.intel.rules_yaml import parse_rules_yaml
from app.models import AnalysisJob, LogFile, LogType, TagDefinition, WorkflowDef
from tests.helpers import login


class TagButtons(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.actions = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("hx-post") == "/intel/tags/delete":
            self.actions.append((attrs["hx-post"], json.loads(attrs["hx-vals"])))


@pytest.fixture()
async def workflow(async_db):
    row = WorkflowDef(name="Security regression", log_types="[]", tasks_yaml="tasks: []")
    async_db.add(row)
    await async_db.commit()
    return row


async def upload(client, workflow, name, **data):
    return await client.post(
        "/upload",
        data={"workflow_id": str(workflow.id), **data},
        files={"file": (name, b"ElfFile\0security regression contents", "application/octet-stream")},
    )


@pytest.mark.parametrize("tag", ["../../jobs/1", "%2e%2e/%2e%2e/jobs/1", "..\\..\\jobs\\1", "mitre/t1059", "x\"'><img src=x>", "équipe/调查"])
async def test_tag_action_cannot_become_an_admin_job_action(test_client, async_db, member_user, admin_user, workflow, tag):
    job = AnalysisJob(file_id=1, workflow_id=workflow.id, is_private=True, submitted_by_user_id=admin_user.id)
    async_db.add(LogFile(id=1, original_filename="private.evtx", stored_filename="private", sha256="a" * 64, size_bytes=1))
    await async_db.flush()
    async_db.add(job)
    await async_db.commit()
    await login(test_client, member_user.email)
    assert (await test_client.post("/intel/tags", data={"tag": tag})).status_code == 200
    assert (await test_client.post(f"/jobs/{job.id}/delete")).status_code == 403
    await login(test_client, admin_user.email)
    buttons = TagButtons((await test_client.get("/intel/tags")).text)
    action, values = next((url, fields) for url, fields in buttons.actions if fields["tag"] == tag.lower())
    # Exercise the same WHATWG normalization used by a browser before HTTP dispatch.
    normalized = subprocess.check_output(["node", "-e", "process.stdout.write(new URL(process.argv[1], 'http://test').pathname)", action], text=True)
    assert normalized == "/intel/tags/delete"
    assert (await test_client.post(normalized, data=values)).status_code == 200
    async_db.expire_all()
    assert await async_db.get(AnalysisJob, 1) is not None
    assert await async_db.scalar(select(TagDefinition).where(TagDefinition.tag == tag.lower())) is None
    assert (await test_client.post("/intel/tags/old-name/delete")).status_code == 404


@pytest.mark.parametrize("path", ["/intel/rules/import", "/comments/job/1"])
@pytest.mark.parametrize("declared", [None, "1"])
@pytest.mark.parametrize("authenticated", [False, True])
async def test_multipart_is_bounded_before_auth(test_client, member_user, monkeypatch, path, declared, authenticated):
    from starlette import formparsers

    if authenticated:
        await login(test_client, member_user.email)
    opened = []
    original = formparsers.SpooledTemporaryFile

    def spool(*args, **kwargs):
        file = original(*args, **kwargs)
        opened.append(file)
        return file

    monkeypatch.setattr(formparsers, "SpooledTemporaryFile", spool)
    produced = 0

    async def chunks():
        nonlocal produced
        yield b'--review\r\nContent-Disposition: form-data; name="unexpected"; filename="attack.bin"\r\n\r\n'
        for _ in range(32):
            produced += 65536
            yield b"x" * 65536
        yield b"\r\n--review--\r\n"

    headers = {"content-type": "multipart/form-data; boundary=review"}
    if declared:
        headers["content-length"] = declared
    response = await test_client.post(path, content=chunks(), headers=headers)
    assert response.status_code == 413
    assert produced <= 1024 * 1024
    assert opened and all(file.closed for file in opened)
    assert "x-content-type-options" in response.headers


async def test_body_limit_closes_files_that_already_rolled_to_disk(monkeypatch):
    from fastapi import FastAPI, File, UploadFile
    from starlette import formparsers

    from app.middleware.production import RequestBodyLimitMiddleware

    opened = []
    original = formparsers.SpooledTemporaryFile

    def spool(*args, **kwargs):
        file = original(*args, **kwargs)
        opened.append(file)
        return file

    monkeypatch.setattr(formparsers, "SpooledTemporaryFile", spool)
    app = FastAPI()

    @app.post("/form")
    async def form(file: UploadFile = File(...)):
        raise AssertionError("oversized bodies must not reach the handler")

    app.add_middleware(RequestBodyLimitMiddleware, max_upload_bytes=1, max_body_bytes=1536 * 1024)

    async def chunks():
        yield b'--review\r\nContent-Disposition: form-data; name="file"; filename="attack.bin"\r\n\r\n'
        for _ in range(32):
            yield b"x" * 65536
        yield b"\r\n--review--\r\n"

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        response = await client.post("/form", content=chunks(), headers={"content-type": "multipart/form-data; boundary=review"})
    assert response.status_code == 413
    assert opened and all(file.closed and file._rolled for file in opened)


@pytest.mark.parametrize(
    "document",
    [
        "a: &a [x]\nb: &b [*a, *a]\nrules: [{name: test, entity_types: [*b]}]",
        "a: &a [*a]\nrules: []",
        "rules: " + "[" * 20 + "x" + "]" * 20,
        "rules: [{name: test, entity_types: [[ip_address]]}]",
        "rules: [{name: test, tags: [{name: [x]}]}]",
        "rules: [{name: test, webhook: {url: [x]}}]",
        "rules: [{name: test, webhook: {headers: {X-Test: [x]}}}]",
        "lists: [{name: test, values: [[x]]}]",
    ],
)
def test_yaml_rejects_expanding_or_wrongly_typed_values(document):
    parsed = parse_rules_yaml(document)
    assert parsed.errors
    assert len(parsed.errors) <= 101
    assert all(len(error) <= 256 for error in parsed.errors)
    assert not parsed.rules and not parsed.lists


def test_yaml_diagnostics_and_event_count_are_bounded():
    parsed = parse_rules_yaml("rules:\n" + ("- name: " + "x" * 1000 + "\n") * 200)
    assert len(parsed.errors) == 101
    assert all(len(error) <= 256 for error in parsed.errors)
    parsed = parse_rules_yaml("ignored: [" + "x," * 100_001 + "]\nrules: []")
    assert "too many" in parsed.errors[0]


async def test_duplicate_bytes_keep_each_submitters_metadata(test_client, async_db, regular_user, member_user, workflow, monkeypatch):
    monkeypatch.setattr("app.storage.free_bytes_for_uploads", lambda: 10**12)
    secret = "CONFIDENTIAL_customer_case42.evtx"
    await login(test_client, regular_user.email)
    first = await upload(test_client, workflow, secret, is_private="true")
    assert first.status_code == 303
    test_client.cookies.clear()
    assert (await test_client.get(first.headers["location"])).status_code == 404
    second = await upload(test_client, workflow, "ordinary.evtx")
    assert second.status_code == 303
    page = await test_client.get(second.headers["location"])
    assert "ordinary.evtx" in page.text and secret not in page.text
    await login(test_client, member_user.email)
    third = await upload(test_client, workflow, "member.evtx")
    assert third.status_code == 303
    jobs = (await async_db.scalars(select(AnalysisJob).order_by(AnalysisJob.id))).all()
    assert len({job.file_id for job in jobs}) == 1
    file = await async_db.get(LogFile, jobs[0].file_id)
    assert "CONFIDENTIAL" not in file.stored_filename
    assert [job.filename for job in jobs] == [secret, "ordinary.evtx", "member.evtx"]
    resubmitted = await test_client.post("/jobs/resubmit", data={"file_id": jobs[-1].file_id, "workflow_id": workflow.id})
    assert resubmitted.status_code == 303
    assert secret not in (await test_client.get(resubmitted.headers["location"])).text
    assert f'/jobs/{jobs[1].id}"' not in (await test_client.get("/jobs", params={"q": secret})).text


async def test_legacy_filename_is_admin_only(test_client, async_db, regular_user, admin_user, workflow, monkeypatch):
    monkeypatch.setattr("app.storage.free_bytes_for_uploads", lambda: 10**12)
    await upload(test_client, workflow, "UNVERIFIED_secret.evtx")
    job = await async_db.scalar(select(AnalysisJob))
    job.submitted_filename = None
    await async_db.commit()
    await async_db.refresh(job)
    assert job.filename.startswith("upload-")
    await login(test_client, regular_user.email)
    assert "UNVERIFIED_secret" not in (await test_client.get(f"/jobs/{job.id}")).text
    assert f'/jobs/{job.id}"' not in (await test_client.get("/jobs?q=UNVERIFIED_secret")).text
    await login(test_client, admin_user.email)
    assert "UNVERIFIED_secret" in (await test_client.get(f"/jobs/{job.id}")).text


async def test_anonymous_override_cannot_poison_later_analysis(test_client, async_db, workflow, monkeypatch):
    monkeypatch.setattr("app.storage.free_bytes_for_uploads", lambda: 10**12)
    assert (await upload(test_client, workflow, "attack.evtx", log_type_override="syslog")).status_code == 303
    windows = WorkflowDef(name="Windows only", log_types='["evtx"]', tasks_yaml="tasks: []")
    async_db.add(windows)
    await async_db.commit()
    for override in ("auto", "evtx"):
        result = await upload(test_client, windows, "legitimate.evtx", log_type_override=override, force_resubmit="true")
        assert result.status_code == 303
    jobs = (await async_db.scalars(select(AnalysisJob).order_by(AnalysisJob.id))).all()
    assert [job.effective_log_type for job in jobs] == [LogType.SYSLOG, LogType.EVTX, LogType.EVTX]
    file = await async_db.get(LogFile, jobs[0].file_id)
    assert file.detected_type == file.log_type == LogType.EVTX


@pytest.mark.parametrize("slow_headers", [False, True])
async def test_webhook_slow_receiver_cannot_hold_delivery(slow_headers):
    from app.intel.webhooks import _send_async

    disconnected = asyncio.Event()
    connections = set()

    async def receiver(reader, writer):
        connections.add(writer)
        try:
            await reader.readuntil(b"\r\n\r\n")
            if slow_headers:
                for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n":
                    writer.write(bytes([byte]))
                    await writer.drain()
                    await asyncio.sleep(0.04)
            else:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
                await writer.drain()
            await reader.read()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            connections.discard(writer)
            disconnected.set()

    server = await asyncio.start_server(receiver, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with server:
            started = asyncio.get_running_loop().time()
            status, error = await _send_async(f"http://localhost:{port}/", b"", {}, timeout=0.25, method="POST", pin_ip="127.0.0.1")
            assert asyncio.get_running_loop().time() - started < 1
            assert (status, error) == ((None, "timed out") if slow_headers else (200, None))
            await asyncio.wait_for(disconnected.wait(), 1)
    finally:
        for writer in connections:
            writer.close()


@pytest.mark.parametrize("path,limit", [("/form", 1024 * 1024), ("/upload", 2 * 1024 * 1024), ("/detect-preview", 256 * 1024)])
@pytest.mark.parametrize("extra", [0, 1])
async def test_streaming_body_limit_boundaries(path, limit, extra):
    from app.middleware.production import RequestBodyLimitMiddleware

    consumed = 0

    async def downstream(scope, receive, send):
        nonlocal consumed
        while True:
            message = await receive()
            consumed += len(message.get("body", b""))
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = RequestBodyLimitMiddleware(downstream, max_upload_bytes=1024 * 1024)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        response = await client.post(path, content=b"x" * (limit + extra), headers={"content-length": "1"})
    assert response.status_code == (413 if extra else 204)
    assert consumed <= limit
