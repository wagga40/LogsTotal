"""Ingestion contracts: attribution, per-file isolation, receipts and case linking."""

import asyncio
import json

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.auth.api_tokens import generate_token
from app.config import settings
from app.database import get_async_session
from app.main import app
from app.models import AnalysisJob, ApiToken, CaseEntityLink, CaseJobLink, InvestigationCase, LogFile, SubmissionReceipt, User, WorkflowDef
from tests.helpers import create_schema

EVTX = b"ElfFile\x00" + b"\x00" * 100


@pytest.fixture()
async def workflow(async_db):
    row = WorkflowDef(name="Upload WF", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(row)
    await async_db.commit()
    return row


async def token(db, user, scopes):
    plaintext, digest, prefix = generate_token()
    db.add(ApiToken(name="ingest", token_hash=digest, prefix=prefix, scopes_json=json.dumps(scopes), created_by_user_id=user.id))
    await db.commit()
    return {"Authorization": f"Bearer {plaintext}"}


async def submit(client, workflow, *, headers=None, body=EVTX, path="/api/v1/jobs", filename="sample.evtx", **fields):
    return await client.post(
        path, headers=headers, data={"workflow_id": str(workflow.id), **fields}, files={"file": (filename, body, "application/octet-stream")}, follow_redirects=False
    )


async def test_token_upload_attribution_scope_and_json(test_client, async_db, workflow, admin_user):
    auth = await token(async_db, admin_user, ["job:submit"])
    response = await submit(test_client, workflow, headers=auth)
    assert response.status_code == 202, response.text
    data = response.json()
    assert data["status"] == "pending" and data["reused"] is False
    job = await async_db.get(AnalysisJob, data["job_id"])
    assert job.submitted_by_user_id == admin_user.id
    assert (await test_client.get(f"/api/v1/jobs?ids={job.id}", headers=auth)).status_code == 403
    auth = await token(async_db, admin_user, ["job:read"])
    statuses = await test_client.get(f"/api/v1/jobs?ids={job.id}", headers=auth)
    assert statuses.status_code == 200
    assert statuses.json()["jobs"][0]["job_id"] == job.id
    assert (await submit(test_client, workflow, headers=auth)).status_code == 403


async def test_api_requires_identity_and_bad_bearer_never_falls_back(user_client, test_client, workflow):
    # Both fixtures reference the cookie-authenticated client here.
    assert (await submit(user_client, workflow, headers={"Authorization": "Bearer invalid"})).status_code == 401
    assert (await submit(user_client, workflow, headers={"Authorization": "Bearer invalid"}, path="/upload")).status_code == 401
    user_client.cookies.clear()
    assert (await submit(test_client, workflow)).status_code == 401
    assert (await submit(test_client, workflow, path="/upload", headers={"Accept": "application/json"})).status_code == 202


#: What a browser resends on every request behind the proxy profile's optional basic auth.
#: Caddy's `basicauth` does not strip it, so the app receives it on each upload and poll.
PROXY_BASIC = {"Authorization": "Basic dXNlcjpwYXNz"}


async def test_a_reverse_proxy_basic_auth_header_is_not_a_token_attempt(user_client, async_db, workflow, regular_user):
    """Behind `BASIC_AUTH_USER`/`BASIC_AUTH_HASH` every browser request carries the proxy's
    `Authorization: Basic …`. Treating it as a failed token made every upload on such a
    deployment answer 401 "Invalid bearer token". It is not a token attempt: the upload, the
    API and the status poll fall back to the cookie session, as every older route already did.
    """
    upload = await submit(user_client, workflow, headers={**PROXY_BASIC, "Accept": "application/json"}, path="/upload")
    assert upload.status_code == 202, upload.text
    job = await async_db.get(AnalysisJob, upload.json()["job_id"])
    assert job.submitted_by_user_id == regular_user.id
    api = await submit(user_client, workflow, headers=PROXY_BASIC, body=EVTX + b"api")
    assert api.status_code == 202, api.text
    poll = await user_client.get(f"/api/v1/jobs?ids={job.id}", headers=PROXY_BASIC)
    assert poll.status_code == 200, poll.text
    user_client.cookies.clear()
    anonymous = await submit(user_client, workflow, headers={**PROXY_BASIC, "Accept": "application/json"}, path="/upload", body=EVTX + b"anon")
    assert anonymous.status_code == 202, anonymous.text


@pytest.mark.parametrize("header", ["Bearer invalid", "Bearer", "BEARER nope", "bearer x"])
async def test_every_bearer_attempt_still_never_falls_back(user_client, workflow, header):
    """The other half of the rule survives: a Bearer header that fails — even an empty one —
    never quietly runs with the cookie's privileges or anonymously."""
    for path in ("/upload", "/api/v1/jobs"):
        response = await submit(user_client, workflow, headers={"Authorization": header}, path=path)
        assert response.status_code == 401, (path, header, response.status_code)


async def test_revoked_upload_token_rejected_before_body(test_client, async_db, workflow, admin_user):
    from app.database import utc_now_naive

    auth = await token(async_db, admin_user, ["job:submit"])
    row = await async_db.scalar(select(ApiToken))
    row.revoked_at = utc_now_naive()
    await async_db.commit()
    assert (await submit(test_client, workflow, headers=auth)).status_code == 401
    assert await async_db.scalar(select(func.count(AnalysisJob.id))) == 0


async def test_idempotency_replay_conflict_and_lookup(user_client, async_db, workflow, monkeypatch):
    queued = []
    monkeypatch.setattr("app.routers.upload.run_analysis", queued.append)
    headers = {"Idempotency-Key": "request-1"}
    first = await submit(user_client, workflow, headers=headers, force_resubmit="true")
    second = await submit(user_client, workflow, headers=headers, force_resubmit="true")
    assert first.status_code == 202 and second.status_code == 200
    assert first.json() == second.json()
    assert queued == [first.json()["job_id"]]
    assert (await submit(user_client, workflow, headers=headers, force_resubmit="true", body=EVTX + b"changed")).status_code == 409
    assert (await submit(user_client, workflow, headers=headers, force_resubmit="true", is_private="true")).status_code == 409
    assert (await user_client.get("/api/v1/submissions/request-1")).json() == first.json()
    assert await async_db.scalar(select(func.count(SubmissionReceipt.id))) == 1
    assert len(list(settings.upload_dir.iterdir())) == 1


async def test_case_creation_and_linking_are_idempotent(member_client, async_db, workflow):
    headers = {"Idempotency-Key": "case-1"}
    first = await member_client.post("/api/v1/cases", json={"name": " Investigation "}, headers=headers)
    assert first.status_code == 201
    case_id = first.json()["case_id"]
    again = await member_client.post("/api/v1/cases", json={"name": "Investigation"}, headers=headers)
    assert again.status_code == 200 and again.json() == first.json()
    assert (await member_client.post("/api/v1/cases", json={"name": "Different"}, headers=headers)).status_code == 409
    first_job = await submit(member_client, workflow)
    reused = await submit(member_client, workflow, case_id=str(case_id))
    assert reused.status_code == 200
    assert reused.json()["job_id"] == first_job.json()["job_id"]
    await submit(member_client, workflow, case_id=str(case_id))
    assert await async_db.scalar(select(func.count(CaseJobLink.id))) == 1
    assert await async_db.scalar(select(func.count(CaseEntityLink.id))) == 0
    case = await async_db.get(InvestigationCase, case_id)
    assert case.is_shared is False


async def test_case_scope_is_additional_to_submit_scope(test_client, async_db, workflow, admin_user):
    auth = await token(async_db, admin_user, ["job:submit"])
    case = InvestigationCase(name="Investigation", created_by_user_id=admin_user.id)
    async_db.add(case)
    await async_db.commit()
    assert (await submit(test_client, workflow, headers=auth, case_id=str(case.id))).status_code == 403
    auth = await token(async_db, admin_user, ["job:submit", "case:write"])
    response = await submit(test_client, workflow, headers=auth, case_id=str(case.id))
    assert response.status_code == 202
    assert response.json()["case_id"] == case.id


async def test_basic_user_cannot_group_or_create_cases(user_client, workflow):
    assert (await user_client.post("/api/v1/cases", json={"name": "New"})).status_code == 403
    assert (await submit(user_client, workflow, case_id="123")).status_code == 403


async def test_private_jobs_are_hidden_in_grouped_status_and_other_receipts(user_client, async_db, workflow):
    private = await submit(user_client, workflow, is_private="true", headers={"Idempotency-Key": "secret"})
    public = await submit(user_client, workflow, body=EVTX + b"public")
    private_id, public_id = private.json()["job_id"], public.json()["job_id"]
    user_client.cookies.clear()
    data = (await user_client.get(f"/api/v1/jobs?ids={private_id},{public_id},987654")).json()
    assert [j["job_id"] for j in data["jobs"]] == [public_id]
    assert data["unavailable_ids"] == [private_id, 987654]
    assert (await user_client.get("/api/v1/submissions/secret")).status_code == 401
    assert (await user_client.get("/api/v1/jobs?ids=" + ",".join("1" for _ in range(51)))).status_code == 400
    assert (await user_client.get("/api/v1/jobs?ids=1,nope")).status_code == 400


async def test_queue_failure_keeps_case_and_receipt_recoverable(member_client, async_db, workflow, monkeypatch):
    case_id = (await member_client.post("/api/v1/cases", json={"name": "Queue failure"})).json()["case_id"]

    def fail(_):
        raise ConnectionError("queue down")

    monkeypatch.setattr("app.routers.upload.run_analysis", fail)
    result = await submit(member_client, workflow, case_id=str(case_id), headers={"Idempotency-Key": "failed"})
    assert result.status_code == 503
    data = (await member_client.get("/api/v1/submissions/failed")).json()
    assert data["status"] == "failed" and data["case_id"] == case_id
    assert await async_db.scalar(select(CaseJobLink.job_id)) == data["job_id"]
    monkeypatch.setattr("app.routers.upload.run_analysis", lambda _: None)
    retry = await submit(member_client, workflow, case_id=str(case_id), headers={"Idempotency-Key": "retry"})
    assert retry.status_code == 202 and retry.json()["job_id"] != data["job_id"]


async def test_each_request_has_exactly_one_file_and_failure_does_not_affect_others(user_client, workflow, async_db):
    bad = await user_client.post("/api/v1/jobs", data={"workflow_id": workflow.id}, files=[("file", ("a.evtx", EVTX)), ("file", ("b.evtx", EVTX))])
    assert bad.status_code == 400
    good = await submit(user_client, workflow)
    bad = await submit(user_client, workflow, log_type_override="syslog")
    assert good.status_code == 202 and bad.status_code == 400
    assert await async_db.scalar(select(func.count(AnalysisJob.id))) == 1


async def test_deleted_job_receipt_is_a_tombstone(user_client, workflow, async_db):
    response = await submit(user_client, workflow, headers={"Idempotency-Key": "deleted"})
    job = await async_db.get(AnalysisJob, response.json()["job_id"])
    await async_db.delete(job)
    await async_db.commit()
    async_db.expire_all()
    assert (await user_client.get("/api/v1/submissions/deleted")).status_code == 410


@pytest.mark.parametrize("same_submission", [True, False], ids=["concurrent-retries", "fifty-files"])
async def test_concurrent_submissions(test_client, async_db, tmp_path, monkeypatch, same_submission):
    """Independent DB connections contend on the receipt's unique constraint."""
    import app.database as database

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'race.db'}")
    await create_schema(engine)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db:
        user = User(email="race@example.test", hashed_password="unused", is_active=True, is_superuser=True, role="admin")
        wf = WorkflowDef(name="Race", log_types='["evtx"]', tasks_yaml="tasks: []")
        db.add_all([user, wf])
        await db.commit()
        auth = await token(db, user, ["job:submit"])
    auth["Idempotency-Key"] = "concurrent"
    count = 6 if same_submission else 50
    expected = 1 if same_submission else count
    queued = []
    monkeypatch.setattr("app.routers.upload.run_analysis", queued.append)
    monkeypatch.setattr(settings, "upload_max_concurrent", 10)
    monkeypatch.setattr(database, "async_session_maker", maker)

    async def sessions():
        async with maker() as db:
            yield db

    old = app.dependency_overrides[get_async_session]
    app.dependency_overrides[get_async_session] = sessions
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            slots = asyncio.Semaphore(6 if same_submission else 2)

            async def send(index):
                async with slots:
                    headers = {**auth, "Idempotency-Key": "concurrent" if same_submission else f"file-{index}"}
                    content = EVTX if same_submission else EVTX + str(index).encode()
                    return await submit(client, wf, headers=headers, body=content, force_resubmit="true")

            results = await asyncio.gather(*(send(index) for index in range(count)))
        assert all(r.status_code in (200, 202) for r in results), [r.text for r in results]
        assert sum(r.status_code == 202 for r in results) == expected
        assert len({r.json()["job_id"] for r in results}) == expected
        assert len(queued) == expected
        async with maker() as db:
            assert await db.scalar(select(func.count(AnalysisJob.id))) == expected
            assert await db.scalar(select(func.count(LogFile.id))) == expected
            assert await db.scalar(select(func.count(SubmissionReceipt.id))) == expected
        assert len(list(settings.upload_dir.iterdir())) == expected
    finally:
        app.dependency_overrides[get_async_session] = old
        await engine.dispose()


async def test_submission_key_with_path_characters_is_recoverable(user_client, workflow):
    from urllib.parse import quote

    key = "sensor/2026-09-26#1"
    response = await submit(user_client, workflow, headers={"Idempotency-Key": key})
    recovered = await user_client.get("/api/v1/submissions/" + quote(key, safe=""))
    assert recovered.status_code == 200 and recovered.json() == response.json()


async def test_s3_submission_and_failed_commit_clean_up(user_client, workflow, async_db, monkeypatch):
    from pathlib import Path

    from app import storage

    objects = {}

    class Client:
        def upload_file(self, source, bucket, key):
            objects[key] = Path(source).read_bytes()

        def delete_object(self, *, Bucket, Key):
            objects.pop(Key, None)

    backend = storage.S3Storage.__new__(storage.S3Storage)
    backend._bucket = "test"
    backend._s3 = Client()
    monkeypatch.setattr(storage, "_storage", backend)
    response = await submit(user_client, workflow, headers={"Idempotency-Key": "s3"})
    assert response.status_code == 202 and list(objects.values()) == [EVTX]
    assert list(settings.upload_dir.glob("*.upload")) == []
    original_keys = set(objects)

    async def fail_commit():
        raise RuntimeError("DB commit failed")

    monkeypatch.setattr(async_db, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="DB commit failed"):
        await submit(user_client, workflow, body=EVTX + b"new", headers={"Idempotency-Key": "s3-failure"})
    assert set(objects) == original_keys
    assert list(settings.upload_dir.glob("*.upload")) == []


async def test_settings_creation_rollback_keeps_authenticated_upload_valid(test_client, async_db, admin_user, workflow, monkeypatch):
    """Force the loser of the first-use SiteSettings insert race deterministically."""
    from app.site_settings import get_site_settings

    auth = await token(async_db, admin_user, ["job:submit"])
    owner_id = admin_user.id

    async def raced_settings(db):
        await db.rollback()
        return await get_site_settings(db)

    monkeypatch.setattr("app.submissions.get_site_settings", raced_settings)
    result = await submit(test_client, workflow, headers=auth)
    assert result.status_code == 202
    job = await async_db.get(AnalysisJob, result.json()["job_id"])
    assert job.submitted_by_user_id == owner_id
