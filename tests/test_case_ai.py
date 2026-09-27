"""Case AI integration: evidence provenance is also the report's access boundary."""

from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from app.ai.case_evidence import prepare_case_evidence, source_identity
from app.database import utc_now_naive
from app.json_utils import dumps, loads
from app.models import (
    AiAnalysisStatus,
    AiProvider,
    AnalysisJob,
    CaseAiAnalysis,
    CaseEntityLink,
    CaseJobLink,
    Entity,
    Finding,
    InvestigationCase,
    JobAiAnalysis,
    JobStatus,
    LogFile,
    Severity,
    SiteSettings,
    TaskResult,
    TaskStatus,
    User,
    WorkflowDef,
)


def seed_case(db, owner=None):
    if owner is None:
        owner = User(id=uuid4(), email="owner@case-ai.test", hashed_password="", role="member", is_active=True)
        db.add(owner)
    other = User(id=uuid4(), email="other@case-ai.test", hashed_password="", role="member", is_active=True)
    provider = AiProvider(name="Case provider", kind="openai", base_url="http://localhost:11434/v1", model="test-model", enabled=True)
    case = InvestigationCase(name="Case AI investigation", summary="Analyst summary", notes="Investigate shared-host", created_by_user_id=owner.id, is_shared=True)
    workflow = WorkflowDef(name="case-ai-wf")
    db.add_all([other, provider, case, workflow, SiteSettings(id=1, show_ai_analysis=True, show_ai_prompt=True)])
    db.flush()
    jobs = []
    for index, status in enumerate((JobStatus.COMPLETED, JobStatus.PARTIAL, JobStatus.COMPLETED, JobStatus.RUNNING)):
        private = index == 2
        file = LogFile(original_filename=f"file{index}.evtx", stored_filename=f"file{index}", sha256=str(index) * 64, size_bytes=1)
        db.add(file)
        db.flush()
        job = AnalysisJob(
            file_id=file.id,
            workflow_id=workflow.id,
            submitted_filename=f"{'secret' if private else 'visible'}-{index}.evtx",
            status=status,
            is_private=private,
            submitted_by_user_id=other.id if private else owner.id,
            analytics_json=dumps({"computers": ["shared-host"], "users": [f"user-{index}"]}),
        )
        db.add(job)
        db.flush()
        db.add(CaseJobLink(case_id=case.id, job_id=job.id, note=f"link rationale {index}"))
        task = TaskResult(job_id=job.id, tool_name="hayabusa", status=TaskStatus.COMPLETED)
        db.add(task)
        db.flush()
        for n in range(25 if index < 2 else 1):
            db.add(
                Finding(
                    task_result_id=task.id,
                    rule_name=f"rule-{index}-{n}",
                    severity=Severity.HIGH,
                    count=n + 1,
                    details=dumps([{"Computer": "shared-host", "CommandLine": "whoami", "UnapprovedSecret": "never-send"}]),
                )
            )
        jobs.append(job)
    entity = Entity(entity_type="computer", value="shared-host", job_count=99999)
    db.add(entity)
    db.flush()
    db.add(CaseEntityLink(case_id=case.id, entity_id=entity.id, note="entity rationale"))
    db.commit()
    return SimpleNamespace(owner=owner, other=other, provider=provider, case=case, jobs=jobs, entity=entity)


@pytest.fixture
async def case_data(async_db, member_user):
    return await async_db.run_sync(lambda db: seed_case(db, member_user))


@pytest.fixture
def enqueue(monkeypatch):
    calls = []
    monkeypatch.setattr("app.workers.tasks.run_case_ai_analysis", lambda run_id: calls.append(run_id))
    return calls


def saved_run(data, **kwargs):
    fields = {
        "case_id": data.case.id,
        "provider_id": data.provider.id,
        "provider_name": "Saved provider",
        "model": "saved-model",
        "requested_by_user_id": data.owner.id,
        "status": AiAnalysisStatus.COMPLETED,
        "content": "Saved assessment",
        "source_jobs_json": dumps([source_identity(data.jobs[0])]),
        "evidence_captured_at": utc_now_naive(),
    }
    fields.update(kwargs)
    return CaseAiAnalysis(**fields)


async def test_case_tab_lazy_load_and_manual_history(member_client, async_db, case_data, enqueue):
    data = case_data
    base = f"/intel/cases/{data.case.id}"
    page = await member_client.get(base)
    assert page.status_code == 200
    assert "loadAiAnalysis from:body once" in page.text
    panel = await member_client.get(base + "/ai-analysis-partial")
    assert panel.status_code == 200
    assert "Analyse this case" in panel.text
    assert not enqueue
    for _ in range(2):
        response = await member_client.post(base + "/ai-analysis", data={"provider_id": data.provider.id}, headers={"HX-Request": "true"})
        assert response.status_code == 200, response.text
        assert 'hx-trigger="every 3s"' in response.text
    assert len(enqueue) == 2
    assert len(list(await async_db.scalars(select(CaseAiAnalysis)))) == 2
    assert not list(await async_db.scalars(select(JobAiAnalysis)))


async def test_report_visibility_tracks_source_permissions_and_deletion(member_client, admin_user, async_db, case_data):
    from app.ai.case_evidence import readable_runs

    data = case_data
    run = saved_run(data, requested_by_user_id=data.other.id, content="PRIVATE ASSESSMENT", source_jobs_json=dumps([source_identity(data.jobs[2])]))
    async_db.add(run)
    await async_db.commit()
    url = f"/intel/cases/{data.case.id}/ai-analysis-partial"
    assert "PRIVATE ASSESSMENT" not in (await member_client.get(url)).text
    assert (await member_client.get(url, params={"analysis_id": run.id})).status_code == 404
    assert await readable_runs(async_db, [run], admin_user) == [run]

    data.jobs[2].is_private = False
    await async_db.commit()
    assert "PRIVATE ASSESSMENT" in (await member_client.get(url)).text
    data.jobs[2].is_private = True
    await async_db.commit()
    assert "PRIVATE ASSESSMENT" not in (await member_client.get(url)).text
    await async_db.execute(delete(CaseJobLink).where(CaseJobLink.job_id == data.jobs[2].id))
    await async_db.delete(data.jobs[2])
    await async_db.commit()
    assert (await member_client.get(url, params={"analysis_id": run.id})).status_code == 404
    assert await readable_runs(async_db, [run], admin_user) == [run]


async def test_deleted_source_stays_restricted_when_job_id_is_reused(member_client, admin_user, async_db, case_data):
    from app.ai.case_evidence import readable_runs
    from app.routers.jobs import _delete_job

    data = case_data
    source = data.jobs[2]
    # Keep the source file alive so the replacement can even have the same file ID.
    data.jobs[3].file_id = source.file_id
    identity = source_identity(source)
    workflow_id = source.workflow_id
    created_at = source.created_at
    run = saved_run(data, source_jobs_json=dumps([identity]))
    async_db.add(run)
    await async_db.commit()
    await _delete_job(async_db, source)
    await async_db.refresh(run)
    assert run.source_deleted_at is not None
    replacement = AnalysisJob(id=identity["id"], file_id=identity["file_id"], workflow_id=workflow_id, created_at=created_at, status=JobStatus.COMPLETED, is_private=False)
    async_db.add(replacement)
    await async_db.commit()
    assert source_identity(replacement) == identity
    assert await readable_runs(async_db, [run], data.owner) == []
    assert await readable_runs(async_db, [run], admin_user) == [run]


async def test_pending_run_hidden_from_other_members(member_client, async_db, case_data):
    run = saved_run(case_data, requested_by_user_id=case_data.other.id, status=AiAnalysisStatus.PENDING, source_jobs_json=None)
    async_db.add(run)
    await async_db.commit()
    response = await member_client.get(f"/intel/cases/{case_data.case.id}/ai-analysis-partial", params={"analysis_id": run.id})
    assert response.status_code == 404


async def test_feature_empty_case_and_provider_gates(member_client, async_db, case_data, enqueue):
    data = case_data
    url = f"/intel/cases/{data.case.id}/ai-analysis"
    site = await async_db.get(SiteSettings, 1)
    site.show_ai_analysis = False
    await async_db.commit()
    assert "loadAiAnalysis" not in (await member_client.get(f"/intel/cases/{data.case.id}")).text
    response = await member_client.post(url, data={"provider_id": data.provider.id}, headers={"HX-Request": "true"})
    assert "switched off" in response.text
    site.show_ai_analysis = True
    data.provider.enabled = False
    await async_db.commit()
    response = await member_client.post(url, data={"provider_id": data.provider.id}, headers={"HX-Request": "true"})
    assert "no longer available" in response.text
    data.provider.enabled = True
    await async_db.execute(delete(CaseJobLink))
    await async_db.execute(delete(CaseEntityLink))
    await async_db.commit()
    response = await member_client.post(url, data={"provider_id": data.provider.id}, headers={"HX-Request": "true"})
    assert "Add a completed or partial job" in response.text
    assert not enqueue


async def test_case_and_role_access(member_client, user_client, async_db, case_data, enqueue):
    # user_client's login replaces the cookie on the shared test client.
    base = f"/intel/cases/{case_data.case.id}"
    assert (await user_client.get(base + "/ai-analysis-partial")).status_code in (302, 303, 403)
    await member_client.post("/auth/cookie/login", data={"username": "member@test.example.com", "password": "testpass123"})
    case_data.case.is_shared = False
    case_data.case.created_by_user_id = case_data.other.id
    await async_db.commit()
    assert (await member_client.get(base + "/ai-analysis-partial")).status_code == 404
    assert (await member_client.post(base + "/ai-analysis", data={"provider_id": case_data.provider.id})).status_code == 404
    assert not enqueue


async def test_stop_delete_and_terminal_polling(member_client, async_db, case_data, fake_redis):
    from app.redis_client import AI_CANCEL_PREFIX, AI_HEARTBEAT_PREFIX

    run = saved_run(case_data, status=AiAnalysisStatus.PENDING, source_jobs_json=None)
    async_db.add(run)
    await async_db.commit()
    base = f"/intel/cases/{case_data.case.id}"
    fake_redis.set(f"{AI_HEARTBEAT_PREFIX}{run.id}", "unrelated job run")
    response = await member_client.post(f"{base}/ai-analysis/{run.id}/cancel", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert 'hx-trigger="every 3s"' not in response.text
    assert fake_redis.exists(f"{AI_CANCEL_PREFIX}case:{run.id}")
    assert not fake_redis.exists(f"{AI_CANCEL_PREFIX}{run.id}")
    assert fake_redis.exists(f"{AI_HEARTBEAT_PREFIX}{run.id}")
    await async_db.refresh(run)
    assert run.status == AiAnalysisStatus.CANCELLED
    response = await member_client.post(base + "/ai-analysis/delete", data={"analysis_ids": str(run.id)}, headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert await async_db.get(CaseAiAnalysis, run.id) is None


async def test_queue_failure_is_saved(member_client, async_db, case_data, monkeypatch):
    def fail(_):
        raise RuntimeError("queue unavailable")

    monkeypatch.setattr("app.workers.tasks.run_case_ai_analysis", fail)
    response = await member_client.post(f"/intel/cases/{case_data.case.id}/ai-analysis", data={"provider_id": case_data.provider.id})
    assert response.status_code == 503
    run = await async_db.scalar(select(CaseAiAnalysis))
    assert run.status == AiAnalysisStatus.FAILED


async def test_admin_monitor_and_provider_deletion(admin_client, async_db, case_data):
    run = saved_run(case_data, status=AiAnalysisStatus.RUNNING, created_at=utc_now_naive() - timedelta(hours=1))
    async_db.add(run)
    await async_db.commit()
    response = await admin_client.get("/admin/tasks")
    assert response.status_code == 200
    assert f"/intel/cases/{case_data.case.id}/ai-analysis/{run.id}/cancel" in response.text
    assert "Case AI investigation" in response.text
    response = await admin_client.post(f"/admin/ai/{case_data.provider.id}/delete", follow_redirects=False)
    assert response.status_code == 303
    await async_db.refresh(run)
    assert run.provider_id is None
    assert run.provider_name == "Saved provider"


def test_case_evidence_is_scoped_and_distributed(sync_db):
    data = seed_case(sync_db)
    prompt, meta, sources = prepare_case_evidence(sync_db, data.case, data.owner)
    assert meta["findings_rendered"] == 40
    assert meta["findings_omitted"] == 10
    samples = [loads(line) for line in prompt.splitlines() if line.startswith("{") and '"finding_id"' in line]
    assert sum(f["job_id"] == data.jobs[0].id for f in samples) == 20
    assert sum(f["job_id"] == data.jobs[1].id for f in samples) == 20
    assert {s["id"] for s in loads(sources)} == {data.jobs[0].id, data.jobs[1].id}
    assert all(s in prompt for s in ("Analyst summary", "Investigate shared-host", "link rationale 0", "entity rationale", "rule-0-", "rule-1-"))
    assert all(s not in prompt for s in ("secret-2", "rule-2-", "rule-3-", "never-send", "99999"))
    assert "truncated" in prompt


@pytest.fixture
def worker_case(sync_db, monkeypatch):
    from app.workers import tasks

    data = seed_case(sync_db)
    run = saved_run(data, status=AiAnalysisStatus.PENDING, source_jobs_json=None, content=None)
    sync_db.add(run)
    sync_db.commit()
    monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(sync_db, "close", lambda: None)
    calls = []

    def complete(**kwargs):
        calls.append(kwargs)
        return "## Verdict\nInvestigate the shared host.", {"input_tokens": 100, "output_tokens": 20}, 12, None

    monkeypatch.setattr("app.ai.client.run_completion", complete)
    return data, run, calls


def test_worker_records_provenance_prompt_and_does_not_repeat(sync_db, worker_case):
    from app.workers.tasks import run_case_ai_analysis

    _data, run, calls = worker_case
    run_case_ai_analysis.call_local(run.id)
    sync_db.refresh(run)
    assert run.status == AiAnalysisStatus.COMPLETED, run.error_message
    assert run.evidence_captured_at and run.source_jobs_json and run.prompt_text
    assert run.input_tokens == 100
    assert "=== CASE BRIEF ===" in calls[0]["system"]
    assert "against a single log file" not in calls[0]["system"]
    run_case_ai_analysis.call_local(run.id)
    assert len(calls) == 1


@pytest.mark.parametrize("scope", ["job", "case"])
@pytest.mark.parametrize("limit", [1, 1200, 6000, None])
def test_worker_uses_the_matching_provider_prompt_limit(sync_db, worker_case, monkeypatch, scope, limit):
    from app.config import settings
    from app.workers.tasks import run_ai_analysis, run_case_ai_analysis

    data, run, calls = worker_case
    monkeypatch.setattr(settings, "ai_max_prompt_chars", 1800)
    data.provider.job_max_prompt_chars = 71
    data.provider.case_max_prompt_chars = 71
    setattr(data.provider, f"{scope}_max_prompt_chars", limit)
    if scope == "job":
        run = JobAiAnalysis(job_id=data.jobs[0].id, provider_id=data.provider.id, provider_name=data.provider.name, model=data.provider.model, status=AiAnalysisStatus.PENDING)
        sync_db.add(run)
    sync_db.commit()
    task = run_ai_analysis if scope == "job" else run_case_ai_analysis
    task.call_local(run.id)
    sync_db.refresh(run)
    assert run.status == AiAnalysisStatus.COMPLETED, run.error_message
    assert len(calls) == 1
    effective_limit = 1800 if limit is None else limit
    prompt = calls[0]["user"]
    assert len(prompt) <= effective_limit
    if limit == 6000:
        assert len(prompt) > settings.ai_max_prompt_chars
    assert len(prompt) != 71  # The other scope's budget must never apply.
    assert run.prompt_text == prompt
    assert run.prompt_chars == len(prompt)
    assert f"(limit {effective_limit})" in run.log_output
    assert calls[0]["max_output_tokens"] == 20_000


@pytest.mark.parametrize("gate", ["feature", "provider", "requester", "case", "cancel"])
def test_queued_worker_rechecks_access(sync_db, worker_case, fake_redis, gate):
    from app.redis_client import AI_CANCEL_PREFIX
    from app.workers.tasks import run_case_ai_analysis

    data, run, calls = worker_case
    if gate == "feature":
        sync_db.get(SiteSettings, 1).show_ai_analysis = False
    elif gate == "provider":
        data.provider.enabled = False
    elif gate == "requester":
        data.owner.role = "user"
    elif gate == "case":
        data.case.is_shared = False
        data.case.created_by_user_id = data.other.id
    else:
        fake_redis.set(f"{AI_CANCEL_PREFIX}case:{run.id}", "1")
    sync_db.commit()
    run_case_ai_analysis.call_local(run.id)
    sync_db.refresh(run)
    assert not calls
    assert run.status == (AiAnalysisStatus.CANCELLED if gate == "cancel" else AiAnalysisStatus.FAILED)


def test_entity_only_case_and_case_delete_cascade(sync_db):
    data = seed_case(sync_db)
    sync_db.execute(delete(CaseJobLink))
    prompt, meta, sources = prepare_case_evidence(sync_db, data.case, data.owner)
    assert "entity rationale" in prompt
    assert loads(sources) == []
    assert meta["findings_rendered"] == 0
    run = saved_run(data, source_jobs_json=sources)
    sync_db.add(run)
    sync_db.commit()
    run_id = run.id
    sync_db.delete(data.case)
    sync_db.commit()
    assert sync_db.get(CaseAiAnalysis, run_id) is None


@pytest.mark.parametrize("change", ["visibility", "feature", "requester"])
def test_worker_rechecks_access_after_digest(sync_db, worker_case, monkeypatch, change):
    from app.ai import case_evidence
    from app.workers.tasks import run_case_ai_analysis

    data, run, calls = worker_case
    original = case_evidence.prepare_case_evidence

    def change_after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        if change == "visibility":
            data.jobs[0].is_private = True
            data.jobs[0].submitted_by_user_id = data.other.id
        elif change == "feature":
            sync_db.get(SiteSettings, 1).show_ai_analysis = False
        else:
            data.owner.is_active = False
        sync_db.commit()
        return result

    monkeypatch.setattr(case_evidence, "prepare_case_evidence", change_after_read)
    run_case_ai_analysis.call_local(run.id)
    sync_db.refresh(run)
    assert not calls
    assert run.status == AiAnalysisStatus.FAILED
    assert "access changed" in run.error_message


@pytest.mark.parametrize("outcome", ["failure", "cancel", "exception"])
def test_worker_terminal_failures_stop_polling(sync_db, worker_case, monkeypatch, outcome):
    from app.ai.client import CANCELLED_ERROR
    from app.workers.tasks import run_case_ai_analysis

    _data, run, _calls = worker_case

    def fail(**kwargs):
        if outcome == "exception":
            raise RuntimeError("provider failure")
        return None, {}, 1, CANCELLED_ERROR if outcome == "cancel" else "provider unavailable"

    monkeypatch.setattr("app.ai.client.run_completion", fail)
    run_case_ai_analysis.call_local(run.id)
    sync_db.refresh(run)
    assert run.status == (AiAnalysisStatus.CANCELLED if outcome == "cancel" else AiAnalysisStatus.FAILED)
    assert run.finished_at


async def test_live_cancel_and_delete_permissions(member_client, async_db, case_data, fake_redis):
    from app.redis_client import AI_HEARTBEAT_PREFIX

    data = case_data
    mine = saved_run(data, status=AiAnalysisStatus.RUNNING)
    other = saved_run(data, requested_by_user_id=data.other.id)
    async_db.add_all([mine, other])
    await async_db.commit()
    base = f"/intel/cases/{data.case.id}/ai-analysis"
    fake_redis.set(f"{AI_HEARTBEAT_PREFIX}case:{mine.id}", "alive")
    response = await member_client.post(f"{base}/{mine.id}/cancel", headers={"HX-Request": "true"})
    assert response.status_code == 200
    await async_db.refresh(mine)
    assert mine.status == AiAnalysisStatus.RUNNING
    assert (await member_client.post(f"{base}/{other.id}/cancel")).status_code == 403
    await member_client.post(f"{base}/delete", data={"analysis_ids": f"{mine.id},{other.id}"})
    assert await async_db.get(CaseAiAnalysis, mine.id)
    assert await async_db.get(CaseAiAnalysis, other.id)


async def test_case_provider_prompt_round_trip(admin_client, async_db, case_data):
    provider = case_data.provider
    response = await admin_client.post(
        f"/admin/ai/{provider.id}",
        data={"name": provider.name, "base_url": provider.base_url, "model": provider.model, "system_prompt": "Job only", "case_system_prompt": "Case only"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    response = await admin_client.post(f"/admin/ai/{provider.id}/duplicate", follow_redirects=False)
    assert response.status_code == 303
    copies = list(await async_db.scalars(select(AiProvider)))
    assert len(copies) == 2
    assert all(p.case_system_prompt == "Case only" and p.system_prompt == "Job only" for p in copies)


def test_retention_invalidates_only_the_matching_source(sync_db):
    from app.workers.tasks import _clear_job_references

    data = seed_case(sync_db)
    affected = saved_run(data)
    unrelated = saved_run(data, source_jobs_json=dumps([{**source_identity(data.jobs[0]), "id": data.jobs[0].id * 10}]))
    sync_db.add_all([affected, unrelated])
    sync_db.commit()
    _clear_job_references(sync_db, data.jobs[0].id)
    sync_db.commit()
    sync_db.refresh(affected)
    sync_db.refresh(unrelated)
    assert affected.source_deleted_at is not None
    assert unrelated.source_deleted_at is None


def test_deleted_run_ids_cannot_reuse_queued_tasks_or_cancel_flags(sync_db):
    data = seed_case(sync_db)
    run = saved_run(data)
    sync_db.add(run)
    sync_db.commit()
    previous_id = run.id
    sync_db.delete(run)
    sync_db.commit()
    replacement = saved_run(data, status=AiAnalysisStatus.PENDING)
    sync_db.add(replacement)
    sync_db.commit()
    assert replacement.id > previous_id
