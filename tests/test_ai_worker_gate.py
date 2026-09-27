"""The worker half of the `show_ai_analysis` switch.

A run can sit in the queue while an admin turns the feature off. "Off" is the promise that
job data stops going to a provider, so the worker has to check it too, not only the route
that queued the run.
"""

from __future__ import annotations

import pytest

from app.models import AiAnalysisStatus, AiProvider, AnalysisJob, JobAiAnalysis, JobStatus, LogFile, SiteSettings, WorkflowDef


@pytest.fixture(autouse=True)
def _worker_session(sync_db, monkeypatch):
    from app.workers import tasks as tasks_mod

    monkeypatch.setattr(tasks_mod, "get_sync_session", lambda: sync_db)
    monkeypatch.setattr(sync_db, "close", lambda: None)


def test_a_queued_run_does_not_call_out_once_the_feature_is_off(sync_db, monkeypatch):
    from app.workers import tasks

    called: list[object] = []
    monkeypatch.setattr("app.ai.client.run_completion", lambda *a, **k: called.append(a) or (None, None, 0, "never"))

    sync_db.add_all([LogFile(id=1, original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1), WorkflowDef(id=1, name="wf")])
    sync_db.add(SiteSettings(id=1, show_ai_analysis=False))
    sync_db.flush()
    provider = AiProvider(name="p", kind="openai", base_url="http://127.0.0.1:11434/v1", model="m", enabled=True)
    job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED)
    sync_db.add_all([provider, job])
    sync_db.flush()
    run = JobAiAnalysis(job_id=job.id, provider_id=provider.id, provider_name="p", model="m", status=AiAnalysisStatus.PENDING)
    sync_db.add(run)
    sync_db.commit()

    tasks.run_ai_analysis.call_local(run.id)

    sync_db.refresh(run)
    assert called == []
    assert run.status == AiAnalysisStatus.FAILED
    assert "switched off" in (run.error_message or "")
