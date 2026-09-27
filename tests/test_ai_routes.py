"""Route tests for the AI analysis of a job.

Two gates on one feature, which is the whole reason this file exists: *running* an
analysis is member-or-above (it spends money or a GPU), while *viewing* one is open to
anyone who can already view the job — a finished analysis is part of the job's record, the
way its findings are. Getting either half wrong is invisible in the browser until the wrong
person clicks the button, or until the button stops appearing for the right one.

The other pinned invariant is the polling contract: `hx-trigger="every 3s"` is emitted
**only** while the selected run is pending or running. Backwards, and every viewer of every
finished job issues a request every three seconds forever.

The POST enqueues a real Huey task, so `no_huey` (autouse) replaces `run_ai_analysis` with
a recorder — the router imports it inside the handler, so the module attribute is the seam.
Nothing here may reach Redis or the network.
"""

from __future__ import annotations

import re
from datetime import timedelta

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.database import utc_now_naive
from app.models import (
    AiAnalysisStatus,
    AiProvider,
    AnalysisJob,
    JobAiAnalysis,
    JobStatus,
    LogFile,
    User,
    WorkflowDef,
)
from app.routers.ai import STALE_GRACE_SECONDS

pytestmark = pytest.mark.anyio

RUN_FORM = 'hx-post="/jobs/'  # the "Analyse this job" form; absent for a viewer who cannot run
POLL = 'hx-trigger="every 3s"'


async def _create_user(async_db, *, email: str, role: str = "member", is_superuser: bool = False) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=is_superuser, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


async def _logout(client) -> None:
    await client.post("/auth/cookie/logout", follow_redirects=False)
    client.cookies.clear()


async def _provider(async_db, *, name: str = "Local Ollama", enabled: bool = True, is_default: bool = True, timeout_seconds: int = 300) -> AiProvider:
    provider = AiProvider(
        name=name,
        kind="openai",
        base_url="http://127.0.0.1:11434/v1",
        model="qwen3:8b",
        enabled=enabled,
        is_default=is_default,
        timeout_seconds=timeout_seconds,
    )
    async_db.add(provider)
    await async_db.commit()
    await async_db.refresh(provider)
    return provider


async def _analysis(
    async_db,
    job_id: int,
    *,
    status: AiAnalysisStatus = AiAnalysisStatus.COMPLETED,
    content: str | None = "Nothing to see here.",
    provider_id: int | None = None,
    provider_name: str = "Local Ollama",
    minutes_ago: int = 0,
    requested_by_user_id=None,
    log_output: str | None = None,
    prompt_text: str | None = None,
) -> JobAiAnalysis:
    row = JobAiAnalysis(
        job_id=job_id,
        provider_id=provider_id,
        provider_name=provider_name,
        model="qwen3:8b",
        status=status,
        content=content,
        log_output=log_output,
        prompt_text=prompt_text,
        requested_by_user_id=requested_by_user_id,
        created_at=utc_now_naive() - timedelta(minutes=minutes_ago),
    )
    async_db.add(row)
    await async_db.commit()
    await async_db.refresh(row)
    return row


def _start(client, job_id: int, provider_id: int):
    """POST the run form the way the pane does — htmx, so the panel comes back inline."""
    return client.post(f"/jobs/{job_id}/ai-analysis", data={"provider_id": provider_id}, headers={"HX-Request": "true"})


@pytest.fixture(autouse=True)
def no_huey(monkeypatch):
    """Replace the Huey task with a recorder. Never enqueue, never infer, never call out.

    `routers/ai.py` imports `run_ai_analysis` inside the handler, so the module attribute
    is what the route resolves at call time — the same seam `test_security_hardening.py`
    uses for `run_analysis`.
    """
    calls: list[int] = []
    monkeypatch.setattr("app.workers.tasks.run_ai_analysis", lambda analysis_id: calls.append(analysis_id))
    return calls


@pytest.fixture(autouse=True)
async def ai_feature_on(async_db):
    """Switch the feature on: most of this file is about the feature itself.

    `show_ai_analysis` defaults off, and it gates starting a run as well as the tab. The
    tests about the switch turn it back off explicitly.
    """
    from app.site_settings import get_site_settings

    (await get_site_settings(async_db)).show_ai_analysis = True
    await async_db.commit()


async def _feature_off(async_db) -> None:
    from app.site_settings import get_site_settings

    (await get_site_settings(async_db)).show_ai_analysis = False
    await async_db.commit()


@pytest.fixture(autouse=True)
def heartbeat_unknown(monkeypatch):
    """Answer "is a worker on this run?" with *unknown*, and keep this file off Redis.

    `_has_heartbeat` is three-valued and `None` is its Redis-is-unreachable branch, which
    falls back to the age-and-provider-timeout bound. Making that the default here is not a
    convenience: it is the only value that keeps every test in this file testing what it was
    written to test, and it means a machine that happens to have Redis running cannot give a
    different result from one that does not. Tests that care about liveness override it.
    """
    monkeypatch.setattr("app.routers.ai._has_heartbeat", lambda analysis_id: None)


@pytest.fixture
def heartbeat(monkeypatch):
    """Set what `_has_heartbeat` reports: True (live worker), False (none), None (unknown)."""

    def _set(value):
        monkeypatch.setattr("app.routers.ai._has_heartbeat", lambda analysis_id: value)

    return _set


@pytest.fixture()
async def base_rows(async_db):
    """A public job, a private job owned by `owner`, and one user of every role."""
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    await async_db.commit()

    owner = await _create_user(async_db, email="owner@ai.example.com")
    other = await _create_user(async_db, email="other@ai.example.com")
    basic = await _create_user(async_db, email="basic@ai.example.com", role="user")
    admin = await _create_user(async_db, email="admin@ai.example.com", role="admin", is_superuser=True)

    public_job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    private_job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner.id)
    other_job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    async_db.add_all([public_job, private_job, other_job])
    await async_db.commit()

    for obj in (public_job, private_job, other_job, owner, other, basic, admin):
        await async_db.refresh(obj)
    return {
        "public_job": public_job,
        "private_job": private_job,
        "other_job": other_job,
        "owner": owner,
        "other": other,
        "basic": basic,
        "admin": admin,
    }


# ── Who may start a run ──────────────────────────────────────────────────────


async def test_anonymous_cannot_start_a_run(test_client, async_db, base_rows, no_huey):
    provider = await _provider(async_db)
    resp = await _start(test_client, base_rows["public_job"].id, provider.id)
    assert resp.status_code == 401, resp.text
    assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() == []
    assert no_huey == []


async def test_plain_user_cannot_start_a_run(test_client, async_db, base_rows, no_huey):
    """A `role="user"` viewer may read the answer but not spend a GPU on a new one."""
    provider = await _provider(async_db)
    await _login(test_client, "basic@ai.example.com")

    resp = await _start(test_client, base_rows["public_job"].id, provider.id)
    assert resp.status_code == 403
    assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() == []
    assert no_huey == []


async def test_member_starts_a_run_and_the_task_is_queued(test_client, async_db, base_rows, no_huey):
    provider = await _provider(async_db)
    job = base_rows["public_job"]
    await _login(test_client, "other@ai.example.com")

    resp = await _start(test_client, job.id, provider.id)
    assert resp.status_code == 200

    rows = (await async_db.execute(select(JobAiAnalysis))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.job_id == job.id
    assert row.status == AiAnalysisStatus.PENDING
    # Snapshots, not reads through provider_id — deleting the provider must not orphan them.
    assert (row.provider_name, row.model) == (provider.name, provider.model)
    assert row.requested_by_user_id == base_rows["other"].id
    assert no_huey == [row.id], "the run must be handed to the worker exactly once"

    # A pending run polls, and the button that would start a second one is disabled.
    assert POLL in resp.text
    assert "A run is already in progress." in resp.text


async def test_admin_starts_a_run(test_client, async_db, base_rows, no_huey):
    provider = await _provider(async_db)
    await _login(test_client, "admin@ai.example.com")

    resp = await _start(test_client, base_rows["public_job"].id, provider.id)
    assert resp.status_code == 200
    assert len(no_huey) == 1


async def test_a_non_htmx_post_redirects_to_the_ai_tab(test_client, async_db, base_rows):
    """The no-JS fallback, same shape as `_queue_background_task`'s."""
    provider = await _provider(async_db)
    job = base_rows["public_job"]
    await _login(test_client, "other@ai.example.com")

    resp = await test_client.post(f"/jobs/{job.id}/ai-analysis", data={"provider_id": provider.id}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/jobs/{job.id}#ai"


# ── Private jobs ─────────────────────────────────────────────────────────────


async def test_private_job_is_a_404_for_another_member_owner_and_admin_can_run(test_client, async_db, base_rows, no_huey):
    """404, not 403: the same reply as a nonexistent job, so it is not an existence oracle."""
    provider = await _provider(async_db)
    job = base_rows["private_job"]

    await _login(test_client, "other@ai.example.com")
    assert (await _start(test_client, job.id, provider.id)).status_code == 404
    assert (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).status_code == 404
    assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() == []
    assert no_huey == []

    # Byte-identical to a job that does not exist at all.
    missing = await _start(test_client, 999_999, provider.id)
    assert missing.status_code == 404

    await _login(test_client, "owner@ai.example.com")
    assert (await _start(test_client, job.id, provider.id)).status_code == 200

    await _login(test_client, "admin@ai.example.com")
    assert (await _start(test_client, job.id, provider.id)).status_code == 200

    assert len(no_huey) == 2


# ── Who may see the pane ─────────────────────────────────────────────────────


async def test_anonymous_reads_the_pane_on_a_public_job_but_gets_no_run_form(test_client, async_db, base_rows):
    await _provider(async_db)
    job = base_rows["public_job"]
    await _analysis(async_db, job.id, content="Suspicious PowerShell download cradle.")

    resp = await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")
    assert resp.status_code == 200
    assert "Suspicious PowerShell download cradle." in resp.text
    assert RUN_FORM not in resp.text
    assert 'name="provider_id"' not in resp.text
    assert "Showing a previously generated analysis." in resp.text


async def test_plain_user_reads_the_pane_but_gets_no_run_form(test_client, async_db, base_rows):
    await _provider(async_db)
    job = base_rows["public_job"]
    await _analysis(async_db, job.id, content="Readable by everyone who can read the job.")
    await _login(test_client, "basic@ai.example.com")

    resp = await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")
    assert resp.status_code == 200
    assert "Readable by everyone who can read the job." in resp.text
    assert RUN_FORM not in resp.text


async def test_member_gets_the_run_form(test_client, async_db, base_rows):
    provider = await _provider(async_db)
    job = base_rows["public_job"]
    await _login(test_client, "other@ai.example.com")

    resp = await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")
    assert resp.status_code == 200
    assert f'hx-post="/jobs/{job.id}/ai-analysis"' in resp.text
    assert f'value="{provider.id}"' in resp.text
    assert "Analyse this job" in resp.text


async def test_anonymous_cannot_read_the_pane_of_a_private_job(test_client, async_db, base_rows):
    await _provider(async_db)
    assert (await test_client.get(f"/jobs/{base_rows['private_job'].id}/ai-analysis-partial")).status_code == 404


# ── The polling contract ─────────────────────────────────────────────────────


@pytest.mark.parametrize("status", [AiAnalysisStatus.PENDING, AiAnalysisStatus.RUNNING])
async def test_an_active_run_keeps_polling(test_client, async_db, base_rows, status):
    job = base_rows["public_job"]
    await _provider(async_db)
    await _analysis(async_db, job.id, status=status, content=None)

    body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert POLL in body
    assert f'hx-get="/jobs/{job.id}/ai-analysis-partial' in body


@pytest.mark.parametrize("status", [AiAnalysisStatus.COMPLETED, AiAnalysisStatus.FAILED])
async def test_a_finished_run_stops_polling(test_client, async_db, base_rows, status):
    """The highest-value assertion here: backwards, every viewer polls a dead job forever."""
    job = base_rows["public_job"]
    await _provider(async_db)
    await _analysis(async_db, job.id, status=status, content="Done." if status is AiAnalysisStatus.COMPLETED else None)

    body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert 'id="ai-analysis-region"' in body, "the pane must still render — absence of the trigger is only meaningful if it did"
    assert POLL not in body


async def test_a_job_with_no_runs_does_not_poll(test_client, async_db, base_rows):
    await _provider(async_db)
    body = (await test_client.get(f"/jobs/{base_rows['public_job'].id}/ai-analysis-partial")).text
    assert 'id="ai-analysis-region"' in body
    assert POLL not in body


async def test_a_failed_run_shows_its_error_not_a_spinner(test_client, async_db, base_rows):
    job = base_rows["public_job"]
    row = await _analysis(async_db, job.id, status=AiAnalysisStatus.FAILED, content=None)
    row.error_message = "model qwen3-8b not found"
    await async_db.commit()

    await _login(test_client, "admin@ai.example.com")
    body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert "The analysis failed" in body
    assert "model qwen3-8b not found" in body
    assert POLL not in body


async def test_the_person_who_started_a_failed_run_sees_why(test_client, async_db, base_rows):
    job = base_rows["public_job"]
    row = await _analysis(async_db, job.id, status=AiAnalysisStatus.FAILED, content=None, requested_by_user_id=base_rows["other"].id)
    row.error_message = "model qwen3-8b not found"
    await async_db.commit()

    await _login(test_client, "other@ai.example.com")
    assert "model qwen3-8b not found" in (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text


@pytest.mark.parametrize("viewer", [None, "basic@ai.example.com", "owner@ai.example.com"])
async def test_a_failed_runs_error_detail_is_not_shown_to_everyone(test_client, async_db, base_rows, viewer):
    """The error can name the provider's internal host or quote a proxy's error page. Tool
    errors on the same job are admin-only; this was the one detail shown to anonymous."""
    job = base_rows["public_job"]
    row = await _analysis(async_db, job.id, status=AiAnalysisStatus.FAILED, content=None, requested_by_user_id=base_rows["other"].id)
    row.error_message = "could not resolve host: ollama.corp.internal [Errno 8]"
    await async_db.commit()

    if viewer:
        await _login(test_client, viewer)
    body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert "The analysis failed" in body
    assert "ollama.corp.internal" not in body


# ── History ──────────────────────────────────────────────────────────────────


async def test_runs_are_history_newest_first_and_selectable(test_client, async_db, base_rows):
    job = base_rows["public_job"]
    await _provider(async_db)
    oldest = await _analysis(async_db, job.id, content="OLDEST verdict.", provider_name="Ollama", minutes_ago=30)
    middle = await _analysis(async_db, job.id, content="MIDDLE verdict.", provider_name="Claude", minutes_ago=15)
    newest = await _analysis(async_db, job.id, content="NEWEST verdict.", provider_name="GPT", minutes_ago=0)

    body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    # The newest run is the one rendered when nothing is asked for.
    assert "NEWEST verdict." in body
    assert "OLDEST verdict." not in body and "MIDDLE verdict." not in body
    # ...and the history strip lists all three, newest first.
    positions = [body.index(f"analysis_id={row.id}") for row in (newest, middle, oldest)]
    assert positions == sorted(positions), "history must be newest-first"

    # An explicit selection wins over the default.
    picked = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial?analysis_id={oldest.id}")).text
    assert "OLDEST verdict." in picked
    assert "NEWEST verdict." not in picked


async def test_an_analysis_id_from_another_job_is_ignored(test_client, async_db, base_rows):
    """It falls back to this job's latest rather than rendering someone else's run."""
    job, other_job = base_rows["public_job"], base_rows["other_job"]
    await _provider(async_db)
    await _analysis(async_db, job.id, content="MARKER-this-job")
    foreign = await _analysis(async_db, other_job.id, content="MARKER-other-job")

    resp = await test_client.get(f"/jobs/{job.id}/ai-analysis-partial?analysis_id={foreign.id}")
    assert resp.status_code == 200
    assert "MARKER-other-job" not in resp.text
    assert "MARKER-this-job" in resp.text


async def test_a_single_run_renders_no_history_strip(test_client, async_db, base_rows):
    job = base_rows["public_job"]
    await _provider(async_db)
    await _analysis(async_db, job.id, content="Only run.")

    body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert "analysis_id=" not in body, "a picker with one entry is a choice of one"


# ── Empty state ──────────────────────────────────────────────────────────────


async def test_no_provider_configured_renders_a_clean_empty_state(test_client, async_db, base_rows):
    """No AiProvider rows at all: 200 with guidance, never a run form and never a 500."""
    job = base_rows["public_job"]
    assert (await async_db.execute(select(AiProvider))).scalars().all() == []

    await _login(test_client, "other@ai.example.com")
    member_body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert "No AI provider is configured yet." in member_body
    assert "Ask an administrator to add one." in member_body
    assert RUN_FORM not in member_body
    assert POLL not in member_body

    await _login(test_client, "admin@ai.example.com")
    admin_body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert 'href="/admin/ai"' in admin_body

    await _logout(test_client)
    anon = await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")
    assert anon.status_code == 200
    assert "No AI analysis has been run for this job." in anon.text
    assert RUN_FORM not in anon.text


async def test_only_enabled_providers_are_offered(test_client, async_db, base_rows):
    await _provider(async_db, name="Retired", enabled=False, is_default=False)
    live = await _provider(async_db, name="Live", enabled=True)
    await _login(test_client, "other@ai.example.com")

    body = (await test_client.get(f"/jobs/{base_rows['public_job'].id}/ai-analysis-partial")).text
    assert f'value="{live.id}"' in body
    assert "Retired" not in body


# ── A provider that cannot be used ───────────────────────────────────────────


async def test_a_disabled_provider_cannot_start_a_run(test_client, async_db, base_rows, no_huey):
    """The panel comes back with a message — not a 500, and not a queued run."""
    disabled = await _provider(async_db, name="Retired", enabled=False, is_default=False)
    await _login(test_client, "other@ai.example.com")

    resp = await _start(test_client, base_rows["public_job"].id, disabled.id)
    assert resp.status_code == 200
    assert "That AI provider is no longer available." in resp.text
    assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() == []
    assert no_huey == []


async def test_the_per_user_rate_limit_refuses_the_run_without_queueing_it(test_client, async_db, base_rows, no_huey, monkeypatch):
    """A limited request must come back as the panel with a message — and above all must
    not reach the worker, since the cost this limit exists to bound is the inference."""
    monkeypatch.setattr("app.config.settings.ai_rate_limit_per_minute", 1)
    provider = await _provider(async_db)
    job = base_rows["public_job"]
    await _login(test_client, "other@ai.example.com")

    assert (await _start(test_client, job.id, provider.id)).status_code == 200
    second = await _start(test_client, job.id, provider.id)
    assert second.status_code == 200
    assert "too many analyses" in second.text
    assert len(no_huey) == 1
    assert len((await async_db.execute(select(JobAiAnalysis))).scalars().all()) == 1


async def test_a_deleted_provider_gives_the_same_reply(test_client, async_db, base_rows, no_huey):
    await _provider(async_db)
    await _login(test_client, "other@ai.example.com")

    resp = await _start(test_client, base_rows["public_job"].id, 999_999)
    assert resp.status_code == 200
    assert "That AI provider is no longer available." in resp.text
    assert no_huey == []


# ── The tab ──────────────────────────────────────────────────────────────────


async def test_build_job_tabs_default_is_unchanged(base_rows):
    """`show_ai` is keyword-only with a default, so every existing call site is untouched."""
    from app.routers.jobs import _build_job_tabs

    # The claim is "anonymous gets exactly one tab, and it is Results with nothing on it" —
    # asserted field by field rather than as a whole-dict equality, so adding a presentational
    # key (an icon) is not a failing test.
    solo = _build_job_tabs(None, 0)
    assert len(solo) == 1
    assert (solo[0]["key"], solo[0]["label"], solo[0]["badge"], solo[0]["lazy_event"]) == ("results", "Results", None, None)
    assert [t["key"] for t in _build_job_tabs(base_rows["other"], 3)] == ["results", "discussion"]
    assert [t["key"] for t in _build_job_tabs(base_rows["basic"], 0)] == ["results", "discussion"]


async def test_build_job_tabs_with_show_ai(base_rows):
    from app.routers.jobs import _build_job_tabs

    tabs = _build_job_tabs(base_rows["other"], 0, show_ai=True)
    assert [t["key"] for t in tabs] == ["results", "ai", "discussion"]

    ai_tab = next(t for t in tabs if t["key"] == "ai")
    assert ai_tab["label"] == "AI Analysis"
    assert ai_tab["lazy_event"] == "loadAiAnalysis"
    assert ai_tab["icon"] == "sparkles"
    assert ai_tab["badge"] is None

    # Anonymous keeps a strip of its own — results plus the AI tab, no discussion.
    assert [t["key"] for t in _build_job_tabs(None, 0, show_ai=True)] == ["results", "ai"]


async def test_the_job_page_lazy_loads_the_pane_when_the_tab_is_on(test_client, async_db, base_rows):
    """The pane must wait for `loadAiAnalysis`; loading with the page would run the query
    for every visitor who never opens the tab."""
    from app.site_settings import get_site_settings

    site_settings = await get_site_settings(async_db)
    site_settings.show_ai_analysis = True
    await async_db.commit()

    job = base_rows["public_job"]
    await _login(test_client, "other@ai.example.com")
    body = (await test_client.get(f"/jobs/{job.id}")).text

    assert 'hx-trigger="loadAiAnalysis from:body once"' in body
    assert f'hx-get="/jobs/{job.id}/ai-analysis-partial"' in body
    assert "select('ai')" in body


async def test_a_non_member_gets_the_tab_only_once_a_run_exists(test_client, async_db, base_rows):
    """A tab whose only content is a button they cannot press is worse than no tab; a
    finished analysis, on the other hand, is part of the job's record."""
    from app.site_settings import get_site_settings

    site_settings = await get_site_settings(async_db)
    site_settings.show_ai_analysis = True
    await async_db.commit()

    job = base_rows["public_job"]
    await _login(test_client, "basic@ai.example.com")
    assert "loadAiAnalysis" not in (await test_client.get(f"/jobs/{job.id}")).text

    await _analysis(async_db, job.id, content="A verdict worth reading.")
    assert "loadAiAnalysis" in (await test_client.get(f"/jobs/{job.id}")).text


async def test_the_tab_is_absent_when_the_feature_is_off(test_client, async_db, base_rows):
    """`show_ai_analysis` defaults off, and a member is the viewer most likely to get the
    tab — so if the flag were ignored anywhere, it would show here."""
    from app.models import SiteSettings

    assert SiteSettings.__table__.c.show_ai_analysis.default.arg is False
    await _feature_off(async_db)

    await _provider(async_db)
    await _analysis(async_db, base_rows["public_job"].id, content="hidden behind the flag")
    await _login(test_client, "other@ai.example.com")
    body = (await test_client.get(f"/jobs/{base_rows['public_job'].id}")).text
    assert "loadAiAnalysis" not in body


async def test_a_run_cannot_be_started_while_the_feature_is_off(test_client, async_db, base_rows, no_huey):
    """Off means job data does not go to a provider — not merely that the tab is hidden.
    A member with the form still open, or a script, must not get past it."""
    provider = await _provider(async_db)
    await _feature_off(async_db)
    await _login(test_client, "other@ai.example.com")

    resp = await _start(test_client, base_rows["public_job"].id, provider.id)
    assert resp.status_code == 200
    assert "switched off" in resp.text
    assert RUN_FORM not in resp.text
    assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() == []
    assert no_huey == []


# ── Only a finished job can be analysed ──────────────────────────────────────
#
# The eligible set is `completed` + `partial`, NOT `TERMINAL_JOB_STATUSES` — a job that
# failed or was cancelled before producing findings has nothing for a model to read, and
# handing it an empty brief buys a confident answer about nothing.


@pytest.mark.parametrize("status", [JobStatus.PENDING, JobStatus.RUNNING, JobStatus.FAILED, JobStatus.CANCELLED])
async def test_starting_a_run_on_an_unanalysable_job_is_refused(test_client, async_db, base_rows, no_huey, status):
    provider = await _provider(async_db)
    job = AnalysisJob(file_id=1, workflow_id=1, status=status, is_private=False)
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)
    await _login(test_client, "other@ai.example.com")

    resp = await _start(test_client, job.id, provider.id)

    # Refused through the panel, like every other refusal here — not a 4xx, because the
    # form posts into the region and an error page would replace the pane with a stack trace.
    assert resp.status_code == 200
    assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() == []
    assert no_huey == []


@pytest.mark.parametrize("status", [JobStatus.COMPLETED, JobStatus.PARTIAL])
async def test_a_partial_job_can_still_be_analysed(test_client, async_db, base_rows, no_huey, status):
    """`partial` is deliberately in: the tools that did run produced real findings."""
    provider = await _provider(async_db)
    job = AnalysisJob(file_id=1, workflow_id=1, status=status, is_private=False)
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)
    await _login(test_client, "other@ai.example.com")

    assert (await _start(test_client, job.id, provider.id)).status_code == 200
    assert len((await async_db.execute(select(JobAiAnalysis))).scalars().all()) == 1
    assert len(no_huey) == 1


async def test_the_run_form_is_hidden_while_the_job_is_still_running(test_client, async_db, base_rows):
    await _provider(async_db)
    job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.RUNNING, is_private=False)
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)
    await _login(test_client, "other@ai.example.com")

    body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert RUN_FORM not in body
    assert "still running" in body
    # Not confused with the "no provider configured" branch, which has a different remedy.
    assert "No AI provider is configured yet." not in body


async def test_a_pending_job_keeps_its_tab_but_a_failed_one_loses_it(test_client, async_db, base_rows):
    """The gate is "terminal *and* ineligible", not simply "ineligible".

    A failed job will never become analysable, so hiding its tab costs nothing. A pending
    one will — and hiding it there would mean re-rendering the tab strip mid-poll, which
    lives inside the same `x-data` as the comment box.
    """
    from app.site_settings import get_site_settings

    site_settings = await get_site_settings(async_db)
    site_settings.show_ai_analysis = True
    await async_db.commit()

    pending = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.PENDING, is_private=False)
    failed = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.FAILED, is_private=False)
    async_db.add_all([pending, failed])
    await async_db.commit()
    await async_db.refresh(pending)
    await async_db.refresh(failed)
    await _login(test_client, "other@ai.example.com")

    assert "loadAiAnalysis" in (await test_client.get(f"/jobs/{pending.id}")).text
    assert "loadAiAnalysis" not in (await test_client.get(f"/jobs/{failed.id}")).text

    # ...but a run that already exists on the failed job stays readable: it is part of the
    # job's record, and re-running into a failure must not hide what was concluded before.
    await _analysis(async_db, failed.id, content="Concluded before the re-run failed.")
    assert "loadAiAnalysis" in (await test_client.get(f"/jobs/{failed.id}")).text


# ── Deletion ─────────────────────────────────────────────────────────────────


async def test_job_delete_removes_its_ai_analyses(test_client, async_db, base_rows, fake_redis):
    """Foreign keys are ON in tests: a forgotten child table dangles here and raises
    ForeignKeyViolation on PostgreSQL."""
    job = base_rows["public_job"]
    provider = await _provider(async_db)
    await _analysis(async_db, job.id, provider_id=provider.id, content="about to vanish")

    await _login(test_client, "admin@ai.example.com")
    resp = await test_client.post(f"/jobs/{job.id}/delete", follow_redirects=False)
    assert resp.status_code in (200, 303)

    assert (await async_db.execute(select(JobAiAnalysis).where(JobAiAnalysis.job_id == job.id))).scalars().all() == []
    assert await async_db.get(AnalysisJob, job.id) is None


async def test_deleting_a_provider_keeps_its_runs_as_history(test_client, async_db, base_rows):
    """Runs are history, not a cache: the FK is nulled and the snapshot keeps them readable."""
    job = base_rows["public_job"]
    provider = await _provider(async_db, name="Doomed")
    run = await _analysis(async_db, job.id, provider_id=provider.id, provider_name="Doomed", content="still readable")

    await _login(test_client, "admin@ai.example.com")
    resp = await test_client.post(f"/admin/ai/{provider.id}/delete", follow_redirects=False)
    assert resp.status_code == 303

    await async_db.refresh(run)
    assert run.provider_id is None
    assert run.provider_name == "Doomed"

    body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
    assert "still readable" in body
    assert "Doomed" in body


class TestStalledRuns:
    """A restarted worker must not leave the row at RUNNING forever.

    The poll trigger keys off exactly that status, so without a staleness bound every viewer
    of that job re-requests this partial every three seconds, indefinitely — a dead run
    turning into permanent background load. The bound stays presentational: the row is left
    alone (a GET must not write), but the pane stops claiming progress and stops polling.

    Two signals, in priority order. The worker publishes a **heartbeat** for the whole run,
    so liveness is normally a fact rather than an inference — that is `TestRunLiveness`
    below. Only when Redis cannot answer does the age-and-provider-timeout arithmetic
    apply, which is what the `heartbeat_unknown` autouse fixture pins this class to.
    """

    async def test_a_run_older_than_the_bound_stops_polling(self, test_client, async_db, base_rows):
        job = base_rows["public_job"]
        provider = await _provider(async_db, name="Slow box", timeout_seconds=600)
        await _analysis(
            async_db,
            job.id,
            status=AiAnalysisStatus.RUNNING,
            content=None,
            provider_id=provider.id,
            minutes_ago=(600 + STALE_GRACE_SECONDS) // 60 + 5,
        )
        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert 'hx-trigger="every 3s"' not in body, "a stalled run must stop polling"
        assert "never reported back" in body
        assert "The model is reading" not in body, "a stalled run must not claim to be in progress"

    async def test_a_run_inside_the_bound_keeps_polling(self, test_client, async_db, base_rows):
        job = base_rows["public_job"]
        provider = await _provider(async_db, name="Slow box", timeout_seconds=600)
        await _analysis(
            async_db,
            job.id,
            status=AiAnalysisStatus.RUNNING,
            content=None,
            provider_id=provider.id,
            minutes_ago=1,
        )
        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert 'hx-trigger="every 3s"' in body
        assert "never reported back" not in body

    async def test_the_bound_follows_the_providers_own_timeout(self, test_client, async_db, base_rows):
        """A slow local model must not be declared dead while it is still working.

        Same age, two providers: the one configured to allow an hour is still running, the
        one that gives up in a minute is not.
        """
        job = base_rows["public_job"]
        job2 = base_rows["other_job"]
        patient = await _provider(async_db, name="Patient", timeout_seconds=3600)
        hasty = await _provider(async_db, name="Hasty", timeout_seconds=60, is_default=False)

        await _analysis(async_db, job.id, status=AiAnalysisStatus.RUNNING, content=None, provider_id=patient.id, minutes_ago=30)
        await _analysis(async_db, job2.id, status=AiAnalysisStatus.RUNNING, content=None, provider_id=hasty.id, minutes_ago=30)

        patient_body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        hasty_body = (await test_client.get(f"/jobs/{job2.id}/ai-analysis-partial")).text

        assert 'hx-trigger="every 3s"' in patient_body, "an hour-long timeout must survive 30 minutes"
        assert 'hx-trigger="every 3s"' not in hasty_body, "a one-minute timeout is long dead at 30 minutes"


class TestRunLiveness:
    """The heartbeat outranks the clock, in both directions.

    An age bound can only ever be a guess — it declares a genuinely slow model dead at some
    arbitrary point, and a run whose worker was killed thirty seconds ago *alive* for the
    next half hour. The worker publishes `AI_HEARTBEAT_PREFIX` for the duration of the run,
    so both questions have real answers.
    """

    async def test_a_beating_run_keeps_polling_however_old_it_is(self, test_client, async_db, base_rows, heartbeat):
        """A worker is demonstrably on it, so the configured timeout is not the question."""
        heartbeat(True)
        job = base_rows["public_job"]
        provider = await _provider(async_db, name="Very slow box", timeout_seconds=60)
        await _analysis(async_db, job.id, status=AiAnalysisStatus.RUNNING, content=None, provider_id=provider.id, minutes_ago=120)

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert 'hx-trigger="every 3s"' in body, "a heartbeat means a worker is still on it"
        assert "never reported back" not in body

    async def test_a_run_with_no_heartbeat_is_abandoned_long_before_the_old_bound(self, test_client, async_db, base_rows, heartbeat):
        """Worker killed mid-inference, nothing left to report.

        Age arithmetic alone would claim this row is in progress for `timeout + 900s`.
        With no heartbeat behind it, it is abandoned as soon as the start-up grace lapses.
        """
        heartbeat(False)
        job = base_rows["public_job"]
        provider = await _provider(async_db, name="Patient", timeout_seconds=3600)
        await _analysis(async_db, job.id, status=AiAnalysisStatus.RUNNING, content=None, provider_id=provider.id, minutes_ago=10)

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert 'hx-trigger="every 3s"' not in body, "no heartbeat and past the grace: nothing is running"
        assert "never reported back" in body

    async def test_a_just_started_run_is_not_abandoned_before_its_first_beat(self, test_client, async_db, base_rows, heartbeat):
        """The grace exists for exactly one window: status committed, first beat not yet in."""
        heartbeat(False)
        job = base_rows["public_job"]
        provider = await _provider(async_db, name="Fresh", timeout_seconds=600)
        await _analysis(async_db, job.id, status=AiAnalysisStatus.RUNNING, content=None, provider_id=provider.id, minutes_ago=0)

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert 'hx-trigger="every 3s"' in body
        assert "never reported back" not in body

    async def test_a_pending_run_past_the_queue_expiry_is_abandoned(self, test_client, async_db, base_rows, heartbeat):
        """Nothing beats for a queued task — Huey's own expiry is the bound that applies.

        `run_ai_analysis` is registered with `expires=settings.huey_queue_expiry`, so past
        that point the task has been discarded and the row is waiting for something that no
        longer exists. There is no heartbeat to consult and no provider timeout to consult
        either: the run never reached a provider.
        """
        heartbeat(True)  # irrelevant for pending, and that is the point
        from app.config import settings

        job = base_rows["public_job"]
        provider = await _provider(async_db, name="Queued", timeout_seconds=600)
        await _analysis(
            async_db,
            job.id,
            status=AiAnalysisStatus.PENDING,
            content=None,
            provider_id=provider.id,
            minutes_ago=(settings.huey_queue_expiry // 60) + 10,
        )

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert 'hx-trigger="every 3s"' not in body
        assert "no worker will pick it up" in body

    async def test_a_terminal_run_is_never_called_stalled(self, test_client, async_db, base_rows):
        """Staleness only applies to pending/running — an old completed run is just old."""
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, status=AiAnalysisStatus.COMPLETED, content="Ancient but fine.", minutes_ago=60 * 24 * 30)
        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "never reported back" not in body
        assert "Ancient but fine." in body
        assert 'hx-trigger="every 3s"' not in body


# ── Stopping a run ───────────────────────────────────────────────────────────


def _cancel(client, job_id: int, analysis_id: int):
    return client.post(f"/jobs/{job_id}/ai-analysis/{analysis_id}/cancel", headers={"HX-Request": "true"})


def _delete(client, job_id: int, ids):
    """The pane posts one comma-separated field — the selection lives in an Alpine store."""
    return client.post(
        f"/jobs/{job_id}/ai-analysis/delete",
        data={"analysis_ids": ",".join(str(i) for i in ids)},
        headers={"HX-Request": "true"},
    )


class TestCancelAuthorization:
    """Stopping is not the same permission as running.

    Running is member-or-above because it spends a GPU. Stopping is admin-or-the-person-who
    started it, because a member reaching into a colleague's in-flight run and killing it is
    a different act from starting one of their own.
    """

    async def test_anonymous_cannot_stop_a_run(self, test_client, async_db, base_rows):
        run = await _analysis(async_db, base_rows["public_job"].id, status=AiAnalysisStatus.RUNNING, content=None)
        assert (await _cancel(test_client, base_rows["public_job"].id, run.id)).status_code == 401
        await async_db.refresh(run)
        assert run.status == AiAnalysisStatus.RUNNING

    async def test_a_plain_user_cannot_stop_a_run(self, test_client, async_db, base_rows):
        run = await _analysis(async_db, base_rows["public_job"].id, status=AiAnalysisStatus.RUNNING, content=None)
        await _login(test_client, "basic@ai.example.com")
        assert (await _cancel(test_client, base_rows["public_job"].id, run.id)).status_code == 403

    async def test_a_member_cannot_stop_someone_elses_run(self, test_client, async_db, base_rows):
        run = await _analysis(
            async_db,
            base_rows["public_job"].id,
            status=AiAnalysisStatus.RUNNING,
            content=None,
            requested_by_user_id=base_rows["owner"].id,
        )
        await _login(test_client, "other@ai.example.com")
        assert (await _cancel(test_client, base_rows["public_job"].id, run.id)).status_code == 403
        await async_db.refresh(run)
        assert run.status == AiAnalysisStatus.RUNNING

    async def test_the_person_who_started_it_can_stop_it(self, test_client, async_db, base_rows, heartbeat):
        heartbeat(False)
        run = await _analysis(
            async_db,
            base_rows["public_job"].id,
            status=AiAnalysisStatus.RUNNING,
            content=None,
            requested_by_user_id=base_rows["owner"].id,
        )
        await _login(test_client, "owner@ai.example.com")
        assert (await _cancel(test_client, base_rows["public_job"].id, run.id)).status_code == 200
        await async_db.refresh(run)
        assert run.status == AiAnalysisStatus.CANCELLED

    async def test_an_admin_can_stop_anyones_run(self, test_client, async_db, base_rows, heartbeat):
        heartbeat(False)
        run = await _analysis(
            async_db,
            base_rows["public_job"].id,
            status=AiAnalysisStatus.RUNNING,
            content=None,
            requested_by_user_id=base_rows["owner"].id,
        )
        await _login(test_client, "admin@ai.example.com")
        assert (await _cancel(test_client, base_rows["public_job"].id, run.id)).status_code == 200
        await async_db.refresh(run)
        assert run.status == AiAnalysisStatus.CANCELLED

    async def test_a_run_on_another_job_is_a_404_not_a_403(self, test_client, async_db, base_rows):
        """Same reply as "no such run": the route must not confirm a run exists elsewhere."""
        foreign = await _analysis(async_db, base_rows["other_job"].id, status=AiAnalysisStatus.RUNNING, content=None)
        await _login(test_client, "admin@ai.example.com")
        assert (await _cancel(test_client, base_rows["public_job"].id, foreign.id)).status_code == 404

    async def test_a_private_job_is_not_reachable_by_a_stranger(self, test_client, async_db, base_rows):
        run = await _analysis(async_db, base_rows["private_job"].id, status=AiAnalysisStatus.RUNNING, content=None)
        await _login(test_client, "other@ai.example.com")
        assert (await _cancel(test_client, base_rows["private_job"].id, run.id)).status_code == 404


class TestCancelTheThreeCases:
    """The same three the job cancel route has, because the failure modes are the same.

    The third one is why this feature exists: a run whose worker died mid-inference had no
    way back to a terminal status at all.
    """

    async def test_a_queued_run_is_finalised_here(self, test_client, async_db, base_rows, heartbeat):
        """Nothing has claimed it, so nothing else can record the outcome.

        The worker re-reads the flag at pickup and drops the task, so writing the row now is
        safe — and it is the only thing that helps when the fleet is down and no worker will
        ever pick it up.
        """
        heartbeat(True)  # irrelevant while pending, which is the point
        run = await _analysis(
            async_db,
            base_rows["public_job"].id,
            status=AiAnalysisStatus.PENDING,
            content=None,
            requested_by_user_id=base_rows["owner"].id,
        )
        await _login(test_client, "owner@ai.example.com")
        body = (await _cancel(test_client, base_rows["public_job"].id, run.id)).text

        await async_db.refresh(run)
        assert run.status == AiAnalysisStatus.CANCELLED
        assert run.finished_at is not None
        assert POLL not in body, "a cancelled run must stop polling"

    async def test_a_running_run_with_a_live_worker_is_left_to_the_worker(self, test_client, async_db, base_rows, heartbeat):
        """Two writers on one row is a lost update; the worker owns it and knows when it stopped."""
        heartbeat(True)
        run = await _analysis(
            async_db,
            base_rows["public_job"].id,
            status=AiAnalysisStatus.RUNNING,
            content=None,
            requested_by_user_id=base_rows["owner"].id,
        )
        await _login(test_client, "owner@ai.example.com")
        body = (await _cancel(test_client, base_rows["public_job"].id, run.id)).text

        await async_db.refresh(run)
        assert run.status == AiAnalysisStatus.RUNNING, "the worker records the cancellation, not the route"
        assert "Stopping" in body
        assert POLL in body, "still polling: the worker has not finished tearing down yet"

    async def test_a_running_run_with_no_worker_is_finalised_here(self, test_client, async_db, base_rows, heartbeat):
        """The hang. No heartbeat means nothing is left to read a cancel flag."""
        heartbeat(False)
        run = await _analysis(
            async_db,
            base_rows["public_job"].id,
            status=AiAnalysisStatus.RUNNING,
            content=None,
            requested_by_user_id=base_rows["owner"].id,
            minutes_ago=45,
        )
        await _login(test_client, "owner@ai.example.com")
        body = (await _cancel(test_client, base_rows["public_job"].id, run.id)).text

        await async_db.refresh(run)
        assert run.status == AiAnalysisStatus.CANCELLED
        assert "no worker was still processing it" in body

    async def test_stopping_an_already_finished_run_changes_nothing(self, test_client, async_db, base_rows):
        run = await _analysis(
            async_db,
            base_rows["public_job"].id,
            status=AiAnalysisStatus.COMPLETED,
            content="Done.",
            requested_by_user_id=base_rows["owner"].id,
        )
        await _login(test_client, "owner@ai.example.com")
        body = (await _cancel(test_client, base_rows["public_job"].id, run.id)).text

        await async_db.refresh(run)
        assert run.status == AiAnalysisStatus.COMPLETED
        assert run.content == "Done."
        assert "already finished" in body


# ── Deleting runs ────────────────────────────────────────────────────────────


class TestDeleteRuns:
    async def test_several_runs_go_in_one_request(self, test_client, async_db, base_rows):
        """The actual ask: clearing out a job's accumulated history, not one row at a time."""
        job = base_rows["public_job"]
        owner = base_rows["owner"]
        runs = [await _analysis(async_db, job.id, content=f"run {i}", requested_by_user_id=owner.id) for i in range(4)]
        await _login(test_client, "owner@ai.example.com")

        resp = await _delete(test_client, job.id, [runs[0].id, runs[2].id])
        assert resp.status_code == 200
        assert "Deleted 2 analysis run(s)." in resp.text

        left = {r.id for r in (await async_db.execute(select(JobAiAnalysis))).scalars().all()}
        assert left == {runs[1].id, runs[3].id}

    async def test_a_running_run_is_refused_rather_than_deleted(self, test_client, async_db, base_rows):
        """A worker is about to commit to that row; deleting under it is a lost update."""
        job, owner = base_rows["public_job"], base_rows["owner"]
        live = await _analysis(async_db, job.id, status=AiAnalysisStatus.RUNNING, content=None, requested_by_user_id=owner.id)
        done = await _analysis(async_db, job.id, content="finished", requested_by_user_id=owner.id)
        await _login(test_client, "owner@ai.example.com")

        resp = await _delete(test_client, job.id, [live.id, done.id])
        assert "Deleted 1 analysis run(s)." in resp.text
        assert "still running — stop it first." in resp.text

        left = {r.id for r in (await async_db.execute(select(JobAiAnalysis))).scalars().all()}
        assert left == {live.id}

    async def test_someone_elses_run_is_not_deleted_and_the_reply_says_so(self, test_client, async_db, base_rows):
        """Reporting only the successes is what makes a bulk action feel broken."""
        job = base_rows["public_job"]
        mine = await _analysis(async_db, job.id, content="mine", requested_by_user_id=base_rows["other"].id)
        theirs = await _analysis(async_db, job.id, content="theirs", requested_by_user_id=base_rows["owner"].id)
        await _login(test_client, "other@ai.example.com")

        resp = await _delete(test_client, job.id, [mine.id, theirs.id])
        assert "Deleted 1 analysis run(s)." in resp.text
        assert "started by someone else" in resp.text

        left = {r.id for r in (await async_db.execute(select(JobAiAnalysis))).scalars().all()}
        assert left == {theirs.id}

    async def test_an_admin_may_delete_anyones_run(self, test_client, async_db, base_rows):
        job = base_rows["public_job"]
        run = await _analysis(async_db, job.id, content="someone else's", requested_by_user_id=base_rows["owner"].id)
        await _login(test_client, "admin@ai.example.com")

        await _delete(test_client, job.id, [run.id])
        assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() == []

    async def test_a_run_belonging_to_another_job_is_never_touched(self, test_client, async_db, base_rows):
        """The delete is scoped by job id in SQL, not merely checked afterwards."""
        admin = base_rows["admin"]
        mine = await _analysis(async_db, base_rows["public_job"].id, content="mine", requested_by_user_id=admin.id)
        foreign = await _analysis(async_db, base_rows["other_job"].id, content="foreign", requested_by_user_id=admin.id)
        await _login(test_client, "admin@ai.example.com")

        resp = await _delete(test_client, base_rows["public_job"].id, [mine.id, foreign.id])
        assert "no longer existed" in resp.text, "an id on another job is reported, not silently dropped"

        left = {r.id for r in (await async_db.execute(select(JobAiAnalysis))).scalars().all()}
        assert left == {foreign.id}

    async def test_anonymous_cannot_delete(self, test_client, async_db, base_rows):
        run = await _analysis(async_db, base_rows["public_job"].id, content="public")
        assert (await _delete(test_client, base_rows["public_job"].id, [run.id])).status_code == 401
        assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() != []

    async def test_a_plain_user_cannot_delete(self, test_client, async_db, base_rows):
        run = await _analysis(async_db, base_rows["public_job"].id, content="public")
        await _login(test_client, "basic@ai.example.com")
        assert (await _delete(test_client, base_rows["public_job"].id, [run.id])).status_code == 403

    async def test_an_empty_selection_says_so_instead_of_deleting_everything(self, test_client, async_db, base_rows):
        """The failure that matters if the ids field ever arrives blank."""
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="keep me", requested_by_user_id=base_rows["admin"].id)
        await _login(test_client, "admin@ai.example.com")

        resp = await _delete(test_client, job.id, [])
        assert "Select at least one" in resp.text
        assert (await async_db.execute(select(JobAiAnalysis))).scalars().all() != []


class TestIdParsing:
    """The wire format for the selection: one comma-separated field."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("3,4", [3, 4]),
            (" 3 , 4 ", [3, 4]),
            ("3,3,4", [3, 4]),
            ("3,,4", [3, 4]),
            ("3,x,4", [3, 4]),
            ("", []),
            ("   ", []),
            ("nonsense", []),
        ],
    )
    def test_parse_ids(self, raw, expected):
        from app.routers.ai import _parse_ids

        assert _parse_ids(raw) == expected


# ── The answer's own area, and copying it ────────────────────────────────────


class TestTheAnswerArea:
    """A clipboard button renders perfectly whether or not it can ever work, so the parts
    that make it work are asserted here rather than left to a manual click."""

    async def test_the_copy_button_targets_the_markdown_source_not_the_rendered_prose(self, test_client, async_db, base_rows):
        await _provider(async_db)
        job = base_rows["public_job"]
        analysis = await _analysis(async_db, job.id, content="## Verdict\n\n| rule | n |\n| --- | --- |\n| evil | 3 |")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text

        # The delegated handler in app.js reads `textContent` off `data-copy-target`.
        assert f'data-copy-target="ai-markdown-{analysis.id}"' in body
        assert f'id="ai-markdown-{analysis.id}"' in body
        # Copying the *source* is the whole point: the rendered half has no pipes left in
        # it, so a button reading the prose div would silently lose every table.
        assert "| rule | n |" in body, "the Markdown source must be in the DOM to be copyable"
        assert "<table>" in body, "...and the rendered table is still shown"

    async def test_the_copy_icons_never_stack_two_display_utilities(self, test_client, async_db, base_rows):
        """`hidden` and `inline-flex` on one element is stylesheet-order roulette — the
        same trap as `overflow-hidden` with `.lt-scroll`."""
        await _provider(async_db)
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="x")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        for cls in re.findall(r'class="([^"]*logstotal-copy-icon[^"]*)"', body):
            names = set(cls.split())
            assert not (names & {"flex", "inline-flex", "block", "inline-block", "grid"}), f"display utility beside `hidden` in {cls!r}"

    async def test_the_answer_sits_in_its_own_card_with_its_provenance(self, test_client, async_db, base_rows):
        """Not bare inside the metadata card, at the same level as the token count — the one
        piece of prose on the page with no frame around it."""
        await _provider(async_db)
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="A verdict.")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        # The comment-card shape from `_comment_thread.html`: sunken panel, then the body.
        assert "bg-gray-950/60" in body
        assert "A verdict." in body


# ── The verbose run log ──────────────────────────────────────────────────────


class TestRunLogVisibility:
    """Deployment detail, so admin-only — the gate `_job_status.html` puts on "Show logs".

    It differs from that one in when it renders: this appears **while the run is still
    going**, because "is this actually working?" is a question about a run in flight.
    """

    async def test_an_admin_sees_the_trace(self, test_client, async_db, base_rows):
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="Done.", log_output="[   0.0s] Provider Local at http://10.0.0.9/v1")
        await _login(test_client, "admin@ai.example.com")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "Show run log" in body
        assert "http://10.0.0.9/v1" in body

    async def test_a_member_does_not(self, test_client, async_db, base_rows):
        """The trace names the provider's base URL, which a member sees nowhere else."""
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="Done.", log_output="[   0.0s] Provider Local at http://10.0.0.9/v1")
        await _login(test_client, "other@ai.example.com")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "Show run log" not in body
        assert "10.0.0.9" not in body

    async def test_an_anonymous_viewer_does_not(self, test_client, async_db, base_rows):
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="Done.", log_output="[   0.0s] Provider Local at http://10.0.0.9/v1")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "10.0.0.9" not in body

    async def test_it_renders_while_the_run_is_still_going(self, test_client, async_db, base_rows, heartbeat):
        heartbeat(True)
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, status=AiAnalysisStatus.RUNNING, content=None, log_output="[   2.0s] First tokens received")
        await _login(test_client, "admin@ai.example.com")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "Show run log" in body
        assert "First tokens received" in body
        assert POLL in body, "a live run keeps polling, which is what refreshes the log"


# ── The prompt that was actually sent ────────────────────────────────────────


class TestPromptVisibility:
    """ "What did we send them?" is a data-handling question, so it gets a real answer.

    `prompt_chars` has always recorded the brief's *size*. That settles nothing: the point
    of keeping the text is to be able to read exactly what left the instance before pointing
    a job at a hosted model. Admin-only, and gated on `SiteSettings.show_ai_prompt`, which
    governs storage as well as display — see the column docstring.
    """

    async def test_an_admin_sees_the_prompt_when_the_setting_is_on(self, test_client, async_db, base_rows):
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="Done.", prompt_text="=== JOB BRIEF ===\nMARKER-sent-to-model")
        await _login(test_client, "admin@ai.example.com")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "Show prompt sent" in body
        assert "MARKER-sent-to-model" in body

    async def test_the_setting_hides_prompts_already_stored(self, test_client, async_db, base_rows):
        """Off must hide history too. Someone turning this off is not asking for a smaller
        database, they are asking for the text not to be readable."""
        from app.site_settings import get_site_settings

        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="Done.", prompt_text="MARKER-sent-to-model")
        settings_row = await get_site_settings(async_db)
        settings_row.show_ai_prompt = False
        await async_db.commit()

        await _login(test_client, "admin@ai.example.com")
        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "Show prompt sent" not in body
        assert "MARKER-sent-to-model" not in body

    async def test_a_member_never_sees_the_prompt(self, test_client, async_db, base_rows):
        """It carries the same event samples the security docs warn about shipping."""
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="Done.", prompt_text="MARKER-sent-to-model")
        await _login(test_client, "other@ai.example.com")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "MARKER-sent-to-model" not in body

    async def test_an_anonymous_viewer_never_sees_the_prompt(self, test_client, async_db, base_rows):
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="Done.", prompt_text="MARKER-sent-to-model")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "MARKER-sent-to-model" not in body

    async def test_a_run_with_no_stored_prompt_offers_nothing(self, test_client, async_db, base_rows):
        """Runs from before the column existed, and runs made while the setting was off."""
        job = base_rows["public_job"]
        await _analysis(async_db, job.id, content="Done.", prompt_text=None)
        await _login(test_client, "admin@ai.example.com")

        body = (await test_client.get(f"/jobs/{job.id}/ai-analysis-partial")).text
        assert "Show prompt sent" not in body


# ── Tab icons ────────────────────────────────────────────────────────────────


class TestTabIcons:
    """Every tab carries a glyph name, and every glyph name is one `tab_icon` can draw.

    Both halves matter and neither is visible from a route test: a tab with no icon renders
    a strip where one label is mysteriously unadorned, and a tab naming a glyph the macro
    does not know renders nothing at all — silently, because the macro's `if` simply misses.
    """

    def _icon_names(self):
        import re
        from pathlib import Path

        # The dictionary moved to `_icons.html` when the admin cards and settings sections
        # started drawing from the same vocabulary — one dictionary is the whole point, so
        # this follows it rather than growing a second source of truth to check.
        src = Path("app/templates/partials/_icons.html").read_text()
        block = src[src.index("{%- set d = {") : src.index("} -%}")]
        return set(re.findall(r"^\s*'([a-z]+)':", block, re.M))

    def test_the_macro_draws_every_icon_the_job_tabs_name(self, base_rows):
        from app.routers.jobs import _build_job_tabs

        known = self._icon_names()
        tabs = _build_job_tabs(base_rows["admin"], 2, show_ai=True)
        assert tabs, "expected a full tab list"
        for tab in tabs:
            assert tab.get("icon"), f"tab {tab['key']!r} has no icon"
            assert tab["icon"] in known, f"tab {tab['key']!r} names an icon the macro cannot draw: {tab['icon']!r}"

    def test_the_macro_draws_every_icon_the_case_tabs_name(self):
        from app.routers.cases import _build_case_tabs

        known = self._icon_names()
        for tab in _build_case_tabs(1, 2, 3):
            assert tab.get("icon"), f"tab {tab['key']!r} has no icon"
            assert tab["icon"] in known, f"tab {tab['key']!r} names an unknown icon {tab['icon']!r}"

    async def test_the_macro_draws_every_icon_the_entity_tabs_name(self, async_db):
        from app.models import Entity
        from app.routers.intel import _build_entity_tabs

        known = self._icon_names()
        # An executable, so the conditional Processes tab is included in the check.
        entity = Entity(value="powershell.exe", entity_type="executable")
        async_db.add(entity)
        await async_db.commit()
        tabs = _build_entity_tabs(entity, 1, 2, comment_count=3)
        assert any(t["key"] == "processes" for t in tabs), "expected the conditional tab to be covered"
        for tab in tabs:
            assert tab.get("icon"), f"tab {tab['key']!r} has no icon"
            assert tab["icon"] in known, f"tab {tab['key']!r} names an unknown icon {tab['icon']!r}"

    async def test_the_icon_reaches_the_rendered_strip(self, test_client, async_db, base_rows):
        """The macro has to actually be called — importing it and forgetting it is silent."""
        await _provider(async_db)
        await _analysis(async_db, base_rows["public_job"].id, content="Done.")
        await _login(test_client, "admin@ai.example.com")

        body = (await test_client.get(f"/jobs/{base_rows['public_job'].id}")).text
        assert body.count("<svg") >= 3, "each tab in the strip should carry a glyph"


# ── Duplicating a provider ───────────────────────────────────────────────────


class TestDuplicateProvider:
    """Providers differ from one another in one field, so copying one is the common edit.

    Re-entering a base URL and re-pasting an API key to change a model name is where a typo
    comes from — and a mistyped base URL surfaces as a 404 that reads like a bad model name,
    which is the single most confusing failure this feature has.
    """

    async def _dup(self, client, provider_id):
        return await client.post(f"/admin/ai/{provider_id}/duplicate", follow_redirects=False)

    async def test_it_copies_the_settings_under_a_free_name(self, test_client, async_db, base_rows):
        from app.auth.api_tokens import encrypt_secret

        source = await _provider(async_db, name="Ollama", timeout_seconds=900)
        source.api_token_encrypted = encrypt_secret("sk-secret")
        source.notes = "the local box"
        await async_db.commit()

        await _login(test_client, "admin@ai.example.com")
        assert (await self._dup(test_client, source.id)).status_code == 303

        rows = (await async_db.execute(select(AiProvider).order_by(AiProvider.id))).scalars().all()
        assert len(rows) == 2
        copy = rows[1]
        assert copy.name == "Ollama (copy)"
        assert (copy.kind, copy.base_url, copy.model) == (source.kind, source.base_url, source.model)
        assert copy.timeout_seconds == 900
        assert copy.notes == "the local box"
        # The token comes along: same key, same instance, same admin. A copy that silently
        # lost its credential fails at the first run with an auth error pointing at nothing.
        assert copy.api_token_encrypted == source.api_token_encrypted

    async def test_the_copy_is_never_the_default(self, test_client, async_db, base_rows):
        """At most one provider holds it, so a copy claiming it would demote the original."""
        source = await _provider(async_db, name="Ollama", is_default=True)
        await _login(test_client, "admin@ai.example.com")
        await self._dup(test_client, source.id)

        rows = (await async_db.execute(select(AiProvider).order_by(AiProvider.id))).scalars().all()
        await async_db.refresh(source)
        assert source.is_default is True, "the original must keep it"
        assert rows[1].is_default is False
        assert sum(1 for r in rows if r.is_default) == 1

    async def test_copying_twice_keeps_finding_a_free_name(self, test_client, async_db, base_rows):
        source = await _provider(async_db, name="Ollama")
        await _login(test_client, "admin@ai.example.com")
        await self._dup(test_client, source.id)
        await self._dup(test_client, source.id)
        await self._dup(test_client, source.id)

        names = {r.name for r in (await async_db.execute(select(AiProvider))).scalars().all()}
        assert names == {"Ollama", "Ollama (copy)", "Ollama (copy 2)", "Ollama (copy 3)"}

    async def test_a_copy_of_a_copy_does_not_stack_suffixes(self, test_client, async_db, base_rows):
        source = await _provider(async_db, name="Ollama")
        await _login(test_client, "admin@ai.example.com")
        await self._dup(test_client, source.id)

        first = (await async_db.execute(select(AiProvider).where(AiProvider.name == "Ollama (copy)"))).scalar_one()
        await self._dup(test_client, first.id)
        names = {r.name for r in (await async_db.execute(select(AiProvider))).scalars().all()}
        assert "Ollama (copy) (copy)" in names, "the stem is the source's own name, whatever it is"

    async def test_a_long_name_still_fits_the_column(self, test_client, async_db, base_rows):
        """`name` is String(80); the suffix has to fit inside it, not overflow it."""
        source = await _provider(async_db, name="x" * 80)
        await _login(test_client, "admin@ai.example.com")
        assert (await self._dup(test_client, source.id)).status_code == 303

        copy = (await async_db.execute(select(AiProvider).where(AiProvider.id != source.id))).scalar_one()
        assert len(copy.name) <= 80
        assert copy.name.endswith("(copy)")

    async def test_only_an_admin_can_duplicate(self, test_client, async_db, base_rows):
        source = await _provider(async_db, name="Ollama")
        await _login(test_client, "other@ai.example.com")
        assert (await self._dup(test_client, source.id)).status_code == 403
        assert len((await async_db.execute(select(AiProvider))).scalars().all()) == 1

    async def test_duplicating_a_missing_provider_is_a_404(self, test_client, base_rows):
        await _login(test_client, "admin@ai.example.com")
        assert (await self._dup(test_client, 4242)).status_code == 404


class TestCopyNameGeneration:
    async def test_it_skips_names_already_taken(self, async_db):
        from app.routers.ai_admin import _copy_name

        async_db.add_all([AiProvider(name=n, kind="openai", base_url="http://h/v1", model="m") for n in ("A", "A (copy)", "A (copy 2)")])
        await async_db.commit()
        assert await _copy_name(async_db, "A") == "A (copy 3)"

    async def test_the_first_copy_has_no_number(self, async_db):
        from app.routers.ai_admin import _copy_name

        assert await _copy_name(async_db, "Fresh") == "Fresh (copy)"
