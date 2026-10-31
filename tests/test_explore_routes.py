"""The Explore routes: who may open them, and what each one answers, over a real store.

The store is built by the real builder from a sample, and one detection is linked to it by
the real overlay, so these exercise the whole read path: access check, store lookup,
compile, engine, template.
"""

from __future__ import annotations

import csv
import io
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/windows/sysmon_process_creation.json"
GEN = "json_evtx-b1-0000abcd"
pytestmark = pytest.mark.anyio


@pytest.fixture()
def events_env(tmp_path, monkeypatch):
    from app import storage as storage_mod
    from app.config import settings
    from app.events import engine as engine_mod

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    for attr, value in (("upload_dir", upload_dir), ("events_enabled", True), ("events_export_rate_limit_per_minute", 0)):
        monkeypatch.setattr(settings, attr, value)
    monkeypatch.setattr(storage_mod, "_storage", None)
    monkeypatch.setattr(engine_mod, "_engine", None)
    queued = []
    import app.workers.tasks as tasks

    monkeypatch.setattr(tasks, "build_event_store", lambda store_id: queued.append(("store", store_id)))
    monkeypatch.setattr(tasks, "build_event_overlay", lambda job_id: queued.append(("overlay", job_id)))
    yield upload_dir, queued
    engine_mod._engine = None


async def _job(async_db, *, submitter=None, private=False, sha=None):
    from app.models import AnalysisJob, JobStatus, LogFile, LogType, WorkflowDef

    tag = uuid.uuid4().hex
    wf = WorkflowDef(name=f"W-{tag}", description="", log_types='["json_evtx"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="s.json", stored_filename=f"{tag}.json", sha256=sha or tag * 2, size_bytes=1, log_type=LogType.JSON_EVTX, detected_type=LogType.JSON_EVTX)
    async_db.add_all([wf, lf])
    await async_db.flush()
    job = AnalysisJob(
        submitted_filename="s.json",
        effective_log_type=LogType.JSON_EVTX,
        file_id=lf.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=submitter,
        is_private=private,
    )
    async_db.add(job)
    await async_db.commit()
    return job, lf


async def _indexed(async_db, upload_dir, **job_kwargs):
    """A job whose upload has a ready store, and an overlay linking one rule to powershell.exe."""
    from app import job_artifacts
    from app.models import EventStore, EventStoreStatus, JobArtifact

    job, lf = await _job(async_db, **job_kwargs)
    store = upload_dir / "events" / lf.sha256 / GEN
    # The sample carries no record ids, which every real EVTX record has and exact linking
    # keys on: number its lines.
    sample = upload_dir / f"sample-{job.id}.json"
    records = [json.loads(line) for line in SAMPLE.read_text().splitlines() if line.strip()]
    for n, record in enumerate(records, start=100):
        record["Event"]["System"]["EventRecordID"] = n
    sample.write_text("\n".join(json.dumps(r) for r in records))
    subprocess.run(
        [sys.executable, "-m", "app.events.build", "--input", str(sample), "--log-type", "json_evtx", "--out", str(store), "--memory-mb", "256"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=120,
    )
    host, channel, rid = (
        duckdb.connect().execute(f"SELECT _lt_host, _lt_channel, _lt_rid FROM read_parquet('{store}/events.parquet') WHERE \"Image\" LIKE '%powershell%'").fetchone()
    )
    rules = [["hayabusa", "rule-1", "Encoded PowerShell", "high"]]
    links = tmp = upload_dir / f"links-{job.id}.json"
    tmp.write_text(json.dumps({"v": 1, "rules": rules, "links": [[0, "w", host, channel, rid]], "unkeyed": 0, "truncated": False}))
    out = upload_dir / f"ov-{job.id}"
    subprocess.run(
        [sys.executable, "-m", "app.events.overlay", "--store", str(store), "--links", str(links), "--out", str(out), "--memory-mb", "256"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=120,
    )
    (out / "proc_forest_full.json").unlink(missing_ok=True)
    (store / "overlays").mkdir(exist_ok=True)
    shutil.move(str(out), str(store / "overlays" / f"job_{job.id}"))
    manifest = json.loads((store / "manifest.json").read_text())
    async_db.add(
        EventStore(
            log_file_id=lf.id,
            log_type="json_evtx",
            builder_version=1,
            status=EventStoreStatus.READY.value,
            gen=GEN,
            event_count=manifest["totals"]["events"],
            attempts=1,
            truncated=False,
        )
    )
    kind, version = job_artifacts.EVENT_OVERLAY
    async_db.add(JobArtifact(job_id=job.id, kind=kind, version=version, payload=job_artifacts.pack({"gen": GEN, "links_sha": "ab12cd34", "rules": rules, "detected_events": 1})))
    await async_db.commit()
    return job


async def _login(client, email):
    client.cookies.clear()
    if email:
        r = await client.post("/auth/cookie/login", data={"username": email, "password": "testpass123"})
        assert r.status_code in (200, 204, 303)


ADMIN, MEMBER, USER = "admin@test.example.com", "member@test.example.com", "user@test.example.com"


@pytest.fixture()
async def people(admin_user, member_user, regular_user):
    return {"admin": admin_user, "member": member_user, "user": regular_user}


async def test_every_refusal_is_the_missing_job_404(test_client, async_db, events_env, people, monkeypatch):
    """Anonymous, a user on someone else's job, a member on a private job, and the switches:
    all answer exactly what a job that does not exist answers."""
    from app.config import settings
    from app.site_settings import get_site_settings

    upload_dir, _ = events_env
    public = await _indexed(async_db, upload_dir)
    own = await _indexed(async_db, upload_dir, submitter=people["user"].id)
    private = await _job(async_db, submitter=people["admin"].id, private=True)

    async def body(email, job_id):
        await _login(test_client, email)
        r = await test_client.get(f"/jobs/{job_id}/explore-partial")
        return r.status_code, r.text

    missing = await body(None, 999_999)
    assert missing[0] == 404
    assert await body(None, public.id) == missing, "anonymous viewers never see the log"
    user_missing = await body(USER, 999_999)
    assert await body(USER, public.id) == user_missing, "a user may explore only their own job"
    assert (await body(USER, own.id))[0] == 200
    member_missing = await body(MEMBER, 999_999)
    assert await body(MEMBER, private[0].id) == member_missing
    assert (await body(MEMBER, public.id))[0] == 200
    assert (await body(ADMIN, private[0].id))[0] == 200
    monkeypatch.setattr(settings, "events_enabled", False)
    assert await body(MEMBER, public.id) == member_missing
    monkeypatch.setattr(settings, "events_enabled", True)
    site = await get_site_settings(async_db)
    site.show_explore = False
    await async_db.commit()
    assert await body(MEMBER, public.id) == member_missing
    for path in ("explore/results", "explore/histogram.json", "explore/field?f=Image", "explore/event?uid=0", "explore/suggest", "explore/export.csv"):
        r = await test_client.get(f"/jobs/{public.id}/{path}")
        assert (r.status_code, r.text) == member_missing, path


async def test_the_pane_and_its_searches(member_client, async_db, events_env):
    upload_dir, _ = events_env
    job = await _indexed(async_db, upload_dir)
    pane = await member_client.get(f"/jobs/{job.id}/explore-partial")
    assert pane.status_code == 200 and 'id="explore-form"' in pane.text and 'hx-trigger="every' not in pane.text
    assert "4</strong> of 4 events" in pane.text
    r = await member_client.get(f"/jobs/{job.id}/explore/results", params={"q": "powershell"})
    assert "1</strong> of 4 events" in r.text and "powershell.exe" in r.text
    assert r.headers["HX-Replace-Url"] == f"/jobs/{job.id}?q=powershell#explore"
    assert json.loads(r.headers["HX-Trigger"]) == {"exploreResults": {"qs": "q=powershell", "q": "powershell"}}
    det = await member_client.get(f"/jobs/{job.id}/explore/results", params={"det": "1"})
    assert "1</strong> of 4 events" in det.text and "Detected: high" in det.text
    bad = await member_client.get(f"/jobs/{job.id}/explore/results", params={"q": "ComandLine:x"})
    assert bad.status_code == 200 and "Did you mean CommandLine" in bad.text
    cell = await member_client.get(f"/jobs/{job.id}/explore/results", params={"q": "", "fcol": "Image", "fval": "cmd"})
    assert "1</strong> of 4 events" in cell.text and json.loads(cell.headers["HX-Trigger"])["exploreResults"]["q"] == "Image:*cmd*"
    page = await member_client.get(f"/jobs/{job.id}/explore/results", params={"page": "99"})
    assert "4</strong> of 4 events" in page.text, "a page past the end lands on the last one"


async def test_fields_drawer_histogram_and_suggestions(member_client, async_db, events_env):
    upload_dir, _ = events_env
    job = await _indexed(async_db, upload_dir)
    facet = await member_client.get(f"/jobs/{job.id}/explore/field", params={"f": "EventID"})
    assert 'data-term="EventID:=1"' in facet.text
    uid = duckdb.connect().execute(f"SELECT _lt_uid FROM read_parquet('{next((upload_dir / 'events').rglob('events.parquet'))}') WHERE \"Image\" LIKE '%powershell%'").fetchone()[0]
    drawer = await member_client.get(f"/jobs/{job.id}/explore/event", params={"uid": uid})
    assert "Encoded PowerShell" in drawer.text and "powershell.exe" in drawer.text and 'id="explore-event-json"' in drawer.text
    assert "Events within 5 minutes on this host" in drawer.text
    hist = (await member_client.get(f"/jobs/{job.id}/explore/histogram.json")).json()
    assert sum(hist["counts"]) == 4 and sum(hist["detected"]) == 1
    sug = (await member_client.get(f"/jobs/{job.id}/explore/suggest", params={"q": "lev", "pos": 3})).json()
    assert "level:" in sug["suggestions"] and sug["start"] == 0
    values = (await member_client.get(f"/jobs/{job.id}/explore/suggest", params={"q": "level:h", "pos": 7})).json()
    assert values["suggestions"] == ["high"]


async def test_exports_are_audited_and_rate_limited(member_client, async_db, events_env, monkeypatch):
    from sqlalchemy import select

    from app.config import settings
    from app.models import ActivityEvent
    from app.site_settings import get_site_settings

    upload_dir, _ = events_env
    job = await _indexed(async_db, upload_dir)
    site = await get_site_settings(async_db)
    site.activity_log_enabled = True
    await async_db.commit()
    r = await member_client.get(f"/jobs/{job.id}/explore/export.csv", params={"q": "EventID:1"})
    assert r.status_code == 200 and r.headers["content-disposition"].endswith(f'job-{job.id}-events.csv"')
    rows = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
    assert rows[0][:2] == ["Time (UTC)", "Host"] and len(rows) == 3
    nd = await member_client.get(f"/jobs/{job.id}/explore/export.ndjson")
    assert len(nd.text.strip().splitlines()) == 4 and all("_lt_uid" in json.loads(line) for line in nd.text.splitlines())
    audited = (await async_db.scalars(select(ActivityEvent).where(ActivityEvent.action == "export.job_events"))).all()
    assert len(audited) == 2 and audited[0].target_id == str(job.id)
    monkeypatch.setattr(settings, "events_export_rate_limit_per_minute", 1)
    await member_client.get(f"/jobs/{job.id}/explore/export.csv")
    assert (await member_client.get(f"/jobs/{job.id}/explore/export.csv")).status_code == 429


async def test_an_unindexed_upload_offers_a_build(member_client, async_db, events_env):
    from sqlalchemy import select

    from app.models import EventStore

    _upload_dir, queued = events_env
    job, lf = await _job(async_db)
    pane = await member_client.get(f"/jobs/{job.id}/explore-partial")
    assert "no event index yet" in pane.text and "Build event index" in pane.text
    built = await member_client.post(f"/jobs/{job.id}/explore/build")
    row = await async_db.scalar(select(EventStore).where(EventStore.log_file_id == lf.id))
    assert row is not None and row.status == "pending" and queued == [("store", row.id)]
    assert 'hx-trigger="every 5s"' in built.text, "a queued build polls until the index is ready"


async def test_the_job_page_tab(test_client, async_db, events_env, people):
    upload_dir, _ = events_env
    job = await _indexed(async_db, upload_dir)
    await _login(test_client, MEMBER)
    page = await test_client.get(f"/jobs/{job.id}?q=powershell&det=1&unrelated=x")
    assert '"key": "explore"' in page.text and '"badge": "4"' in page.text
    assert f'hx-get="/jobs/{job.id}/explore-partial?q=powershell&amp;det=1"' in page.text, "the link's Explore state reaches the pane, nothing else"
    await _login(test_client, None)
    anonymous = await test_client.get(f"/jobs/{job.id}")
    assert anonymous.status_code == 200 and "explore-region" not in anonymous.text


def test_filter_row_cells_on_fixed_columns_use_the_shortcuts():
    from app.routers.explore import filter_term

    assert filter_term("_lt_eid", ">=4600") == "eid:>=4600"
    assert filter_term("_lt_host", "ws1") == "host:*ws1*"
    assert filter_term("_lt_time", ">=2026-01-01T10:00") == "after:2026-01-01T10:00"
    assert filter_term("_lt_time", "<2026-01-02") == "before:2026-01-02"
    assert filter_term("_lt_time", "monday") == "" and filter_term("_lt_rid", "5") == ""
    assert filter_term("Image", "cmd") == "Image:*cmd*"
