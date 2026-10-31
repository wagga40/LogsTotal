"""Detections joined onto the event store: exact keys link, hints link only when unique.

Measured on job 12 (four tools, 213 MB EVTX): every one of 232,529 links joined to exactly one
stored event, 180,778 detected events, in 0.51 s and 343 MB.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _build(tmp_path: Path, source: Path, kind: str) -> Path:
    out = tmp_path / f"store-{kind}"
    subprocess.run(
        [sys.executable, "-m", "app.events.build", "--input", str(source), "--log-type", kind, "--out", str(out), "--reference", "2026-03-01", "--memory-mb", "256"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=120,
    )
    return out


def _overlay(tmp_path: Path, store: Path, links: dict) -> tuple[Path, dict]:
    (tmp_path / "links.json").write_text(json.dumps(links))
    out = tmp_path / "overlay"
    result = subprocess.run(
        [sys.executable, "-m", "app.events.overlay", "--store", str(store), "--links", str(tmp_path / "links.json"), "--out", str(out), "--memory-mb", "256"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return out, json.loads((out / "overlay.json").read_text())


def test_exact_windows_keys_link_and_a_missing_event_does_not(tmp_path):
    store = _build(tmp_path, ROOT / "samples/windows/security_events.xml", "xml")
    con = duckdb.connect()
    host, channel, rid, uid = con.execute(f"SELECT _lt_host, _lt_channel, _lt_rid, _lt_uid FROM read_parquet('{store / 'events.parquet'}') ORDER BY _lt_uid LIMIT 1").fetchone()
    links = {
        "rules": [["zircolite", "r1", "Rule One", "high"], ["hayabusa", "r2", "Rule Two", "critical"]],
        "links": [[0, "w", host, channel, rid], [1, "w", host, channel, rid], [0, "w", "nowhere", channel, 1]],
        "unkeyed": 0,
        "truncated": False,
    }
    out, meta = _overlay(tmp_path, store, links)
    assert meta["detected_events"] == 1
    assert meta["per_tool"]["zircolite"] == {"links": 2, "linked": 1, "ambiguous": 0}
    hits = con.execute(f"SELECT _lt_uid, rule_ix FROM read_parquet('{out / 'hits.parquet'}') ORDER BY rule_ix").fetchall()
    assert hits == [(uid, 0), (uid, 1)]
    level = con.execute(f"SELECT level_rank, n_rules, tools_mask FROM read_parquet('{out / 'levels.parquet'}')").fetchone()
    assert level[0] == 4 and level[1] == 2 and level[2] == 3, "highest severity, both rules, both tools"


def test_an_ambiguous_hint_is_counted_never_guessed(tmp_path):
    """Two identical syslog lines in the same second: a message hash cannot tell them apart."""
    log = tmp_path / "s.log"
    log.write_text(
        "Feb 14 08:59:41 web01 sshd[1]: Failed password for root\nFeb 14 08:59:41 web01 sshd[1]: Failed password for root\nFeb 14 08:59:42 web01 sshd[1]: Accepted password for root\n"
    )
    store = _build(tmp_path, log, "syslog")
    con = duckdb.connect()
    rows = con.execute(f"SELECT epoch(_lt_time)::BIGINT, message_sha FROM read_parquet('{store / 'events.parquet'}') ORDER BY _lt_uid").fetchall()
    links = {
        "rules": [["chopchopgo", "r1", "SSH", "medium"]],
        "links": [[0, "h", rows[0][0], None, None, None, rows[0][1]], [0, "h", rows[2][0], None, None, None, rows[2][1]]],
        "unkeyed": 0,
        "truncated": False,
    }
    _, meta = _overlay(tmp_path, store, links)
    assert meta["per_tool"]["chopchopgo"] == {"links": 2, "linked": 1, "ambiguous": 1}
    assert meta["detected_events"] == 1


@pytest.fixture()
def ready_store(sync_db, tmp_path, monkeypatch):
    """A built, published store for one auditd upload, and a job on it with links."""
    import shutil

    from app import job_artifacts
    from app import storage as storage_mod
    from app.config import settings
    from app.events.store import request_build_sync, run_build
    from app.models import AnalysisJob, JobStatus, LogFile, LogType, WorkflowDef

    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    for attr, value in (("upload_dir", upload_dir), ("events_enabled", True), ("events_min_free_disk_mb", 0), ("events_build_memory_mb", 256)):
        monkeypatch.setattr(settings, attr, value)
    monkeypatch.setattr(storage_mod, "_storage", None)
    shutil.copy(ROOT / "samples/linux/auditd_sample.log", upload_dir / "a.log")
    wf = WorkflowDef(name="W", description="", log_types='["auditd"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="a.log", stored_filename="a.log", sha256="9" * 64, size_bytes=1, log_type=LogType.AUDITD, detected_type=LogType.AUDITD)
    sync_db.add_all([wf, lf])
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, effective_log_type=LogType.AUDITD)
    sync_db.add(job)
    sync_db.commit()
    sid = request_build_sync(sync_db, log_file_id=lf.id, log_type="auditd", job_id=job.id)
    sync_db.commit()
    run_build(sync_db, sid)
    con = duckdb.connect()
    store_dir = next((upload_dir / "events" / lf.sha256).iterdir())
    epoch, seq = con.execute(f"SELECT epoch(_lt_time)::BIGINT, _lt_seq FROM read_parquet('{store_dir / 'events.parquet'}') ORDER BY _lt_uid LIMIT 1").fetchone()
    job_artifacts.put_sync(
        sync_db,
        job.id,
        job_artifacts.EVENT_LINKS,
        {"v": 1, "rules": [["zircolite", "r", "Audit rule", "high"]], "links": [[0, "h", epoch, None, seq, None, None]], "unkeyed": 0, "truncated": False},
    )
    sync_db.commit()
    return job, store_dir


def test_run_overlay_publishes_beside_the_store_and_is_idempotent(sync_db, ready_store):
    from app import job_artifacts
    from app.events.store import run_overlay

    job, store_dir = ready_store
    outcome = run_overlay(sync_db, job.id)
    assert outcome.startswith("1 detected events"), outcome
    overlay = store_dir / "overlays" / f"job_{job.id}"
    assert {p.name for p in overlay.iterdir()} == {"hits.parquet", "levels.parquet", "overlay.json"}
    meta = job_artifacts.get_sync(sync_db, job.id, job_artifacts.EVENT_OVERLAY)
    assert meta["gen"] == store_dir.name and meta["detected_events"] == 1
    # The full process forest is per-job data: stored as an artifact, never beside the store.
    full = job_artifacts.get_sync(sync_db, job.id, job_artifacts.PROC_FOREST_FULL)
    assert full["stats"]["source"] == "events" and full["stats"]["processes"] >= 1, full["stats"]
    assert run_overlay(sync_db, job.id) == "up to date"


def test_without_a_ready_store_the_overlay_waits(sync_db, ready_store):
    from app.events.store import run_overlay
    from app.models import EventStore

    job, _ = ready_store
    sync_db.query(EventStore).update({"status": "building"})
    sync_db.commit()
    assert run_overlay(sync_db, job.id) == "no ready store yet"
