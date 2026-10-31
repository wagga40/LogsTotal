"""JobArtifact: the timeline buckets and the process forest, stored once by the analytics pass.

Both were caches over the raw tool outputs, rebuilt on every miss (one development job: 2.5 s
plus 0.9 s and about 1 GB of RSS) and lost with the outputs at JOB_OUTPUT_RETENTION_DAYS.
"""

from __future__ import annotations

import json

import pytest

from app import job_artifacts

pytestmark = pytest.mark.anyio


def _sysmon(pid, ppid, image, *, guid=None, parent_guid=None, ts="2026-01-01T00:00:00Z"):
    return {
        "Event": {
            "System": {"EventID": 1, "Computer": "WIN-1", "Channel": "Microsoft-Windows-Sysmon/Operational", "TimeCreated_attributes": {"SystemTime": ts}},
            "EventData": {
                "ProcessId": str(pid),
                "ParentProcessId": str(ppid),
                "Image": image,
                "CommandLine": image,
                "ProcessGuid": guid or f"{{{pid}}}",
                "ParentProcessGuid": parent_guid or f"{{{ppid}}}",
            },
        },
        "timestamp": ts,
    }


def _job(sync_db):
    from app.models import AnalysisJob, JobStatus, LogFile, LogType, WorkflowDef

    wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    sync_db.add_all([wf, lf])
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    sync_db.add(job)
    sync_db.commit()
    return job


def test_pack_round_trips_and_put_replaces(sync_db):
    job = _job(sync_db)
    job_artifacts.put_sync(sync_db, job.id, job_artifacts.TL_BUCKETS, {"2026-01-01T00": {"execution": 2}})
    job_artifacts.put_sync(sync_db, job.id, job_artifacts.TL_BUCKETS, {"2026-01-01T01": {"discovery": 1}})
    sync_db.commit()
    assert job_artifacts.get_sync(sync_db, job.id, job_artifacts.TL_BUCKETS) == {"2026-01-01T01": {"discovery": 1}}


def test_a_row_of_another_version_reads_as_absent(sync_db):
    """A shape change bumps the version; old rows then fall back until recalculated."""
    job = _job(sync_db)
    kind, version = job_artifacts.PROC_FOREST
    job_artifacts.put_sync(sync_db, job.id, (kind, version - 1), {"roots": []})
    sync_db.commit()
    assert job_artifacts.get_sync(sync_db, job.id, job_artifacts.PROC_FOREST) is None


def test_the_analytics_pass_stores_both_artifacts(sync_db, tmp_path):
    """Through _cache_analytics, the one writer all three analytics paths share."""
    from app.analytics import _compute_analytics_data
    from app.workers.tasks import _cache_analytics

    job = _job(sync_db)
    events = [_sysmon(200, 100, r"C:\Windows\System32\cmd.exe"), _sysmon(300, 200, r"C:\Windows\System32\whoami.exe")]
    task = tmp_path / f"job_{job.id}" / "task_1"
    task.mkdir(parents=True)
    # Zircolite's flattened shape, which lineage reads (Chainsaw's wrapped document is not
    # unwrapped by lineage today, so it contributes no process nodes on either path).
    flat = [{"EventID": 1, "Computer": "WIN-1", "Channel": "Microsoft-Windows-Sysmon/Operational", "SystemTime": e["timestamp"], **e["Event"]["EventData"]} for e in events]
    (task / "x_zircolite.json").write_text(json.dumps([{"title": "r", "id": "r1", "rule_level": "high", "tags": [], "count": len(flat), "matches": flat}]))
    data = _compute_analytics_data(job, job_dir=tmp_path / f"job_{job.id}")
    assert _cache_analytics(job, data, job_dir=tmp_path / f"job_{job.id}")
    sync_db.commit()
    forest = job_artifacts.get_sync(sync_db, job.id, job_artifacts.PROC_FOREST)
    assert forest == json.loads(json.dumps(data["process_forest"]))
    assert forest["stats"]["hits"] == 2
    assert job_artifacts.get_sync(sync_db, job.id, job_artifacts.TL_BUCKETS) == data["timeline_buckets"]
    assert "process_forest" not in json.loads(job.analytics_json), "artifacts never ride in analytics_json"


def test_the_forest_is_served_from_the_artifact_without_the_raw_outputs(monkeypatch):
    """After output retention the outputs are gone; the stored forest still renders."""
    from app.intel import process_tree
    from app.intel.lineage import build_process_forest

    forest = build_process_forest([_sysmon(200, 100, r"C:\Windows\System32\cmd.exe")])

    def no_outputs(*a, **k):
        raise AssertionError("the raw outputs must not be read when an artifact exists")

    monkeypatch.setattr(process_tree, "job_outputs_dir", no_outputs)
    assert process_tree.build_job_forest_sync(5, artifact=job_artifacts.pack(forest)) == json.loads(json.dumps(forest))


def test_output_files_merge_in_path_order_whatever_finishes_first(tmp_path, monkeypatch):
    """Completion order made a multi-tool job's event order, and so the process tree's
    tie-breaking, differ between runs. Merged by path, it cannot."""
    import time

    from app.intel import event_timeline

    for name, pid, delay in (("a_chainsaw.json", 1, 0.05), ("b_rsigma.json", 2, 0.0)):
        (tmp_path / name).write_text(json.dumps({"pid": pid, "delay": delay}))

    real = event_timeline.parse_single_output_file

    def slow_first(path, *a, **kw):
        payload = json.loads(path.read_text())
        time.sleep(payload["delay"])  # the first file finishes last
        return {}, [{"from": path.name}]

    monkeypatch.setattr(event_timeline, "parse_single_output_file", slow_first)
    _, events = event_timeline.extract_all_from_raw_output(1, job_dir=tmp_path)
    assert [e["from"] for e in events] == ["a_chainsaw.json", "b_rsigma.json"]
    monkeypatch.setattr(event_timeline, "parse_single_output_file", real)


async def test_deleting_a_job_removes_its_artifacts(admin_client, async_db):
    from sqlalchemy import func, select

    from app.models import AnalysisJob, JobArtifact, JobStatus, LogFile, LogType, WorkflowDef

    wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="b" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([wf, lf])
    await async_db.flush()
    job = AnalysisJob(submitted_filename="a.evtx", effective_log_type=LogType.EVTX, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.flush()
    async_db.add(JobArtifact(job_id=job.id, kind="tl_buckets", version=1, payload=job_artifacts.pack({})))
    await async_db.commit()
    resp = await admin_client.post(f"/jobs/{job.id}/delete", follow_redirects=False)
    assert resp.status_code in (200, 303)
    assert await async_db.scalar(select(func.count()).select_from(JobArtifact)) == 0
