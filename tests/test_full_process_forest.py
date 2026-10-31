"""The process forest from every process creation in the upload, detections marked.

Hit-anchored forests (from rule matches) are unchanged; the parity suite pins them. These
cover the store-built forest: its nodes carry the store row's uid, a detected node is `hit`
with its level in `det`, and an undetected one is `context`, not `inferred`.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from app.intel.lineage import build_process_forest, mark_detections, select_detection_first

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]


def _row(uid, pid, ppid, image, *, guid=None, pguid=None, time="2026-01-01T00:00:00"):
    return {
        "_lt_uid": uid,
        "EventID": 1,
        "Computer": "WIN-1",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "SystemTime": time,
        "ProcessId": str(pid),
        "ParentProcessId": str(ppid),
        "Image": image,
        "ProcessGuid": guid or f"{{g{pid}}}",
        "ParentProcessGuid": pguid or f"{{g{ppid}}}",
    }


def test_store_rows_carry_their_uid_and_detections_are_marked():
    rows = [
        _row(0, 10, 1, r"C:\Windows\explorer.exe"),
        _row(1, 20, 10, r"C:\Windows\System32\cmd.exe", time="2026-01-01T00:00:01"),
        _row(2, 30, 20, r"C:\Windows\System32\whoami.exe", time="2026-01-01T00:00:02"),
    ]
    forest = mark_detections(build_process_forest(rows), {2: 3})
    nodes = {}
    stack = list(forest["roots"])
    while stack:
        n = stack.pop()
        nodes[n["image"]] = n
        stack.extend(n["children"])
    assert nodes["whoami.exe"]["hit"] is True and nodes["whoami.exe"]["det"] == 3
    assert nodes["cmd.exe"]["hit"] is False and nodes["cmd.exe"]["uid"] == 1, "context: real, undetected"
    assert forest["stats"]["detected"] == 1 and forest["stats"]["source"] == "events"


def test_tool_events_carry_no_uid():
    """The hit-anchored forest's shape is pinned by the parity suite; it must not gain a key."""
    event = {k: v for k, v in _row(0, 10, 1, r"C:\x.exe").items() if k != "_lt_uid"}
    (root,) = build_process_forest([event])["roots"]
    assert "uid" not in root


def test_the_display_cap_keeps_every_detection_and_its_ancestry():
    rows = [_row(0, 10, 1, r"C:\a.exe")] + [_row(i, 100 + i, 10, rf"C:\noise{i}.exe", time=f"2026-01-01T00:00:{i:02d}") for i in range(1, 40)]
    rows.append(_row(99, 500, 139, r"C:\evil.exe", time="2026-01-01T00:01:00"))  # child of noise39
    forest = mark_detections(build_process_forest(rows), {99: 4})
    view = select_detection_first(forest, max_nodes=5)
    kept = []
    stack = list(view["roots"])
    while stack:
        n = stack.pop()
        kept.append(n["image"])
        stack.extend(n["children"])
    assert {"evil.exe", "noise39.exe", "a.exe"} <= set(kept), "the detection and the chain that explains it"
    assert view["stats"]["shown"] == 5 and view["stats"]["total_processes"] == len(rows) and view["stats"]["truncated"]


def test_the_overlay_builds_the_full_forest_from_the_store(tmp_path):
    store = tmp_path / "store"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "app.events.build",
            "--input",
            str(ROOT / "samples/windows/sysmon_process_creation.json"),
            "--log-type",
            "json_evtx",
            "--out",
            str(store),
            "--memory-mb",
            "256",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=120,
    )
    (tmp_path / "links.json").write_text(json.dumps({"rules": [], "links": [], "unkeyed": 0, "truncated": False}))
    subprocess.run(
        [sys.executable, "-m", "app.events.overlay", "--store", str(store), "--links", str(tmp_path / "links.json"), "--out", str(tmp_path / "out"), "--memory-mb", "256"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=120,
    )
    forest = json.loads((tmp_path / "out" / "proc_forest_full.json").read_text())
    assert forest["stats"]["source"] == "events" and forest["stats"]["hits"] == 2 and forest["stats"]["detected"] == 0


async def _job_with_both_forests(async_db, **job_fields):
    from app import job_artifacts
    from app.models import AnalysisJob, JobArtifact, JobStatus, LogFile, LogType, WorkflowDef

    tag = uuid.uuid4().hex
    wf = WorkflowDef(name=f"W-{tag}", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="a.evtx", stored_filename=f"{tag}.evtx", sha256=tag * 2, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([wf, lf])
    await async_db.flush()
    job = AnalysisJob(submitted_filename="a.evtx", effective_log_type=LogType.EVTX, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, **job_fields)
    async_db.add(job)
    await async_db.flush()
    anchored = build_process_forest([{k: v for k, v in _row(0, 10, 1, r"C:\anchored_only.exe").items() if k != "_lt_uid"}])
    full = mark_detections(build_process_forest([_row(0, 10, 1, r"C:\whole_upload.exe")]), {})
    kind, version = job_artifacts.PROC_FOREST
    full_kind, full_version = job_artifacts.PROC_FOREST_FULL
    async_db.add_all(
        [
            JobArtifact(job_id=job.id, kind=kind, version=version, payload=job_artifacts.pack(anchored)),
            JobArtifact(job_id=job.id, kind=full_kind, version=full_version, payload=job_artifacts.pack(full)),
        ]
    )
    await async_db.commit()
    return job


async def test_the_job_tree_is_full_for_an_explorer_and_hit_anchored_otherwise(admin_client, async_db):
    job = await _job_with_both_forests(async_db)
    admin = (await admin_client.get(f"/jobs/{job.id}/process-tree")).text
    admin_client.cookies.clear()  # the fixtures share one client: drop the admin session
    anonymous = (await admin_client.get(f"/jobs/{job.id}/process-tree")).text
    assert "whole_upload.exe" in admin and ">context<" in admin
    assert "anchored_only.exe" in anonymous and "whole_upload.exe" not in anonymous, "an anonymous viewer never sees processes no rule matched"


async def test_a_signed_in_user_gets_the_full_tree_only_for_their_own_job(user_client, regular_user, async_db):
    mine = await _job_with_both_forests(async_db, submitted_by_user_id=regular_user.id)
    theirs = await _job_with_both_forests(async_db)
    assert "whole_upload.exe" in (await user_client.get(f"/jobs/{mine.id}/process-tree")).text
    other = (await user_client.get(f"/jobs/{theirs.id}/process-tree")).text
    assert "anchored_only.exe" in other and "whole_upload.exe" not in other


def test_can_explore_job_truth_table():
    from types import SimpleNamespace as NS

    from app.models import can_explore_job

    def user(uid, role="user", *, superuser=False, active=True):
        return NS(id=uid, role=role, is_superuser=superuser, is_active=active)

    public = NS(is_private=False, submitted_by_user_id=1)
    private = NS(is_private=True, submitted_by_user_id=1)
    anonymous_job = NS(is_private=False, submitted_by_user_id=None)
    admin, member, owner, stranger = user(9, "admin", superuser=True), user(8, "member"), user(1), user(2)
    cases = [
        (public, None, False),  # anonymous viewers see findings, never the log
        (public, stranger, False),
        (public, owner, True),
        (public, member, True),
        (private, member, False),  # can_view_job comes first
        (private, owner, True),
        (private, admin, True),
        (anonymous_job, stranger, False),  # None == None must not make everyone the submitter
        (public, user(1, active=False), False),
        (public, user(8, "member", active=False), False),
    ]
    for job, who, expected in cases:
        assert can_explore_job(job, who) is expected, (job, who)
