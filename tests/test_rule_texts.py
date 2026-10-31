"""`app/rule_texts.py`: one row per distinct rule text, however many findings cite it."""

from __future__ import annotations

from sqlalchemy import func, select


def test_a_batch_stores_each_distinct_text_once(sync_db):
    from app.models import RuleText
    from app.rule_texts import rule_text_ids_sync, rule_text_sha

    a, b = "title: A\n" * 50, "title: B\n" * 50
    ids = rule_text_ids_sync(sync_db, [a, b, a, None, ""])
    sync_db.commit()
    assert set(ids) == {rule_text_sha(a), rule_text_sha(b)}
    assert sync_db.scalar(select(func.count()).select_from(RuleText)) == 2


def test_a_later_batch_reuses_existing_rows(sync_db):
    from app.models import RuleText
    from app.rule_texts import rule_text_id_sync, rule_text_ids_sync, rule_text_sha

    a = "title: A\n" * 50
    first = rule_text_id_sync(sync_db, a)
    sync_db.commit()
    again = rule_text_ids_sync(sync_db, [a, "title: C\n"])
    sync_db.commit()
    assert again[rule_text_sha(a)] == first
    assert sync_db.scalar(select(func.count()).select_from(RuleText)) == 2


def test_the_text_is_compressed_at_rest_and_read_back_whole(sync_db):
    from sqlalchemy import text

    from app.db_types import PREFIX
    from app.models import RuleText
    from app.rule_texts import rule_text_id_sync

    content = "title: Suspicious PowerShell\nauthor: someone\ndetection:\n  selection:\n    CommandLine|contains: -enc\n" * 20
    rid = rule_text_id_sync(sync_db, content)
    sync_db.commit()
    assert sync_db.execute(text("SELECT content FROM rule_text WHERE id = :id"), {"id": rid}).scalar().startswith(PREFIX)
    assert sync_db.get(RuleText, rid).content == content


def test_a_finding_reads_its_rule_through_the_subquery(sync_db):
    from sqlalchemy.orm import undefer

    from app.models import AnalysisJob, Finding, JobStatus, LogFile, LogType, TaskResult, TaskStatus, WorkflowDef
    from app.rule_texts import rule_text_id_sync

    wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
    lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    sync_db.add_all([wf, lf])
    sync_db.flush()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    sync_db.add(job)
    sync_db.flush()
    tr = TaskResult(job_id=job.id, tool_name="chainsaw", status=TaskStatus.COMPLETED)
    sync_db.add(tr)
    sync_db.flush()
    content = "title: X\nauthor: me\n" * 40
    sync_db.add(Finding(task_result_id=tr.id, rule_name="x", severity="high", count=1, rule_text_id=rule_text_id_sync(sync_db, content)))
    sync_db.commit()
    sync_db.expunge_all()
    finding = sync_db.scalars(select(Finding).options(undefer(Finding.rule_content))).one()
    assert finding.rule_content == content
