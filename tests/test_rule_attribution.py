"""A finding names its rule's author: Detection Rule License 1.1 asks it of match output."""

from __future__ import annotations

import pytest

from app.rule_attribution import _zircolite_authors, authors_from_rule_text, rule_author

HAYABUSA_RULE = """title: Suspicious Encoded PowerShell
author: Zach Mathis
level: medium
"""
#: A rule id from the vendored Zircolite Windows ruleset, and the author recorded there.
ZIRCOLITE_ID = "438025f9-5856-4663-83f7-52f878a70a50"


def test_the_author_line_of_a_rule_is_read():
    assert authors_from_rule_text(HAYABUSA_RULE) == "Zach Mathis"
    assert authors_from_rule_text("title: t\nauthor: 'Florian Roth (Nextron Systems)'\n") == "Florian Roth (Nextron Systems)"


def test_every_distinct_author_of_a_multi_rule_finding_is_kept():
    text = "author: A\n---\nauthor: B\n---\nauthor: A\n"
    assert authors_from_rule_text(text) == "A; B"


def test_a_mention_inside_a_field_is_not_the_field():
    assert authors_from_rule_text("description: the author: field is missing here\nlevel: low\n") == ""
    assert authors_from_rule_text(None) == ""


def test_zircolite_findings_take_their_author_from_the_ruleset():
    """Zircolite stores the compiled SQL, which carries no author."""
    assert ZIRCOLITE_ID in _zircolite_authors()
    author = rule_author("zircolite", ZIRCOLITE_ID, "SELECT * FROM logs WHERE EventID=1")
    assert author and author == _zircolite_authors()[ZIRCOLITE_ID]
    assert rule_author("chainsaw", ZIRCOLITE_ID, "SELECT 1") == "", "the lookup is Zircolite's ruleset, not a guess for any tool"


async def _seed(async_db, tool: str, rule_id: str, rule_content: str):
    from app.models import AnalysisJob, Finding, JobStatus, LogFile, Severity, TaskResult, TaskStatus, WorkflowDef

    lf = LogFile(original_filename="sec.evtx", stored_filename="s.evtx", sha256="d" * 64, size_bytes=1)
    wf = WorkflowDef(name="wf")
    async_db.add_all([lf, wf])
    await async_db.commit()
    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(job)
    await async_db.commit()
    tr = TaskResult(job_id=job.id, tool_name=tool, status=TaskStatus.COMPLETED, findings_count=1)
    async_db.add(tr)
    await async_db.commit()
    finding = Finding(task_result_id=tr.id, rule_id=rule_id, rule_name="r", severity=Severity.HIGH, count=1, rule_content=rule_content)
    async_db.add(finding)
    await async_db.commit()
    return job, finding


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "rule_id", "content"),
    [("hayabusa", "h-1", HAYABUSA_RULE), ("zircolite", ZIRCOLITE_ID, "SELECT * FROM logs")],
)
async def test_the_rule_panel_and_the_export_both_name_the_author(test_client, async_db, tool, rule_id, content):
    job, finding = await _seed(async_db, tool, rule_id, content)
    expected = rule_author(tool, rule_id, content)
    assert expected

    panel = await test_client.get(f"/jobs/findings/{finding.id}/rule")
    assert panel.status_code == 200
    assert "Rule author:" in panel.text

    export = await test_client.get(f"/jobs/{job.id}/findings.json")
    assert export.status_code == 200
    assert [row["rule_author"] for row in export.json()] == [expected]
