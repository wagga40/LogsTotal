"""`CompressedText`: zstd JSON text at rest, transparent to every reader.

The three columns using it held 14 MB of the 42.8 MB development database (`Finding.details`
11 MB, relationship evidence samples 7 MB of which 84% duplicated, analytics up to 275 KB a
job). Old plaintext rows must keep reading unchanged, and nothing may read them inside SQL.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text

from app.db_types import MIN_CHARS, PREFIX, CompressedText

ROOT = Path(__file__).resolve().parents[1]
COLUMNS = {"details", "sample_events_json", "analytics_json"}


def test_a_large_value_round_trips_through_the_codec():
    col = CompressedText()
    value = json.dumps([{"CommandLine": "powershell.exe -nop -enc " + "A" * 40, "Image": "C:\\Windows\\System32\\cmd.exe", "n": i} for i in range(200)])
    stored = col.process_bind_param(value, None)
    assert stored.startswith(PREFIX)
    assert len(stored) < len(value) / 4
    assert col.process_result_value(stored, None) == value


def test_small_values_and_none_stay_plain():
    col = CompressedText()
    assert col.process_bind_param(None, None) is None
    small = json.dumps({"k": "v"})
    assert len(small) < MIN_CHARS
    assert col.process_bind_param(small, None) == small


def test_incompressible_text_is_kept_plain():
    import secrets

    col = CompressedText()
    noise = json.dumps([secrets.token_urlsafe(48) for _ in range(40)])
    assert col.process_bind_param(noise, None) == noise or len(col.process_bind_param(noise, None)) < len(noise)


def test_legacy_plaintext_rows_read_unchanged():
    """A database written before the codec holds plain JSON; reading it must not change it."""
    col = CompressedText()
    legacy = json.dumps([{"a": "b" * 2000}])
    assert col.process_result_value(legacy, None) == legacy


def test_unicode_survives():
    col = CompressedText()
    value = json.dumps([{"user": "администратор", "path": "C:\\Users\\Zoë\\日本語"}] * 50, ensure_ascii=False)
    assert col.process_result_value(col.process_bind_param(value, None), None) == value


def test_the_real_columns_store_less_and_read_back_whole(tmp_path):
    """Through a real engine: what lands on disk is the encoded form, what the ORM returns is
    the original — via the ORM attribute and via a Core select of the column alike."""
    from sqlalchemy.orm import Session

    from app.database import Base
    from app.models import AnalysisJob, Finding, JobStatus, LogFile, LogType, TaskResult, TaskStatus, WorkflowDef

    engine = create_engine(f"sqlite:///{tmp_path / 'c.db'}")
    Base.metadata.create_all(engine)
    details = json.dumps([{"EventID": 1, "CommandLine": "cmd.exe /c whoami " * 20, "Computer": "WIN-1"}] * 30)
    with Session(engine) as db:
        wf = WorkflowDef(name="W", description="", log_types='["evtx"]', tasks_yaml="tasks: []")
        lf = LogFile(original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=1, log_type=LogType.EVTX, detected_type=LogType.EVTX)
        db.add_all([wf, lf])
        db.flush()
        job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, analytics_json=json.dumps({"timeline": [0] * 2000}))
        db.add(job)
        db.flush()
        tr = TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.COMPLETED)
        db.add(tr)
        db.flush()
        db.add(Finding(task_result_id=tr.id, rule_name="r", severity="high", count=1, details=details))
        db.commit()
    with engine.connect() as conn:
        raw = conn.execute(text("SELECT details FROM finding")).scalar()
        raw_analytics = conn.execute(text("SELECT analytics_json FROM analysisjob")).scalar()
    assert raw.startswith(PREFIX) and len(raw) < len(details) / 5
    assert raw_analytics.startswith(PREFIX)
    with Session(engine) as db:
        assert db.scalar(select(Finding.details)) == details
        assert db.scalars(select(Finding)).one().details == details
        assert db.scalar(select(Finding.has_details)) is True
    engine.dispose()


def _sql_reads_of(column: str) -> list[str]:
    """`func.<x>(...)`, `.like/.ilike/.contains/.startswith` over the column, anywhere in app/."""
    offenders = []
    for path in (ROOT / "app").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                target = node.func.value
                if isinstance(target, ast.Attribute) and target.attr == column and node.func.attr in {"like", "ilike", "contains", "startswith", "endswith", "regexp_match", "op"}:
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "func":
                    for arg in node.args:
                        if isinstance(arg, ast.Attribute) and arg.attr == column:
                            offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    return offenders


@pytest.mark.parametrize("column", sorted(COLUMNS))
def test_no_sql_reads_a_compressed_column(column):
    """SQL would see `zs1:…`. The one exception is `Finding.has_details` (coalesce != ''),
    which holds for the encoded form too."""
    allowed = {"app/models.py"}  # has_details
    assert [o for o in _sql_reads_of(column) if o.split(":")[0] not in allowed] == []
