"""Tests for scripts/recommend_scaling.py — sizing model and .env writing."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "recommend_scaling.py"


@pytest.fixture()
def scaling():
    spec = importlib.util.spec_from_file_location("recommend_scaling", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("cores", "ram", "workers", "threads", "tool_max_workers"),
    [
        # Pins the README "Recommended defaults by host size" table.
        # tool_max_workers assumes the shipped largest workflow (windows_full.yml = 3 tools),
        # capped so a parallel job's peak (tool_max_workers x threads) stays within cores.
        (2, 2.0, 1, 1, 2),
        (4, 8.0, 2, 2, 2),
        (8, 16.0, 4, 2, 3),
        (16, 32.0, 8, 2, 3),
        (32, 64.0, 16, 2, 3),
    ],
)
def test_recommend_matches_readme_table(scaling, cores, ram, workers, threads, tool_max_workers):
    rec = scaling.recommend(cores, ram, max_tool_count=3)
    assert rec["huey_workers"] == workers
    assert rec["threads_per_tool"] == threads
    assert rec["peak_cpu"] == workers * threads
    assert rec["tool_max_workers"] == tool_max_workers


def test_recommend_tool_max_workers_fallback(scaling):
    # No detectable tool count → fallback of 2, still capped by the CPU bound.
    assert scaling.recommend(8, 16.0)["tool_max_workers"] == 2  # min(2, 8//2=4)
    assert scaling.recommend(2, 2.0)["tool_max_workers"] == 2  # min(2, 2//1=2)
    assert scaling.recommend(1, 1.0)["tool_max_workers"] == 1  # min(2, 1//1=1)


def test_recommend_ram_bound(scaling):
    rec = scaling.recommend(16, 3.0)  # plenty of cores, tiny RAM
    assert rec["ram_bound"] is True
    assert rec["huey_workers"] == 2  # 3.0 // 1.5


def test_detect_workflow_threads_none_when_unset(scaling, tmp_path):
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir()
    (wf_dir / "a.yml").write_text("tasks:\n  - tool: zircolite\n    timeout: 300\n", encoding="utf-8")
    assert scaling.detect_workflow_threads(tmp_path) is None


def test_detect_workflow_threads_max(scaling, tmp_path):
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir()
    (wf_dir / "a.yml").write_text("tasks:\n  - tool: hayabusa\n    threads: 2\n  - tool: chainsaw\n    threads: 4\n", encoding="utf-8")
    assert scaling.detect_workflow_threads(tmp_path) == 4


def test_detect_max_tool_count(scaling, tmp_path):
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir()
    (wf_dir / "one.yml").write_text("tasks:\n  - tool: zircolite\n    timeout: 300\n", encoding="utf-8")
    (wf_dir / "three.yml").write_text(
        "tasks:\n  - tool: hayabusa\n    threads: 2\n  - tool: chainsaw\n    threads: 2\n  - tool: zircolite\n    timeout: 300\n",
        encoding="utf-8",
    )
    assert scaling.detect_max_tool_count(tmp_path) == 3


def test_detect_max_tool_count_fallback_none(scaling, tmp_path):
    assert scaling.detect_max_tool_count(tmp_path) is None  # no workflows dir at all
    (tmp_path / "workflows").mkdir()
    assert scaling.detect_max_tool_count(tmp_path) is None  # empty dir


def test_apply_workflows_preserves_bytes(scaling, tmp_path):
    wf_dir = tmp_path / "workflows"
    wf_dir.mkdir()
    original = (
        "name: Test\n"
        "tasks:\n"
        "  - tool: hayabusa\n"
        "    rules_path: tools/hayabusa/rules/\n"
        "    timeout: 300\n"
        "    threads: 1\n"
        "  - tool: chainsaw\n"
        "    rules_path: tools/chainsaw/sigma/\n"
        "    timeout: 300\n"
        "  - tool: zircolite\n"
        "    rules_path: tools/zircolite/rules.json\n"
        "    timeout: 300\n"
    )
    wf = wf_dir / "w.yml"
    wf.write_text(original, encoding="utf-8")

    rec = scaling.recommend(8, 16.0)  # threads_per_tool == 2
    assert scaling.apply_to_workflows(rec, project_root=tmp_path) == 0
    result = wf.read_text(encoding="utf-8")

    orig_lines = original.splitlines()
    res_lines = result.splitlines()
    # hayabusa's existing `threads: 1` was replaced; chainsaw got one inserted; both == 2.
    threads_lines = [ln for ln in res_lines if ln.strip().startswith("threads:")]
    assert threads_lines == ["    threads: 2", "    threads: 2"]
    # zircolite untouched — exactly the two threads lines above exist.
    assert result.count("threads:") == 2
    # Every non-threads line is byte-identical and in the same order.
    assert [ln for ln in res_lines if "threads:" not in ln] == [ln for ln in orig_lines if "threads:" not in ln]
    # Idempotent: a second pass changes nothing.
    assert scaling.apply_to_workflows(rec, project_root=tmp_path) == 0
    assert wf.read_text(encoding="utf-8") == result


def test_apply_workflows_no_files(scaling, tmp_path, capsys):
    (tmp_path / "workflows").mkdir()
    rec = scaling.recommend(8, 16.0)
    assert scaling.apply_to_workflows(rec, project_root=tmp_path) == 0
    assert "no workflows" in capsys.readouterr().out.lower()


def test_detect_database_kind(scaling, tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    (tmp_path / ".env").write_text("DATABASE_URL=sqlite+aiosqlite:///./logstotal.db\n", encoding="utf-8")
    assert scaling.detect_database_kind(tmp_path) == "sqlite"
    (tmp_path / ".env").write_text("DATABASE_URL=postgresql+asyncpg://u:p@h:5432/db\n", encoding="utf-8")
    assert scaling.detect_database_kind(tmp_path) == "postgresql"


def test_apply_skips_db_pool_size_on_sqlite(scaling, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    env = tmp_path / ".env"
    env.write_text("DATABASE_URL=sqlite+aiosqlite:///./logstotal.db\nHUEY_WORKERS=2\n", encoding="utf-8")
    monkeypatch.setattr(scaling, "PROJECT_ROOT", tmp_path)

    rec = scaling.recommend(8, 16.0)
    rc = scaling.apply_to_env(rec, assume_yes=True)
    assert rc == 0
    text = env.read_text(encoding="utf-8")
    assert "HUEY_WORKERS=4" in text
    assert "TOOL_MAX_WORKERS=2" in text
    assert "DB_POOL_SIZE" not in text
    assert "Skipping DB_POOL_SIZE" in capsys.readouterr().out


def test_apply_writes_db_pool_size_on_postgres(scaling, tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    env = tmp_path / ".env"
    env.write_text("DATABASE_URL=postgresql+asyncpg://u:p@h:5432/db\n", encoding="utf-8")
    monkeypatch.setattr(scaling, "PROJECT_ROOT", tmp_path)

    rec = scaling.recommend(8, 16.0)
    assert scaling.apply_to_env(rec, assume_yes=True) == 0
    assert "DB_POOL_SIZE=5" in env.read_text(encoding="utf-8")


def test_recommend_is_the_shared_app_concurrency_function(scaling):
    """The sizing math must have exactly one home: app/concurrency.py."""
    from app.concurrency import recommend_host_settings

    assert scaling.recommend is recommend_host_settings
    assert scaling.RAM_GB_PER_WORKER == __import__("app.concurrency", fromlist=["x"]).RAM_GB_PER_WORKER
