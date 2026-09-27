#!/usr/bin/env python3
"""
Recommend worker / concurrency settings for THIS host's CPU and RAM.

Applies the sizing model documented in docs/scaling.md ("Scaling & Capacity
Planning") and prints recommended values with the reasoning behind each. With
--apply it writes the env-level knobs (HUEY_WORKERS, TOOL_MAX_WORKERS,
DB_POOL_SIZE) into .env; per-tool `threads` (workflow YAML) and the
`parallel_execution` toggle (admin Settings) are printed for you to apply
manually, since they don't live in .env.

Usage:
    python3 scripts/recommend_scaling.py            # print recommendations
    python3 scripts/recommend_scaling.py --apply    # also write env knobs to .env
    python3 scripts/recommend_scaling.py --apply --yes   # no confirmation prompt
    python3 scripts/recommend_scaling.py --apply-workflows  # write per-tool threads into workflows/*.yml
    python3 scripts/recommend_scaling.py --cores 8 --ram 16   # plan for another host

The model in one line:
    peak CPU pressure ≈ HUEY_WORKERS x (TOOL_MAX_WORKERS if parallel else 1) x per-tool threads
Keep that near the core count to avoid oversubscription.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# The sizing math lives in app/concurrency.py (single source of truth, shared
# with the admin concurrency card and system checks). app/ is import-safe here:
# concurrency.py is pure stdlib, and this script already runs without a venv.
sys.path.insert(0, str(PROJECT_ROOT))
from app.concurrency import RAM_GB_PER_WORKER, detect_ram_gb  # noqa: E402
from app.concurrency import recommend_host_settings as recommend  # noqa: E402

# The one colour decision — see scripts/cli_color.py. Sibling import, the
# scripts/deploy_fleet_env.py idiom: these helpers run through `run_py` on hosts with no
# venv, so nothing here may reach the application.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli_color import colors  # noqa: E402


def detect_workflow_threads(project_root: Path | None = None) -> int | None:
    """Max `threads:` value set across workflows/*.yml, or None when no workflow sets it.

    Omitting `threads:` does not mean "all logical cores": LogsTotal passes an
    explicit cap of 1. The shipped workflows set `threads: 2` for hayabusa/chainsaw.
    """
    project_root = project_root or PROJECT_ROOT
    values: list[int] = []
    for wf in sorted((project_root / "workflows").glob("*.yml")):
        try:
            values += [int(v) for v in re.findall(r"^\s*threads:\s*(\d+)\s*$", wf.read_text(encoding="utf-8"), flags=re.M)]
        except OSError:
            continue
    return max(values) if values else None


def detect_max_tool_count(project_root: Path | None = None) -> int | None:
    """Largest number of tool tasks in any single workflows/*.yml, or None when none parse.

    The per-job tool executor caps parallelism at min(TOOL_MAX_WORKERS, tools-in-job), so
    the useful TOOL_MAX_WORKERS is "big enough for the largest workflow". Counts `- tool:`
    list items with the same stdlib-regex approach as detect_workflow_threads.
    """
    project_root = project_root or PROJECT_ROOT
    counts: list[int] = []
    for wf in sorted((project_root / "workflows").glob("*.yml")):
        try:
            n = len(re.findall(r"^\s*-\s+tool:\s*\S", wf.read_text(encoding="utf-8"), flags=re.M))
        except OSError:
            continue
        if n:
            counts.append(n)
    return max(counts) if counts else None


def detect_worker_compose_workers(project_root: Path | None = None) -> int | None:
    """HUEY_WORKERS default baked into docker-compose.worker.yml, or None if absent."""
    project_root = project_root or PROJECT_ROOT
    try:
        text = (project_root / "docker-compose.worker.yml").read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r"\$\{HUEY_WORKERS:-(\d+)\}", text)
    return int(m.group(1)) if m else None


def detect_database_kind(project_root: Path | None = None) -> str:
    """ "postgresql" or "sqlite", from the environment or .env (best-effort)."""
    project_root = project_root or PROJECT_ROOT
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        try:
            m = re.search(r"^DATABASE_URL=(.+)$", (project_root / ".env").read_text(encoding="utf-8"), flags=re.M)
            url = m.group(1) if m else ""
        except OSError:
            pass
    return "postgresql" if "postgres" in url else "sqlite"


def print_report(rec: dict) -> None:
    c = colors()
    cores = rec["cores"]
    ram = rec["ram_gb"]
    ram_str = f"{ram:.1f} GB RAM" if ram else "RAM: unknown"
    print(f"\n{c['bold']}LogsTotal scaling recommendation{c['off']}")
    print(f"  {c['cyan']}{'─' * 58}{c['off']}")
    # The two numbers everything below is derived from.
    print(f"  Detected: {c['bold']}{cores}{c['off']} CPU core(s), {c['bold']}{ram_str}{c['off']}")
    print()
    print(f"  {c['bold']}The model:{c['off']}")
    print("    peak CPU ≈ HUEY_WORKERS x (TOOL_MAX_WORKERS if parallel else 1) x per-tool threads")
    print("    — keep peak near the core count so tools don't fight for CPU.")
    print()
    # The three lines an operator is here to copy, so they are the emphasised ones.
    print(f"  {c['bold']}Recommended .env (worker host):{c['off']}")
    print(f"    {c['bold']}HUEY_WORKERS={rec['huey_workers']}{c['off']}        # concurrent jobs per worker process")
    print(f"    {c['bold']}TOOL_MAX_WORKERS={rec['tool_max_workers']}{c['off']}    # only used when parallel_execution is ON")
    print(f"    {c['bold']}DB_POOL_SIZE={rec['db_pool_size']}{c['off']}        # PostgreSQL only; ≥ HUEY_WORKERS per process")
    print()
    print(f"  {c['bold']}Recommended workflow YAML (CPU-bound tools — hayabusa, chainsaw):{c['off']}")
    print(f"    {c['bold']}threads: {rec['threads_per_tool']}{c['off']}")
    current_threads = detect_workflow_threads()
    if current_threads is None:
        print("    Currently: no workflow sets `threads:` → each tool uses the explicit default of 1,")
        print(f"    so today's actual peak is HUEY_WORKERS x 1 (the recommended peak of {rec['peak_cpu']}")
        print(f"    assumes you add `threads: {rec['threads_per_tool']}` to workflows/*.yml, then run: ./logstotal sync-workflows)")
    else:
        print(f"    Currently: workflows set threads up to {current_threads} (shipped default: 2)")
    print()
    parallel_word = "OFF (default) — consider ON for low-volume use" if rec["suggest_parallel"] else "OFF (default)"
    print(f"  parallel_execution (admin → Settings): {parallel_word}")
    if rec["suggest_parallel"]:
        print("    Default OFF maximises throughput. On a host this size, if jobs usually")
        print("    arrive one at a time, turning it ON makes each job finish faster by")
        print(f"    running its tools concurrently — TOOL_MAX_WORKERS={rec['tool_max_workers']} is already sized")
        print("    for that (drop HUEY_WORKERS so peak stays near the core count).")
    else:
        print("    Leave it off: at this worker count, parallelising tools within a job")
        print("    would oversubscribe the CPU. Throughput already comes from HUEY_WORKERS.")
    print()
    print(f"  {c['bold']}Reasoning:{c['off']}")
    print(f"    • per-tool threads = {rec['threads_per_tool']} ({'≥4 cores' if cores >= 4 else '<4 cores, keep light'})")
    print(f"    • HUEY_WORKERS = {rec['huey_workers']} → peak ≈ {rec['peak_cpu']} of {cores} cores", end="")
    print(" (RAM-bound)" if rec["ram_bound"] else "")
    if rec["ram_bound"]:
        print(f"      RAM limits concurrency here (~{RAM_GB_PER_WORKER} GB per running job).")
    tmw, tpt = rec["tool_max_workers"], rec["threads_per_tool"]
    print(f"    • TOOL_MAX_WORKERS = {tmw} → sized for up to {rec['max_tool_count']} tools/job, capped so a")
    print(f"      parallel job's peak ({tmw}x{tpt}={tmw * tpt}) stays within {cores} cores")
    print(f"    • DB_POOL_SIZE = {rec['db_pool_size']} so each worker process has a connection per thread")
    print()
    print(f"  {c['bold']}Notes:{c['off']}")
    print("    • Combined single-server host (web + worker + Redis together)? Drop")
    print("      HUEY_WORKERS by 1 to leave a core for the web/Redis processes.")
    print("    • These are per-process values. A dedicated worker box can go higher;")
    print("      a shared box should stay conservative.")
    print("    • Recommendations are PER HOST — size each machine to its own CPU/RAM.")
    worker_default = detect_worker_compose_workers()
    if worker_default is not None:
        print(f"      Dedicated worker machines (docker-compose.worker.yml) default to HUEY_WORKERS={worker_default};")
        print("      override it in that host's own .env with the value above.")
    else:
        print("      Dedicated worker machines (docker-compose.worker.yml) set HUEY_WORKERS")
        print("      in that host's own .env — use the value above.")
    print("    • Re-run with --apply to write the .env knobs, or --apply-workflows to set")
    print("      per-tool `threads:` in workflows/*.yml (then run: ./logstotal sync-workflows).")


def _set_env_key(text: str, key: str, value: str) -> str:
    """Replace an existing (possibly commented) KEY line, or append it."""
    if re.search(rf"^{re.escape(key)}=.*$", text, flags=re.M):
        return re.sub(rf"^{re.escape(key)}=.*$", f"{key}={value}", text, count=1, flags=re.M)
    # Replace a commented-out form like "# DB_POOL_SIZE=5" if present, else append.
    if re.search(rf"^#\s*{re.escape(key)}=.*$", text, flags=re.M):
        return re.sub(rf"^#\s*{re.escape(key)}=.*$", f"{key}={value}", text, count=1, flags=re.M)
    if text and not text.endswith("\n"):
        text += "\n"
    return text + f"{key}={value}\n"


def apply_to_env(rec: dict, assume_yes: bool) -> int:
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        print("ERROR: .env not found. Create it first: cp .env.example .env", file=sys.stderr)
        return 1
    knobs = {
        "HUEY_WORKERS": str(rec["huey_workers"]),
        "TOOL_MAX_WORKERS": str(rec["tool_max_workers"]),
        "DB_POOL_SIZE": str(rec["db_pool_size"]),
    }
    if detect_database_kind() == "sqlite":
        knobs.pop("DB_POOL_SIZE")
        print("\n  Skipping DB_POOL_SIZE — this deployment uses SQLite, which ignores it.")
    print("\n  Will write to .env:")
    for k, v in knobs.items():
        print(f"    {k}={v}")
    if not assume_yes:
        try:
            answer = input("\n  Proceed? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            print("  Aborted — nothing written.")
            return 0
    text = env_path.read_text(encoding="utf-8")
    for k, v in knobs.items():
        text = _set_env_key(text, k, v)
    env_path.write_text(text, encoding="utf-8")
    print(f"  Wrote {len(knobs)} key(s) to .env. Restart the worker for changes to take effect.")
    print("  Remember to also set `threads:` in workflows/*.yml (or run --apply-workflows) and")
    print("  the parallel_execution toggle in the admin Settings page if you want those.")
    return 0


_THREADS_TOOLS = {"hayabusa", "chainsaw"}


def _apply_threads_to_text(text: str, value: int) -> tuple[str, list[str]]:
    """Set `threads: value` on every hayabusa/chainsaw task in a workflow YAML.

    Line-level and format-preserving: only `threads:` lines are replaced or inserted; every
    other line stays byte-identical. Zircolite (and any other tool) is left alone. Returns
    (new_text, human-readable change descriptions).
    """
    lines = text.splitlines(keepends=True)
    tool_re = re.compile(r"^(\s*)-\s+tool:\s*(\S+)")
    tasks = [(i, len(m.group(1)), m.group(2)) for i, line in enumerate(lines) if (m := tool_re.match(line))]
    threads_re = re.compile(r"^(\s*)threads:\s*(\d+)\s*[\r\n]*$")
    changes: list[str] = []
    # Walk tasks back-to-front so an insertion never shifts an earlier task's indices.
    for idx in range(len(tasks) - 1, -1, -1):
        start, dash_indent, tool_name = tasks[idx]
        end = tasks[idx + 1][0] if idx + 1 < len(tasks) else len(lines)
        if tool_name not in _THREADS_TOOLS:
            continue
        replaced = False
        for j in range(start, end):
            tm = threads_re.match(lines[j])
            if tm and len(tm.group(1)) > dash_indent:
                if tm.group(2) != str(value):
                    nl = "\r\n" if lines[j].endswith("\r\n") else ("\n" if lines[j].endswith("\n") else "")
                    lines[j] = f"{tm.group(1)}threads: {value}{nl}"
                    changes.append(f"{tool_name}: threads {tm.group(2)} → {value}")
                replaced = True
                break
        if replaced:
            continue
        # No threads: line in this task → insert one, matching the child-key indentation.
        child_indent = None
        for j in range(start + 1, end):
            cm = re.match(r"^(\s+)\S", lines[j])
            if cm and len(cm.group(1)) > dash_indent:
                child_indent = cm.group(1)
                break
        if child_indent is None:
            child_indent = " " * (dash_indent + 2)
        nl = "\r\n" if lines[start].endswith("\r\n") else "\n"
        lines.insert(start + 1, f"{child_indent}threads: {value}{nl}")
        changes.append(f"{tool_name}: threads (added) → {value}")
    return "".join(lines), changes


def apply_to_workflows(rec: dict, project_root: Path | None = None) -> int:
    project_root = project_root or PROJECT_ROOT
    value = rec.get("threads_per_tool")
    if not value:
        print("\n  --apply-workflows: no thread recommendation to apply — nothing done.", file=sys.stderr)
        return 1
    files = sorted((project_root / "workflows").glob("*.yml"))
    if not files:
        print("\n  --apply-workflows: no workflows/*.yml found — nothing done.")
        return 0
    print(f"\n  Applying `threads: {value}` to hayabusa/chainsaw tasks in workflows/*.yml:")
    changed = 0
    for wf in files:
        try:
            text = wf.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"    {wf.name}: skipped (unreadable: {exc})")
            continue
        new_text, changes = _apply_threads_to_text(text, value)
        if new_text == text:
            print(f"    {wf.name}: no change")
            continue
        wf.write_text(new_text, encoding="utf-8")
        changed += 1
        print(f"    {wf.name}:")
        for c in changes:
            print(f"      - {c}")
    print(f"\n  Updated {changed} file(s). Load them into the DB with: ./logstotal sync-workflows")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recommend LogsTotal worker scaling for this host",
        epilog=(
            "Recommendations are PER HOST. --apply writes the .env knobs; --apply-workflows\nwrites per-tool threads into workflows/*.yml (then run: ./logstotal sync-workflows)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cores", type=int, default=None, help="override detected CPU core count")
    parser.add_argument("--ram", type=float, default=None, help="override detected RAM (GB)")
    parser.add_argument("--apply", action="store_true", help="write env knobs (HUEY_WORKERS, TOOL_MAX_WORKERS, DB_POOL_SIZE) into .env")
    parser.add_argument("--apply-workflows", action="store_true", help="write per-tool `threads:` into workflows/*.yml (hayabusa/chainsaw), format-preserving")
    parser.add_argument("--yes", action="store_true", help="with --apply, skip the confirmation prompt")
    args = parser.parse_args()

    cores = args.cores or os.cpu_count() or 1
    ram = args.ram if args.ram is not None else detect_ram_gb()
    rec = recommend(cores, ram, detect_max_tool_count())
    print_report(rec)
    rc = 0
    if args.apply:
        rc = apply_to_env(rec, assume_yes=args.yes)
    if args.apply_workflows and rc == 0:
        rc = apply_to_workflows(rec)
    return rc


if __name__ == "__main__":
    sys.exit(main())
