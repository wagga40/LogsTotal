"""One reader for a Taskfile that is three files.

`Taskfile.yml` includes `taskfiles/dev.yml` and `taskfiles/ops.yml` with `flatten: true`, so
every task keeps its own name. But `yaml.safe_load(TASKFILE)["tasks"]` does not see the
included tasks: the root declares four and the rest live next door.

The contract modules also raw-scan the file's text for things YAML cannot express — a shell
bridge, an anchor block. So there are two readers here,
not one, and the raw one CONCATENATES rather than merging: a guard that only ever saw the
root file would pass while the half it was written for went unchecked.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ROOT_TASKFILE = REPO_ROOT / "Taskfile.yml"


def taskfile_paths() -> list[Path]:
    """The root Taskfile and every file it includes, root first.

    Read from the `includes:` block rather than globbed, so a file added to taskfiles/ but
    never wired up is not silently treated as live — and one that IS wired up cannot be
    missed by a guard that globbed a different directory.
    """
    root = yaml.safe_load(ROOT_TASKFILE.read_text(encoding="utf-8"))
    paths = [ROOT_TASKFILE]
    for spec in (root.get("includes") or {}).values():
        rel = spec["taskfile"] if isinstance(spec, dict) else spec
        path = (REPO_ROOT / rel).resolve()
        assert path.is_file(), f"Taskfile.yml includes {rel}, which does not exist"
        paths.append(path)
    return paths


def all_tasks() -> dict:
    """Every task, from every file, keyed by the name `task <name>` actually resolves.

    `flatten: true` means no namespace prefix, so a name defined in two files would be
    ambiguous — go-task exits 203 on it rather than picking one, which is the behaviour that
    makes flattening safe. Asserted here too, because the message it gives is terse.
    """
    merged: dict = {}
    for path in taskfile_paths():
        tasks = yaml.safe_load(path.read_text(encoding="utf-8")).get("tasks") or {}
        clash = set(tasks) & set(merged)
        assert not clash, f"{path.name} redefines tasks from another Taskfile: {sorted(clash)}"
        merged.update(tasks)
    return merged


def all_raw() -> str:
    """Every Taskfile's text, concatenated, for the guards YAML cannot express."""
    return "\n".join(p.read_text(encoding="utf-8") for p in taskfile_paths())
