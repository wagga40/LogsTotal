"""Contract tests for Taskfile.yml.

Everything here guards a failure mode that produces a *working-looking* Taskfile:
a task that compiles but resolves the wrong value, a guard that silently covers
nothing, a linter that skips a file. `task check` cannot see any of them.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from _taskfile import ROOT_TASKFILE, all_raw, all_tasks, taskfile_paths

REPO_ROOT = Path(__file__).resolve().parents[1]
TASKFILE = REPO_ROOT / "Taskfile.yml"


def _tasks() -> dict:
    """Every task across the root Taskfile and its includes — see tests/_taskfile.py."""
    return all_tasks()


# ── The env: bridge depends on these keys staying out of .env ────────────────

# Tasks bridge these into their scripts with `env: {KEY: '{{.KEY}}'}`, which covers
# `task x KEY=v`, `KEY=v task x` and unset alike. The one way to break it is to add
# the key to .env: a template `{{.KEY}}` prefers a dotenv value over the process
# environment, so `KEY=v task x` would silently lose to the .env line.
BRIDGED_KEYS = (
    "REF",
    "VERSION",
    "ALLOW_UNRELEASED",
    "RELEASE_REPO_URL",
    "SKIP_IF_CURRENT",
    "RESTAGE_IF_CURRENT",
    "ARCHIVE",
    "SKIP_BACKUP",
    "BACKUP_FILE",
    "HEALTH_URL",
    "DEPLOY_PLAN_FORMAT",
)


@pytest.mark.parametrize("key", BRIDGED_KEYS)
def test_bridged_keys_are_not_documented_as_env_settings(key: str):
    example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    offenders = [ln for ln in example.splitlines() if ln.strip().lstrip("#").strip().startswith(f"{key}=")]
    assert not offenders, (
        f"{key} appears in .env.example ({offenders}). It is bridged into a script with "
        f"`env: {{{key}: '{{{{.{key}}}}}'}}`, and a dotenv value beats the process "
        f"environment in that template — so `{key}=x task <name>` would silently lose "
        f"to .env. Bridge it in the cmd with ${{{key}:-...}} instead, or pick another name."
    )


def test_every_bridged_task_uses_an_env_block_not_a_shell_bridge():
    """The shell form also executed a value containing $(...)."""
    raw = all_raw()
    code = "\n".join(ln for ln in raw.splitlines() if not ln.lstrip().startswith("#"))
    for key in BRIDGED_KEYS:
        assert f'{key}="${{{key}:-' not in code, f"{key} is back to a shell bridge — see the note on health:remote"


# ── lint:shell must not skip a shell script ─────────────────────────────────


def test_lint_shell_covers_every_shell_script():
    """Naming scripts explicitly lets a newly added one — an entrypoint, say — go
    unchecked from the day it is added."""
    body = yaml.safe_dump(_tasks()["lint:shell"]["cmds"])
    for script in sorted(REPO_ROOT.glob("*.sh")):
        assert script.name in body, f"lint:shell does not check {script.name}"
    assert "scripts/*.sh" in body and "scripts/lib/*.sh" in body


# ── Every task still compiles ───────────────────────────────────────────────


@pytest.mark.skipif(shutil.which("task") is None, reason="go-task not installed")
def test_every_task_compiles():
    """`task --dry <name>` renders a task's templates without running it, which
    catches a bad `{{...}}` that no other test would see. Preconditions fire under
    --dry, so a missing tool on this host counts as a pass — the point is the
    template, not the toolchain."""
    failures = []
    for name in sorted(_tasks()):
        res = subprocess.run(
            ["task", "--dry", name],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "NO_COLOR": "1"},
        )
        if res.returncode != 0 and "precondition not met" not in res.stderr:
            failures.append(f"{name}: {res.stderr.strip().splitlines()[-1] if res.stderr.strip() else res.returncode}")
    assert not failures, "tasks that do not compile:\n  " + "\n  ".join(failures)


# ── Every task that shells out to a tool declares it ────────────────────────

# name -> (regex fragment matched against the task's cmds, precondition anchor's sh)
_TOOL_GUARDS = {
    "pdm": ("pdm ", "command -v pdm"),
    "docker": ("docker ", "command -v docker"),
    "sqlite3": ("sqlite3 ", "command -v sqlite3"),
    "redis-server": ("redis-server", "command -v redis-server"),
    "curl": ("curl ", "command -v curl"),
    "perl": ("perl ", "command -v perl"),
    "shellcheck": ("shellcheck ", "command -v shellcheck"),
}

# Tasks that reach a tool without declaring it, on purpose.
_GUARD_EXEMPT = {
    # Skips cleanly by design when node is absent, so `task test` passes on a
    # Python-only box; a precondition would turn that skip into a failure.
    ("test:js", "node"),
    # Guards git itself and degrades to "unknown" — a precondition would make
    # `task version` fail outside a git checkout, where it still has a VERSION file.
    ("version", "git"),
    # Branches on open/xdg-open and prints the URL when neither exists.
    ("open", "open"),
    # Its docker check sits AFTER the POSTGRES_TEST_URL short-circuit, deliberately:
    # pointing the task at your own server must not require Docker.
    ("test:pg", "docker"),
    # The four stdlib-only python tasks go through lib/common.sh::run_py, which
    # falls back to a host python3 when pdm is absent — that fallback IS the feature.
    ("gen-secrets", "pdm"),
    ("env:diff", "pdm"),
    ("recommend-scaling", "pdm"),
    ("proxy:enable", "pdm"),
    # `setup` carries its own inline `command -v pdm` guard, which
    # tests/test_scripts_robustness.py::test_setup_tasks_guard_missing_pdm extracts
    # from the raw task body — an anchored precondition would be invisible to it.
    ("setup", "pdm"),
    # The string is the CONTAINER's command (`redis:7-alpine redis-server
    # --requirepass ...`), not a host binary. Its real requirement is docker,
    # which it does declare.
    ("redis:docker", "redis-server"),
}


def _cmd_text(task: dict) -> str:
    """A task's shell, minus comments and minus lines that only print.

    A comment or an `echo` that mentions docker is not a use of docker — the
    curated `default` block says "task doctor:docker for a Docker deployment"
    and was reported as unguarded docker use.
    """
    parts = []
    for c in task.get("cmds") or []:
        if not isinstance(c, str):
            continue
        for line in c.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("echo ") or stripped == "echo":
                continue
            parts.append(line)
    return "\n".join(parts)


def test_every_task_that_uses_a_tool_declares_a_precondition():
    """Without this the failure is mvdan/sh's `"pdm": executable file not found in
    $PATH`, which names neither the task's requirement nor how to satisfy it."""
    tasks = _tasks()
    problems = []
    for name, task in sorted(tasks.items()):
        if not isinstance(task, dict):
            continue
        body = _cmd_text(task)
        declared = yaml.safe_dump(task.get("preconditions") or [])
        for tool, (fragment, guard) in _TOOL_GUARDS.items():
            if (name, tool) in _GUARD_EXEMPT:
                continue
            if fragment not in body:
                continue
            if guard in declared or guard in body:
                continue
            problems.append(f"{name}: runs {tool} with no precondition and no inline check")
    assert not problems, "\n  ".join(["unguarded tool use:", *problems])


def test_the_shared_anchors_cannot_be_mistaken_for_tasks():
    """Every key in the x-preconditions block carries its anchor on the same line.

    Two tests still scan raw text for a bare 2-space key, and one there would register as a
    phantom task that then needs a desc: and a docs mention.

    Per file, not over the concatenation: each Taskfile carries its own copy of the block
    (YAML anchors do not cross files), and slicing between the first `x-preconditions:` and
    the first `tasks:` of three joined files spans a boundary and checks neither properly.
    """
    for path in taskfile_paths():
        raw = path.read_text(encoding="utf-8")
        if "x-preconditions:" not in raw:
            continue
        # Ends at whichever top-level key follows — the root has `includes:` in between,
        # and its two keys are include names, not anchors.
        ends = [raw.index(k) for k in ("\nincludes:", "\ntasks:") if k in raw]
        block = raw[raw.index("x-preconditions:") : min(ends)]
        for line in block.splitlines():
            if re.match(r"^  [a-z]", line):
                assert "&" in line, f"{path.name}: {line.strip()!r} in x-preconditions has no anchor — it reads as a task"


def test_the_curated_default_only_names_real_tasks():
    """`default` hand-lists the tasks a newcomer should start with. Nothing else
    watches it: the docs-sync guards scan docs and scripts, never the Taskfile, so a
    renamed task would leave `task` advertising a command that no longer exists."""
    import re

    default = _tasks()["default"]
    body = "\n".join(c for c in default["cmds"] if isinstance(c, str))
    named = set(re.findall(r"(?:\btask|\./logstotal) ([a-z][a-zA-Z0-9:_-]*)", body))
    assert named, "the curated block names no tasks — has it been replaced by a bare --list?"
    unknown = named - set(_tasks())
    assert not unknown, f"`default` advertises tasks that do not exist: {sorted(unknown)}"


class _DuplicateKeyLoader(yaml.SafeLoader):
    """A SafeLoader that records duplicate mapping keys instead of silently keeping the last.

    PyYAML — and go-task's own unmarshaler — resolve a duplicate key last-wins without a
    word, so a task defined twice compiles, runs, and is invisible to every other test in
    this file: `_tasks()` returns a dict, and the first copy has already been discarded by
    the time it is indexed.

    A raw two-space-key scan was the obvious alternative and is wrong twice over. It
    false-positives on `redis`, which is a task AND the `&needs-redis` key in the
    x-preconditions anchor block, and it cannot follow the file once it is split into
    includes. Rejecting duplicates at parse time is the same check wherever the YAML lives.
    """

    duplicates: list[tuple[str, int, int]] = []

    def construct_mapping(self, node, deep=False):
        seen: dict[object, int] = {}
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            line = key_node.start_mark.line + 1
            if key in seen:
                _DuplicateKeyLoader.duplicates.append((str(key), seen[key], line))
            seen[key] = line
        return super().construct_mapping(node, deep)


def test_no_key_is_defined_twice():
    """A duplicate task key parses cleanly and runs the *last* copy.

    `fleet` and `fleet:pull` were each defined twice for three releases — 44 byte-identical
    lines, introduced by a Taskfile restructure — and nothing noticed, because the only
    symptom is dead text that drifts the next time one copy is edited.
    """
    problems = []
    for path in taskfile_paths():
        _DuplicateKeyLoader.duplicates = []
        yaml.load(path.read_text(encoding="utf-8"), Loader=_DuplicateKeyLoader)
        problems += [f"{path.name}: {key!r} at line {second} duplicates line {first}" for key, first, second in _DuplicateKeyLoader.duplicates]
    assert not problems, "a Taskfile defines the same key twice:\n  " + "\n  ".join(problems)


def test_aliases_do_not_collide_with_task_names():
    """An alias that shadows a real task name is ambiguous, and go-task resolves it
    silently rather than complaining."""
    tasks = _tasks()
    names = set(tasks)
    seen: dict[str, str] = {}
    for name, task in sorted(tasks.items()):
        for alias in (task.get("aliases") or []) if isinstance(task, dict) else []:
            assert alias not in names, f"{name}: alias {alias!r} shadows the task of that name"
            assert alias not in seen, f"{name}: alias {alias!r} already belongs to {seen[alias]}"
            seen[alias] = name


def test_destructive_tasks_confirm_first():
    """Anything that replaces or deletes live state asks before doing it. -y skips
    the prompt, so automation is unaffected."""
    tasks = _tasks()
    must_prompt = [
        "db:reset",
        "clean",
        "clean:all",
        "uploads:clean",
        "docker:clean",
        "backup:prune",
        "restore:sqlite",
        "restore:postgres",
        "upgrade:rollback",  # was deploy:rollback + upgrade:rollback; one verb, both scopes
        "deploy:remove",
        "tools:update",
        "release:finish",  # writes a commit and a tag
    ]
    missing = [n for n in must_prompt if not (tasks.get(n) or {}).get("prompt")]
    assert not missing, f"destructive tasks with no confirmation: {missing}"


#: Tasks that carry no `summary:`, grandfathered. A ratchet, not an allow-list to grow:
#: a NEW task must explain itself, but nobody should invent prose for
#: `docker compose logs -f web` just to satisfy a guard — a summary that restates the
#: desc teaches operators that `task --summary` is not worth running.
_NO_SUMMARY_OK = frozenset(
    {
        "check",
        "docker:down",
        "docker:logs",
        "docker:logs:web",
        "docker:logs:worker",
        "docker:worker-down",
        "docker:worker-logs",
        "fmt",
        "fmt:check",
        "lint",
        "lint:shell",
        "redis:docker",
        "test:cov",
    }
)


def test_every_new_task_has_a_summary():
    """`desc` is the one-liner in `task --list`; `summary` is what `task --summary <name>`
    prints, and it is where a task's real arguments and failure modes live."""
    tasks = _tasks()
    missing = {n for n, v in tasks.items() if isinstance(v, dict) and not v.get("summary")}
    new = sorted(missing - _NO_SUMMARY_OK)
    assert not new, f"tasks with no summary: {new} — add one, or grandfather it in _NO_SUMMARY_OK with a reason"


def test_no_summary_allow_list_has_no_stale_entries():
    """A grandfathered task that has since grown a summary must leave the list, or the
    ratchet quietly stops ratcheting."""
    tasks = _tasks()
    stale = sorted(n for n in _NO_SUMMARY_OK if n not in tasks or (tasks[n] or {}).get("summary"))
    assert not stale, f"_NO_SUMMARY_OK entries that are gone or now have a summary: {stale}"


class TestTheFleetWorkflowKeepsItsFirstStep:
    """`deploy:init` writes deploy.env and stops.

    `task deploy` accepts the same host list, but that misses the point: init is the step
    that produces a file to READ AND EDIT before anything is contacted. Without it the
    fleet's configuration only exists after a deploy has already used its defaults.
    """

    def test_deploy_init_exists(self):
        tasks = _tasks()
        assert "deploy:init" in tasks, "the step that gives the operator something to tune"

    def test_it_writes_and_stops_rather_than_deploying(self):
        cmds = _cmd_text(_tasks()["deploy:init"])
        assert "deploy-fleet.sh init" in cmds, f"deploy:init must dispatch the init action, got {cmds!r}"

    def test_the_documented_order_names_all_four_steps(self):
        """init → edit deploy.env → plan → deploy. A reader who only sees `./logstotal deploy`
        never learns there was a file to change."""
        doc = (REPO_ROOT / "docs" / "install" / "fleet.md").read_text(encoding="utf-8")
        flow = doc.split("## Automated setup", 1)[1].split("\n## ", 1)[0]
        for step in ("./logstotal deploy:init", "deploy.env", "./logstotal deploy:plan", "./logstotal deploy"):
            assert step in flow, f"the setup flow never mentions {step}"

    def test_the_install_directory_is_explained_where_the_flow_is(self):
        """Which directory the release is installed INTO, and whether it can be deleted,
        are the two questions the text must not leave to inference."""
        doc = (REPO_ROOT / "docs" / "install" / "fleet.md").read_text(encoding="utf-8")
        assert "### Where it gets installed" in doc
        section = doc.split("### Where it gets installed", 1)[1].split("\n## ", 1)[0]
        assert "DEPLOY_REMOTE_DIR" in section
        assert "toolkit" in section, "it must say the deploy-from directory is not the install directory"
        assert "deploy:remove" in section, "it must say what deletes the install directory"


def test_every_task_that_reaches_an_adopting_script_bridges_fleet_from():
    """FLEET_FROM must work as `task upgrade FLEET_FROM=cp` too, not only as an exported var.

    go-task never exports a CLI variable to the shell, so without the bridge that form is
    silently ignored — the exact shape of the DEPLOY_HOSTS bug documented above, where
    `task upgrade DEPLOY_HOSTS="cp,w1"` upgraded the fleet named in deploy.env instead.

    Keyed off the SCRIPT rather than a list of task names, so a new verb wired to one of
    these is covered the day it is added rather than the day someone notices.
    """
    adopting = (
        "deploy-multiserver.sh",
        "deploy-preflight.sh",
        "deploy-smoke.sh",
        "deploy-fleet.sh",
        "fleet.sh",
        "upgrade.sh",
    )
    missing = []
    for name, task in sorted(_tasks().items()):
        if not isinstance(task, dict):
            continue
        cmds = " ".join(c if isinstance(c, str) else str(c) for c in (task.get("cmds") or []))
        if any(script in cmds for script in adopting) and "FLEET_FROM" not in str(task.get("env") or {}):
            missing.append(name)
    assert not missing, f"tasks reaching an adopting script without a FLEET_FROM bridge: {missing}"


# ── The split into three files ───────────────────────────────────────────────


def test_every_taskfile_carries_the_same_preconditions():
    """YAML anchors do not cross files, so each Taskfile needs its own copy of the block.

    That is the one real cost of three files, and the only mitigation is to notice when the
    copies diverge. Drift here is silent in the worst way: an anchor edited in one file and
    not the other leaves half the tasks guarded by the old text, and both files still parse,
    still run, and still pass every other test.
    """
    blocks = {}
    for path in taskfile_paths():
        # The parsed mapping, not the raw slice: PyYAML resolves the anchors on the way
        # past, so this compares what the preconditions actually SAY. The root also carries
        # its own `includes:` commentary between the block and the next key, which a text
        # slice would drag in and report as drift forever.
        blocks[path.name] = yaml.safe_load(path.read_text(encoding="utf-8")).get("x-preconditions")

    missing = sorted(name for name, block in blocks.items() if not block)
    assert not missing, f"a Taskfile has no x-preconditions block, so its `*needs-` anchors cannot resolve: {missing}"

    reference = blocks[ROOT_TASKFILE.name]
    drifted = sorted(name for name, block in blocks.items() if block != reference)
    assert not drifted, (
        f"the shared preconditions have drifted from {ROOT_TASKFILE.name} in: {drifted}. Anchors do not cross files, so every Taskfile carries a copy — keep them identical."
    )


def test_the_root_only_wires_things_up():
    """The root is the map, not the territory. If tasks accumulate there the split is
    already unravelling, and the next one goes wherever the last one went."""
    root = yaml.safe_load(ROOT_TASKFILE.read_text(encoding="utf-8"))
    assert root.get("includes"), "the root Taskfile no longer includes anything"
    own = set(root.get("tasks") or {})
    assert own <= {"default"}, f"tasks defined in the root instead of dev.yml/ops.yml: {sorted(own - {'default'})}"


def test_no_include_moves_the_working_directory():
    """`dir:` on an include changes the cwd its tasks run from. Every cmd here is
    `bash scripts/x.sh`, resolved from the repo root — measured, an included task's cmds run
    there by default — so a `dir:` would break every path in both files at once."""
    root = yaml.safe_load(ROOT_TASKFILE.read_text(encoding="utf-8"))
    for name, spec in (root.get("includes") or {}).items():
        assert isinstance(spec, dict), f"include {name} must be a mapping so flatten can be set"
        assert "dir" not in spec, f"include {name} sets dir:, which breaks every `bash scripts/...` path"
        assert spec.get("flatten") is True, f"include {name} must set flatten: true, or every task it holds is renamed"


def test_no_include_is_optional():
    """`optional: true` turns a missing file into SILENCE — its tasks simply do not exist,
    including in `task --list`. Without it the same situation is a loud exit 100, which is
    how you find out the archive you extracted is incomplete."""
    root = yaml.safe_load(ROOT_TASKFILE.read_text(encoding="utf-8"))
    for name, spec in (root.get("includes") or {}).items():
        assert not (isinstance(spec, dict) and spec.get("optional")), f"include {name} is optional: a missing file would hide its tasks without a word"
