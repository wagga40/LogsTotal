"""The two CI workflows must check the same things.

`.github/workflows/ci.yml` and `.forgejo/workflows/ci.yml` describe two different runners:
one has sudo and service containers, the other has a persistent `$HOME` and no package
manager. Those differences are real and the files are allowed to disagree about them.

What they are not allowed to disagree about is *what gets checked* — and they already had.
The Forgejo file grew a deploy dry-run GitHub never got; GitHub grew a Python matrix
Forgejo never got; neither installed Tailwind for the archive gate, so the archive CI
verified was never the archive a release published. Each drift was invisible because the
two files are never read side by side.

The mechanism is that every check is a `task ci:*` defined once in `Taskfile.yml`. These
tests hold that line: same task set, tasks that exist, no check smuggled back into YAML.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from _taskfile import all_tasks

REPO_ROOT = Path(__file__).resolve().parent.parent
GITHUB_CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
FORGEJO_CI = REPO_ROOT / ".forgejo" / "workflows" / "ci.yml"
GITHUB_RELEASE = REPO_ROOT / ".github" / "workflows" / "release.yml"
FORGEJO_RELEASE = REPO_ROOT / ".forgejo" / "workflows" / "release.yml"

CI_WORKFLOWS = (GITHUB_CI, FORGEJO_CI)
RELEASE_WORKFLOWS = (GITHUB_RELEASE, FORGEJO_RELEASE)

#: `./logstotal foo:bar` / `task foo -- args`, but not `task --list` or a bare `task`.
_TASK_CALL = re.compile(r"(?:\./logstotal|\btask)\s+([a-z][a-z0-9:_-]*)")


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_scripts(path: Path) -> list[str]:
    """Every `run:` body in a workflow, from every job."""
    bodies = []
    for job in (_load(path).get("jobs") or {}).values():
        for stepnum in job.get("steps") or []:
            if isinstance(stepnum, dict) and stepnum.get("run"):
                bodies.append(stepnum["run"])
    return bodies


def _tasks_invoked(path: Path) -> set[str]:
    """The set of `task <name>` entry points a workflow calls, across all its jobs.

    Across the file, not per job, on purpose: GitHub runs `task check` in its own
    un-matrixed job while Forgejo folds it into the test job, and that is a topology
    difference rather than a coverage one.
    """
    return {name for body in _run_scripts(path) for name in _TASK_CALL.findall(body)}


def _taskfile_names() -> set[str]:
    raw = {"tasks": all_tasks()}
    return set(raw.get("tasks") or {})


def test_both_workflows_check_exactly_the_same_things():
    github, forgejo = _tasks_invoked(GITHUB_CI), _tasks_invoked(FORGEJO_CI)
    assert github == forgejo, (
        "the two CI workflows call different tasks, which is how they drifted before.\n"
        f"  only on GitHub:  {sorted(github - forgejo)}\n"
        f"  only on Forgejo: {sorted(forgejo - github)}"
    )


@pytest.mark.parametrize("path", CI_WORKFLOWS, ids=lambda p: p.parent.parent.name)
def test_every_task_a_workflow_names_exists(path: Path):
    """A typo'd task name fails the job with `task: Task "ci:tests" does not exist`."""
    missing = sorted(_tasks_invoked(path) - _taskfile_names())
    assert not missing, f"{path.relative_to(REPO_ROOT)} calls tasks that are not in Taskfile.yml: {missing}"


@pytest.mark.parametrize("path", CI_WORKFLOWS, ids=lambda p: p.parent.parent.name)
def test_the_four_ci_entry_points_all_run(path: Path):
    """Each CI job has a task, and all four run. A job silently dropped is coverage lost."""
    expected = {"ci:test", "ci:artifacts", "ci:deploy", "ci:dry-run"}
    missing = sorted(expected - _tasks_invoked(path))
    assert not missing, f"{path.relative_to(REPO_ROOT)} no longer runs: {missing}"


@pytest.mark.parametrize("path", CI_WORKFLOWS + RELEASE_WORKFLOWS, ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_ci_runs_tasks_the_way_an_operator_does(path: Path):
    """Through ./logstotal, with no go-task installed first.

    That is the path every host takes, so CI exercising it is what proves a fresh machine
    can run a task at all. A setup-task step would put a `task` on PATH and hide a broken
    wrapper behind it.
    """
    uses = [s.get("uses", "") for job in (_load(path).get("jobs") or {}).values() for s in job.get("steps") or [] if isinstance(s, dict)]
    assert not [u for u in uses if "setup-task" in u], f"{path.relative_to(REPO_ROOT)} installs go-task instead of letting ./logstotal provide it"
    bare = [line.strip() for body in _run_scripts(path) for line in body.splitlines() if re.match(r"\s*task\s+[a-z]", line)]
    assert not bare, f"{path.relative_to(REPO_ROOT)} calls go-task directly: {bare}"


@pytest.mark.parametrize(("ci", "release"), list(zip(CI_WORKFLOWS, RELEASE_WORKFLOWS, strict=True)), ids=lambda p: p.parent.parent.name)
def test_a_release_rebuild_gates_on_the_tag_it_publishes(ci: Path, release: Path):
    """A manual re-run of a release builds an existing tag. Its CI gate used to check out
    the default branch instead: a green gate over code that was not the code published."""
    gate = _load(release)["jobs"]["ci"]
    assert "inputs.tag" in str((gate.get("with") or {}).get("ref", "")), f"{release.relative_to(REPO_ROOT)} does not tell CI which ref it is publishing"
    for name, job in (_load(ci).get("jobs") or {}).items():
        for step in job.get("steps") or []:
            if isinstance(step, dict) and str(step.get("uses", "")).startswith("actions/checkout"):
                assert (step.get("with") or {}).get("ref") == "${{ inputs.ref }}", (
                    f"{ci.relative_to(REPO_ROOT)} job {name} checks out the event's ref, not the one it was called for"
                )


@pytest.mark.parametrize("path", CI_WORKFLOWS, ids=lambda p: p.parent.parent.name)
def test_a_superseded_push_is_cancelled(path: Path):
    """Without this, a second push queues behind the first — four minutes on one runner."""
    concurrency = _load(path).get("concurrency")
    assert concurrency, f"{path.relative_to(REPO_ROOT)} declares no concurrency group"
    assert concurrency.get("cancel-in-progress") is True, f"{path.relative_to(REPO_ROOT)} does not cancel superseded runs"
    assert "github.ref" in concurrency.get("group", ""), "the group must be per-ref, or one branch's push cancels another's"


@pytest.mark.parametrize("path", RELEASE_WORKFLOWS, ids=lambda p: p.parent.parent.name)
def test_a_release_is_never_cancelled(path: Path):
    """The mirror image. A half-published release is worse than a slow one."""
    assert _load(path).get("concurrency") is None, (
        f"{path.relative_to(REPO_ROOT)} declares a concurrency group. A release that is cancelled part way can leave a tag with no archive attached."
    )


@pytest.mark.parametrize("path", CI_WORKFLOWS, ids=lambda p: p.parent.parent.name)
def test_no_check_is_reimplemented_in_yaml(path: Path):
    """Provisioning belongs here; checking does not.

    For example: `shellcheck` invoked directly from a job, when `task lint:shell` is what
    the Taskfile contract test pins; or `pytest` invoked directly for the PostgreSQL tests,
    a second interpreter start.
    """
    forbidden = ("shellcheck ", "pytest ", "verify-artifacts.sh", "package.sh")
    offenders = []
    for body in _run_scripts(path):
        for line in body.splitlines():
            # A ci-provision.sh line *names* tools to install; it does not run them. That is
            # the one place a checker's name may legitimately appear.
            if "ci-provision.sh" in line:
                continue
            offenders += [(needle, line.strip()) for needle in forbidden if needle in line]
    assert not offenders, f"{path.relative_to(REPO_ROOT)} runs checks inline instead of through a task: {offenders}"


@pytest.mark.parametrize("path", CI_WORKFLOWS, ids=lambda p: p.parent.parent.name)
def test_the_job_that_runs_the_suite_fetches_tags(path: Path):
    """`test_the_declared_version_has_a_git_tag` fails — it does not skip — without them.

    It skips only when `.git` is absent, and every checkout leaves `.git` present. So a
    shallow checkout with no tags turns a green suite red for a reason no tag can fix.
    Only `fetch-depth: 0` counts. `fetch-tags: true` at depth 1 fetches the one commit, and
    git then brings along only a tag that points at it: the suite passed on the tagged
    commit and failed on the first commit after it.
    """
    for job in (_load(path).get("jobs") or {}).values():
        if not any("ci:test" in (s.get("run") or "") for s in job.get("steps") or [] if isinstance(s, dict)):
            continue
        checkout = next((s for s in job["steps"] if isinstance(s, dict) and "checkout" in str(s.get("uses", ""))), None)
        assert checkout, "the test job does not check out the repository"
        params = checkout.get("with") or {}
        assert params.get("fetch-depth") == 0, (
            f"{path.relative_to(REPO_ROOT)}: the job running `task ci:test` must fetch tags with fetch-depth: 0 "
            f"(fetch-tags: true at depth 1 misses every tag not on the checked-out commit), got {params}"
        )
        return
    pytest.fail(f"{path.relative_to(REPO_ROOT)} has no job running `task ci:test`")
