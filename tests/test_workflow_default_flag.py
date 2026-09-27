"""The `is_default` workflow flag: single-valued in the DB, and actually applied by the form.

The flag decides which workflow the upload form pre-selects. Two independent things can
make it quietly inert, and both are pinned here.

1. Written straight through by `POST /workflows/new` and `/{id}/edit`, it could sit on any
   number of workflows. The form picks with `find(wf => wf.is_default)` over a name-ordered
   list, which makes a second default not an error but a silent dependence on alphabetical
   order.

2. `x-model` on a `<select>` whose `<option>`s come from a child `<template x-for>`
   desyncs. Alpine applies an element's own directives before walking its children, so
   `x-model` sets `select.value` against an empty list, the browser drops it, and x-for then
   leaves the browser auto-selecting index 0. Alpine state holds the default; the control
   shows — and submits — the alphabetically-first workflow. Only a browser catches that, so
   what is asserted here is the shape of the remedy: the `x-ref` handle and
   the post-x-for reconcile that writes the value back once the options exist. Delete
   either and the flag goes quiet again while every route test still passes.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from app.models import WorkflowDef

pytestmark = pytest.mark.anyio


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _workflow_form(name: str, *, is_default: bool) -> dict[str, str]:
    data = {
        "name": name,
        "description": "",
        "log_types": "evtx",
        "tasks_yaml": "tasks:\n  - tool: zircolite\n    rules_path: tools/zircolite/rules\n",
    }
    if is_default:
        data["is_default"] = "true"
    return data


async def _defaults(async_db) -> list[str]:
    rows = await async_db.execute(select(WorkflowDef).order_by(WorkflowDef.name))
    return [wf.name for wf in rows.scalars().all() if wf.is_default]


async def test_creating_a_default_demotes_the_previous_one(admin_client, async_db):
    """Two rows may never hold the flag at once — the second create wins."""
    resp = await admin_client.post("/workflows/new", data=_workflow_form("Alpha", is_default=True), follow_redirects=False)
    assert resp.status_code == 303
    assert await _defaults(async_db) == ["Alpha"]

    resp = await admin_client.post("/workflows/new", data=_workflow_form("Beta", is_default=True), follow_redirects=False)
    assert resp.status_code == 303
    assert await _defaults(async_db) == ["Beta"]


async def test_editing_a_workflow_into_the_default_demotes_the_others(admin_client, async_db):
    await admin_client.post("/workflows/new", data=_workflow_form("Alpha", is_default=True), follow_redirects=False)
    await admin_client.post("/workflows/new", data=_workflow_form("Beta", is_default=False), follow_redirects=False)
    assert await _defaults(async_db) == ["Alpha"]

    beta = await async_db.scalar(select(WorkflowDef).where(WorkflowDef.name == "Beta"))
    resp = await admin_client.post(f"/workflows/{beta.id}/edit", data=_workflow_form("Beta", is_default=True), follow_redirects=False)
    assert resp.status_code == 303

    async_db.expire_all()
    assert await _defaults(async_db) == ["Beta"]


async def test_saving_the_default_unchanged_keeps_it(admin_client, async_db):
    """The demote must exclude the row being saved, or editing the default clears it."""
    await admin_client.post("/workflows/new", data=_workflow_form("Alpha", is_default=True), follow_redirects=False)
    alpha = await async_db.scalar(select(WorkflowDef).where(WorkflowDef.name == "Alpha"))

    await admin_client.post(f"/workflows/{alpha.id}/edit", data=_workflow_form("Alpha", is_default=True), follow_redirects=False)

    async_db.expire_all()
    assert await _defaults(async_db) == ["Alpha"]


async def test_unchecking_the_box_leaves_no_default(admin_client, async_db):
    await admin_client.post("/workflows/new", data=_workflow_form("Alpha", is_default=True), follow_redirects=False)
    alpha = await async_db.scalar(select(WorkflowDef).where(WorkflowDef.name == "Alpha"))

    await admin_client.post(f"/workflows/{alpha.id}/edit", data=_workflow_form("Alpha", is_default=False), follow_redirects=False)

    async_db.expire_all()
    assert await _defaults(async_db) == []


def test_shipped_workflow_yamls_declare_exactly_one_default():
    """`task sync-workflows` writes the key through verbatim, so the files hold the invariant."""
    defaults = []
    for path in sorted((PROJECT_ROOT / "workflows").glob("*.yml")):
        data = yaml.safe_load(path.read_text()) or {}
        if data.get("is_default", False):
            defaults.append(path.name)
    assert len(defaults) == 1, f"expected exactly one shipped default workflow, got {defaults}"


def test_upload_form_reconciles_the_select_after_x_for_builds_the_options():
    """Guard against the x-model/x-for desync described in this module's docstring."""
    source = (PROJECT_ROOT / "app" / "templates" / "index.html").read_text()

    select_tag = re.search(r'<select[^>]*x-model="row.workflowId"[^>]*>', source)
    assert select_tag, "the workflow <select> disappeared — retarget this test"
    assert "'workflow-' + row.id" in select_tag.group(0), "each workflow select needs its own DOM handle"
    script = (PROJECT_ROOT / "app/static/upload.js").read_text()
    assert re.search(r"syncWorkflow\(row\)\s*\{.*?\$nextTick", script, re.S), "reconcile after x-for creates the options"
    assert "document.getElementById('workflow-' + row.id)" in script
    assert "select.value = row.workflowId" in script


class TestDirectorySyncKeepsItSingleValued:
    """`task sync-workflows` / `init_db.py` share the third write path to `is_default`.

    Only the admin CRUD routes called `_demote_other_defaults`. `sync_workflows_from_dir`
    wrote the flag straight from each YAML, so two shipped files claiming it — or one
    claiming it while an admin-created workflow already held it — left two rows set, and
    the upload form's `find(wf => wf.is_default)` fell back to alphabetical order.

    Resolved rather than rejected: a second default is an ambiguity with an obvious
    resolution, and putting it in the `errors` list would make `task sync-workflows` exit 1
    over something it can fix.
    """

    async def test_one_default_in_the_directory_wins_over_the_table(self, async_db, tmp_path):
        from app.detection.workflow_runner import sync_workflows_from_dir

        # An existing default that no YAML claims — e.g. one an admin set in the UI.
        async_db.add(WorkflowDef(name="admin-made", description="", log_types="[]", tasks_yaml="tasks: []", is_default=True))
        await async_db.commit()

        (tmp_path / "a.yml").write_text(yaml.dump({"name": "from-yaml", "log_types": ["evtx"], "is_default": True, "tasks": []}), encoding="utf-8")
        await sync_workflows_from_dir(async_db, tmp_path)
        await async_db.commit()

        defaults = sorted((await async_db.execute(select(WorkflowDef.name).where(WorkflowDef.is_default.is_(True)))).scalars().all())
        assert defaults == ["from-yaml"], f"expected the directory's default to win outright, got {defaults}"

    async def test_two_yaml_defaults_resolve_to_the_first_by_filename(self, async_db, tmp_path):
        from app.detection.workflow_runner import sync_workflows_from_dir

        (tmp_path / "a-first.yml").write_text(yaml.dump({"name": "alpha", "log_types": ["evtx"], "is_default": True, "tasks": []}), encoding="utf-8")
        (tmp_path / "z-last.yml").write_text(yaml.dump({"name": "zulu", "log_types": ["evtx"], "is_default": True, "tasks": []}), encoding="utf-8")

        added, _updated, errors = await sync_workflows_from_dir(async_db, tmp_path)
        await async_db.commit()

        assert errors == [], "a second default is resolvable, so it must not fail the sync"
        assert added == 2, "both workflows must still load"
        defaults = (await async_db.execute(select(WorkflowDef.name).where(WorkflowDef.is_default.is_(True)))).scalars().all()
        assert list(defaults) == ["alpha"], f"expected the first file in sorted order to keep the flag, got {list(defaults)}"

    async def test_a_directory_with_no_default_leaves_the_table_alone(self, async_db, tmp_path):
        """Syncing workflows that make no claim must not clear an admin's choice."""
        from app.detection.workflow_runner import sync_workflows_from_dir

        async_db.add(WorkflowDef(name="admin-made", description="", log_types="[]", tasks_yaml="tasks: []", is_default=True))
        await async_db.commit()

        (tmp_path / "a.yml").write_text(yaml.dump({"name": "plain", "log_types": ["evtx"], "tasks": []}), encoding="utf-8")
        await sync_workflows_from_dir(async_db, tmp_path)
        await async_db.commit()

        defaults = (await async_db.execute(select(WorkflowDef.name).where(WorkflowDef.is_default.is_(True)))).scalars().all()
        assert list(defaults) == ["admin-made"]
