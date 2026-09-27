"""
Workflow CRUD — admin only.
"""

from __future__ import annotations

from urllib.parse import quote

import yaml
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity
from app.auth.users import current_superuser
from app.database import get_async_session
from app.detection.workflow_runner import parse_workflow_yaml
from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.models import AnalysisJob, LogType, User, WorkflowDef
from app.templates_config import templates
from app.yaml_utils import safe_load as yaml_safe_load

router = APIRouter(prefix="/workflows")


async def _demote_other_defaults(db: AsyncSession, keep_id: int | None = None) -> None:
    """Keep `is_default` single-valued across the table.

    The upload form pre-selects with `find(wf => wf.is_default)` over a name-ordered list,
    so a second default is never an error anybody sees — it just makes the pre-selection
    quietly depend on alphabetical order. Enforced here rather than as a partial unique
    index, which SQLite and PostgreSQL spell differently and which Alembic autogenerate
    would keep re-proposing against the parity test.
    """
    stmt = update(WorkflowDef).where(WorkflowDef.is_default.is_(True)).values(is_default=False)
    if keep_id is not None:
        stmt = stmt.where(WorkflowDef.id != keep_id)
    await db.execute(stmt)


@router.get("")
async def workflow_list(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """List all workflows. Admin only."""
    result = await db.execute(select(WorkflowDef).order_by(WorkflowDef.name))
    workflows = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "workflows/list.html",
        {
            "request": request,
            "user": user,
            "workflows": workflows,
            "error": request.query_params.get("error"),
        },
    )


@router.get("/new")
async def workflow_new(
    request: Request,
    user: User = Depends(current_superuser),
):
    """Render the new-workflow form. Admin only."""
    log_types = [t.value for t in LogType if t != LogType.UNKNOWN]
    return templates.TemplateResponse(
        request,
        "workflows/edit.html",
        {
            "request": request,
            "user": user,
            "workflow": None,
            "log_types": log_types,
            "default_yaml": _DEFAULT_YAML,
        },
    )


@router.post("/new")
async def workflow_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    log_types: list[str] = Form(default=[]),
    tasks_yaml: str = Form(...),
    is_default: bool = Form(False),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Validate and persist a new workflow definition. Admin only."""
    _validate_yaml(tasks_yaml)
    await _refuse_a_taken_name(db, name)

    wf = WorkflowDef(
        name=name,
        description=description,
        log_types=json_dumps(log_types),
        tasks_yaml=tasks_yaml,
        is_default=is_default,
    )
    if is_default:
        await _demote_other_defaults(db)
    db.add(wf)
    await db.commit()
    await activity.record(
        "admin.workflow.create",
        request=request,
        user=user,
        target_type="workflow",
        target_id=str(wf.id),
        summary=name,
        meta={"log_types": log_types, "default": bool(is_default)},
    )
    return RedirectResponse("/workflows", status_code=303)


@router.get("/{wf_id}/edit")
async def workflow_edit(
    wf_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Render the edit form for an existing workflow. Admin only."""
    wf = await db.get(WorkflowDef, wf_id)
    if not wf:
        raise HTTPException(404)
    log_types = [t.value for t in LogType if t != LogType.UNKNOWN]
    wf_log_types = json_loads(wf.log_types or "[]")
    return templates.TemplateResponse(
        request,
        "workflows/edit.html",
        {
            "request": request,
            "user": user,
            "workflow": wf,
            "log_types": log_types,
            "wf_log_types": wf_log_types,
            "default_yaml": _DEFAULT_YAML,
        },
    )


@router.post("/{wf_id}/edit")
async def workflow_update(
    wf_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    log_types: list[str] = Form(default=[]),
    tasks_yaml: str = Form(...),
    is_default: bool = Form(False),
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Update an existing workflow definition. Admin only."""
    wf = await db.get(WorkflowDef, wf_id)
    if not wf:
        raise HTTPException(404)
    _validate_yaml(tasks_yaml)
    await _refuse_a_taken_name(db, name, keep_id=wf.id)

    # The field *names*, not their values: `tasks_yaml` is the whole task definition, and a
    # copy of it in every audit row would be both enormous and a second unmanaged copy of
    # something already stored. "Someone changed the tasks on the Windows workflow, here is
    # who and when" is what this record is for; the workflow itself holds the rest.
    incoming = {
        "name": name,
        "description": description,
        "log_types": json_dumps(log_types),
        "tasks_yaml": tasks_yaml,
        "is_default": is_default,
    }
    changed = sorted(key for key, value in incoming.items() if getattr(wf, key) != value)

    wf.name = name
    wf.description = description
    wf.log_types = json_dumps(log_types)
    wf.tasks_yaml = tasks_yaml
    wf.is_default = is_default
    if is_default:
        await _demote_other_defaults(db, keep_id=wf.id)
    await db.commit()
    await activity.record(
        "admin.workflow.update",
        request=request,
        user=user,
        target_type="workflow",
        target_id=str(wf.id),
        summary=f"{name} — {', '.join(changed)}" if changed else f"{name} — no change",
        # `fields`, not `changed`: the latter is a typed key meaning `{field: {from, to}}`,
        # which the activity table iterates with `.items()`. A list of names under that name
        # is a different fact and would render the whole log as a 500.
        meta={"fields": changed},
    )
    return RedirectResponse("/workflows", status_code=303)


@router.post("/{wf_id}/delete")
async def workflow_delete(
    wf_id: int,
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Delete a workflow definition. Admin only.

    Refused while any job ran it: `analysisjob.workflow_id` is NOT NULL, so the delete could
    only ever fail (a 500 for every workflow that had done anything), and deleting the jobs
    to make room would erase history nobody asked to lose.
    """
    wf = await db.get(WorkflowDef, wf_id)
    if not wf:
        raise HTTPException(404)
    jobs = await db.scalar(select(func.count(AnalysisJob.id)).where(AnalysisJob.workflow_id == wf_id)) or 0
    if jobs:
        message = f"'{wf.name}' was used by {jobs} job{'s' if jobs != 1 else ''}, so it cannot be deleted. Edit it instead, or delete those jobs first."
        return RedirectResponse(f"/workflows?error={quote(message)}", status_code=303)
    # Read the name before the delete — after it, the row that would explain the event is
    # exactly the row that is gone. `target_id` is a plain string for the same reason.
    name = wf.name
    await db.delete(wf)
    await db.commit()
    await activity.record(
        "admin.workflow.delete",
        request=request,
        user=user,
        target_type="workflow",
        target_id=str(wf_id),
        summary=name,
    )
    return RedirectResponse("/workflows", status_code=303)


# ── Helpers ─────────────────────────────────────────────────────────────────────


async def _refuse_a_taken_name(db: AsyncSession, name: str, *, keep_id: int | None = None) -> None:
    """400 for a name another workflow has, rather than the unique constraint's 500."""
    stmt = select(WorkflowDef.id).where(WorkflowDef.name == name)
    if keep_id is not None:
        stmt = stmt.where(WorkflowDef.id != keep_id)
    if await db.scalar(stmt.limit(1)):
        raise HTTPException(400, f"A workflow named '{name}' already exists.")


def _validate_yaml(tasks_yaml: str):
    try:
        data = yaml_safe_load(tasks_yaml)
        if not isinstance(data, dict) or "tasks" not in data:
            raise HTTPException(400, "YAML must contain a top-level 'tasks' key.")
        parse_workflow_yaml(tasks_yaml)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except yaml.YAMLError as exc:
        raise HTTPException(400, f"Invalid YAML: {exc}") from exc


_DEFAULT_YAML = """\
tasks:
  - tool: zircolite
    rules_path: sigma_rules/windows
    options:
      tmpdir: /tmp/logstotal

  - tool: chainsaw
    rules_path: sigma_rules/windows

  - tool: hayabusa
    rules_path: sigma_rules/windows
"""
