"""Compare persisted rule matches without loading event samples or raw outputs."""

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.constants import POST_TASK_NAMES, TERMINAL_JOB_STATUSES
from app.models import AnalysisJob, Finding, JobStatus, LogFile, TaskResult, TaskStatus, User, WorkflowDef, enum_val, visible_job_filter


def _comparison_baselines_query(current: AnalysisJob, user: User | None):
    """The eligible baselines, newest first, shared by actions and comparisons."""
    # Compare timestamps in the database: SQLite stores server defaults and
    # Python-bound datetimes with different fractional-second precision.
    current_time = select(AnalysisJob.created_at).where(AnalysisJob.id == current.id).scalar_subquery()
    return (
        select(AnalysisJob.id)
        .join(LogFile)
        .where(
            LogFile.sha256 == current.log_file.sha256,
            AnalysisJob.status.in_([JobStatus(s) for s in TERMINAL_JOB_STATUSES]),
            or_(AnalysisJob.created_at < current_time, and_(AnalysisJob.created_at == current_time, AnalysisJob.id < current.id)),
            visible_job_filter(user),
        )
        .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
    )


async def comparison_baseline_id(db: AsyncSession, current: AnalysisJob, user: User | None) -> int | None:
    """Find the previous visible terminal run without loading all choices."""
    if enum_val(current.status) not in TERMINAL_JOB_STATUSES:
        return None
    return await db.scalar(_comparison_baselines_query(current, user).limit(1))


async def comparison_baselines(db: AsyncSession, current: AnalysisJob, user: User | None) -> list[dict]:
    """Lightweight labels for eligible choices; no findings or event data."""
    if enum_val(current.status) not in TERMINAL_JOB_STATUSES:
        return []
    query = (
        _comparison_baselines_query(current, user)
        .add_columns(AnalysisJob.created_at, AnalysisJob.status, WorkflowDef.name.label("workflow_name"))
        .join(WorkflowDef, WorkflowDef.id == AnalysisJob.workflow_id)
    )
    return [dict(row) for row in (await db.execute(query)).mappings()]


async def compare_findings_page(db: AsyncSession, baseline_id: int, current_id: int, *, page: int, per_page: int) -> dict:
    """Page identities in SQL, then aggregate only those rules from both runs.

    The number of rows transferred is bounded by page size times two runs times severity
    levels, even when a rule appears in multiple tasks. No finding blobs or ORM
    finding instances are loaded. Callers must authorize both jobs first.
    """
    has_id = and_(Finding.rule_id.is_not(None), Finding.rule_id != "")
    kind = case((has_id, "id"), else_="title").label("kind")
    identity = case((has_id, Finding.rule_id), else_=Finding.rule_name).label("identity")
    scope = (TaskResult.job_id.in_([baseline_id, current_id]), TaskResult.tool_name.not_in(POST_TASK_NAMES))
    keys = select(TaskResult.tool_name, kind, identity).join(Finding, Finding.task_result_id == TaskResult.id).where(*scope).distinct()
    total = await db.scalar(select(func.count()).select_from(keys.subquery()))
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    result = {"rows": [], "total": total, "page": page, "pages": pages, "per_page": per_page}
    if not total:
        return result
    selected = keys.order_by(TaskResult.tool_name, kind, identity).offset((page - 1) * per_page).limit(per_page).cte("page_rules")
    # Match task-first ordering even when parallel tasks finish in a different
    # order. A different insertion order must not create a title change.
    matched = (
        select(
            TaskResult.job_id,
            TaskResult.tool_name,
            kind,
            identity,
            Finding.severity,
            Finding.count,
            func.first_value(Finding.id)
            .over(
                partition_by=[TaskResult.job_id, TaskResult.tool_name, kind, identity],
                order_by=[TaskResult.id, Finding.id],
            )
            .label("first_id"),
        )
        .join(Finding, Finding.task_result_id == TaskResult.id)
        .join(selected, and_(TaskResult.tool_name == selected.c.tool_name, kind == selected.c.kind, identity == selected.c.identity))
        .where(*scope)
        .subquery()
    )
    grouped = (
        select(
            matched.c.job_id,
            matched.c.tool_name,
            matched.c.kind,
            matched.c.identity,
            matched.c.severity,
            func.sum(matched.c.count).label("count"),
            func.min(matched.c.first_id).label("first_id"),
        )
        .group_by(matched.c.job_id, matched.c.tool_name, matched.c.kind, matched.c.identity, matched.c.severity)
        .subquery()
    )
    first = aliased(Finding)
    query = (
        select(grouped, first.rule_name, first.rule_id)
        .join(first, first.id == grouped.c.first_id)
        .order_by(grouped.c.tool_name, grouped.c.kind, grouped.c.identity, grouped.c.first_id)
    )
    old, new = {}, {}
    for row in (await db.execute(query)).mappings():
        groups = old if row["job_id"] == baseline_id else new
        key = (row["tool_name"], row["kind"], row["identity"])
        group = groups.setdefault(key, {"title": row["rule_name"], "rule_id": row["rule_id"], "count": 0, "severities": {}})
        group["count"] += row["count"]
        group["severities"][enum_val(row["severity"])] = row["count"]
    # Include tasks with zero findings: they determine whether an absent rule
    # means "no longer observed" or simply that the engine did not finish.
    availability = await db.execute(
        select(TaskResult.job_id, TaskResult.tool_name, func.min(case((TaskResult.status == TaskStatus.COMPLETED, 1), else_=0)))
        .where(*scope)
        .group_by(TaskResult.job_id, TaskResult.tool_name)
    )
    available = {(job_id, tool): bool(complete) for job_id, tool, complete in availability}

    for key in sorted(old.keys() | new.keys()):
        before, after = old.get(key), new.get(key)
        comparable = available.get((baseline_id, key[0]), False) and available.get((current_id, key[0]), False)
        if not comparable:
            change = "Not comparable"
        elif before is None:
            change = "Added"
        elif after is None:
            change = "No longer observed"
        elif any(before[k] != after[k] for k in ("title", "count", "severities")):
            change = "Changed"
        else:
            change = "Unchanged"
        result["rows"].append({"tool": key[0], "title": (after or before)["title"], "rule_id": (after or before)["rule_id"], "change": change, "before": before, "after": after})
    return result
