"""Case evidence selection and saved-report access, shared by routes and workers."""

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import load_only

from app.ai.case_digest import MAX_CASE_LINKS, build_case_digest, render_case_prompt
from app.ai.digest import MAX_FINDINGS, build_job_digest
from app.config import settings
from app.constants import AI_ELIGIBLE_JOB_STATUSES
from app.json_utils import dumps, loads
from app.models import (
    AiProvider,
    AnalysisJob,
    CaseAiAnalysis,
    CaseEntityLink,
    CaseJobLink,
    Entity,
    Finding,
    InvestigationCase,
    JobStatus,
    SiteSettings,
    TaskResult,
    User,
    can_view_job,
    enum_val,
    has_intel_access,
    severity_rank_sql,
    visible_case_filter,
    visible_job_filter,
)


def eligible_jobs(case_id, user):
    return (
        select(AnalysisJob)
        .join(CaseJobLink, CaseJobLink.job_id == AnalysisJob.id)
        .where(
            CaseJobLink.case_id == case_id,
            visible_job_filter(user),
            AnalysisJob.status.in_([JobStatus(s) for s in AI_ELIGIBLE_JOB_STATUSES]),
        )
    )


def evidence_exists(case_id, user):
    return select(eligible_jobs(case_id, user).exists() | select(CaseEntityLink.id).join(Entity).where(CaseEntityLink.case_id == case_id).exists())


def source_identity(job):
    # IDs can be reused after deletion on SQLite. Check the original creation time and
    # file identity as well, rather than granting access to a different replacement job.
    return {"id": job.id, "file_id": job.file_id, "created_at": job.created_at.isoformat() if job.created_at else None}


def source_manifest(analysis):
    if analysis.source_jobs_json is None:
        return None
    try:
        value = loads(analysis.source_jobs_json)
        if not isinstance(value, list) or any(not isinstance(s, dict) or type(s.get("id")) is not int for s in value):
            return None
        return value
    except (ValueError, TypeError):
        return None


def invalidate_case_sources(job_id):
    """Keep reports restricted after SQLite reuses a deleted job ID.

    Our source manifest contains only identity dictionaries, never free-form evidence.
    Match a complete integer plus its following comma, in either json_utils encoding
    (orjson or the stdlib fallback). The original provenance remains intact for admins.
    """
    return (
        update(CaseAiAnalysis)
        .where(
            CaseAiAnalysis.source_deleted_at.is_(None),
            or_(CaseAiAnalysis.source_jobs_json.contains(f'"id":{job_id},'), CaseAiAnalysis.source_jobs_json.contains(f'"id": {job_id},')),
        )
        .values(source_deleted_at=func.now())
    )


async def readable_runs(db, runs, user):
    """Never return even a history label for a run with inaccessible evidence."""
    if user.is_superuser:
        return list(runs)
    manifests = {r.id: source_manifest(r) for r in runs}
    ids = {s["id"] for manifest in manifests.values() if manifest is not None for s in manifest}
    jobs = {}
    if ids:
        rows = await db.execute(
            select(AnalysisJob)
            .options(load_only(AnalysisJob.id, AnalysisJob.file_id, AnalysisJob.created_at, AnalysisJob.is_private, AnalysisJob.submitted_by_user_id))
            .where(AnalysisJob.id.in_(ids))
        )
        jobs = {job.id: job for job in rows.scalars()}
    result = []
    for run in runs:
        if run.source_deleted_at is not None:
            continue
        manifest = manifests[run.id]
        if manifest is None:
            if run.source_jobs_json is None and run.requested_by_user_id == user.id:
                result.append(run)
        elif all(s["id"] in jobs and source_identity(jobs[s["id"]]) == s and can_view_job(jobs[s["id"]], user) for s in manifest):
            result.append(run)
    return result


def case_send_allowed(db, analysis):
    """Recheck current access after building the snapshot, immediately before inference."""
    requester = db.scalar(select(User).where(User.id == analysis.requested_by_user_id).execution_options(populate_existing=True))
    if not has_intel_access(requester):
        return False
    if not db.scalar(select(SiteSettings.show_ai_analysis).where(SiteSettings.id == 1)):
        return False
    if not db.scalar(select(AiProvider.enabled).where(AiProvider.id == analysis.provider_id)):
        return False
    if not db.scalar(select(InvestigationCase.id).where(InvestigationCase.id == analysis.case_id, visible_case_filter(requester))):
        return False
    # This marker also catches deletion followed by an indistinguishable replacement
    # while the brief was being prepared.
    if db.scalar(select(CaseAiAnalysis.source_deleted_at).where(CaseAiAnalysis.id == analysis.id)) is not None:
        return False
    sources = source_manifest(analysis)
    if sources is None:
        return False
    ids = [s["id"] for s in sources]
    jobs = {j.id: j for j in db.scalars(select(AnalysisJob).where(AnalysisJob.id.in_(ids)).execution_options(populate_existing=True))}
    return all(s["id"] in jobs and source_identity(jobs[s["id"]]) == s and can_view_job(jobs[s["id"]], requester) for s in sources)


def _json(raw, default):
    try:
        value = loads(raw or "null")
        return value if isinstance(value, type(default)) else default
    except (ValueError, TypeError):
        return default


def prepare_case_evidence(db, case, user, *, max_chars: int | None = None):
    """Bound SQL before loading event details; sample fairly within each severity.

    The extra job used to detect truncation is also a source: even that omission notice
    depends on its existence. Global entity counts/relationships are never read.
    """
    # Keep source rows alive until the worker commits their provenance. PostgreSQL
    # takes shared row locks; SQLite protects the subsequent write with its transaction.
    all_jobs = list(db.scalars(eligible_jobs(case.id, user).order_by(AnalysisJob.id).limit(MAX_CASE_LINKS + 1).with_for_update(read=True, of=AnalysisJob)))
    jobs = all_jobs[:MAX_CASE_LINKS]
    entity_rows = db.execute(
        select(Entity.id, Entity.entity_type, Entity.value, CaseEntityLink.note)
        .join(CaseEntityLink, CaseEntityLink.entity_id == Entity.id)
        .where(CaseEntityLink.case_id == case.id)
        .order_by(CaseEntityLink.id)
        .limit(MAX_CASE_LINKS + 1)
    ).all()
    if not jobs and not entity_rows:
        raise ValueError("Add a completed or partial job, or an entity, before running an analysis.")
    job_ids = [j.id for j in jobs]
    notes = dict(db.execute(select(CaseJobLink.job_id, CaseJobLink.note).where(CaseJobLink.case_id == case.id, CaseJobLink.job_id.in_(job_ids))).all())
    job_context = []
    for job in jobs:
        analytics = _json(job.analytics_json, {})
        digest = build_job_digest(job={}, findings=[], analytics=analytics)
        job_context.append(
            {
                "job_id": job.id,
                "filename": (job.filename or "")[:300],
                "status": enum_val(job.status),
                "analyst_link_note": (notes.get(job.id) or "")[:500],
                "severity_summary": _json(job.severity_summary, {}),
                "observables": digest["entities"],
                "mitre_tactics": digest["mitre_tactics"],
            }
        )
    total = 0
    findings = []
    if job_ids:
        scope = (
            select(
                Finding.id,
                TaskResult.job_id,
                severity_rank_sql().label("severity_rank"),
                func.row_number().over(partition_by=(TaskResult.job_id, Finding.severity), order_by=(Finding.count.desc(), Finding.id)).label("position"),
            )
            .join(TaskResult)
            .where(TaskResult.job_id.in_(job_ids))
            .subquery()
        )
        selected = select(scope.c.id).order_by(scope.c.severity_rank, scope.c.position, scope.c.job_id, scope.c.id).limit(MAX_FINDINGS)
        total = db.scalar(select(func.count()).select_from(Finding).join(TaskResult).where(TaskResult.job_id.in_(job_ids))) or 0
        rows = db.execute(select(Finding, Finding.details, TaskResult.job_id, TaskResult.tool_name).join(TaskResult).where(Finding.id.in_(selected))).all()
        by_id = {
            f.id: {
                "id": f.id,
                "job_id": jid,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": enum_val(f.severity),
                "count": f.count,
                "tool": tool,
                "tags": _json(f.tags, []),
                "events": _json(details, []),
            }
            for f, details, jid, tool in rows
        }
        findings = [by_id[fid] for fid in db.scalars(selected)]
    digest = build_case_digest(
        case={k: getattr(case, k) for k in ("name", "summary", "notes", "status", "severity")},
        jobs=job_context,
        entities=[{"entity_id": e.id, "type": e.entity_type, "value": e.value[:200], "analyst_link_note": (e.note or "")[:500]} for e in entity_rows[:MAX_CASE_LINKS]],
        findings=findings,
        findings_total=total,
        links_truncated=len(all_jobs) > MAX_CASE_LINKS or len(entity_rows) > MAX_CASE_LINKS,
    )
    prompt, meta = render_case_prompt(digest, max_chars=settings.ai_max_prompt_chars if max_chars is None else max_chars)
    return prompt, meta, dumps([source_identity(j) for j in all_jobs])
