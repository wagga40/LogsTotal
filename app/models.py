"""SQLAlchemy ORM models for LogsTotal — users, files, workflows, jobs, findings."""

import enum
from datetime import datetime

from fastapi_users_db_sqlalchemy import SQLAlchemyBaseUserTableUUID
from fastapi_users_db_sqlalchemy.generics import GUID
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import column_property, deferred, relationship

from app.database import Base


def enum_val(e) -> str:
    """Extract string value from an enum (or pass through str)."""
    return e.value if isinstance(e, enum.Enum) else str(e)


def visible_job_filter(user):
    """SQLAlchemy WHERE clause that hides private jobs from non-owners.

    Returns the Python literal ``True`` (an all-pass filter) for admins so
    callers may skip applying it. Shared by every surface that joins to
    ``AnalysisJob`` for a specific viewer — jobs list, similarity, correlation,
    intel entity/relationship listings, and cases — so private-job metadata
    never leaks cross-user. Mirrors ``routers.jobs._can_view_private`` at the
    query layer.
    """
    from sqlalchemy import or_

    if user is not None and getattr(user, "is_superuser", False):
        return True
    conditions = [AnalysisJob.is_private == False]  # noqa: E712
    if user is not None:
        conditions.append(AnalysisJob.submitted_by_user_id == user.id)
    return or_(*conditions)


def visible_case_filter(user):
    """SQLAlchemy WHERE clause limiting cases to own + shared.

    Returns the Python literal ``True`` (an all-pass filter) for admins so callers
    may skip applying it — same contract as :func:`visible_job_filter`. Shared by
    the cases router and by the "which cases is this in?" backlinks on entity and
    job detail, so an unshared case never leaks its name to a non-owner.
    """
    from sqlalchemy import or_

    if user is not None and getattr(user, "is_superuser", False):
        return True
    conditions = [InvestigationCase.is_shared == True]  # noqa: E712
    if user is not None:
        conditions.append(InvestigationCase.created_by_user_id == user.id)
    return or_(*conditions)


def can_view_job(job, user) -> bool:
    """Scalar counterpart of :func:`visible_job_filter` for an in-hand job row."""
    if job is None or not getattr(job, "is_private", False):
        return True
    if user is None:
        return False
    if getattr(user, "is_superuser", False):
        return True
    return job.submitted_by_user_id == user.id


def has_intel_access(user) -> bool:
    """Whether an account may use Intel right now: active, and member or above.

    The scalar form of what `current_member_or_above` enforces on a request, for the code
    that acts on an account's behalf with no request in hand — a watch rule evaluated in
    the worker, a Bearer token delegating its creator's access. Deactivating or demoting an
    account has to stop those as surely as it stops the login.
    """
    if user is None or not getattr(user, "is_active", False):
        return False
    return bool(getattr(user, "is_superuser", False)) or getattr(user, "role", "") in ("admin", "member")


def severity_rank_sql():
    """ORDER BY / MIN() expression that ranks findings most-severe first.

    ``Column(Enum(Severity))`` stores the member *name*, so a plain ``ORDER BY severity``
    sorts alphabetically — CRITICAL, HIGH, INFORMATIONAL, LOW, MEDIUM — and puts
    `informational` above `low` and `medium`. Every severity sort in SQL should go through
    this so the ordering matches ``SEVERITY_ORDER`` and stays right if a level is added.

    **The cast is what makes this work on PostgreSQL**; without it every surface that ranks
    findings — the entity Findings tab, the entity graph, the case roll-up — would 500. On
    PostgreSQL ``Enum`` is a real enum *type*; the ``WHEN`` values here are
    plain Python strings with no type context, so they bind as ``character varying`` and the
    comparison fails with ``operator does not exist: severity = character varying``. SQLite
    stores the column as VARCHAR and never notices.

    It is invisible to the test suite twice over: every test runs on SQLite, and the two
    dialects compile this to *byte-identical SQL text* — the difference is only in the bind
    parameter's type, which `literal_binds` erases. Comparing text to text is right on both
    backends; `tests/test_postgres_sql_compat.py` executes it against a real PostgreSQL.
    """
    from sqlalchemy import String, cast
    from sqlalchemy import case as _case

    from app.constants import SEVERITY_ORDER

    return _case(
        {level.upper(): rank for rank, level in enumerate(SEVERITY_ORDER)},
        value=cast(Finding.severity, String),
        else_=len(SEVERITY_ORDER),
    )


# ── Enums ───────────────────────────────────────────────────────────────────────


class LogType(str, enum.Enum):
    """Supported log file formats for type detection."""

    EVTX = "evtx"
    JSON_EVTX = "json_evtx"
    JSON_WINLOGBEAT = "json_winlogbeat"
    XML_EVTX = "xml_evtx"
    AUDITD = "auditd"
    SYSLOG = "syslog"
    JOURNALD = "journald"
    SYSMON_LINUX = "sysmon_linux"
    UNKNOWN = "unknown"


class JobStatus(str, enum.Enum):
    """Lifecycle states for an analysis job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


class TaskStatus(str, enum.Enum):
    """Lifecycle states for a single tool execution within a job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    """Finding severity levels, ordered from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ── User ────────────────────────────────────────────────────────────────────────


class User(SQLAlchemyBaseUserTableUUID, Base):
    """Application user; extends FastAPI-Users base with display_name and role."""

    __tablename__ = "user"

    display_name: str | None = Column(String(100), nullable=True)
    role: str = Column(String(20), nullable=False, default="user")
    created_at: datetime = Column(DateTime, nullable=False, server_default=func.now())


# ── Log File ─────────────────────────────────────────────────────────────────────


class LogFile(Base):
    """An uploaded log file with SHA-256 hash and optional TLSH for similarity."""

    __tablename__ = "logfile"

    id = Column(Integer, primary_key=True, autoincrement=True)
    original_filename = Column(String(512), nullable=False)
    stored_filename = Column(String(512), nullable=False, unique=True)
    sha256 = Column(String(64), nullable=False, index=True)
    size_bytes = Column(Integer, nullable=False)
    log_type = Column(Enum(LogType), nullable=False, default=LogType.UNKNOWN)
    detected_type = Column(Enum(LogType), nullable=True)  # auto-detected value
    uploaded_at = Column(DateTime, nullable=False, server_default=func.now())
    uploader_ip = Column(String(45), nullable=True)
    tlsh_hash = Column(String(72), nullable=True, index=True)

    jobs = relationship("AnalysisJob", back_populates="log_file")


# ── Workflow Definition ───────────────────────────────────────────────────────────


class WorkflowDef(Base):
    """A YAML-defined detection workflow — an ordered list of tool tasks."""

    __tablename__ = "workflowdef"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    log_types = Column(Text, nullable=False, default="[]")  # JSON array of LogType values
    tasks_yaml = Column(Text, nullable=False, default="tasks: []")
    is_default = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    jobs = relationship("AnalysisJob", back_populates="workflow")


# ── Analysis Job ─────────────────────────────────────────────────────────────────


class AnalysisJob(Base):
    """A single analysis run: one file through one workflow."""

    __tablename__ = "analysisjob"

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_id = Column(Integer, ForeignKey("logfile.id"), nullable=False, index=True)
    workflow_id = Column(Integer, ForeignKey("workflowdef.id"), nullable=False, index=True)
    submitted_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True, index=True)
    submitter_ip = Column(String(45), nullable=True)
    # Submission metadata must never be inherited from another uploader's shared file.
    submitted_filename = Column(String(512), nullable=True)
    effective_log_type = Column(Enum(LogType), nullable=False, default=LogType.UNKNOWN, server_default="UNKNOWN")
    _legacy_filename = column_property(select("upload-" + func.substr(LogFile.sha256, 1, 12)).where(LogFile.id == file_id).correlate_except(LogFile).scalar_subquery())

    @hybrid_property
    def filename(self):
        return self.submitted_filename if self.submitted_filename is not None else self._legacy_filename

    @filename.expression
    def filename(cls):
        return func.coalesce(cls.submitted_filename, cls._legacy_filename)

    status = Column(Enum(JobStatus), nullable=False, default=JobStatus.PENDING, index=True)
    score_ratio = Column(String(20), nullable=True)  # e.g. "2/3"
    total_findings = Column(Integer, nullable=True, default=0)
    severity_summary = Column(Text, nullable=True)  # JSON: {critical:5, high:3, ...}
    created_at = Column(DateTime, nullable=False, server_default=func.now(), index=True)
    finished_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    analytics_json = Column(Text, nullable=True)  # JSON: analytics_json_payload(_compute_analytics_data(job))
    # Indexed as the leading column of visible_job_filter's predicate — it appears in
    # essentially every job query the application makes.
    is_private = Column(Boolean, nullable=False, default=False, server_default="0", index=True)
    # gzip(orjson(app.intel.event_markers.build_index(...))) — the zoomable events timeline.
    # DEFERRED, and that is load-bearing: ~16 call sites do a wholesale select(AnalysisJob),
    # including the 100-row jobs list, where an eager blob would add megabytes per render.
    # Never read this off an ORM instance either — touching a deferred attribute on a
    # detached object raises MissingGreenlet under async SQLAlchemy. Query the column
    # explicitly: select(AnalysisJob.event_markers).where(AnalysisJob.id == ...).
    event_markers = deferred(Column(LargeBinary, nullable=True))

    log_file = relationship("LogFile", back_populates="jobs")
    workflow = relationship("WorkflowDef", back_populates="jobs")
    submitter = relationship("User", foreign_keys=[submitted_by_user_id])
    task_results = relationship("TaskResult", back_populates="job", cascade="all, delete-orphan")
    comments = relationship("Comment", cascade="all, delete-orphan", foreign_keys="Comment.job_id")
    ai_analyses = relationship("JobAiAnalysis", cascade="all, delete-orphan", foreign_keys="JobAiAnalysis.job_id")
    # Analyst tags. NOT `Finding.tags`, which is a JSON string of SIGMA rule tags — see JobTag.
    tags = relationship("JobTag", back_populates="job", cascade="all, delete-orphan")


# ── Task Result ───────────────────────────────────────────────────────────────────


class TaskResult(Base):
    """Result of running a single detection tool within a job."""

    __tablename__ = "taskresult"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    status = Column(Enum(TaskStatus), nullable=False, default=TaskStatus.PENDING)
    findings_count = Column(Integer, nullable=False, default=0)
    duration_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    log_output = Column(Text, nullable=True)  # combined stdout + stderr from tool
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    job = relationship("AnalysisJob", back_populates="task_results")
    findings = relationship("Finding", back_populates="task_result", cascade="all, delete-orphan")


# ── Site Settings ─────────────────────────────────────────────────────────────────


class SiteSettings(Base):
    """Single-row config table (always id=1). Created on first access."""

    __tablename__ = "sitesettings"

    id = Column(Integer, primary_key=True, default=1)
    parallel_execution = Column(Boolean, nullable=False, default=False)
    max_finding_details = Column(Integer, nullable=False, default=10)
    max_upload_files = Column(Integer, nullable=False, default=50, server_default="50")
    show_mitre_heatmap = Column(Boolean, nullable=False, default=True)
    # Two timelines, two switches. `show_event_timeline` gates the hourly activity histogram
    # and `show_alert_timeline` the zoomable per-alert view, so either can be kept without
    # the other. They answer different questions and are bucketed differently (the
    # histogram preserves each tool's own UTC offset; the alert timeline normalises).
    show_event_timeline = Column(Boolean, nullable=False, default=True)
    show_alert_timeline = Column(Boolean, nullable=False, default=True)
    show_entities = Column(Boolean, nullable=False, default=True)
    show_threat_detection = Column(Boolean, nullable=False, default=True)
    show_process_tree = Column(Boolean, nullable=False, default=True)
    # The shipped label vocabulary — `lolbin`, `privileged`, `rfc1918` and the rest —
    # evaluated as rules and applied as tags. On by default: the labels are part of what an
    # instance shows out of the box.
    #
    # One switch above the individual rule toggles, and it gates the *evaluation*, which is
    # where the cost is: labelling is the one thing in this app that writes a row per entity
    # per job. An operator who does not want that growth in `entity_tag` should be able to
    # stop it with one click rather than one per rule.
    builtin_rules_enabled = Column(Boolean, nullable=False, default=True)
    # Analyst prose — case notes, entity notes and every comment thread — rendered as
    # Markdown. Off means plain `whitespace-pre-wrap` rendering; the stored text is untouched
    # either way, so this is purely a display choice and can be flipped back with nothing lost.
    render_markdown = Column(Boolean, nullable=False, default=True)
    # Off by default, unlike every other switch here: the AI Analysis tab is meaningless
    # until an admin has configured a provider on /admin/ai, and a tab whose only content
    # is "ask your administrator" is worse than no tab. Turning it on is the second half
    # of setting the feature up, not a thing to undo.
    show_ai_analysis = Column(Boolean, nullable=False, default=False)
    # Keep the exact brief each run sent, so an admin can read what actually left the
    # instance rather than infer it. On by default — the data is already in the job, the
    # prompt only rearranges it, and "what did we send them?" has no other answer.
    #
    # It gates **storage**, not just display. Off means the column is never written, which
    # is the only reading of "off" that is worth anything to someone turning it off for
    # data-handling reasons; a display-only switch would keep hoarding tens of kilobytes
    # per run and call it private. Existing prompts are also hidden while it is off.
    show_ai_prompt = Column(Boolean, nullable=False, default=True)
    # Record who did what, into `activity_event`. Off by default, like `show_ai_analysis`
    # and for the same class of reason: it stores actor emails and client IPs, which is a
    # data-handling decision an operator should make deliberately rather than inherit.
    #
    # It gates **writes only**, and here it deliberately diverges from `show_ai_prompt`,
    # which also hides what it already stored. The reason to turn an audit trail off is
    # normally "stop recording my users' IPs" — and for that the answer is Prune, not
    # concealment. An operator must always be able to read what was already captured.
    activity_log_enabled = Column(Boolean, nullable=False, default=False)
    # Which categories are captured, as a CSV of `app/activity.py::CATEGORIES`. One column
    # rather than five booleans: the set is a property of the log, not five independent
    # switches, and one column is one migration, one docs row and one form field group.
    # NULL or empty means every category — the useful default for "I just turned it on".
    activity_categories = Column(String(200), nullable=True)
    # Retention override, edited on /admin/storage rather than /admin/settings.
    #
    # NULLABLE, and that is the whole design: NULL means "use JOB_OUTPUT_RETENTION_DAYS", so
    # an operator who sets the env var in .env is not silently ignored. Only this one window
    # is overridable — the other prune windows stay env-only, because this is the one anyone
    # actually turns.
    job_output_retention_days_override = Column(Integer, nullable=True)
    demo_mode = Column(Boolean, nullable=False, default=False)


# ── Finding ───────────────────────────────────────────────────────────────────────


class Finding(Base):
    """A single detection finding (rule match) produced by a tool."""

    __tablename__ = "finding"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_result_id = Column(Integer, ForeignKey("taskresult.id"), nullable=False, index=True)
    rule_id = Column(String(100), nullable=True)
    rule_name = Column(String(500), nullable=False)
    severity = Column(Enum(Severity), nullable=False, default=Severity.INFORMATIONAL)
    count = Column(Integer, nullable=False, default=1)
    tags = Column(Text, nullable=True)  # JSON array: ["attack.t1234", ...]
    rule_signature = Column(String(200), nullable=True, index=True)  # "{rule_id_or_slug}:{severity}"

    # The two blobs, both `deferred()`. A finding's sample events and its Sigma rule YAML
    # are each easily kilobytes, there is one row per rule match per task per job, and the
    # 3-second job-status poll eager-loads every finding of the job — while using
    # `details` only as a *boolean* and `rule_content` not at all. Loading them there would
    # be the largest avoidable read in the application, repeated every three seconds for the
    # life of a running job.
    #
    # Deferring means an access on an attached instance issues its own SELECT, which under
    # async SQLAlchemy raises `MissingGreenlet` — so the two loaders that genuinely want them
    # say `undefer()` explicitly: `_load_finding_job` (/jobs/findings/{id}/rule and /events)
    # and `_load_job_full(with_blobs=True)` (/jobs/{id}/findings.json). The case timeline
    # selects `Finding.details` as a plain column, which mapper-level deferral does not apply
    # to. That is the point: it is visible at the query which callers pay for the blob.
    details = deferred(Column(Text, nullable=True))  # JSON array of matched events (truncated)
    rule_content = deferred(Column(Text, nullable=True))  # original Sigma rule YAML

    __table_args__ = (
        # Both are GROUP BY / WHERE keys in the per-job and per-case roll-ups, which run on
        # the largest table in the schema (one row per rule match, per task, per job).
        # Led by task_result_id so they also serve the "this job's findings" path that
        # every roll-up starts from.
        Index("ix_finding_task_severity", "task_result_id", "severity"),
        Index("ix_finding_task_rule_name", "task_result_id", "rule_name"),
    )

    task_result = relationship("TaskResult", back_populates="findings")


# "Does this finding have sample events?" without reading them. Declared out of the class
# body so `details` names its Column exactly once (declaring both there makes SQLAlchemy
# warn that one of the two names will be ignored). Selected eagerly, so the job page's
# per-finding "Show events" toggle costs nothing and never touches the deferred blob.
# `routers/intel.py` uses the same mapped property.
Finding.has_details = column_property(func.coalesce(Finding.__table__.c.details, "") != "")


# ── Intel Entities ────────────────────────────────────────────────────────────


class Entity(Base):
    """A deduplicated observable entity extracted from log analysis (IP, user, hash, etc.)."""

    __tablename__ = "entity"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String(500), nullable=False)
    entity_type = Column(String(20), nullable=False, index=True)
    first_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    job_count = Column(Integer, nullable=False, default=0)
    watchlist = Column(Boolean, nullable=False, default=False, server_default="0", index=True)
    allowlisted = Column(Boolean, nullable=False, default=False, server_default="0", index=True)
    notes = Column(Text, nullable=True)
    attributes_json = Column(Text, nullable=True)  # per-type context dict (see app/intel/attributes.py)

    __table_args__ = (
        UniqueConstraint("value", "entity_type", name="uq_entity_value_type"),
        # ORDER BY last_seen_at DESC is the Intel dashboard's default sort and the IOC
        # feed's ordering — without this it is a filesort over the whole entity table on
        # every load of the busiest page in Intel.
        Index("ix_entity_last_seen", "last_seen_at"),
    )

    job_links = relationship("EntityJobLink", back_populates="entity", cascade="all, delete-orphan")
    tags = relationship("EntityTag", back_populates="entity", cascade="all, delete-orphan")
    finding_links = relationship("FindingEntityLink", back_populates="entity", cascade="all, delete-orphan")
    case_links = relationship("CaseEntityLink", back_populates="entity", cascade="all, delete-orphan")
    comments = relationship("Comment", cascade="all, delete-orphan", foreign_keys="Comment.entity_id")


class EntityJobLink(Base):
    """Links an entity to a specific analysis job with occurrence count."""

    __tablename__ = "entity_job_link"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_id = Column(Integer, ForeignKey("entity.id"), nullable=False, index=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    occurrence_count = Column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("entity_id", "job_id", name="uq_entity_job"),
        # Covering index for the relationship graph's self-joins. `uq_entity_job` leads with
        # `entity_id`, so "everything in this job" — the direction every co-occurrence query
        # walks (`a.job_id == b.job_id`, and the near-clique fanout guard's
        # `GROUP BY job_id`) — is a scan without this. At the graph's 5,000-node ceiling
        # that is the difference between a page load and a timeout.
        Index("ix_entity_job_link_job_entity", "job_id", "entity_id"),
    )

    entity = relationship("Entity", back_populates="job_links")
    job = relationship("AnalysisJob")


class EntityTag(Base):
    """Freeform analyst tag on an entity (e.g. 'apt28', 'reviewed', 'false-positive')."""

    __tablename__ = "entity_tag"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_id = Column(Integer, ForeignKey("entity.id"), nullable=False, index=True)
    # Indexed on its own: the uq_entity_tag composite leads with entity_id, so a
    # dashboard `WHERE tag IN (...)` pivot would otherwise be a full scan.
    tag = Column(String(50), nullable=False, index=True)
    color = Column(String(20), nullable=False, default="gray", server_default="gray")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    created_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)

    __table_args__ = (UniqueConstraint("entity_id", "tag", name="uq_entity_tag"),)

    entity = relationship("Entity", back_populates="tags")
    created_by = relationship("User", foreign_keys=[created_by_user_id])


class JobTag(Base):
    """The same analyst tag, on a job instead of an entity.

    A second link table rather than a polymorphic ``(target_type, target_id)`` pair — the
    `Comment` argument, for the same reasons: the target set is closed, so polymorphism
    would cost referential integrity and the ORM cascades and buy nothing.

    The **vocabulary is shared**: names and colours come from `TagDefinition`, so `apt29`
    is one thing with one colour whether it is on an entity or on a job. `app/tags.py` owns
    the writes that keep that true across both tables.

    Note this is unrelated to ``Finding.tags``, which is a JSON string of SIGMA rule tags.
    Two templates can render ``job.tags`` and ``finding.tags`` side by side and mean
    entirely different things.
    """

    __tablename__ = "job_tag"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    # Indexed on its own, for the same reason as EntityTag.tag: the uq_job_tag composite
    # leads with job_id, so a `WHERE tag IN (...)` filter on the jobs list would otherwise
    # be a full scan.
    tag = Column(String(50), nullable=False, index=True)
    color = Column(String(20), nullable=False, default="gray", server_default="gray")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    created_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)

    __table_args__ = (UniqueConstraint("job_id", "tag", name="uq_job_tag"),)

    job = relationship("AnalysisJob", back_populates="tags")
    created_by = relationship("User", foreign_keys=[created_by_user_id])


class JobWatch(Base):
    """One user's subscription to one job. The row *is* the subscription.

    Deliberately **not** an `IntelRule`. A watch rule is a *query* over entities — its
    criteria language only understands entity columns, and `IntelRuleMatch.entity_id` is
    NOT NULL. Making that nullable to carry job events would destroy the thing that makes
    it trustworthy: `uq_intel_rule_match(rule_id, entity_id, job_id)` is the idempotency
    guarantee, and both SQLite and PostgreSQL treat NULL as distinct in a UNIQUE index, so
    `(5, NULL, 42)` would insert without limit — for exactly the new rows and nowhere else.

    A watch is a subscription instead: no criteria, no evaluation pass, just "tell me when
    something happens here".
    """

    __tablename__ = "job_watch"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    user_id = Column(GUID(), ForeignKey("user.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    __table_args__ = (UniqueConstraint("job_id", "user_id", name="uq_job_watch"),)

    events = relationship("JobWatchEvent", cascade="all, delete-orphan")
    # Eager-loaded by the fan-out, which needs the User to run `can_view_job` — a lazy read
    # there is a MissingGreenlet on the async side and an extra query per watcher on both.
    user = relationship("User", foreign_keys=[user_id])


class JobWatchEvent(Base):
    """One notification: something happened on a job someone is watching.

    ``ref_id`` is **deliberately not a foreign key**. It points at whatever caused the
    event — a `Comment`, a `JobAiAnalysis`, a `JobTag` — and those can go: a tag is
    hard-deleted, a comment is soft-deleted. The event should survive as "this happened",
    the same reasoning as `ActivityEvent.target_type`/`target_id` being plain strings.

    (One consequence, accepted: SQLite reuses `max(id)+1`, so a deleted-then-recreated tag
    can collide with a past event's key and be suppressed. That suppresses noise, never
    data.)

    There is no ``acknowledged_by_user_id``. A watch belongs to exactly one user and only
    that user can acknowledge it, so the column would always equal ``watch.user_id`` —
    `IntelRuleMatch` needs one because admins see every rule.
    """

    __tablename__ = "job_watch_event"

    id = Column(Integer, primary_key=True, autoincrement=True)
    watch_id = Column(Integer, ForeignKey("job_watch.id"), nullable=False, index=True)
    # Denormalised from the watch so the bell can filter by job visibility without a
    # second join, and so cleanup on job deletion is one statement.
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    kind = Column(String(16), nullable=False)  # comment | ai | tag
    ref_id = Column(Integer, nullable=False)
    # A snapshot, like `JobAiAnalysis.provider_name`: the row stays readable after whatever
    # it describes is gone.
    summary = Column(String(200), nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now(), index=True)
    acknowledged_at = Column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("watch_id", "kind", "ref_id", name="uq_job_watch_event"),
        Index("ix_job_watch_event_watch_created", "watch_id", "created_at"),
    )


class FindingEntityLink(Base):
    """Denormalized link: which entities appear in which Finding (for fast reverse lookup)."""

    __tablename__ = "finding_entity_link"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("finding.id"), nullable=False, index=True)
    entity_id = Column(Integer, ForeignKey("entity.id"), nullable=False, index=True)

    __table_args__ = (UniqueConstraint("finding_id", "entity_id", name="uq_finding_entity"),)

    finding = relationship("Finding")
    entity = relationship("Entity", back_populates="finding_links")


class EntityRelationship(Base):
    """A first-class, evidence-backed directed edge between two entities.

    Captured at extraction time from co-present fields in a single event
    (e.g. Sysmon EID 1 ``Image`` + ``Hashes`` -> ``hashes_to``). Deduplicated
    across all jobs; ``occurrence_count`` is derived from the per-job
    ``EntityRelationshipEvidence`` rows, so re-running a job does not inflate it.
    See ``app/intel/relationships.py::RELATIONSHIP_TYPES``.
    """

    __tablename__ = "entity_relationship"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_entity_id = Column(Integer, ForeignKey("entity.id"), nullable=False, index=True)
    target_entity_id = Column(Integer, ForeignKey("entity.id"), nullable=False, index=True)
    relationship_type = Column(String(40), nullable=False, index=True)
    first_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    occurrence_count = Column(Integer, nullable=False, default=1)

    __table_args__ = (UniqueConstraint("source_entity_id", "target_entity_id", "relationship_type", name="uq_entity_relationship"),)

    source = relationship("Entity", foreign_keys=[source_entity_id])
    target = relationship("Entity", foreign_keys=[target_entity_id])


class EntityRelationshipEvidence(Base):
    """Per-job provenance for an ``EntityRelationship`` edge.

    Records, for each (relationship, job) pair, how many times the edge was
    observed in that job and a small capped sample of the actual events that
    formed it (``sample_events_json``). This is what lets the UI answer
    "which events / jobs back this relationship?" — the deduplicated
    ``EntityRelationship`` row carries no provenance on its own.

    Captured in the same analytics pass that extracts relationships; sample
    events are trimmed to a whitelist of fields (see
    ``app/intel/relationships.py::trim_evidence_event``).
    """

    __tablename__ = "entity_relationship_evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    relationship_id = Column(Integer, ForeignKey("entity_relationship.id"), nullable=False, index=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    occurrence_count = Column(Integer, nullable=False, default=1)
    first_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime, nullable=False, server_default=func.now())
    sample_events_json = Column(Text, nullable=True)  # capped JSON list of trimmed events

    __table_args__ = (UniqueConstraint("relationship_id", "job_id", name="uq_relationship_evidence"),)


# ── Worker Policy ─────────────────────────────────────────────────────────


class WorkerPolicy(Base):
    """Per-hostname concurrency cap controlling how many jobs a worker handles.

    max_concurrent_jobs: 0 = unlimited (default), -1 = paused, 1+ = cap.
    """

    __tablename__ = "worker_policy"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(200), nullable=False, unique=True, index=True)
    max_concurrent_jobs = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())


# ── Background Task ──────────────────────────────────────────────────────────


class BackgroundTaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    # A run an admin stopped. Distinct from FAILED because a cancelled backfill did what
    # it was told, and reporting it as a failure blames the platform for obeying — the
    # same argument `JobStatus.CANCELLED` settles for jobs.
    CANCELLED = "cancelled"


class BackgroundTask(Base):
    """Tracks non-job background tasks (backfills, maintenance) for admin visibility.

    ``kind`` is the stable key into ``app/task_registry.py`` — ``name`` is free-form display
    text, so it cannot be filtered or dispatched on. ``kind`` is what
    Retry looks up to know which task to enqueue.

    ``huey_task_id`` is the only way back from a row to its queue entry, which is what makes
    revoking a queued task possible at all.

    ``requested_by_label`` is a snapshot, **not** a foreign key. The task list wants a name,
    not a join, and the `JobAiAnalysis.provider_name` idiom keeps a row attributed after the
    account is gone. It also avoids another FK to ``user.id`` and the ``_USER_REFERENCES``
    entry that would come with it.

    ``heartbeat_at`` is what makes "recover a stuck task" possible: without it, a row left
    at ``running`` by a dead worker is indistinguishable from slow progress. Progress itself
    is written into the ``detail`` column at each batch
    commit rather than into new columns — every backfill loops ``WHERE id > last_id LIMIT n``
    with no total, so a `progress_total` would mean an extra `COUNT(*)` over the largest
    tables for a number that only decorates a bar.
    """

    __tablename__ = "backgroundtask"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    kind = Column(String(50), nullable=True, index=True)
    huey_task_id = Column(String(64), nullable=True, index=True)
    requested_by_label = Column(String(200), nullable=True)
    #: The single argument any of these tasks actually takes (a job id, for
    #: `recalculate_single_analytics`). A general `params_json` would be six empty columns.
    target_id = Column(String(64), nullable=True)
    status = Column(Enum(BackgroundTaskStatus), nullable=False, default=BackgroundTaskStatus.PENDING)
    detail = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    started_at = Column(DateTime, nullable=True)
    heartbeat_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)


# ── Investigation Cases ───────────────────────────────────────────────────────


class InvestigationCase(Base):
    """An analyst-curated grouping of entities + jobs forming a named investigation."""

    __tablename__ = "investigation_case"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    summary = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="open", server_default="open", index=True)
    severity = Column(String(20), nullable=True)
    # Both legs of visible_case_filter — every case query filters on one or the other.
    created_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True, index=True)
    is_shared = Column(Boolean, nullable=False, default=False, server_default="0", index=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
    closed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)  # running investigation narrative, 8000-char cap enforced in the route

    ai_analyses = relationship("CaseAiAnalysis", cascade="all, delete-orphan", foreign_keys="CaseAiAnalysis.case_id")
    entity_links = relationship("CaseEntityLink", back_populates="case", cascade="all, delete-orphan")
    job_links = relationship("CaseJobLink", back_populates="case", cascade="all, delete-orphan")
    comments = relationship("Comment", cascade="all, delete-orphan", foreign_keys="Comment.case_id")
    created_by = relationship("User", foreign_keys=[created_by_user_id])


class CaseEntityLink(Base):
    """Many-to-many: case ↔ entity, with audit info."""

    __tablename__ = "case_entity_link"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("investigation_case.id"), nullable=False, index=True)
    entity_id = Column(Integer, ForeignKey("entity.id"), nullable=False, index=True)
    added_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)
    added_at = Column(DateTime, nullable=False, server_default=func.now())
    note = Column(String(500), nullable=True)  # "why is this here"

    __table_args__ = (
        UniqueConstraint("case_id", "entity_id", name="uq_case_entity"),
        # The paged listing's access path verbatim: one case, newest first. Same shape as
        # `ix_comment_case_created` on Comment.
        Index("ix_case_entity_link_case_added", "case_id", "added_at"),
    )

    case = relationship("InvestigationCase", back_populates="entity_links")
    entity = relationship("Entity", back_populates="case_links")
    added_by = relationship("User", foreign_keys=[added_by_user_id])


class CaseJobLink(Base):
    """Many-to-many: case ↔ analysis job."""

    __tablename__ = "case_job_link"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("investigation_case.id"), nullable=False, index=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    added_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)
    added_at = Column(DateTime, nullable=False, server_default=func.now())
    note = Column(String(500), nullable=True)  # "why is this here"

    __table_args__ = (
        UniqueConstraint("case_id", "job_id", name="uq_case_job"),
        Index("ix_case_job_link_case_added", "case_id", "added_at"),
    )

    case = relationship("InvestigationCase", back_populates="job_links")
    job = relationship("AnalysisJob")
    added_by = relationship("User", foreign_keys=[added_by_user_id])


# ── Comments ──────────────────────────────────────────────────────────────────


class Comment(Base):
    """A discussion-thread comment on a case, an entity, or a job.

    Exactly one of ``case_id`` / ``entity_id`` / ``job_id`` is set, enforced by
    ``ck_comment_single_target``. Real FKs are used rather than a polymorphic
    ``(target_type, target_id)`` pair: the target set is closed at three, so
    polymorphism buys nothing and costs referential integrity plus the ORM cascade
    that makes ``await db.delete(case)`` / ``db.delete(job)`` clean up for free.

    NOTE: orphaned ``Entity`` rows are removed with a Core ``delete()`` in
    ``app/intel/entities.py::remove_entity_links_for_job_async`` — no ORM cascade
    fires there, so that function deletes matching Comment rows explicitly.

    Soft delete: ``deleted_at`` / ``deleted_by_user_id`` are stamped and ``body`` is
    blanked, so the text is genuinely gone (these threads can quote log data) while
    the audit row survives on a shared investigation surface. Every read filters
    ``deleted_at IS NULL``, so counts and rendering behave exactly like a hard
    delete — there is no tombstone UI. ``author_user_id`` is nullable so a deleted
    user leaves the thread intact, mirroring ``CaseEntityLink.added_by``.
    """

    __tablename__ = "comment"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("investigation_case.id"), nullable=True)
    entity_id = Column(Integer, ForeignKey("entity.id"), nullable=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=True)
    author_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)
    body = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    edited_at = Column(DateTime, nullable=True)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "(CASE WHEN case_id IS NULL THEN 0 ELSE 1 END + CASE WHEN entity_id IS NULL THEN 0 ELSE 1 END + CASE WHEN job_id IS NULL THEN 0 ELSE 1 END) = 1",
            name="ck_comment_single_target",
        ),
        # Exactly the "fetch a target's thread ordered by time" access path; the
        # leading column also serves the FK lookup, so no extra single-column index.
        Index("ix_comment_case_created", "case_id", "created_at"),
        Index("ix_comment_entity_created", "entity_id", "created_at"),
        Index("ix_comment_job_created", "job_id", "created_at"),
    )

    author = relationship("User", foreign_keys=[author_user_id])
    deleted_by = relationship("User", foreign_keys=[deleted_by_user_id])


# ── Saved Searches ────────────────────────────────────────────────────────────


class SavedSearch(Base):
    """A persisted filter state for the entity dashboard (``scope`` is always ``entities`` today)."""

    __tablename__ = "saved_search"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(120), nullable=False)
    scope = Column(String(20), nullable=False, default="entities", server_default="entities")
    query_json = Column(Text, nullable=False, default="{}")
    created_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True, index=True)
    is_shared = Column(Boolean, nullable=False, default=False, server_default="0")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    created_by = relationship("User", foreign_keys=[created_by_user_id])


# ── Enrichment Services ───────────────────────────────────────────────────────


class EnrichmentService(Base):
    """Admin-editable external lookup service (VirusTotal, OTX, MISP, etc.) shown on entity pages."""

    __tablename__ = "enrichment_service"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(80), nullable=False, unique=True)
    provider_key = Column(String(40), nullable=True)  # 'otx', 'urlscan', etc., or None for custom
    entity_types = Column(Text, nullable=False, default="[]")  # JSON list of entity_type strings
    link_template = Column(String(500), nullable=True)  # {value} substitution
    api_template = Column(String(500), nullable=True)
    api_method = Column(String(10), nullable=False, default="GET", server_default="GET")
    api_headers_json = Column(Text, nullable=True)  # supports {token} substitution
    api_token_encrypted = Column(Text, nullable=True)  # Fernet-encrypted at rest
    enabled = Column(Boolean, nullable=False, default=True, server_default="1", index=True)
    display_order = Column(Integer, nullable=False, default=100)
    notes = Column(Text, nullable=True)
    cache_ttl_seconds = Column(Integer, nullable=False, default=86400, server_default="86400")  # live-enrichment cache TTL
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())


class EntityEnrichmentResult(Base):
    """Cached result of a live (API) enrichment lookup for an entity from a service."""

    __tablename__ = "entity_enrichment_result"

    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_id = Column(Integer, ForeignKey("entity.id"), nullable=False, index=True)
    service_id = Column(Integer, ForeignKey("enrichment_service.id"), nullable=False, index=True)
    response_json = Column(Text, nullable=True)  # raw API body, truncated to a cap
    summary_json = Column(Text, nullable=True)  # post-extracted dict shown on the entity page
    fetched_at = Column(DateTime, nullable=False, server_default=func.now())
    expires_at = Column(DateTime, nullable=True)
    ok = Column(Boolean, nullable=False, default=False)
    error_message = Column(String(500), nullable=True)

    __table_args__ = (UniqueConstraint("entity_id", "service_id", name="uq_entity_enrichment"),)

    entity = relationship("Entity")
    service = relationship("EnrichmentService")


# ── API Tokens ────────────────────────────────────────────────────────────────


class SubmissionReceipt(Base):
    """Idempotent writes; independent of browser batch history.

    Keep tombstones when a job/case is deleted so replay cannot recreate it.
    """

    __tablename__ = "submission_receipt"

    id = Column(Integer, primary_key=True)
    user_id = Column(GUID(), ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    kind = Column(String(10), nullable=False)
    key = Column(String(128), nullable=False)
    fingerprint = Column(String(64), nullable=False)
    job_id = Column(Integer, ForeignKey("analysisjob.id", ondelete="SET NULL"), nullable=True)
    case_id = Column(Integer, ForeignKey("investigation_case.id", ondelete="SET NULL"), nullable=True)
    reused = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    __table_args__ = (UniqueConstraint("user_id", "kind", "key", name="uq_submission_receipt"),)


class ApiToken(Base):
    """Scoped bearer tokens for ingestion, jobs, cases, the IOC feed and TAXII."""

    __tablename__ = "api_token"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(120), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 hex of plaintext
    prefix = Column(String(8), nullable=False)  # first 8 chars of plaintext, UI display only
    scopes_json = Column(Text, nullable=False, default="[]")  # JSON list of scope strings
    created_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    created_by = relationship("User", foreign_keys=[created_by_user_id])


# ── Watch rules (per-user detection over submitted logs) ──────────────────────


class IntelRule(Base):
    """A per-user rule evaluated against every finished job's entities.

    The *alerting* mechanism, per user by construction — alerts and acknowledgement included
    — and able to say "tell me when any new LOLBin shows up", not only "tell me about this
    exact entity".

    `query` uses the same syntax as the Intel dashboard and is evaluated through the same
    `apply_entity_filters`, so what you searched is what alerts. That shared path is the
    whole point: a second, hand-rolled matcher would drift from SQL semantics and the
    feature would stop being trustworthy.

    `Entity.watchlist` is the *shared team flag* (it drives the graph, GraphML, the IOC
    feed, the `sort=watchlist` option and a dashboard stat). The star button sets it and
    creates a personal exact-value rule.
    """

    __tablename__ = "intel_rule"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(120), nullable=False)
    description = Column(String(500), nullable=True)
    owner_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True, index=True)
    enabled = Column(Boolean, nullable=False, default=True, server_default="1", index=True)

    # What the criteria are written against: `entity` (the Intel dashboard grammar, matched
    # per entity in the job) or `job` (the jobs-list grammar, matched against the job itself).
    # See `constants.RULE_SCOPES`.
    #
    # A `String(16)`, not an `Enum`. A PostgreSQL enum can only gain a label through
    # `ALTER TYPE … ADD VALUE` inside an autocommit block — see the guard in
    # `tests/test_migrations_auto.py` — and a two-value set that may grow is not worth that.
    scope = Column(String(16), nullable=False, default="entity", server_default="entity", index=True)

    # Criteria — the dashboard query language for an entity rule, the jobs-list grammar for
    # a job rule. `entity_types` applies only to the former.
    query = Column(String(500), nullable=False, default="", server_default="")
    entity_types = Column(Text, nullable=False, default="[]", server_default="[]")  # JSON list

    # Actions.
    # Auto-tagging. A comma-separated list of `normalize_tag`'d names, with a colour list to
    # match, index-aligned — the same pair of strings the tag picker posts everywhere else,
    # parsed by the same `tags.parse_tag_write`.
    #
    # A CSV rather than a JSON column: a single value is already a valid one-element list.
    # `SiteSettings.activity_categories` is the CSV-in-a-column precedent.
    action_tag = Column(String(500), nullable=True)
    action_tag_color = Column(String(200), nullable=False, default="gray", server_default="gray")
    action_notify = Column(Boolean, nullable=False, default=True, server_default="1")

    # Webhook. The URL is user-entered and private/internal hosts are permitted by design;
    # see docs/security.md and settings.webhook_require_public_host for the trade-off.
    webhook_url = Column(String(500), nullable=True)
    webhook_secret_encrypted = Column(Text, nullable=True)  # Fernet, app/auth/api_tokens.py
    webhook_enabled = Column(Boolean, nullable=False, default=False, server_default="0")
    webhook_method = Column(String(10), nullable=False, default="POST", server_default="POST")
    # Extra headers as a JSON object, e.g. an auth token your receiver expects. Values are
    # NOT encrypted — the signing secret is the field for anything sensitive.
    webhook_headers_json = Column(Text, nullable=True)
    # Also deliver this owner's *job-watch* events to this rule's webhook.
    #
    # A flag on an existing rule rather than per-`JobWatch` webhook columns, and the reason
    # is not laziness: a per-watch URL means re-entering an endpoint and a secret on every
    # job you follow, plus a second copy of the SSRF guard, the rate limit and the retry
    # backoff to keep in step with this one — and `WebhookDelivery.rule_id` would have to
    # go nullable, which breaks the user-deletion cleanup. At most one rule per owner
    # carries it, the `WorkflowDef.is_default` rule.
    notify_job_watch = Column(Boolean, nullable=False, default=False, server_default="0")

    # Set when the rule was created by the entity ★ shortcut, so toggling it off is a point
    # lookup rather than a query-string match.
    auto_entity_id = Column(Integer, ForeignKey("entity.id"), nullable=True, index=True)

    # Shipped by LogsTotal rather than written by a person — the label vocabulary
    # (`lolbin`, `privileged`, …), seeded from `rules/builtin.yml` by `app/intel/rules_yaml.py`.
    # Three things branch on it and each fails silently without it:
    #
    #  * it has no owner, and `_owner_can_see_job(None, job)` is False for a private job, so
    #    without an exemption a built-in would never label anything from a private
    #    submission. Safe *because* a built-in only tags: no alert row, no webhook, nothing
    #    leaves the instance.
    #  * `MAX_MATCHES_PER_RULE` would cap labelling at 100 entities per job; a label has to
    #    reach every match.
    #  * it does not count against `watch_rules_max_per_user` — nobody's budget was spent
    #    on a row they did not create.
    is_builtin = Column(Boolean, nullable=False, default=False, server_default="0", index=True)
    # The seed's identity, so re-syncing updates rather than duplicates and a deleted
    # built-in can be restored. Unique, and nullable for every rule a person wrote.
    builtin_key = Column(String(50), nullable=True, unique=True)
    # The hash of the definition this row was last seeded with from `rules/*.yml`,
    # `enabled` excluded; NULL for a rule a person created. At every start the seeder
    # compares the row's current definition with it: equal means nobody edited the row, so
    # the file's newer version is applied; different means an admin's edit, which is left
    # alone. The two obvious policies are both wrong — overwrite-on-boot (what workflows
    # do) discards an admin's edit on every Docker restart, and never-overwrite means a
    # shipped fix reaches nobody.
    seed_hash = Column(String(64), nullable=True)

    last_evaluated_at = Column(DateTime, nullable=True)
    last_matched_at = Column(DateTime, nullable=True)
    match_count = Column(Integer, nullable=False, default=0, server_default="0")
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("owner_user_id", "auto_entity_id", name="uq_intel_rule_auto_entity"),
        Index("ix_intel_rule_enabled_owner", "enabled", "owner_user_id"),
    )

    owner = relationship("User", foreign_keys=[owner_user_id])
    matches = relationship("IntelRuleMatch", back_populates="rule", cascade="all, delete-orphan")
    job_matches = relationship("JobRuleMatch", back_populates="rule", cascade="all, delete-orphan")


class RuleList(Base):
    """A named set of values a rule condition can test with `list:<name>`.

    LOLBAS names, GTFOBins names, suspicious TLDs: the sets the shipped rules need, and any
    set an admin adds. Instance-wide like the shared rules, seeded from `rules/lists.yml` at
    start under the same "the file updates what nobody edited" policy (`seed_hash`), edited
    on the Rules page, exported and imported with the rules.

    Deliberately the rules' own copy rather than a reference into
    `config/threat_detection.yaml`. That file configures the detection pipeline that runs on
    an upload; this configures what happens *after*. They are tuned by different people for
    different reasons, and a list a rule depends on must not move because someone adjusted
    a threat check.

    `match` is `exact` (the whole value, case-insensitively) or `suffix` (the value ends
    with an entry — the TLD list, whose entries keep their leading dot so `.tk` cannot match
    `stk`). A `String(16)` rather than an enum, the `IntelRule.scope` argument.

    Values are rows in `rule_list_value` rather than a text column so that `list:` compiles
    to an EXISTS the database answers through the `(list_id, value)` index: no lookup at
    parse time, so the parser stays pure, and no cache to keep coherent between the web and
    worker processes.
    """

    __tablename__ = "rule_list"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False)
    match = Column(String(16), nullable=False, default="exact", server_default="exact")
    description = Column(String(500), nullable=True)
    seed_hash = Column(String(64), nullable=True)
    # Where the values come from, when they come from somewhere. A list bound to a URL is
    # re-fetched by `refresh_rule_lists_periodic`; `refresh_hours` of 0 means "only when
    # someone presses Refresh", which is the right setting for a source that changes rarely
    # and the only one that costs nothing.
    #
    # A URL-backed list is an edited list by construction, so `write_list` clears
    # `seed_hash` for it and the seeder stops overwriting it. Without that, the next boot
    # would put the shipped values back.
    source_url = Column(String(500), nullable=True)
    refresh_hours = Column(Integer, nullable=False, default=0, server_default="0")
    last_fetched_at = Column(DateTime, nullable=True)
    # Tri-state on purpose: NULL is "never tried", which is not the same as "tried and
    # failed" and must not render as one.
    last_fetch_ok = Column(Boolean, nullable=True)
    last_fetch_error = Column(String(300), nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (UniqueConstraint("name", name="uq_rule_list_name"),)

    entries = relationship("RuleListValue", back_populates="list", cascade="all, delete-orphan", passive_deletes=True)


class RuleListValue(Base):
    """One entry of a `RuleList`, lowercased.

    `pattern` is what the SQL compares against: the value itself for an exact list, and
    `%` plus the LIKE-escaped value for a suffix list — computed once at write time so the
    `list:` clause needs no per-row escaping and a value containing `_` or `%` stays literal.
    """

    __tablename__ = "rule_list_value"

    id = Column(Integer, primary_key=True, autoincrement=True)
    list_id = Column(Integer, ForeignKey("rule_list.id", ondelete="CASCADE"), nullable=False)
    value = Column(String(200), nullable=False)
    pattern = Column(String(220), nullable=False)

    __table_args__ = (UniqueConstraint("list_id", "value", name="uq_rule_list_value"),)

    list = relationship("RuleList", back_populates="entries")


class IntelRuleMatch(Base):
    """One alert: rule R matched entity E in job J.

    The unique constraint is the idempotency guarantee — re-running a job, or a backfill,
    must not raise the same alert twice. Keyed by rule, which makes alerts per-user by
    construction, acknowledgement included.
    """

    __tablename__ = "intel_rule_match"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("intel_rule.id"), nullable=False, index=True)
    entity_id = Column(Integer, ForeignKey("entity.id"), nullable=False, index=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now(), index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)

    __table_args__ = (
        UniqueConstraint("rule_id", "entity_id", "job_id", name="uq_intel_rule_match"),
        Index("ix_intel_rule_match_rule_created", "rule_id", "created_at"),
    )

    rule = relationship("IntelRule", back_populates="matches")
    entity = relationship("Entity")
    job = relationship("AnalysisJob")
    acknowledged_by = relationship("User", foreign_keys=[acknowledged_by_user_id])


class JobRuleMatch(Base):
    """One alert: a `scope="job"` rule matched job J.

    **A second table, not a nullable `entity_id` on `IntelRuleMatch`.** That column is NOT
    NULL and has to stay so: `uq_intel_rule_match(rule_id, entity_id, job_id)` is what makes
    a re-run raise no duplicate, and both SQLite and PostgreSQL treat NULL as *distinct* in a
    UNIQUE index — so `(5, NULL, 42)` would insert without limit, for exactly the new rows
    and nowhere else. The guarantee would break silently, and only for job rules. `JobTag`
    beside `EntityTag` is the same argument.

    `uq_job_rule_match(rule_id, job_id)` is the whole of the idempotency here. A job rule is
    a single-row test against the job being finished, so there is no per-rule match cap to
    apply and nothing to truncate: it matched or it did not.

    No `acknowledged_by_user_id`… there is one, and for the `IntelRuleMatch` reason rather
    than the `JobWatchEvent` one: an admin sees every rule, so "who cleared this" is a real
    question here in a way it is not for a subscription that belongs to one person.
    """

    __tablename__ = "job_rule_match"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("intel_rule.id"), nullable=False, index=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now(), index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)

    __table_args__ = (
        UniqueConstraint("rule_id", "job_id", name="uq_job_rule_match"),
        Index("ix_job_rule_match_rule_created", "rule_id", "created_at"),
    )

    rule = relationship("IntelRule", back_populates="job_matches")
    job = relationship("AnalysisJob")
    acknowledged_by = relationship("User", foreign_keys=[acknowledged_by_user_id])


class WebhookDelivery(Base):
    """One webhook POST attempt, kept so a rule owner can debug their own receiver.

    `error_message` must never contain the shared secret or the URL's userinfo.
    """

    __tablename__ = "webhook_delivery"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("intel_rule.id"), nullable=False, index=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=True, index=True)
    match_count = Column(Integer, nullable=False, default=0)
    attempt = Column(Integer, nullable=False, default=1)
    status_code = Column(Integer, nullable=True)
    ok = Column(Boolean, nullable=False, default=False, index=True)
    error_message = Column(String(300), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now(), index=True)

    rule = relationship("IntelRule")


class TagDefinition(Base):
    """A tag in the vocabulary, whether or not anything carries it yet.

    `EntityTag` is the *association* and cannot represent a tag with no entities; without
    this row the only way to bring a tag into existence would be to apply it to something,
    which makes the obvious workflow — agree on a vocabulary, then label against it —
    impossible.

    Colour still lives on `EntityTag` for tags that are in use (one colour per name,
    maintained instance-wide by the write paths), because that is what the chips render
    from. This row carries the colour for a tag nobody has applied yet, and is the record
    that keeps such a tag visible in the manager and the picker.
    """

    __tablename__ = "tag_definition"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tag = Column(String(50), nullable=False, unique=True, index=True)
    color = Column(String(20), nullable=False, default="gray", server_default="gray")
    description = Column(String(300), nullable=True)
    created_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    created_by = relationship("User", foreign_keys=[created_by_user_id])


# ── AI analysis ───────────────────────────────────────────────────────────────


class AiAnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AiProvider(Base):
    """An admin-configured LLM endpoint used to interpret a job's findings.

    ``kind`` selects the request/response shape, not the vendor: ``openai`` is the
    ``/chat/completions`` wire format that Ollama, LM Studio, vLLM, OpenRouter, Groq and
    OpenAI itself all speak, and ``anthropic`` is ``/v1/messages``. Two shapes cover every
    provider worth naming, which is why there is no per-provider adapter here — see
    ``app/ai/providers.py`` for the registry that owns the actual mapping.

    There is deliberately **no custom-headers column**. ``EnrichmentService`` has one and
    needs ``UNSAFE_HEADER_KEYS`` to police it; here the auth header is derived from
    ``kind``, so that entire injection surface simply does not exist.

    ``base_url`` is validated with ``app.intel.webhooks.validate_url_syntax`` at save time
    and re-resolved with ``validate_url_addresses(require_public=settings.ai_require_public_host)``
    immediately before each request. Private addresses are allowed by default on purpose:
    the reference deployment for this feature is an Ollama on localhost.
    """

    __tablename__ = "ai_provider"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(80), nullable=False, unique=True)
    kind = Column(String(20), nullable=False, default="openai", server_default="openai")
    base_url = Column(String(500), nullable=False)
    model = Column(String(200), nullable=False)
    api_token_encrypted = Column(Text, nullable=True)  # Fernet-encrypted at rest
    system_prompt = Column(Text, nullable=True)  # overrides app.ai.digest.DEFAULT_SYSTEM_PROMPT
    case_system_prompt = Column(Text, nullable=True)
    temperature = Column(Float, nullable=False, default=0.2, server_default="0.2")
    # Reasoning models spend output tokens on hidden thinking before writing an answer.
    max_output_tokens = Column(Integer, nullable=False, default=20_000, server_default="20000")
    # Null inherits AI_MAX_PROMPT_CHARS, preserving deployment-specific defaults.
    job_max_prompt_chars = Column(Integer, nullable=True)
    case_max_prompt_chars = Column(Integer, nullable=True)
    # 300s, not 120: a 27B model on a laptop GPU took 155s for a two-finding job. A hosted
    # API is far quicker, but the default has to fit the deployment this feature was built
    # for, and a timeout that fires on a working setup reads as a broken one.
    timeout_seconds = Column(Integer, nullable=False, default=300, server_default="300")
    enabled = Column(Boolean, nullable=False, default=True, server_default="1", index=True)
    is_default = Column(Boolean, nullable=False, default=False, server_default="0")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())


class JobAiAnalysis(Base):
    """One AI interpretation of one job — a *run*, not a cache.

    Runs accumulate rather than overwrite, so the same job can be put to a local Ollama and
    to Claude and the two answers compared side by side. That is also why ``provider_name``
    and ``model`` are **snapshots** rather than reads through ``provider_id``: deleting a
    provider nulls the FK and leaves every past run readable and correctly attributed.
    (``enrichment_delete`` hard-deletes its cached rows — the opposite call, because those
    are a cache and these are history.)
    """

    __tablename__ = "job_ai_analysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(Integer, ForeignKey("analysisjob.id"), nullable=False, index=True)
    provider_id = Column(Integer, ForeignKey("ai_provider.id"), nullable=True, index=True)
    provider_name = Column(String(80), nullable=False)
    model = Column(String(200), nullable=False)
    status = Column(Enum(AiAnalysisStatus), nullable=False, default=AiAnalysisStatus.PENDING, index=True)
    content = Column(Text, nullable=True)
    error_message = Column(String(500), nullable=True)
    # Step-by-step trace of the run, written as it happens: brief built, prompt size,
    # request sent, response received, tokens. This is what makes a slow run legible
    # instead of a spinner — the same job `TaskResult.log_output` does for a tool. Capped
    # at write time, like that column, so a pathological run cannot grow without bound.
    log_output = Column(Text, nullable=True)
    # The exact user-message text this run sent, when `SiteSettings.show_ai_prompt` is on.
    # `prompt_chars` records its *size*; this is the thing itself, because
    # "how much did we send" and "what did we send" are different questions and only the
    # second one settles a data-handling argument. Bounded by the provider's job prompt
    # limit, or `AI_MAX_PROMPT_CHARS` when unset.
    prompt_text = Column(Text, nullable=True)
    requested_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)
    prompt_chars = Column(Integer, nullable=True)
    input_tokens = Column(Integer, nullable=True)
    output_tokens = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    finished_at = Column(DateTime, nullable=True)

    # The exact access path: "runs for this job, newest first".
    __table_args__ = (Index("ix_job_ai_analysis_job_created", "job_id", "created_at"),)

    provider = relationship("AiProvider")
    requested_by = relationship("User", foreign_keys=[requested_by_user_id])


class CaseAiAnalysis(Base):
    """A saved case assessment with immutable evidence provenance."""

    __tablename__ = "case_ai_analysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("investigation_case.id"), nullable=False, index=True)
    provider_id = Column(Integer, ForeignKey("ai_provider.id"), nullable=True, index=True)
    provider_name = Column(String(80), nullable=False)
    model = Column(String(200), nullable=False)
    status = Column(Enum(AiAnalysisStatus), nullable=False, default=AiAnalysisStatus.PENDING, index=True)
    content = Column(Text, nullable=True)
    error_message = Column(String(500), nullable=True)
    # Step-by-step trace of the run, written as it happens: brief built, prompt size,
    # request sent, response received, tokens. This is what makes a slow run legible
    # instead of a spinner — the same job `TaskResult.log_output` does for a tool. Capped
    # at write time, like that column, so a pathological run cannot grow without bound.
    log_output = Column(Text, nullable=True)
    # The exact user-message text this run sent, when `SiteSettings.show_ai_prompt` is on.
    # `prompt_chars` records its *size*; this is the thing itself, because
    # "how much did we send" and "what did we send" are different questions and only the
    # second one settles a data-handling argument. Bounded by the provider's case prompt
    # limit, or `AI_MAX_PROMPT_CHARS` when unset.
    prompt_text = Column(Text, nullable=True)
    requested_by_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)
    prompt_chars = Column(Integer, nullable=True)
    input_tokens = Column(Integer, nullable=True)
    output_tokens = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    finished_at = Column(DateTime, nullable=True)

    # Source identities survive job deletion; missing sources deny non-admin reads.
    source_jobs_json = Column(Text, nullable=True)
    source_deleted_at = Column(DateTime, nullable=True)
    evidence_captured_at = Column(DateTime, nullable=True)

    # The exact access path: runs for this case, newest first.
    # Queued tasks and cancellation keys outlive deletion. Never reuse a run ID.
    __table_args__ = (Index("ix_case_ai_analysis_case_created", "case_id", "created_at"), {"sqlite_autoincrement": True})

    provider = relationship("AiProvider")
    requested_by = relationship("User", foreign_keys=[requested_by_user_id])


# ── Activity log ──────────────────────────────────────────────────────────────


class ActivityEvent(Base):
    """One recorded action: who did what, when, from where, and how it turned out.

    Called *activity* rather than *audit* because ``audit`` already means the auditd log
    format everywhere else in this codebase (``LogType.AUDITD``, the parsers in
    ``intel/lineage.py`` and ``event_markers.py``), and a second meaning for the word in
    a security tool is a genuine hazard.

    Two shape decisions are load-bearing:

    ``actor_label`` is an **email snapshot**, the ``JobAiAnalysis.provider_name`` idiom.
    Deleting a user nulls ``actor_user_id`` (via ``admin._USER_REFERENCES``) and the row
    stays readable and attributed. Anonymised rather than deleted, deliberately: an audit
    log a user can erase by deleting their own account is not an audit log.

    ``target_type``/``target_id`` are **plain strings, not foreign keys**. "Who deleted
    job 42" has to outlive job 42, and an FK is precisely what would prevent that. It also
    keeps this table out of the job-FK half of ``tests/test_fk_cleanup_parity.py``.

    Writing is gated by ``SiteSettings.activity_log_enabled`` (default off — see
    ``app/activity.py``). Reading is not: an operator who turns capture off must still be
    able to read what was already captured, and Prune is how they remove it.
    """

    __tablename__ = "activity_event"

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now(), index=True)
    actor_user_id = Column(GUID(), ForeignKey("user.id"), nullable=True)
    # Snapshot of the actor's email at the time of the action. "anonymous" or "system"
    # for the unauthenticated and worker-side cases, so the column is never empty.
    actor_label = Column(String(255), nullable=False, default="anonymous")
    actor_ip = Column(String(45), nullable=True)
    # A key from `app.activity.ACTIONS` — a registry, so the filter list, the docs table
    # and the call sites cannot drift apart.
    action = Column(String(80), nullable=False, index=True)
    category = Column(String(30), nullable=False, index=True)
    target_type = Column(String(40), nullable=True)
    target_id = Column(String(64), nullable=True)
    summary = Column(String(500), nullable=True)
    # Extra structured context: the changed keys of a settings save, the scope of a token,
    # the row counts of a prune. NEVER a secret — writers record field *names*, not values.
    metadata_json = Column(Text, nullable=True)
    # Ties a row to the log lines from the same request. Same width as the sanitised
    # `X-Request-ID` the middleware accepts.
    request_id = Column(String(64), nullable=True)
    outcome = Column(String(16), nullable=False, default="success")

    __table_args__ = (
        Index("ix_activity_event_category_created", "category", "created_at"),
        Index("ix_activity_event_actor_created", "actor_user_id", "created_at"),
        Index("ix_activity_event_target", "target_type", "target_id"),
    )

    actor = relationship("User", foreign_keys=[actor_user_id])
