"""Shared constants used across routers and workers."""

import re

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
EMPTY_SEVERITY_SUMMARY = dict.fromkeys(SEVERITY_ORDER, 0)

# How the jobs list draws a row. `compact` is the table; `roomy`
# is a card per job with every tag under a rule, for the analyst who labels heavily.
#
# One frozenset read by both the writer and the read-side clamp: the preference rides a
# non-HttpOnly cookie, so a stale or hand-edited value must degrade to the default rather
# than render nothing.
DEFAULT_JOBS_VIEW = "compact"
ALLOWED_JOBS_VIEWS = frozenset({"compact", "roomy"})
JOBS_VIEW_COOKIE = "logstotal_jobs_view"

# Rows per page on the jobs list — the same arrangement as the view: one tuple read by the
# writer and the read-side clamp, because the cookie is not HttpOnly and a hand-edited value
# must degrade to the default rather than page by a million.
DEFAULT_JOBS_PER_PAGE = 20
JOBS_PER_PAGE_CHOICES = (20, 50, 100)
JOBS_PER_PAGE_COOKIE = "logstotal_jobs_per_page"

# What a rule's criteria are written against. `entity` matches per entity in the finished
# job, through `app/intel/queries.py`; `job` matches the job itself, through
# `app/jobs_query.py`. One tuple rather than an Enum column — see `IntelRule.scope`.
#
# Order is display order: the form's scope selector renders it, and `entity` first keeps the
# default first. `DEFAULT_RULE_SCOPE` is read by the write path *and* the read-side clamp,
# the `ALLOWED_JOBS_VIEWS` arrangement, so a stored value from a future release degrades to
# something that renders rather than to nothing.
RULE_SCOPES = ("entity", "job")
DEFAULT_RULE_SCOPE = "entity"
RULE_SCOPE_LABELS = {"entity": "Entities", "job": "Jobs"}

# Entity types, in dashboard display order. Lives here rather than beside the badge colours
# in routers/intel.py because `app/intel/queries.py` needs it to validate a `type:` term and
# is a pure module that must not import a router. `ENTITY_TYPE_META` there carries the
# label/colour for each of these keys; a test pins the two to the same key set.
ENTITY_TYPES = ("user", "computer", "ip_address", "hash", "executable", "domain", "cmdline_file", "service", "task")
# Rank for "most severe wins" comparisons (lower index = more severe).
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Severity → hex, for surfaces that cannot use a Tailwind class: the events-timeline
# canvas paints into a <canvas>, so it needs the literal colour and receives it in the API
# response. These are the resolved values of ``_sev_dot_classes`` in
# templates/partials/_severity_macros.html (Tailwind's 500 ramp) — keep them in step so a
# marker and its severity dot never disagree. Templates must still import the macros; this
# is not a second palette for HTML.
SEVERITY_COLORS = {
    "critical": "#ef4444",  # red-500
    "high": "#f97316",  # orange-500
    "medium": "#eab308",  # yellow-500
    "low": "#3b82f6",  # blue-500
    "informational": "#6b7280",  # gray-500
    "unknown": "#4b5563",  # gray-600 — no matching Finding, see event_markers
}

# Entity type → hex, and edge kind → hex. Same justification as SEVERITY_COLORS above: the
# relationship graph paints into a WebGL canvas, which cannot use a Tailwind class. Kept
# here so the legend, the renderer and the PNG export all read one palette. Templates must
# still use `_entity_type_badge.html` for HTML badges; this is not a second palette for
# markup, and `tests/test_graph_client_contract.py` fails the build if a hex reappears in
# graph*.js or the legend partial.
ENTITY_TYPE_COLORS = {
    "user": "#3b82f6",  # blue-500
    "computer": "#a855f7",  # purple-500
    "ip_address": "#22c55e",  # green-500
    "hash": "#eab308",  # yellow-500
    "executable": "#f97316",  # orange-500
    "domain": "#06b6d4",  # cyan-500
    "cmdline_file": "#f43f5e",  # rose-500
    "service": "#14b8a6",  # teal-500
    "task": "#6366f1",  # indigo-500
}

# Display metadata per entity type: the plural label and the Tailwind colour *name* the
# chips use. Sits beside ENTITY_TYPES and ENTITY_TYPE_COLORS so the per-type facts live in
# one place rather than one set of keys in several.
ENTITY_TYPE_META = {
    "user": {"label": "Users", "color": "blue"},
    "computer": {"label": "Computers", "color": "purple"},
    "ip_address": {"label": "IPs", "color": "green"},
    "hash": {"label": "Hashes", "color": "yellow"},
    "executable": {"label": "Executables", "color": "orange"},
    "domain": {"label": "Domains", "color": "cyan"},
    "cmdline_file": {"label": "Cmdline Files", "color": "rose"},
    "service": {"label": "Services", "color": "teal"},
    "task": {"label": "Tasks", "color": "indigo"},
}


def parse_entity_types(raw: str | list[str] | None) -> list[str]:
    """Normalise a submitted entity-type selection to known types, order preserved.

    One function for both forms that ask this question — the enrichment service editor and
    the rule editor.

    Accepts **both wire shapes on purpose**. A checkbox group posts the key repeatedly, so
    FastAPI hands over a list; a scripted caller may post one CSV string
    (`entity_types=ip_address,domain`). Splitting every element on commas covers both.

    Unknown tokens are dropped rather than raising: the caller decides what an empty result
    means, and both do (each rejects it with a message about its own form).
    """
    if raw is None:
        return []
    parts = [raw] if isinstance(raw, str) else list(raw)
    out: list[str] = []
    for part in parts:
        for token in str(part).split(","):
            name = token.strip()
            if name in ENTITY_TYPES and name not in out:
                out.append(name)
    return out


# Graph edge kinds, weakest evidence first. "job" means only "named in the same log file".
GRAPH_EDGE_KIND_COLORS = {
    "job": "#475569",  # slate-600
    "finding": "#fbbf24",  # amber-400
    "typed": "#38bdf8",  # sky-400
}

# Shared observable-extraction patterns (compiled once). Used by the analytics pass
# (app/analytics.py), typed-relationship extraction (intel/relationships.py) and process
# lineage (intel/lineage.py).
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_IPV6 = re.compile(
    r"(?:::ffff:\d{1,3}(?:\.\d{1,3}){3}"
    r"|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:\d{1,3}(?:\.\d{1,3}){3}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    r"|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})",
    re.IGNORECASE,
)
RE_HASH = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
RE_DOMAIN = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})*\.[a-z]{2,}$")

# Job statuses that stop the HTMX status polling (job is done, one way or another).
TERMINAL_JOB_STATUSES = ("completed", "failed", "partial", "cancelled")

# The same idea for one AI analysis run: the statuses at which the pane stops polling and
# the worker's catch-all must not overwrite what is already recorded. Shared by
# `routers/ai.py` and `workers/tasks.py` so the poll trigger and the finaliser cannot come
# to different conclusions about whether a run is over.
TERMINAL_AI_STATUSES = ("completed", "failed", "cancelled")

# Job statuses an AI analysis may be started on. Deliberately NOT `TERMINAL_JOB_STATUSES`,
# which is a different question: that tuple answers "has the job stopped moving?" and so
# includes `failed` and `cancelled`. This one answers "is there anything to analyse?", and
# a job that failed or was cancelled before producing findings has nothing — the model
# would be handed an empty brief and would answer confidently about nothing.
#
# `partial` is in, not out: some tools failed but the ones that ran produced real findings,
# and the brief says so. Read by `routers/jobs.py::_show_ai_tab` (the tab),
# `routers/ai.py::_render_panel` (the run control) and `ai_analysis_start` (the refusal),
# so the three cannot come to different conclusions.
AI_ELIGIBLE_JOB_STATUSES = ("completed", "partial")

# error_message written to stale RUNNING jobs/task-results when their worker heartbeat
# is gone. Two recovery paths, two constants — values are user-facing (docs quote them).
RECOVERY_MSG_STARTUP = "Worker lost — recovered on startup"
RECOVERY_MSG_ADMIN = "Worker lost — recovered by admin"
# error_message written to PENDING jobs whose queued task expired before any worker
# claimed it (HUEY_QUEUE_EXPIRY). Not a worker crash — the task was never picked up.
RECOVERY_MSG_EXPIRED = "Expired in the queue before a worker picked it up"

# error_message written to cancelled jobs/task-results (user-facing, docs quote them).
CANCEL_MSG_USER = "Cancelled by user"
CANCEL_MSG_DEAD_WORKER = "Cancelled by user (worker lost)"

# Huey post-steps after detection tools (not part of score ratio denominator).
POST_TASK_ANALYTICS = "Computing analytics"
POST_TASK_SIMILARITY = "File similarity"
POST_TASK_NAMES: frozenset[str] = frozenset({POST_TASK_ANALYTICS, POST_TASK_SIMILARITY})


def is_post_processing_task(tool_name: str) -> bool:
    return tool_name in POST_TASK_NAMES


# Analyst tag palette. Ordered around the colour wheel, warm to cool, with neutral first —
# so the swatch row reads as a spectrum instead of an arbitrary list and two adjacent
# choices are visibly different.
#
# One definition, and a *validation* list: a colour absent from the tuple is silently
# downgraded to "gray" on write, so a second copy is how a colour ends up selectable in one
# editor and rejected by another.
#
# The Tailwind class names for these keys live in `templates/intel/partials/_tag_chip.html`
# and must stay in step — a class assembled at runtime is invisible to the Tailwind scanner,
# so the template spells each one out. `tests/test_tag_palette_parity.py` pins the two
# together.
TAG_COLORS: tuple[str, ...] = ("gray", "red", "rose", "orange", "amber", "yellow", "green", "teal", "cyan", "blue", "indigo", "purple")

# "In these cases" header chips on the entity and job pages — a browsing aid, not a
# listing; the case page is the listing.
CASE_BACKLINK_LIMIT = 10

# Freeform analyst prose caps (plain text, stored on the row rather than as comments).
NOTE_MAX_LENGTH = 8000
