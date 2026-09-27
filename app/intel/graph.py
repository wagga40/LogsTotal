"""Relationship-graph builders — DB in, columnar payload out.

Edges come from three sources, with increasing analytic worth:
  * `EntityJobLink` co-occurrence in the same job (kind="job"). This means only
    *"named in the same log file"* — it never participates in pathfinding, and it is
    never the reason a path exists.
  * `FindingEntityLink` co-occurrence inside one Sigma finding (kind="finding").
  * `EntityRelationship` typed, evidence-backed edges — one **directed** edge per
    ``(source, target, relationship_type)``, not a collapsed undirected pair.

The wire format, including `to_graphml`, lives in `app/intel/graph_payload.py` (pure); this
module only queries.

Visibility: every job-derived edge source (`neighbors_of`, `_job_co_edges`,
`_job_pair_lohi`, `_finding_co_edges`, `_focal_edges`) takes a `viewer` and applies
`visible_job_filter`, so an edge can never reveal that two entities co-occurred inside a
job the viewer cannot see. `_typed_edges` is the deliberate exception —
`EntityRelationship` is a cross-job aggregate with no job column, and the entity
Relationships tab already lists those edges unfiltered, so gating them here alone would
buy nothing. Everything *derived* from a typed edge (evidence rows, per-job counts,
observed times) is filtered. See "Security trade-offs to understand" in docs/security.md
and `test_typed_edges_are_deliberately_unfiltered`.
"""

from __future__ import annotations

from typing import NamedTuple

from sqlalchemy import Select, case, func, select, union
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.intel.graph_payload import EDGE_KIND_FINDING, EDGE_KIND_JOB, GraphEdge, GraphNode, build_payload
from app.models import (
    AnalysisJob,
    Entity,
    EntityJobLink,
    EntityRelationship,
    Finding,
    FindingEntityLink,
    TaskResult,
    visible_job_filter,
)

MAX_NODES = 5_000
MAX_HOPS = 3
MAX_NEIGHBORS_PER_HOP = 500
DEFAULT_NEIGHBOR_LIMIT = 30

# Entity-scope edge budget. Capping nodes alone does not bound the payload: the traversal
# adds up to `limit` edges per frontier node, so a mid-range `limit` fans out far more edges
# than a large one (a large one trips MAX_NODES and breaks the expansion early). Measured on
# a 1,266-entity dev DB, hops=3/limit=120 emitted 20,200 edges / 2.08 MB and reported
# `truncated: False`, so the UI banner stayed silent.
MAX_EDGES = 15_000

# GraphML downloads are parsed offline by yEd/Gephi, not drawn in the browser, and a file
# has no truncation banner to warn that content went missing. Kept generous but pinned
# **separately** from the interactive caps: `MAX_NODES`/`MAX_NEIGHBORS_PER_HOP` are module
# constants read inside `build_entity_graph`, so without its own node budget the export
# would inherit every future raise for free and build a 5,000-node document synchronously
# inside a request.
EXPORT_MAX_EDGES = 25_000
EXPORT_MAX_NODES = 500

# Case-scope budgets. A case with a few hundred entities can imply tens of thousands of
# pairwise job-co-occurrence edges.
CASE_MAX_NODES = 5_000
CASE_MAX_EDGES = 15_000

# Global row budget for one batched hop. `frontier x per_source_limit` is 5,000 x 500 =
# 2.5M rows with the type-preference widening — a worse failure than one round trip per
# node, so the rows themselves are bounded too.
HOP_ROW_CAP = 200_000

# Near-clique guard on `_job_co_edges`. Its LIMIT bounds *output*, not scan: the work is
# `sum over jobs of (entities-in-job intersect node-set)^2`, so one job touching 800 of
# 5,000 nodes emits 640,000 candidate pairs by itself. A near-clique carries no
# information, which is why the case UI already defaults `job_edges=False`. Suppression is
# reported in `stats.job_fanout_suppressed` — a silent semantic change is the graph lying.
MAX_JOB_FANOUT = 300

# The uncapped-total probe is itself bounded; past this it reports a floor ("50,000+").
TOTAL_EDGES_PROBE_CAP = 50_000

# Reserved, separately-budgeted edge allowance for the focal entity. `_job_co_edges` orders
# `shared DESC` in SQL, so a focal spoke with shared=1 loses to 15,000 pairs with shared>=2
# and the Python focal-first ranking never sees it — the graph would render centred on an
# orphan.
FOCAL_EDGE_BUDGET = 500

# Node ceiling while a job scope is active, clamped over whatever the caller asked for.
#
# The scan cost of `_job_co_edges` is `sum over jobs of (entities-in-job ∩ node-set)²`.
# Unscoped, `MAX_JOB_FANOUT` keeps any single term small. Job-scoped there is exactly one
# term and the fanout guard has to come off (see `_job_co_edges`), so the node count is
# the only thing bounding that square: 1,500 nodes is ~1.1M candidate pairs worst case,
# which SQLite handles; 5,000 would be 12.5M and does not. Applied with `min()`, never as
# an override — otherwise the 500-node GraphML export would silently grow to this.
JOB_SCOPE_MAX_NODES = 1_500

# Type-aware neighbour ranking: when the focal entity is one of these types, neighbours
# whose entity_type is in the corresponding set are surfaced first within the same shared-
# job-count tier. Keeps the same neighbour set; just reorders so the most analytically
# useful types appear first in the rendered graph.
_PREFERRED_NEIGHBOR_TYPES: dict[str, frozenset[str]] = {
    "hash": frozenset({"user", "computer", "cmdline_file"}),
    "executable": frozenset({"user", "computer", "cmdline_file"}),
    "ip_address": frozenset({"user", "computer", "domain"}),
    "domain": frozenset({"user", "computer", "ip_address"}),
    "user": frozenset({"computer", "executable", "ip_address"}),
    "computer": frozenset({"user", "executable", "service", "task"}),
}

# Case scope opens with hashes hidden: a case usually pulls in one hash per file touched,
# and they crowd out the user/computer/IP structure an analyst reads the graph for. Entity
# scope keeps every type — there the focal entity is often the hash itself. Decided
# server-side so the client has no scope-conditional default of its own to drift.
CASE_DEFAULT_HIDDEN_TYPES = ["hash"]

# Both scopes open with **job co-occurrence edges hidden**. They are the bulk of every
# graph — 272 of 377 edges on a 31-node dev entity, and the whole reason the default view
# reads as a hairball — and they carry the least: "these two were named in the same log
# file". The *nodes* they found stay (that is how the traversal reached them); only the
# edges are muted, one chip away from coming back. Same argument as `MAX_JOB_FANOUT`:
# a near-total graph is not information.
#
# Client-side, not server-side, and deliberately: the case scope's `job_edges=0` skips the
# query entirely for payload size, whereas an entity graph *needs* those pairs to rank and
# cap. Hiding them is a view decision, so it ships as a view default.
DEFAULT_HIDDEN_EDGE_KINDS = ["job"]

# The columns a node needs. `select(Entity)` drags `Entity.notes` (8,000-char cap) for every
# node in the graph, which at the raised caps is megabytes of text nothing renders.
_NODE_COLUMNS = (
    Entity.id,
    Entity.value,
    Entity.entity_type,
    Entity.job_count,
    Entity.watchlist,
    Entity.allowlisted,
    Entity.attributes_json,
)


def _node_from_row(row) -> GraphNode:
    return GraphNode(
        id=int(row.id),
        label=row.value or f"entity {row.id}",
        entity_type=row.entity_type,
        job_count=int(row.job_count or 0),
        watchlist=bool(row.watchlist),
        allowlisted=bool(row.allowlisted),
        attributes_json=row.attributes_json,
    )


def _cooccurrence_weight(pair: tuple[int, int], *, job_co: dict, finding_co: dict) -> tuple[str, int]:
    """Resolve one *undirected* pair to `(kind, weight)`.

    Only the two co-occurrence kinds; typed relationships are their own directed edges and
    carry `occurrence_count` verbatim. No visibility floor is added to a weight: that is a
    rendering constant, it lives in the client's stroke-width reducer, and here it would
    travel into the GraphML export as though it were evidence.
    """
    weight = job_co.get(pair, 0) + finding_co.get(pair, 0)
    kind = EDGE_KIND_FINDING if pair in finding_co else EDGE_KIND_JOB
    return kind, max(1, weight)


# Ranking tier per edge kind, strongest evidence first. Weights carry no floor, so an
# explicit tier is what keeps an evidence-backed typed edge alive when the cap bites.
_KIND_TIER = {EDGE_KIND_JOB: 0, EDGE_KIND_FINDING: 1}


def _edge_rank(edge: GraphEdge, focal_id: int | None) -> tuple:
    """Cap ordering: focal-incident, then kind tier, then weight, then a stable tie-break."""
    tier = _KIND_TIER.get(edge.kind, 2)
    focal_incident = focal_id is not None and focal_id in (edge.source, edge.target)
    return (not focal_incident, -tier, -int(edge.weight), edge.source, edge.target, edge.kind)


def _stats(
    nodes: int,
    edges: int,
    *,
    total_nodes: int | None,
    total_edges: int,
    hops_used: int = 0,
    nodes_truncated: bool = False,
    edges_truncated: bool = False,
    job_edges: bool = True,
    total_edges_is_floor: bool = False,
    job_fanout_suppressed: int = 0,
    job_id: int | None = None,
    kinds: dict[str, int] | None = None,
) -> dict:
    """Assemble the `stats` block both graph builders return.

    `total_nodes` is ``int | None``. Entity scope emits **None**: its traversal never learns
    the true node total, and the emitted count in its place would be a lie the template has
    to compensate for. Case scope knows its exact count and says so.
    A job-scoped entity graph also knows it exactly, because every hop is constrained to
    one job, so the reachable set *is* that job's entity set — see `build_entity_graph`.
    """
    reason = "+".join(k for k, on in (("nodes", nodes_truncated), ("edges", edges_truncated)) if on)
    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "total_edges_is_floor": bool(total_edges_is_floor),
        "hops_used": hops_used,
        "truncated": bool(nodes_truncated or edges_truncated),
        "truncated_reason": reason,
        "job_edges": job_edges,
        "job_fanout_suppressed": int(job_fanout_suppressed),
        # Echoed so the stats strip and the WebGL-less fallback table can both say what
        # the picture is scoped to without re-deriving it from the URL.
        "job_id": int(job_id) if job_id else None,
        "job_scoped": bool(job_id),
        "kinds": kinds or {},
    }


async def _typed_edges(db: AsyncSession, entity_ids: list[int], *, limit: int = CASE_MAX_EDGES) -> tuple[list[GraphEdge], bool]:
    """Directed typed edges among the given entity set, one per `(src, tgt, rel_type)`.

    No normalisation and no merging. Collapsing `(a -> b, resolves_to)` and
    `(b -> a, connects_to)` onto one undirected line would throw away both the direction and
    the distinction, then draw an arrowhead anyway. Rows are
    taken most-frequent-first and bounded by *limit*; one extra row detects truncation
    without a second COUNT.
    """
    if len(entity_ids) < 2:
        return [], False
    id_set = set(entity_ids)
    rows = (
        await db.execute(
            select(
                EntityRelationship.source_entity_id,
                EntityRelationship.target_entity_id,
                EntityRelationship.relationship_type,
                EntityRelationship.occurrence_count,
                EntityRelationship.id,
            )
            .where(
                EntityRelationship.source_entity_id.in_(id_set),
                EntityRelationship.target_entity_id.in_(id_set),
            )
            .order_by(EntityRelationship.occurrence_count.desc(), EntityRelationship.id)
            .limit(limit + 1)
        )
    ).all()
    truncated = len(rows) > limit
    out = [GraphEdge(int(src), int(tgt), rel_type, int(occ or 1), int(rid)) for src, tgt, rel_type, occ, rid in rows[:limit] if src != tgt]
    return out, truncated


async def neighbors_of(
    db: AsyncSession,
    entity_id: int,
    *,
    limit: int = MAX_NEIGHBORS_PER_HOP,
    include_allowlisted: bool = False,
    focal_entity_type: str | None = None,
    viewer=None,
) -> list[tuple[Entity, int]]:
    """Top neighbours of `entity_id` ranked by shared-job count, as `(Entity, shared)`.

    A public, ORM-returning helper because `entity_stix_export` calls it. The graph builder
    does not: it batches a whole hop into one query (`_neighbors_for_hop`) instead of paying
    one round trip per frontier node. This is a thin hydrating wrapper
    over that same query so the ranking cannot drift between the two callers.
    """
    limit = max(1, min(limit, MAX_NEIGHBORS_PER_HOP))
    ranked = await _neighbors_for_hop(
        db,
        [entity_id],
        limit=limit,
        include_allowlisted=include_allowlisted,
        focal_entity_type=focal_entity_type,
        viewer=viewer,
    )
    rows = ranked.get(entity_id, [])
    if not rows:
        return []
    ids = [r[0] for r in rows]
    ents = {e.id: e for e in (await db.execute(select(Entity).where(Entity.id.in_(ids)))).scalars().all()}
    return [(ents[i], shared) for i, shared in rows if i in ents]


async def _neighbors_for_hop(
    db: AsyncSession,
    frontier: list[int],
    *,
    limit: int,
    include_allowlisted: bool,
    focal_entity_type: str | None,
    viewer=None,
    job_id: int | None = None,
    row_cap: int = HOP_ROW_CAP,
    exclude_jobs: Select | None = None,
) -> dict[int, list[tuple[int, int]]]:
    """One batched query for a whole traversal frontier: `{source_id: [(neighbour_id, shared)]}`.

    Calling `neighbors_of` **once per frontier node** would be ~5 s of pure latency at 5,000
    nodes before any edge work begins — the real limit on the node ceiling, not the payload.

    `ROW_NUMBER() OVER (PARTITION BY source ORDER BY shared DESC, neighbour)` does the
    per-source top-N in SQL, the established pattern here (see
    `routers/intel.py::_fetch_associated_groups`). The candidate window is widened to
    `MAX_NEIGHBORS_PER_HOP` when a type preference applies, as `neighbors_of` does, and the
    *rows* are bounded by `row_cap` with a deterministic outer
    ordering so a wide frontier cannot produce an unbounded result set.
    """
    frontier = list(dict.fromkeys(frontier))
    if not frontier:
        return {}
    preferred = _PREFERRED_NEIGHBOR_TYPES.get(focal_entity_type or "", frozenset())
    per_source = MAX_NEIGHBORS_PER_HOP if preferred else limit

    a = aliased(EntityJobLink)
    b = aliased(EntityJobLink)
    # Unscoped, "how many jobs did these two share" is the right strength signal. Under a
    # job scope it is 1 for every pair by construction, and ordering by a constant leaves
    # `ROW_NUMBER()` picking an arbitrary `limit` neighbours by entity id. The neighbour's
    # own occurrence count *within that job* is the honest within-job replacement. Only
    # ever used for ranking — the caller
    # discards the value — so repurposing the column is safe.
    shared = (func.max(b.occurrence_count) if job_id else func.count(func.distinct(a.job_id))).label("shared")

    base = (
        select(a.entity_id.label("src"), b.entity_id.label("dst"), shared)
        .join(b, a.job_id == b.job_id)
        .join(AnalysisJob, a.job_id == AnalysisJob.id)
        .join(Entity, Entity.id == b.entity_id)
        .where(a.entity_id.in_(frontier), b.entity_id != a.entity_id)
        .group_by(a.entity_id, b.entity_id)
    )
    # `b.job_id == a.job_id` is the join condition, so constraining `a` scopes both
    # endpoints — this is what makes the whole discovered node set job-scoped.
    if job_id:
        base = base.where(a.job_id == job_id)
    elif exclude_jobs is not None:
        # Never under a job scope: there the candidate set *is* the one job, so excluding
        # it for being wide would suppress exactly what was asked for — the same reason
        # `_job_co_edges` forces its fanout guard off when `job_id` is set.
        base = base.where(a.job_id.notin_(exclude_jobs))
    if not include_allowlisted:
        base = base.where(Entity.allowlisted.is_(False))
    vis = visible_job_filter(viewer)
    if vis is not True:
        base = base.where(vis)

    sub = base.subquery()
    ranked = (
        select(
            sub.c.src,
            sub.c.dst,
            sub.c.shared,
            func.row_number().over(partition_by=sub.c.src, order_by=(sub.c.shared.desc(), sub.c.dst)).label("rn"),
        )
    ).subquery()
    stmt = select(ranked.c.src, ranked.c.dst, ranked.c.shared).where(ranked.c.rn <= per_source).order_by(ranked.c.shared.desc(), ranked.c.src, ranked.c.dst).limit(row_cap)
    rows = (await db.execute(stmt)).all()

    if not preferred:
        out: dict[int, list[tuple[int, int]]] = {}
        for src, dst, n in rows:
            out.setdefault(int(src), []).append((int(dst), int(n or 0)))
        return out

    # Type preference re-ranks within the widened candidate pool, then truncates to `limit`
    # — the same two-step `neighbors_of` does, once for the whole frontier.
    type_rows = (await db.execute(select(Entity.id, Entity.entity_type).where(Entity.id.in_({int(r[1]) for r in rows})))).all()
    types = {int(i): t for i, t in type_rows}
    grouped: dict[int, list[tuple[int, int]]] = {}
    for src, dst, n in rows:
        grouped.setdefault(int(src), []).append((int(dst), int(n or 0)))
    return {src: sorted(items, key=lambda p: (0 if types.get(p[0]) in preferred else 1, -p[1], p[0]))[:limit] for src, items in grouped.items()}


def _globally_hot_job_ids(*, fanout: int | None = None) -> Select:
    """Job ids linking more than *fanout* distinct entities — the near-clique guard.

    Self-contained: it needs no node set, so the **traversal** can use it. `_job_co_edges`
    suppresses these jobs' edges, so a traversal walking through them would pull in up to
    `MAX_NEIGHBORS_PER_HOP` neighbours whose only relation to the frontier is co-appearance
    in one enormous job, then drop every edge that would have justified them: full node-set
    cost, no edges, and a neighbour ranking dominated by the job least likely to mean anything.

    Group-by over `ix_entity_job_link_job_entity`, which covers it, and embedded as a
    subquery rather than materialised.
    """
    # Resolved at call time, not bound as a default: MAX_JOB_FANOUT is a module global
    # that tests (and a future settings hook) override.
    threshold = MAX_JOB_FANOUT if fanout is None else fanout
    return select(EntityJobLink.job_id).group_by(EntityJobLink.job_id).having(func.count(func.distinct(EntityJobLink.entity_id)) > threshold)


def _hot_job_ids(entity_ids: list[int], *, fanout: int = MAX_JOB_FANOUT) -> Select:
    """Near-clique jobs **in this picture**: those touching the node set, wide overall.

    Width is counted over the job's whole entity set, not just the part inside the graph.
    Counted over the restriction, a job linking 5,000 entities with four on screen would be
    "4 wide" — not a near-clique, so its edges drawn — and would disagree with the traversal
    guard above, leaving `stats.job_fanout_suppressed` at 0 where the guard had fired.
    """
    touching = select(EntityJobLink.job_id).where(EntityJobLink.entity_id.in_(entity_ids))
    return _globally_hot_job_ids(fanout=fanout).where(EntityJobLink.job_id.in_(touching))


def _job_pair_lohi(entity_ids: list[int], viewer, job_id: int | None = None):
    """Distinct `(lo, hi)` pairs that co-occur in at least one job, viewer-filtered.

    Self-join on ``EntityJobLink`` with ``a.entity_id < b.entity_id`` so each unordered pair
    is produced exactly once, already in (low, high) order.
    """
    a = aliased(EntityJobLink)
    b = aliased(EntityJobLink)
    stmt = (
        select(a.entity_id.label("lo"), b.entity_id.label("hi"))
        .join(b, a.job_id == b.job_id)
        .join(AnalysisJob, a.job_id == AnalysisJob.id)
        .where(a.entity_id.in_(entity_ids), b.entity_id.in_(entity_ids), a.entity_id < b.entity_id)
        .distinct()
    )
    if job_id:
        stmt = stmt.where(a.job_id == job_id)
    vis = visible_job_filter(viewer)
    if vis is not True:
        stmt = stmt.where(vis)
    return stmt


def _finding_pair_lohi(entity_ids: list[int], viewer, job_id: int | None = None):
    """Distinct `(lo, hi)` pairs that co-occur inside a single Sigma finding, viewer-filtered."""
    fa = aliased(FindingEntityLink)
    fb = aliased(FindingEntityLink)
    stmt = (
        select(fa.entity_id.label("lo"), fb.entity_id.label("hi"))
        .join(fb, fa.finding_id == fb.finding_id)
        .join(Finding, fa.finding_id == Finding.id)
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .join(AnalysisJob, TaskResult.job_id == AnalysisJob.id)
        .where(fa.entity_id.in_(entity_ids), fb.entity_id.in_(entity_ids), fa.entity_id < fb.entity_id)
        .distinct()
    )
    if job_id:
        stmt = stmt.where(TaskResult.job_id == job_id)
    vis = visible_job_filter(viewer)
    if vis is not True:
        stmt = stmt.where(vis)
    return stmt


def _typed_pair_lohi(entity_ids: list[int]):
    """Distinct direction-normalized `(lo, hi)` pairs joined by a typed relationship.

    A CASE keeps this portable: SQLite spells two-argument least/greatest ``min()``/
    ``max()`` while PostgreSQL uses ``LEAST``/``GREATEST``. Only used by the totals probe,
    which counts *pairs* — the emitted typed edges are directed and per-type.
    """
    src, tgt = EntityRelationship.source_entity_id, EntityRelationship.target_entity_id
    lo = case((src < tgt, src), else_=tgt).label("lo")
    hi = case((src < tgt, tgt), else_=src).label("hi")
    return select(lo, hi).where(src.in_(entity_ids), tgt.in_(entity_ids), src != tgt).distinct()


async def _job_co_edges(
    db: AsyncSession,
    entity_ids: list[int],
    *,
    viewer=None,
    limit: int = CASE_MAX_EDGES,
    fanout: int | None = MAX_JOB_FANOUT,
    job_id: int | None = None,
) -> tuple[dict[tuple[int, int], int], bool, int]:
    """Shared-job counts keyed by (low_id, high_id), strongest first, bounded by *limit*.

    Returns ``(pairs, truncated, jobs_suppressed)``.

    Filtered through ``visible_job_filter(viewer)``: a "job" edge between two visible
    entities otherwise reveals that they co-occurred inside a job the viewer cannot see.
    ``viewer=None`` means anonymous, i.e. public jobs only.

    *fanout* excludes jobs touching more than that many of the node set. The LIMIT bounds
    output, not scan, so a single near-clique job is what actually costs; the count of
    excluded jobs is returned so the banner can say so rather than silently changing what
    the graph means.

    **`job_id` forces `fanout` off**, here rather than at the call site so it cannot be
    got wrong by a future caller. The guard's candidate set under a job scope is that one
    job, so any job touching more than `fanout` of the node set would have 100% of its
    edges dropped and the banner would report "1 job excluded as a near-clique" about the
    only job in the picture — suppressing precisely what was asked for. `JOB_SCOPE_MAX_NODES`
    is what bounds the scan instead.
    """
    if len(entity_ids) < 2:
        return {}, False, 0
    if job_id:
        fanout = None
    a = aliased(EntityJobLink)
    b = aliased(EntityJobLink)
    shared = func.count(func.distinct(a.job_id))

    suppressed = 0
    stmt = (
        select(a.entity_id, b.entity_id, shared.label("shared"))
        .join(b, a.job_id == b.job_id)
        .join(AnalysisJob, a.job_id == AnalysisJob.id)
        .where(a.entity_id.in_(entity_ids), b.entity_id.in_(entity_ids), a.entity_id < b.entity_id)
        .group_by(a.entity_id, b.entity_id)
        .order_by(shared.desc(), a.entity_id, b.entity_id)
        .limit(limit + 1)
    )
    if job_id:
        stmt = stmt.where(a.job_id == job_id)
    if fanout:
        hot = _hot_job_ids(entity_ids, fanout=fanout).subquery()
        suppressed = int(await db.scalar(select(func.count()).select_from(hot)) or 0)
        if suppressed:
            stmt = stmt.where(a.job_id.notin_(select(hot.c.job_id)))
    vis = visible_job_filter(viewer)
    if vis is not True:
        stmt = stmt.where(vis)
    rows = (await db.execute(stmt)).all()
    return {(int(lo), int(hi)): int(n or 0) for lo, hi, n in rows[:limit]}, len(rows) > limit, suppressed


async def _focal_edges(
    db: AsyncSession,
    entity_ids: list[int],
    focal_id: int,
    *,
    viewer=None,
    limit: int = FOCAL_EDGE_BUDGET,
    job_id: int | None = None,
) -> dict[tuple[int, int], int]:
    """Shared-job counts for pairs **incident to the focal entity**, separately budgeted.

    `_job_co_edges` orders `shared DESC` in SQL and cuts at `limit`, so a focal spoke with
    `shared=1` loses to 15,000 pairs with `shared>=2` and never reaches the Python
    focal-first ranking — the view then renders centred on an orphan. This query exists so
    the centre of the graph has an allowance nothing else can outrank.

    Viewer-filtered like every other job-derived source, and *especially* here: this budget
    is reserved, so an unfiltered focal spoke would be guaranteed to render. The same
    argument applies to `job_id` — an unscoped spoke at the centre of a job-scoped picture
    would be a guaranteed lie in the one place the eye goes first.
    """
    if len(entity_ids) < 2:
        return {}
    a = aliased(EntityJobLink)
    b = aliased(EntityJobLink)
    shared = func.count(func.distinct(a.job_id))
    stmt = (
        select(a.entity_id, b.entity_id, shared.label("shared"))
        .join(b, a.job_id == b.job_id)
        .join(AnalysisJob, a.job_id == AnalysisJob.id)
        .where(
            a.entity_id.in_(entity_ids),
            b.entity_id.in_(entity_ids),
            a.entity_id < b.entity_id,
            (a.entity_id == focal_id) | (b.entity_id == focal_id),
        )
        .group_by(a.entity_id, b.entity_id)
        .order_by(shared.desc(), a.entity_id, b.entity_id)
        .limit(limit)
    )
    if job_id:
        stmt = stmt.where(a.job_id == job_id)
    vis = visible_job_filter(viewer)
    if vis is not True:
        stmt = stmt.where(vis)
    rows = (await db.execute(stmt)).all()
    return {(int(lo), int(hi)): int(n or 0) for lo, hi, n in rows}


async def _finding_co_edges(
    db: AsyncSession,
    entity_ids: list[int],
    *,
    viewer=None,
    limit: int = CASE_MAX_EDGES,
    job_id: int | None = None,
) -> tuple[dict[tuple[int, int], int], bool]:
    """Distinct-finding co-occurrence counts keyed by (low_id, high_id).

    Filtered through ``visible_job_filter(viewer)``: without it a member could infer from an
    amber "same Sigma finding" edge that two visible entities co-occurred inside a *private*
    job's finding — the leak class tests/test_private_job_isolation.py polices.

    Deliberately **not** fanout-guarded: a finding's entity set is already bounded by
    ``SiteSettings.max_finding_details``, and there is no measurement behind adding one.
    """
    if len(entity_ids) < 2:
        return {}, False
    fa = aliased(FindingEntityLink)
    fb = aliased(FindingEntityLink)
    n = func.count(func.distinct(fa.finding_id))
    stmt = (
        select(fa.entity_id, fb.entity_id, n.label("n"))
        .join(fb, fa.finding_id == fb.finding_id)
        .join(Finding, fa.finding_id == Finding.id)
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .join(AnalysisJob, TaskResult.job_id == AnalysisJob.id)
        .where(fa.entity_id.in_(entity_ids), fb.entity_id.in_(entity_ids), fa.entity_id < fb.entity_id)
        .group_by(fa.entity_id, fb.entity_id)
        .order_by(n.desc(), fa.entity_id, fb.entity_id)
        .limit(limit + 1)
    )
    # Without this an amber "same Sigma finding" edge in a job-scoped graph would come
    # from an entirely different job — the one kind of edge whose colour promises otherwise.
    if job_id:
        stmt = stmt.where(TaskResult.job_id == job_id)
    vis = visible_job_filter(viewer)
    if vis is not True:
        stmt = stmt.where(vis)
    rows = (await db.execute(stmt)).all()
    return {(int(lo), int(hi)): int(n_ or 0) for lo, hi, n_ in rows[:limit]}, len(rows) > limit


async def _total_edges_probe(
    db: AsyncSession,
    entity_ids: list[int],
    viewer,
    job_edges: bool,
    *,
    cap: int = TOTAL_EDGES_PROBE_CAP,
    job_id: int | None = None,
) -> tuple[int, bool]:
    """Uncapped `(lo, hi)` pair count *among the emitted nodes*, bounded. `(count, is_floor)`.

    `union` (not `union_all`) dedupes across the three sources, so this matches what an
    uncapped build over the same node set would emit. Scoped to the emitted nodes because
    that is the question the banner asks: "of the nodes you can see, how many edges am I
    hiding?"

    Bounded by *cap*: unbounded, a three-way UNION inside a COUNT(*) is exactly the join
    product the rest of this module spends its time capping. Past the cap it reports a floor
    and the UI says "50,000+".

    `viewer` is threaded into the pair queries: the banner itself leaks otherwise.
    """
    if len(entity_ids) < 2:
        return 0, False
    # `job_id` reaches the two job-derived parts but not `_typed_pair_lohi`, matching
    # exactly what the build emits — the banner has to count the same universe it draws,
    # or the view looks more truncated than it is.
    parts = [_finding_pair_lohi(entity_ids, viewer, job_id), _typed_pair_lohi(entity_ids)]
    if job_edges:
        parts.insert(0, _job_pair_lohi(entity_ids, viewer, job_id))
    bounded = union(*parts).subquery().select().limit(cap + 1).subquery()
    total = int(await db.scalar(select(func.count()).select_from(bounded)) or 0)
    return (cap, True) if total > cap else (total, False)


async def _job_entity_total(db: AsyncSession, job_id: int, viewer, include_allowlisted: bool) -> int:
    """Exact count of entities in one job, under the same filters the traversal used.

    Only meaningful job-scoped, where the reachable set equals the job's entity set. The
    allowlist and visibility predicates have to match `_neighbors_for_hop` or the banner
    reads "31 of 214" against a universe the traversal could never have reached 214 of.
    """
    stmt = (
        select(func.count(func.distinct(EntityJobLink.entity_id)))
        .join(Entity, Entity.id == EntityJobLink.entity_id)
        .join(AnalysisJob, AnalysisJob.id == EntityJobLink.job_id)
        .where(EntityJobLink.job_id == job_id)
    )
    if not include_allowlisted:
        stmt = stmt.where(Entity.allowlisted.is_(False))
    vis = visible_job_filter(viewer)
    if vis is not True:
        stmt = stmt.where(vis)
    return int(await db.scalar(stmt) or 0)


def _assemble_edges(
    pairs: set[tuple[int, int]],
    *,
    job_co: dict,
    finding_co: dict,
    typed: list[GraphEdge],
) -> list[GraphEdge]:
    """Undirected co-occurrence edges for *pairs*, plus the directed typed ones."""
    out: list[GraphEdge] = []
    for lo, hi in sorted(pairs):
        kind, weight = _cooccurrence_weight((lo, hi), job_co=job_co, finding_co=finding_co)
        out.append(GraphEdge(lo, hi, kind, weight))
    return [*out, *typed]


def _kind_counts(edges: list[GraphEdge]) -> dict[str, int]:
    counts = {EDGE_KIND_JOB: 0, EDGE_KIND_FINDING: 0, "typed": 0}
    for e in edges:
        counts[e.kind if e.kind in counts else "typed"] += 1
    return counts


async def build_entity_graph(
    db: AsyncSession,
    entity_id: int,
    *,
    hops: int = 1,
    limit: int = DEFAULT_NEIGHBOR_LIMIT,
    include_allowlisted: bool = False,
    viewer=None,
    max_edges: int = MAX_EDGES,
    max_nodes: int = MAX_NODES,
    query=None,
    threat: bool = True,
    job_id: int | None = None,
) -> dict:
    """Build a columnar graph payload for a focal entity.

    Hops 1..3, one batched query per hop, capped by `limit` per source and `max_nodes`
    globally. The edge set is then the **induced** one over the discovered nodes — not the
    traversal tree — so community detection does not simply rediscover the BFS and a path
    between two neighbours is the real path rather than a detour through the focal node.

    `viewer` is the requesting user (None = anonymous), threaded into every job-derived
    query. `query` is a parsed search query whose `re:` terms are matched here (see
    `queries.match_entity_rows`); everything else in the grammar is evaluated client-side.

    `job_id` narrows the picture to what one job observed. It is assumed **already
    visibility-checked by the caller** — but `visible_job_filter(viewer)` still applies to
    every query underneath, so an unvalidated id can only ever narrow the result, never
    widen it. Two things deliberately stay global under it: `_typed_edges`, because
    `EntityRelationship` has no job column and the only per-job dimension
    (`EntityRelationshipEvidence`) is incomplete for historical edges; and
    `fetch_threat_columns`, whose four columns are entity properties rather than job facts
    — case membership has no job dimension at all. So positions and edges are job-scoped
    while node *paint* is not, and `_graph_help.html` says so.
    """
    hops = max(1, min(int(hops), MAX_HOPS))
    limit = max(1, min(int(limit), MAX_NEIGHBORS_PER_HOP))
    max_edges = max(1, int(max_edges))
    max_nodes = max(1, int(max_nodes))
    if job_id:
        # `min`, not an override: the export budget must stay the smaller of the two.
        max_nodes = min(max_nodes, JOB_SCOPE_MAX_NODES)

    focal_row = (await db.execute(select(*_NODE_COLUMNS).where(Entity.id == entity_id))).first()
    if focal_row is None:
        return build_payload(
            scope="entity",
            focal_id=entity_id,
            nodes=[],
            edges=[],
            stats=_stats(0, 0, total_nodes=None, total_edges=0, job_id=job_id),
        )

    nodes_by_id: dict[int, GraphNode] = {int(focal_row.id): _node_from_row(focal_row)}
    frontier = [int(focal_row.id)]
    hops_used = 0
    nodes_truncated = False

    # Built once and reused across hops — a Select is a description, not a result, so this
    # costs nothing until the hop query embeds it.
    hot_jobs = None if job_id else _globally_hot_job_ids()

    for _ in range(hops):
        if len(nodes_by_id) >= max_nodes:
            nodes_truncated = True
            break
        hops_used += 1
        ranked = await _neighbors_for_hop(
            db,
            frontier,
            limit=limit,
            include_allowlisted=include_allowlisted,
            focal_entity_type=focal_row.entity_type,
            viewer=viewer,
            job_id=job_id,
            exclude_jobs=hot_jobs,
        )
        discovered: list[int] = []
        for src_id in frontier:
            for neighbour_id, _shared in ranked.get(src_id, []):
                if neighbour_id in nodes_by_id or neighbour_id in discovered:
                    continue
                if len(nodes_by_id) + len(discovered) >= max_nodes:
                    nodes_truncated = True
                    break
                discovered.append(neighbour_id)
            if nodes_truncated:
                break
        if not discovered:
            break
        for row in (await db.execute(select(*_NODE_COLUMNS).where(Entity.id.in_(discovered)))).all():
            nodes_by_id[int(row.id)] = _node_from_row(row)
        frontier = discovered
        if nodes_truncated:
            break

    node_ids = list(nodes_by_id)
    job_co, job_trunc, suppressed = await _job_co_edges(db, node_ids, viewer=viewer, limit=max_edges, job_id=job_id)
    if hot_jobs is not None and len(node_ids) < 2:
        # `_job_co_edges` returns early below two nodes, so it never counts. That is the
        # *usual* outcome when the focal entity's only jobs are near-cliques: the
        # traversal declined them, nothing was discovered, and the guard would silently
        # report 0 for a graph it had emptied. Only reached on that early-return path, so
        # it costs a query exactly when there were no edges to pay for anyway.
        hot = _hot_job_ids(node_ids).subquery()
        suppressed = max(suppressed, int(await db.scalar(select(func.count()).select_from(hot)) or 0))
    focal_co = await _focal_edges(db, node_ids, int(focal_row.id), viewer=viewer, job_id=job_id)
    job_co = {**focal_co, **job_co}
    finding_co, finding_trunc = await _finding_co_edges(db, node_ids, viewer=viewer, limit=max_edges, job_id=job_id)
    # Deliberately unscoped: `EntityRelationship` has no job column, and the only per-job
    # dimension is incomplete for historical edges — filtering through it would silently
    # hide real relationships. The node set is already job-scoped, so a typed edge here is
    # a true statement about two entities the job saw; it just is not a statement about
    # the job. `test_typed_edges_are_deliberately_unfiltered` pins the unscoped case.
    typed, typed_trunc = await _typed_edges(db, node_ids, limit=max_edges)

    pairs = set(job_co) | set(finding_co)
    all_edges = _assemble_edges(pairs, job_co=job_co, finding_co=finding_co, typed=typed)
    edges_truncated = job_trunc or finding_trunc or typed_trunc

    total_edges = len(all_edges)
    total_is_floor = False
    if len(all_edges) > max_edges:
        all_edges.sort(key=lambda e: _edge_rank(e, int(focal_row.id)))
        all_edges = all_edges[:max_edges]
        edges_truncated = True
    if edges_truncated or nodes_truncated:
        total_edges, total_is_floor = await _total_edges_probe(db, node_ids, viewer, True, job_id=job_id)
        total_edges = max(total_edges, len(all_edges))

    # A traversal normally never learns the true node total, which is why entity scope
    # emits None. Under a job scope it *is* knowable and cheap: every hop is constrained
    # to `job_id`, so the reachable set is exactly that job's entity set. One COUNT turns
    # the banner from "31 nodes" into "31 of 214", which is the honest version of the same
    # sentence and the one thing the job scope gives away for free.
    total_nodes = await _job_entity_total(db, job_id, viewer, include_allowlisted) if job_id else None

    matches, matches_partial = await _match(db, query, nodes_by_id)
    threat_map, cases_map = (await fetch_threat_columns(db, node_ids, viewer=viewer)) if threat else ({}, {})
    return build_payload(
        scope="entity",
        focal_id=int(focal_row.id),
        nodes=list(nodes_by_id.values()),
        edges=all_edges,
        hidden_types=[],
        hidden_kinds=DEFAULT_HIDDEN_EDGE_KINDS,
        matches=matches,
        matches_partial=matches_partial,
        threat=threat_map,
        cases=cases_map,
        stats=_stats(
            len(nodes_by_id),
            len(all_edges),
            total_nodes=total_nodes,
            total_edges=total_edges,
            total_edges_is_floor=total_is_floor,
            hops_used=hops_used,
            nodes_truncated=nodes_truncated,
            edges_truncated=edges_truncated,
            job_fanout_suppressed=suppressed,
            job_id=job_id,
            kinds=_kind_counts(all_edges),
        ),
    )


async def build_case_graph(
    db: AsyncSession,
    case_entity_ids: list[int],
    *,
    include_allowlisted: bool = False,
    viewer=None,
    job_edges: bool = True,
    max_nodes: int = CASE_MAX_NODES,
    max_edges: int = CASE_MAX_EDGES,
    query=None,
    threat: bool = True,
    case_id: int | None = None,
    job_id: int | None = None,
) -> dict:
    """Build a columnar payload bounded by a case's entity set (no hop expansion).

    `job_edges=False` skips the job-co-occurrence query entirely rather than computing and
    discarding it — the single biggest win for a large case, and the reason the case UI
    defaults it off. Nodes are ranked by `Entity.job_count`, a global count rather than a
    case-scoped degree, because this function only receives entity ids.

    `viewer` gates finding-kind and job-kind edges through `visible_job_filter`.

    `job_id` is optional here, unlike the entity scope: a case's whole point is cross-job
    correlation, so it renders unfiltered by default and the filter is something you reach
    for. The caller narrows `case_entity_ids` to that job's entities; this only scopes the
    edges. Same two deliberate exclusions as the entity builder — typed edges and threat
    paint stay global.
    """
    case_entity_ids = list(case_entity_ids)
    if not case_entity_ids:
        return build_payload(
            scope="case",
            nodes=[],
            edges=[],
            hidden_types=CASE_DEFAULT_HIDDEN_TYPES,
            hidden_kinds=DEFAULT_HIDDEN_EDGE_KINDS,
            stats=_stats(0, 0, total_nodes=0, total_edges=0, job_edges=job_edges, job_id=job_id),
        )

    max_nodes = max(1, int(max_nodes))
    max_edges = max(1, int(max_edges))

    base = select(*_NODE_COLUMNS).where(Entity.id.in_(case_entity_ids))
    if not include_allowlisted:
        base = base.where(Entity.allowlisted.is_(False))

    total_nodes = int(await db.scalar(select(func.count()).select_from(base.subquery())) or 0)
    rows = (await db.execute(base.order_by(Entity.job_count.desc(), Entity.id).limit(max_nodes))).all()
    nodes = [_node_from_row(r) for r in rows]
    nodes_truncated = total_nodes > len(nodes)

    entity_ids = [n.id for n in nodes]
    job_co, job_trunc, suppressed = (await _job_co_edges(db, entity_ids, viewer=viewer, limit=max_edges, job_id=job_id)) if job_edges else ({}, False, 0)
    finding_co, finding_trunc = await _finding_co_edges(db, entity_ids, viewer=viewer, limit=max_edges, job_id=job_id)
    typed, typed_trunc = await _typed_edges(db, entity_ids, limit=max_edges)

    pairs = set(job_co) | set(finding_co)
    all_edges = _assemble_edges(pairs, job_co=job_co, finding_co=finding_co, typed=typed)
    edges_truncated = job_trunc or finding_trunc or typed_trunc

    total_edges = len(all_edges)
    total_is_floor = False
    if len(all_edges) > max_edges:
        all_edges.sort(key=lambda e: _edge_rank(e, None))
        all_edges = all_edges[:max_edges]
        edges_truncated = True
    if nodes_truncated or edges_truncated:
        total_edges, total_is_floor = await _total_edges_probe(db, entity_ids, viewer, job_edges, job_id=job_id)
        total_edges = max(total_edges, len(all_edges))

    matches, matches_partial = await _match(db, query, {n.id: n for n in nodes})
    threat_map, cases_map = (await fetch_threat_columns(db, entity_ids, viewer=viewer, current_case_id=case_id)) if threat else ({}, {})
    return build_payload(
        scope="case",
        nodes=nodes,
        edges=all_edges,
        hidden_types=CASE_DEFAULT_HIDDEN_TYPES,
        hidden_kinds=DEFAULT_HIDDEN_EDGE_KINDS,
        matches=matches,
        matches_partial=matches_partial,
        threat=threat_map,
        cases=cases_map,
        stats=_stats(
            len(nodes),
            len(all_edges),
            total_nodes=total_nodes,
            total_edges=total_edges,
            total_edges_is_floor=total_is_floor,
            nodes_truncated=nodes_truncated,
            edges_truncated=edges_truncated,
            job_edges=job_edges,
            job_fanout_suppressed=suppressed,
            job_id=job_id,
            kinds=_kind_counts(all_edges),
        ),
    )


# ── Threat context ─────────────────────────────────────────────────────────
#
# Folded into the main graph request rather than offered as a `?threat=1` second call.
# No graph endpoint accepts a client-supplied entity-id list — that turns it into an oracle
# for entities the viewer could not otherwise enumerate — so a second request would have to
# re-derive the entire graph just to attach five columns, plus a cache to make that
# affordable, plus a way to know the two derivations agreed. One request removes all three.

# Per-entity finding rows are capped so a hub entity linked to tens of thousands of
# findings cannot dominate the request. Rows are taken most-severe-first, so the cap can
# lower a tactic's ranking but never the reported worst severity.
THREAT_ROW_CAP = 20_000


async def fetch_threat_columns(
    db: AsyncSession,
    node_ids: list[int],
    *,
    viewer=None,
    current_case_id: int | None = None,
) -> tuple[dict, dict[int, list[int]]]:
    """Worst severity, dominant tactic, enrichment verdict and case membership per node.

    Returns ``(threat_by_entity, cases_by_entity)``.

    **Every query here is viewer-filtered, and two of them are leak classes of their own.** Worst
    severity and dominant tactic traverse ``FindingEntityLink -> Finding -> TaskResult ->
    AnalysisJob``: without ``visible_job_filter`` a node would be painted CRITICAL because
    of a finding inside another analyst's private job. Case membership traverses
    ``CaseEntityLink -> InvestigationCase`` and needs ``visible_case_filter`` — unfiltered,
    it discloses both the existence and the membership of an unshared case.

    The enrichment verdict is a small integer derived from ``summary_json``; the raw
    ``response_json`` and the decrypted API token never leave the server.
    """
    from app.intel.graph_payload import NodeThreat
    from app.intel.live_enrichment import verdict_from_summary
    from app.intel.tactics import primary_tactic_from_tags
    from app.json_utils import loads as json_loads
    from app.models import CaseEntityLink, EnrichmentService, EntityEnrichmentResult, InvestigationCase, severity_rank_sql, visible_case_filter

    if not node_ids:
        return {}, {}

    severity: dict[int, int] = {}
    tactic: dict[int, str] = {}
    verdict: dict[int, int] = {}
    cases: dict[int, list[int]] = {}

    # Severity + tactic in one pass. Grouping on `Finding.tags` collapses the JSON parse to
    # one call per *distinct tag set* rather than one per link row — a job's findings share
    # a handful of tag sets between them.
    rank = severity_rank_sql()
    stmt = (
        select(
            FindingEntityLink.entity_id,
            Finding.tags,
            func.min(rank).label("rank"),
            func.count().label("n"),
        )
        .join(Finding, FindingEntityLink.finding_id == Finding.id)
        .join(TaskResult, Finding.task_result_id == TaskResult.id)
        .join(AnalysisJob, TaskResult.job_id == AnalysisJob.id)
        .where(FindingEntityLink.entity_id.in_(node_ids))
        .group_by(FindingEntityLink.entity_id, Finding.tags)
        .order_by(func.min(rank))
        .limit(THREAT_ROW_CAP)
    )
    vis = visible_job_filter(viewer)
    if vis is not True:
        stmt = stmt.where(vis)

    tactic_weight: dict[int, dict[str, int]] = {}
    for entity_id, tags_json, min_rank, n in (await db.execute(stmt)).all():
        eid = int(entity_id)
        current = severity.get(eid)
        if current is None or int(min_rank) < current:
            severity[eid] = int(min_rank)
        try:
            tags = json_loads(tags_json or "[]")
        except Exception:
            continue
        name = primary_tactic_from_tags(tags)
        if name:
            tactic_weight.setdefault(eid, {})[name] = tactic_weight.setdefault(eid, {}).get(name, 0) + int(n or 1)

    for eid, weights in tactic_weight.items():
        tactic[eid] = max(sorted(weights), key=lambda t: weights[t])

    # Enrichment verdicts. `ok` rows only — an error row's summary is an error message, not
    # a judgement. Strongest verdict across services wins.
    enrichment_rows = (
        await db.execute(
            select(EntityEnrichmentResult.entity_id, EnrichmentService.provider_key, EntityEnrichmentResult.summary_json)
            .join(EnrichmentService, EntityEnrichmentResult.service_id == EnrichmentService.id)
            .where(EntityEnrichmentResult.entity_id.in_(node_ids), EntityEnrichmentResult.ok.is_(True))
        )
    ).all()
    for entity_id, provider_key, summary_json in enrichment_rows:
        try:
            summary = json_loads(summary_json) if summary_json else None
        except Exception:
            continue
        value = verdict_from_summary(provider_key, summary)
        eid = int(entity_id)
        if value > verdict.get(eid, 0):
            verdict[eid] = value

    # Case membership. `in_case` means "also in at least one *other* visible case", so the
    # case you are already looking at does not paint every node in its own graph.
    case_stmt = (
        select(CaseEntityLink.entity_id, CaseEntityLink.case_id)
        .join(InvestigationCase, CaseEntityLink.case_id == InvestigationCase.id)
        .where(CaseEntityLink.entity_id.in_(node_ids))
    )
    case_vis = visible_case_filter(viewer)
    if case_vis is not True:
        case_stmt = case_stmt.where(case_vis)
    if current_case_id is not None:
        case_stmt = case_stmt.where(CaseEntityLink.case_id != current_case_id)
    for entity_id, case_id in (await db.execute(case_stmt)).all():
        cases.setdefault(int(entity_id), []).append(int(case_id))

    threat = {eid: NodeThreat(severity=severity.get(eid), tactic=tactic.get(eid), verdict=verdict.get(eid, 0)) for eid in set(severity) | set(tactic) | set(verdict)}
    return threat, cases


class _MatchRow(NamedTuple):
    """The `(id, value)` shape `match_entity_rows` needs, without an ORM round trip."""

    id: int
    value: str


async def _match(db: AsyncSession, query, nodes_by_id: dict[int, GraphNode]) -> tuple[set[int] | None, bool]:
    """Run the server-side half of a parsed query — `re:` and `list:` — against the node set.

    Everything else is client-side. The lists a query names are loaded here, once, because
    `match_entity_rows` is pure and the client never sees the lists at all.
    """
    if not query:
        return None, False
    from app.intel.queries import list_terms, match_entity_rows
    from app.intel.rule_lists import load_list_values

    names = list_terms(query)
    lists = await load_list_values(db, names) if names else None
    return match_entity_rows(query, [_MatchRow(n.id, n.label) for n in nodes_by_id.values()], lists=lists)
